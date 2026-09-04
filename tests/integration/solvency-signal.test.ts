import { describe, it, expect } from 'vitest';
import { RiskCheckHandler } from '../../src/api/handler.ts';
import { PoisoningDetectionService } from '../../src/domain/services/poisoning-detection-service.ts';
import { PrefixSuffixStrategy } from '../../src/matching/prefix-suffix/prefix-suffix-strategy.ts';
import { LevenshteinStrategy } from '../../src/matching/levenshtein/levenshtein-strategy.ts';
import { RecordingLogger } from '../unit/strategy-contract.ts';
import { WBTC_2024, USDT_2025 } from '../fixtures/incidents.ts';
import type { BlockProvider } from '../../src/domain/interfaces/block-provider.ts';
import type { TrustedSetProvider } from '../../src/domain/interfaces/trusted-set-provider.ts';
import type { CounterpartySignalProvider } from '../../src/domain/interfaces/counterparty-signal-provider.ts';
import type { CounterpartySolvency, TrustedIdentity } from '../../src/domain/entities/index.ts';
import type { RiskCheckResponse } from '../../src/api/response.ts';

/**
 * The solvency signal, end to end through the handler.
 *
 * The invariant every test here defends: the poisoning verdict — `risk_label`,
 * `risk_confidence`, `risk_reason`, `detail`, and `evidence.canonical` — is
 * byte-identical whether the second opinion succeeds, fails, times out, or is
 * absent entirely. The signal is additive or it is a regression.
 */

const BLOCK = 19_789_008;

class FixedBlockProvider implements BlockProvider {
  constructor(private readonly block: number | null = BLOCK) {}
  currentBlock(): Promise<number | null> {
    return Promise.resolve(this.block);
  }
}

class EmptyTrustProvider implements TrustedSetProvider {
  deriveTrustedSet(): Promise<readonly TrustedIdentity[]> {
    return Promise.resolve([]);
  }
}

/** A stub signal source, recording what it was asked. */
class StubSolvencyProvider implements CounterpartySignalProvider {
  readonly seen: { address: string; chain: string }[] = [];
  constructor(private readonly answer: CounterpartySolvency) {}
  solvencyOf(address: string, chain: string): Promise<CounterpartySolvency> {
    this.seen.push({ address, chain });
    return Promise.resolve(this.answer);
  }
}

/** Violates the non-throwing contract on purpose, to prove the handler survives it. */
class ThrowingSolvencyProvider implements CounterpartySignalProvider {
  solvencyOf(): Promise<CounterpartySolvency> {
    return Promise.reject(new Error('anchor exploded'));
  }
}

const assessed = (verdict: 'ALLOW' | 'RECHECK' | 'BLOCK'): CounterpartySolvency => ({
  state: 'assessed',
  source: 'aave-v3-pool-contract',
  verdict,
  reasoning: `test reasoning for ${verdict}`,
  healthFactor: verdict === 'BLOCK' ? 0.98 : 1.51,
  checkedAtBlock: 50_821_710,
});

const NO_POSITION: CounterpartySolvency = {
  state: 'no_position',
  source: 'aave-v3-pool-contract',
  checkedAtBlock: 50_821_585,
};

const build = (solvency: CounterpartySignalProvider | null = null): RiskCheckHandler => {
  const logger = new RecordingLogger();
  const service = new PoisoningDetectionService(
    [new PrefixSuffixStrategy(logger), new LevenshteinStrategy(logger)],
    logger,
  );
  return new RiskCheckHandler(
    service,
    new FixedBlockProvider(),
    new EmptyTrustProvider(),
    logger,
    solvency,
  );
};

const asResponse = (body: unknown): RiskCheckResponse => body as RiskCheckResponse;

/** The WBTC lookalike against its real trusted counterparty: a high_risk match. */
const POISONED_REQUEST = {
  address: WBTC_2024.lookalike,
  chain: 'ethereum' as const,
  callerHistory: [WBTC_2024.trusted],
};

/** An unrelated destination with real history: a safe verdict. */
const CLEAN_REQUEST = {
  address: WBTC_2024.victim,
  chain: 'ethereum' as const,
  callerHistory: [WBTC_2024.trusted],
};

describe('the poisoning verdict is unchanged by the solvency signal', () => {
  const variants: readonly [string, CounterpartySignalProvider | null][] = [
    ['no provider configured', null],
    ['healthy counterparty', new StubSolvencyProvider(assessed('ALLOW'))],
    ['distressed counterparty', new StubSolvencyProvider(assessed('RECHECK'))],
    ['insolvent counterparty', new StubSolvencyProvider(assessed('BLOCK'))],
    ['no lending position', new StubSolvencyProvider(NO_POSITION)],
    [
      'signal unavailable',
      new StubSolvencyProvider({ state: 'unavailable', reason: 'http_502' }),
    ],
    ['provider throws', new ThrowingSolvencyProvider()],
  ];

  for (const [name, provider] of variants) {
    it(`is identical with ${name}`, async () => {
      const result = await build(provider).handle(POISONED_REQUEST);
      const body = asResponse(result.body);

      expect(result.status).toBe(200);
      expect(body.risk_label).toBe('high_risk');
      expect(body.risk_confidence).toBeCloseTo(0.8775, 4);
      expect(body.risk_reason).toContain('poisoning_match');
      expect(body.risk_reason).toContain('prefix_suffix=0.8125');
      // No solvency term may appear in the poisoning reason.
      expect(body.risk_reason).not.toMatch(/ALLOW|RECHECK|BLOCK|solvency/);
      expect(body.detail.match_type).toBe('prefix_suffix');
      expect(body.detail.matched_against).toBe('0xd9a1...3a91');
      // The canonical string must not move either: it is the reproducibility
      // hash, and a third party's uptime cannot be allowed to change it.
      expect(body.evidence.canonical).toBe(`${WBTC_2024.lookalike}|ethereum|high_risk|${BLOCK}`);
    });
  }

  it('produces the same canonical string across every variant', async () => {
    const canonicals = new Set<string>();
    for (const [, provider] of variants) {
      const result = await build(provider).handle(POISONED_REQUEST);
      canonicals.add(asResponse(result.body).evidence.canonical);
    }
    expect(canonicals.size).toBe(1);
  });
});

describe('the solvency block reports the three states distinctly', () => {
  it('reports an assessed position with its verdict, reasoning, and health factor', async () => {
    const result = await build(new StubSolvencyProvider(assessed('RECHECK'))).handle(CLEAN_REQUEST);
    const solvency = asResponse(result.body).counterparty_solvency;

    expect(solvency.checked).toBe(true);
    if (!solvency.checked) return;
    expect(solvency.verdict).toBe('RECHECK');
    expect(solvency.source).toBe('aave-v3-pool-contract');
    expect(solvency.health_factor).toBe(1.51);
    expect(solvency.checked_at_block).toBe(50_821_710);
  });

  it('distinguishes NO_POSITION from ALLOW', async () => {
    // Upstream answers ALLOW for both a healthy borrower and an address with no
    // position at all. Those are different facts and the response says which.
    const noPosition = asResponse(
      (await build(new StubSolvencyProvider(NO_POSITION)).handle(CLEAN_REQUEST)).body,
    ).counterparty_solvency;
    const healthy = asResponse(
      (await build(new StubSolvencyProvider(assessed('ALLOW'))).handle(CLEAN_REQUEST)).body,
    ).counterparty_solvency;

    expect(noPosition.checked && noPosition.verdict).toBe('NO_POSITION');
    expect(healthy.checked && healthy.verdict).toBe('ALLOW');
  });

  it('reports an unavailable signal as checked: false, with the reason', async () => {
    const result = await build(
      new StubSolvencyProvider({ state: 'unavailable', reason: 'unreachable:TimeoutError' }),
    ).handle(CLEAN_REQUEST);

    expect(asResponse(result.body).counterparty_solvency).toEqual({
      checked: false,
      reason: 'unreachable:TimeoutError',
    });
  });

  it('reports checked: false when no provider is configured', async () => {
    const result = await build(null).handle(CLEAN_REQUEST);
    expect(asResponse(result.body).counterparty_solvency).toEqual({
      checked: false,
      reason: 'not_configured',
    });
  });

  it('survives a provider that breaks its non-throwing contract', async () => {
    const result = await build(new ThrowingSolvencyProvider()).handle(CLEAN_REQUEST);

    expect(result.status).toBe(200);
    expect(asResponse(result.body).counterparty_solvency).toEqual({
      checked: false,
      reason: 'provider_error',
    });
  });
});

describe('recommended_action composes both checks', () => {
  it('proceeds when nothing fired', async () => {
    const result = await build(new StubSolvencyProvider(assessed('ALLOW'))).handle(CLEAN_REQUEST);
    expect(asResponse(result.body).recommended_action).toEqual({
      action: 'proceed',
      reason: 'poisoning=safe:solvency=ALLOW:action=proceed',
    });
  });

  it('reviews a clean address whose counterparty is distressed', async () => {
    const result = await build(new StubSolvencyProvider(assessed('RECHECK'))).handle(CLEAN_REQUEST);
    expect(asResponse(result.body).recommended_action.action).toBe('review');
  });

  it('blocks a lookalike even when the counterparty is healthy', async () => {
    const result = await build(new StubSolvencyProvider(assessed('ALLOW'))).handle(POISONED_REQUEST);
    expect(asResponse(result.body).recommended_action).toEqual({
      action: 'block',
      reason: 'poisoning=high_risk:solvency=ALLOW:action=block',
    });
  });

  it('escalates insufficient_history to block when the counterparty is distressed', async () => {
    // `caution` + distress is the one row where the composition says more than
    // either input did. Neither alone would block; together they should.
    const result = await build(new StubSolvencyProvider(assessed('RECHECK'))).handle({
      address: USDT_2025.lookalike,
      chain: 'ethereum',
    });

    const body = asResponse(result.body);
    expect(body.risk_label).toBe('caution');
    expect(body.risk_reason).toBe('insufficient_history');
    expect(body.recommended_action.action).toBe('block');
  });

  it('does not escalate when the signal is merely unavailable', async () => {
    // If an outage upstream could tighten this miner's advice, a third party's
    // uptime would become this miner's false-positive rate.
    const result = await build(
      new StubSolvencyProvider({ state: 'unavailable', reason: 'http_502' }),
    ).handle({ address: USDT_2025.lookalike, chain: 'ethereum' });

    expect(asResponse(result.body).recommended_action.action).toBe('review');
  });
});

describe('the signal is requested correctly', () => {
  it('asks about the destination address, lowercased, with the request chain', async () => {
    const provider = new StubSolvencyProvider(NO_POSITION);
    const checksummed = WBTC_2024.lookalike.toUpperCase().replace('0X', '0x');

    await build(provider).handle({ address: checksummed, chain: 'base' });

    expect(provider.seen).toEqual([{ address: WBTC_2024.lookalike, chain: 'base' }]);
  });

  it('is not requested at all when the request is rejected', async () => {
    const provider = new StubSolvencyProvider(NO_POSITION);
    const result = await build(provider).handle({ address: 'not-an-address', chain: 'base' });

    expect(result.status).toBe(400);
    expect(provider.seen).toHaveLength(0);
  });

  it('asks about the destination, never about the caller', async () => {
    // The destination is what funds are about to move to, and it is the only
    // party whose solvency is relevant to that decision.
    const provider = new StubSolvencyProvider(NO_POSITION);
    await build(provider).handle({
      address: WBTC_2024.lookalike,
      chain: 'base',
      callerAddress: WBTC_2024.victim,
    });

    expect(provider.seen).toHaveLength(1);
    expect(provider.seen[0]?.address).toBe(WBTC_2024.lookalike);
    expect(provider.seen[0]?.address).not.toBe(WBTC_2024.victim);
  });
});
