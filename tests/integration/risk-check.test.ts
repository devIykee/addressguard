import { describe, it, expect } from 'vitest';
import { RiskCheckHandler } from '../../src/api/handler.ts';
import { PoisoningDetectionService } from '../../src/domain/services/poisoning-detection-service.ts';
import { PrefixSuffixStrategy } from '../../src/matching/prefix-suffix/prefix-suffix-strategy.ts';
import { LevenshteinStrategy } from '../../src/matching/levenshtein/levenshtein-strategy.ts';
import { NullBlockProvider } from '../../src/infrastructure/rpc-block-provider.ts';
import { buildCanonical, type RiskCheckResponse } from '../../src/api/response.ts';
import { RecordingLogger } from '../unit/strategy-contract.ts';
import { WBTC_2024, USDT_2025 } from '../fixtures/incidents.ts';
import { WBTC_2024_TXLIST } from '../fixtures/explorer-payloads.ts';
import { extractDeliberateRecipients } from '../../src/infrastructure/explorer-trusted-set-provider.ts';
import type { BlockProvider } from '../../src/domain/interfaces/block-provider.ts';
import type { TrustedSetProvider } from '../../src/domain/interfaces/trusted-set-provider.ts';
import type { Chain, TrustedIdentity } from '../../src/domain/entities/index.ts';

/** A block provider returning a fixed height, so canonical strings are stable. */
class FixedBlockProvider implements BlockProvider {
  constructor(private readonly block: number | null) {}
  currentBlock(): Promise<number | null> {
    return Promise.resolve(this.block);
  }
}

/** A trusted-set provider driven by the recorded explorer payload. */
class RecordedTrustProvider implements TrustedSetProvider {
  calls = 0;
  constructor(private readonly rows: readonly unknown[] = WBTC_2024_TXLIST.result) {}
  deriveTrustedSet(caller: string): Promise<readonly TrustedIdentity[]> {
    this.calls += 1;
    return Promise.resolve(
      extractDeliberateRecipients(this.rows, caller).map((identity) => ({
        identity,
        source: 'chain_derived' as const,
      })),
    );
  }
}

class EmptyTrustProvider implements TrustedSetProvider {
  calls = 0;
  deriveTrustedSet(): Promise<readonly TrustedIdentity[]> {
    this.calls += 1;
    return Promise.resolve([]);
  }
}

class ThrowingTrustProvider implements TrustedSetProvider {
  deriveTrustedSet(): Promise<readonly TrustedIdentity[]> {
    return Promise.reject(new Error('explorer exploded'));
  }
}

const build = (
  blockProvider: BlockProvider = new FixedBlockProvider(19789008),
  trustProvider: TrustedSetProvider = new EmptyTrustProvider(),
): RiskCheckHandler => {
  const logger = new RecordingLogger();
  const service = new PoisoningDetectionService(
    [new PrefixSuffixStrategy(logger), new LevenshteinStrategy(logger)],
    logger,
  );
  return new RiskCheckHandler(service, blockProvider, trustProvider, logger);
};

const asResponse = (body: unknown): RiskCheckResponse => body as RiskCheckResponse;

describe('POST /risk-check — validation', () => {
  it('rejects a missing address', async () => {
    const result = await build().handle({ chain: 'base' });
    expect(result.status).toBe(400);
    expect(result.body).toMatchObject({ error: 'invalid_request' });
  });

  it('rejects a malformed address', async () => {
    const result = await build().handle({ address: 'not-an-address', chain: 'base' });
    expect(result.status).toBe(400);
  });

  it('rejects an unsupported chain', async () => {
    const result = await build().handle({ address: WBTC_2024.lookalike, chain: 'solana' });
    expect(result.status).toBe(400);
    expect(JSON.stringify(result.body)).toContain('chain');
  });

  it('accepts a checksummed (mixed-case) address', async () => {
    // EIP-55 casing is a checksum, not an identity. Rejecting it would reject
    // the spelling most wallets produce.
    const checksummed = WBTC_2024.lookalike.toUpperCase().replace('0X', '0x');
    const result = await build().handle({ address: checksummed, chain: 'ethereum' });
    expect(result.status).toBe(200);
    expect(asResponse(result.body).address).toBe(WBTC_2024.lookalike);
  });

  it('ignores unknown fields rather than rejecting them', async () => {
    // Telegraph's request builder constructs calls from the YAML; a strict
    // boundary would turn a harmless extra field into a 400 on every routed
    // request.
    const result = await build().handle({
      address: WBTC_2024.lookalike,
      chain: 'base',
      unexpected: 'field',
    });
    expect(result.status).toBe(200);
  });

  it('does not reject the whole request over one malformed history entry', async () => {
    // The alternative is an attacker-supplied denial of the check: append one
    // bad string to callerHistory and the destination goes unchecked.
    const result = await build().handle({
      address: WBTC_2024.lookalike,
      chain: 'ethereum',
      callerHistory: ['garbage', WBTC_2024.trusted],
    });

    expect(result.status).toBe(200);
    expect(asResponse(result.body).risk_label).toBe('high_risk');
  });
});

describe('POST /risk-check — real incidents end to end', () => {
  it('returns high_risk for the WBTC 2024 lookalike', async () => {
    const result = await build().handle({
      address: WBTC_2024.lookalike,
      chain: 'ethereum',
      callerHistory: [WBTC_2024.trusted],
    });

    const body = asResponse(result.body);
    expect(result.status).toBe(200);
    expect(body.risk_label).toBe('high_risk');
    expect(body.risk_confidence).toBeCloseTo(0.8775, 4);
    expect(body.detail.match_type).toBe('prefix_suffix');
    expect(body.detail.matched_against).toBe('0xd9a1...3a91');
    expect(body.detail.trust_source).toBe('caller_supplied');
    expect(body.detail.trusted_set_size).toBe(1);
  });

  it('returns high_risk for the USDT 2025 lookalike, naming both signals', async () => {
    const result = await build().handle({
      address: USDT_2025.lookalike,
      chain: 'ethereum',
      callerHistory: [USDT_2025.trusted],
    });

    const body = asResponse(result.body);
    expect(body.risk_label).toBe('high_risk');
    expect(body.risk_reason).toContain('prefix_suffix=0.7500');
    expect(body.risk_reason).toContain('full_levenshtein=0.3250');
  });

  it('returns safe for an unrelated destination with real history', async () => {
    const result = await build().handle({
      address: WBTC_2024.victim,
      chain: 'ethereum',
      callerHistory: [WBTC_2024.trusted],
    });

    const body = asResponse(result.body);
    expect(body.risk_label).toBe('safe');
    expect(body.risk_reason).toBe('no_poisoning_match');
    expect(body.detail.matched_against).toBeNull();
    expect(body.detail.similarity_score).toBe(0);
  });
});

describe('POST /risk-check — never safe without a check', () => {
  it('returns caution/insufficient_history with no history and no callerAddress', async () => {
    const result = await build().handle({ address: WBTC_2024.lookalike, chain: 'base' });

    const body = asResponse(result.body);
    expect(body.risk_label).toBe('caution');
    expect(body.risk_reason).toBe('insufficient_history');
    expect(body.detail.trust_source).toBe('none');
    expect(body.detail.trusted_set_size).toBe(0);
  });

  it('returns caution when chain derivation yields nothing', async () => {
    const provider = new EmptyTrustProvider();
    const result = await build(new FixedBlockProvider(1), provider).handle({
      address: WBTC_2024.lookalike,
      chain: 'ethereum',
      callerAddress: WBTC_2024.victim,
    });

    expect(provider.calls).toBe(1);
    expect(asResponse(result.body).risk_label).toBe('caution');
    expect(asResponse(result.body).risk_reason).toBe('insufficient_history');
  });

  it('degrades to caution rather than 500 when the provider throws', async () => {
    const result = await build(new FixedBlockProvider(1), new ThrowingTrustProvider()).handle({
      address: WBTC_2024.lookalike,
      chain: 'ethereum',
      callerAddress: WBTC_2024.victim,
    });

    expect(result.status).toBe(200);
    expect(asResponse(result.body).risk_label).toBe('caution');
  });
});

describe('POST /risk-check — chain-derived trust', () => {
  it('derives the trusted set from callerAddress and catches the attack', async () => {
    // The end-to-end case the callerAddress path exists for: no history
    // supplied, and the answer is still correct — derived from the victim's own
    // signed transactions at the block before the real loss.
    const result = await build(
      new FixedBlockProvider(WBTC_2024.lossBlock - 1),
      new RecordedTrustProvider(),
    ).handle({
      address: WBTC_2024.lookalike,
      chain: 'ethereum',
      callerAddress: WBTC_2024.victim,
    });

    const body = asResponse(result.body);
    expect(body.risk_label).toBe('high_risk');
    expect(body.detail.trust_source).toBe('chain_derived');
    expect(body.detail.matched_against).toBe('0xd9a1...3a91');
  });

  it('does not call the explorer when callerHistory is supplied', async () => {
    // Keeps the common path off the network entirely.
    const provider = new RecordedTrustProvider();
    await build(new FixedBlockProvider(1), provider).handle({
      address: WBTC_2024.lookalike,
      chain: 'ethereum',
      callerHistory: [WBTC_2024.trusted],
      callerAddress: WBTC_2024.victim,
    });

    expect(provider.calls).toBe(0);
  });

  it('derives when callerHistory is present but empty', async () => {
    const provider = new RecordedTrustProvider();
    const result = await build(new FixedBlockProvider(1), provider).handle({
      address: WBTC_2024.lookalike,
      chain: 'ethereum',
      callerHistory: [],
      callerAddress: WBTC_2024.victim,
    });

    expect(provider.calls).toBe(1);
    expect(asResponse(result.body).risk_label).toBe('high_risk');
  });
});

describe('POST /risk-check — evidence block', () => {
  it('pins the block height and builds a deterministic canonical string', async () => {
    const result = await build(new FixedBlockProvider(19789008)).handle({
      address: WBTC_2024.lookalike,
      chain: 'ethereum',
      callerHistory: [WBTC_2024.trusted],
    });

    const body = asResponse(result.body);
    expect(body.evidence.checked_at_block).toBe(19789008);
    expect(body.evidence.canonical).toBe(
      `${WBTC_2024.lookalike}|ethereum|high_risk|19789008`,
    );
  });

  it('produces identical canonical strings for identical inputs', async () => {
    const handler = build(new FixedBlockProvider(19789008));
    const request = {
      address: WBTC_2024.lookalike,
      chain: 'ethereum' as const,
      callerHistory: [WBTC_2024.trusted],
    };

    const first = asResponse((await handler.handle(request)).body);
    const second = asResponse((await handler.handle(request)).body);

    expect(first.evidence.canonical).toBe(second.evidence.canonical);
    expect(first.risk_reason).toBe(second.risk_reason);
  });

  it('reports an unknown block as null and "unknown", not as 0', async () => {
    // A wrong block number in a field meant to make an answer reproducible is
    // worse than an absent one.
    const result = await build(new NullBlockProvider()).handle({
      address: WBTC_2024.lookalike,
      chain: 'base',
      callerHistory: [WBTC_2024.trusted],
    });

    const body = asResponse(result.body);
    expect(body.evidence.checked_at_block).toBeNull();
    expect(body.evidence.canonical).toContain('|unknown');
  });

  it('carries an evidence block even on insufficient_history', async () => {
    // An unverifiable answer still has to be pinnable, or it cannot be audited.
    const result = await build(new FixedBlockProvider(123)).handle({
      address: WBTC_2024.lookalike,
      chain: 'base',
    });

    const body = asResponse(result.body);
    expect(body.evidence.checked_at_block).toBe(123);
    expect(body.evidence.canonical).toBe(`${WBTC_2024.lookalike}|base|caution|123`);
  });

  it('emits an ISO-8601 timestamp', async () => {
    const result = await build().handle({ address: WBTC_2024.lookalike, chain: 'base' });
    const iso = asResponse(result.body).evidence.checked_at;

    expect(iso).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/);
    expect(new Date(iso).toISOString()).toBe(iso);
  });
});

describe('buildCanonical', () => {
  it('excludes the timestamp, so identical inputs hash identically', () => {
    // Including a clock would make every hash unique and destroy the
    // reproducibility the field exists to provide.
    const a = buildCanonical(WBTC_2024.lookalike, 'ethereum', 'high_risk', 100);
    const b = buildCanonical(WBTC_2024.lookalike, 'ethereum', 'high_risk', 100);
    expect(a).toBe(b);
    expect(a).not.toMatch(/\d{4}-\d{2}-\d{2}T/);
  });

  it('distinguishes chains, labels, and blocks', () => {
    const base: [string, Chain, string, number] = [WBTC_2024.lookalike, 'base', 'safe', 1];
    const canonical = buildCanonical(...base);

    expect(canonical).not.toBe(buildCanonical(WBTC_2024.lookalike, 'ethereum', 'safe', 1));
    expect(canonical).not.toBe(buildCanonical(WBTC_2024.lookalike, 'base', 'caution', 1));
    expect(canonical).not.toBe(buildCanonical(WBTC_2024.lookalike, 'base', 'safe', 2));
  });

  it('is lowercase regardless of input casing', () => {
    const canonical = buildCanonical(
      WBTC_2024.lookalike.toUpperCase().replace('0X', '0x'),
      'base',
      'safe',
      1,
    );
    expect(canonical).toBe(canonical.toLowerCase());
  });
});
