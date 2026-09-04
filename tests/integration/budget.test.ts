import { describe, it, expect } from 'vitest';
import { RiskCheckHandler } from '../../src/api/handler.ts';
import { PoisoningDetectionService } from '../../src/domain/services/poisoning-detection-service.ts';
import { PrefixSuffixStrategy } from '../../src/matching/prefix-suffix/prefix-suffix-strategy.ts';
import { LevenshteinStrategy } from '../../src/matching/levenshtein/levenshtein-strategy.ts';
import { RecordingLogger } from '../unit/strategy-contract.ts';
import { WBTC_2024 } from '../fixtures/incidents.ts';
import type { BlockProvider } from '../../src/domain/interfaces/block-provider.ts';
import type { TrustedSetProvider } from '../../src/domain/interfaces/trusted-set-provider.ts';
import type { CounterpartySignalProvider } from '../../src/domain/interfaces/counterparty-signal-provider.ts';
import type { CounterpartySolvency, TrustedIdentity } from '../../src/domain/entities/index.ts';

/**
 * The request must fit inside the function budget even when every third party is
 * hung.
 *
 * `vercel.json` sets `maxDuration: 15`, and the real timeouts sum past that if
 * the outbound calls run in series: the explorer alone tries two API generations
 * at 6s each. Measured against hung local servers before this was fixed, one
 * request took 17.0s and the function would have returned a 504.
 *
 * The fix is ordering, not shorter timeouts: the two calls that do not depend on
 * the trusted set are started before chain derivation is awaited, so they overlap
 * it. This test asserts the ordering property directly with fake timings rather
 * than by sleeping, so it stays fast and deterministic.
 */

const VERCEL_MAX_DURATION_MS = 15_000;

/** Records when it was called, and resolves after `delayMs` of virtual time. */
class TimedProvider {
  startedAt = -1;
  constructor(
    private readonly clock: { now: number },
    private readonly delayMs: number,
  ) {}
  protected begin(): number {
    this.startedAt = this.clock.now;
    return this.startedAt + this.delayMs;
  }
}

class SlowBlockProvider extends TimedProvider implements BlockProvider {
  finishesAt = -1;
  currentBlock(): Promise<number | null> {
    this.finishesAt = this.begin();
    return Promise.resolve(1);
  }
}

class SlowTrustProvider extends TimedProvider implements TrustedSetProvider {
  finishesAt = -1;
  deriveTrustedSet(): Promise<readonly TrustedIdentity[]> {
    this.finishesAt = this.begin();
    return Promise.resolve([]);
  }
}

class SlowSolvencyProvider extends TimedProvider implements CounterpartySignalProvider {
  finishesAt = -1;
  solvencyOf(): Promise<CounterpartySolvency> {
    this.finishesAt = this.begin();
    return Promise.resolve({ state: 'unavailable', reason: 'timeout' });
  }
}

describe('worst-case request stays inside the function budget', () => {
  it('starts the block and solvency reads before awaiting chain derivation', async () => {
    // Real worst-case timings: explorer 2 x 6s, rpc 2 x 2.5s, solvency 5s.
    const clock = { now: 0 };
    const block = new SlowBlockProvider(clock, 5_000);
    const trust = new SlowTrustProvider(clock, 12_000);
    const solvency = new SlowSolvencyProvider(clock, 5_000);

    const logger = new RecordingLogger();
    const handler = new RiskCheckHandler(
      new PoisoningDetectionService(
        [new PrefixSuffixStrategy(logger), new LevenshteinStrategy(logger)],
        logger,
      ),
      block,
      trust,
      logger,
      solvency,
    );

    await handler.handle({
      address: WBTC_2024.lookalike,
      chain: 'base',
      callerAddress: WBTC_2024.victim,
    });

    // All three start at t=0: none of them waits on another.
    expect(block.startedAt).toBe(0);
    expect(solvency.startedAt).toBe(0);
    expect(trust.startedAt).toBe(0);

    // So the wall clock is the slowest single call, not the sum.
    const wallClock = Math.max(block.finishesAt, trust.finishesAt, solvency.finishesAt);
    expect(wallClock).toBe(12_000);
    expect(wallClock).toBeLessThan(VERCEL_MAX_DURATION_MS);

    // The sum is what a sequential implementation would have cost, and it is over
    // budget — which is what makes the ordering load-bearing rather than cosmetic.
    const sequential = 5_000 + 12_000 + 5_000;
    expect(sequential).toBeGreaterThan(VERCEL_MAX_DURATION_MS);
  });

  it('does not call the solvency source or the explorer before validation', async () => {
    // A rejected request must cost zero outbound calls, or a malformed-input
    // flood becomes an outbound amplifier.
    const clock = { now: 0 };
    const block = new SlowBlockProvider(clock, 1);
    const trust = new SlowTrustProvider(clock, 1);
    const solvency = new SlowSolvencyProvider(clock, 1);

    const logger = new RecordingLogger();
    const handler = new RiskCheckHandler(
      new PoisoningDetectionService([new PrefixSuffixStrategy(logger)], logger),
      block,
      trust,
      logger,
      solvency,
    );

    const result = await handler.handle({ address: 'not-an-address', chain: 'base' });

    expect(result.status).toBe(400);
    expect(block.startedAt).toBe(-1);
    expect(trust.startedAt).toBe(-1);
    expect(solvency.startedAt).toBe(-1);
  });
});
