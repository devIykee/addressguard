import { describe, it, expect } from 'vitest';
import {
  PoisoningDetectionService,
  REASON_INSUFFICIENT_HISTORY,
  REASON_NO_MATCH,
} from '../../src/domain/services/poisoning-detection-service.ts';
import { PrefixSuffixStrategy } from '../../src/matching/prefix-suffix/prefix-suffix-strategy.ts';
import { LevenshteinStrategy } from '../../src/matching/levenshtein/levenshtein-strategy.ts';
import { RecordingLogger } from './strategy-contract.ts';
import { WBTC_2024, USDT_2025, UNRELATED_PAIRS } from '../fixtures/incidents.ts';
import type {
  SimilarityStrategy,
  StrategyAuthority,
} from '../../src/domain/interfaces/similarity-strategy.ts';
import type { MatchType, TrustedIdentity } from '../../src/domain/entities/index.ts';
import {
  HIGH_RISK_AT,
  CAUTION_AT,
  LEV_MAX_ALONE,
  INSUFFICIENT_HISTORY_CONFIDENCE,
  NO_MATCH_CONFIDENCE,
} from '../../config/thresholds.ts';

/** A strategy returning a fixed score, so aggregation is tested in isolation. */
class StubStrategy implements SimilarityStrategy {
  constructor(
    readonly matchType: MatchType,
    readonly authority: StrategyAuthority,
    private readonly fixedScore: number,
    readonly name = `stub-${matchType}`,
  ) {}
  score(): number {
    return this.fixedScore;
  }
}

const supplied = (...addresses: string[]): TrustedIdentity[] =>
  addresses.map((identity) => ({ identity, source: 'caller_supplied' }));

const realService = (): PoisoningDetectionService => {
  const logger = new RecordingLogger();
  return new PoisoningDetectionService(
    [new PrefixSuffixStrategy(logger), new LevenshteinStrategy(logger)],
    logger,
  );
};

describe('PoisoningDetectionService — real incidents end to end', () => {
  it('labels the WBTC 2024 lookalike high_risk', () => {
    const result = realService().check(WBTC_2024.lookalike, supplied(WBTC_2024.trusted));

    expect(result.riskLabel).toBe('high_risk');
    expect(result.match?.matchedAgainst).toBe(WBTC_2024.trusted);
    expect(result.match?.matchType).toBe('prefix_suffix');
    expect(result.trustedSetSize).toBe(1);
  });

  it('labels the USDT 2025 lookalike high_risk only via corroboration', () => {
    // Prefix/suffix alone scores this exactly 0.75 — caution. It reaches
    // high_risk only because Levenshtein lifts it. Asserted numerically so the
    // combination rule cannot silently stop mattering.
    const result = realService().check(USDT_2025.lookalike, supplied(USDT_2025.trusted));

    expect(result.riskLabel).toBe('high_risk');
    expect(result.riskConfidence).toBeCloseTo(0.815, 4);
  });

  it('names BOTH signals with their own scores in risk_reason', () => {
    // Traceability: a reader must be able to see why the verdict crossed, not
    // just that it did. For the USDT case that means seeing a floor-level
    // prefix/suffix score next to the corroborating Levenshtein score — the two
    // numbers that explain the 0.815.
    const result = realService().check(USDT_2025.lookalike, supplied(USDT_2025.trusted));

    expect(result.riskReason).toContain('poisoning_match');
    expect(result.riskReason).toContain('similarity=0.8150');
    expect(result.riskReason).toContain('prefix_suffix=0.7500');
    expect(result.riskReason).toContain('full_levenshtein=0.3250');
    // The matched identity is abbreviated the way a wallet UI would show it —
    // the same truncation the attack exploits.
    expect(result.riskReason).toContain('0x2c11...9c0b');
  });

  it('names both signals for the WBTC case too', () => {
    const result = realService().check(WBTC_2024.lookalike, supplied(WBTC_2024.trusted));

    expect(result.riskReason).toContain('prefix_suffix=0.8125');
    expect(result.riskReason).toContain('full_levenshtein=0.3250');
    expect(result.riskReason).toContain('similarity=0.8775');
  });

  it('produces a byte-identical reason string for identical inputs', () => {
    const first = realService().check(WBTC_2024.lookalike, supplied(WBTC_2024.trusted));
    const second = realService().check(WBTC_2024.lookalike, supplied(WBTC_2024.trusted));
    expect(first.riskReason).toBe(second.riskReason);
  });

  it('labels the victim address itself safe against its own trusted set', () => {
    // The victim's own address is unrelated to what it pays. A detector firing
    // here would flag ordinary legitimate payments.
    const result = realService().check(WBTC_2024.victim, supplied(WBTC_2024.trusted));
    expect(result.riskLabel).toBe('safe');
    expect(result.riskReason).toBe(REASON_NO_MATCH);
  });

  it('labels unrelated addresses safe with high confidence', () => {
    for (const pair of UNRELATED_PAIRS) {
      const result = realService().check(pair.a, supplied(pair.b));
      expect(result.riskLabel, pair.label).toBe('safe');
      expect(result.riskConfidence).toBe(NO_MATCH_CONFIDENCE);
      expect(result.match).toBeNull();
    }
  });

  it('finds the lookalike among a trusted set of mostly unrelated addresses', () => {
    const result = realService().check(
      WBTC_2024.lookalike,
      supplied(
        USDT_2025.victim,
        UNRELATED_PAIRS[1].a,
        WBTC_2024.trusted, // the only real match, deliberately last
        USDT_2025.trusted,
      ),
    );

    expect(result.riskLabel).toBe('high_risk');
    expect(result.match?.matchedAgainst).toBe(WBTC_2024.trusted);
    expect(result.trustedSetSize).toBe(4);
  });
});

describe('PoisoningDetectionService — exact-match exclusion', () => {
  it('does not treat an address identical to a trusted entry as poisoning', () => {
    // An exact match is an address the caller already legitimately uses. This
    // is the single most important false positive to avoid: flagging the user's
    // own known-good counterparty as an impersonation of itself.
    const result = realService().check(WBTC_2024.trusted, supplied(WBTC_2024.trusted));

    expect(result.riskLabel).not.toBe('high_risk');
    expect(result.match).toBeNull();
  });

  it('reports insufficient_history when the trusted set holds only the candidate', () => {
    // After excluding the identity, nothing comparable is left — so the honest
    // answer is "no check ran", not "safe".
    const result = realService().check(WBTC_2024.trusted, supplied(WBTC_2024.trusted));

    expect(result.riskLabel).toBe('caution');
    expect(result.riskReason).toBe(REASON_INSUFFICIENT_HISTORY);
    expect(result.trustedSetSize).toBe(0);
  });

  it('excludes the identity but still checks the rest of the set', () => {
    const result = realService().check(
      WBTC_2024.lookalike,
      supplied(WBTC_2024.lookalike, WBTC_2024.trusted),
    );

    expect(result.riskLabel).toBe('high_risk');
    expect(result.match?.matchedAgainst).toBe(WBTC_2024.trusted);
    expect(result.trustedSetSize).toBe(1);
  });

  it('excludes on normalized form, so EIP-55 casing is still an exact match', () => {
    const checksummed = WBTC_2024.trusted.toUpperCase().replace('0X', '0x');
    const result = realService().check(checksummed, supplied(WBTC_2024.trusted));

    expect(result.match).toBeNull();
    expect(result.riskReason).toBe(REASON_INSUFFICIENT_HISTORY);
  });
});

describe('PoisoningDetectionService — insufficient history is never safe', () => {
  it('returns caution for an empty trusted set', () => {
    const result = realService().check(WBTC_2024.lookalike, []);

    expect(result.riskLabel).toBe('caution');
    expect(result.riskReason).toBe(REASON_INSUFFICIENT_HISTORY);
    expect(result.riskConfidence).toBe(INSUFFICIENT_HISTORY_CONFIDENCE);
    expect(result.match).toBeNull();
  });

  it('never returns safe without a non-empty comparable set', () => {
    // Stated as an invariant rather than a single case: `safe` requires that a
    // comparison actually happened.
    for (const trustedSet of [[], supplied(WBTC_2024.lookalike)]) {
      const result = realService().check(WBTC_2024.lookalike, trustedSet);
      expect(result.riskLabel).not.toBe('safe');
    }
  });

  it('does not throw when the trusted set contains malformed entries', () => {
    // One bad entry must not fail the request. The good entry must still match.
    const result = realService().check(
      WBTC_2024.lookalike,
      supplied('', 'not-an-address', '0x', WBTC_2024.trusted),
    );

    expect(result.riskLabel).toBe('high_risk');
    expect(result.match?.matchedAgainst).toBe(WBTC_2024.trusted);
  });

  it('returns safe rather than crashing when every entry is malformed', () => {
    const result = realService().check(WBTC_2024.lookalike, supplied('', 'nope', '0x00'));
    expect(result.riskLabel).toBe('safe');
    expect(result.riskReason).toBe(REASON_NO_MATCH);
  });
});

describe('PoisoningDetectionService — corroborating signals cannot assert high_risk', () => {
  const corroboratingOnly = (score: number): PoisoningDetectionService => {
    const logger = new RecordingLogger();
    return new PoisoningDetectionService(
      [new StubStrategy('full_levenshtein', 'corroborating', score)],
      logger,
    );
  };

  it('caps a 0.95 Levenshtein-only score below high_risk', () => {
    // The concrete misfire this defends against: an end-shifted variant scores
    // 0.95 on edit distance while prefix/suffix correctly scores 0, because the
    // visible ends no longer align. Uncapped, that asserts high_risk on a pair
    // no wallet UI would confuse.
    const result = corroboratingOnly(0.95).check(
      WBTC_2024.lookalike,
      supplied(WBTC_2024.trusted),
    );

    expect(result.riskLabel).toBe('caution');
    expect(result.riskConfidence).toBe(LEV_MAX_ALONE);
  });

  it('caps even a perfect 1.0 corroborating score below high_risk', () => {
    const result = corroboratingOnly(1).check(WBTC_2024.lookalike, supplied(WBTC_2024.trusted));

    expect(result.riskLabel).toBe('caution');
    expect(result.riskConfidence).toBeLessThan(HIGH_RISK_AT);
  });

  it('never reaches high_risk for any corroborating-only score', () => {
    // Swept rather than sampled: no value of a corroborating signal alone may
    // produce the strongest verdict.
    for (let score = 0; score <= 1.0001; score += 0.05) {
      const result = corroboratingOnly(Math.min(score, 1)).check(
        WBTC_2024.lookalike,
        supplied(WBTC_2024.trusted),
      );
      expect(result.riskLabel, `score=${score.toFixed(2)}`).not.toBe('high_risk');
    }
  });

  it('still surfaces the match, so a capped verdict is not a silent one', () => {
    const result = corroboratingOnly(0.95).check(
      WBTC_2024.lookalike,
      supplied(WBTC_2024.trusted),
    );

    expect(result.match).not.toBeNull();
    expect(result.match?.matchType).toBe('full_levenshtein');
    expect(result.riskReason).toContain('full_levenshtein=0.9500');
  });

  it('a primary signal at the same score DOES reach high_risk', () => {
    // The contrast that proves the cap is about authority, not magnitude.
    const logger = new RecordingLogger();
    const service = new PoisoningDetectionService(
      [new StubStrategy('prefix_suffix', 'primary', 0.95)],
      logger,
    );
    const result = service.check(WBTC_2024.lookalike, supplied(WBTC_2024.trusted));

    expect(result.riskLabel).toBe('high_risk');
  });
});

describe('PoisoningDetectionService — aggregation is strategy-agnostic', () => {
  it('picks the strongest match across several trusted identities', () => {
    const logger = new RecordingLogger();
    // A strategy that scores by position in the trusted set, so the expected
    // winner is unambiguous and independent of any similarity formula.
    const positional: SimilarityStrategy = {
      matchType: 'prefix_suffix',
      name: 'positional',
      authority: 'primary',
      score: (_candidate, trusted) => (trusted === USDT_2025.trusted ? 0.9 : 0.6),
    };
    const service = new PoisoningDetectionService([positional], logger);

    const result = service.check(
      WBTC_2024.lookalike,
      supplied(WBTC_2024.trusted, USDT_2025.trusted, UNRELATED_PAIRS[1].a),
    );

    expect(result.match?.matchedAgainst).toBe(USDT_2025.trusted);
    expect(result.riskConfidence).toBe(0.9);
  });

  it('works with zero strategies injected, returning safe rather than throwing', () => {
    // Degenerate but reachable via misconfiguration. It must not claim a
    // verdict it has no means to compute — and it must not crash.
    const service = new PoisoningDetectionService([], new RecordingLogger());
    const result = service.check(WBTC_2024.lookalike, supplied(WBTC_2024.trusted));

    expect(result.riskLabel).toBe('safe');
    expect(result.match).toBeNull();
  });

  it('accepts a new strategy without any change to the service', () => {
    // Open/Closed, demonstrated: a third match type flows through aggregation,
    // labelling, and reason formatting with no edits to the service.
    const logger = new RecordingLogger();
    const service = new PoisoningDetectionService(
      [new StubStrategy('ens_homoglyph', 'primary', 0.88)],
      logger,
    );
    const result = service.check(WBTC_2024.lookalike, supplied(WBTC_2024.trusted));

    expect(result.riskLabel).toBe('high_risk');
    expect(result.match?.matchType).toBe('ens_homoglyph');
    expect(result.riskReason).toContain('ens_homoglyph=0.8800');
  });

  it('preserves the trust source on the match', () => {
    const logger = new RecordingLogger();
    const service = new PoisoningDetectionService(
      [new StubStrategy('prefix_suffix', 'primary', 0.9)],
      logger,
    );
    const result = service.check(WBTC_2024.lookalike, [
      { identity: WBTC_2024.trusted, source: 'chain_derived' },
    ]);

    expect(result.match?.source).toBe('chain_derived');
  });
});

describe('PoisoningDetectionService — label boundaries', () => {
  const atScore = (score: number): PoisoningDetectionService =>
    new PoisoningDetectionService(
      [new StubStrategy('prefix_suffix', 'primary', score)],
      new RecordingLogger(),
    );

  const labelAt = (score: number): string =>
    atScore(score).check(WBTC_2024.lookalike, supplied(WBTC_2024.trusted)).riskLabel;

  it('is safe just below CAUTION_AT and caution at it', () => {
    expect(labelAt(CAUTION_AT - 0.0001)).toBe('safe');
    expect(labelAt(CAUTION_AT)).toBe('caution');
  });

  it('is caution just below HIGH_RISK_AT and high_risk at it', () => {
    expect(labelAt(HIGH_RISK_AT - 0.0001)).toBe('caution');
    expect(labelAt(HIGH_RISK_AT)).toBe('high_risk');
  });

  it('reports confidence rounded to four places, never above 1', () => {
    const result = atScore(1).check(WBTC_2024.lookalike, supplied(WBTC_2024.trusted));
    expect(result.riskConfidence).toBeLessThanOrEqual(1);
  });
});
