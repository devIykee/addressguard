import { describe, it, expect } from 'vitest';
import {
  LevenshteinStrategy,
  levenshtein,
} from '../../src/matching/levenshtein/levenshtein-strategy.ts';
import { PrefixSuffixStrategy } from '../../src/matching/prefix-suffix/prefix-suffix-strategy.ts';
import { describeStrategyContract, RecordingLogger } from './strategy-contract.ts';
import { WBTC_2024, USDT_2025, UNRELATED_PAIRS } from '../fixtures/incidents.ts';
import {
  HIGH_RISK_AT,
  PREFIX_SUFFIX_FLOOR,
  LEV_LIFT_WEIGHT,
  LEV_MAX_ALONE,
  ADDRESS_BODY_LENGTH,
} from '../../config/thresholds.ts';

describeStrategyContract('LevenshteinStrategy', (logger) => new LevenshteinStrategy(logger));

const strategy = (): LevenshteinStrategy => new LevenshteinStrategy(new RecordingLogger());

describe('LevenshteinStrategy — real incidents', () => {
  it('measures both incident pairs at edit distance 27', () => {
    expect(levenshtein(WBTC_2024.trusted.slice(2), WBTC_2024.lookalike.slice(2))).toBe(27);
    expect(levenshtein(USDT_2025.trusted.slice(2), USDT_2025.lookalike.slice(2))).toBe(27);
  });

  it('scores both incident pairs 0.325', () => {
    expect(strategy().score(WBTC_2024.trusted, WBTC_2024.lookalike)).toBeCloseTo(0.325, 6);
    expect(strategy().score(USDT_2025.trusted, USDT_2025.lookalike)).toBeCloseTo(0.325, 6);
  });

  it('scores unrelated controls at most 0.125', () => {
    for (const pair of UNRELATED_PAIRS) {
      expect(strategy().score(pair.a, pair.b), pair.label).toBeLessThanOrEqual(0.125);
    }
  });

  it('separates real pairs from controls by only ~0.2 — the reason for the cap', () => {
    // This is the measurement that justifies LEV_MAX_ALONE. It is asserted
    // rather than described so that if a future change to the metric widens or
    // narrows this gap, the assumption behind the cap is re-examined.
    const worstIncident = Math.min(
      strategy().score(WBTC_2024.trusted, WBTC_2024.lookalike),
      strategy().score(USDT_2025.trusted, USDT_2025.lookalike),
    );
    const bestControl = Math.max(
      ...UNRELATED_PAIRS.map((p) => strategy().score(p.a, p.b)),
    );

    expect(worstIncident - bestControl).toBeLessThan(0.25);
    // And real attacks score below the midpoint of this metric's own scale,
    // which no authoritative signal should do.
    expect(worstIncident).toBeLessThan(0.5);
  });
});

describe('LevenshteinStrategy — the cap is load-bearing, not decorative', () => {
  /**
   * A shifted variant: one character inserted near the front, which pushes
   * every later character out of alignment. Edit distance stays tiny while the
   * visible suffix no longer matches at all.
   */
  const shifted = (address: string): string => {
    const body = address.slice(2);
    return `0x${body.slice(0, 3)}5${body.slice(3, ADDRESS_BODY_LENGTH - 1)}`;
  };

  it('scores an end-shifted variant 0.95 where prefix/suffix scores 0', () => {
    const variant = shifted(WBTC_2024.trusted);
    const lev = strategy().score(WBTC_2024.trusted, variant);
    const prefixSuffix = new PrefixSuffixStrategy(new RecordingLogger()).score(
      WBTC_2024.trusted,
      variant,
    );

    expect(lev).toBeCloseTo(0.95, 6);
    expect(prefixSuffix).toBe(0);
  });

  it('that 0.95 exceeds HIGH_RISK_AT — so an uncapped score would misfire', () => {
    // The failure this defends against, stated as an assertion: a pair whose
    // visible ends differ (so no wallet UI would confuse them) scoring above
    // the high_risk threshold on edit distance alone.
    const lev = strategy().score(WBTC_2024.trusted, shifted(WBTC_2024.trusted));
    expect(lev).toBeGreaterThan(HIGH_RISK_AT);
  });

  it('LEV_MAX_ALONE sits below HIGH_RISK_AT, so the cap binds', () => {
    // If a retune ever raised LEV_MAX_ALONE to or above HIGH_RISK_AT, the cap
    // would silently stop capping. This asserts the ordering itself.
    expect(LEV_MAX_ALONE).toBeLessThan(HIGH_RISK_AT);
  });
});

describe('LEV_LIFT_WEIGHT — derived bounds hold', () => {
  const levScore = (a: string, b: string): number => strategy().score(a, b);

  it('lifts the USDT 2025 fixture from the floor over HIGH_RISK_AT', () => {
    const lifted =
      PREFIX_SUFFIX_FLOOR + LEV_LIFT_WEIGHT * levScore(USDT_2025.trusted, USDT_2025.lookalike);
    expect(lifted).toBeGreaterThanOrEqual(HIGH_RISK_AT);
    expect(lifted).toBeCloseTo(0.815, 6);
  });

  it('does not let a control-strength Levenshtein signal lift a floor match over the line', () => {
    const bestControl = Math.max(...UNRELATED_PAIRS.map((p) => levScore(p.a, p.b)));
    const lifted = PREFIX_SUFFIX_FLOOR + LEV_LIFT_WEIGHT * bestControl;
    expect(lifted).toBeLessThan(HIGH_RISK_AT);
    expect(lifted).toBeCloseTo(0.775, 6);
  });
});

describe('levenshtein', () => {
  it('returns 0 for identical strings', () => {
    expect(levenshtein('abc', 'abc')).toBe(0);
    expect(levenshtein('', '')).toBe(0);
  });

  it('returns the other length when one side is empty', () => {
    expect(levenshtein('', 'abcd')).toBe(4);
    expect(levenshtein('abcd', '')).toBe(4);
  });

  it('counts single-character edits', () => {
    expect(levenshtein('abc', 'abd')).toBe(1); // substitution
    expect(levenshtein('abc', 'abcd')).toBe(1); // insertion
    expect(levenshtein('abcd', 'abc')).toBe(1); // deletion
  });

  it('matches known values', () => {
    expect(levenshtein('kitten', 'sitting')).toBe(3);
    expect(levenshtein('flaw', 'lawn')).toBe(2);
  });

  it('is symmetric', () => {
    expect(levenshtein('kitten', 'sitting')).toBe(levenshtein('sitting', 'kitten'));
  });

  it('never exceeds the longer length', () => {
    expect(levenshtein('1'.repeat(40), '2'.repeat(40))).toBeLessThanOrEqual(40);
  });
});
