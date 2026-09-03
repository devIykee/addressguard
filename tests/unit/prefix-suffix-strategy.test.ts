import { describe, it, expect } from 'vitest';
import {
  PrefixSuffixStrategy,
  endOverlap,
} from '../../src/matching/prefix-suffix/prefix-suffix-strategy.ts';
import { describeStrategyContract, RecordingLogger } from './strategy-contract.ts';
import { WBTC_2024, USDT_2025, UNRELATED_PAIRS } from '../fixtures/incidents.ts';
import {
  PREFIX_SUFFIX_FLOOR,
  HIGH_RISK_AT,
  CAUTION_AT,
  MIN_PREFIX_CHARS,
  MIN_SUFFIX_CHARS,
} from '../../config/thresholds.ts';

describeStrategyContract('PrefixSuffixStrategy', (logger) => new PrefixSuffixStrategy(logger));

const strategy = (): PrefixSuffixStrategy => new PrefixSuffixStrategy(new RecordingLogger());

describe('PrefixSuffixStrategy — real incidents', () => {
  it('measures the WBTC 2024 overlap as (4, 6)', () => {
    // Asserted on the counter directly, not just via the score, so a counting
    // regression reads as a counting bug rather than a mysterious score shift.
    const overlap = endOverlap(WBTC_2024.trusted.slice(2), WBTC_2024.lookalike.slice(2));
    expect(overlap).toEqual({ prefix: WBTC_2024.prefix, suffix: WBTC_2024.suffix });
  });

  it('measures the USDT 2025 overlap as (4, 4)', () => {
    const overlap = endOverlap(USDT_2025.trusted.slice(2), USDT_2025.lookalike.slice(2));
    expect(overlap).toEqual({ prefix: USDT_2025.prefix, suffix: USDT_2025.suffix });
  });

  it('scores the WBTC 2024 pair (d=10) into high_risk on its own', () => {
    const score = strategy().score(WBTC_2024.trusted, WBTC_2024.lookalike);
    expect(score).toBeCloseTo(0.8125, 4);
    expect(score).toBeGreaterThanOrEqual(HIGH_RISK_AT);
  });

  it('scores the USDT 2025 pair (d=8) at exactly the floor — caution, not high_risk', () => {
    // This is the load-bearing case for the combination rule: the harder real
    // incident does NOT reach high_risk on prefix/suffix alone. It gets there
    // only once Levenshtein corroborates, which is tested in the service suite.
    const score = strategy().score(USDT_2025.trusted, USDT_2025.lookalike);
    expect(score).toBeCloseTo(PREFIX_SUFFIX_FLOOR, 6);
    expect(score).toBeLessThan(HIGH_RISK_AT);
    expect(score).toBeGreaterThanOrEqual(CAUTION_AT);
  });

  it('scores every unrelated pair 0', () => {
    for (const pair of UNRELATED_PAIRS) {
      expect(strategy().score(pair.a, pair.b), pair.label).toBe(0);
    }
  });

  it('does not treat the victim and its own trusted counterparty as a match', () => {
    // The victim's address and the address it pays are unrelated strings; a
    // detector that scored them would fire on ordinary legitimate payments.
    for (const incident of [WBTC_2024, USDT_2025]) {
      expect(strategy().score(incident.victim, incident.trusted), incident.label).toBe(0);
    }
  });
});

describe('PrefixSuffixStrategy — detection floor', () => {
  const body = (prefix: string, middle: string, suffix: string): string =>
    `0x${prefix}${middle}${suffix}`;

  /** Builds a pair with exactly the requested end overlap and a differing middle. */
  const pair = (prefixLen: number, suffixLen: number): [string, string] => {
    const p = 'abcdef0123456789'.slice(0, prefixLen);
    const s = 'fedcba9876543210'.slice(0, suffixLen);
    const midLen = 40 - prefixLen - suffixLen;
    const a = body(p, '1'.repeat(midLen), s);
    const b = body(p, '2'.repeat(midLen), s);
    return [a, b];
  };

  it('scores 0 just below the prefix floor', () => {
    const [a, b] = pair(MIN_PREFIX_CHARS - 1, MIN_SUFFIX_CHARS + 2);
    expect(strategy().score(a, b)).toBe(0);
  });

  it('scores 0 just below the suffix floor', () => {
    const [a, b] = pair(MIN_PREFIX_CHARS + 2, MIN_SUFFIX_CHARS - 1);
    expect(strategy().score(a, b)).toBe(0);
  });

  it('scores at the floor value once both minimums are met', () => {
    const [a, b] = pair(MIN_PREFIX_CHARS, MIN_SUFFIX_CHARS);
    expect(strategy().score(a, b)).toBeCloseTo(PREFIX_SUFFIX_FLOOR, 6);
  });

  it('ramps monotonically with total overlap and saturates at 1.0', () => {
    const scores: number[] = [];
    for (let suffixLen = MIN_SUFFIX_CHARS; suffixLen <= 16; suffixLen += 1) {
      const [a, b] = pair(MIN_PREFIX_CHARS, suffixLen);
      scores.push(strategy().score(a, b));
    }

    for (let i = 1; i < scores.length; i += 1) {
      expect(scores[i]!, `d step ${i}`).toBeGreaterThanOrEqual(scores[i - 1]!);
    }
    expect(scores.at(-1)).toBe(1);
  });

  it('never exceeds 1.0 for a near-identical pair', () => {
    // 39 of 40 characters shared: an absurd amount of mining, but the score
    // must stay normalized rather than running past the top of the scale.
    const a = `0x${'a'.repeat(39)}1`;
    const b = `0x${'a'.repeat(39)}2`;
    expect(strategy().score(a, b)).toBeLessThanOrEqual(1);
  });
});

describe('endOverlap', () => {
  it('does not double-count an identical pair', () => {
    // Forwards and backwards scans would each traverse the whole string,
    // reporting d=80 for a 40-character body. The identity case belongs to the
    // aggregator, but the counter still has to stay meaningful.
    const overlap = endOverlap('a'.repeat(40), 'a'.repeat(40));
    expect(overlap.prefix + overlap.suffix).toBeLessThanOrEqual(40);
  });

  it('reports zero overlap for fully differing strings', () => {
    expect(endOverlap('1'.repeat(40), '2'.repeat(40))).toEqual({ prefix: 0, suffix: 0 });
  });

  it('handles empty input', () => {
    expect(endOverlap('', '')).toEqual({ prefix: 0, suffix: 0 });
  });
});
