import { describe, it, expect } from 'vitest';
import { composeAdvice, formatAdviceReason } from '../../src/domain/services/advice.ts';
import { isDistressed } from '../../src/domain/entities/index.ts';
import type {
  CounterpartySolvency,
  RecommendedAction,
  RiskLabel,
} from '../../src/domain/entities/index.ts';

/**
 * The composition rule between the two checks.
 *
 * Every row of the lattice documented on `composeAdvice` is asserted here, so a
 * future retune fails loudly instead of silently reclassifying. The rows that
 * matter most are the two the composition is *for*: `caution + distress` (which
 * escalates past what either input said) and every `high_risk` row (which must
 * not be softened by a healthy balance sheet).
 */

const UNAVAILABLE: CounterpartySolvency = { state: 'unavailable', reason: 'test' };

const NO_POSITION: CounterpartySolvency = {
  state: 'no_position',
  source: 'aave-v3-pool-contract',
  checkedAtBlock: 50_821_356,
};

const assessed = (
  verdict: 'ALLOW' | 'RECHECK' | 'BLOCK',
  healthFactor: number | null,
): CounterpartySolvency => ({
  state: 'assessed',
  source: 'aave-v3-pool-contract',
  verdict,
  reasoning: `test reasoning for ${verdict}`,
  healthFactor,
  checkedAtBlock: 50_821_356,
});

/** Live values, captured from production during integration. */
const HEALTHY = assessed('ALLOW', 1.5083);
const THIN = assessed('RECHECK', 1.33);
const INSOLVENT = assessed('BLOCK', 0.98);

const ALL_SOLVENCY: readonly CounterpartySolvency[] = [
  UNAVAILABLE,
  NO_POSITION,
  HEALTHY,
  THIN,
  INSOLVENT,
];

describe('isDistressed', () => {
  it('is true only for an assessed position with a non-ALLOW verdict', () => {
    expect(isDistressed(THIN)).toBe(true);
    expect(isDistressed(INSOLVENT)).toBe(true);
  });

  it('is false for a healthy position, no position, and an unavailable source', () => {
    // The last two are the important ones: "we could not ask" and "there is
    // nothing to assess" must never read as distress, or an outage would start
    // escalating every verdict.
    expect(isDistressed(HEALTHY)).toBe(false);
    expect(isDistressed(NO_POSITION)).toBe(false);
    expect(isDistressed(UNAVAILABLE)).toBe(false);
  });
});

describe('composeAdvice — poisoning stays decisive', () => {
  it('blocks on high_risk regardless of what the solvency source says', () => {
    // The inversion this guards against: a lookalike address belonging to a
    // well-collateralized borrower must not be talked down to `review` because
    // its balance sheet looks good. Poisoning is the question this miner answers.
    for (const solvency of ALL_SOLVENCY) {
      expect(composeAdvice('high_risk', solvency)).toBe('block');
    }
  });

  it('blocks on an insolvent counterparty regardless of the poisoning label', () => {
    for (const label of ['safe', 'caution', 'high_risk'] as const) {
      expect(composeAdvice(label, INSOLVENT)).toBe('block');
    }
  });
});

describe('composeAdvice — the full lattice', () => {
  const cases: readonly [RiskLabel, CounterpartySolvency, RecommendedAction, string][] = [
    ['safe', UNAVAILABLE, 'proceed', 'no lookalike, no second opinion'],
    ['safe', NO_POSITION, 'proceed', 'no lookalike, nothing to assess'],
    ['safe', HEALTHY, 'proceed', 'no lookalike, healthy counterparty'],
    ['safe', THIN, 'review', 'not a lookalike, but the counterparty is distressed'],
    ['safe', INSOLVENT, 'block', 'insolvency is decisive on its own'],

    ['caution', UNAVAILABLE, 'review', 'borderline, no second opinion'],
    ['caution', NO_POSITION, 'review', 'borderline, nothing to assess'],
    ['caution', HEALTHY, 'review', 'borderline, healthy counterparty'],
    ['caution', THIN, 'block', 'two independent concerns compound'],
    ['caution', INSOLVENT, 'block', 'insolvency is decisive'],

    ['high_risk', UNAVAILABLE, 'block', 'strong lookalike match'],
    ['high_risk', NO_POSITION, 'block', 'strong lookalike match'],
    ['high_risk', HEALTHY, 'block', 'a healthy balance sheet cannot soften this'],
    ['high_risk', THIN, 'block', 'strong lookalike match'],
    ['high_risk', INSOLVENT, 'block', 'both checks fired'],
  ];

  for (const [label, solvency, expected, why] of cases) {
    const term = solvency.state === 'assessed' ? solvency.verdict : solvency.state;
    it(`${label} + ${term} -> ${expected} (${why})`, () => {
      expect(composeAdvice(label, solvency)).toBe(expected);
    });
  }

  it('covers every combination of label and solvency state', () => {
    // Guards the table itself: 3 labels x 5 solvency shapes. A new label or a
    // new solvency state that nobody thought to compose would fail here rather
    // than silently falling through to a default.
    expect(cases).toHaveLength(3 * ALL_SOLVENCY.length);
  });
});

describe('composeAdvice — an unavailable source never escalates', () => {
  it('produces the same action as a healthy counterparty for every label', () => {
    // Stated as a property rather than three rows: if a third party's outage
    // could tighten this miner's advice, its uptime would become this miner's
    // false-positive rate.
    for (const label of ['safe', 'caution', 'high_risk'] as const) {
      expect(composeAdvice(label, UNAVAILABLE)).toBe(composeAdvice(label, HEALTHY));
    }
  });
});

describe('formatAdviceReason', () => {
  it('names both inputs and the resulting action', () => {
    expect(formatAdviceReason('safe', THIN, 'review')).toBe(
      'poisoning=safe:solvency=RECHECK:action=review',
    );
  });

  it('distinguishes an unavailable source from a source reporting no position', () => {
    expect(formatAdviceReason('safe', UNAVAILABLE, 'proceed')).toBe(
      'poisoning=safe:solvency=unavailable:action=proceed',
    );
    expect(formatAdviceReason('safe', NO_POSITION, 'proceed')).toBe(
      'poisoning=safe:solvency=no_position:action=proceed',
    );
  });

  it('never emits the poisoning reason grammar', () => {
    // `risk_reason` means "a poisoning check produced this". If the advice
    // string could be mistaken for one, a reader could attribute a solvency
    // finding to a check that never ran.
    for (const solvency of ALL_SOLVENCY) {
      const action = composeAdvice('caution', solvency);
      const reason = formatAdviceReason('caution', solvency, action);
      expect(reason).not.toContain('poisoning_match');
      expect(reason).not.toContain('insufficient_history');
      expect(reason).not.toContain('no_poisoning_match');
    }
  });
});
