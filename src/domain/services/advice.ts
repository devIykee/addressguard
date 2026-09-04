import type {
  CounterpartySolvency,
  RecommendedAction,
  RiskLabel,
} from '../entities/index.ts';
import { isDistressed } from '../entities/index.ts';

/**
 * Combines the poisoning verdict and the solvency verdict into one advisory
 * action, without either overwriting the other.
 *
 * ## Why this is not a score
 *
 * The obvious implementation blends the two into a number. It is wrong, because
 * the two checks answer different questions and their errors are uncorrelated:
 *
 *   poisoning  — is this destination a lookalike of an identity you trust?
 *   solvency   — is this counterparty currently over-leveraged?
 *
 * A distressed borrower is not a poisoning attempt, and a poisoning address is
 * typically a fresh EOA with no lending position at all (verified: both incident
 * lookalikes return `no_position` from the upstream source). Averaging them
 * would let a healthy balance sheet dilute a lookalike match — the exact
 * inversion this miner exists to prevent.
 *
 * So the rule is a lattice, not a sum: take the most severe of the two, and let
 * the two "medium" signals combine.
 *
 * ## The rule
 *
 *   high_risk       + anything      -> block     poisoning is decisive
 *   any             + BLOCK         -> block     insolvency is decisive
 *   caution         + distress      -> block     two independent concerns
 *   caution         + anything else -> review
 *   safe            + distress      -> review    not a lookalike, still risky
 *   safe            + anything else -> proceed
 *
 * The `caution + distress -> block` row is the only one where the composition
 * says more than either input did. It is deliberate: `caution` already means a
 * borderline lookalike match or no history to check against, and an independently
 * distressed counterparty is a second reason to stop. Neither alone would block;
 * together they should.
 *
 * Pure and synchronous. Every row above is asserted by a test, so a future
 * retune fails loudly rather than silently reclassifying.
 */
export function composeAdvice(
  riskLabel: RiskLabel,
  solvency: CounterpartySolvency,
): RecommendedAction {
  if (riskLabel === 'high_risk') return 'block';
  if (solvency.state === 'assessed' && solvency.verdict === 'BLOCK') return 'block';

  if (riskLabel === 'caution') {
    return isDistressed(solvency) ? 'block' : 'review';
  }

  // riskLabel === 'safe': a real comparison ran and found no lookalike.
  return isDistressed(solvency) ? 'review' : 'proceed';
}

/**
 * A one-line, machine-parseable trace of what drove the action.
 *
 * Deliberately NOT merged into `risk_reason`. That field's grammar is
 * `poisoning_match:...` / `no_poisoning_match` / `insufficient_history`, and a
 * reader who sees a poisoning reason must be able to trust that a poisoning
 * check produced it. Mixing a solvency term into it would make the field lie
 * about which check fired.
 *
 *   poisoning=safe:solvency=RECHECK:action=review
 *   poisoning=high_risk:solvency=unavailable:action=block
 */
export function formatAdviceReason(
  riskLabel: RiskLabel,
  solvency: CounterpartySolvency,
  action: RecommendedAction,
): string {
  const solvencyTerm =
    solvency.state === 'assessed'
      ? solvency.verdict
      : solvency.state === 'no_position'
        ? 'no_position'
        : 'unavailable';

  return `poisoning=${riskLabel}:solvency=${solvencyTerm}:action=${action}`;
}
