import type {
  Chain,
  CounterpartySolvency,
  OnChainEvidence,
  RecommendedAction,
  RiskCheckResult,
} from '../domain/entities/index.ts';
import { abbreviate } from '../domain/address.ts';
import { composeAdvice, formatAdviceReason } from '../domain/services/advice.ts';

/**
 * The wire response.
 *
 * `risk_label`, `risk_confidence`, and `risk_reason` are flat and top-level
 * because that is what Telegraph's `signal_mapping` reads — a nested field
 * cannot be named there. Everything Tier 2 adds goes inside `detail` or
 * `onchain_evidence`, so the three fields the protocol parses never move.
 *
 * snake_case throughout, matching the request contract and the YAML schema.
 */
export interface RiskCheckResponse {
  readonly address: string;
  readonly risk_label: RiskCheckResult['riskLabel'];
  readonly risk_confidence: number;
  readonly risk_reason: string;
  readonly detail: {
    readonly matched_against: string | null;
    readonly match_type: string | null;
    readonly similarity_score: number;
    /** How many trusted identities were actually compared against. */
    readonly trusted_set_size: number;
    /**
     * Where the trusted set came from. `none` when nothing was available, which
     * is the case that must never be reported as `safe`.
     */
    readonly trust_source: 'caller_supplied' | 'chain_derived' | 'mixed' | 'none';
  };
  /**
   * An independent second opinion on the destination, from an external miner
   * answering a different question: is this counterparty financially distressed?
   *
   * In its own block, deliberately. It does not contribute to `risk_label`,
   * `risk_confidence`, or `risk_reason` — solvency is not evidence about
   * lookalike impersonation — so it sits beside them rather than folded into
   * them. `checked: false` when the signal was unavailable; the verdict above is
   * identical either way.
   */
  readonly counterparty_solvency: SolvencyBlock;
  /**
   * What a calling agent should do, given both checks. Advisory and additive: a
   * caller that only reads `risk_label` gets exactly what it got before.
   */
  readonly recommended_action: {
    readonly action: RecommendedAction;
    readonly reason: string;
  };
  readonly evidence: {
    readonly checked_at_block: number | null;
    readonly checked_at: string;
    readonly canonical: string;
  };
}

export type SolvencyBlock =
  | { readonly checked: false; readonly reason: string }
  | {
      readonly checked: true;
      readonly source: string;
      readonly verdict: 'ALLOW' | 'RECHECK' | 'BLOCK' | 'NO_POSITION';
      readonly reasoning: string | null;
      readonly health_factor: number | null;
      readonly checked_at_block: number | null;
    };

/**
 * Flattens a `CounterpartySolvency` into its wire block.
 *
 * Exported and pure so the three-state mapping is asserted directly — the
 * distinction between "unavailable" and "no position" is the one that would
 * otherwise quietly collapse into a single falsy value.
 */
export function toSolvencyBlock(solvency: CounterpartySolvency): SolvencyBlock {
  if (solvency.state === 'unavailable') {
    return { checked: false, reason: solvency.reason };
  }

  if (solvency.state === 'no_position') {
    // `NO_POSITION` is reported rather than collapsed into `ALLOW`. The upstream
    // source does answer ALLOW for a wallet with no lending position, but "there
    // was nothing to assess" and "we assessed it and it is healthy" are
    // different facts, and an agent weighing them deserves to know which it has.
    return {
      checked: true,
      source: solvency.source,
      verdict: 'NO_POSITION',
      reasoning: null,
      health_factor: null,
      checked_at_block: solvency.checkedAtBlock,
    };
  }

  return {
    checked: true,
    source: solvency.source,
    verdict: solvency.verdict,
    reasoning: solvency.reasoning,
    health_factor: solvency.healthFactor,
    checked_at_block: solvency.checkedAtBlock,
  };
}

/**
 * Builds the deterministic canonical string.
 *
 * `address|chain|risk_label|checked_at_block` — the exact inputs and outputs
 * that define the answer, and nothing that varies for another reason. The
 * timestamp is deliberately excluded: including it would make every hash unique
 * and destroy the reproducibility the field exists to provide.
 *
 * An unknown block height is rendered as the literal `unknown` rather than
 * omitted, so the string never collapses two different states into one.
 */
export function buildCanonical(
  address: string,
  chain: Chain,
  label: string,
  block: number | null,
): string {
  return [address, chain, label, block === null ? 'unknown' : String(block)]
    .join('|')
    .toLowerCase();
}

/**
 * Shapes a domain result into the wire response.
 *
 * `solvency` defaults to `unavailable` so a caller that does not supply the
 * signal still produces a well-formed response with `counterparty_solvency:
 * { checked: false }` — the same shape a failed lookup produces, rather than a
 * missing field. The canonical string does NOT include it: an advisory
 * second-opinion field that can flap with a third party's uptime must not change
 * the reproducibility hash of the poisoning verdict.
 */
export function toResponse(
  result: RiskCheckResult,
  chain: Chain,
  block: number | null,
  trustSource: RiskCheckResponse['detail']['trust_source'],
  solvency: CounterpartySolvency = { state: 'unavailable', reason: 'not_requested' },
  now: Date = new Date(),
): RiskCheckResponse {
  const evidence: OnChainEvidence = {
    checkedAtBlock: block,
    checkedAt: now.toISOString(),
    canonical: buildCanonical(result.address, chain, result.riskLabel, block),
  };

  const action = composeAdvice(result.riskLabel, solvency);

  return {
    address: result.address,
    risk_label: result.riskLabel,
    risk_confidence: result.riskConfidence,
    risk_reason: result.riskReason,
    detail: {
      matched_against: result.match === null ? null : abbreviate(result.match.matchedAgainst),
      match_type: result.match?.matchType ?? null,
      similarity_score: result.match?.similarityScore ?? 0,
      trusted_set_size: result.trustedSetSize,
      trust_source: trustSource,
    },
    counterparty_solvency: toSolvencyBlock(solvency),
    recommended_action: {
      action,
      reason: formatAdviceReason(result.riskLabel, solvency, action),
    },
    evidence: {
      checked_at_block: evidence.checkedAtBlock,
      checked_at: evidence.checkedAt,
      canonical: evidence.canonical,
    },
  };
}
