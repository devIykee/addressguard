/**
 * Risk labels, in the vocabulary Telegraph's `label_field` reads.
 *
 * Ordered by severity so comparisons and tests can rely on the ordering.
 */
export type RiskLabel = 'safe' | 'caution' | 'high_risk';

/**
 * Which matching strategy produced a match. Surfaced in
 * `detail.match_type` and in `risk_reason`.
 *
 * `ens_homoglyph` is declared now and produced only once Tier 2b lands — the
 * response contract should not change shape when it does.
 */
export type MatchType = 'prefix_suffix' | 'full_levenshtein' | 'ens_homoglyph';

/**
 * Where a trusted identity came from. Determines nothing about scoring, but
 * an agent reading the response deserves to know whether the comparison set
 * was asserted by the caller or derived from chain.
 */
export type TrustSource = 'caller_supplied' | 'chain_derived';

/** A supported chain. Kept narrow deliberately: only what is actually served. */
export type Chain = 'base' | 'ethereum';

/**
 * One trusted identity to compare a candidate address against.
 */
export interface TrustedIdentity {
  /** Lowercased `0x`-prefixed address, or an ENS label once Tier 2b lands. */
  readonly identity: string;
  readonly source: TrustSource;
}

/**
 * The outcome of comparing one candidate against one trusted identity with
 * one strategy. Data only.
 */
export interface MatchResult {
  /** The trusted identity that was matched against. */
  readonly matchedAgainst: string;
  readonly matchType: MatchType;
  /** Normalized similarity in [0, 1]. */
  readonly similarityScore: number;
  /** Where the matched identity came from. */
  readonly source: TrustSource;
}

/**
 * Verifiability metadata. Present on every response, including errors of
 * judgement like `insufficient_history` — an answer that cannot be pinned to a
 * block and reproduced from a canonical string is an assertion, not evidence.
 */
export interface OnChainEvidence {
  /**
   * Block height the answer was computed at, or `null` when no block could be
   * read. Null rather than 0 or a stale value: a wrong block number is worse
   * than an absent one.
   */
  readonly checkedAtBlock: number | null;
  /** ISO-8601 UTC timestamp. */
  readonly checkedAt: string;
  /**
   * Deterministic string over the exact inputs and outputs, so identical
   * inputs hash identically:
   *   `address|chain|risk_label|checked_at_block`
   */
  readonly canonical: string;
}

/**
 * A second, independent opinion on the destination, from an external miner that
 * answers a different question: is this counterparty financially distressed?
 *
 * Three states, distinguished for the same reason `PoisoningTransferEvidence`
 * distinguishes its three: "we asked and there is nothing to assess" must not be
 * reported as "we could not ask", and neither may be reported as clean.
 *
 *  - `unavailable`  — the source could not be reached, timed out, answered with
 *    something that is not a solvency verdict, or does not cover this chain. No
 *    claim is made in either direction.
 *  - `no_position`  — the source answered, and the counterparty has no lending
 *    position at all. A real answer but an uninformative one: absence of
 *    leverage is not evidence of anything.
 *  - `assessed`     — the source answered with a live position and a verdict.
 */
export type CounterpartySolvency =
  | { readonly state: 'unavailable'; readonly reason: string }
  | {
      readonly state: 'no_position';
      readonly source: string;
      readonly checkedAtBlock: number | null;
    }
  | {
      readonly state: 'assessed';
      readonly source: string;
      /** The upstream verdict, verbatim. Not remapped — see `composeAdvice`. */
      readonly verdict: SolvencyVerdict;
      readonly reasoning: string;
      /** `null` when the position holds collateral but carries no debt. */
      readonly healthFactor: number | null;
      readonly checkedAtBlock: number | null;
    };

/** The upstream solvency vocabulary, kept verbatim rather than translated. */
export type SolvencyVerdict = 'ALLOW' | 'RECHECK' | 'BLOCK';

/**
 * True when the solvency signal reports live financial distress, as opposed to
 * reporting health, reporting no position, or being unavailable.
 *
 * One predicate rather than a set-membership test repeated at each call site, so
 * "what counts as distress" is defined once.
 */
export function isDistressed(solvency: CounterpartySolvency): boolean {
  return solvency.state === 'assessed' && solvency.verdict !== 'ALLOW';
}

/**
 * What a calling agent should actually do, given both checks.
 *
 * Advisory and additive. It exists because an agent holding two verdicts about
 * two different questions has to combine them somehow, and doing that once here,
 * with the rule written down, beats every caller inventing its own. `risk_label`
 * stays the answer to the poisoning question alone.
 */
export type RecommendedAction = 'proceed' | 'review' | 'block';

/**
 * The full result of a risk check, before HTTP shaping.
 */
export interface RiskCheckResult {
  readonly address: string;
  readonly riskLabel: RiskLabel;
  readonly riskConfidence: number;
  readonly riskReason: string;
  readonly match: MatchResult | null;
  /** How many trusted identities were actually compared against. */
  readonly trustedSetSize: number;
}
