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
