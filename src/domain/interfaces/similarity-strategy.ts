import type { MatchType } from '../entities/index.ts';

/**
 * How much weight a strategy's score may carry on its own.
 *
 * This is a property of the *signal*, declared by the strategy, rather than a
 * conditional in the aggregator. `PoisoningDetectionService` reads it and never
 * names a concrete strategy, so a new strategy declares its own authority and
 * the aggregation rule does not change.
 *
 * - `primary` — the score reflects the mechanism of the attack directly and may
 *   assert `high_risk` alone. `PrefixSuffixStrategy` qualifies: attackers
 *   vanity-mine the visible ends precisely because those are what gets read.
 *
 * - `corroborating` — the score is real evidence but does not separate attacks
 *   from unrelated addresses sharply enough to carry the strongest verdict. It
 *   can lift a primary match and it is capped when it is the only signal.
 *   `LevenshteinStrategy` qualifies: measured 0.325 on real incidents against a
 *   0.125 control floor.
 */
export type StrategyAuthority = 'primary' | 'corroborating';

/**
 * Compares two identity strings and returns a normalized similarity score.
 *
 * The interface is deliberately one method wide (plus identity metadata).
 * Anything a specific strategy needs beyond the two strings — an ENS
 * resolver, an RPC client — is injected into that strategy's constructor, not
 * added here. Otherwise `PrefixSuffixStrategy`, which is a pure function over
 * two strings, would have to accept collaborators it never calls.
 *
 * ## Contract
 *
 * Every implementation must satisfy all of the following. A shared test suite
 * (`tests/unit/strategy-contract.ts`) runs every implementation through it, so
 * these are enforced rather than documented:
 *
 * 1. Returns a finite number in `[0, 1]`.
 * 2. **Never throws.** Malformed input — wrong length, non-hex, empty string,
 *    or a value that is `undefined` at runtime despite the type — returns `0`
 *    and logs a warning. A strategy that threw on one bad array element would
 *    fail an entire request over it.
 * 3. Symmetric: `score(a, b) === score(b, a)`.
 * 4. Identical inputs are not this interface's problem to reject. An exact
 *    match is an address the caller already legitimately uses, and excluding
 *    it is an aggregation decision, made once in
 *    `PoisoningDetectionService` rather than repeated in every strategy.
 * 5. Deterministic: same inputs, same score, always. No clocks, no randomness,
 *    no network calls inside `score`.
 */
export interface SimilarityStrategy {
  /**
   * Stable identifier, surfaced in `detail.match_type` and `risk_reason`.
   * Part of the wire contract, so it does not change casually.
   */
  readonly matchType: MatchType;

  /**
   * Human-readable name for logs. Not part of the wire contract.
   */
  readonly name: string;

  /** How much this signal may assert on its own. See {@link StrategyAuthority}. */
  readonly authority: StrategyAuthority;

  /**
   * @returns normalized similarity in `[0, 1]`. `0` means "no signal",
   * which is also what malformed input returns.
   */
  score(candidate: string, trusted: string): number;
}
