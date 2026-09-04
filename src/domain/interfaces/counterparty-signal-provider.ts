import type { Chain, CounterpartySolvency } from '../entities/index.ts';

/**
 * An independent, external opinion on a destination address, from a source that
 * is not a string comparison.
 *
 * ## Why this is a separate interface
 *
 * Every other signal in this miner is a `SimilarityStrategy`: a pure, synchronous
 * function over two strings. A solvency lookup is none of those things — it is
 * asynchronous, it takes one address rather than a pair, it can be unavailable,
 * and its answer cannot be combined with a similarity score because the two do
 * not measure the same thing.
 *
 * Forcing it into `SimilarityStrategy` would break that interface's contract in
 * three places at once (never throws / deterministic / no network calls inside
 * `score`), so it gets its own seam instead. It sits alongside `BlockProvider`
 * and `TrustedSetProvider`, and takes `chain` for the same reason they do:
 * coverage differs per chain and the caller does not know which source covers
 * what.
 *
 * ## What it must never do
 *
 * It must never influence `risk_label`, `risk_confidence`, or `risk_reason`.
 * Those three answer one question — is this destination a lookalike of something
 * the caller trusts — and a solvency verdict is not evidence about that question.
 * A `risk_reason` of `poisoning_match:...` produced by a health-factor lookup
 * would be a false statement about which check fired.
 *
 * The signal is reported in its own response block and composed into an advisory
 * `recommended_action`, which is additive. See `composeAdvice`.
 */
export interface CounterpartySignalProvider {
  /**
   * @returns the counterparty's solvency state. Must not throw and must not
   * hang: an unreachable source, or a chain the source does not cover, resolves
   * to `state: 'unavailable'` — which is distinct from `no_position`, where the
   * source answered and there is nothing to assess.
   */
  solvencyOf(address: string, chain: Chain): Promise<CounterpartySolvency>;
}
