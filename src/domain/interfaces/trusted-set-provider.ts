import type { Chain, TrustedIdentity } from '../entities/index.ts';

/**
 * Derives the set of identities a caller has demonstrably chosen to pay, from
 * chain, given only the caller's own address.
 *
 * ## Why this exists
 *
 * `callerHistory` is a client assertion, and an autonomously routed call has
 * no history to assert — the routing engine has the question, not the caller's
 * wallet contents. Without a derivation path every routed call returns
 * `insufficient_history`: honest, and useless.
 *
 * ## Why the obvious implementation is exploitable
 *
 * A derived trust set must not be poisonable. If the attacker's lookalike can
 * get *into* the trusted set, the check inverts and blesses the attack.
 * Three candidate rules, tested against both incident fixtures at the block
 * immediately before each loss:
 *
 *   rule                                              | outcome
 *   --------------------------------------------------|--------------------
 *   any counterparty in the caller's tx history        | attacker TRUSTED
 *   any Transfer log naming the caller as sender       | attacker TRUSTED
 *   only counterparties of txs the caller SIGNED       | attacker excluded
 *
 * The second rule fails because a zero-value `Transfer` log can name an
 * arbitrary sender — that is the poisoning mechanism itself. So trust comes
 * only from **deliberate sends**: transactions where `tx.from == caller`, with
 * the recipient taken from a non-zero `value` or from decoded
 * `transfer(to,...)` / `transferFrom(...,to,...)` calldata. An attacker cannot
 * forge that; it requires the caller's signature.
 *
 * ## Known limitation, stated rather than hidden
 *
 * The rule drops contract-mediated sends — a DEX router moving tokens on the
 * caller's behalf, where the recipient lives in internal transfers rather than
 * signed calldata. Verified: 5 legitimate counterparties dropped on one
 * fixture victim's March 2024 swaps.
 *
 * That is the correct trade. A false negative in the trusted set costs a
 * `safe` verdict that should have been `caution`. A false positive costs the
 * entire check. `callerHistory` stays available for callers who want to supply
 * those explicitly, and the two sources union.
 */
export interface TrustedSetProvider {
  /**
   * @param caller the caller's own address, lowercased `0x`-prefixed.
   * @returns identities the caller has deliberately paid, or an empty array
   * when nothing could be derived. Must not throw: an unavailable explorer
   * degrades to `insufficient_history`, never to a fabricated `safe`.
   */
  deriveTrustedSet(caller: string, chain: Chain): Promise<readonly TrustedIdentity[]>;
}
