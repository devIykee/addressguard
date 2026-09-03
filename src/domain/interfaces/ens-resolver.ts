/**
 * TIER 2b — declared now, implemented later.
 *
 * Resolves an ENS name to an address.
 *
 * ENS is where homoglyph attacks actually apply. A raw hex address is drawn
 * from `[0-9a-f]`, so visually-confusable substitution barely has room to
 * operate — but an ENS label is full text, where `vitaIik.eth` (capital I),
 * `vita1ik.eth` (digit 1), and `rn`-for-`m` are real, distinct attacks.
 *
 * Kept separate from `SimilarityStrategy`: the strategy compares label *text*
 * and needs no network, while resolution is a network call with its own
 * failure modes. `EnsHomoglyphStrategy` will do the text comparison and stay a
 * pure `SimilarityStrategy`; this interface exists for the separate question
 * of what address a name currently points at.
 */
export interface EnsResolver {
  /**
   * @returns the resolved lowercased address, or `null` when the name does not
   * resolve or resolution failed. Must not throw.
   */
  resolve(name: string): Promise<string | null>;
}
