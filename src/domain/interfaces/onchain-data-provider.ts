import type { Chain } from '../entities/index.ts';

/**
 * TIER 2a — declared now, implemented later.
 *
 * Independent, on-chain confirmation that a poisoning attempt is *active*,
 * rather than merely that two strings look alike.
 *
 * The mechanical fingerprint: the attacker sends a real transfer from the
 * lookalike address to the victim, specifically so the lookalike appears in
 * the victim's transaction history and gets copied out of it later. Both
 * incident fixtures work exactly this way. That transfer is independently
 * verifiable, which is what separates this from a pure string heuristic.
 *
 * Named `zero-value or dust` rather than just `dust` on the measurement
 * evidence: across 270M poisoning attempts, zero-value transfers are ~55% and
 * counterfeit-token transfers ~44%, while true dust (<$10) is under 2%. A
 * dust-only check would miss the overwhelming majority, so zero-value comes
 * first.
 *
 * Declared in Tier 1 so Tier 2a is additive — a new implementation and one
 * more constructor argument, with no change to the response fields Telegraph
 * reads.
 */
export interface OnChainDataProvider {
  /**
   * Looks for a transfer from `suspect` to `victim` consistent with an active
   * poisoning attempt.
   *
   * @returns the evidence if found; `found: false` when the check ran and
   * found nothing; `checked: false` when the check could not run at all.
   * The three states are distinct on purpose: "we looked and found nothing"
   * must not be reported as "we could not look", and neither may be reported
   * as clean.
   */
  findPoisoningTransfer(
    suspect: string,
    victim: string,
    chain: Chain,
  ): Promise<PoisoningTransferEvidence>;
}

export type PoisoningTransferEvidence =
  | { readonly checked: false }
  | { readonly checked: true; readonly found: false }
  | {
      readonly checked: true;
      readonly found: true;
      readonly txHash: string;
      readonly blockNumber: number;
      /** `zero_value`, `dust`, or `counterfeit_token`. */
      readonly kind: 'zero_value' | 'dust' | 'counterfeit_token';
    };
