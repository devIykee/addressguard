import type { Chain } from '../entities/index.ts';

/**
 * Reads the current block height, for `evidence.checked_at_block`.
 *
 * Separate from `OnChainDataProvider` (Tier 2a) on purpose: reading a block
 * number is one cheap `eth_blockNumber` call that Tier 1 needs, while
 * scanning transfer history is a different, heavier capability with different
 * failure modes. A Tier 1 deployment should not have to satisfy the larger
 * interface to report a block height.
 */
export interface BlockProvider {
  /**
   * @returns the current block height, or `null` if it could not be read.
   * Must not throw — a failed freshness read degrades the evidence block, it
   * does not fail the risk check.
   */
  currentBlock(chain: Chain): Promise<number | null>;
}
