import type { BlockProvider } from '../domain/interfaces/block-provider.ts';
import type { Logger } from '../domain/interfaces/logger.ts';
import type { Chain } from '../domain/entities/index.ts';

/**
 * Public RPC endpoints, in fallback order. Verified reachable during design.
 *
 * No API keys, deliberately: a hackathon miner must stay live for a week
 * without a paid plan expiring, and a key in a config file that is public by
 * design is worse than no key. Ruled out during probing: publicnode (archive
 * requests demand a token), cloudflare-eth (-32046), ankr (key required),
 * llamarpc (521).
 */
const ENDPOINTS: Readonly<Record<Chain, readonly string[]>> = {
  ethereum: ['https://eth.drpc.org', 'https://rpc.flashbots.net'],
  base: ['https://mainnet.base.org', 'https://base-rpc.publicnode.com'],
};

/** Freshness cache TTL. Base produces a block every ~2s, Ethereum every ~12s. */
const CACHE_TTL_MS = 10_000;

/**
 * A block read must never be the reason a risk check fails, so this is short.
 * The verdict does not depend on it — only the evidence block does.
 */
const TIMEOUT_MS = 2_500;

/**
 * Reads the current block height over JSON-RPC, for `evidence.checked_at_block`.
 *
 * Fails soft by design. Every failure path returns `null`, which the handler
 * renders as `checked_at_block: null` — an explicitly unknown block, rather
 * than a stale or invented one. A wrong block number in a field meant to make
 * an answer reproducible is worse than an absent one.
 */
export class RpcBlockProvider implements BlockProvider {
  private readonly cache = new Map<Chain, { block: number; at: number }>();

  private readonly logger: Logger;
  private readonly endpoints: Readonly<Record<Chain, readonly string[]>>;
  private readonly now: () => number;

  constructor(
    logger: Logger,
    endpoints: Readonly<Record<Chain, readonly string[]>> = ENDPOINTS,
    now: () => number = Date.now,
  ) {
    this.logger = logger;
    this.endpoints = endpoints;
    this.now = now;
  }

  async currentBlock(chain: Chain): Promise<number | null> {
    const cached = this.cache.get(chain);
    if (cached !== undefined && this.now() - cached.at < CACHE_TTL_MS) {
      return cached.block;
    }

    for (const endpoint of this.endpoints[chain]) {
      const block = await this.tryEndpoint(endpoint);
      if (block !== null) {
        this.cache.set(chain, { block, at: this.now() });
        return block;
      }
    }

    this.logger.warn('block height unavailable on every endpoint', { chain });
    return null;
  }

  private async tryEndpoint(endpoint: string): Promise<number | null> {
    try {
      const response = await fetch(endpoint, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'eth_blockNumber', params: [] }),
        signal: AbortSignal.timeout(TIMEOUT_MS),
      });

      if (!response.ok) {
        this.logger.warn('rpc returned non-2xx for eth_blockNumber', {
          endpoint,
          status: response.status,
        });
        return null;
      }

      const payload: unknown = await response.json();
      return parseBlockNumber(payload);
    } catch (error: unknown) {
      this.logger.warn('rpc call failed for eth_blockNumber', {
        endpoint,
        error: error instanceof Error ? error.message : String(error),
      });
      return null;
    }
  }
}

/**
 * Extracts a block height from a JSON-RPC response.
 *
 * Exported for tests: the parse has to reject an error-shaped 200 response,
 * which several public endpoints return (`{"error": {...}}` with HTTP 200), and
 * that behaviour is worth pinning.
 */
export function parseBlockNumber(payload: unknown): number | null {
  if (typeof payload !== 'object' || payload === null) return null;

  const result = (payload as { result?: unknown }).result;
  if (typeof result !== 'string' || !/^0x[0-9a-fA-F]+$/.test(result)) return null;

  const block = Number.parseInt(result, 16);
  return Number.isSafeInteger(block) && block > 0 ? block : null;
}

/** A provider that reports an unknown block, without touching the network. */
export class NullBlockProvider implements BlockProvider {
  currentBlock(): Promise<number | null> {
    return Promise.resolve(null);
  }
}
