import type { TrustedSetProvider } from '../domain/interfaces/trusted-set-provider.ts';
import type { Logger } from '../domain/interfaces/logger.ts';
import type { Chain, TrustedIdentity } from '../domain/entities/index.ts';
import { normalizeAddress, isValidAddress } from '../domain/address.ts';

/**
 * Blockscout instances, per chain. No API key required.
 *
 * Blockscout rather than raw `eth_getLogs`: every free RPC endpoint tested caps
 * log queries at 10,000 blocks, which is ~5.5 hours on Base and ~33 hours on
 * Ethereum. A poisoning transfer planted days earlier would fall outside that
 * window, so a log-based derivation would silently return an incomplete trusted
 * set. Blockscout indexes by account and has no such cap.
 *
 * Base is best-effort: `base.blockscout.com` returned 500s and connection
 * failures during probing. When it is unavailable the derivation returns empty
 * and the verdict degrades to `insufficient_history` — never to a fabricated
 * `safe`.
 */
const EXPLORERS: Readonly<Record<Chain, string>> = {
  ethereum: 'https://eth.blockscout.com',
  base: 'https://base.blockscout.com',
};

/** ERC-20 `transfer(address,uint256)`. */
const SELECTOR_TRANSFER = '0xa9059cbb';
/** ERC-20 `transferFrom(address,address,uint256)`. */
const SELECTOR_TRANSFER_FROM = '0x23b872dd';

/** How many recent transactions to examine. */
const PAGE_SIZE = 200;

/**
 * Longer than the block-height timeout: this is load-bearing for the verdict
 * rather than for metadata, so it is worth waiting for. Still bounded, because
 * a hung explorer must not hold a request open indefinitely.
 */
const TIMEOUT_MS = 6_000;

/**
 * Derives a caller's trusted set from transactions the caller actually signed.
 *
 * See `TrustedSetProvider` for why signer-verification is the rule and what it
 * costs. In short: an attacker can forge a `Transfer` log naming the caller as
 * sender — that is the poisoning mechanism itself — but cannot forge the
 * caller's signature on a transaction.
 */
export class ExplorerTrustedSetProvider implements TrustedSetProvider {
  private readonly logger: Logger;
  private readonly explorers: Readonly<Record<Chain, string>>;

  constructor(logger: Logger, explorers: Readonly<Record<Chain, string>> = EXPLORERS) {
    this.logger = logger;
    this.explorers = explorers;
  }

  async deriveTrustedSet(caller: string, chain: Chain): Promise<readonly TrustedIdentity[]> {
    const address = normalizeAddress(caller);
    if (!isValidAddress(address)) {
      this.logger.warn('trusted-set derivation skipped: malformed caller address', { chain });
      return [];
    }

    const rows = await this.fetchTransactions(address, chain);
    if (rows === null) return [];

    const recipients = extractDeliberateRecipients(rows, address);

    this.logger.info('derived trusted set from chain', {
      chain,
      caller: address,
      examined: rows.length,
      derived: recipients.length,
    });

    return recipients.map((identity) => ({ identity, source: 'chain_derived' as const }));
  }

  private async fetchTransactions(address: string, chain: Chain): Promise<unknown[] | null> {
    // Two API generations, tried in order. Blockscout's v1 `txlist` is the
    // Etherscan-compatible endpoint and returns the flat shape this module
    // parses natively; v2 is the current API and is the only one reachable on
    // some instances. During probing eth.blockscout.com served v1 fine while
    // base.blockscout.com dropped v1 connections entirely but answered v2 — so
    // supporting only one would leave a chain silently underserved.
    const viaV1 = await this.fetchV1(address, chain);
    if (viaV1 !== null) return viaV1;

    const viaV2 = await this.fetchV2(address, chain);
    if (viaV2 !== null) {
      this.logger.info('explorer v1 unavailable; used v2 API', { chain });
      return viaV2;
    }

    return null;
  }

  private async fetchV1(address: string, chain: Chain): Promise<unknown[] | null> {
    const url = new URL('/api', this.explorers[chain]);
    url.searchParams.set('module', 'account');
    url.searchParams.set('action', 'txlist');
    url.searchParams.set('address', address);
    url.searchParams.set('sort', 'desc');
    url.searchParams.set('page', '1');
    url.searchParams.set('offset', String(PAGE_SIZE));

    const payload = await this.getJson(url, chain, 'txlist v1');
    if (payload === null) return null;

    const result = (payload as { result?: unknown }).result;
    return Array.isArray(result) ? result : null;
  }

  /**
   * Blockscout v2. Different shape — `from`/`to` are objects with a `hash`, and
   * calldata is `raw_input` — so rows are normalized into the flat v1 shape and
   * the derivation rule stays in one place.
   *
   * `filter=from` asks the explorer for outbound transactions only. That is a
   * bandwidth optimization, not a security boundary: `extractDeliberateRecipients`
   * re-checks the signer on every row regardless, because trusting an explorer's
   * filter to enforce the rule that makes the trusted set unpoisonable would be
   * misplaced.
   */
  private async fetchV2(address: string, chain: Chain): Promise<unknown[] | null> {
    const url = new URL(
      `/api/v2/addresses/${address}/transactions?filter=from`,
      this.explorers[chain],
    );

    const payload = await this.getJson(url, chain, 'transactions v2');
    if (payload === null) return null;

    const items = (payload as { items?: unknown }).items;
    if (!Array.isArray(items)) return null;

    return items.slice(0, PAGE_SIZE).map(normalizeV2Row);
  }

  private async getJson(url: URL, chain: Chain, label: string): Promise<unknown | null> {
    try {
      const response = await fetch(url, {
        headers: { accept: 'application/json' },
        signal: AbortSignal.timeout(TIMEOUT_MS),
      });

      if (!response.ok) {
        this.logger.warn('explorer returned non-2xx', { chain, label, status: response.status });
        return null;
      }

      return await response.json();
    } catch (error: unknown) {
      this.logger.warn('explorer request failed', {
        chain,
        label,
        error: error instanceof Error ? error.message : String(error),
      });
      return null;
    }
  }
}

/**
 * Flattens a Blockscout v2 transaction into the v1 shape the parser expects.
 *
 * Exported for tests: the field remapping is exactly the kind of thing that
 * silently produces an empty trusted set if `from` is read as a string when it
 * is an object.
 */
export function normalizeV2Row(row: unknown): unknown {
  if (typeof row !== 'object' || row === null) return row;
  const tx = row as Record<string, unknown>;

  return {
    from: hashOf(tx.from),
    to: hashOf(tx.to),
    value: typeof tx.value === 'string' ? tx.value : String(tx.value ?? '0'),
    input: typeof tx.raw_input === 'string' ? tx.raw_input : '0x',
  };
}

function hashOf(party: unknown): string | null {
  if (typeof party === 'string') return party;
  if (typeof party === 'object' && party !== null) {
    const hash = (party as { hash?: unknown }).hash;
    if (typeof hash === 'string') return hash;
  }
  return null;
}

/**
 * Pulls the recipients of deliberate sends out of raw explorer rows.
 *
 * Exported and pure so the derivation rule is tested against recorded payloads
 * rather than against the network. Every branch here is a decision about what
 * counts as trust:
 *
 *  - `from !== caller`  → skipped. An inbound transfer says nothing about
 *    whether the caller chose to pay anyone, and inbound zero-value transfers
 *    are the attack itself.
 *
 *  - non-zero native `value` → the `to` address is trusted.
 *
 *  - `transfer(to, amount)` / `transferFrom(from, to, amount)` → the address in
 *    the CALLDATA is trusted, not `to`. `to` is the token contract. Reading
 *    `to` here would record USDT's contract as a trusted counterparty and miss
 *    the actual recipient — which, on the USDT 2025 fixture, is precisely the
 *    address the victim meant to pay.
 *
 *  - zero-value plain call → skipped. Nothing was sent.
 *
 * Never throws: malformed rows are skipped individually. Explorer output is
 * external input, and one odd row must not deny the whole check.
 */
export function extractDeliberateRecipients(rows: readonly unknown[], caller: string): string[] {
  const recipients = new Set<string>();

  for (const row of rows) {
    if (typeof row !== 'object' || row === null) continue;

    const tx = row as Record<string, unknown>;
    const from = typeof tx.from === 'string' ? normalizeAddress(tx.from) : null;
    if (from === null || from !== caller) continue;

    const input = typeof tx.input === 'string' ? tx.input.toLowerCase() : '0x';

    // ERC-20 transfer: recipient is the first calldata word.
    if (input.startsWith(SELECTOR_TRANSFER)) {
      addIfValid(recipients, decodeAddressArg(input, 0));
      continue;
    }

    // ERC-20 transferFrom: recipient is the second calldata word.
    if (input.startsWith(SELECTOR_TRANSFER_FROM)) {
      addIfValid(recipients, decodeAddressArg(input, 1));
      continue;
    }

    // Native send with real value.
    if (parsePositiveValue(tx.value)) {
      const to = typeof tx.to === 'string' ? normalizeAddress(tx.to) : null;
      addIfValid(recipients, to);
    }
  }

  recipients.delete(caller);
  return [...recipients];
}

/**
 * Reads the nth 32-byte argument of ABI calldata as an address.
 *
 * @returns `null` when the calldata is too short — truncated `input` fields do
 * appear in explorer output.
 */
function decodeAddressArg(input: string, argIndex: number): string | null {
  const argsStart = 10; // '0x' + 8 hex chars of selector
  const wordStart = argsStart + argIndex * 64;
  const wordEnd = wordStart + 64;
  if (input.length < wordEnd) return null;

  const word = input.slice(wordStart, wordEnd);
  // An address occupies the low 20 bytes; the high 12 must be zero padding.
  if (!/^0{24}[0-9a-f]{40}$/.test(word)) return null;

  return `0x${word.slice(24)}`;
}

function parsePositiveValue(value: unknown): boolean {
  if (typeof value !== 'string' || !/^\d+$/.test(value)) return false;
  // BigInt rather than Number: wei values exceed Number.MAX_SAFE_INTEGER.
  return BigInt(value) > 0n;
}

function addIfValid(target: Set<string>, address: string | null): void {
  if (address !== null && isValidAddress(address)) target.add(address);
}
