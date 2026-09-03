/**
 * Address normalization and validation, shared by every strategy and by the
 * HTTP boundary.
 *
 * Lives in `domain/` because the notion of "a well-formed identity" is a
 * domain concept, not an HTTP or matching concern.
 */

const HEX_ADDRESS = /^0x[0-9a-f]{40}$/;

/**
 * Lowercases and trims. Does not validate — callers that need validation call
 * {@link isValidAddress}.
 *
 * Case-folding matters here: EIP-55 checksummed addresses mix case purely as a
 * checksum, so `0xABcd…` and `0xabcd…` are the same address. Comparing without
 * folding would report a spurious difference between two spellings of one
 * identity.
 */
export function normalizeAddress(value: string): string {
  return value.trim().toLowerCase();
}

/** True for an exactly-40-hex-digit `0x`-prefixed address, already normalized. */
export function isValidAddress(value: string): boolean {
  return HEX_ADDRESS.test(value);
}

/**
 * The 40 hex digits, without the `0x`. Returns `null` for anything malformed,
 * which is how strategies detect bad input without throwing.
 */
export function addressBody(value: string): string | null {
  const normalized = normalizeAddress(value);
  return isValidAddress(normalized) ? normalized.slice(2) : null;
}

/**
 * Abbreviates an address the way a wallet UI does — which is precisely the
 * display convention address poisoning exploits. Used in `risk_reason`, so a
 * reader sees the same truncation the victim would have.
 */
export function abbreviate(value: string): string {
  const normalized = normalizeAddress(value);
  if (normalized.length <= 12) return normalized;
  return `${normalized.slice(0, 6)}...${normalized.slice(-4)}`;
}
