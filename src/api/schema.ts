import { z } from 'zod';

/**
 * The HTTP boundary. This is the only place untyped input enters the system,
 * and it is validated immediately — nothing downstream accepts `unknown`.
 *
 * Two deliberate choices about strictness:
 *
 *  - Addresses are accepted in any case and normalized downstream, because
 *    EIP-55 checksumming is a checksum rather than an identity. Rejecting
 *    mixed case would reject the spelling most wallets produce.
 *
 *  - `callerHistory` entries are NOT pattern-validated here. A single malformed
 *    entry must not fail an otherwise valid request — the strategies score it 0
 *    and log a warning. Rejecting the whole request would hand an attacker a
 *    trivial denial of the check: append one bad string to a history array and
 *    the destination goes unchecked.
 */

const ADDRESS = z
  .string()
  .trim()
  .regex(/^0x[0-9a-fA-F]{40}$/, 'must be a 0x-prefixed 40-hex-character address');

export const CHAINS = ['base', 'ethereum'] as const;

/**
 * Upper bounds on the arrays. Sized well above real use — a wallet with more
 * than 256 distinct deliberate counterparties is not the target case — and low
 * enough that a request cannot make the matcher do unbounded work.
 */
const MAX_HISTORY_ENTRIES = 256;

export const riskCheckRequestSchema = z
  .object({
    /** The destination being checked. */
    address: ADDRESS,

    chain: z.enum(CHAINS),

    /**
     * Identities the caller says it trusts. Loosely typed on purpose: see the
     * note above about one bad entry not failing the request.
     */
    callerHistory: z.array(z.string()).max(MAX_HISTORY_ENTRIES).optional(),

    /**
     * The caller's own wallet. When present and `callerHistory` is absent or
     * empty, the trusted set is derived from chain instead — which is what makes
     * the miner useful on autonomously routed calls, where no history is
     * supplied.
     */
    callerAddress: ADDRESS.optional(),

    /** TIER 2b — accepted and ignored until the ENS strategy lands. */
    ensName: z.string().trim().max(255).optional(),

    /** TIER 2b — accepted and ignored until the ENS strategy lands. */
    callerTrustedEnsNames: z.array(z.string()).max(MAX_HISTORY_ENTRIES).optional(),
  })
  // Unknown keys are ignored rather than rejected: Telegraph's request builder
  // constructs calls from the YAML, and a strict boundary would turn a
  // harmless extra field into a 400 on every routed request.
  .loose();

export type RiskCheckRequest = z.infer<typeof riskCheckRequestSchema>;

/**
 * Parses a request body, returning either the validated value or a flat list of
 * human-readable field errors.
 */
export function parseRiskCheckRequest(
  body: unknown,
): { ok: true; value: RiskCheckRequest } | { ok: false; errors: string[] } {
  const result = riskCheckRequestSchema.safeParse(body);

  if (result.success) {
    return { ok: true, value: result.data };
  }

  const errors = result.error.issues.map((issue) => {
    const path = issue.path.join('.');
    return path.length > 0 ? `${path}: ${issue.message}` : issue.message;
  });

  return { ok: false, errors };
}
