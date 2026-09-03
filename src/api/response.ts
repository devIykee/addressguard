import type { Chain, OnChainEvidence, RiskCheckResult } from '../domain/entities/index.ts';
import { abbreviate } from '../domain/address.ts';

/**
 * The wire response.
 *
 * `risk_label`, `risk_confidence`, and `risk_reason` are flat and top-level
 * because that is what Telegraph's `signal_mapping` reads — a nested field
 * cannot be named there. Everything Tier 2 adds goes inside `detail` or
 * `onchain_evidence`, so the three fields the protocol parses never move.
 *
 * snake_case throughout, matching the request contract and the YAML schema.
 */
export interface RiskCheckResponse {
  readonly address: string;
  readonly risk_label: RiskCheckResult['riskLabel'];
  readonly risk_confidence: number;
  readonly risk_reason: string;
  readonly detail: {
    readonly matched_against: string | null;
    readonly match_type: string | null;
    readonly similarity_score: number;
    /** How many trusted identities were actually compared against. */
    readonly trusted_set_size: number;
    /**
     * Where the trusted set came from. `none` when nothing was available, which
     * is the case that must never be reported as `safe`.
     */
    readonly trust_source: 'caller_supplied' | 'chain_derived' | 'mixed' | 'none';
  };
  readonly evidence: {
    readonly checked_at_block: number | null;
    readonly checked_at: string;
    readonly canonical: string;
  };
}

/**
 * Builds the deterministic canonical string.
 *
 * `address|chain|risk_label|checked_at_block` — the exact inputs and outputs
 * that define the answer, and nothing that varies for another reason. The
 * timestamp is deliberately excluded: including it would make every hash unique
 * and destroy the reproducibility the field exists to provide.
 *
 * An unknown block height is rendered as the literal `unknown` rather than
 * omitted, so the string never collapses two different states into one.
 */
export function buildCanonical(
  address: string,
  chain: Chain,
  label: string,
  block: number | null,
): string {
  return [address, chain, label, block === null ? 'unknown' : String(block)]
    .join('|')
    .toLowerCase();
}

/** Shapes a domain result into the wire response. */
export function toResponse(
  result: RiskCheckResult,
  chain: Chain,
  block: number | null,
  trustSource: RiskCheckResponse['detail']['trust_source'],
  now: Date = new Date(),
): RiskCheckResponse {
  const evidence: OnChainEvidence = {
    checkedAtBlock: block,
    checkedAt: now.toISOString(),
    canonical: buildCanonical(result.address, chain, result.riskLabel, block),
  };

  return {
    address: result.address,
    risk_label: result.riskLabel,
    risk_confidence: result.riskConfidence,
    risk_reason: result.riskReason,
    detail: {
      matched_against: result.match === null ? null : abbreviate(result.match.matchedAgainst),
      match_type: result.match?.matchType ?? null,
      similarity_score: result.match?.similarityScore ?? 0,
      trusted_set_size: result.trustedSetSize,
      trust_source: trustSource,
    },
    evidence: {
      checked_at_block: evidence.checkedAtBlock,
      checked_at: evidence.checkedAt,
      canonical: evidence.canonical,
    },
  };
}
