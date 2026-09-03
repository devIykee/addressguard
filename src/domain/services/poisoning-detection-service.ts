import type {
  MatchType,
  RiskCheckResult,
  RiskLabel,
  TrustedIdentity,
} from '../entities/index.ts';
import type {
  SimilarityStrategy,
  StrategyAuthority,
} from '../interfaces/similarity-strategy.ts';
import type { Logger } from '../interfaces/logger.ts';
import { normalizeAddress, abbreviate } from '../address.ts';
import {
  HIGH_RISK_AT,
  CAUTION_AT,
  LEV_MAX_ALONE,
  LEV_LIFT_WEIGHT,
  INSUFFICIENT_HISTORY_CONFIDENCE,
  NO_MATCH_CONFIDENCE,
} from '../../../config/thresholds.ts';

/** Structured, deterministic `risk_reason` values. Never prose. */
export const REASON_INSUFFICIENT_HISTORY = 'insufficient_history';
export const REASON_NO_MATCH = 'no_poisoning_match';

/**
 * Runs every injected strategy across every trusted identity, picks the
 * strongest match, and turns it into a label.
 *
 * Depends only on the `SimilarityStrategy` interface and a `Logger`, both
 * injected — it never names a concrete strategy, so Tier 2b's ENS strategy
 * plugs in by being added to the array rather than by editing this file.
 */
export class PoisoningDetectionService {
  // Explicit fields rather than constructor parameter properties: Node's
  // --experimental-strip-types runs TypeScript by erasing types only, and
  // parameter properties require emitting assignments. Writing them out keeps
  // the miner runnable with no build step, which is one less thing that can
  // break a deployment.
  private readonly strategies: readonly SimilarityStrategy[];
  private readonly logger: Logger;

  constructor(strategies: readonly SimilarityStrategy[], logger: Logger) {
    this.strategies = strategies;
    this.logger = logger;
  }

  check(candidate: string, trustedSet: readonly TrustedIdentity[]): RiskCheckResult {
    const address = normalizeAddress(candidate);

    // Only genuinely comparable targets count. An exact match is an address the
    // caller already legitimately uses — not poisoning — so it is excluded
    // here, once, rather than in every strategy. Excluding it also means a
    // trusted set consisting solely of the candidate is correctly treated as
    // "nothing to compare against" rather than as a perfect match.
    const comparable = trustedSet.filter(
      (entry) => normalizeAddress(entry.identity) !== address,
    );

    if (comparable.length === 0) {
      // Never `safe` here. Claiming safety on a check that did not run would
      // assert something never verified — the whole point of the miner.
      this.logger.info('no comparable trusted identities; returning caution', {
        address,
        suppliedCount: trustedSet.length,
      });
      return {
        address,
        riskLabel: 'caution',
        riskConfidence: INSUFFICIENT_HISTORY_CONFIDENCE,
        riskReason: REASON_INSUFFICIENT_HISTORY,
        match: null,
        trustedSetSize: 0,
      };
    }

    const best = this.strongestMatch(address, comparable);

    if (best === null || best.combined < CAUTION_AT) {
      return {
        address,
        riskLabel: 'safe',
        riskConfidence: NO_MATCH_CONFIDENCE,
        riskReason: REASON_NO_MATCH,
        match: null,
        trustedSetSize: comparable.length,
      };
    }

    const label: RiskLabel = best.combined >= HIGH_RISK_AT ? 'high_risk' : 'caution';

    return {
      address,
      riskLabel: label,
      riskConfidence: round(best.combined),
      riskReason: formatReason(best),
      match: {
        matchedAgainst: best.trusted.identity,
        matchType: best.primaryType ?? best.contributions[0]!.matchType,
        similarityScore: round(best.combined),
        source: best.trusted.source,
      },
      trustedSetSize: comparable.length,
    };
  }

  /**
   * Scores every (trusted identity x strategy) pair and returns the strongest
   * combined result, or `null` if nothing scored above zero.
   */
  private strongestMatch(
    address: string,
    comparable: readonly TrustedIdentity[],
  ): CombinedMatch | null {
    let best: CombinedMatch | null = null;

    for (const trusted of comparable) {
      const contributions: Contribution[] = [];

      for (const strategy of this.strategies) {
        const score = strategy.score(address, trusted.identity);
        if (score > 0) {
          contributions.push({
            matchType: strategy.matchType,
            authority: strategy.authority,
            score,
          });
        }
      }

      if (contributions.length === 0) continue;

      const combined = combineScores(contributions);
      if (best === null || combined.combined > best.combined) {
        best = { ...combined, trusted, contributions };
      }
    }

    return best;
  }
}

interface Contribution {
  readonly matchType: MatchType;
  readonly authority: StrategyAuthority;
  readonly score: number;
}

interface CombinedMatch {
  readonly combined: number;
  /** The primary strategy's match type, if a primary signal fired. */
  readonly primaryType: MatchType | null;
  readonly trusted: TrustedIdentity;
  readonly contributions: readonly Contribution[];
}

/**
 * Combines one trusted identity's per-strategy scores into a single number.
 *
 * Two rules, both driven by the measured separation of each signal:
 *
 *  - A primary signal sets the base. Corroborating signals add a bounded lift
 *    on top, so a borderline primary match plus real corroboration can clear
 *    `high_risk` — which is exactly the USDT 2025 incident.
 *
 *  - With no primary signal, the best corroborating score is capped at
 *    `LEV_MAX_ALONE`, which sits below `HIGH_RISK_AT`. Corroborating evidence
 *    alone can raise `caution` and can never assert `high_risk`.
 *
 * The rule reads `authority` off the strategy rather than checking names, so
 * adding a strategy does not mean editing this function.
 */
function combineScores(contributions: readonly Contribution[]): {
  combined: number;
  primaryType: MatchType | null;
} {
  const primaries = contributions.filter((c) => c.authority === 'primary');
  const corroborating = contributions.filter((c) => c.authority === 'corroborating');

  const bestCorroborating =
    corroborating.length > 0 ? Math.max(...corroborating.map((c) => c.score)) : 0;

  if (primaries.length === 0) {
    return {
      combined: Math.min(bestCorroborating, LEV_MAX_ALONE),
      primaryType: null,
    };
  }

  const strongestPrimary = primaries.reduce((a, b) => (b.score > a.score ? b : a));
  const lifted = strongestPrimary.score + LEV_LIFT_WEIGHT * bestCorroborating;

  return {
    combined: Math.min(1, lifted),
    primaryType: strongestPrimary.matchType,
  };
}

/**
 * Builds the structured `risk_reason`.
 *
 * Every contributing signal is named with its own score, so a reader can see
 * *why* a verdict crossed a threshold rather than only that it did. The USDT
 * 2025 case reaches `high_risk` only through corroboration, and a reason string
 * that showed one signal would make that indistinguishable from a strong
 * single-signal match.
 *
 *   poisoning_match:0xd9a1...3a91:similarity=0.8125:prefix_suffix=0.8125:full_levenshtein=0.3250
 */
function formatReason(match: CombinedMatch): string {
  const signals = [...match.contributions]
    .sort((a, b) => b.score - a.score)
    .map((c) => `${c.matchType}=${c.score.toFixed(4)}`)
    .join(':');

  return [
    'poisoning_match',
    abbreviate(match.trusted.identity),
    `similarity=${match.combined.toFixed(4)}`,
    signals,
  ].join(':');
}

/** Four decimal places: enough to be reproducible, not so many as to imply precision. */
function round(value: number): number {
  return Math.round(value * 10_000) / 10_000;
}
