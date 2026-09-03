import type {
  SimilarityStrategy,
  StrategyAuthority,
} from '../../domain/interfaces/similarity-strategy.ts';
import type { Logger } from '../../domain/interfaces/logger.ts';
import type { MatchType } from '../../domain/entities/index.ts';
import { addressBody } from '../../domain/address.ts';
import { ADDRESS_BODY_LENGTH } from '../../../config/thresholds.ts';

/**
 * Normalized full-string edit distance between two addresses.
 *
 * ## Why this is the secondary signal, and capped
 *
 * Measured on the two real incidents, this metric scores both pairs 0.325
 * against a 0.10-0.125 unrelated-control floor. Real attacks land *below the
 * midpoint of its own scale* — a 0.2 separation is not enough to carry the
 * strongest verdict, so `LEV_MAX_ALONE` caps a Levenshtein-only match at
 * `caution`. The measurement study behind the thresholds reaches the same
 * conclusion and discards middle-of-string metrics as "largely irrelevant":
 * attackers mine the visible ends and leave the middle random, so edit
 * distance spends most of its resolution on characters nobody reads.
 *
 * ## Why keep it at all
 *
 * Two jobs it does that prefix/suffix cannot:
 *
 *  1. It corroborates a borderline prefix/suffix match. The USDT 2025 incident
 *     sits at exactly the prefix/suffix floor (d=8, 0.75) and reaches
 *     `high_risk` only once this signal lifts it — a real case, not a
 *     hypothetical one.
 *  2. It catches end-shifted variants. An insertion near the front leaves the
 *     suffix misaligned, so prefix/suffix scores 0 while edit distance still
 *     sees a near-identical string.
 *
 * Both jobs are corroborative. Neither is authoritative, which is exactly what
 * the cap encodes.
 */
export class LevenshteinStrategy implements SimilarityStrategy {
  readonly matchType: MatchType = 'full_levenshtein';
  readonly name = 'full-levenshtein';
  /**
   * Corroborating: 0.325 on real incidents against a 0.125 control floor is
   * not enough separation to assert `high_risk` alone. The aggregator reads
   * this and applies `LEV_MAX_ALONE`.
   */
  readonly authority: StrategyAuthority = 'corroborating';

  private readonly logger: Logger;

  constructor(logger: Logger) {
    this.logger = logger;
  }

  score(candidate: string, trusted: string): number {
    const a = addressBody(candidate);
    const b = addressBody(trusted);

    if (a === null || b === null) {
      this.logger.warn('levenshtein: malformed address, scoring 0', {
        strategy: this.name,
        candidateValid: a !== null,
        trustedValid: b !== null,
      });
      return 0;
    }

    const distance = levenshtein(a, b);
    // Both bodies are exactly ADDRESS_BODY_LENGTH here, since addressBody()
    // rejects anything else — so the denominator is a constant rather than
    // max(a.length, b.length), and the score is comparable across pairs.
    return 1 - distance / ADDRESS_BODY_LENGTH;
  }
}

/**
 * Levenshtein edit distance, two-row dynamic programming.
 *
 * Exported for the calibration tests, which assert the measured distances of
 * the real incident pairs (27 for both) directly, so a regression here reads
 * as a distance bug rather than a mysterious scoring shift.
 *
 * Two rows rather than a full matrix: for a fixed 40-character input the
 * difference is negligible, but the aggregator runs this once per
 * (candidate, trusted) pair and a trusted set can be large, so there is no
 * reason to allocate 1,681 cells per comparison.
 */
export function levenshtein(a: string, b: string): number {
  if (a === b) return 0;
  if (a.length === 0) return b.length;
  if (b.length === 0) return a.length;

  let previous = new Array<number>(b.length + 1);
  let current = new Array<number>(b.length + 1);

  for (let j = 0; j <= b.length; j += 1) previous[j] = j;

  for (let i = 1; i <= a.length; i += 1) {
    current[0] = i;
    const charA = a[i - 1];

    for (let j = 1; j <= b.length; j += 1) {
      const substitutionCost = charA === b[j - 1] ? 0 : 1;
      current[j] = Math.min(
        previous[j]! + 1, // deletion
        current[j - 1]! + 1, // insertion
        previous[j - 1]! + substitutionCost, // substitution
      );
    }

    [previous, current] = [current, previous];
  }

  return previous[b.length]!;
}
