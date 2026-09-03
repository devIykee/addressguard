import type {
  SimilarityStrategy,
  StrategyAuthority,
} from '../../domain/interfaces/similarity-strategy.ts';
import type { Logger } from '../../domain/interfaces/logger.ts';
import type { MatchType } from '../../domain/entities/index.ts';
import { addressBody } from '../../domain/address.ts';
import {
  MIN_PREFIX_CHARS,
  MIN_SUFFIX_CHARS,
  SATURATION_D,
  PREFIX_SUFFIX_FLOOR,
  RAMP_ORIGIN_D,
} from '../../../config/thresholds.ts';

/**
 * Counts matching leading and trailing hex characters between two addresses.
 *
 * This is the primary poisoning signal, and it is primary because of how the
 * attack works rather than because it is convenient. Attackers vanity-mine an
 * address matching the *ends* of one their victim already trusts, because the
 * ends are what wallet UIs and block explorers show: `0xd9a1...3a91`. The
 * middle is left random — mining it would cost orders of magnitude more and
 * buy nothing, since nobody reads it.
 *
 * That is also why full-string edit distance is the weaker signal here and is
 * capped accordingly (see `LEV_MAX_ALONE` in config/thresholds.ts).
 */
export class PrefixSuffixStrategy implements SimilarityStrategy {
  readonly matchType: MatchType = 'prefix_suffix';
  readonly name = 'prefix-suffix';
  /** Primary: this metric reflects the attack mechanism directly. */
  readonly authority: StrategyAuthority = 'primary';

  private readonly logger: Logger;

  constructor(logger: Logger) {
    this.logger = logger;
  }

  score(candidate: string, trusted: string): number {
    const a = addressBody(candidate);
    const b = addressBody(trusted);

    if (a === null || b === null) {
      // Contract: malformed input scores 0 and warns. One bad entry in a
      // callerHistory array must not fail the whole request.
      this.logger.warn('prefix-suffix: malformed address, scoring 0', {
        strategy: this.name,
        candidateValid: a !== null,
        trustedValid: b !== null,
      });
      return 0;
    }

    const overlap = endOverlap(a, b);

    // Below the detection floor there is no signal to report. A 2-character
    // prefix collision happens by chance roughly 1 in 256 — reporting it
    // would bury real matches in noise.
    if (overlap.prefix < MIN_PREFIX_CHARS || overlap.suffix < MIN_SUFFIX_CHARS) {
      return 0;
    }

    return rampScore(overlap.prefix + overlap.suffix);
  }
}

/**
 * Matching leading and trailing characters of two equal-length hex bodies.
 *
 * Exported for the calibration test, which asserts the measured (4,6) and
 * (4,4) overlaps of the two real incidents directly — so a regression in this
 * counter is caught as a counting bug rather than surfacing later as a
 * mysterious scoring change.
 */
export function endOverlap(a: string, b: string): { prefix: number; suffix: number } {
  const len = Math.min(a.length, b.length);

  let prefix = 0;
  while (prefix < len && a[prefix] === b[prefix]) prefix += 1;

  // An identical pair would otherwise be counted twice — once forwards, once
  // backwards — yielding d = 80 for a 40-character body. Identity is excluded
  // by the aggregator, not here (see the SimilarityStrategy contract), so this
  // clamp exists to keep the count meaningful rather than to make a policy
  // decision.
  let suffix = 0;
  while (suffix < len - prefix && a[a.length - 1 - suffix] === b[b.length - 1 - suffix]) {
    suffix += 1;
  }

  return { prefix, suffix };
}

/**
 * Maps total matched end characters `d` onto a score.
 *
 *   d = 8  -> 0.750   (the floor: a real signal, but the weakest one)
 *   d = 10 -> 0.8125
 *   d = 12 -> 0.875
 *   d >= 16 -> 1.0    (not plausibly accidental; nothing left to express)
 *
 * Linear because there is no evidence for a particular curve — the
 * measurement study reports attack *counts* by `d`, not success rates that
 * would justify one. A linear ramp between two justified endpoints claims
 * less than a fitted curve would.
 */
function rampScore(d: number): number {
  const span = SATURATION_D - RAMP_ORIGIN_D;
  const progress = Math.min(1, Math.max(0, (d - RAMP_ORIGIN_D) / span));
  return PREFIX_SUFFIX_FLOOR + (1 - PREFIX_SUFFIX_FLOOR) * progress;
}
