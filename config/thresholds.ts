/**
 * Similarity thresholds and scoring constants.
 *
 * Every constant here traces to a measurement, not a preference. Two sources:
 *
 *  (a) Two address-poisoning incidents reconstructed from Ethereum mainnet
 *      during design (see tests/fixtures/incidents.ts for addresses and
 *      transaction hashes).
 *  (b) "Blockchain Address Poisoning" (arXiv:2501.16681 / ACM CCS 2024), a
 *      measurement study over 270M poisoning attempts on Ethereum and BSC.
 *
 * Measured separation on the two incidents, against unrelated controls:
 *
 *   pair                              prefix  suffix   d   levenshtein
 *   WBTC 2024 trusted vs lookalike       4       6    10      0.325
 *   USDT 2025 trusted vs lookalike       4       4     8      0.325
 *   unrelated control                    0       0     0      0.125
 *   unrelated control 2                  0       0     0      0.100
 *
 * Prefix/suffix separates cleanly (10 and 8 vs 0). Full-string Levenshtein
 * gives real attacks 0.325 against a 0.10-0.125 floor: a 0.2 gap on a 0-1
 * scale, with real attacks scoring BELOW the midpoint. That is why
 * LEV_MAX_ALONE exists.
 */

/**
 * Minimum matching leading hex characters (after the `0x`) for a
 * prefix/suffix match to be considered at all.
 *
 * Source: (b)'s detection floor is `a >= 3`, chosen because wallet UIs
 * historically truncate addresses to the first and last 3-5 characters.
 * Observed attacks cluster from (3,4) upward.
 */
export const MIN_PREFIX_CHARS = 3;

/**
 * Minimum matching trailing hex characters. Source: (b)'s floor `b >= 4`.
 */
export const MIN_SUFFIX_CHARS = 4;

/**
 * Total matched end characters (`d = prefix + suffix`) at which the
 * prefix/suffix score saturates at 1.0.
 *
 * Source: (b) observes attack counts thinning past d=14 and topping out near
 * d=20 (estimated ~27,093 GPU-days to vanity-mine). By d=16 a collision is
 * not plausibly accidental, so there is nothing left to express above it.
 */
export const SATURATION_D = 16;

/**
 * Score awarded to a prefix/suffix match that just clears the floor.
 *
 * A match at exactly (3,4) is already a real signal — it is (b)'s detection
 * floor, not a coincidence — so the floor score is high. Both incident
 * fixtures land at or above this.
 */
export const PREFIX_SUFFIX_FLOOR = 0.75;

/**
 * `d` at which PREFIX_SUFFIX_FLOOR is awarded. Scores ramp linearly from
 * here to SATURATION_D.
 *
 * MIN_PREFIX_CHARS + MIN_SUFFIX_CHARS = 7 is the smallest possible qualifying
 * d, but 8 is used as the ramp origin so that the USDT 2025 fixture (d=8,
 * the harder of the two real cases) sits exactly at the floor rather than
 * above it. That fixture then requires Levenshtein corroboration to reach
 * high_risk, which is the combination rule earning its place.
 */
export const RAMP_ORIGIN_D = 8;

/**
 * Combined score at or above which a match is labelled `high_risk`.
 *
 * Set below both fixtures' final combined scores and far above the 0.125
 * unrelated-control ceiling.
 */
export const HIGH_RISK_AT = 0.8;

/**
 * Combined score at or above which a match is labelled `caution`.
 *
 * Catches near-floor prefix/suffix hits and Levenshtein-only hits without
 * letting either reach `high_risk`.
 */
export const CAUTION_AT = 0.55;

/**
 * Address length in hex characters, excluding the `0x`. The normalizing
 * denominator for edit distance.
 */
export const ADDRESS_BODY_LENGTH = 40;

/**
 * Hard ceiling on the combined score when the only contributing signal is
 * Levenshtein similarity — i.e. no prefix/suffix match cleared the floor.
 *
 * Deliberately just below HIGH_RISK_AT so the cap is the visibly binding
 * constraint rather than an accident of arithmetic. Rationale: per the
 * measurement table above, full-string edit distance does not separate real
 * poisoning pairs from unrelated addresses well enough to assert the strongest
 * verdict. Levenshtein is kept because it corroborates borderline
 * prefix/suffix matches and catches end-shifted variants that an exact
 * prefix/suffix comparison misses — but on its own it caps at `caution`.
 *
 * Asserted directly by a unit test, not left true by construction.
 *
 * Concrete case this defends against, from the calibration run: shifting one
 * character into the middle of a trusted address
 * (`0xd9a1b0b1…3a91` -> `0xd9a51b0b…53a9`) scores **0.95** on Levenshtein —
 * edit distance 2 — while prefix/suffix correctly scores it 0, because the
 * suffix no longer aligns. Uncapped, that single insertion would assert
 * `high_risk` on a pair no wallet UI would ever confuse, since the visible
 * ends differ. The cap is what keeps a high edit-similarity score from
 * outranking the signal that actually reflects the attack.
 */
export const LEV_MAX_ALONE = 0.79;

/**
 * Maximum lift the Levenshtein signal can add on top of a qualifying
 * prefix/suffix match.
 *
 * Derived, not chosen. Measured Levenshtein similarity is 0.325 for both
 * incident pairs and at most 0.125 for the unrelated controls. Two constraints
 * follow, given PREFIX_SUFFIX_FLOOR = 0.75 and HIGH_RISK_AT = 0.80:
 *
 *   lower bound   the USDT 2025 fixture must clear high_risk once corroborated
 *                 0.75 + w * 0.325 >= 0.80   =>   w >= 0.1538
 *
 *   upper bound   the worst control must NOT lift a floor-level match over
 *                 0.75 + w * 0.125 <  0.80   =>   w <  0.4000
 *
 * 0.20 sits inside both with margin at each end: the USDT fixture lands at
 * 0.815, a control-strength Levenshtein signal lands at 0.775 and stays
 * `caution`. Both are asserted by tests, so a future retune that breaks either
 * bound fails rather than silently reclassifying.
 */
export const LEV_LIFT_WEIGHT = 0.2;

/**
 * `risk_confidence` returned when no trusted identity was available to check
 * against, so no comparison actually ran.
 *
 * Non-zero because "we could not check" is itself a weak negative signal for
 * an agent about to move funds; low because nothing was verified. Never
 * paired with a `safe` label.
 */
export const INSUFFICIENT_HISTORY_CONFIDENCE = 0.25;

/**
 * `risk_confidence` returned when a real comparison ran across a non-empty
 * trusted set and found nothing above CAUTION_AT.
 *
 * High but not 1.0: the check that ran is sound, but it only covers lookalike
 * impersonation. A `safe` here means "not a lookalike of anything you trust",
 * not "this address is safe" — no single miner can assert the latter.
 */
export const NO_MATCH_CONFIDENCE = 0.9;
