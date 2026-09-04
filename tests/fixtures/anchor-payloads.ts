/**
 * Anchor responses, recorded verbatim from production during integration.
 *
 * Anchor is a Telegraph FRAUD_DETECTION miner (registration #49, verified live
 * on the intent's miner list) that reads live Aave v3 lending state on Base
 * mainnet and returns an ALLOW / RECHECK / BLOCK solvency verdict.
 *
 * Recorded rather than fetched so the adapter tests are offline and
 * deterministic — the same seam `explorer-payloads` provides for trust
 * derivation. Only the thin HTTP layer above these is untested by unit tests.
 *
 * Captured 2026-09-03 from https://anchor-miner.vercel.app/api/risk-check.
 * Nothing here is synthetic except where a comment says so.
 */

/**
 * A live Aave v3 borrower with real leverage. The `MODERATE` label maps to
 * `ALLOW` upstream, which is the case that proves `ALLOW` is not the same thing
 * as "no position": there IS a position here, it is simply healthy.
 */
export const ANCHOR_ACTIVE_POSITION = {
  wallet: '0x50B75AaCb1ed974F5c901a32BeE767de39CBb060',
  protocol: 'aave-v3',
  verdict: 'ALLOW',
  reasoning:
    'Active Aave v3 position carries moderate leverage (health factor 1.51) with a ~33.70% ' +
    'buffer to liquidation. Adequate for now; no action required beyond normal monitoring.',
  signals: {
    riskLabel: 'MODERATE',
    healthFactor: 1.5083,
    liquidationDistancePercent: 33.7,
    totalCollateralUSD: 88336.83,
    totalDebtUSD: 45682.47,
    liquidationThreshold: 0.78,
  },
  confidence: 0.967,
  meta: {
    blockNumber: 50821710,
    timestamp: '2026-09-03T10:52:47.000Z',
    source: 'aave-v3-pool-contract',
    chainId: 8453,
    network: 'base-mainnet',
  },
} as const;

/**
 * The WBTC 2024 lookalike — the attacker address from this project's own
 * incident fixture — as Anchor sees it.
 *
 * This is the measurement that decides the whole integration design: a real
 * poisoning address has NO lending position, so the solvency check has nothing
 * to say about it. The two signals are orthogonal, which is why one must never
 * be allowed to move the other's verdict. Verified identically for the USDT 2025
 * lookalike and for the legitimate trusted address in both incidents.
 */
export const ANCHOR_NO_POSITION = {
  wallet: '0xd9A1C3788D81257612E2581A6ea0aDa244853a91',
  protocol: 'aave-v3',
  verdict: 'ALLOW',
  reasoning:
    'No Aave v3 lending position and no leverage found for this wallet. No on-chain solvency ' +
    'defect detected; nothing to flag from lending state alone.',
  signals: {
    riskLabel: 'NONE',
    healthFactor: null,
    liquidationDistancePercent: null,
    totalCollateralUSD: 0,
    totalDebtUSD: 0,
    liquidationThreshold: 0,
  },
  confidence: 0.993,
  meta: {
    blockNumber: 50821585,
    timestamp: '2026-09-03T10:48:37.000Z',
    source: 'aave-v3-pool-contract',
    chainId: 8453,
    network: 'base-mainnet',
  },
} as const;

/**
 * The knowledge-path shape, recorded from `?wallet=not-an-address`.
 *
 * The single most important fixture here. Anchor serves TWO response shapes from
 * one path: a wallet solvency verdict, and this — an LLM answer to a
 * natural-language fraud question, with `signals: null` and `verdict: 'INFO'`.
 *
 * An adapter that read `verdict` without checking `signals` would report an LLM
 * paragraph as a lending assessment. `INFO` is not in the solvency vocabulary so
 * it is rejected on the verdict check alone, but the test asserts both guards,
 * because a future upstream change that returned ALLOW on this path would
 * otherwise slip straight through.
 */
export const ANCHOR_KNOWLEDGE_ANSWER = {
  wallet: null,
  protocol: null,
  verdict: 'INFO',
  reasoning:
    'No relevant fraud case, scheme, scam, or financial-crime topic was identified in the request.',
  signals: null,
  confidence: 0.8,
  meta: {
    blockNumber: null,
    timestamp: '2026-09-03T11:20:57.631Z',
    source: 'llm-fraud-knowledge',
    model: 'openai/gpt-oss-120b',
  },
} as const;

/**
 * The 400 body, recorded from a call with no parameters at all. Included so the
 * adapter is tested against the real error shape rather than an imagined one.
 */
export const ANCHOR_MISSING_INPUT = {
  error: 'Missing input. Provide a wallet to assess, or a query to answer.',
  examples: {
    wallet: '/api/risk-check?wallet=0x50B75AaCb1ed974F5c901a32BeE767de39CBb060',
    query: '/api/risk-check?query=What+characterized+the+BitConnect+Ponzi+scheme%3F',
  },
} as const;

/**
 * SYNTHETIC. Anchor's own unit tests cover the distressed labels, but no live
 * wallet was in `AT_RISK` or `LIQUIDATABLE` state during the integration window,
 * so these two are hand-built from the documented verdict mapping
 * (AT_RISK -> RECHECK, CRITICAL/LIQUIDATABLE -> BLOCK) rather than recorded.
 *
 * Marked explicitly because every other fixture in this project is real, and a
 * reader is entitled to know which is which.
 */
export const ANCHOR_AT_RISK_SYNTHETIC = {
  wallet: '0x50B75AaCb1ed974F5c901a32BeE767de39CBb060',
  protocol: 'aave-v3',
  verdict: 'RECHECK',
  reasoning:
    'Counterparty holds an active Aave v3 position ~4.12% from liquidation (health factor 1.33). ' +
    'Collateral buffer is thin; re-verify solvency or require added margin before extending credit.',
  signals: {
    riskLabel: 'AT_RISK',
    healthFactor: 1.33,
    liquidationDistancePercent: 4.12,
    totalCollateralUSD: 53000,
    totalDebtUSD: 30000,
    liquidationThreshold: 0.78,
  },
  confidence: 0.95,
  meta: {
    blockNumber: 50821800,
    timestamp: '2026-09-03T10:55:00.000Z',
    source: 'aave-v3-pool-contract',
    chainId: 8453,
    network: 'base-mainnet',
  },
} as const;

/** SYNTHETIC, as above. */
export const ANCHOR_LIQUIDATABLE_SYNTHETIC = {
  wallet: '0x50B75AaCb1ed974F5c901a32BeE767de39CBb060',
  protocol: 'aave-v3',
  verdict: 'BLOCK',
  reasoning:
    'Active Aave v3 position is at or past the liquidation threshold now (health factor 0.98). ' +
    'The counterparty is effectively insolvent on this position; block credit and treat as distressed.',
  signals: {
    riskLabel: 'LIQUIDATABLE',
    healthFactor: 0.98,
    liquidationDistancePercent: 0,
    totalCollateralUSD: 41000,
    totalDebtUSD: 32600,
    liquidationThreshold: 0.78,
  },
  confidence: 0.94,
  meta: {
    blockNumber: 50821900,
    timestamp: '2026-09-03T10:58:00.000Z',
    source: 'aave-v3-pool-contract',
    chainId: 8453,
    network: 'base-mainnet',
  },
} as const;
