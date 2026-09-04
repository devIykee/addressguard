import type { CounterpartySignalProvider } from '../domain/interfaces/counterparty-signal-provider.ts';
import type { Logger } from '../domain/interfaces/logger.ts';
import type { Chain, CounterpartySolvency, SolvencyVerdict } from '../domain/entities/index.ts';
import { normalizeAddress, isValidAddress } from '../domain/address.ts';

/**
 * Anchor — a Telegraph FRAUD_DETECTION miner (registration #49) that reads live
 * Aave v3 lending state and returns an ALLOW / RECHECK / BLOCK solvency verdict
 * for a wallet.
 *
 * Called over plain HTTP rather than through the Telegraph node. Routing a call
 * through `/engine/v1/ask` costs $0.01 in x402 payment per request and, measured
 * during integration, adds 17-20s of latency before the miner is even reached —
 * well past this miner's 15s function budget. The direct call is 1-3s and free.
 * The Telegraph path is the right one for a consumer app that wants to generate
 * countable intent traffic; it is the wrong one for a miner enriching its own
 * answer inside a request.
 *
 * @see https://github.com/Sammy949/anchor
 */
const ANCHOR_BASE_URL = 'https://anchor-miner.vercel.app';

/**
 * Anchor reads Aave v3 from Base mainnet (chain 8453) only — a single hardcoded
 * pool address, no chain parameter in its API.
 *
 * This matters more than it looks. The endpoint accepts ANY well-formed address
 * and answers 200 with `riskLabel: NONE` when it finds no position. So asking it
 * about an Ethereum address does not fail: it returns a confident-looking
 * "no lending position found", which is true of Base and says nothing about
 * Ethereum. Passing an Ethereum address through would manufacture a clean signal
 * out of a chain mismatch.
 *
 * So the chain is gated here, at the boundary, and a non-Base chain resolves to
 * `unavailable` with the reason stated.
 */
const SUPPORTED_CHAINS: readonly Chain[] = ['base'];

/**
 * Measured against production over 24 cache-defeating calls: p50 1.4s, p90 4.0s,
 * worst 8.7s (a cold serverless start plus an RPC round trip).
 *
 * 5s deliberately cuts the tail. This signal is advisory — losing it degrades
 * `recommended_action` to the poisoning verdict alone — so waiting 9s for it
 * inside a 15s budget would risk the whole request for a field that is not the
 * answer. Same reasoning as the block-height timeout, one tier longer because
 * this one feeds a verdict rather than metadata.
 */
const TIMEOUT_MS = 5_000;

const VERDICTS: readonly SolvencyVerdict[] = ['ALLOW', 'RECHECK', 'BLOCK'];

/**
 * Adapts Anchor's HTTP response into a `CounterpartySolvency`.
 *
 * Contractually non-throwing, like every other provider here: an unreachable or
 * misbehaving upstream must degrade one advisory field, never fail the request.
 * The class catches everything and reports `unavailable` with a reason.
 */
export class AnchorSignalProvider implements CounterpartySignalProvider {
  private readonly logger: Logger;
  private readonly baseUrl: string;
  private readonly timeoutMs: number;

  constructor(logger: Logger, baseUrl: string = ANCHOR_BASE_URL, timeoutMs: number = TIMEOUT_MS) {
    this.logger = logger;
    this.baseUrl = baseUrl;
    this.timeoutMs = timeoutMs;
  }

  async solvencyOf(address: string, chain: Chain): Promise<CounterpartySolvency> {
    const normalized = normalizeAddress(address);

    if (!isValidAddress(normalized)) {
      // Upstream treats a malformed address as a natural-language question and
      // answers it with an LLM — verified: `?wallet=not-an-address` returns
      // `verdict: INFO` with a paragraph of prose. Never send one.
      return { state: 'unavailable', reason: 'malformed_address' };
    }

    if (!SUPPORTED_CHAINS.includes(chain)) {
      return { state: 'unavailable', reason: `chain_not_covered:${chain}` };
    }

    const url = new URL('/api/risk-check', this.baseUrl);
    url.searchParams.set('wallet', normalized);

    let payload: unknown;
    try {
      const response = await fetch(url, {
        headers: { accept: 'application/json' },
        signal: AbortSignal.timeout(this.timeoutMs),
      });

      if (!response.ok) {
        this.logger.warn('solvency source returned non-2xx', {
          status: response.status,
          address: normalized,
        });
        return { state: 'unavailable', reason: `http_${response.status}` };
      }

      payload = await response.json();
    } catch (error: unknown) {
      // AbortSignal.timeout raises TimeoutError; network failures raise TypeError.
      // Both are the same outcome here, so they are reported the same way.
      const reason = error instanceof Error ? error.name : 'unknown';
      this.logger.warn('solvency source unreachable', {
        address: normalized,
        reason,
        error: error instanceof Error ? error.message : String(error),
      });
      return { state: 'unavailable', reason: `unreachable:${reason}` };
    }

    return this.interpret(payload, normalized);
  }

  private interpret(payload: unknown, address: string): CounterpartySolvency {
    const parsed = parseAnchorResponse(payload);

    if (parsed === null) {
      // The endpoint serves two response shapes from one path: a wallet verdict,
      // and an `INFO` knowledge answer with `signals: null`. An `INFO` here means
      // the address was not recognized as one, so there is no solvency claim in
      // the payload at all — treating its `verdict` field as one would report an
      // LLM paragraph as a lending assessment.
      this.logger.warn('solvency source answered in an unexpected shape', { address });
      return { state: 'unavailable', reason: 'unrecognized_response' };
    }

    if (parsed.riskLabel === 'NONE') {
      this.logger.info('counterparty has no lending position', {
        address,
        source: parsed.source,
      });
      return {
        state: 'no_position',
        source: parsed.source,
        checkedAtBlock: parsed.blockNumber,
      };
    }

    return {
      state: 'assessed',
      source: parsed.source,
      verdict: parsed.verdict,
      reasoning: parsed.reasoning,
      healthFactor: parsed.healthFactor,
      checkedAtBlock: parsed.blockNumber,
    };
  }
}

interface AnchorVerdict {
  readonly verdict: SolvencyVerdict;
  readonly riskLabel: string;
  readonly reasoning: string;
  readonly healthFactor: number | null;
  readonly blockNumber: number | null;
  readonly source: string;
}

/**
 * Validates and flattens Anchor's wallet-path response.
 *
 * Exported and pure so the shape handling is tested against recorded payloads
 * rather than against the network — including the `INFO` knowledge shape, which
 * is the one that would otherwise slip through as a solvency verdict.
 *
 * @returns `null` for anything that is not a wallet-path solvency verdict.
 */
export function parseAnchorResponse(payload: unknown): AnchorVerdict | null {
  if (typeof payload !== 'object' || payload === null) return null;
  const body = payload as Record<string, unknown>;

  const verdict = body.verdict;
  if (typeof verdict !== 'string' || !VERDICTS.includes(verdict as SolvencyVerdict)) {
    return null;
  }

  // `signals` is null on the knowledge path and populated on the wallet path.
  // This is the field that separates the two shapes, so it is required rather
  // than defaulted.
  const signals = body.signals;
  if (typeof signals !== 'object' || signals === null) return null;
  const s = signals as Record<string, unknown>;

  const riskLabel = s.riskLabel;
  if (typeof riskLabel !== 'string') return null;

  const meta = typeof body.meta === 'object' && body.meta !== null
    ? (body.meta as Record<string, unknown>)
    : {};

  return {
    verdict: verdict as SolvencyVerdict,
    riskLabel,
    reasoning: typeof body.reasoning === 'string' ? body.reasoning : '',
    healthFactor: finiteOrNull(s.healthFactor),
    blockNumber: finiteOrNull(meta.blockNumber),
    source: typeof meta.source === 'string' ? meta.source : 'anchor',
  };
}

/**
 * Numbers only, and only real ones. A `null` health factor is meaningful here —
 * Aave returns uint max for a position with no debt — so it must survive as
 * `null` rather than becoming `0`, which would read as a liquidated position.
 */
function finiteOrNull(value: unknown): number | null {
  return typeof value === 'number' && Number.isFinite(value) ? value : null;
}
