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

/**
 * Hard ceiling on the upstream response body.
 *
 * The upstream's real answers measure ~700 bytes, so 32 KB is ~45x headroom and
 * still small enough that nothing it returns can matter to this function's own
 * memory or response size. Without this, `reasoning` and `source` are copied
 * verbatim from a third party into AddressGuard's own response with no bound at
 * all: an 8 MB `reasoning` field was demonstrated producing a 9 MB AddressGuard
 * response, past Vercel's 4.5 MB response cap, which converts a healthy request
 * into a 413. Read the body as a bounded stream rather than trusting
 * `content-length`, which a hostile or broken upstream can simply lie about.
 */
const MAX_BODY_BYTES = 32 * 1024;

/**
 * Caps on the individual strings copied out of the upstream answer.
 *
 * Separate from MAX_BODY_BYTES because a body can be small enough to accept and
 * still carry one absurd field. These are display/log values, never used in a
 * comparison, so truncating is lossless for every real answer.
 */
const MAX_REASONING_CHARS = 2_000;
const MAX_SOURCE_CHARS = 128;

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
        // A redirect is not a valid answer from a pinned single-purpose endpoint.
        // Left at the default `follow`, one compromised or hijacked upstream turns
        // this trusted outbound call into an attacker-chosen one — demonstrated:
        // a 302 to a local service was followed, and that service's body was
        // accepted as a solvency verdict.
        redirect: 'error',
      });

      if (!response.ok) {
        this.logger.warn('solvency source returned non-2xx', {
          status: response.status,
          address: normalized,
        });
        return { state: 'unavailable', reason: `http_${response.status}` };
      }

      const body = await readCapped(response, MAX_BODY_BYTES);
      if (body === null) {
        this.logger.warn('solvency source body exceeded the cap', {
          address: normalized,
          capBytes: MAX_BODY_BYTES,
        });
        return { state: 'unavailable', reason: 'body_too_large' };
      }

      payload = JSON.parse(body);
    } catch (error: unknown) {
      // AbortSignal.timeout raises TimeoutError; network failures raise TypeError;
      // a refused redirect and unparseable JSON land here too. All are the same
      // outcome — no usable second opinion — so all report the same way.
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
    riskLabel: clamp(riskLabel, MAX_SOURCE_CHARS),
    reasoning: typeof body.reasoning === 'string' ? clamp(body.reasoning, MAX_REASONING_CHARS) : '',
    healthFactor: plausibleHealthFactor(s.healthFactor),
    blockNumber: plausibleBlock(meta.blockNumber),
    source: typeof meta.source === 'string' ? clamp(meta.source, MAX_SOURCE_CHARS) : 'anchor',
  };
}

/**
 * Truncates an upstream string to a bound.
 *
 * Every string here is copied into AddressGuard's own response, so an unbounded
 * one is an amplification vector: a hostile upstream's 8 MB `reasoning` became a
 * 9 MB AddressGuard response in testing, past Vercel's 4.5 MB cap. The marker is
 * kept so a truncated value is visibly truncated rather than silently altered.
 */
function clamp(value: string, maxChars: number): string {
  return value.length <= maxChars ? value : `${value.slice(0, maxChars)}…[truncated]`;
}

/**
 * A health factor that is a real number in a plausible range, or `null`.
 *
 * `Number.isFinite` alone accepts `-1e308` and `1e308`, which are finite and
 * absurd — a negative health factor is not a thing Aave can report, and either
 * extreme rendered into a response is a nonsense number attributed to a named
 * source. Aave's own values sit around 1; anything past 1e6 is a defect upstream,
 * not a position. Reported as `null` (unknown) rather than clamped to a number
 * that was never measured.
 *
 * `null` still survives as `null`: Aave returns uint max for a position with no
 * debt, and coercing that to 0 would read as a liquidated position.
 */
function plausibleHealthFactor(value: unknown): number | null {
  if (typeof value !== 'number' || !Number.isFinite(value)) return null;
  if (value < 0 || value > 1e6) return null;
  return value;
}

/** A block height that is a non-negative integer, or `null`. */
function plausibleBlock(value: unknown): number | null {
  if (typeof value !== 'number' || !Number.isInteger(value) || value < 0) return null;
  return value;
}

/**
 * Reads a response body up to `maxBytes`, returning `null` if it is longer.
 *
 * Streams and counts rather than trusting `content-length`, which a hostile or
 * broken upstream can understate or omit. Aborts as soon as the cap is passed, so
 * an endless body is bounded by the cap and not only by the request timeout.
 */
async function readCapped(response: Response, maxBytes: number): Promise<string | null> {
  const body = response.body;
  if (body === null) return '';

  const reader = body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;

  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      if (value === undefined) continue;

      total += value.byteLength;
      if (total > maxBytes) {
        await reader.cancel();
        return null;
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }

  return new TextDecoder().decode(concat(chunks, total));
}

function concat(chunks: readonly Uint8Array[], total: number): Uint8Array {
  const out = new Uint8Array(total);
  let at = 0;
  for (const chunk of chunks) {
    out.set(chunk, at);
    at += chunk.byteLength;
  }
  return out;
}
