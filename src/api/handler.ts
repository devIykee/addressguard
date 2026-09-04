import type { Chain, CounterpartySolvency, TrustedIdentity } from '../domain/entities/index.ts';
import type { PoisoningDetectionService } from '../domain/services/poisoning-detection-service.ts';
import type { BlockProvider } from '../domain/interfaces/block-provider.ts';
import type { TrustedSetProvider } from '../domain/interfaces/trusted-set-provider.ts';
import type { CounterpartySignalProvider } from '../domain/interfaces/counterparty-signal-provider.ts';
import type { Logger } from '../domain/interfaces/logger.ts';
import { normalizeAddress } from '../domain/address.ts';
import { parseRiskCheckRequest } from './schema.ts';
import { toResponse, type RiskCheckResponse } from './response.ts';

export interface HandlerResult {
  readonly status: number;
  readonly body: RiskCheckResponse | { readonly error: string; readonly details?: string[] };
}

/**
 * The transport-independent request handler.
 *
 * Written as a plain function over a parsed body so the same code serves both
 * entry points — `node:http` locally and the Vercel serverless function in
 * production. Tests exercise this directly, which means the tests exercise what
 * production runs rather than a parallel implementation of it.
 */
export class RiskCheckHandler {
  private readonly service: PoisoningDetectionService;
  private readonly blockProvider: BlockProvider;
  private readonly trustedSetProvider: TrustedSetProvider;
  private readonly logger: Logger;
  /**
   * Optional. The miner answers its own question with or without a second
   * opinion, so the collaborator is optional rather than required — an operator
   * who does not want an outbound dependency composes the app without it and
   * every response reports `counterparty_solvency: { checked: false }`.
   */
  private readonly solvencyProvider: CounterpartySignalProvider | null;

  constructor(
    service: PoisoningDetectionService,
    blockProvider: BlockProvider,
    trustedSetProvider: TrustedSetProvider,
    logger: Logger,
    solvencyProvider: CounterpartySignalProvider | null = null,
  ) {
    this.service = service;
    this.blockProvider = blockProvider;
    this.trustedSetProvider = trustedSetProvider;
    this.logger = logger;
    this.solvencyProvider = solvencyProvider;
  }

  async handle(body: unknown): Promise<HandlerResult> {
    const parsed = parseRiskCheckRequest(body);

    if (!parsed.ok) {
      this.logger.info('rejected malformed request', { errors: parsed.errors });
      return {
        status: 400,
        body: { error: 'invalid_request', details: parsed.errors },
      };
    }

    const request = parsed.value;
    const chain: Chain = request.chain;

    const supplied = (request.callerHistory ?? []).map((identity) => ({
      identity: normalizeAddress(identity),
      source: 'caller_supplied' as const,
    }));

    // Chain derivation runs only when the caller supplied no history of their
    // own. Two reasons: it is the case that would otherwise always answer
    // `insufficient_history` (an autonomously routed call has no history to
    // supply), and skipping the network call when history IS supplied keeps the
    // common path fast.
    const derived =
      supplied.length === 0 && request.callerAddress !== undefined
        ? await this.deriveTrust(request.callerAddress, chain)
        : [];

    const trustedSet: TrustedIdentity[] = [...supplied, ...derived];

    // Both outbound reads are metadata-or-advisory, and neither depends on the
    // other, so they run concurrently. Serially they would add up to two round
    // trips (up to ~2s + ~5s) on a 15s function budget; concurrently the cost is
    // the slower of the two. `Promise.all` is safe here only because both
    // providers are contractually non-throwing — the solvency provider catches
    // everything and resolves to `unavailable`, and the block provider resolves
    // to `null`. If either could reject, one failure would take down the other.
    const [block, solvency] = await Promise.all([
      this.blockProvider.currentBlock(chain),
      this.solvencyOf(request.address, chain),
    ]);

    const result = this.service.check(request.address, trustedSet);

    this.logger.info('risk check complete', {
      address: result.address,
      chain,
      label: result.riskLabel,
      trustedSetSize: result.trustedSetSize,
      suppliedCount: supplied.length,
      derivedCount: derived.length,
      block,
      solvency: solvency.state,
    });

    return {
      status: 200,
      body: toResponse(
        result,
        chain,
        block,
        describeTrustSource(supplied.length, derived.length),
        solvency,
      ),
    };
  }

  /**
   * Reads the counterparty solvency signal, or reports why it is absent.
   *
   * Wrapped in its own try/catch despite the provider being contractually
   * non-throwing, for the same reason `deriveTrust` is: this is the component
   * that talks to a third party, and a defect there must degrade one advisory
   * field rather than fail a check that had already succeeded.
   */
  private async solvencyOf(address: string, chain: Chain): Promise<CounterpartySolvency> {
    if (this.solvencyProvider === null) {
      return { state: 'unavailable', reason: 'not_configured' };
    }

    try {
      return await this.solvencyProvider.solvencyOf(normalizeAddress(address), chain);
    } catch (error: unknown) {
      this.logger.error('solvency provider threw; continuing without it', {
        chain,
        error: error instanceof Error ? error.message : String(error),
      });
      return { state: 'unavailable', reason: 'provider_error' };
    }
  }

  private async deriveTrust(
    callerAddress: string,
    chain: Chain,
  ): Promise<readonly TrustedIdentity[]> {
    try {
      return await this.trustedSetProvider.deriveTrustedSet(normalizeAddress(callerAddress), chain);
    } catch (error: unknown) {
      // The provider is contractually non-throwing, but it is the one component
      // that talks to a third-party explorer. A defect there must degrade to
      // `insufficient_history`, not to a 500.
      this.logger.error('trusted-set derivation threw; continuing without it', {
        chain,
        error: error instanceof Error ? error.message : String(error),
      });
      return [];
    }
  }
}

function describeTrustSource(
  suppliedCount: number,
  derivedCount: number,
): RiskCheckResponse['detail']['trust_source'] {
  if (suppliedCount > 0 && derivedCount > 0) return 'mixed';
  if (suppliedCount > 0) return 'caller_supplied';
  if (derivedCount > 0) return 'chain_derived';
  return 'none';
}
