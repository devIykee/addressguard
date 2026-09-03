import type { Chain, TrustedIdentity } from '../domain/entities/index.ts';
import type { PoisoningDetectionService } from '../domain/services/poisoning-detection-service.ts';
import type { BlockProvider } from '../domain/interfaces/block-provider.ts';
import type { TrustedSetProvider } from '../domain/interfaces/trusted-set-provider.ts';
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

  constructor(
    service: PoisoningDetectionService,
    blockProvider: BlockProvider,
    trustedSetProvider: TrustedSetProvider,
    logger: Logger,
  ) {
    this.service = service;
    this.blockProvider = blockProvider;
    this.trustedSetProvider = trustedSetProvider;
    this.logger = logger;
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

    // Block height is metadata; it must never fail the check, so it is read
    // concurrently with nothing and its failure is a null rather than a throw.
    const block = await this.blockProvider.currentBlock(chain);

    const result = this.service.check(request.address, trustedSet);

    this.logger.info('risk check complete', {
      address: result.address,
      chain,
      label: result.riskLabel,
      trustedSetSize: result.trustedSetSize,
      suppliedCount: supplied.length,
      derivedCount: derived.length,
      block,
    });

    return {
      status: 200,
      body: toResponse(result, chain, block, describeTrustSource(supplied.length, derived.length)),
    };
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
