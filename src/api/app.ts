import type { PoisoningDetectionService } from '../domain/services/poisoning-detection-service.ts';
import { PoisoningDetectionService as Service } from '../domain/services/poisoning-detection-service.ts';
import { PrefixSuffixStrategy } from '../matching/prefix-suffix/prefix-suffix-strategy.ts';
import { LevenshteinStrategy } from '../matching/levenshtein/levenshtein-strategy.ts';
import { ConsoleLogger } from '../infrastructure/console-logger.ts';
import { RpcBlockProvider } from '../infrastructure/rpc-block-provider.ts';
import { ExplorerTrustedSetProvider } from '../infrastructure/explorer-trusted-set-provider.ts';
import { AnchorSignalProvider } from '../infrastructure/anchor-signal-provider.ts';
import { RiskCheckHandler } from './handler.ts';
import type { Logger } from '../domain/interfaces/logger.ts';

/**
 * The single composition root.
 *
 * This is the only place concrete implementations are named. Every other module
 * takes its collaborators through its constructor, which is what makes the unit
 * tests pure and what makes Tier 2 additive: adding the ENS strategy means one
 * more entry in the `strategies` array here, and no edit anywhere else.
 */
export interface App {
  readonly handler: RiskCheckHandler;
  readonly service: PoisoningDetectionService;
  readonly logger: Logger;
}

export function buildApp(logger: Logger = new ConsoleLogger()): App {
  const strategies = [
    new PrefixSuffixStrategy(logger),
    new LevenshteinStrategy(logger),
    // TIER 2b: new EnsHomoglyphStrategy(logger) goes here. Nothing else changes.
  ];

  const service = new Service(strategies, logger);
  const blockProvider = new RpcBlockProvider(logger);
  const trustedSetProvider = new ExplorerTrustedSetProvider(logger);

  // The counterparty solvency signal — an independent second opinion from
  // Anchor, a FRAUD_DETECTION miner that reads live Aave v3 lending state.
  //
  // Not a `SimilarityStrategy`: it answers a different question, asynchronously,
  // with a different failure mode. So it enters through its own seam, lands in
  // its own response block, and never moves `risk_label`. See
  // `CounterpartySignalProvider` for the full argument.
  const solvencyProvider = new AnchorSignalProvider(logger);

  return {
    handler: new RiskCheckHandler(
      service,
      blockProvider,
      trustedSetProvider,
      logger,
      solvencyProvider,
    ),
    service,
    logger,
  };
}
