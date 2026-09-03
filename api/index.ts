import { buildApp } from '../src/api/app.ts';
import { CHAINS } from '../src/api/schema.ts';

/**
 * Vercel serverless entry point.
 *
 * Deliberately thin: it translates a Vercel request/response pair into the same
 * `RiskCheckHandler.handle(body)` call that `src/api/server.ts` makes locally.
 * The routing, validation, matching, and response shaping are all shared, so
 * the integration tests exercise production behaviour rather than a parallel
 * implementation of it.
 *
 * The app is built once at module scope so warm invocations reuse the composed
 * object graph and the block-height cache. On a cold start this costs one
 * construction and no network calls — `buildApp` touches nothing external.
 */

interface VercelRequest {
  readonly method?: string;
  readonly url?: string;
  readonly body?: unknown;
}

interface VercelResponse {
  status(code: number): VercelResponse;
  json(body: unknown): void;
  setHeader(name: string, value: string): void;
}

const app = buildApp();

export default async function handler(
  request: VercelRequest,
  response: VercelResponse,
): Promise<void> {
  response.setHeader('content-type', 'application/json; charset=utf-8');

  const path = new URL(request.url ?? '/', 'http://localhost').pathname;

  if (request.method === 'GET' && path.endsWith('/health')) {
    // Liveness only. It must not depend on the RPC endpoints or the explorer:
    // a health check that fails because a third-party service is down would
    // report the miner as dead while it is still answering every request
    // correctly, and Rule 02 judges on staying operational.
    response.status(200).json({
      status: 'ok',
      service: 'addressguard',
      supported_intents: ['FRAUD_DETECTION'],
      chains: CHAINS,
    });
    return;
  }

  if (request.method !== 'POST') {
    response.status(405).json({ error: 'method_not_allowed', details: ['use POST'] });
    return;
  }

  try {
    // Vercel parses JSON bodies for us; a string body means an unparsed or
    // non-JSON content type, so it is parsed here rather than rejected.
    const body = typeof request.body === 'string' ? safeParse(request.body) : (request.body ?? {});
    const result = await app.handler.handle(body);
    response.status(result.status).json(result.body);
  } catch (error: unknown) {
    app.logger.error('unhandled error in serverless handler', {
      error: error instanceof Error ? error.message : String(error),
    });
    response.status(500).json({ error: 'internal_error' });
  }
}

function safeParse(raw: string): unknown {
  if (raw.length === 0) return {};
  try {
    return JSON.parse(raw);
  } catch {
    // An unparseable body reaches the zod boundary as a non-object and comes
    // back as a 400 with field errors, which is more useful than a bare 500.
    return raw;
  }
}
