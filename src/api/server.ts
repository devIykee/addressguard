import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { buildApp } from './app.ts';
import { CHAINS } from './schema.ts';

/**
 * Local / container HTTP entry point.
 *
 * Plain `node:http` with no framework: the miner has one real route, and a
 * dependency that needs patching mid-hackathon is a liveness risk (Rule 02
 * requires the miner to stay operational through Track 3). The Vercel entry
 * point in `api/index.ts` wraps the same handler.
 */

const MAX_BODY_BYTES = 64 * 1024;

const app = buildApp();

const server = createServer((request, response) => {
  void route(request, response);
});

async function route(request: IncomingMessage, response: ServerResponse): Promise<void> {
  const url = new URL(request.url ?? '/', `http://${request.headers.host ?? 'localhost'}`);

  if (request.method === 'GET' && url.pathname === '/health') {
    // Liveness only — deliberately does not touch RPC or the explorer. A health
    // check that fails because a third-party explorer is down would report the
    // miner as dead when it is still able to serve every request correctly.
    send(response, 200, {
      status: 'ok',
      service: 'addressguard',
      supported_intents: ['FRAUD_DETECTION'],
      chains: CHAINS,
    });
    return;
  }

  if (url.pathname !== '/risk-check') {
    send(response, 404, { error: 'not_found', details: ['only POST /risk-check is served'] });
    return;
  }

  if (request.method !== 'POST') {
    send(response, 405, { error: 'method_not_allowed', details: ['use POST'] });
    return;
  }

  let raw: string;
  try {
    raw = await readBody(request);
  } catch (error: unknown) {
    const message = error instanceof Error ? error.message : String(error);
    // Answer before hanging up. Destroying the socket on the spot would leave
    // the caller with an empty reply instead of a 413 they can act on, so the
    // remaining upload is abandoned only once the response has been flushed.
    response.on('finish', () => request.destroy());
    send(response, 413, { error: 'request_too_large', details: [message] });
    return;
  }

  let body: unknown;
  try {
    body = raw.length === 0 ? {} : JSON.parse(raw);
  } catch {
    send(response, 400, { error: 'invalid_json', details: ['body must be valid JSON'] });
    return;
  }

  try {
    const result = await app.handler.handle(body);
    send(response, result.status, result.body);
  } catch (error: unknown) {
    // Nothing in the handler is expected to throw; if it does, the miner must
    // still answer rather than hang the connection.
    app.logger.error('unhandled error serving risk check', {
      error: error instanceof Error ? error.message : String(error),
    });
    send(response, 500, { error: 'internal_error' });
  }
}

function readBody(request: IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let size = 0;
    let rejected = false;

    request.on('data', (chunk: Buffer) => {
      if (rejected) return;
      size += chunk.length;
      if (size > MAX_BODY_BYTES) {
        // Stop buffering immediately, but leave the socket open so the caller
        // receives the 413. The route handler destroys it after responding.
        rejected = true;
        chunks.length = 0;
        request.pause();
        reject(new Error(`body exceeds ${MAX_BODY_BYTES} bytes`));
        return;
      }
      chunks.push(chunk);
    });

    request.on('end', () => {
      if (!rejected) resolve(Buffer.concat(chunks).toString('utf8'));
    });
    request.on('error', reject);
  });
}

function send(response: ServerResponse, status: number, body: unknown): void {
  const payload = JSON.stringify(body);
  response.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'content-length': Buffer.byteLength(payload),
  });
  response.end(payload);
}

const port = Number.parseInt(process.env.PORT ?? '8080', 10);
server.listen(port, () => {
  app.logger.info('addressguard listening', { port });
});
