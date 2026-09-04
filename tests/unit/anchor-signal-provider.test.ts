import { describe, it, expect } from 'vitest';
import {
  AnchorSignalProvider,
  parseAnchorResponse,
} from '../../src/infrastructure/anchor-signal-provider.ts';
import { RecordingLogger } from './strategy-contract.ts';
import {
  ANCHOR_ACTIVE_POSITION,
  ANCHOR_AT_RISK_SYNTHETIC,
  ANCHOR_KNOWLEDGE_ANSWER,
  ANCHOR_LIQUIDATABLE_SYNTHETIC,
  ANCHOR_MISSING_INPUT,
  ANCHOR_NO_POSITION,
} from '../fixtures/anchor-payloads.ts';
import { WBTC_2024 } from '../fixtures/incidents.ts';

/**
 * The Anchor adapter, tested against recorded production payloads.
 *
 * Two things are under test and they matter for different reasons. `parseAnchorResponse`
 * is where a wrong answer would be *silent*: the upstream endpoint serves two
 * different response shapes from one path, and reading the wrong one would report
 * an LLM paragraph as a lending assessment. The provider class is where a wrong
 * answer would be *loud*: it must never throw, and it must never let a failure
 * upstream become a failure here.
 */

const ADDRESS = ANCHOR_ACTIVE_POSITION.wallet;

/** A fetch stub, so the adapter is tested without the network. */
function stubFetch(
  responder: (url: string) => { status?: number; body?: unknown } | Promise<never>,
): typeof globalThis.fetch {
  return ((input: string | URL) => {
    const result = responder(String(input));
    if (result instanceof Promise) return result;
    const { status = 200, body = {} } = result;
    return Promise.resolve(
      new Response(JSON.stringify(body), {
        status,
        headers: { 'content-type': 'application/json' },
      }),
    );
  }) as typeof globalThis.fetch;
}

/**
 * Swaps `globalThis.fetch` for the duration of one call and restores it after,
 * even on failure. Preferred over `vi.stubGlobal` so the restore is visible at
 * the call site and cannot leak into another test file.
 */
async function withFetch<T>(stub: typeof globalThis.fetch, run: () => Promise<T>): Promise<T> {
  const original = globalThis.fetch;
  globalThis.fetch = stub;
  try {
    return await run();
  } finally {
    globalThis.fetch = original;
  }
}

const build = (logger = new RecordingLogger()): AnchorSignalProvider =>
  new AnchorSignalProvider(logger, 'https://anchor.test');

describe('parseAnchorResponse — separating the two response shapes', () => {
  it('parses a wallet-path solvency verdict', () => {
    const parsed = parseAnchorResponse(ANCHOR_ACTIVE_POSITION);
    expect(parsed).not.toBeNull();
    expect(parsed?.verdict).toBe('ALLOW');
    expect(parsed?.riskLabel).toBe('MODERATE');
    expect(parsed?.healthFactor).toBe(1.5083);
    expect(parsed?.blockNumber).toBe(50821710);
    expect(parsed?.source).toBe('aave-v3-pool-contract');
  });

  it('rejects the knowledge-path answer', () => {
    // The critical case. `verdict: 'INFO'` with `signals: null` is an LLM answer
    // to a natural-language question, not a solvency assessment. Reading its
    // `verdict` field as one would attribute a paragraph of prose to a lending
    // check that never ran.
    expect(parseAnchorResponse(ANCHOR_KNOWLEDGE_ANSWER)).toBeNull();
  });

  it('rejects a solvency-shaped verdict that carries no signals', () => {
    // Belt and braces on the above: if upstream ever answered ALLOW on the
    // knowledge path, the verdict check alone would pass it. The `signals`
    // requirement is what actually separates the two shapes.
    const shaped = { ...ANCHOR_KNOWLEDGE_ANSWER, verdict: 'ALLOW' };
    expect(parseAnchorResponse(shaped)).toBeNull();
  });

  it('rejects the error body', () => {
    expect(parseAnchorResponse(ANCHOR_MISSING_INPUT)).toBeNull();
  });

  it('rejects a verdict outside the solvency vocabulary', () => {
    const rogue = { ...ANCHOR_ACTIVE_POSITION, verdict: 'MAYBE' };
    expect(parseAnchorResponse(rogue)).toBeNull();
  });

  it('rejects non-objects without throwing', () => {
    for (const input of [null, undefined, 'a string', 42, [], true]) {
      expect(parseAnchorResponse(input)).toBeNull();
    }
  });

  it('preserves a null health factor rather than coercing it to zero', () => {
    // Aave returns uint max for a position with no debt, which Anchor reports as
    // `null`. Coerced to 0 it would read as a liquidated position — the exact
    // inversion of what it means.
    const parsed = parseAnchorResponse(ANCHOR_NO_POSITION);
    expect(parsed?.healthFactor).toBeNull();
  });

  it('survives a missing meta block', () => {
    const { meta: _meta, ...withoutMeta } = ANCHOR_ACTIVE_POSITION;
    const parsed = parseAnchorResponse(withoutMeta);
    expect(parsed).not.toBeNull();
    expect(parsed?.blockNumber).toBeNull();
    expect(parsed?.source).toBe('anchor');
  });
});

describe('AnchorSignalProvider — mapping to solvency state', () => {
  it('reports an active healthy position as assessed, not as no_position', () => {
    return withFetch(stubFetch(() => ({ body: ANCHOR_ACTIVE_POSITION })), async () => {
      const solvency = await build().solvencyOf(ADDRESS, 'base');
      expect(solvency.state).toBe('assessed');
      if (solvency.state !== 'assessed') return;
      expect(solvency.verdict).toBe('ALLOW');
      expect(solvency.healthFactor).toBe(1.5083);
      expect(solvency.checkedAtBlock).toBe(50821710);
    });
  });

  it('reports riskLabel NONE as no_position', () => {
    return withFetch(stubFetch(() => ({ body: ANCHOR_NO_POSITION })), async () => {
      const solvency = await build().solvencyOf(WBTC_2024.lookalike, 'base');
      expect(solvency.state).toBe('no_position');
    });
  });

  it('maps a thin position to RECHECK and a liquidatable one to BLOCK', () => {
    return withFetch(stubFetch(() => ({ body: ANCHOR_AT_RISK_SYNTHETIC })), async () => {
      const solvency = await build().solvencyOf(ADDRESS, 'base');
      expect(solvency.state === 'assessed' && solvency.verdict).toBe('RECHECK');
    }).then(() =>
      withFetch(stubFetch(() => ({ body: ANCHOR_LIQUIDATABLE_SYNTHETIC })), async () => {
        const solvency = await build().solvencyOf(ADDRESS, 'base');
        expect(solvency.state === 'assessed' && solvency.verdict).toBe('BLOCK');
      }),
    );
  });

  it('sends the address as a lowercased wallet query parameter', () => {
    const seen: string[] = [];
    return withFetch(
      stubFetch((url) => {
        seen.push(url);
        return { body: ANCHOR_ACTIVE_POSITION };
      }),
      async () => {
        await build().solvencyOf(ADDRESS, 'base');
        expect(seen).toHaveLength(1);
        const url = new URL(seen[0]!);
        expect(url.pathname).toBe('/api/risk-check');
        expect(url.searchParams.get('wallet')).toBe(ADDRESS.toLowerCase());
      },
    );
  });
});

describe('AnchorSignalProvider — a hostile upstream cannot amplify through us', () => {
  /** Builds a solvency-shaped body whose `reasoning` is `bytes` long. */
  const oversized = (bytes: number): unknown => ({
    ...ANCHOR_AT_RISK_SYNTHETIC,
    reasoning: 'A'.repeat(bytes),
  });

  it('rejects a body past the cap rather than buffering it', () => {
    // Demonstrated before the cap existed: an 8 MB `reasoning` produced a 9 MB
    // AddressGuard response, past Vercel's 4.5 MB response limit, turning a
    // healthy request into a 413. The upstream's real answers are ~700 bytes.
    return withFetch(stubFetch(() => ({ body: oversized(64 * 1024) })), async () => {
      const logger = new RecordingLogger();
      const solvency = await build(logger).solvencyOf(ADDRESS, 'base');

      expect(solvency).toEqual({ state: 'unavailable', reason: 'body_too_large' });
      expect(logger.warnings.join()).toContain('exceeded the cap');
    });
  });

  it('truncates a long-but-acceptable reasoning string', () => {
    // A body can pass the byte cap and still carry one absurd field.
    return withFetch(stubFetch(() => ({ body: oversized(8_000) })), async () => {
      const solvency = await build().solvencyOf(ADDRESS, 'base');

      expect(solvency.state).toBe('assessed');
      if (solvency.state !== 'assessed') return;
      expect(solvency.reasoning.length).toBeLessThan(3_000);
      // Visibly truncated, not silently altered.
      expect(solvency.reasoning).toContain('[truncated]');
    });
  });

  it('truncates an oversized source label', () => {
    const body = {
      ...ANCHOR_ACTIVE_POSITION,
      meta: { ...ANCHOR_ACTIVE_POSITION.meta, source: 'B'.repeat(4_000) },
    };
    return withFetch(stubFetch(() => ({ body })), async () => {
      const solvency = await build().solvencyOf(ADDRESS, 'base');
      expect(solvency.state === 'assessed' && solvency.source.length).toBeLessThan(200);
    });
  });

  it('refuses a redirect instead of following it', () => {
    // Left at fetch's default `follow`, a hijacked or compromised upstream turns
    // this one pinned outbound call into an attacker-chosen one. Demonstrated: a
    // 302 to a local service was followed and that service's body was accepted
    // as a solvency verdict.
    const redirecting = (() =>
      Promise.resolve(
        new Response(null, { status: 302, headers: { location: 'http://169.254.169.254/' } }),
      )) as typeof globalThis.fetch;

    return withFetch(redirecting, async () => {
      const solvency = await build().solvencyOf(ADDRESS, 'base');
      // Either the fetch layer rejects (redirect: 'error') or the 302 is a
      // non-2xx. Both are refusals; neither follows the redirect.
      expect(solvency.state).toBe('unavailable');
    });
  });

  it('rejects an implausible health factor rather than reporting it', () => {
    // `Number.isFinite` accepts -1e308. A negative health factor is not
    // something Aave can report, and rendering it would attribute a nonsense
    // number to a named source.
    for (const hf of [-1e308, -1, 1e9, Number.NaN, Number.POSITIVE_INFINITY]) {
      const body = {
        ...ANCHOR_AT_RISK_SYNTHETIC,
        signals: { ...ANCHOR_AT_RISK_SYNTHETIC.signals, healthFactor: hf },
      };
      const parsed = parseAnchorResponse(body);
      expect(parsed?.healthFactor, `healthFactor ${hf} must not be reported`).toBeNull();
    }
  });

  it('keeps a plausible health factor, including the no-debt null', () => {
    expect(parseAnchorResponse(ANCHOR_ACTIVE_POSITION)?.healthFactor).toBe(1.5083);
    expect(parseAnchorResponse(ANCHOR_NO_POSITION)?.healthFactor).toBeNull();
  });

  it('rejects a non-integer or negative block number', () => {
    for (const block of [-1, 1.5, Number.NaN]) {
      const body = { ...ANCHOR_ACTIVE_POSITION, meta: { ...ANCHOR_ACTIVE_POSITION.meta, blockNumber: block } };
      expect(parseAnchorResponse(body)?.blockNumber).toBeNull();
    }
  });

  it('does not let upstream JSON pollute Object.prototype', () => {
    const hostile = `{"verdict":"ALLOW","reasoning":"x","signals":{"riskLabel":"SAFE","healthFactor":1},
      "meta":{"blockNumber":1,"source":"x"},"__proto__":{"polluted":"yes"}}`;

    const parsed = parseAnchorResponse(JSON.parse(hostile));

    expect(parsed?.verdict).toBe('ALLOW');
    expect(({} as Record<string, unknown>).polluted).toBeUndefined();
  });
});

describe('AnchorSignalProvider — every failure degrades, none throws', () => {
  it('reports a non-2xx as unavailable with the status', () => {
    return withFetch(stubFetch(() => ({ status: 502, body: { error: 'upstream' } })), async () => {
      const logger = new RecordingLogger();
      const solvency = await build(logger).solvencyOf(ADDRESS, 'base');
      expect(solvency).toEqual({ state: 'unavailable', reason: 'http_502' });
      expect(logger.warnings.join()).toContain('non-2xx');
    });
  });

  it('reports a network failure as unavailable', () => {
    return withFetch(stubFetch(() => Promise.reject(new TypeError('fetch failed'))), async () => {
      const solvency = await build().solvencyOf(ADDRESS, 'base');
      expect(solvency.state).toBe('unavailable');
      expect(solvency.state === 'unavailable' && solvency.reason).toContain('unreachable');
    });
  });

  it('reports a timeout as unavailable rather than hanging the request', async () => {
    // The stub must honour `signal`, because that is the whole mechanism under
    // test. A stub that returns a never-resolving promise and ignores the signal
    // hangs forever and proves nothing — real `fetch` rejects with the signal's
    // reason when it aborts, so this one does too.
    const hangsUntilAborted = ((_input: string | URL, init?: RequestInit) =>
      new Promise<Response>((_resolve, reject) => {
        const signal = init?.signal;
        if (signal == null) return;
        signal.addEventListener('abort', () => reject(signal.reason), { once: true });
      })) as typeof globalThis.fetch;

    const provider = new AnchorSignalProvider(new RecordingLogger(), 'https://anchor.test', 25);

    const solvency = await withFetch(hangsUntilAborted, () => provider.solvencyOf(ADDRESS, 'base'));

    expect(solvency.state).toBe('unavailable');
    // AbortSignal.timeout rejects with a TimeoutError, so the reason
    // distinguishes a slow source from an unreachable one — worth telling apart
    // in logs when diagnosing which failure mode is degrading the signal.
    expect(solvency.state === 'unavailable' && solvency.reason).toContain('TimeoutError');
  });

  it('passes an abort signal on every request', () => {
    // Asserted separately, because the timeout test above can only fail loudly if
    // the signal is actually wired through. A provider that forgot to pass one
    // would hang for as long as the upstream socket stayed open.
    let sawSignal = false;
    const check = ((_input: string | URL, init?: RequestInit) => {
      sawSignal = init?.signal != null;
      return Promise.resolve(
        new Response(JSON.stringify(ANCHOR_ACTIVE_POSITION), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        }),
      );
    }) as typeof globalThis.fetch;

    return withFetch(check, async () => {
      await build().solvencyOf(ADDRESS, 'base');
      expect(sawSignal).toBe(true);
    });
  });

  it('reports unparseable JSON as unavailable', () => {
    const badJson = (() =>
      Promise.resolve(
        new Response('<html>gateway timeout</html>', {
          status: 200,
          headers: { 'content-type': 'text/html' },
        }),
      )) as typeof globalThis.fetch;

    return withFetch(badJson, async () => {
      const solvency = await build().solvencyOf(ADDRESS, 'base');
      expect(solvency.state).toBe('unavailable');
    });
  });

  it('never sends a malformed address upstream', () => {
    let called = false;
    return withFetch(
      stubFetch(() => {
        called = true;
        return { body: ANCHOR_ACTIVE_POSITION };
      }),
      async () => {
        const solvency = await build().solvencyOf('not-an-address', 'base');
        // Upstream would answer a malformed address with an LLM paragraph, so
        // the request is not made at all.
        expect(called).toBe(false);
        expect(solvency).toEqual({ state: 'unavailable', reason: 'malformed_address' });
      },
    );
  });

  it('does not ask about a chain the source does not cover', () => {
    let called = false;
    return withFetch(
      stubFetch(() => {
        called = true;
        return { body: ANCHOR_NO_POSITION };
      }),
      async () => {
        // The trap this guards: Anchor answers 200 with `riskLabel: NONE` for any
        // address it finds no Base position for. Ask it about an Ethereum address
        // and it returns a confident "no lending position" that is true of Base
        // and says nothing about Ethereum — a clean signal manufactured out of a
        // chain mismatch.
        const solvency = await build().solvencyOf(ADDRESS, 'ethereum');
        expect(called).toBe(false);
        expect(solvency).toEqual({
          state: 'unavailable',
          reason: 'chain_not_covered:ethereum',
        });
      },
    );
  });
});
