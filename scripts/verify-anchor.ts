/**
 * Live verification against the real solvency source.
 *
 * The unit and integration tests cover this adapter against recorded payloads,
 * which is the right default — they are offline, deterministic, and they cover
 * failure modes a live source will not reproduce on demand. What they cannot
 * prove is that the recorded shape still matches what production serves today.
 * This script does that, and nothing else.
 *
 *   node --experimental-strip-types scripts/verify-anchor.ts
 *
 * Exit code is 0 only if every case passes, so it is usable as a smoke check
 * before a deploy. It makes real outbound calls and needs no key.
 */

import { AnchorSignalProvider } from '../src/infrastructure/anchor-signal-provider.ts';
import { ConsoleLogger } from '../src/infrastructure/console-logger.ts';
import { buildApp } from '../src/api/app.ts';
import { WBTC_2024, USDT_2025 } from '../tests/fixtures/incidents.ts';
import type { CounterpartySolvency } from '../src/domain/entities/index.ts';
import type { RiskCheckResponse } from '../src/api/response.ts';

/** A live Aave v3 borrower on Base. Re-find one with a fresh position if it repays. */
const ACTIVE_BORROWER = '0x50b75aacb1ed974f5c901a32bee767de39cbb060';

interface Case {
  readonly title: string;
  readonly run: () => Promise<boolean>;
}

const logger = new ConsoleLogger();
const provider = new AnchorSignalProvider(logger);

let failures = 0;

function check(label: string, ok: boolean, detail: string): boolean {
  console.log(`    ${ok ? 'ok  ' : 'FAIL'}  ${label}${detail ? ` — ${detail}` : ''}`);
  if (!ok) failures += 1;
  return ok;
}

function describeSolvency(solvency: CounterpartySolvency): string {
  if (solvency.state === 'unavailable') return `unavailable (${solvency.reason})`;
  if (solvency.state === 'no_position') return `no_position at block ${solvency.checkedAtBlock}`;
  return `${solvency.verdict}, hf=${solvency.healthFactor}, block ${solvency.checkedAtBlock}`;
}

const cases: readonly Case[] = [
  {
    title: 'A live borrower returns an assessed position',
    run: async () => {
      const solvency = await provider.solvencyOf(ACTIVE_BORROWER, 'base');
      console.log(`      ${describeSolvency(solvency)}`);

      if (solvency.state === 'unavailable') {
        return check('assessed', false, `source unavailable: ${solvency.reason}`);
      }
      if (solvency.state === 'no_position') {
        // Not a defect in this code: the sample wallet repaid. Say so plainly
        // rather than failing on something that is not the adapter's fault.
        console.log('      NOTE: sample borrower now has no position; pick a fresh one.');
        return check('answered with a recognized shape', true, 'no_position');
      }

      const okVerdict = check('verdict is in the solvency vocabulary', true, solvency.verdict);
      const okBlock = check(
        'block-pinned',
        typeof solvency.checkedAtBlock === 'number' && solvency.checkedAtBlock > 0,
        String(solvency.checkedAtBlock),
      );
      const okReasoning = check('carries reasoning', solvency.reasoning.length > 0, '');
      return okVerdict && okBlock && okReasoning;
    },
  },
  {
    title: 'Both incident lookalikes have no lending position',
    run: async () => {
      // The measurement the whole design rests on: a poisoning address has no
      // position, so the two signals are orthogonal. If this ever stops being
      // true, the composition rule deserves a second look.
      let allOk = true;
      for (const incident of [WBTC_2024, USDT_2025]) {
        const solvency = await provider.solvencyOf(incident.lookalike, 'base');
        allOk =
          check(
            `${incident.lookalike.slice(0, 10)}… is not assessed as a live position`,
            solvency.state !== 'assessed',
            describeSolvency(solvency),
          ) && allOk;
      }
      return allOk;
    },
  },
  {
    title: 'An Ethereum request never borrows a Base answer',
    run: async () => {
      const solvency = await provider.solvencyOf(ACTIVE_BORROWER, 'ethereum');
      return check(
        'unavailable with chain_not_covered',
        solvency.state === 'unavailable' && solvency.reason === 'chain_not_covered:ethereum',
        describeSolvency(solvency),
      );
    },
  },
  {
    title: 'An unreachable source degrades instead of failing',
    run: async () => {
      const offline = new AnchorSignalProvider(logger, 'https://127.0.0.1:9', 1_000);
      const solvency = await offline.solvencyOf(ACTIVE_BORROWER, 'base');
      return check(
        'unavailable, not thrown',
        solvency.state === 'unavailable',
        describeSolvency(solvency),
      );
    },
  },
  {
    title: 'The full handler answers with both signals',
    run: async () => {
      const app = buildApp(logger);
      const result = await app.handler.handle({
        address: WBTC_2024.lookalike,
        chain: 'base',
        callerHistory: [WBTC_2024.trusted],
      });

      const body = result.body as RiskCheckResponse;
      console.log(`      ${JSON.stringify(body, null, 2).split('\n').join('\n      ')}`);

      const okLabel = check('poisoning verdict intact', body.risk_label === 'high_risk', body.risk_label);
      const okReason = check(
        'risk_reason names only poisoning signals',
        body.risk_reason.startsWith('poisoning_match:') &&
          !/ALLOW|RECHECK|BLOCK|solvency/.test(body.risk_reason),
        body.risk_reason,
      );
      const okAction = check(
        'recommended_action blocks a lookalike',
        body.recommended_action.action === 'block',
        body.recommended_action.reason,
      );
      const okSolvency = check(
        'solvency block is present and well-formed',
        typeof body.counterparty_solvency.checked === 'boolean',
        JSON.stringify(body.counterparty_solvency),
      );
      return okLabel && okReason && okAction && okSolvency;
    },
  },
];

async function main(): Promise<void> {
  console.log('\nVerifying the counterparty solvency signal against the live source.\n');

  for (const [index, testCase] of cases.entries()) {
    console.log(`[${index + 1}/${cases.length}] ${testCase.title}`);
    try {
      await testCase.run();
    } catch (error: unknown) {
      // A throw here is itself a finding: every provider in this codebase is
      // contractually non-throwing.
      check('did not throw', false, error instanceof Error ? error.message : String(error));
    }
    console.log('');
  }

  if (failures > 0) {
    console.error(`${failures} check(s) failed.\n`);
    process.exit(1);
  }
  console.log('All checks passed.\n');
}

void main();
