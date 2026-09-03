/**
 * Self-consumption demo.
 *
 * Simulates an agent about to send funds: it calls /risk-check with a
 * destination and the caller's trusted identities, then blocks or allows the
 * send based on the verdict. This is the consumer side of the miner — the thing
 * that makes the response contract worth having.
 *
 * Every scenario uses addresses from real, on-chain-verified incidents. Nothing
 * here is synthetic.
 *
 *   node --experimental-strip-types demo/cli.ts
 *   node --experimental-strip-types demo/cli.ts https://addressguard.vercel.app
 */

const endpoint = process.argv[2] ?? 'http://127.0.0.1:8080';

interface RiskResponse {
  readonly risk_label: 'safe' | 'caution' | 'high_risk';
  readonly risk_confidence: number;
  readonly risk_reason: string;
  readonly detail: {
    readonly matched_against: string | null;
    readonly match_type: string | null;
    readonly trusted_set_size: number;
    readonly trust_source: string;
  };
  readonly evidence: {
    readonly checked_at_block: number | null;
    readonly canonical: string;
  };
}

interface Scenario {
  readonly title: string;
  readonly background: string;
  readonly amount: string;
  readonly request: Record<string, unknown>;
  readonly expect: RiskResponse['risk_label'];
}

const scenarios: readonly Scenario[] = [
  {
    title: 'POISONED — the 1155 WBTC attack, replayed',
    background:
      'On 2026-05-03 a whale paid 0xd9a1b0b1…3a91, then 16 blocks later the\n' +
      '  lookalike 0xd9a1c378…3a91 sent them a zero-value transaction to plant\n' +
      '  itself in their history. 77 minutes later they sent it 1155 WBTC (~$68M).',
    amount: '1155.28802767 WBTC',
    request: {
      address: '0xd9a1c3788d81257612e2581a6ea0ada244853a91',
      chain: 'ethereum',
      callerHistory: ['0xd9a1b0b1e1ae382dbdc898ea68012ffcb2853a91'],
    },
    expect: 'high_risk',
  },
  {
    title: 'POISONED — the harder case, only 8 characters of overlap',
    background:
      'On 2026-04-20 a victim sent a 10 USDT test transfer to 0x2c11a3a5…9c0b,\n' +
      '  then a forged zero-value log named the lookalike 0x2c1134a0…9c0b as a\n' +
      '  recipient. Two minutes later: 699,990 USDT. Only (4,4) end overlap, so\n' +
      '  prefix/suffix alone scores this 0.75 — corroboration carries it over.',
    amount: '699,990 USDT',
    request: {
      address: '0x2c1134a046c659fc9c3dfb663061e3e6c7989c0b',
      chain: 'ethereum',
      callerHistory: ['0x2c11a3a5f725a21024dc5467f69eb649b1cd9c0b'],
    },
    expect: 'high_risk',
  },
  {
    title: 'SAFE — an ordinary payment to an unrelated address',
    background:
      'The destination shares no visible characters with anything the caller\n' +
      '  trusts. A detector that fires here would be useless in production.',
    amount: '1.5 ETH',
    request: {
      address: '0xd8da6bf26964af9d7eed9e03e53415d37aa96045',
      chain: 'ethereum',
      callerHistory: ['0xd9a1b0b1e1ae382dbdc898ea68012ffcb2853a91'],
    },
    expect: 'safe',
  },
  {
    title: 'SAFE — paying an address the caller already uses',
    background:
      'An exact match is not poisoning: it is a counterparty the caller has\n' +
      '  paid before. Flagging it would be the worst false positive available.',
    amount: '0.05 ETH',
    request: {
      address: '0xd9a1b0b1e1ae382dbdc898ea68012ffcb2853a91',
      chain: 'ethereum',
      callerHistory: [
        '0xd9a1b0b1e1ae382dbdc898ea68012ffcb2853a91',
        '0x2c11a3a5f725a21024dc5467f69eb649b1cd9c0b',
      ],
    },
    expect: 'safe',
  },
  {
    title: 'NO HISTORY — the honest answer, not a convenient one',
    background:
      'No trusted identity was supplied and no caller wallet was given, so no\n' +
      '  comparison ran. Returning "safe" here would claim a check that never\n' +
      '  happened, so the answer is caution / insufficient_history.',
    amount: '10,000 USDC',
    request: {
      address: '0xd9a1c3788d81257612e2581a6ea0ada244853a91',
      chain: 'base',
    },
    expect: 'caution',
  },
  {
    title: 'CHAIN-DERIVED — no history supplied, verdict still real',
    background:
      'Only the caller\'s own wallet is given. The trusted set is derived from\n' +
      '  transactions they actually signed — which an attacker cannot forge —\n' +
      '  and the destination is checked against it. This is what lets an\n' +
      '  autonomously routed call answer at all.',
    amount: '25 ETH',
    request: {
      address: '0x111119f3ab7c2e81d04a6b5c39e72fd0c8b42a65',
      chain: 'ethereum',
      callerAddress: '0x1e227979f0b5bc691a70deaed2e0f39a6f538fd5',
    },
    expect: 'high_risk',
  },
];

const BOLD = '[1m';
const DIM = '[2m';
const RED = '[31m';
const GREEN = '[32m';
const YELLOW = '[33m';
const RESET = '[0m';

const badge = (label: string): string => {
  if (label === 'high_risk') return `${RED}${BOLD} BLOCKED ${RESET}`;
  if (label === 'caution') return `${YELLOW}${BOLD} HOLD ${RESET}`;
  return `${GREEN}${BOLD} ALLOWED ${RESET}`;
};

/** What an agent would actually do with each verdict. */
const decide = (label: string): string => {
  if (label === 'high_risk') return 'transaction NOT sent — destination is a lookalike';
  if (label === 'caution') return 'transaction held for confirmation — check not conclusive';
  return 'transaction sent';
};

async function run(): Promise<void> {
  process.stdout.write(
    `\n${BOLD}AddressGuard — agent pre-send check${RESET}\n${DIM}endpoint: ${endpoint}${RESET}\n`,
  );

  let passed = 0;
  let failed = 0;

  for (const [index, scenario] of scenarios.entries()) {
    process.stdout.write(
      `\n${DIM}${'─'.repeat(74)}${RESET}\n${BOLD}${index + 1}. ${scenario.title}${RESET}\n` +
        `${DIM}  ${scenario.background}${RESET}\n\n` +
        `  about to send ${BOLD}${scenario.amount}${RESET} to ${scenario.request.address}\n`,
    );

    let response: RiskResponse;
    try {
      const raw = await fetch(`${endpoint}/risk-check`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(scenario.request),
        signal: AbortSignal.timeout(20_000),
      });

      if (!raw.ok) {
        process.stdout.write(`  ${RED}request failed: HTTP ${raw.status}${RESET}\n`);
        failed += 1;
        continue;
      }

      response = (await raw.json()) as RiskResponse;
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : String(error);
      process.stdout.write(
        `  ${RED}could not reach the miner: ${message}${RESET}\n` +
          `  ${DIM}start it with: npm start${RESET}\n`,
      );
      failed += 1;
      continue;
    }

    const ok = response.risk_label === scenario.expect;
    passed += ok ? 1 : 0;
    failed += ok ? 0 : 1;

    process.stdout.write(
      `\n  ${badge(response.risk_label)}  ${decide(response.risk_label)}\n\n` +
        `  ${DIM}label      ${RESET}${response.risk_label} ` +
        `${DIM}(confidence ${response.risk_confidence})${RESET}\n` +
        `  ${DIM}reason     ${RESET}${response.risk_reason}\n` +
        `  ${DIM}matched    ${RESET}${response.detail.matched_against ?? '—'}` +
        `${response.detail.match_type === null ? '' : ` via ${response.detail.match_type}`}\n` +
        `  ${DIM}trust      ${RESET}${response.detail.trust_source} ` +
        `${DIM}(${response.detail.trusted_set_size} identit${
          response.detail.trusted_set_size === 1 ? 'y' : 'ies'
        } compared)${RESET}\n` +
        `  ${DIM}canonical  ${RESET}${response.evidence.canonical}\n` +
        `  ${ok ? `${GREEN}✓${RESET}` : `${RED}✗${RESET}`} ${DIM}expected ${scenario.expect}${RESET}\n`,
    );
  }

  process.stdout.write(
    `\n${DIM}${'─'.repeat(74)}${RESET}\n` +
      `${BOLD}${passed}/${scenarios.length} scenarios behaved as expected${RESET}` +
      `${failed > 0 ? ` ${RED}(${failed} unexpected)${RESET}` : ''}\n\n`,
  );

  process.exitCode = failed === 0 ? 0 : 1;
}

await run();
