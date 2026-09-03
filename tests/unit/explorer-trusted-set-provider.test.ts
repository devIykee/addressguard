import { describe, it, expect } from 'vitest';
import { extractDeliberateRecipients } from '../../src/infrastructure/explorer-trusted-set-provider.ts';
import {
  WBTC_2024_TXLIST,
  USDT_2025_TXLIST,
  MALFORMED_TXLIST_ROWS,
} from '../fixtures/explorer-payloads.ts';
import { WBTC_2024, USDT_2025 } from '../fixtures/incidents.ts';

describe('extractDeliberateRecipients — the derived trusted set is not poisonable', () => {
  it('WBTC 2024: trusts the real counterparty and excludes the attacker', () => {
    // Recorded at the block before the loss. Both rows are in the window: the
    // victim's deliberate send AND the attacker's inbound zero-value plant.
    const trusted = extractDeliberateRecipients(WBTC_2024_TXLIST.result, WBTC_2024_TXLIST.victim);

    expect(trusted).toContain(WBTC_2024.trusted);
    expect(trusted).not.toContain(WBTC_2024.lookalike);
  });

  it('USDT 2025: trusts the real counterparty and excludes the attacker', () => {
    const trusted = extractDeliberateRecipients(USDT_2025_TXLIST.result, USDT_2025_TXLIST.victim);

    expect(trusted).toContain(USDT_2025.trusted);
    expect(trusted).not.toContain(USDT_2025.lookalike);
  });

  it('excludes an inbound zero-value sender — the attack itself', () => {
    // This single assertion is the difference between a derivation that blesses
    // the attack and one that catches it. A naive "any counterparty in history"
    // rule includes this row, because the lookalike IS a counterparty.
    const trusted = extractDeliberateRecipients(WBTC_2024_TXLIST.result, WBTC_2024_TXLIST.victim);

    const inboundPlant = WBTC_2024_TXLIST.result.find((r) => r.value === '0' && r.input === '0x');
    expect(inboundPlant?.from).toBe(WBTC_2024.lookalike);
    expect(trusted).not.toContain(inboundPlant?.from);
  });

  it('excludes an inbound funding transfer from a third party', () => {
    // Receiving value from an address says nothing about whether the caller
    // chose to pay it.
    const trusted = extractDeliberateRecipients(USDT_2025_TXLIST.result, USDT_2025_TXLIST.victim);
    expect(trusted).not.toContain('0x0d0707963952f2fba59dd06f2b425ace40b492fe');
  });
});

describe('extractDeliberateRecipients — ERC-20 recipients come from calldata', () => {
  it('does not record the token contract as the trusted counterparty', () => {
    // Both USDT rows have `to` = the USDT contract and `value` = '0'. A
    // derivation reading `to` would trust USDT's contract address and miss every
    // real recipient — which on this fixture means missing the address the
    // victim meant to pay.
    const trusted = extractDeliberateRecipients(USDT_2025_TXLIST.result, USDT_2025_TXLIST.victim);

    expect(trusted).not.toContain('0xdac17f958d2ee523a2206206994597c13d831ec7');
    expect(trusted).toContain(USDT_2025.trusted);
  });

  it('returns a set, not a single address', () => {
    const trusted = extractDeliberateRecipients(USDT_2025_TXLIST.result, USDT_2025_TXLIST.victim);

    // Two distinct deliberate ERC-20 sends in the window.
    expect(trusted).toHaveLength(2);
    expect(trusted).toContain(USDT_2025.trusted);
    expect(trusted).toContain('0x3c87ade10d648fc7eb92c49d5cb58f0d94785773');
  });

  it('decodes transferFrom, taking the second argument as recipient', () => {
    const caller = USDT_2025.victim;
    const recipient = WBTC_2024.trusted;
    const rows = [
      {
        blockNumber: '1',
        hash: '0xaa',
        from: caller,
        to: '0xdac17f958d2ee523a2206206994597c13d831ec7',
        value: '0',
        // transferFrom(caller, recipient, 1)
        input: `0x23b872dd${caller.slice(2).padStart(64, '0')}${recipient
          .slice(2)
          .padStart(64, '0')}${'1'.padStart(64, '0')}`,
      },
    ];

    const trusted = extractDeliberateRecipients(rows, caller);
    expect(trusted).toEqual([recipient]);
  });

  it('skips truncated ERC-20 calldata rather than decoding garbage', () => {
    const caller = USDT_2025.victim;
    const rows = [
      {
        blockNumber: '1',
        hash: '0xaa',
        from: caller,
        to: '0xdac17f958d2ee523a2206206994597c13d831ec7',
        value: '0',
        input: '0xa9059cbb00',
      },
    ];

    expect(extractDeliberateRecipients(rows, caller)).toEqual([]);
  });
});

describe('extractDeliberateRecipients — robustness', () => {
  it('never throws on malformed rows, and still returns the good ones', () => {
    const caller = USDT_2025_TXLIST.victim;
    const mixed = [...MALFORMED_TXLIST_ROWS, ...USDT_2025_TXLIST.result];

    let trusted: string[] = [];
    expect(() => {
      trusted = extractDeliberateRecipients(mixed, caller);
    }).not.toThrow();

    expect(trusted).toContain(USDT_2025.trusted);
  });

  it('returns empty for an empty row set rather than throwing', () => {
    expect(extractDeliberateRecipients([], USDT_2025.victim)).toEqual([]);
  });

  it('handles wei values above Number.MAX_SAFE_INTEGER', () => {
    // 1e21 wei overflows a double. Parsed as BigInt, so a large legitimate send
    // is not silently treated as zero.
    const caller = USDT_2025.victim;
    const recipient = WBTC_2024.trusted;
    const rows = [
      { blockNumber: '1', hash: '0xaa', from: caller, to: recipient, value: '1000000000000000000000', input: '0x' },
    ];

    expect(extractDeliberateRecipients(rows, caller)).toEqual([recipient]);
  });

  it('skips zero-value plain calls — nothing was sent', () => {
    const caller = USDT_2025.victim;
    const rows = [
      { blockNumber: '1', hash: '0xaa', from: caller, to: WBTC_2024.trusted, value: '0', input: '0x' },
    ];

    expect(extractDeliberateRecipients(rows, caller)).toEqual([]);
  });

  it('never includes the caller itself', () => {
    // A self-send would otherwise make the caller its own trusted counterparty,
    // and the service would then exclude it as an exact match — harmless, but
    // it would inflate trustedSetSize with a meaningless entry.
    const caller = USDT_2025.victim;
    const rows = [
      { blockNumber: '1', hash: '0xaa', from: caller, to: caller, value: '1000', input: '0x' },
    ];

    expect(extractDeliberateRecipients(rows, caller)).toEqual([]);
  });

  it('matches the caller case-insensitively', () => {
    const rows = WBTC_2024_TXLIST.result;
    const upper = WBTC_2024_TXLIST.victim.toUpperCase().replace('0X', '0x');

    expect(extractDeliberateRecipients(rows, upper.toLowerCase())).toContain(WBTC_2024.trusted);
  });

  it('deduplicates repeated recipients', () => {
    const caller = USDT_2025.victim;
    const recipient = WBTC_2024.trusted;
    const row = {
      blockNumber: '1',
      hash: '0xaa',
      from: caller,
      to: recipient,
      value: '1000',
      input: '0x',
    };

    expect(extractDeliberateRecipients([row, row, row], caller)).toEqual([recipient]);
  });
});
