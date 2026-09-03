import { describe, it, expect } from 'vitest';
import {
  normalizeV2Row,
  extractDeliberateRecipients,
} from '../../src/infrastructure/explorer-trusted-set-provider.ts';
import { parseBlockNumber } from '../../src/infrastructure/rpc-block-provider.ts';
import { WBTC_2024 } from '../fixtures/incidents.ts';

/**
 * Blockscout v2 row, shaped as the live API returns it: `from`/`to` are objects
 * carrying a `hash`, and calldata is `raw_input` rather than `input`.
 *
 * Recorded from base.blockscout.com/api/v2 during design. The v2 path exists
 * because base.blockscout.com dropped v1 connections entirely while answering
 * v2 — a chain would otherwise be silently unserved.
 */
const v2Row = {
  from: {
    ens_domain_name: 'vitalik.eth',
    hash: '0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045',
    is_contract: false,
  },
  to: {
    ens_domain_name: null,
    hash: '0x2626664c2603336E57B271c5C0b26F421741e481',
    is_contract: true,
  },
  value: '0',
  raw_input: '0x5ae401dc0000000000000000000000000000000000000000000000000000000069f4eb33',
  method: 'multicall',
};

describe('normalizeV2Row', () => {
  it('flattens from/to objects to their hashes', () => {
    // The specific failure this guards: reading `from` as a string when it is an
    // object yields undefined, the signer check fails on every row, and the
    // derivation silently returns an empty trusted set. Silent, because an empty
    // set is a legitimate outcome — it looks like "this wallet has no history".
    const flat = normalizeV2Row(v2Row) as Record<string, unknown>;

    expect(flat.from).toBe('0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045');
    expect(flat.to).toBe('0x2626664c2603336E57B271c5C0b26F421741e481');
  });

  it('maps raw_input to input', () => {
    const flat = normalizeV2Row(v2Row) as Record<string, unknown>;
    expect(flat.input).toBe(v2Row.raw_input);
  });

  it('feeds the same derivation rule as a v1 row', () => {
    // End to end: a v2 native send must produce the same trusted set a v1 row
    // would, so the derivation logic stays in exactly one place.
    const nativeSend = {
      from: { hash: WBTC_2024.victim },
      to: { hash: WBTC_2024.trusted },
      value: '50000000000000000',
      raw_input: '0x',
    };

    const derived = extractDeliberateRecipients(
      [normalizeV2Row(nativeSend)],
      WBTC_2024.victim,
    );
    expect(derived).toEqual([WBTC_2024.trusted]);
  });

  it('still rejects an attacker-signed v2 row', () => {
    // The poisonability guarantee must survive the shape change.
    const plant = {
      from: { hash: WBTC_2024.lookalike },
      to: { hash: WBTC_2024.victim },
      value: '0',
      raw_input: '0x',
    };

    expect(extractDeliberateRecipients([normalizeV2Row(plant)], WBTC_2024.victim)).toEqual([]);
  });

  it('tolerates a null `to` (contract creation)', () => {
    const creation = { from: { hash: WBTC_2024.victim }, to: null, value: '1', raw_input: '0x' };
    const flat = normalizeV2Row(creation) as Record<string, unknown>;

    expect(flat.to).toBeNull();
    expect(() => extractDeliberateRecipients([flat], WBTC_2024.victim)).not.toThrow();
  });

  it('tolerates missing and mistyped fields', () => {
    for (const row of [{}, { from: 42, to: [], value: null }, null, 'string']) {
      expect(() => normalizeV2Row(row)).not.toThrow();
    }
  });

  it('accepts a plain string party, in case an instance returns v1-shaped rows', () => {
    const mixed = { from: WBTC_2024.victim, to: WBTC_2024.trusted, value: '1', raw_input: '0x' };
    const flat = normalizeV2Row(mixed) as Record<string, unknown>;

    expect(flat.from).toBe(WBTC_2024.victim);
    expect(flat.to).toBe(WBTC_2024.trusted);
  });

  it('coerces a numeric value to a string', () => {
    const numeric = { from: { hash: WBTC_2024.victim }, to: { hash: WBTC_2024.trusted }, value: 5 };
    const flat = normalizeV2Row(numeric) as Record<string, unknown>;

    expect(flat.value).toBe('5');
  });
});

describe('parseBlockNumber', () => {
  it('reads a hex result', () => {
    // 0x18b08cb — a real Ethereum height observed during design.
    expect(parseBlockNumber({ result: '0x18b08cb' })).toBe(25888971);
  });

  it('rejects an error-shaped 200 response', () => {
    // Several public endpoints answer HTTP 200 with a JSON-RPC error body. A
    // parser that only checked the HTTP status would treat this as a height.
    expect(parseBlockNumber({ error: { code: -32046, message: 'Cannot fulfill request' } })).toBeNull();
    expect(parseBlockNumber({ jsonrpc: '2.0', id: 1 })).toBeNull();
  });

  it('rejects non-hex, zero, and malformed results', () => {
    expect(parseBlockNumber({ result: '0x' })).toBeNull();
    expect(parseBlockNumber({ result: '0x0' })).toBeNull();
    expect(parseBlockNumber({ result: 'latest' })).toBeNull();
    expect(parseBlockNumber({ result: 12345 })).toBeNull();
    expect(parseBlockNumber(null)).toBeNull();
    expect(parseBlockNumber('nope')).toBeNull();
  });
});
