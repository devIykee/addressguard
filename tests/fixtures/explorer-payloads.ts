/**
 * Blockscout `txlist` responses, recorded verbatim from
 * `https://eth.blockscout.com/api?module=account&action=txlist&...` during
 * design.
 *
 * Each window ends at the block immediately BEFORE the corresponding loss, so
 * the fixture reproduces exactly what the miner would have seen if an agent had
 * asked "is this destination safe?" moments before the victim sent the funds.
 * That is the only question worth testing the derivation against.
 *
 * Recorded rather than fetched so the trust-derivation tests are offline and
 * deterministic. `explorer-payloads` is the seam: the provider is tested against
 * these, and only the thin HTTP layer above them is untested by unit tests.
 */

export const WBTC_2024_TXLIST = {
  victim: '0x1e227979f0b5bc691a70deaed2e0f39a6f538fd5',
  startBlock: 19700000,
  endBlock: 19789008,
  result: [
    {
      // The lookalike's inbound zero-value plant. Signed by the ATTACKER, so it
      // must never contribute trust — this is the row that breaks a naive
      // "any counterparty" derivation.
      blockNumber: '19788644',
      hash: '0x87c6e5d56fea35315ba283de8b6422ad390b6b9d8d399d9b93a9051a3e11bf73',
      from: '0xd9a1c3788d81257612e2581a6ea0ada244853a91',
      to: '0x1e227979f0b5bc691a70deaed2e0f39a6f538fd5',
      value: '0',
      input: '0x',
    },
    {
      // The victim's deliberate 0.05 ETH send. Signed by the victim, non-zero
      // value: this is the one row that legitimately establishes trust.
      blockNumber: '19788628',
      hash: '0xb18ab131d251f7429c56a2ae2b1b75ce104fe9e83315a0c71ccf2b20267683ac',
      from: '0x1e227979f0b5bc691a70deaed2e0f39a6f538fd5',
      to: '0xd9a1b0b1e1ae382dbdc898ea68012ffcb2853a91',
      value: '50000000000000000',
      input: '0x',
    },
  ],
} as const;

export const USDT_2025_TXLIST = {
  victim: '0xcf03aa88afda357c837b9ddd38a678e3ad7cd5d7',
  startBlock: 22300000,
  endBlock: 22307397,
  result: [
    {
      // A second 10 USDT test send, to a different counterparty. Trusted, and
      // useful: it proves the derivation returns a SET rather than one address.
      blockNumber: '22307391',
      hash: '0xd002a1577aad5b83a56b13b3f389b7af5dc2ccf79b83b7ed4e8fc628c34daf44',
      from: '0xcf03aa88afda357c837b9ddd38a678e3ad7cd5d7',
      to: '0xdac17f958d2ee523a2206206994597c13d831ec7',
      value: '0',
      input:
        '0xa9059cbb0000000000000000000000003c87ade10d648fc7eb92c49d5cb58f0d947857730000000000000000000000000000000000000000000000000000000000989680',
    },
    {
      // The victim's 10 USDT test send to the address it actually meant to pay.
      // Note `value: '0'` — the recipient lives in the ERC-20 calldata, not in
      // the native value field. A derivation reading only `to` would record the
      // USDT contract as the trusted counterparty and miss this entirely.
      blockNumber: '22307387',
      hash: '0xa47c61b48fcc7f56759de5091f5a6f74c4ac9d7525321f1bfa0f31aee371187a',
      from: '0xcf03aa88afda357c837b9ddd38a678e3ad7cd5d7',
      to: '0xdac17f958d2ee523a2206206994597c13d831ec7',
      value: '0',
      input:
        '0xa9059cbb0000000000000000000000002c11a3a5f725a21024dc5467f69eb649b1cd9c0b0000000000000000000000000000000000000000000000000000000000989680',
    },
    {
      // Inbound funding from a third party. Not signed by the victim, so it
      // establishes no trust — receiving from an address says nothing about
      // whether the caller chose to pay it.
      blockNumber: '22307349',
      hash: '0xc3a1570240938f717e644c0228b2bb87521a061679e101e4702356bd249abccf',
      from: '0x0d0707963952f2fba59dd06f2b425ace40b492fe',
      to: '0xcf03aa88afda357c837b9ddd38a678e3ad7cd5d7',
      value: '61800000000000000',
      input: '0x',
    },
  ],
} as const;

/** The shape the provider parses. Matches Blockscout's `txlist` rows. */
export interface RecordedTx {
  readonly blockNumber: string;
  readonly hash: string;
  readonly from: string;
  readonly to: string;
  readonly value: string;
  readonly input: string;
}

/**
 * Rows that a correct derivation must survive without throwing. Every one of
 * these appeared in real explorer output during design, or is a documented
 * Blockscout edge case.
 */
export const MALFORMED_TXLIST_ROWS: readonly unknown[] = [
  // contract creation: `to` is null
  { blockNumber: '1', hash: '0xaa', from: '0xcf03aa88afda357c837b9ddd38a678e3ad7cd5d7', to: null, value: '1', input: '0x' },
  // truncated ERC-20 calldata
  { blockNumber: '2', hash: '0xbb', from: '0xcf03aa88afda357c837b9ddd38a678e3ad7cd5d7', to: '0xdac17f958d2ee523a2206206994597c13d831ec7', value: '0', input: '0xa9059cbb00' },
  // non-numeric value
  { blockNumber: '3', hash: '0xcc', from: '0xcf03aa88afda357c837b9ddd38a678e3ad7cd5d7', to: '0xaaaa', value: 'n/a', input: '0x' },
  // missing fields entirely
  { hash: '0xdd' },
  // wrong types
  { blockNumber: 5, hash: null, from: 42, to: [], value: {}, input: false },
  null,
  'not an object',
];
