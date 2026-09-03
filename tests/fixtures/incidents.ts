/**
 * Address-poisoning incidents, reconstructed from Ethereum mainnet during
 * design. Every address, transaction hash, and block number below was
 * verified live via `eth_getTransactionByHash`, `eth_getBlockByNumber`,
 * `eth_getTransactionReceipt`, and Blockscout's `txlist`/`tokentx` endpoints.
 * None of it is synthetic and none of it was typed from recall.
 *
 * Recorded as constants so the test suite is deterministic and offline. Tests
 * that need explorer payloads use the recorded fixtures in
 * `explorer-payloads.ts`, not the network.
 *
 * ## The two incidents use different poisoning mechanisms
 *
 * This distinction is load-bearing for Tier 2a and is easy to miss, since both
 * end with the victim copying a lookalike out of their own history:
 *
 *   WBTC 2024 — INBOUND. The lookalike address itself sends the victim a real
 *     zero-value transaction. `tx.from` IS the lookalike. The victim's history
 *     shows an incoming transfer.
 *
 *   USDT 2025 — FORGED OUTBOUND. A third-party contract emits a zero-value
 *     ERC-20 `Transfer` log naming the VICTIM as sender and the lookalike as
 *     recipient. `tx.from` is neither party (0x6d4de4bd...). The victim's
 *     history shows what looks like their own outgoing payment to the
 *     lookalike — which is more convincing, and is why the measurement study
 *     calls this variant "potentially even more dangerous".
 *
 * A Tier 2a check that only looks for inbound transfers from the suspect would
 * find the WBTC case and miss the USDT one. Both directions are needed.
 */

/**
 * 1155 WBTC, 3 May 2024, ~$68M at the time. The largest documented address
 * poisoning loss.
 *
 * Sequence, all on Ethereum mainnet (timestamps verified via
 * `eth_getBlockByNumber`):
 *
 *   19788628  09:14 UTC  victim sends 0.05 ETH to its real counterparty
 *                        (a deliberate, signed send — this is what makes the
 *                        counterparty trusted)
 *   19788644  09:17 UTC  the lookalike itself sends the victim a ZERO-VALUE
 *                        transaction, planting itself in the victim's history
 *   19789009  10:31 UTC  victim sends 1155.28802767 WBTC to the LOOKALIKE,
 *                        having copied it out of that history
 *
 * 77 minutes from bait to loss. Prefix/suffix overlap between trusted and
 * lookalike: (4, 6), d = 10.
 */
export const WBTC_2024 = {
  label: 'WBTC 2024 (~$68M)',
  victim: '0x1e227979f0b5bc691a70deaed2e0f39a6f538fd5',
  /** The address the victim actually meant to pay. */
  trusted: '0xd9a1b0b1e1ae382dbdc898ea68012ffcb2853a91',
  /** The attacker's vanity-mined lookalike. */
  lookalike: '0xd9a1c3788d81257612e2581a6ea0ada244853a91',
  /** Victim's deliberate 0.05 ETH send to the real counterparty. */
  trustEstablishingTx: '0xb18ab131d251f7429c56a2ae2b1b75ce104fe9e83315a0c71ccf2b20267683ac',
  trustEstablishingBlock: 19788628,
  /**
   * The zero-value transaction that planted the lookalike. INBOUND: sent by
   * the lookalike itself, so `tx.from` is the lookalike address.
   */
  poisoningTx: '0x87c6e5d56fea35315ba283de8b6422ad390b6b9d8d399d9b93a9051a3e11bf73',
  poisoningBlock: 19788644,
  poisoningDirection: 'inbound_from_lookalike',
  /**
   * The 1155.28802767 WBTC loss — an ERC-20 `transfer(lookalike, 115528802767)`
   * call to the WBTC contract, not a native send.
   */
  lossTx: '0x3374abc5a9c766ba709651399b6e6162de97ca986abc23f423a9d893c8f5f570',
  lossBlock: 19789009,
  /** Expected prefix/suffix overlap. */
  prefix: 4,
  suffix: 6,
} as const;

/**
 * 699,990 USDT, 20 April 2025. The harder of the two cases: only (4, 4) of
 * overlap, d = 8 — exactly at the prefix/suffix scoring floor, so it needs
 * Levenshtein corroboration to reach `high_risk`. That is what makes it the
 * fixture that pins the combination rule.
 *
 * Sequence, all on Ethereum mainnet:
 *
 *   22307387  03:00 UTC  victim sends a 10 USDT test transfer to the real
 *                        address
 *   22307390  03:00 UTC  a third-party contract emits a ZERO-VALUE USDT
 *                        `Transfer` log naming the VICTIM as sender and the
 *                        lookalike as recipient (`value: 0` confirmed in the
 *                        receipt). `tx.from` is 0x6d4de4bd... — neither the
 *                        victim nor the lookalike
 *   22307398  03:02 UTC  victim sends 699,990 USDT to the LOOKALIKE
 *
 * Roughly two minutes from bait to loss.
 */
export const USDT_2025 = {
  label: 'USDT 2025 (~$700K)',
  victim: '0xcf03aa88afda357c837b9ddd38a678e3ad7cd5d7',
  trusted: '0x2c11a3a5f725a21024dc5467f69eb649b1cd9c0b',
  lookalike: '0x2c1134a046c659fc9c3dfb663061e3e6c7989c0b',
  /** Victim's deliberate 10 USDT test send (`transfer(trusted, 10000000)`). */
  trustEstablishingTx: '0xa47c61b48fcc7f56759de5091f5a6f74c4ac9d7525321f1bfa0f31aee371187a',
  trustEstablishingBlock: 22307387,
  /**
   * The forged zero-value Transfer. FORGED OUTBOUND: emitted by a contract
   * call the victim never signed, but it appears in the victim's history as
   * their own outgoing payment.
   */
  poisoningTx: '0x30714a52580828b27d69a711601c637c1e93b06414aed782272d73186b2c1919',
  poisoningBlock: 22307390,
  poisoningDirection: 'forged_outbound_from_victim',
  /** The 699,990 USDT loss (`transfer(lookalike, 699990000000)`). */
  lossTx: '0xa80805c97f5008637c4706b03316f61429ca3243f84b1124630d32a9540915df',
  lossBlock: 22307398,
  prefix: 4,
  suffix: 4,
} as const;

/**
 * Unrelated address pairs, for the negative side of every separation test.
 * A detector that scores these anywhere near the incident pairs is useless
 * regardless of how it scores the incidents.
 *
 * The two ENS-derived addresses were resolved live through the ENS registry
 * (`0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e` → resolver → `addr(bytes32)`),
 * not copied from memory. Measured end overlaps: (0,0), (0,0), (1,0) — all
 * below the detection floor, which is the property these fixtures exist to
 * assert.
 */
export const UNRELATED_PAIRS = [
  {
    label: 'WBTC victim vs USDT victim',
    a: WBTC_2024.victim,
    b: USDT_2025.victim,
  },
  {
    label: 'vitalik.eth vs ens.eth',
    a: '0xd8da6bf26964af9d7eed9e03e53415d37aa96045',
    b: '0xfe89cc7abb2c4183683ab71653c4cdc9b02d44b7',
  },
  {
    label: 'WBTC trusted vs vitalik.eth',
    a: WBTC_2024.trusted,
    b: '0xd8da6bf26964af9d7eed9e03e53415d37aa96045',
  },
] as const;

/** Both incidents, for tests that assert the same property over each. */
export const INCIDENTS = [WBTC_2024, USDT_2025] as const;

/**
 * Inputs that must not throw anywhere. The `SimilarityStrategy` contract
 * requires malformed input to score `0` and log a warning, because one bad
 * entry in a `callerHistory` array must not fail the whole request.
 */
export const MALFORMED_INPUTS = [
  '',
  '   ',
  '0x',
  'not-an-address',
  '0xZZZZ79f0b5bc691a70deaed2e0f39a6f538fd5',
  // one hex digit short
  '0x1e227979f0b5bc691a70deaed2e0f39a6f538fd',
  // one hex digit long
  '0x1e227979f0b5bc691a70deaed2e0f39a6f538fd55',
  // missing 0x prefix
  '1e227979f0b5bc691a70deaed2e0f39a6f538fd5',
  '0X1E227979F0B5BC691A70DEAED2E0F39A6F538FD5extra',
] as const;
