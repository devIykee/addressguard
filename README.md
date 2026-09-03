# AddressGuard

A Telegraph Protocol miner for the `FRAUD_DETECTION` intent that answers one
narrow question: **is this destination address a lookalike of one the caller
already trusts?**

That is the address-poisoning attack. An attacker vanity-mines an address
matching the first and last few hex characters of a real counterparty — the part
wallet UIs truncate to and humans actually read — then plants it in the victim's
transaction history so it gets copied out later. It has cost individual victims
$68M and $700K in incidents this project reconstructs from chain and uses as
test fixtures.

```
POST /risk-check
{ "address": "0xd9a1c3788d81257612e2581a6ea0ada244853a91",
  "chain": "ethereum",
  "callerHistory": ["0xd9a1b0b1e1ae382dbdc898ea68012ffcb2853a91"] }

→ risk_label      high_risk
  risk_confidence 0.8775
  risk_reason     poisoning_match:0xd9a1...3a91:similarity=0.8775:
                  prefix_suffix=0.8125:full_levenshtein=0.3250
```

---

## What is implemented

Tier 1 is complete: both matching strategies, the aggregation service, on-chain
trust derivation, the HTTP layer with block-pinned evidence, the miner YAML, and
a self-consumption demo. **122 tests pass; `tsc --noEmit` is clean** under
`strict` plus `noUncheckedIndexedAccess` and `exactOptionalPropertyTypes`.

| Component | State |
|---|---|
| `PrefixSuffixStrategy` | Implemented, tested against two real incidents |
| `LevenshteinStrategy` | Implemented, capped — see [Why Levenshtein is capped](#why-levenshtein-is-capped) |
| `PoisoningDetectionService` | Implemented, exact-match exclusion tested explicitly |
| Chain-derived trust (`callerAddress`) | Implemented — see [limitations](#known-limitations-stated-plainly) |
| HTTP layer + `evidence` block | Implemented, deterministic `canonical` string |
| `telegraph.miner.yaml` | Written, schema-validated locally |
| Demo CLI | 6 scenarios, all passing against a live server |

### Not built

Stated as unbuilt rather than described as though present:

- **Tier 2a — on-chain dust/zero-value evidence.** The `OnChainDataProvider`
  interface is defined and both incident fixtures carry a `poisoningDirection`
  field for it, but no implementation exists. Designed, not written.
- **Tier 2b — ENS typosquat detection.** `EnsResolver` is defined; `ensName` and
  `callerTrustedEnsNames` are accepted by the API and **recorded but not
  scored**. The YAML says so explicitly.
- **Tier 2c — `callerHistory` self-verification.** Not started.
- **Part B — WASM scoring module.** Not built. See
  [Part B is harder than it looks](#part-b-is-harder-than-it-looks).

### Deliberately out of scope

These are well served by existing `FRAUD_DETECTION` miners, and a thin
reimplementation would add nothing:

| Out of scope | Already done well by |
|---|---|
| Contract risk, proxy/upgradeability, mint authority | Refut, Veridex |
| Protocol solvency and counterparty credit | Anchor, Telegraph Sentinel |
| Behavioural fraud, wash trading, honeypots | TrustGate, DegenLens |
| Scam-list and registry matching | Telegraph Sentinel, PhishTank |

AddressGuard is the only one of the fifteen live miners on this intent that takes
the **caller's own trusted identities** as input.

---

## Quick start

```bash
npm install
npm test              # 122 tests
npm run typecheck     # tsc --noEmit, strict
npm start             # listens on $PORT, default 8080

# in another shell
npm run demo          # 6 scenarios against the running server
```

No build step. No API keys. Node 22+ (uses `--experimental-strip-types`).

---

## The API

### `POST /risk-check`

| Field | Required | Meaning |
|---|---|---|
| `address` | yes | Destination being checked. Any case; EIP-55 casing is normalized, not rejected. |
| `chain` | yes | `base` or `ethereum`. |
| `callerHistory` | no | Addresses the caller already trusts. Max 256. |
| `callerAddress` | no | The caller's own wallet — derives the trusted set from chain when `callerHistory` is absent. |
| `ensName` | no | Reserved for Tier 2b. Recorded, not scored. |
| `callerTrustedEnsNames` | no | Reserved for Tier 2b. Recorded, not scored. |

A malformed `callerHistory` entry scores 0 and is skipped rather than failing the
request. The alternative would hand an attacker a trivial denial of the check:
append one bad string and the destination goes unchecked.

### Response

```json
{
  "address": "0xd9a1c3788d81257612e2581a6ea0ada244853a91",
  "risk_label": "high_risk",
  "risk_confidence": 0.8775,
  "risk_reason": "poisoning_match:0xd9a1...3a91:similarity=0.8775:prefix_suffix=0.8125:full_levenshtein=0.3250",
  "detail": {
    "matched_against": "0xd9a1...3a91",
    "match_type": "prefix_suffix",
    "similarity_score": 0.8775,
    "trusted_set_size": 1,
    "trust_source": "caller_supplied"
  },
  "evidence": {
    "checked_at_block": 25894035,
    "checked_at": "2026-09-03T03:17:13.227Z",
    "canonical": "0xd9a1c3788d81257612e2581a6ea0ada244853a91|ethereum|high_risk|25894035"
  }
}
```

`risk_label` / `risk_confidence` / `risk_reason` are flat and top-level because
that is what Telegraph's `signal_mapping` can name. Everything Tier 2 adds goes
inside `detail`, so those three never move.

**`risk_reason` names every contributing signal with its own score.** A verdict
that crossed the threshold only because a second signal corroborated a
borderline first one is visibly different from a strong single-signal match. That
is the difference between traceable and merely asserted.

**`evidence.canonical`** is `address|chain|risk_label|checked_at_block`,
lowercased. The timestamp is deliberately excluded — including it would make
every hash unique and destroy the reproducibility the field exists to provide.

### Labels

| Label | When |
|---|---|
| `high_risk` | Combined score ≥ 0.80 against a trusted identity. |
| `caution` | Score in [0.55, 0.80), **or** no trusted identity was available (`insufficient_history`). |
| `safe` | A real comparison ran against a non-empty trusted set and found nothing. |

**`safe` is never returned when no comparison happened.** With no trusted set
there is nothing to compare against, and claiming safety would assert a check
that never ran. That case is `caution` with `risk_reason: insufficient_history`.

A `safe` verdict means "not a lookalike of anything you trust" — not "this
address is safe". No single miner can assert the latter.

---

## Why it works this way

### Thresholds are measured, not chosen

Every constant in [`config/thresholds.ts`](config/thresholds.ts) traces to a
measurement. Two sources: two incidents reconstructed from Ethereum mainnet, and
[*Blockchain Address Poisoning*](https://arxiv.org/html/2501.16681)
(arXiv:2501.16681 / ACM CCS 2024), a study over 270M poisoning attempts.

| Pair | prefix | suffix | d | Levenshtein |
|---|---|---|---|---|
| WBTC 2024 trusted vs. lookalike | 4 | 6 | 10 | 0.325 |
| USDT 2025 trusted vs. lookalike | 4 | 4 | 8 | 0.325 |
| Unrelated control | 0 | 0 | 0 | 0.125 |
| Unrelated control 2 | 0 | 0 | 0 | 0.100 |

The detection floor (`prefix ≥ 3`, `suffix ≥ 4`) is the study's, derived from
wallet UIs truncating to 3–5 characters and explorers to 6–7. Saturation at
`d = 16` is where the study observes attack counts thinning out — by then a
collision is not plausibly accidental.

### Why Levenshtein is capped

Full-string edit distance scores real attacks **0.325** against a 0.10–0.125
control floor. Real attacks land *below the midpoint of its own scale*, with only
a 0.2 gap from unrelated noise. It cannot carry the strongest verdict.

The concrete failure, from the calibration run: shifting one character into the
middle of a trusted address (`0xd9a1b0b1…3a91` → `0xd9a51b0b…53a9`) scores
**0.95** on Levenshtein — edit distance 2 — while prefix/suffix correctly scores
it **0**, because the visible ends no longer align. Uncapped, one insertion would
assert `high_risk` on a pair no wallet UI would ever confuse.

So `LEV_MAX_ALONE = 0.79` sits just below the 0.80 `high_risk` threshold. A test
sweeps every corroborating-only score from 0 to 1 and asserts none reaches
`high_risk`, with a contrast case proving a *primary* signal at the same 0.95
does. The cap is about authority, not magnitude.

Levenshtein is kept because it does two things prefix/suffix cannot: it
corroborates borderline matches (the USDT incident sits exactly at the
prefix/suffix floor and reaches `high_risk` only once lifted), and it catches
end-shifted variants an exact comparison misses.

### The trusted set must not be poisonable

If the attacker's lookalike can get *into* the trusted set, the check inverts and
blesses the attack. Three candidate derivation rules, tested against both
fixtures at the block immediately **before** each loss:

| Rule | Outcome |
|---|---|
| Any counterparty in the caller's transaction history | attacker **trusted** |
| Any `Transfer` log naming the caller as sender | attacker **trusted** |
| **Only counterparties of transactions the caller signed** | attacker **excluded** ✓ |

The second rule fails because a zero-value `Transfer` log can name an arbitrary
sender — that is the poisoning mechanism itself. So trust comes only from
**deliberate sends**: `tx.from == caller`, with the recipient taken from a
non-zero `value` or from decoded `transfer(to,…)` / `transferFrom(…,to,…)`
calldata. An attacker cannot forge that; it requires the caller's signature.

Measured at the block before each loss:

```
WBTC 2024, block 19789008   trusted = {0xd9a1b0b1…3a91}   legit ✓  attacker ✗
USDT 2025, block 22307397   trusted = {0x2c11a3a5…9c0b,
                                       0x3c87ade1…5773}   legit ✓  attacker ✗
```

In both cases the derived set contains the address the victim *meant* to pay and
excludes the lookalike they actually paid.

One subtlety the recorded fixtures caught: both USDT rows have `value: "0"` and
`to` = the USDT contract. The real recipient is only in the ERC-20 calldata. A
derivation reading `to` would record USDT's contract as the trusted counterparty
and miss the address the victim meant to pay — on the exact fixture meant to
prove the rule works.

### Both incidents, and why they differ

| | WBTC 2024 | USDT 2025 |
|---|---|---|
| Loss | 1155.28802767 WBTC (~$68M) | 699,990 USDT |
| End overlap | (4, 6), d=10 | (4, 4), d=8 |
| Bait → loss | 77 minutes | ~2 minutes |
| Mechanism | **Inbound** — the lookalike sends the victim a zero-value tx | **Forged outbound** — a third-party contract emits a zero-value `Transfer` log naming the *victim* as sender |

The second is more convincing to a victim: their history shows what looks like
their own outgoing payment. Per the study, zero-value transfers are ~55% of
attempts and counterfeit-token transfers ~44%, while true dust (<$10) is under
2%.

**This matters for Tier 2a:** a check that only looks for inbound transfers from
the suspect finds WBTC and misses USDT entirely. Both directions are required.
Recorded on each fixture as `poisoningDirection` so the Tier 2a tests cannot be
written against one shape only.

All addresses, transaction hashes, and block numbers in
[`tests/fixtures/incidents.ts`](tests/fixtures/incidents.ts) were verified live
via `eth_getTransactionByHash`, `eth_getBlockByNumber`, and Blockscout. None are
synthetic.

---

## Known limitations, stated plainly

### Chain-derived trust drops contract-mediated sends

The signer-verification rule reads only transactions the caller signed, so a DEX
router moving tokens on the caller's behalf is invisible — the recipient lives in
internal transfers rather than in signed calldata. Measured: 5 legitimate
counterparties dropped across one fixture victim's March 2024 swaps.

This is the correct trade. A false negative in the trusted set costs a `safe`
verdict that should have been `caution`; a false positive costs the entire check.

### On Base, that limitation is the common case

Measured on a live request: **200 transactions examined, 0 trusted identities
derived.** Every one was `approve`, `multicall`, or a Uniswap router swap. On an
L2 where most activity is DEX routing, this is not an edge case.

**Use `callerHistory` on Base.** Chain derivation works well on Ethereum — 7
counterparties from the same 200-transaction window — and is best-effort on Base.
When it yields nothing the answer is `insufficient_history`, never a fabricated
`safe`.

### Explorer availability

`base.blockscout.com` drops v1 (`txlist`) connections entirely while answering
the v2 API, so there is a v1→v2 fallback with row normalization. The `filter=from`
parameter on v2 is a bandwidth optimization only — the signer check is re-applied
to every row locally, because trusting an explorer's filter to enforce the rule
that makes the trusted set unpoisonable would be misplaced.

### What degrades vs. what errors

An erroring miner loses Canonical Score, so every external failure degrades a
verdict instead of returning an error:

| Failure | Behaviour |
|---|---|
| RPC block read fails on all endpoints | `checked_at_block: null`, `canonical` contains `unknown`. Verdict unaffected. |
| Explorer unavailable / rate-limited | Empty derived set → `caution` / `insufficient_history`. |
| Trusted-set provider throws | Caught, logged, treated as empty. Still HTTP 200. |
| One malformed `callerHistory` entry | Scored 0, logged, skipped. Others still checked. |
| Malformed `address` or `chain` | HTTP 400 with field errors — the only 4xx a well-formed caller can trigger. |
| Body over 64 KB | HTTP 413, response flushed before the socket closes. |

`GET /health` deliberately touches neither RPC nor explorer. A health check that
failed because a third-party service was down would report the miner as dead
while it was still answering every request correctly.

---

## Architecture

Full design rationale in [`ARCHITECTURE.md`](ARCHITECTURE.md).

```
src/
  domain/
    entities/       MatchResult, RiskCheckResult, OnChainEvidence, RiskLabel
    interfaces/     SimilarityStrategy, Logger, BlockProvider,
                    TrustedSetProvider, OnChainDataProvider (T2a),
                    EnsResolver (T2b)
    services/       PoisoningDetectionService — aggregation only
  matching/
    prefix-suffix/  primary signal
    levenshtein/    corroborating signal, capped
    ens-homoglyph/  Tier 2b, empty
  verification/     Tier 2a, empty
  infrastructure/   ConsoleLogger, RpcBlockProvider,
                    ExplorerTrustedSetProvider
  api/              schema.ts (zod), handler.ts, response.ts,
                    app.ts (composition root), server.ts
api/index.ts        Vercel entry — wraps the same handler
config/             thresholds.ts, telegraph.miner.yaml
tests/              unit/, integration/, fixtures/
```

Dependencies point inward: `api → domain ← matching`. `domain/` imports nothing
from `matching/`, `infrastructure/`, or `api/` — it only defines the interfaces
they satisfy. `src/api/app.ts` is the single composition root and the only place
concrete classes are named.

**Strategy authority, not strategy names.** `PoisoningDetectionService` iterates
an injected `readonly SimilarityStrategy[]` and reads each one's declared
`authority` (`primary` | `corroborating`) to decide how much it may assert. It
never checks a strategy's identity, so adding the Tier 2b ENS strategy is one
line in `app.ts` — no edit to the service, the handler, or the response contract.
A test adds a third `ens_homoglyph` match type and asserts it flows through
aggregation, labelling, and reason formatting untouched.

**The `SimilarityStrategy` contract is executable.** Every implementation runs
through a shared suite (`tests/unit/strategy-contract.ts`): finite `[0,1]`, never
throws on any of 9 malformed inputs in either argument position, warns rather
than swallows, symmetric, deterministic across instances, case-insensitive, and
real incidents scoring strictly above unrelated controls. "Never throws" is the
one the aggregator depends on — a strategy that threw on one bad array element
would fail a whole request over it.

---

## Deployment

Vercel, with `api/index.ts` as the serverless entry and `src/api/server.ts` for
local and container use. Both wrap the same `RiskCheckHandler`, so the
integration tests exercise production behaviour rather than a parallel
implementation.

```bash
vercel --prod
```

Then set `base_url` in `config/telegraph.miner.yaml` to the deployed host,
validate at [integrate.telegraphprotocol.com](https://integrate.telegraphprotocol.com),
and register. Validate before spending gas — registration is on-chain and cannot
be edited.

### The YAML detail that decides whether traffic ever arrives

`endpoints[].intents` and `endpoints[].params` are present deliberately.

The original spec for this project omitted both. Per Telegraph's own schema docs,
`intents` is **required** — "an endpoint declaring no intents can never be
selected" — and without `params` the request builder has to guess field names,
which the docs call "the single most common cause of a miner rejecting the calls
Telegraph sends it."

For this miner, `params.body` is what tells the request builder that
`callerHistory` and `callerAddress` exist at all. Without it, a routed call
arrives carrying `address` only, no trusted set can be assembled, and every
answer degrades to `insufficient_history` — registered, active, and useless.
Seven of the fifteen live `FRAUD_DETECTION` miners omit both fields.

`id: 1155` (the WBTC fixture's amount) and slug `addressguard-poisoning-check`
were both confirmed unused against the live 129-miner registry.

---

## Part B is harder than it looks

Not built, and the reason is worth recording. The live `FRAUD_DETECTION` scoring
champion (registration 2793) posts:

```
candidate_margin 1.0    worst_self_match 1.0    candidate_wins 15/15
```

A margin of exactly 1.0 means it scores every benchmark good answer 1.0 and every
bad answer 0.0. Promotion requires matching that margin *and* win count — so a
scorer awarding partial credit for an adjacent severity tier mathematically
cannot match it, and would pass the structural checks then fail promotion.

Of 45 canonical intents, 21 have a perfect-1.0 champion and 24 sit below 0.95 —
six below 0.75, where a champion is already losing benchmark cases. Since a
scoring module registers for exactly one intent, the first question is not how to
design the scorer but which intent to point it at. Recorded rather than guessed
at.

---

## Verification

```
122 tests, 6 files
  strategy contract (shared, run per implementation)
  prefix-suffix         real incidents, detection floor, ramp monotonicity
  levenshtein           cap enforcement, derived lift bounds
  service               exact-match exclusion, insufficient_history,
                        authority sweep, label boundaries
  trust derivation      poisonability, ERC-20 calldata, malformed rows
  v2 normalization      field remapping, error-shaped 200s
  integration           HTTP in / JSON out, evidence determinism
```

Live-verified against the running server, not only in tests:

| Case | Result |
|---|---|
| WBTC 2024 lookalike | `high_risk` 0.8775 |
| USDT 2025 lookalike (d=8) | `high_risk` 0.8150 |
| Unrelated destination | `safe` 0.9 |
| Exact match with trusted entry | `safe` — not flagged |
| No history, no `callerAddress` | `caution` / `insufficient_history` |
| Chain-derived, lookalike of a live counterparty | `high_risk` 0.8825, 7 identities compared |
| 404 / 405 / bad JSON / 413 | Correct status, server survives each |

`npm run demo` replays six of these end to end, blocking the mock send on a
poisoning match.

---

## Sources

- [*Blockchain Address Poisoning*](https://arxiv.org/html/2501.16681) — arXiv:2501.16681 / ACM CCS 2024
- [SlowMist: the 1155 WBTC phishing incident](https://slowmist.medium.com/small-bait-big-fish-unveiling-the-1155-wbtc-phishing-incident-22bf53b6fe60)
- [Decrypt: $700K USDT address-poisoning loss](https://decrypt.co/316412/crypto-user-loses-700000-to-address-poisoning-scam-heres-what-happened)
- [Telegraph miner YAML specification](https://github.com/telegraphprotocol/telegraph-docs/blob/main/miners/yaml-config.md)
