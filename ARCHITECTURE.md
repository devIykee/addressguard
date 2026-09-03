# AddressGuard — Architecture (Tier 1, with Tier 2 seams)

Telegraph Protocol miner for the `FRAUD_DETECTION` canonical intent. Verified
canonical and live at 2026-09-02 (`miner_count: 15`).

**One question, answered narrowly:** is this destination identity a *lookalike*
of one the caller already trusts? Nothing else. Contract risk, behavioural
fraud, and scam-list matching are out of scope and already well served on this
intent — see README scope note.

---

## 1. What live verification changed

Four things were checked against the network before designing anything. Three
of them change the build; all four are load-bearing, so they're recorded here
rather than absorbed silently.

### 1.1 The YAML in the brief would register and then never be routed to

`endpoints[]` accepts **ten** keys, not the eight the brief lists. The two
missing ones are the two that decide whether traffic arrives at all:

| Key | Live schema says | Brief said |
|---|---|---|
| `intents` | **Required** — "registration is refused if none does" | not listed |
| `params` | "Recommended"; without it the node guesses field names | not listed |

Confirmed against `telegraph-docs/miners/yaml-config.md:225-252` and against
`degenlens-onchain`'s live YAML, which declares `intents` on 8 endpoints and
`params` on 13. Seven other live `FRAUD_DETECTION` miners omit both — they are
registered, active, and (per the docs' own diagnosis) reachable only by
hand-built calls, not by autonomous routing.

**Decision:** declare both. `params.body` is what tells the request builder
that `callerHistory` exists — without it, a routed call arrives with `address`
only and every answer degrades to `insufficient_history`. This is the single
highest-leverage line in the config.

Everything else in the brief's schema constraint list held: `input_schema` /
`output_schema` top-level only, `signal_mapping` limited to the three
`*_field` keys, `additionalProperties: false` throughout.

### 1.2 Full-string Levenshtein does not separate real poisoning pairs

Measured on two incidents reconstructed from chain (§6), against unrelated
controls:

| Pair | prefix `a` | suffix `b` | `d=a+b` | Levenshtein sim |
|---|---|---|---|---|
| WBTC 2024 — trusted vs. lookalike | 4 | 6 | 10 | 0.325 |
| USDT 2025 — trusted vs. lookalike | 4 | 4 | 8 | 0.325 |
| unrelated control | 0 | 0 | 0 | 0.125 |
| unrelated control 2 | 0 | 0 | 0 | 0.100 |

Prefix/suffix separates cleanly (10 and 8 vs. 0). Levenshtein gives real pairs
0.325 against a 0.10–0.125 floor — a 0.2 gap on a 0–1 scale, with the real
attacks scoring *below the midpoint*. It cannot carry a `high_risk` verdict.
The CCS'24/arXiv 2501.16681 measurement study reaches the same conclusion
independently and discards middle-of-string metrics as "largely irrelevant":
attackers vanity-mine the ends because that is what wallet UIs truncate, and
leave the middle random.

**Decision:** build `LevenshteinStrategy` as specified, but as a *secondary*
signal — it can lift a borderline `d` into `high_risk` and it catches
end-shifted variants prefix/suffix misses, and it cannot alone exceed the
`caution` ceiling. Documented in `config/thresholds.ts`, not buried.

### 1.3 Thresholds have a published source, so they aren't judgement calls

The same study's detection floor is `a>=3 && b>=4`, derived from wallet UIs
truncating to 3–5 characters and explorers to 6–7. Observed attacks cluster
from `(3,4)` upward, thin out past `d=14`, and top out near `d=20` (est.
27,093 GPU-days to mine). Both fixtures sit just above the floor at `(4,6)`
and `(4,4)`. Thresholds in §5 are anchored to those numbers.

### 1.4 Part B is harder than the brief assumes — the champion is perfect

`GET /api/wasm` → `intents.FRAUD_DETECTION.champion` (registration 2793,
active since 2026-08-31):

```
candidate_margin 1.0      worst_self_match 1.0      candidate_wins 15/15
champion_margin  0.9999   score_stddev     0.4714   spearman 0.933
```

A margin of exactly `1.0` means it scores every benchmark good answer 1.0 and
every bad answer 0.0. Promotion requires matching that margin *and* winning at
least 15/15 — so a scorer that is merely reasonable does not get promoted.

**Recorded risk, not designed yet (revisit at Part B, per process order):** if
a benchmark `ground_truth` is prose containing no tier vocabulary, a pure
tier-normalizing scorer routes both the good and the bad answer to the same
"unparseable" branch. Margin collapses and it fails the "scores actually vary"
check outright. B.2 as written therefore needs some fallback for non-tier text,
retaining vocabulary normalization for the label-shaped cases it was designed
for. Not designed here — Part B is gated behind Part A, and designing it now
would be guessing at benchmark content.

---

## 1.5 Two decisions taken with the user

**Deploy target: Vercel.** Two live `FRAUD_DETECTION` miners already run there
(`anchor-miner.vercel.app`, `veridex-ecru.vercel.app`), so it is proven for
this intent. Build shape: a plain handler function, wrapped by both
`api/index.ts` (Vercel serverless) and `src/api/server.ts` (`node:http`, for
local tests and the Part C demo). The handler is the same code in both, so
tests exercise what production runs.

**`callerAddress` is in Tier 1, not Tier 2c.** As specced, Tier 1 trusts
client-supplied `callerHistory` — but an autonomously routed call has no
history to supply, and `input_schema` cannot force the engine to invent one.
Every routed call would return `caution / insufficient_history`: honest, and
useless. Tier 1 therefore accepts an optional `callerAddress` and derives the
trusted set from chain when `callerHistory` is absent.

That pulls the Tier 2a RPC path forward, so the guardrail is: it is
**additive and optional**. All three matching paths, the label rules, and the
response contract are unchanged; if the derivation fails or returns nothing,
the answer degrades to exactly the specced `insufficient_history`. The dust/
zero-value *evidence* check (2a proper) and ENS (2b) stay in Tier 2.

### The derivation rule, and why the obvious version is exploitable

A derived trust set must not be poisonable — if the attacker's lookalike can
get *into* the trusted set, the check inverts and blesses the attack. Three
rules were tested against both fixtures at the block *before* each loss:

| Rule | Result |
|---|---|
| Any counterparty in the caller's tx history | attacker **trusted** — poisoned |
| Any `Transfer` log naming the caller as sender | attacker **trusted** — forged logs |
| **Only counterparties of transactions the caller signed** | attacker **excluded** ✓ |

Trust comes only from **deliberate sends**: transactions where
`tx.from == callerAddress`, taking the recipient from a non-zero `value` or
from decoded `transfer(to,…)` / `transferFrom(…,to,…)` calldata. An attacker
cannot forge this — it requires the caller's signature.

Measured at the block before each loss:

```
WBTC 2024, block 19789008   trusted={0xd9a1b0b1…3a91}  legit ✓  attacker ✗
                            14 forged-log counterparties excluded, incl. attacker
USDT 2025, block 22307397   trusted={0x2c11a3a5…9c0b, 0x3c87ade1…5773}  legit ✓  attacker ✗
                            3 forged-log counterparties excluded, incl. attacker
```

In both cases the derived set contains the address the victim *meant* to pay
and excludes the lookalike they actually paid — which is the entire check.

Known cost, stated rather than hidden: the rule drops
contract-mediated sends (a DEX router moving tokens on the caller's behalf),
because the recipient is inside internal transfers rather than the signed
calldata. Verified on the same victim's March 2024 swaps — 5 legitimate
counterparties dropped. That is the right trade: a false negative in the
trusted set costs a `safe` verdict that should have been `caution`, while a
false positive costs the whole check. `callerHistory` remains available for
callers who want to supply those explicitly, and the two sources union.

---

## 2. End-to-end data flow

```
POST /risk-check
      │
      ▼
api/  ── zod parse (only place `unknown` enters)      ── 400 on failure
      │  normalize: lowercase hex, strip dupes
      ▼
resolve trusted set:
      │  callerHistory if supplied
      │  ∪ chain-derived deliberate sends, if callerAddress supplied
      ▼
domain/services/PoisoningDetectionService
      │  guard: trusted set empty ───────────────────► caution / insufficient_history
      │  guard: candidate === trusted[i]   ──────────► excluded, never a match
      │
      │  for each trusted identity:
      │    for each injected SimilarityStrategy:  score ∈ [0,1]
      │    combine → MatchResult{ strategy, target, score }
      │  keep argmax
      ▼
config/thresholds.ts  → score ⇒ safe | caution | high_risk
      ▼
api/  ── shape response, build evidence.canonical, attach checked_at_block
      ▼
{ risk_label, risk_confidence, risk_reason, detail, evidence }
```

`risk_label` / `risk_confidence` / `risk_reason` are top-level and flat —
that's the contract Telegraph's `signal_mapping` reads. `detail` and
`evidence` hang off the side for humans and for the demo; Tier 2 extends those
two and touches nothing the protocol parses.

**`evidence.canonical`** is `address|chain|risk_label|checked_at_block`,
lowercased. Deterministic in, deterministic out: same inputs and same block
hash identically, so an answer is reproducible instead of merely asserted.
`checked_at_block` is a live `eth_blockNumber` read, cached briefly — the two
strongest miners on this intent (Anchor's block-pinned freshness, TxLens'
`canonical` string) both treat this as core, and it's cheap.

---

## 3. Module boundaries

```
src/
  domain/
    entities/            MatchResult, RiskCheckResult, OnChainEvidence,
                         RiskLabel        — data only, no behaviour
    interfaces/          SimilarityStrategy   ← Tier 1 uses
                         Logger               ← Tier 1 uses
                         BlockProvider        ← Tier 1 uses (checked_at_block)
                         TrustedSetProvider   ← Tier 1 uses (§1.5 derivation)
                         OnChainDataProvider  ← Tier 2a, declared now
                         EnsResolver          ← Tier 2b, declared now
    services/            PoisoningDetectionService — aggregation only
  matching/
    prefix-suffix/       PrefixSuffixStrategy      (Tier 1)
    levenshtein/         LevenshteinStrategy       (Tier 1)
    ens-homoglyph/       .gitkeep                  (Tier 2b)
  verification/          .gitkeep                  (Tier 2a)
  infrastructure/        RpcBlockProvider, ConsoleLogger,
                         ExplorerTrustedSetProvider
                         (RpcDustTxProvider, RpcEnsResolver — Tier 2)
  api/                   schema.ts (zod), handler.ts, server.ts
api/                     index.ts — Vercel entry, wraps the same handler
config/
  thresholds.ts          named constants + why, sourced to §5
  telegraph.miner.yaml
tests/
  unit/                  one file per strategy + service
  integration/           HTTP in, JSON out
```

Dependency direction is strictly inward: `api → domain ← matching`,
`api → infrastructure`. `domain/` imports nothing from `matching/`,
`infrastructure/`, or `api/` — it only defines the interfaces they satisfy.

Empty Tier 2 folders exist deliberately. The interfaces they will implement
are written in Tier 1 (`OnChainDataProvider`, `EnsResolver`), so Tier 2 is an
additive change: a new file, one more entry in an injected array, no edits to
the service, the handler, or the response contract Telegraph reads.

---

## 4. SOLID, mapped to these files

Not a restatement of the principles — the specific decision each one forces
here, and the thing that would go wrong without it.

**Single Responsibility.** Three layers that change for three different
reasons. `matching/*` changes when a new attack shape is discovered.
`PoisoningDetectionService` changes when the *aggregation rule* changes (pick
strongest match, exclude exact matches, cap unverified targets). `api/`
changes when the wire format changes. Concretely: raising the `high_risk`
threshold touches `config/thresholds.ts` and nothing else; adding
`onchain_evidence` to `detail` touches `api/` and nothing else.

**Open/Closed.** `PoisoningDetectionService` iterates an injected
`readonly SimilarityStrategy[]` and never names a concrete strategy. Adding
Tier 2b's `EnsHomoglyphStrategy` is: write the class, add it to the array in
`server.ts`. The service file is not reopened. This is the specific reason the
interface exists — Tier 2b is a planned second implementer, not a hypothetical
one.

**Liskov Substitution.** Every `SimilarityStrategy` obeys the same contract,
enforced by a shared test suite each implementation is run through: two
identity strings in, `[0,1]` out, **never throws**. Malformed input (wrong
length, non-hex, empty, `undefined` at runtime despite the types) returns `0`
and logs a warning. A strategy that threw on a malformed history entry would
take down a whole request over one bad array element — so the contract forbids
it, and the shared suite proves each one honours it.

**Interface Segregation.** `SimilarityStrategy` is one method, `score()`, plus
a `name` for `risk_reason`. It does not load config, fetch data, or log — the
Tier 2b ENS strategy needs an `EnsResolver` and network access, and if that
were bolted onto the shared interface, `PrefixSuffixStrategy` (a pure
function) would have to accept a resolver it never calls. `EnsResolver` and
`OnChainDataProvider` are separate interfaces injected only into the
implementations that need them.

**Dependency Inversion.** `PoisoningDetectionService`'s constructor takes
`SimilarityStrategy[]` and `Logger`; the handler takes the service and a
`BlockProvider`. No module reaches for a concrete class or a singleton, and
there is no global mutable state. This is what makes the unit tests pure: the
service is tested with two stub strategies returning fixed scores, so a test
for "picks the strongest match and excludes exact matches" cannot break
because a similarity formula was retuned.

---

## 5. Thresholds — `config/thresholds.ts`

Every constant traces to §1.2/§1.3 or to a stated failure mode.

| Constant | Value | Why this number |
|---|---|---|
| `MIN_PREFIX_CHARS` | 3 | Published detection floor `a>=3`; wallet UIs truncate to 3–5 |
| `MIN_SUFFIX_CHARS` | 4 | Published floor `b>=4` |
| `SATURATION_D` | 16 | Observed attacks thin past `d=14`; `d>=16` is unambiguous |
| `PREFIX_SUFFIX_FLOOR` | 0.75 | Score at the floor `(3,4)`; both fixtures land ≥0.8125 |
| `HIGH_RISK_AT` | 0.80 | Below the fixtures (0.8125, 0.75+lev lift), above the 0.125 control ceiling |
| `CAUTION_AT` | 0.55 | Catches near-floor and Levenshtein-only hits without reaching `high_risk` |
| `LEV_MAX_ALONE` | 0.79 | Hard cap: §1.2 — Levenshtein alone can never assert `high_risk`. Sits just under `HIGH_RISK_AT` (0.80) so the cap is visibly the binding constraint. Asserted by a dedicated unit test, not left true by construction |
| `LEV_LIFT_WEIGHT` | 0.15 | Max lift Levenshtein adds on top of a prefix/suffix hit |

Prefix/suffix score, for `d = a + b` once the floor is met:

```
0.75 + 0.25 * min(1, (d - 8) / 8)      d=8 → 0.750   d=10 → 0.8125
                                        d=12 → 0.875   d=16 → 1.000
```

The USDT fixture at `d=8` scores 0.750 on prefix/suffix alone — `caution`, not
`high_risk` — and is lifted over 0.80 by the Levenshtein term. That is the
combination rule earning its place, and it is an explicit test case.

**Label rules.**

- `safe` — only when the trusted set is non-empty **and** no match cleared
  `CAUTION_AT`. Never on an empty trusted set: that would assert a check that
  never ran.
- `caution` — score in `[CAUTION_AT, HIGH_RISK_AT)`, or
  `risk_reason: "insufficient_history"`.
- `high_risk` — score `>= HIGH_RISK_AT`.

`risk_confidence` is the similarity score itself for a match, and a fixed
documented low value for `insufficient_history` — a confidence, not a
restatement of the label.

`risk_reason` is structured and deterministic, never prose
(`FRAUD_DETECTION` is Tier A, scored by near-match):

```
poisoning_match:0xd9A1…3a91:similarity=0.94
insufficient_history
no_poisoning_match
```

---

## 6. Test fixtures — reconstructed from chain, not invented

Both incidents were traced on Ethereum mainnet during design. Full addresses
and transaction hashes go in the fixture files.

**1155 WBTC, May 2024 (~$68M).** Victim `0x1E22…8FD5` sent 0.05 ETH to a real
counterparty `0xd9A1b0B1…3a91` at block 19788628. Sixteen blocks later the
attacker's lookalike `0xd9A1C378…3a91` sent the victim a **0-value** transfer
(block 19788644) to plant itself in their history. At block 19789009 the
victim sent 1155.28802767 WBTC to the lookalike. Prefix/suffix `(4,6)`.
Verified: `eth_getTransactionByHash`, Blockscout `tokentx`.

**699,990 USDT, April 2025.** Victim `0xcf03aA88…d5d7` sent a 10 USDT test
transfer to `0x2c11a3a5…9c0b` (block 22307387). Three blocks later a
zero-value USDT `Transfer` log was forged naming the lookalike
`0x2c1134a0…9c0b` (block 22307390, confirmed `value: 0` in the receipt). At
block 22307398 the victim sent 699,990 USDT to the lookalike. Prefix/suffix
`(4,4)` — the harder case, and the one that pins the combination rule.

Both are the same mechanism: a **zero-value transfer** planting the lookalike
in the victim's history. That is why Tier 2a checks for it directly, and why
it correlates on *zero-value* transfers, not only dust. Per the same study,
zero-value transfers are ~55% of poisoning attempts and counterfeit-token
transfers ~44%, while true dust (<$10) is under 2% — so "dust" alone would
miss the overwhelming majority. The Tier 2a check covers zero-value first.

Also tested: exact-match exclusion (candidate identical to a trusted entry →
never a match), unrelated controls → `safe`, empty trusted set → `caution`,
malformed input (short hex, non-hex, empty string) → strategy returns `0` and
does not throw, and the §1.5 derivation on both fixtures at the block before
each loss (legit trusted, attacker excluded).

---

## 7. Verified external dependencies

Probed live, since the brief flagged public-endpoint reliability as a
stop-and-ask. All Tier 1 and Tier 2 dependencies resolve without a paid key.

| Need | Endpoint | Result |
|---|---|---|
| `checked_at_block`, Base | `https://mainnet.base.org` | `eth_blockNumber` OK |
| `checked_at_block`, Ethereum | `https://eth.drpc.org`, `rpc.flashbots.net` | OK |
| Tier 1 trusted-set derivation | `eth.blockscout.com` `action=txlist` | OK, no key |
| Tier 2a dust/zero-value tx | `eth.blockscout.com` `action=tokentx` | OK, no key, account-indexed |
| Tier 2a fallback | `eth_getLogs` on drpc / mainnet.base.org | OK, **10,000-block cap** |
| Tier 2b ENS | ENS registry `0x0000…2e1e` → resolver `addr()` | OK — `vitalik.eth` → `0xd8dA…6045` |

Two constraints follow, and they are why Blockscout is the primary Tier 2a
provider rather than raw `eth_getLogs`: the log path is capped at 10,000
blocks on every free endpoint tested (~5.5h on Base, ~33h on Ethereum), which
is far too short to catch a poisoning transfer planted days earlier.
`base.blockscout.com` returned 500/connection failures during probing, so Base
needs the `eth_getLogs` fallback with an explicit "not checked" result rather
than a silent false negative. Ruled out: `publicnode` (archive requests need a
token), `cloudflare-eth`, `ankr` (key required), `llamarpc` (521).

The same Base gap applies to §1.5: `callerAddress` derivation is reliable on
Ethereum and best-effort on Base. When derivation is unavailable the answer is
`insufficient_history`, never a fabricated `safe`.

---

## 8. Build order

Tests land with each module, before the next one starts.

1. `PrefixSuffixStrategy` + shared strategy-contract suite + §6 fixtures
2. `LevenshteinStrategy`, through the same shared suite
3. `PoisoningDetectionService` — exact-match exclusion and
   `insufficient_history` tested explicitly, with stub strategies
4. `ExplorerTrustedSetProvider` (§1.5) — unit-tested against recorded
   explorer payloads, so the tests are offline and deterministic
5. `api/` — zod boundary, response shaping, `evidence.canonical`,
   `checked_at_block`; integration tests
6. `telegraph.miner.yaml` **with `intents` + `params`** (§1.1), validated at
   integrate.telegraphprotocol.com before any gas
7. Deploy to Vercel, register, confirm `activation_status`

**Then stop — this is the checkpoint, stated explicitly when reached.** Tier 1
is not "done" until it is deployed, validated at
integrate.telegraphprotocol.com, registered, and confirmed
`activation_status: active` via
`GET /api/miners/<registrationId>`. The §1.5 `callerAddress` derivation is
real added complexity inside Tier 1 and does not move that line. No Tier 2
file is created before the checkpoint passes; if it doesn't pass, Tier 1 gets
polished and shipped and Tier 2 is documented as planned, not started.

## 9. Reserved for Tier 2 — recorded, not built

- `id: 1155` and slug `addressguard-poisoning-check` both confirmed unused
  against the live 129-miner list. `1155` is the WBTC fixture's amount.
- Tier 2a: zero-value / dust transfer *evidence* — does the suspect address
  itself have an inbound-to-caller zero-value transfer? Raises confidence and
  appends `:onchain_dust_tx_confirmed` to `risk_reason`.
- Tier 2b: `EnsHomoglyphStrategy` behind the same `SimilarityStrategy`
  interface.
- Tier 2c: flag `callerHistory` entries not corroborated by the §1.5
  derivation, and cap an uncorroborated match target at `caution`.
