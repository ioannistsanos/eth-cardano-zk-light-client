# Stage-2 Boot rehearsal — Preview testnet (deployment record)

**REHEARSAL.** Toy n=8 verifying keys ⇒ the vk *shape* is N-independent, so every number below is the
real deployment figure, but the vks are L1-frozen anchors and Phase-C governance is out of scope, so
**this bridge can never serve a real proof — it is a dead-end by design.** A Boot with real n=512 vk
*values* is a re-run of this identical tooling (same datum size / minADA / fee / tx size); the first one
is transaction `27c9765b…` of 2026-06-17 (`benchmarks/raw/phase-a-rehearsal/D27-regular-rehearsal.log:7-8`).

**Network:** Cardano **Preview** testnet · free tADA · never mainnet. Date: 2026-06-13.

## Citable artifacts (measured as-is)

| artifact | value |
|---|---|
| Boot tx hash | `a179dcc7e869ff74c36cfce39ee37a9917b3f72cb14b6b9f8a3b71c6f97bbf34` |
| bridge address | `addr_test1wpthwsstjl44spsmhqrjjv25gmeq2lj0m6w8n56phg4gm9gqk3ng7` |
| genesis bridge UTxO | `a179dcc7…f97bbf34#0` (live) |
| state-thread policy id | `65ca7463fb2ffedc98d5c79a90d86d42b02aa7001bdf9c3a8958b840` |
| NFT | `(policy, "zkbridge_state", 1)` in the bridge UTxO value |
| seed UTxO (consumed) | `f210390156e7…59de77cd#1` |
| collateral-prep split tx | `f210390156e7e2d06de08ed0ab367cf90402710f427979ddbd7dd78459de77cd` |
| deployer (throwaway Preview) | `addr_test1vqnpr3xsh5jf8wmqdswqcspr025vr7sw9p4609lhu3ee7kc445rkj` |

## Measured numbers vs the Stage-1c pre-registrations

| quantity | measured (on-chain) | pre-registered | verdict |
|---|---|---|---|
| **minADA (the §2.1.6 "locked ada deposit")** | **12,447,280 lovelace ≈ 12.4473 ADA** | 11–13 ADA | **within** — the thesis's unquantified deposit, now MEASURED |
| Boot tx size | **3598 B** | 3.5–5 KB | within (22.0% of the 16384 limit) |
| Boot fee | **317,085 lovelace ≈ 0.3171 ADA** | 0.5–0.8 ADA | **UNDER** — real mint ex-units ≪ the generous estimate (D22) |
| datum size | **2632 B** | 2632 | match |
| total deploy cost | ≈ **12.76 ADA** (12.4473 locked + 0.3171 fee), deposit recoverable on spend | — | — |

## The on-chain byte-identity proof (the loop closed)

The bridge UTxO's **inline datum is 2632 B with sha2_256 = `86eeded9…c2fdad6`** — **byte-identical** to
the Stage-1b pin (`validator/lib/zkbridge/genesis_datum_test.ak`). The chain held end-to-end:

```
Aiken cbor.serialise (source of truth, Stage-1b)
  → boot/genesis_datum_period1600.hex (sha2_256 pinned)
  → RawCBOR verbatim embed (assemble.py)
  → guard: sha2_256 on the SIGNED tx before submit
  → ON-CHAIN inline datum: sha2_256 == 86eeded9…  ✓
```

What Stage-1b proved decodable at the first spend is exactly what is on-chain now. (The first spend
itself is AWS-gated — needs a real proof — and this rehearsal bridge cannot serve one; that is the
frozen-anchor dead-end, by design.)

## What ran

§2.1.6 gate (`boot_genesis`, abort semantics, PASSED) → genesis values · `derive_params` (seed →
POLICY_ID → bridge address, guards) · collateral-prep split (a single faucet UTxO can't be both seed
and collateral) · `assemble.py --submit` — the three guards IN ORDER (datum byte-identity FIRST, then
param-identity, then output self-check), build, sign (throwaway skey, outside the repo), submit, poll,
query. Keys + Blockfrost key read from `~/.config/zkbridge/preview/`, never committed.
