# (C) VM-tier scenario runbook — the live 1-VM ZK-bridge relay

> The ordered plan for the final empirical run. **Nothing here executes automatically** — it is the
> reference we follow, grounded in the measured/built reality: D16 (boundary 60.9M constraints), D23
> (setup), D24 (proving + destruction), D27 (regular on-chain), the pk/vk/τ lifecycle (§5), the
> ~12.45 ADA deposit (D22), and the relayer in `prover/offchain/relayer/` + `prover/cmd/relayer/` + `boot/`.

## Goal

One GCP VM runs the entire relayer through **1 Bootstrap → regular×N (until the rollover) → 1 Boundary →
2 Regular** (N variable), each phase measured on both sides (D26/D27/D28), with the regular/boundary
decision **live** (detected, not announced) and pk/τ destroyed after. The scenario Boot writes
**vk_fresh** so the fresh-pk proofs verify; the *shape* is the `--plan` (`regular*,regular,regular`), each
*decision* is the relayer's `Cache.Discern`. **Chosen boundary B: the period-1787 rollover, Fri
2026-06-26 20:01 EEST** (§2). Local timezone Europe/Athens EEST +03:00.

---

## 1 · The exact sequence (one VM, in order)

| # | step | command (grounded) | produces | verified before next |
|---|---|---|---|---|
| **S0** | cross-check the bootstrap root and the genesis validators root | obtain the finalized checkpoint root from at least **TWO independent sources** (different operators — e.g. two public checkpoint-sync providers, or a provider + an explorer); compare the 32-byte roots. **Also** query `/eth/v1/beacon/genesis` on the beacon node the relayer will use and compare its `genesis_validators_root` with the mainnet constant `0x4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95` (the value carried by the committed mainnet fixtures, e.g. `validator/fixtures/bls_regular_period1600.json`) | the agreed `--bootstrap-root` + both source URLs + the `genesis_validators_root` comparison, recorded in the provenance log | **proceed only if the roots agree AND `genesis_validators_root` equals the constant** — §3.1.6 pre-condition P1 (the finalized root) and the genesis-validators-root pre-condition; the code verifies finality cryptographically (a/c/d) but cannot detect a single lying endpoint, and the relayer reads `genesis_validators_root` from `/genesis` at seed time (`prover/offchain/relayer/live.go:75-79`) without comparing it to a constant, so both checks are the operator's |
| **S1** | provision | GCP `n2-custom-12-131072-ext` (12 vCPU / **125 GiB** — the D23/D24 shape; the 128 GiB box the 108.71 GiB boundary setup needs) in **us-central1, zone `us-central1-a`** (primary; the proven D23/D24 region; fallback `us-central1-b/c/f` on `ZONE_RESOURCE_POOL_EXHAUSTED` — the D24 zone-move). Spot. Quota pre-verified: **200 CPUS / 248 N2_CPUS, need 12 — ample** (no increase). **Every remote script ends `sudo shutdown -h now`.** | the VM | `nproc=12`, `free ≈125Gi`; git/tokens NOT on the VM (Option-C) |
| **S2** | fresh setup | `cmd/groth16_setup` (RunSetup) — **both** circuits, n=512, pk/ccs→SCRATCH, vk→OUT | pk_fresh (regular **1.37 GB** + boundary **44.0 GB**, 44,031,872,691 bytes or 41.0 GiB), ccs, vk binaries | exit 0, **no swap**; regular ~**6 min**/4.11 GiB, boundary ~**3.29 h**/108.71 GiB (D23); `vk.ReadFrom` → 14/15 G1 + 5 G2 → **D25** |
| **S3** | export vk_fresh | `cmd/vk_to_json` → `groth16_{regular,boundary}_n512_FRESH.json` | the **fresh** public vks | shape 14/15 G1 + 5 G2; **NOT** the committed D24 vks, **NOT** toy |
| 🚦 | **GO/NO-GO** | see **§1.1** | a manual GO | the 3 pre-Boot checks pass |
| **S4** | scenario Boot | `emit_genesis_datum.py --vk-regular FRESH --vk-boundary FRESH --base-values <real current bootstrap> [--finalized-root/-slot]` → `genesis_datum_scenario.hex` ; `derive_params.py --seed-txid … --seed-ix …` ; `assemble.py --submit --datum-hex genesis_datum_scenario.hex --datum-sha <sha> --seed … --collateral …` | the **live bridge UTxO** (vk_fresh + genesis committee, **period 1786**), ~12.45 ADA locked (D22); Boot ~Fri midday | the 3 Boot guards (datum byte-identity → param-identity → output self-check) + the bridge UTxO confirmed; **B = period-1787 is the NEXT rollover after this Boot** (§2 rule) |
| **S5** | seed-check | (offline, pre-run) `SeedCacheFromFixtures` on the scenario bootstrap | the seeded `Cache` | **seeded commitments == the vk_fresh genesis datum's** — see **§1.2** |
| **S6** | birth | `cmd/relayer --mode live …` → `LoadProver` once (pk_fresh ~42 GB resident) | the resident prover | LoadProver completes; **birth ~Fri 19:00–19:30, BEFORE B = 20:01** (§2) |
| **S7** | the live run | `cmd/relayer --mode live --plan regular*,regular,regular --bootstrap-root <checkpoint> --output-dir <pk> --python <venv> --out benchmarks/raw/phase-a-scenario` (regular* SPENDS N regulars until the rollover, then the boundary, then 2 trailing) | N+3 confirmed spends + STATUS/phase-N/SUMMARY | SUMMARY complete → **D26/D27/D28** |
| **S8** | destroy | §5 | pk/τ gone; final inventory 0/0/0 | only **after** 5/5 + artifacts verified home |

### 1.1 · 🚦 Pre-Boot GO/NO-GO (between S3 and S4)

The vk-mismatch is the **single most expensive mistake** — it surfaces only at reg#1, *after* the ~3.5 h
setup. A 30-second manual confirm before the irreversible-ish Boot catches it before reg#1, not after.
**GO requires all three:**

- **(a) Fresh vks exist + right shape** — `groth16_{regular,boundary}_n512_FRESH.json` are present and
  read back to **14 G1 (α+13 ic) + 5 G2** (regular) / **15 G1 (α+14 ic) + 5 G2** (boundary).
- **(b) `emit_genesis_datum.py` points at the FRESH vk JSONs** — a literal **path/filename check** that
  `--vk-regular`/`--vk-boundary` reference the S3 `…_FRESH.json` files, **not** the committed
  `validator/fixtures/groth16_*_n512.json` (those are **vk_D24** — pk destroyed, unusable) and **not** the
  toy n=8 vks.
- **(c) The genesis datum sha is recorded** — capture `sha2_256(genesis_datum_scenario.hex)`; it is the
  same value `assemble.py --datum-sha` asserts and the seed-check (§1.2) reconciles against.

**NO-GO on any → stop, fix, re-check.** Do not submit the Boot until GO.

### 1.2 · S5 seed-check — live consistency vs the offline known-good

Two distinct things, kept separate so we don't expect a match that can't exist:

- **Offline (already proven):** the seeding *logic* was validated against **known-good** values — the
  `TestSeedCache_Period1600KnownGood` gate asserts the period-1600 seeding produces
  `10041e8c…`/`483e20c9…` (the exact gate-1/D27 commitments accepted on-chain). The correctness of
  `bootstrap.Verify → committee commitments` is therefore proven byte-for-byte against a proven-on-chain
  instance.
- **Live (S5, this run):** the scenario seeds from a **fresh** current-period bootstrap with **new**
  committees — so there is **no** known-good to compare against. S5 is a **consistency** check:
  *seeded `Cache` commitments == the vk_fresh genesis datum's committee commitments* (i.e. the same
  `bootstrap.Verify` output went into both the datum the Boot wrote and the cache the relayer seeds). A
  mismatch bricks reg#1; a match means the proven-correct logic produced consistent values on the new
  committees. **Do not expect `10041e8c…`/`483e20c9…` at S5** — those are the offline gate's period-1600
  values, not the scenario's.

---

## 2 · The scheduling computation — chosen B = period-1787 (Fri 2026-06-26 20:01 EEST)

With the **`regular*` plan** (`--plan regular*,regular,regular`) the pre-boundary run is OPEN-ENDED: the
relayer SPENDS advancing regulars until it detects + spends the rollover, then the 2 trailing regulars.
So **reg#1+#2 no longer need to "finish before B"** — the only hard constraint is **BIRTH the relayer
BEFORE B**. The risk flips from "started too close → HALT" to "**birthed too late → seed mismatch**" (the
Boot rule + idle-bridge note below).

**Chosen B (locked 2026-06-22):** the **period-1787 rollover** — `B_slot = 1787·8192 = 14,639,104`,
`B_unix = 1606824023 + 14,639,104·12 = 1,782,493,271` = **Fri 2026-06-26 20:01 EEST** (17:01 UTC); ~5 h of
in-window runway. The bridge's current committee is therefore period **1786**.

```
B_slot  = (P+1) · 8192                       # P = current sync-committee period at run time
B_unix  = genesis_time + B_slot · 12         # genesis_time(mainnet) = 1606824023 ; SecondsPerSlot = 12
```

**Per-regular cadence** (sizing N): poll-detect ≤ **6m31s** (S1) + prove **14.56 s** (D24 regular) + spend
~**1–2 min** ≈ **~8 min**/regular. Birth **~30–90 min** before B → **N ≈ 4–12** pre-boundary regulars — a
reasonable demonstration count (not the fixed 2, not dozens).

```
Fri morning       VM-start -> fresh setup (S2, ~3.5 h, unattended)
Fri ~midday       setup done -> GO/NO-GO (1.1) -> scenario Boot (S4): captures period 1786 -> live bridge
Fri ~19:00        LoadProver (S6) -> BIRTH (--mode live), >= ~1 h before B; bridge idle is SAFE (see below)
Fri 19:00->20:01  regular* spends ~4-8 regulars (period 1786)
Fri 20:01  (B)    discern + spend the BOUNDARY (rotate 1786->1787) -- the watched phase
Fri 20:01->20:45  2 trailing regulars (period 1787) -> SUMMARY -> S8 destruction
```

**The Boot rule (committee-window invariant):** the Boot must capture the period current in `[B−1, B]` —
**B must be the *next* rollover after the Boot**. `B−1` = period-1786 start = **Thu 16:42**, so any Boot
Thu 16:42 → Fri 20:01 captures **1786**; the Fri-midday Boot qualifies. **The idle bridge (midday → evening
birth) is SAFE:** no rollover occurs in between, so the committee cannot drift — the relayer seeds the same
period 1786 (cache == datum) and reg#1 simply advances the finalized slot from genesis to current. **Birth
before B = 20:01** — a *later* birth collides with the rolled-over chain (`bootstrap.Verify` seed HALT).

**Recompute on the morning:** the period numbers are FIXED; re-run the read-only head query (the
computation above) to confirm B_unix (live head ±a slot or two) + that the current
period is **1786** before Booting. D25 refines the setup time.

---

## 3 · The vk-matching order (explicit — the vk↔pk-pairing constraint)

A fresh-pk proof verifies **only** under vk_fresh. Therefore:

- **The scenario Boot (S4) must follow the fresh setup (S2–S3)** and write **vk_fresh** into the genesis
  datum.
- `emit_genesis_datum.py` is invoked with `--vk-regular/--vk-boundary = the S3 fresh vk JSONs` — **never**
  the committed `groth16_*_n512.json` (vk_D24 — pk destroyed) and **never** the toy n=8 vks. *Enforced by
  the §1.1 GO/NO-GO (b).*
- The seed-check (§1.2) confirms the seeded commitments == the genesis datum's (consistency on the new
  committees; the seeding logic's correctness was proven offline against known-good).
- A wrong vk ⇒ **every spend rejects on-chain** — the single most expensive mistake; gated S3 → GO/NO-GO →
  S4 → S5.

---

## 4 · Unattended monitoring + retry

- **STATUS.json** (rewritten each transition): `{phase N/5, planned_kind, state:
  polling|proving|confirmed|halted, completed, last_tx, error?, updated_unix}` — `cat` to check in.
- **Heartbeat** (stdout/log): `alive · phase X/5 · waiting for boundary · skipped K regulars · +elapsed`.
- **phase-N.json** per completed phase + **SUMMARY.json** on completion.
- **Auto-HALT + self-stop on ANY failure** (prove error, spend reject, `Discern==Halt`, σ-verify fail,
  poll deadline) → STATUS `halted` + the error + `sudo shutdown`. You return to **SUMMARY 5/5** or
  **STATUS.halted with the exact cause** — never a spinning VM.
- **Retry:** the **setup + pk_fresh are reusable on disk** — only the Boot + the ~1 h run repeat (NOT the
  ~3.5 h setup). A mid-run HALT leaves a partially-advanced bridge; the clean retry is **re-Boot a fresh
  scenario bridge** (new seed → new bridge, same vk_fresh) + re-run the full `--plan`. ⚠️ A *post-boundary*
  HALT means the original B is past → wait for the **next** B (≤27.3 h) — so the live risks (§7) are best
  caught pre-flight.

---

## 5 · Destruction discipline (S8)

- **Retention:** pk_fresh + ccs + SCRATCH retained until **SUMMARY 5/5** *and* every artifact (5 phase
  records + SUMMARY + raw logs) **scp'd + sha256-verified home** (the D24 4/N re-check).
- **Production vs demonstrator:** in production, τ is destroyed once by the **MPC ceremony
  before** the relayer runs and the pk is **retained permanently** (proofs for years). Ours is a
  **single-party demonstrator** — τ is never persisted (gnark's `Setup` discards it in RAM), and we
  destroy **all** setup artifacts (pk + the VM/RAM that briefly held τ) **after** the scenario, to make
  the throwaway-demonstrator status unambiguous.
- **Exact sequence (mirrors D24):** after the verify-home passes → `shred -uvz -n 1 pk_regular_n512.pk
  pk_boundary_n512.pk` (+ ccs) + `rm -rf SCRATCH` → delete the VM (boot disk auto-deleted) + any
  snapshots/disks → **final inventory: instances=0, disks=0, snapshots=0**. The **vks are PUBLIC** —
  exported + committed as the scenario's vk fixtures. **HALT-before-destroy:** any mismatch → destroy
  nothing, re-run.

---

## 6 · Measurement capture

| entry | what | source |
|---|---|---|
| **D25** | fresh setup wall + RAM (regular ~6 min/4.11 GiB, boundary ~3.29 h/108.71 GiB) + fresh vk shapes | S2 raw logs (re-confirms/refines D23) |
| **D26** *(new)* | per-phase relayer timing: poll-detect, witness-build, **prove** (reg ~14.56 s / bndry ~7.14 min), spend-submit, total wall-clock, cache rotation — the first end-to-end relay-pipeline timing | the loop's phase-N records |
| **D27** | per-phase on-chain ExUnits/fee/size — regulars **≈ 7.09 B** (re-confirm on vk_fresh) + the **FIRST boundary D27** (the boundary verify on-chain, never measured — the standing gap closes) | spend.py `--emit-json` → SpendResult |
| **D28** *(new)* | system behaviour: the boundary **lag** (prove 7.14 min > 6.4 min cadence) + the **self-heal** (always go-to-latest), regulars skipped during the boundary-wait, 1-VM keep-up feasibility | the loop's records + heartbeat |

---

## 7 · Pre-flight checklist + risk flags

**Must be true before VM start:**

- ✅ **Wallet funded** — ~9987 tADA at `addr_test1vqnpr3x…` (`~/.config/zkbridge/preview/`), ≥2 UTxOs
  (seed + collateral); covers the Boot (~12.45 ADA) + all fees.
- ✅ **All offline gates green** — the 4 seams (redeemer/datum/spend/prover) + the 11 relayer tests + the
  3 step-3 validations (dry-run, seeding, spend-parse).
- ✅ **Self-stop baked in** — `cmd/relayer`'s `Stop = sudo shutdown`; every remote script ends with it
  (the D23 ~8 h-idle/~$8 lesson — **standing rule**).
- ✅ **vk-matching order** locked (§3 + the §1.1 GO/NO-GO) — Boot uses vk_fresh.

**RISK flags (honest):**

1. **The boundary on-chain verify is NEW** — the boundary prove + spend run for the first time live (no
   committed boundary σ; `capture.go`'s `goldenBoundary` covers only the *witness*-build). If the boundary
   spend rejects → a **FINDING** (HALT + investigate) — the one genuinely-new on-chain path.
2. **Boundary timing** — B is chain-fixed (~27.3 h periods); the run must straddle a real B with the
   §2 lead. Too-close a start → reg#2 HALTs → re-Boot + re-run (and possibly wait for the next B). The
   margin mitigates.
3. **Setup-time uncertainty** — boundary setup ~3.29 h ± ?; the robust ordering (§2: setup first, then
   schedule to the next B) absorbs it.
4. **GCP capacity** (D23/D24) — the 128 GiB shape can hit `ZONE_RESOURCE_POOL_EXHAUSTED`; fallback = the
   snapshot **zone-move** to a sibling zone (D24), or try multiple zones at provision.
5. **Cost** — ~3.5 h setup + ~1 h run on the 128 GiB spot box ≈ a few $ (well within the ~$20–50 budget);
   self-stop guarantees no idle.
