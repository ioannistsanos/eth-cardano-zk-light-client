# M5 — Synthetic Phase A Regular (Groth16 + BLS-real + MSM-6) Additivity

Phase 1, measurement M5. Empirical CPU/memory cost of the **composite** of the
three regular-Phase-A cryptographic sequences run in ONE Plutus V3 script, and
whether they compose **additively** with the three independently-measured
component marginals (M1b, M2-real, M3).

See `docs/phase1-methodology.md`, `docs/records.md` (D1, D2, D3), and
`docs/aiken-gotchas.md` (G5, G6, G7).

## Scope (what M5 is and is NOT)

M5 measures **only the cryptographic + MSM portion** of a regular Phase A
transaction:

- Groth16 verify — D1 4-miller-loop on-chain form (M1b): 4×`miller_loop` +
  2×`mul_miller_loop_result` + 1×`final_verify`.
- BLS aggregate verify — **D2 canonical no-mul form** (M2-real): `hash_to_group`
  + 2×`miller_loop` + 1×`final_verify` (NO `mul_miller_loop_result`).
- MSM-6 (M3): 6×`g1_scalar_mul` + 6×`g1_add`.

M5 **deliberately EXCLUDES** datum/redeemer deserialization, anchor-invariance
checks, state-thread NFT continuity, and the datum write. Those are measured on
a real transaction in **Phase 4**. The thesis "~500 M script overhead"
placeholder is therefore `Phase4_total − M5`; **M5 does not measure it**.

## Decision record — BLS uses the D2 (no-mul) form

The BLS sub-sequence is the canonical CIP-381 `final_verify(ml1, ml2)` form
(D2) — i.e. exactly what the real Phase A validator runs — **not** the thesis
Table-2 product form with `mul_miller_loop_result`. This is **−2,174,038 CPU**
vs the Table-2 form. See `docs/records.md` D2.

## Configuration

- **Aiken**: v1.1.22+39d6b04 — **Plutus**: V3 (Conway)
- **Hardware**: WSL2 Ubuntu 24.04, Intel i7-9750H @ 2.60 GHz (6c/12t),
  8,068,188 kB MemTotal; kernel 6.6.114.1-microsoft-standard-WSL2 x86_64
- **Command** (from `validator/`, **G7 exact-match** — pins the exact 2-test
  set so the determinism hash is robust to suite growth):
  `aiken check -e -m bench_m5_core -m bench_m5_control --seed 42`
- **Determinism**: 3 iterations byte-identical (md5
  `104cc8b5400b4cf3977cbb6b244aa31a` ×3). Reported cost is deterministic (from
  the cost model, not wall-clock).
- **Dependencies**: none (BLS builtins from `aiken/builtin` prelude).

## Method note — faithful concatenation + barrier-control subtraction

`bench_m5_core` is a faithful **concatenation** of the three component cores
(M1b core + M2-real core + M3 core), sharing no computed values across the three
sub-sequences. `bench_m5_control` concatenates the three component controls: it
performs the **union of the shared setup** — 4×`G1_uncompress` + 2×`G2_uncompress`
+ 1×`sha2_256` — plus the same const references (`bls_dst`, the six scalars) the
cores load, and **none** of the operation builtins. So:

    marginal = bench_m5_core − bench_m5_control

isolates exactly the union of operation builtins (+ their per-builtin CEK). All
const-loads (generators, preimage, DST, scalars) and the uncompress/sha2 setup
cancel.

**G6**: the BLS message is derived at runtime via `sha2_256(preimage)`, so
`hash_to_group` is not constant-folded — `aiken export` of the mirrors succeeded
(no flat-encoding panic).

Keep-alive idiom: both core and control use `expect _ = x` (G5-recommended) to
force evaluation of, respectively, the three sub-chain results (`g_ok`, `b_ok`,
`m_acc6`) and the seven setup values + const references. This is what makes the
`trace` count symmetric (see below).

## UPLC verification (temp `pub fn` mirrors, exported + decoded, then removed)

Mirrors `pf_m5_core` / `pf_m5_control` were appended, exported via
`aiken export -m benchmarks/m5_phase_a_regular -n <fn>`, decoded via
`aiken uplc decode --cbor --hex`, builtins counted, then **removed** before
commit (`grep 'pub fn pf_m5'` → none).

| Builtin | `pf_m5_core` | `pf_m5_control` | role |
|---|---|---|---|
| `bls12_381_millerLoop` | **6** | 0 | 4 Groth16 (incl. D1 4th-ML) + 2 BLS |
| `bls12_381_mulMlResult` | **2** | 0 | Groth16 LHS product |
| `bls12_381_finalVerify` | **2** | 0 | 1 Groth16 + 1 BLS |
| `bls12_381_G2_hashToGroup` | **1** | 0 | BLS H(m) |
| `bls12_381_G1_scalarMul` | **6** | 0 | MSM pubᵢ·IC[i] |
| `bls12_381_G1_add` | **6** | 0 | MSM accumulation |
| `bls12_381_G1_uncompress` | 4 | 4 | shared setup → cancels |
| `bls12_381_G2_uncompress` | 2 | 2 | shared setup → cancels |
| `sha2_256` | 1 | 1 | shared setup → cancels |
| `trace` | **1** | **1** | `expect` desugar (dead branch) |

The operation builtins (top six rows) appear in core at exactly the **union**
counts and are **absent** from control. **`trace_core` (1) == `trace_control`
(1) → trace is symmetric and cancels in the marginal** (see Interpretation).

## Hypothesis — additivity H₀ (locked before measurement)

- **PRIMARY target** = sum of the three MEASURED component marginals:
  `1,354,670,882 (M1b) + 1,008,845,331 (M2-real) + 465,400,878 (M3) =
  2,828,917,091`.
- **H₀**: `|marginal − 2,828,917,091| / 2,828,917,091 ≤ 0.05 %`
  (band **±1,414,459** CPU steps).
- `Δ = marginal − 2,828,917,091` (signed) is the **result of interest** = the
  cross-structure CEK of running the three sequences in one continuation chain
  vs three separate ones — not a pass/fail to be "fixed".

## Measured

Deterministic — all three trials identical (cpu/mem).

| Test | Reported CPU | Reported Memory |
|---|---|---|
| `bench_m5_core` | 3,191,261,979 | 13,678 |
| `bench_m5_control` | 362,184,888 | 3,648 |
| **marginal (core − control)** | **2,829,077,091** | **10,030** |

## Additivity table (PRIMARY)

| Component (form) | Measured marginal (standalone) | source |
|---|---|---|
| Groth16 — M1b (D1, 4-ML) | 1,354,670,882 | M1b-report |
| BLS — M2-real (D2, no-mul) | 1,008,845,331 | M2-report |
| MSM-6 — M3 | 465,400,878 | M3-report |
| **Σ component marginals (target)** | **2,828,917,091** | |
| **M5 composite marginal (measured)** | **2,829,077,091** | this report |
| **Δ = composite − Σ** | **+160,000** | |
| **Δ%** | **+0.005656 %** | |
| **H₀ (±0.05 %)** | ✅ **holds** (8.8× inside band) | |

The three crypto sequences compose **additively**: the composite marginal
exceeds the sum of the standalone marginals by only **+160,000 CPU steps
(+0.0057 %)**, ~8.8× tighter than the ±0.05 % band. This validates projecting
the Phase A regular crypto+MSM cost by **summation** of the component costs
(first-order, with a small additive correction).

## Secondary cross-check (CEK transparency)

Cost-model **pure-builtin** sum (no CEK), from M5's verified builtin counts:

| Builtin | count × unit cost | subtotal |
|---|---|---|
| `miller_loop` | 6 × 254,006,273 | 1,524,037,638 |
| `mul_miller_loop_result` | 2 × 2,174,038 | 4,348,076 |
| `final_verify` | 2 × 333,849,714 | 667,699,428 |
| `hash_to_group` (n=32) | 166,917,843 + 4,307·32 | 167,055,667 |
| `g1_scalar_mul` (n=4) | 6 × (76,433,006 + 8,868·4) | 458,810,868 |
| `g1_add` | 6 × 962,335 | 5,774,010 |
| **Σ (cost-model, no CEK)** | | **2,827,725,687** |

| Quantity | CPU |
|---|---|
| M5 composite marginal | 2,829,077,091 |
| Cost-model pure-builtin sum | 2,827,725,687 |
| **marginal − cost-model = total CEK in M5** | **+1,351,404** |
| Expected aggregate per-builtin CEK (M1b+M2-real+M3) | +1,191,404 |
| ↳ from: +448,000 (M1b) − 72,596 (M2-real) + 816,000 (M3) | |
| **Residual = cross-structure CEK** | **+160,000** |

M5's total CEK (+1,351,404) is consistent with the components' aggregate
per-builtin CEK (+1,191,404), with **+160,000** of cross-structure CEK on top —
exactly the Δ vs the PRIMARY target (the two cross-checks agree to the byte).

## Interpretation — Δ decomposition (R2)

**Trace symmetry.** `trace_core == trace_control == 1` (UPLC table), so the
`trace` builtin (from `expect` desugaring — a dead branch, never executed at
runtime) **cancels exactly** in `core − control`. **Δ is therefore free of
trace-asymmetry artifacts.**

**Decomposition of Δ = +160,000:**

| Component of Δ | CPU |
|---|---|
| trace-asymmetry cost (`trace_core` − `trace_control` = 0) | 0 |
| genuine cross-structure CEK | +160,000 |

The full +160,000 is **cross-structure CEK**: the CEK machine threads the
composite as a single continuation chain (~31 `let` bindings + 3 `expect`s)
rather than three separate chains, and the additional inter-sequence threading
that does not cancel against the (also-concatenated) control is +160,000 steps
(+0.0057 %). It is **positive** (one long chain costs marginally more than three
short ones).

**Nuance (honest accounting).** The PRIMARY target carries M2-real's *standalone*
marginal, which itself included a dead-branch `trace` asymmetry (M2 core had 0
`trace`, M2 control had 1 — see M2-report). M5's composite, by contrast, cancels
its BLS-portion `trace` (1 == 1). Because `expect` traces are dead branches with
~0 runtime cost — empirically: M3 vs M4 controls (7 vs 8 `expect`s) were
byte-identical at 53,108,222 — this structural difference contributes
negligibly; the +160,000 is dominated by genuine cross-structure CEK. This is a
**candidate calibration note for Phase 4 projection** (a ~+0.006 % additive
correction when summing component costs), **not** a change to any thesis figure
or component measurement.

## Memory

Max reported memory is `bench_m5_core` at **13,678** units — **0.083 %** of the
16,500,000 transaction budget. Marginal mem 10,030. The full regular crypto+MSM
sequence is comfortably within the memory limit (M8).

## Result

- **H₀ (additivity) holds**: composite marginal 2,829,077,091 vs target
  2,828,917,091, Δ = **+160,000 (+0.0057 %)**, ~8.8× inside the ±0.05 % band.
- **All commit gates passed**: operation counts = union, `trace` symmetric,
  |Δ%| ≤ 0.05 %.
- The regular Phase A crypto+MSM cost is **additive** in its three components;
  summation is a sound first-order projection model for Phase 4, with a small
  (+160,000) cross-structure-CEK correction.
- This is the crypto+MSM **floor**; Phase 4 adds the script/state overhead
  (`Phase4_total − M5`).

## Raw output

See `benchmarks/raw/phase-1-cost-model/M5-raw.log`.
