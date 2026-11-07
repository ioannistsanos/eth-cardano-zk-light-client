# M6 — Synthetic Phase A Boundary (Groth16 + BLS-real + MSM-7) Additivity

Phase 1, measurement M6. Empirical CPU/memory cost of the **composite** of the
three **boundary**-Phase-A cryptographic sequences run in ONE Plutus V3 script,
and whether they compose **additively** with the three independently-measured
component marginals (M1b, M2-real, **M4 MSM-7**). Boundary twin of M5.

See `docs/phase1-methodology.md`, `docs/records.md` (D1, D2, D3),
`benchmarks/phase-1-cost-model/M5-report.md`, and `docs/aiken-gotchas.md`
(G5, G6, G7).

## Scope (what M6 is and is NOT)

M6 measures **only the cryptographic + MSM portion** of a boundary Phase A
transaction:

- Groth16 verify — D1 4-miller-loop on-chain form (M1b) — **unchanged vs regular**.
- BLS aggregate verify — D2 canonical no-mul form (M2-real) — **unchanged vs regular**.
- MSM-7 (M4): 7×`g1_scalar_mul` + 7×`g1_add` (boundary = regular 6 + `new_committee_id`).

The number of pairings is independent of public-input count, so **boundary −
regular at this layer is exactly one extra `scalar_mul` + one extra `g1_add`** —
the 7th MSM term.

M6 **deliberately EXCLUDES** datum/redeemer deserialization, anchor-invariance,
state-thread NFT continuity, and the datum write — measured on a real boundary
tx in **Phase 4**. `Phase4_boundary_total − M6` is the empirical boundary
"script overhead"; **M6 does not measure it**.

## Decision record — BLS uses the D2 (no-mul) form

Same as M5/regular: the BLS sub-sequence is the canonical CIP-381
`final_verify(ml1, ml2)` form (D2) — what the real validator runs — **−2,174,038
CPU** vs the thesis Table-2 product form. See `docs/records.md` D2.

## Configuration

- **Aiken**: v1.1.22+39d6b04 — **Plutus**: V3 (Conway)
- **Hardware**: WSL2 Ubuntu 24.04, Intel i7-9750H @ 2.60 GHz (6c/12t),
  8,068,188 kB MemTotal; kernel 6.6.114.1-microsoft-standard-WSL2 x86_64
- **Command** (from `validator/`, **G7 exact-match**):
  `aiken check -e -m bench_m6_core -m bench_m6_control --seed 42`
- **Determinism**: 3 iterations byte-identical (md5
  `e82cc659716f97d1910fafe0e890993b` ×3). Deterministic (cost model, not wall-clock).
- **Dependencies**: none (BLS builtins from `aiken/builtin` prelude).

## Method note — faithful concatenation + barrier-control subtraction

`bench_m6_core` is a faithful **concatenation** of the three boundary component
cores (M1b core + M2-real core + **M4 MSM-7 core**), sharing no computed values.
`bench_m6_control` performs the **union of the shared setup** — 4×`G1_uncompress`
+ 2×`G2_uncompress` + 1×`sha2_256` — plus the same const references (`bls_dst`,
the **seven** scalars), and **none** of the operation builtins. So:

    marginal = bench_m6_core − bench_m6_control

isolates exactly the union of operation builtins (+ their per-builtin CEK).

**G6**: the BLS message is derived at runtime via `sha2_256(preimage)`, so
`hash_to_group` is not constant-folded (`aiken export` of the mirrors succeeded).
Keep-alive idiom: both core and control use `expect _ = x` (G5) — core forces the
three sub-chain results (`g_ok`, `b_ok`, `m_acc7`), control forces the seven setup
values + const references. This makes `trace` symmetric (below).

## UPLC verification (temp `pub fn` mirrors, exported + decoded, then removed)

Mirrors `pf_m6_core` / `pf_m6_control` were appended, exported via
`aiken export -m benchmarks/m6_phase_a_boundary -n <fn>`, decoded via
`aiken uplc decode --cbor --hex`, builtins counted, then **removed** before commit
(`grep 'pub fn pf_m6'` → none).

| Builtin | `pf_m6_core` | `pf_m6_control` | role |
|---|---|---|---|
| `bls12_381_millerLoop` | **6** | 0 | 4 Groth16 (incl. D1 4th-ML) + 2 BLS |
| `bls12_381_mulMlResult` | **2** | 0 | Groth16 LHS product |
| `bls12_381_finalVerify` | **2** | 0 | 1 Groth16 + 1 BLS |
| `bls12_381_G2_hashToGroup` | **1** | 0 | BLS H(m) |
| `bls12_381_G1_scalarMul` | **7** | 0 | MSM pubᵢ·IC[i] (7 = boundary) |
| `bls12_381_G1_add` | **7** | 0 | MSM accumulation (7) |
| `bls12_381_G1_uncompress` | 4 | 4 | shared setup → cancels |
| `bls12_381_G2_uncompress` | 2 | 2 | shared setup → cancels |
| `sha2_256` | 1 | 1 | shared setup → cancels |
| `trace` | **1** | **1** | `expect` desugar (dead branch) |

Operation builtins (top six rows) appear in core at exactly the **union** counts
and are **absent** from control. **`trace_core` (1) == `trace_control` (1) → trace
symmetric, cancels in the marginal.**

## Hypothesis — additivity H₀ (locked before measurement)

- **PRIMARY target** = sum of the three MEASURED component marginals:
  `1,354,670,882 (M1b) + 1,008,845,331 (M2-real) + 542,959,691 (M4 MSM-7) =
  2,906,475,904`.
- **H₀**: `|marginal − 2,906,475,904| / 2,906,475,904 ≤ 0.05 %` (band **±1,453,238**).
- `Δ = marginal − 2,906,475,904` (signed) is the **result of interest** = cross-
  structure CEK of running the three sequences in one continuation chain.

## Measured

Deterministic — all three trials identical.

| Test | Reported CPU | Reported Memory |
|---|---|---|
| `bench_m6_core` | 3,268,820,792 | 14,514 |
| `bench_m6_control` | 362,184,888 | 3,648 |
| **marginal (core − control)** | **2,906,635,904** | **10,866** |

## Additivity table (PRIMARY)

| Component (form) | Measured marginal (standalone) | source |
|---|---|---|
| Groth16 — M1b (D1, 4-ML) | 1,354,670,882 | M1b-report |
| BLS — M2-real (D2, no-mul) | 1,008,845,331 | M2-report |
| **MSM-7 — M4** | **542,959,691** | M4-report |
| **Σ component marginals (target)** | **2,906,475,904** | |
| **M6 composite marginal (measured)** | **2,906,635,904** | this report |
| **Δ = composite − Σ** | **+160,000** | |
| **Δ%** | **+0.005505 %** | |
| **H₀ (±0.05 %)** | ✅ **holds** (~9× inside band) | |

The three crypto sequences compose **additively** at the boundary: composite
marginal exceeds the sum of standalone marginals by **+160,000 CPU steps
(+0.0055 %)** — **identical to M5's +160,000** (see tertiary). Phase A boundary
crypto+MSM cost can be projected by **summation** with the same small additive
correction.

## Secondary cross-check (CEK transparency)

Cost-model **pure-builtin** sum (no CEK), from M6's verified builtin counts:

| Builtin | count × unit cost | subtotal |
|---|---|---|
| `miller_loop` | 6 × 254,006,273 | 1,524,037,638 |
| `mul_miller_loop_result` | 2 × 2,174,038 | 4,348,076 |
| `final_verify` | 2 × 333,849,714 | 667,699,428 |
| `hash_to_group` (n=32) | 166,917,843 + 4,307·32 | 167,055,667 |
| `g1_scalar_mul` (n=4) | 7 × (76,433,006 + 8,868·4) | 535,279,346 |
| `g1_add` | 7 × 962,335 | 6,736,345 |
| **Σ (cost-model, no CEK)** | | **2,905,156,500** |

| Quantity | CPU |
|---|---|
| M6 composite marginal | 2,906,635,904 |
| Cost-model pure-builtin sum | 2,905,156,500 |
| **marginal − cost-model = total CEK in M6** | **+1,479,404** |
| Expected aggregate per-builtin CEK (M1b+M2-real+M4) | +1,319,404 |
| ↳ +448,000 (M1b) − 72,596 (M2-real) + **944,000 (M4)** | |
| **Residual = cross-structure CEK** | **+160,000** |

**Note on M4's CEK = 944,000** (not `7×136,000 = 952,000`): `542,959,691 −
542,015,691 = 944,000 = 952,000 − 8,000`, where the −8,000 is the reproducible M4
6→7-input offset (M4-report), already inside the measured M4 marginal. M6's total
CEK (+1,479,404) = aggregate per-builtin CEK (+1,319,404) + cross-structure CEK
(+160,000) — both cross-checks agree to the byte.

## Tertiary cross-check (two measured composites)

Since Groth16 and BLS are byte-identical between regular (M5) and boundary (M6),
the difference of the two **measured** composite marginals must equal the
difference of the two **measured** standalone MSM marginals:

| Quantity | CPU |
|---|---|
| `M6_marginal − M5_marginal` = 2,906,635,904 − 2,829,077,091 | **77,558,813** |
| `M4_marginal − M3_marginal` = 542,959,691 − 465,400,878 | **77,558,813** |
| **delta-of-deltas** | **0** |

**Exact to the byte.** Boundary − regular at the crypto+MSM layer is **exactly the
7th MSM term** (one `scalar_mul` + one `g1_add`, with their per-builtin CEK and
the M4 −8,000 offset). The cross-structure CEK (+160,000) is identical in M5 and
M6 and therefore cancels in `M6 − M5`.

## Interpretation — Δ decomposition

**Trace symmetry.** `trace_core == trace_control == 1` (UPLC table), so the `trace`
builtin (dead `expect` branch) **cancels exactly** in `core − control`. **Δ is
free of trace-asymmetry artifacts.**

| Component of Δ | CPU |
|---|---|
| trace-asymmetry cost (`trace_core` − `trace_control` = 0) | 0 |
| genuine cross-structure CEK | +160,000 |

The full +160,000 is **cross-structure CEK** — the same value M5 measured, as the
tertiary delta-of-deltas = 0 confirms. Positive (one long continuation chain costs
marginally more than three short ones); +0.0055 %.

## Memory

Max reported memory is `bench_m6_core` at **14,514** units — **0.088 %** of the
16,500,000 transaction budget. Marginal mem 10,866. The full boundary crypto+MSM
sequence is comfortably within the memory limit (M8).

## Result

- **H₀ (additivity) holds**: composite marginal 2,906,635,904 vs target
  2,906,475,904, Δ = **+160,000 (+0.0055 %)**, ~9× inside the ±0.05 % band.
- **All commit gates passed**: operation counts = union, `trace` symmetric,
  |Δ%| ≤ 0.05 %.
- **Tertiary exact**: `M6 − M5 = M4 − M3 = 77,558,813` (delta-of-deltas 0) —
  boundary − regular = exactly the 7th MSM term.
- The boundary Phase A crypto+MSM cost is **additive**; summation is a sound
  first-order projection (same +160,000 cross-structure-CEK correction as regular).
- This is the boundary crypto+MSM **floor**; Phase 4 adds the script/state
  overhead (`Phase4_boundary − M6`).

## Raw output

See `benchmarks/raw/phase-1-cost-model/M6-raw.log`.
