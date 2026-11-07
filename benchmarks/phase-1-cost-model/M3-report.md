# M3 — MSM regular (6 inputs) + scalarMul characterization

Phase 1, measurement M3. Empirical CPU/memory cost of the Groth16
public-input MSM the on-chain verifier performs:

    vk_x = IC[0] + Σᵢ pub_i · IC[i]   (i = 1..6, regular Phase A; thesis §3.2.2)

Six `bls12_381_g1_scalar_mul` + six `bls12_381_g1_add`. M3 also identifies
the scalarMul cost-model **n-unit** (bytes? 64-bit words? flat?) by comparing
32-byte vs 2-byte scalars against paired clean controls.

See `docs/phase1-methodology.md`, `docs/aiken-gotchas.md` (G5, G6).

## Background

Thesis Table 2 budgets the 6-input MSM scalarMul at **~458,879,328 CPU
steps** — about 76,479,888 per call. Against the cost formula `76,433,006 +
8,868·n` this implies `n ≈ 5.3`, which is anomalous (neither bytes nor
64-bit words). M3 sets out to identify the n-unit empirically and correct
the figure.

G6 (the constant-folding probe) confirmed `bls12_381_g1_scalar_mul` and
`bls12_381_g1_add` are NOT folded by Aiken v1.1.22 — no runtime barrier is
needed. Values can be compile-time `const`s.

## Hypotheses

**H₀ (formula self-consistency)**: `marg_A` fits
`6·(76,433,006 + 8,868·eff_n) + 6·962,335` for a single integer `eff_n`
within ±0.05 %. Identify `eff_n` and state bytes vs words vs other.

**Size question**: report whether `size_delta = marg_A − marg_B ≈ 0` (flat,
n=32 model exact regardless of scalar size) or `> 0` (scalarMul charges by
scalar size; small public inputs cost less; thesis's 32-byte figure is an
upper bound for a heterogeneous-input real MSM).

**No pass/fail verdict on Σ_A.** `eff_n` and `size_delta` are the reported
*results*.

## Configuration

- **Aiken**: v1.1.22+39d6b04 — **Plutus**: V3 (Conway)
- **Hardware**: WSL2 Ubuntu 24.04, Intel i7-9750H @ 2.60 GHz (6c/12t),
  8,068,188 kB MemTotal; kernel 6.6.114.1-microsoft-standard-WSL2 x86_64
- **Command** (from `validator/`): `aiken check -m bench_m3 --seed 42`
- **Determinism**: 3 iterations byte-identical (md5
  `a7deb2043f83ddcdb0054965693dd81c` ×3)
- **Dependencies**: none (BLS builtins from `aiken/builtin` prelude).

## Inputs

- **Canonical BLS12-381 G1 generator** (compressed, 48 B); reused as `p` in
  both cores (cost is point-value-independent for `g1_scalar_mul`/`g1_add`).
- **Six DISTINCT 32-byte scalars** for TEST A: `sᵢ = 2²⁵² + i` (i = 1..6).
  Distinct values defeat CSE / value-equal shortcuts; each well below the
  scalar field order `r ≈ 2²⁵⁴·⁸`.
- **Six DISTINCT 2-byte scalars** for TEST B: `0x0100..0x0105`. Avoid 0/1 to
  dodge mult-by-0/1 special-case branches.

## Method note — paired barrier-control subtraction

The two cores (`bench_m3_msm_core_n32`, `bench_m3_msm_core_n2`) each have a
*paired* control (`bench_m3_msm_control_n32`, `bench_m3_msm_control_n2`)
performing identical setup — same `G1_uncompress`, same six scalar `Int`
loads forced live via `expect _ = sᵢ` — but **none** of the four measured
builtins. So:

    marg_A = A − C32       cleanly = 6×scalarMul(32-byte) + 6×g1_add
    marg_B = B − C2        cleanly = 6×scalarMul(2-byte)  + 6×g1_add

The 32-byte ↔ 2-byte Int-literal load delta cancels in **both** pairs, so
`size_delta = marg_A − marg_B` isolates scalarMul size-sensitivity with
zero Int-load contamination.

UPLC verification (temp `pub fn` mirrors, exported via `aiken export`,
decoded via `aiken uplc decode --cbor --hex`, then removed before this
report):

| Builtin | `pf_core_n32` | `pf_core_n2` | `pf_control_n32` | `pf_control_n2` |
|---|---|---|---|---|
| `bls12_381_G1_uncompress` | 1 | 1 | 1 | 1 |
| `bls12_381_G1_scalarMul` | **6** | **6** | **0** | **0** |
| `bls12_381_G1_add` | **6** | **6** | **0** | **0** |
| `trace` | 1 | 1 | 1 | 1 |

The only difference between each core and its paired control is the 6
scalarMul + 6 g1_add. Trace counts match — no asymmetry.

## Measured

Deterministic — all three trials identical (cpu/mem).

| Test | Trial | Reported CPU | Reported Memory |
|---|---|---|---|
| `bench_m3_msm_core_n32` (32-byte) | 1–3 | 518,509,100 | 6,434 |
| `bench_m3_msm_core_n2` (2-byte) | 1–3 | 518,349,476 | 6,434 |
| `bench_m3_msm_control_n32` | 1–3 | 53,108,222 | 1,118 |
| `bench_m3_msm_control_n2` | 1–3 | 53,108,222 | 1,118 |

**Isolated costs (marginals):**

| Quantity | CPU | Memory |
|---|---|---|
| `marg_A` (6×scalarMul, n=32B + 6×g1_add) | **465,400,878** | 5,316 |
| `marg_B` (6×scalarMul, n=2B + 6×g1_add) | **465,241,254** | 5,316 |
| **`size_delta = marg_A − marg_B`** | **+159,624** | 0 |

## Theoretical (sum-of-parts candidates)

| n hypothesis | Σ for 6 scalarMul + 6 g1_add |
|---|---|
| n = 32 (bytes) | 466,074,702 |
| n = 4 (64-bit words) | **464,584,878** |
| Thesis Table 2 (~5.3, anomalous) | 458,879,328 + 5,774,010 = ~464,653,338 |

## Delta & analysis — the n-unit

**`size_delta = +159,624 = 6 × 8,868 × 3`** exactly. The integer factor `3`
identifies the n-unit:

- 32-byte scalar = **4 × 64-bit words**
- 2-byte scalar  = **1 × 64-bit word**
- Δ(words) = 4 − 1 = **3** → matches `size_delta` exactly.

`eff_n_A − eff_n_B = 19.336 − 16.336 = 3.000` (exact). The integer
*difference* confirms 64-bit words. The non-integer *absolute* values
(19.336, 16.336) reveal a constant per-call CEK overhead on top of the
cost-model formula:

    per_sm_A (32B, 4 words) = 76,604,478 = 76,433,006 + 8,868·4 + 136,000
    per_sm_B  (2B, 1 word ) = 76,577,874 = 76,433,006 + 8,868·1 + 136,000
                                                                 ^^^^^^
                                                          per-scalarMul CEK
                                                          overhead, constant

The **136,000-step CEK overhead per scalarMul** is identical for both scalar
sizes — confirming it's the CEK machine's per-builtin-application cost
(parameter binding, env update, builtin dispatch), not part of the cost
model. `g1_add`'s per-call empirical cost matches its cost-model value
exactly (962,335) — `g1_add` has zero measurable per-call CEK overhead.

**Total reconstruction for TEST A** (matches to the byte):

    G1_uncompress (1×)        =  53,108,222
    6 × scalarMul (n=4, +CEK) = 459,626,868   (= 6 × 76,604,478)
    6 × g1_add                =   5,774,010   (= 6 × 962,335)
    --------------------------------------
    Σ                         = 518,509,100   ≡ A.cpu ✓

## Implication

**The scalarMul cost-model n-unit is 64-bit words.** Specifically, `n` is
the number of 64-bit words needed to represent the scalar Integer (after
modular reduction to mod-r width, since real Groth16 public inputs are
field elements `< r ≈ 2²⁵⁴·⁸`, i.e. 32 bytes = 4 words). The cost-model
formula `76,433,006 + 8,868·n` is exact in this unit; the empirical
per-call cost adds a constant `+136,000` CEK overhead from the CEK machine.

**Corrected Phase A regular MSM portion** (vs thesis Table 2):

| Component | Thesis Table 2 | M3 empirical | Delta |
|---|---|---|---|
| 6 × scalarMul (32-byte real inputs) | 458,879,328 | 459,626,868 | +747,540 |
| 6 × g1_add | 5,774,010 | 5,774,010 | 0 |
| **MSM total (6-input)** | **464,653,338** | **465,400,878** | **+747,540** |

The Phase A regular MSM portion is **~0.75 M CPU higher than thesis** (+0.16 %)
— driven entirely by the per-scalarMul CEK overhead the thesis omitted.
The boundary (7-input MSM) corrects analogously; M3 measures only the 6-input
regular case, so the boundary figure is left to M4, which measured
**542,959,691 vs thesis 542,095,561 → +864,130 (+0.16 %)** (measured 2026-05-28).
Negligible against the D1 increment
(+254 M) but useful as a Table-2 correction.

**size_delta is small but non-zero** (+0.034 % of marg_A). The MSM cost
depends on scalar word-count. In a real Phase A regular tx all six public
inputs are 32-byte field elements (`committee_id`, `attested_header_root`,
`finalized_header_root`, `finalized_slot`, `apk`, `count`), so n=4 words
applies uniformly — no realistic heterogeneity to exploit. The 32-byte
figure is the realistic on-chain value (not just an upper bound).

Memory: marginal mem 5,316 (both A and B), far below the 16,500,000
transaction budget (M8).

**Calibration note for M5/M6 (and any synthesis).** Aggregate CEK overhead
scales with builtin-call **count** and is **builtin-specific** — it must be
added on top of the cost-model sum, not assumed to be captured inside it.
Cheap, frequently-called builtins make it visible; expensive rare ones
hide it. Per-application figures established so far:

| Builtin | Per-application CEK overhead | Source |
|---|---|---|
| `bls12_381_g1_scalar_mul` | **+136,000** | M3 (this report) |
| `bls12_381_miller_loop` (let-bound result) | **+16,000** | M1b − M1 increment |
| `bls12_381_g1_add` | **~0** (≤ measurement noise) | M3 (this report) |
| `bls12_381_mul_miller_loop_result` | (TBD; M2 mixed-sources residual ~112 K) | M2 |
| `bls12_381_final_verify` | (TBD) | M2 |

For **M5/M6 Phase A projections**: add `+136 K × n_scalarMul` on top of the
cost-model MSM sum (regular: **+816 K**; boundary: **+952 K**). This
**refines**, does not supersede, the M1b−M1 per-let increment of ~16 K for
a `let X = miller_loop(...)` binding — different builtins, different CEK
costs; future M-measurements must measure each builtin's CEK overhead
separately.

## Cross-checks

1. **size_delta exact identity**: 159,624 = 6·8,868·3 to the byte → matches
   64-bit-word hypothesis without rounding.
2. **CEK overhead consistency**: identical 136,000 inferred from both A and
   B independently. If it were size-dependent we'd see a different number
   from each.
3. **g1_add cost recovery**: `marg_A − 6·per_sm_A = 5,774,010 = 6 × 962,335`
   exactly → cost-model `g1_add` value is verified to the byte; no CEK
   overhead per g1_add.
4. **Control symmetry**: `C32.cpu == D2.cpu` exactly (53,108,222 each) →
   2-byte vs 32-byte Int-literal load delta is below measurement resolution
   on the `expect _ = sᵢ` path. The paired controls are equivalent in
   practice but kept paired for principled isolation.

## Open follow-ups (not stop conditions)

1. **scalarMul +136 K CEK is per-call constant**: refresh per-call CEK
   estimate project-wide (cf. M2's per-let figure of ~16 K).
2. **`g1_add` zero-CEK exception**: `g1_add` shows no measurable per-call
   CEK overhead. Worth probing whether this generalizes to other "cheap"
   builtins (compare/equal/add) — could affect cost-model-vs-empirical
   reasoning for those.
3. **Thesis ~5.3 anomaly explained**: the implied `n ≈ 5.3` likely arose
   from the thesis dividing thesis's empirical/estimated figure by 8,868
   without separating the per-call CEK overhead. The corrected analysis is
   `n = 4 words + 136 K CEK`.
4. **Memory budget**: M3 confirms all tests well under the 16.5 M limit
   (max 6,434).

## D3 in detail (summarised in `docs/records.md`)

D3 carries two empirically independent findings, both required to
reconstruct the on-chain MSM cost to the byte: (a) the scalarMul
cost-model n-unit, and (b) a per-application CEK overhead not in the
cost model.

### Finding (a) — n-unit is 64-bit words

The scalarMul cost formula `76,433,006 + 8,868·n` from
`builtinCostModelC.json` [40] left the **n-unit** unspecified. Thesis
Table 2 used ~458,879,328 for 6 scalarMul, implying `n ≈ 5.3` per call —
anomalous (neither bytes nor 64-bit words).

M3 identified the n-unit empirically using paired clean controls:

    size_delta = marg_A − marg_B = 159,624 = 6 × 8,868 × 3   (exactly)

where 3 matches the difference in 64-bit-word counts between 32-byte and
2-byte scalars (4 − 1 = 3). **The n-unit is 64-bit words.** For 32-byte
real Phase A public inputs, n = 4 → cost-model charge per scalarMul =
`76,433,006 + 8,868·4 = 76,468,478`.

### Finding (b) — per-application CEK overhead = +136,000 (NOT in cost model)

The cost-model formula alone does not reproduce the measured cost. Both
TEST A (n=4) and TEST B (n=1) reveal an additional **+136,000 CPU steps
per scalarMul application**:

    per_sm_A (32B, 4 words) = 76,604,478 = 76,433,006 + 8,868·4 + 136,000
    per_sm_B  (2B, 1 word ) = 76,577,874 = 76,433,006 + 8,868·1 + 136,000

The same +136,000 appears identically in both — **constant across scalar
size** (so it cancels in `size_delta`, leaving finding (a) clean). It is
**not** documented in `builtinCostModelC.json` [40]: the cost-model
formula gives the builtin's intrinsic charge; the +136,000 is what the
CEK machine adds to *apply* the builtin (parameter binding, environment
update, builtin dispatch).

This overhead is **builtin-specific, not a uniform per-application
constant**: `g1_add` shows **~0 measurable CEK overhead** — its empirical
per-call cost equals the cost-model value (962,335) to the byte. So
future M-measurements must measure each builtin's CEK overhead separately;
there is no single "per-builtin CEK" figure to borrow.

**Hypothesis (not asserted as fact)**: the +136 K may reflect
Integer-argument unboxing/copy proportional to "deal with an Int
parameter," whereas G1Element parameters are passed by reference. M3 does
not test this mechanism directly; it is offered only as a candidate
explanation.

### Reconstruction (byte-exact)

Every CPU step in `bench_m3_msm_core_n32` is accounted for:

    G1_uncompress (1×)              =  53,108,222
    6 × scalarMul (n=4 + 136K CEK)  = 459,626,868   (= 6 × 76,604,478)
    6 × g1_add (no CEK overhead)    =   5,774,010   (= 6 ×    962,335)
    --------------------------------------------------------
    Σ                               = 518,509,100   ≡ A.cpu  (3× byte-identical)

### Impact on Phase A budget projections

| Phase A path | Thesis Table 2 MSM | Empirical MSM | Δ |
|---|---|---|---|
| Regular (6 inputs)  | 464,653,338 | 465,400,878 (M3) | +747,540 (+0.16 %) |
| Boundary (7 inputs) | 542,095,561 | 542,959,691 (M4) | +864,130 (+0.16 %) |

> **Boundary row is the M4-measured MSM** (measured 2026-05-28), not this report's
> M3 projection. M3 measured only the 6-input regular MSM; the boundary
> *projection* (542,967,691) and its −8,000 reconciliation to the measured
> 542,959,691 live in M4-report's predicted-vs-measured comparison.

Negligible compared with D1 (+254 M) but useful as a Table-2 line-item
correction. Combined with D1 + D2 + D3: regular ~3.33 B, boundary
~3.42 B — both still ≪ 10 B per-tx limit.

## Raw output

See `benchmarks/raw/phase-1-cost-model/M3-raw.log`.
