# M1b — Realistic On-Chain Groth16 Sequence (4 Miller Loops)

Phase 1, measurement M1b. Empirical confirmation of discrepancy **D1**
(`docs/records.md`): a realizable on-chain Groth16 verifier on Cardano
requires a **4th** miller loop relative to thesis Table 2's 3-miller-loop
figure, because CIP-381 deliberately omits `MlResult` serialization.

## Background

Thesis Table 2 (§3.2.2) budgets **3 × millerLoop** for the Groth16
verification core (the M1 scenario, empirically validated in
`M1-groth16-sequence.md`: marginal = 1,100,648,609, Δ = +0.04 %).

Per D1, that undercounts the realizable on-chain cost. The verification
equation's `e(α,β)` term is conventionally precomputed off-chain and bundled
with the verification key as a serialized GT/`MlResult` element. CIP-381 [13]
provides **no `MlResult` serialization builtin** (a deliberate design choice —
see D1 for the CIP ecosystem context), so `e(α,β)` cannot be supplied
precomputed via datum/redeemer. An on-chain verifier must reconstruct it from
`α ∈ G1`, `β ∈ G2` (in the vk), adding a **4th miller loop**. M1b measures
that realistic sequence:

```
4 × bls12_381_miller_loop + 2 × bls12_381_mul_miller_loop_result
  + 1 × bls12_381_final_verify
```

## Hypotheses

**Standalone (M1b vs its own sum-of-parts):**
- **H₀**: marginal_M1b = Σ_M1b = 1,354,222,882 (CEK charges the sum-of-parts).
- **H₁**: marginal_M1b > Σ_M1b (measurable CEK overhead Δ_M1b).

**Cross-hypothesis (D1 confirmation):**
- `increment = marginal_M1b − marginal_M1` equals exactly **one miller loop**
  (254,006,273) to within a small CEK noise floor.

Decision rule: `|Δ%| < 1 %` confirms sum-of-parts; D1 is confirmed if
`increment ≈ 254,006,273` within 1 %.

## Configuration

Identical to M1 (`M1-groth16-sequence.md`):

- **Aiken**: v1.1.22+39d6b04 — **Plutus**: V3 (Conway)
- **Hardware**: WSL2 Ubuntu 24.04, Intel i7-9750H @ 2.60GHz (6c/12t),
  8,068,188 kB MemTotal; kernel 6.6.114.1-microsoft-standard-WSL2 x86_64
- **Command** (from `validator/`): `aiken check --seed 42`
- **Determinism**: 3 iterations byte-identical (md5
  `5b6b9d4683ccfbddcc1d18ad791c5ac8` ×3)
- **Erratum (2026-05-29, doc hygiene — no measured value changed).** This md5
  was captured when the project contained only `m1_groth16.ak` — a **3-test**
  suite (`{core, m1b, control}`) — so bare `aiken check --seed 42` hashed those
  3 tests. The suite has since grown to **14 tests**, and the same bare command
  now emits a 14-test JSON (md5 `ecd3c1232a4407eb391f68f4a11cebeb`). All
  per-test cpu/mem reproduce to the byte. The original 3-test hash is recovered
  exactly (3× byte-identical, verified 2026-05-29) via the (substring, G7)
  `aiken check -m bench_m1 --seed 42`, or — growth-robust — the exact-match
  command `aiken check -e -m bench_m1_groth16_core -m
  bench_m1b_groth16_realistic -m bench_m1_control_setup --seed 42` →
  `5b6b9d4683ccfbddcc1d18ad791c5ac8`.
- **Control**: the same `bench_m1_control_setup` as M1 (two `uncompress`
  calls and nothing else, UPLC-verified), reused unchanged.

Implementation note: `bench_m1b_groth16_realistic` is a **`fail`** test whose
body is the literal `final_verify(combined2, ml4)`, where `ml4` is the 4th
miller loop standing in for the reconstructed `e(α,β)`. On mock generator
points the equation does not hold (`combined2 = e(g1,g2)³ ≠ ml4 = e(g1,g2)`),
so `final_verify` returns `False` — the expected outcome on arbitrary points,
so the `fail` test passes. `final_verify`'s cost is input-independent, so the
measured cost equals that of a genuine verification.

## Measured

Deterministic — all three trials identical (cpu/mem).

| Test | Trial | Reported CPU | Reported Memory |
|---|---|---|---|
| `bench_m1_groth16_core` (3-ML) | 1–3 | 1,228,471,303 | 4,315 |
| `bench_m1b_groth16_realistic` (4-ML) | 1 | 1,482,493,576 | 4,487 |
| `bench_m1b_groth16_realistic` (4-ML) | 2 | 1,482,493,576 | 4,487 |
| `bench_m1b_groth16_realistic` (4-ML) | 3 | 1,482,493,576 | 4,487 |
| `bench_m1b_groth16_realistic` | **Mean** | **1,482,493,576** | **4,487** |
| `bench_m1_control_setup` | 1–3 | 127,822,694 | 1,254 |

**Isolated costs** (`core − control`):

| Quantity | CPU |
|---|---|
| marginal_M1 (3-ML, reference) | 1,100,648,609 |
| **marginal_M1b (4-ML)** | **1,354,670,882** |

## Theoretical (sum-of-parts), M1b

| Builtin call | Cost (CPU steps) |
|---|---|
| 4 × `miller_loop` (254,006,273 each) | 1,016,025,092 |
| 2 × `mul_miller_loop_result` (2,174,038 each) | 4,348,076 |
| 1 × `final_verify` | 333,849,714 |
| **Σ_M1b (sum-of-parts)** | **1,354,222,882** |

## Delta (M1b standalone)

- Δ_M1b = marginal_M1b − Σ_M1b = 1,354,670,882 − 1,354,222,882 = **+448,000**
- Δ%_M1b = +448,000 / 1,354,222,882 × 100 = **+0.0331 %**
- |Δ%_M1b| < 1 % → **H₀ holds.** The +448,000 is CEK threading overhead for
  the six `let` bindings (one more than M1's five — the `ml4` binding).

## Cross-check (D1 confirmation)

| Quantity | CPU steps |
|---|---|
| marginal_M1b (4-ML) | 1,354,670,882 |
| marginal_M1 (3-ML) | 1,100,648,609 |
| **increment** | **254,022,273** |
| one `miller_loop` (cost model) | 254,006,273 |
| increment − one ML | **16,000** (0.0063 % of one ML) |

The incremental cost of going from 3 to 4 miller loops is **254,022,273** CPU
steps — within **0.0063 %** of one miller loop's cost-model value
(254,006,273). The 16,000-step excess is the CEK threading of the additional
`let ml4` binding, and equals `Δ_M1b − Δ_M1` exactly (448,000 − 432,000),
confirming internal consistency. **D1 is confirmed empirically.**

## Implication

D1 is confirmed: a realizable on-chain Groth16 verifier costs one extra miller
loop (~254 M CPU steps) over the thesis Table 2 figure, because `e(α,β)`
cannot be passed precomputed under CIP-381 and must be reconstructed on-chain.
Updated Phase A projections (adding ~254 M to the Groth16 portion):

| Phase A path | Thesis Table 2 | D1-corrected (M1b) | Per-tx limit | Headroom |
|---|---|---|---|---|
| Regular | ~3.08 B | **~3.33 B** | 10 B | ~66.7 % |
| Boundary | ~3.17 B | **~3.42 B** | 10 B | ~65.8 % |

Both corrected totals remain well within the 10,000,000,000 CPU-step
per-transaction limit. The correction does not threaten feasibility; it
refines the budget upward by ~8 %. (These totals still carry the unmeasured
~500 M "script overhead" placeholder, which Phase 4 measures directly.)

## Raw output

See `benchmarks/raw/phase-1-cost-model/M1b-raw.log`.
