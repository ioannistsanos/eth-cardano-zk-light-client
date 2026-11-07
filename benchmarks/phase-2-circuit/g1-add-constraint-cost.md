# Phase 2a-1 — Non-native BLS12-381 G1-add R1CS constraint cost

## 1. Scope
Empirical R1CS constraint cost of **one** non-native (emulated) BLS12-381 G1 point
addition — the dominant cost of the real circuit's operations 1 & 2 (512+512
additions). Confirms/refutes the thesis §2.1.3 estimate of **~10–20K constraints
per addition**. Method: compile-only constraint counts (`frontend.Compile` →
`GetNbConstraints`) + linear regression over N independent additions. **NOT** a
proving benchmark (no Setup/Prove except the one functional check in §6).

## 2. Setup
- gnark **v0.13.0**, gnark-crypto **v0.18.0**, go1.23.6, `GOTOOLCHAIN=local`.
- Gadget: `sw_emulated.Curve` for BLS12-381 —
  `New[emulated.BLS12381Fp, emulated.BLS12381Fr](api, GetBLS12381Params())`; point
  type `sw_bls12381.G1Affine` (the same path gnark itself uses, `pairing.go:60`).
- **Native compile field: `ecc.BLS12_381.ScalarField()`** (matches the real
  Groth16/BLS12-381 circuit), NOT the examples' BN254 default.
- Both add methods: `curve.Add` (incomplete/"unsafe") and `curve.AddUnified`
  (complete; handles equal / inverse / infinity).
- Design: **N independent pairs** `R_i = A_i + B_i` (no accumulator, no chain).
  `A_i,B_i` are secret witnesses → adds cannot be constant-folded; values are
  irrelevant to the count (compile is value-independent), so no witness is assigned.
- Each (method, N) compiled **×2**; counts identical (deterministic) — confirmed
  across 3 independent program runs. Box: 7.7 GiB RAM, 12 CPU.
- **N capped at 200** (not 512): a memory failure is not a clean cap, so the
  measured points are fixed up front; 512 is projected from the slope. (The fear
  was moot anyway — see §7 — because the per-add cost is ~10× below the estimate,
  so N=200 was only ~251K constraints / ~3 s.)

## 3. Raw table (each count ×2-stable)
| method | N | constraints |
|---|---:|---:|
| Add | 1 | 1,022 |
| Add | 2 | 1,776 |
| Add | 10 | 7,807 |
| Add | 50 | 35,848 |
| Add | 100 | 68,772 |
| Add | 200 | 129,312 |
| AddUnified | 1 | 1,738 |
| AddUnified | 2 | 3,207 |
| AddUnified | 10 | 14,961 |
| AddUnified | 50 | 68,857 |
| AddUnified | 100 | 129,772 |
| AddUnified | 200 | 251,313 |

Raw output: `benchmarks/raw/phase-2-circuit/g1-add-measure.log`.

## 4. Regression (constraints = intercept + slope·N)
| method | slope /add | intercept | R² |
|---|---:|---:|---:|
| Add | **646.80** | 1,624.89 | 0.998802 |
| AddUnified | **1,253.60** | 2,465.37 | 0.999417 |

To one decimal: **646.8** constraints per addition (`Add`) and **1,253.6** (`AddUnified`), as printed
in the fit line of the raw log (`benchmarks/raw/phase-2-circuit/g1-add-measure.log:25`).

**Linearity:** R² ≈ 0.999 — a good linear fit, with a mild *sub-linearity*: the
fitted slope drifts down as N grows (Add 754 → 647; AddUnified 1469 → 1254) while
the intercept rises (Add 268 → 1625), consistent with the emulated field's
batched/commitment range-checks amortizing over more additions. Not "markedly
non-linear" → no HALT. The marginal at the top of the range (N=100→200) is **605.4
/add** (Add) and **1,215.4 /add** (AddUnified), i.e. the true 512-marginal is, if
anything, slightly *below* the full-fit slope.

## 5. Comparison — REFUTE
- **vs thesis §2.1.3 ~10–20K/add: REFUTE, both methods.**
  - `Add` ≈ **647 /add** → **~15–31× lower** than 10–20K.
  - `AddUnified` ≈ **1,254 /add** → **~8–16× lower** than 10–20K.
- **Safety premium** (AddUnified − Add): **606.80 /add (+93.8%)** — the complete
  formula's edge-case handling (`IsZero`/`Select`/extra `MulMod`) roughly doubles
  the per-add cost.
- **512× projection (operation 1, 512 unconditional adds):**
  - `Add` → **~331K** constraints (slope·512; ~333K incl. intercept).
  - `AddUnified` → **~642K** constraints (~644K incl. intercept).
  - vs thesis op-1 **~5–10M → REFUTE (~8–30× lower)**.
- **Impact on the 10–26M total-circuit projection:** the thesis total is dominated
  by ops 1 & 2 (the two 512-add aggregations, estimated ~5–10M + ~5–15M ≈ 10–25M of
  the 10–26M). At the measured per-add cost the G1-addition portion is **~0.7–1.5M**,
  not 10–25M, suggesting the **full-circuit total may be closer to ~1–3M than
  10–26M (a ~10× downward revision)** — to be confirmed once the SHA-256 Merkle ops
  (§2.1.3 ops 3–6) and the real accumulator/conditional structure are built
  (Phase 2a-2 / 2a-3). *Design-before-observation: the 10–26M estimate is under
  test; this measurement refutes its per-addition basis.*

## 6. Functional correctness
`G1AddCheckCircuit`: in-circuit `AddUnified(P,Q)` asserted equal to the off-circuit
`P+Q`, with P=3G, Q=5G, Sum=8G (gnark-crypto). Full Groth16 Setup→Prove→Verify
over BLS12-381 → **PASS** (check circuit = 1,890 R1CS constraints). The proof is
randomized (Groth16) — not byte-identical run-to-run, expected, not asserted;
only `Verify` is asserted. Constraint counts (§3) are deterministic.

## 7. Notes
- **"Unused result" validation (the empirical guard).** The measurement circuit
  computes `R_i = A_i + B_i` and discards `R_i`; the claim is that the emulated ops
  still emit their constraints (internal `MulMod`/`Div`/`Reduce` asserts + limb
  range-checks at call time). Confirmed two ways: (a) slopes are **hundreds–to–
  thousands /add, not near-zero** (a dropped add would give ~0); (b) the bare N=1
  `AddUnified` = **1,738** vs the functional check circuit (same add *with* an
  `AssertIsEqual` consuming the result) = **1,890** — bare ≈ check − assert, so the
  unused add is **fully counted**. No dead-code elimination.
- **Intercept** (~1.6–2.5K) = fixed emulated-field startup (range-check
  tables / field setup), folded out of the per-add slope.
- **Memory was a non-issue**: the largest compile (N=200 AddUnified, 251,313
  constraints) finished in ~3 s with trivial RAM — the per-add cost being ~10×
  below the estimate means the feared ~10M-constraint 512-compile never arose at
  these N.
- `Add` was measured on the incomplete/unsafe formula (compile-only, no witness,
  so its P≠±Q/0 precondition is moot for the count). The real accumulator's
  Add-vs-AddUnified safety choice (and the infinity-init of `Σ`) is a separate
  later design decision; for a safe accumulator `AddUnified` (~1,254/add) is the
  realistic basis.
- Native field = BLS12-381 scalar field; the full 512-add compile is deferred to
  AWS (Phase 2a-3), where 512 is measured directly rather than projected.
