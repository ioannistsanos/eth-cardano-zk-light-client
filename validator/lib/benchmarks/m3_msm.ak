//// M3 — MSM regular (6 public inputs) + scalarMul characterization (Phase 1).
////
//// Measures the Groth16 public-input MSM the on-chain verifier performs:
////   vk_x = IC[0] + Σᵢ pub_i · IC[i]   (i = 1..6, regular Phase A; thesis §3.2.2)
//// Six bls12_381_g1_scalar_mul + six bls12_381_g1_add. ALSO characterizes the
//// scalarMul cost-model n-unit (bytes? 64-bit words? flat?) by comparing
//// 32-byte vs 2-byte scalars against PAIRED CLEAN CONTROLS.
////
//// Theoretical sum-of-parts (builtinCostModelC.json [40]):
////   scalarMul = 76,433,006 + 8,868·n     (n-unit UNKNOWN — to be identified)
////   G1_add    = 962,335 (constant)
////
////   Σ_A if n = 32 (bytes):   6·(76,433,006 + 8,868·32) + 6·962,335 = 466,074,702
////   Σ_A if n = 4  (words):   6·(76,433,006 + 8,868·4)  + 6·962,335 = 464,584,878
////   (Thesis Table 2 uses ~458,879,328 for 6 scalarMul → implies n ≈ 5.3,
////    anomalous; M3 corrects this on empirical evidence.)
////
//// Four tests (two cores + two paired barrier controls):
////   bench_m3_msm_core_n32      — six DISTINCT 32-byte scalars (conservative MSM target)
////   bench_m3_msm_core_n2       — six DISTINCT 2-byte scalars (size-dependence probe)
////   bench_m3_msm_control_n32   — barrier ctrl for A: same uncompress + 32-byte Int loads
////   bench_m3_msm_control_n2    — barrier ctrl for B: same uncompress + 2-byte Int loads
//// Paired controls cancel the 32B↔2B Int-literal load delta, so
////   marg_A = A − C32   and   marg_B = B − C2
//// each cleanly isolate 6·scalarMul + 6·g1_add. size_delta = marg_A − marg_B
//// then measures scalarMul size-sensitivity with zero Int-load contamination.
////
//// G6 (Aiken constant-folding): scalarMul and g1_add are NOT folded (G6 probe),
//// so no runtime barrier is needed — values can be compile-time constants.
////
//// See docs/aiken-gotchas.md (G5, G6).

use aiken/builtin

const g1_generator_compressed: ByteArray =
  #"97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb"

// Six DISTINCT 32-byte mock scalars: sᵢ = 2²⁵² + i (i = 1..6).
// Each < group order r ≈ 2²⁵⁴·⁸; distinct values defeat CSE / value-equal shortcuts.
// (Real public inputs reduce mod r to this width regardless of semantic size.)
const s32_1: Int = 0x1000000000000000000000000000000000000000000000000000000000000001

const s32_2: Int = 0x1000000000000000000000000000000000000000000000000000000000000002

const s32_3: Int = 0x1000000000000000000000000000000000000000000000000000000000000003

const s32_4: Int = 0x1000000000000000000000000000000000000000000000000000000000000004

const s32_5: Int = 0x1000000000000000000000000000000000000000000000000000000000000005

const s32_6: Int = 0x1000000000000000000000000000000000000000000000000000000000000006

// Six DISTINCT 2-byte mock scalars (avoid 0/1 to dodge mult-by-0/1 shortcuts).
// Probes whether Aiken charges scalarMul by scalar byte-length.
const s2_1: Int = 0x0100

const s2_2: Int = 0x0101

const s2_3: Int = 0x0102

const s2_4: Int = 0x0103

const s2_5: Int = 0x0104

const s2_6: Int = 0x0105

// === TEST A — core MSM, n = 32 conservative (modeled target Σ ≈ 466,074,702) ===
test bench_m3_msm_core_n32() {
  let p = builtin.bls12_381_g1_uncompress(g1_generator_compressed)    // IC[i] (mock; reused — cost is point-value-independent)

  let r1 = builtin.bls12_381_g1_scalar_mul(s32_1, p)                  // pub_1 · IC[1] (term 1)
  let r2 = builtin.bls12_381_g1_scalar_mul(s32_2, p)                  // pub_2 · IC[2] (term 2)
  let r3 = builtin.bls12_381_g1_scalar_mul(s32_3, p)                  // pub_3 · IC[3] (term 3)
  let r4 = builtin.bls12_381_g1_scalar_mul(s32_4, p)                  // pub_4 · IC[4] (term 4)
  let r5 = builtin.bls12_381_g1_scalar_mul(s32_5, p)                  // pub_5 · IC[5] (term 5)
  let r6 = builtin.bls12_381_g1_scalar_mul(s32_6, p)                  // pub_6 · IC[6] (term 6)

  let acc1 = builtin.bls12_381_g1_add(p, r1)                          // IC[0] + term 1 (start MSM)
  let acc2 = builtin.bls12_381_g1_add(acc1, r2)                       // accumulate term 2
  let acc3 = builtin.bls12_381_g1_add(acc2, r3)                       // accumulate term 3
  let acc4 = builtin.bls12_381_g1_add(acc3, r4)                       // accumulate term 4
  let acc5 = builtin.bls12_381_g1_add(acc4, r5)                       // accumulate term 5
  let acc6 = builtin.bls12_381_g1_add(acc5, r6)                       // accumulate term 6 → vk_x

  expect _ = acc6                                                     // force chain (DCE guard; G5)

  True
}

// === TEST B — small-scalar probe (n = 2 bytes; size-dependence check) ===
// If Aiken charges scalarMul by scalar byte-length, marg_B < marg_A; if flat,
// marg_A ≈ marg_B (charge is fixed regardless of input size).
test bench_m3_msm_core_n2() {
  let p = builtin.bls12_381_g1_uncompress(g1_generator_compressed)    // IC[i] (mock; reused)

  let r1 = builtin.bls12_381_g1_scalar_mul(s2_1, p)                   // pub_1 · IC[1] (term 1; small scalar)
  let r2 = builtin.bls12_381_g1_scalar_mul(s2_2, p)                   // pub_2 · IC[2] (term 2)
  let r3 = builtin.bls12_381_g1_scalar_mul(s2_3, p)                   // pub_3 · IC[3] (term 3)
  let r4 = builtin.bls12_381_g1_scalar_mul(s2_4, p)                   // pub_4 · IC[4] (term 4)
  let r5 = builtin.bls12_381_g1_scalar_mul(s2_5, p)                   // pub_5 · IC[5] (term 5)
  let r6 = builtin.bls12_381_g1_scalar_mul(s2_6, p)                   // pub_6 · IC[6] (term 6)

  let acc1 = builtin.bls12_381_g1_add(p, r1)                          // IC[0] + term 1
  let acc2 = builtin.bls12_381_g1_add(acc1, r2)                       // accumulate term 2
  let acc3 = builtin.bls12_381_g1_add(acc2, r3)                       // accumulate term 3
  let acc4 = builtin.bls12_381_g1_add(acc3, r4)                       // accumulate term 4
  let acc5 = builtin.bls12_381_g1_add(acc4, r5)                       // accumulate term 5
  let acc6 = builtin.bls12_381_g1_add(acc5, r6)                       // accumulate term 6 → vk_x

  expect _ = acc6                                                     // force chain (DCE guard; G5)

  True
}

// === TEST C32 — barrier control for the 32-byte core (clean marg_A) ===
// Replicates A's uncompress + the six 32-byte Int loads via `expect _ = x`
// (G5 idiom). UPLC target: 1×G1_uncompress, ZERO of the measured builtins.
test bench_m3_msm_control_n32() {
  let p = builtin.bls12_381_g1_uncompress(g1_generator_compressed)    // replicate A's IC[i] prep

  expect _ = p                                                        // force p binding (G5)
  expect _ = s32_1                                                    // replicate A's pub_1 reference
  expect _ = s32_2                                                    // replicate A's pub_2 reference
  expect _ = s32_3                                                    // replicate A's pub_3 reference
  expect _ = s32_4                                                    // replicate A's pub_4 reference
  expect _ = s32_5                                                    // replicate A's pub_5 reference
  expect _ = s32_6                                                    // replicate A's pub_6 reference

  True
}

// === TEST D2 — barrier control for the 2-byte probe (clean marg_B) ===
// Mirrors TEST B's Int loads (2-byte scalars) so marg_B = B − D isolates
// 6·scalarMul + 6·g1_add with the 2-byte Int-load contribution cancelled.
test bench_m3_msm_control_n2() {
  let p = builtin.bls12_381_g1_uncompress(g1_generator_compressed)    // replicate B's IC[i] prep

  expect _ = p                                                        // force p binding (G5)
  expect _ = s2_1                                                     // replicate B's pub_1 reference
  expect _ = s2_2                                                     // replicate B's pub_2 reference
  expect _ = s2_3                                                     // replicate B's pub_3 reference
  expect _ = s2_4                                                     // replicate B's pub_4 reference
  expect _ = s2_5                                                     // replicate B's pub_5 reference
  expect _ = s2_6                                                     // replicate B's pub_6 reference

  True
}
