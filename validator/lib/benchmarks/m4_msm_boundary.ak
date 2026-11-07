//// M4 — MSM boundary (7 public inputs); CONFIRMATORY for D3 (Phase 1).
////
//// Boundary Phase A circuit exposes 7 public inputs:
////   regular 6 + new_committee_id (thesis §2.1.3.A)
//// MSM: vk_x = IC[0] + Σᵢ pub_i·IC[i], i = 1..7
//// → 7×bls12_381_g1_scalar_mul + 7×bls12_381_g1_add.
////
//// Near-copy of M3 with one extra term. Unlike M3, the scalarMul n-unit
//// and per-call CEK are already KNOWN from D3:
////   n = 4 (64-bit words for 32-byte scalars)
////   per-call CEK = +136,000 (NOT in builtinCostModelC.json; builtin-specific)
////   g1_add has no measurable CEK overhead
//// So M4 is CONFIRMATORY: target is fully determined; H₀ ±0.05% applies
//// as a normal pass/fail.
////
//// Theoretical (D3-derived):
////   per scalarMul (n=4) = 76,433,006 + 8,868·4 + 136,000 = 76,604,478
////   per g1_add          = 962,335 (cost-model exact)
////   Σ_A (7 sM + 7 g1_add) = 7·76,604,478 + 7·962,335
////                         = 536,231,346 + 6,736,345
////                         = 542,967,691
////   Thesis Table 2 boundary uses ~542,095,561 → corrected to 542,967,691
////   (line-item: +872,130 = D3 applied to 7 inputs; thesis's anomalous
////    n≈5.3 cancels a small offset against the +7·136K CEK addition).
////
//// Four tests (two cores + two paired barrier controls):
////   bench_m4_msm_boundary_core_n32     — seven DISTINCT 32-byte scalars
////   bench_m4_msm_boundary_core_n2      — seven DISTINCT 2-byte scalars
////   bench_m4_msm_boundary_control_n32  — paired ctrl for A
////   bench_m4_msm_boundary_control_n2   — paired ctrl for B
//// marg_A = A − C32, marg_B = B − D2 (paired-control subtraction per M3 design;
//// Int-load delta cancels in each pair).
////
//// See benchmarks/phase-1-cost-model/M3-report.md, D3 in
//// docs/records.md D3 (n-unit, CEK calibration), and
//// docs/aiken-gotchas.md (G5, G6).

use aiken/builtin

const g1_generator_compressed: ByteArray =
  #"97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb"

// Seven DISTINCT 32-byte mock scalars: sᵢ = 2²⁵² + i (i = 1..7).
// s32_1..s32_6 reused verbatim from M3; s32_7 added for the boundary slot.
// (Real public inputs reduce mod r to this width regardless of semantic size.)
const s32_1: Int = 0x1000000000000000000000000000000000000000000000000000000000000001
const s32_2: Int = 0x1000000000000000000000000000000000000000000000000000000000000002
const s32_3: Int = 0x1000000000000000000000000000000000000000000000000000000000000003
const s32_4: Int = 0x1000000000000000000000000000000000000000000000000000000000000004
const s32_5: Int = 0x1000000000000000000000000000000000000000000000000000000000000005
const s32_6: Int = 0x1000000000000000000000000000000000000000000000000000000000000006
const s32_7: Int = 0x1000000000000000000000000000000000000000000000000000000000000007

// Seven DISTINCT 2-byte mock scalars (avoid 0/1; s2_1..s2_6 reused from M3).
const s2_1: Int = 0x0100
const s2_2: Int = 0x0101
const s2_3: Int = 0x0102
const s2_4: Int = 0x0103
const s2_5: Int = 0x0104
const s2_6: Int = 0x0105
const s2_7: Int = 0x0106

// === TEST A — core MSM, n = 4 words (32-byte) — D3-targeted Σ_A = 542,967,691 ===
test bench_m4_msm_boundary_core_n32() {
  let p = builtin.bls12_381_g1_uncompress(g1_generator_compressed)    // IC[i] (mock; reused — cost is point-value-independent)

  let r1 = builtin.bls12_381_g1_scalar_mul(s32_1, p)                  // pub_1 · IC[1] (term 1)
  let r2 = builtin.bls12_381_g1_scalar_mul(s32_2, p)                  // pub_2 · IC[2] (term 2)
  let r3 = builtin.bls12_381_g1_scalar_mul(s32_3, p)                  // pub_3 · IC[3] (term 3)
  let r4 = builtin.bls12_381_g1_scalar_mul(s32_4, p)                  // pub_4 · IC[4] (term 4)
  let r5 = builtin.bls12_381_g1_scalar_mul(s32_5, p)                  // pub_5 · IC[5] (term 5)
  let r6 = builtin.bls12_381_g1_scalar_mul(s32_6, p)                  // pub_6 · IC[6] (term 6)
  let r7 = builtin.bls12_381_g1_scalar_mul(s32_7, p)                  // pub_7 · IC[7] (term 7; new_committee_id slot)

  let acc1 = builtin.bls12_381_g1_add(p, r1)                          // IC[0] + term 1 (start MSM)
  let acc2 = builtin.bls12_381_g1_add(acc1, r2)                       // accumulate term 2
  let acc3 = builtin.bls12_381_g1_add(acc2, r3)                       // accumulate term 3
  let acc4 = builtin.bls12_381_g1_add(acc3, r4)                       // accumulate term 4
  let acc5 = builtin.bls12_381_g1_add(acc4, r5)                       // accumulate term 5
  let acc6 = builtin.bls12_381_g1_add(acc5, r6)                       // accumulate term 6
  let acc7 = builtin.bls12_381_g1_add(acc6, r7)                       // accumulate term 7 → vk_x

  expect _ = acc7                                                     // force chain (DCE guard; G5)

  True
}

// === TEST B — small-scalar probe (n = 1 word) — D3 cross-check at boundary count ===
// If D3's calibration holds at 7 inputs, size_delta = marg_A − marg_B must equal
// 7·8,868·3 = 186,228 EXACTLY (Δwords = 3 between 4 and 1).
test bench_m4_msm_boundary_core_n2() {
  let p = builtin.bls12_381_g1_uncompress(g1_generator_compressed)    // IC[i] (mock; reused)

  let r1 = builtin.bls12_381_g1_scalar_mul(s2_1, p)                   // pub_1 · IC[1] (term 1; small scalar)
  let r2 = builtin.bls12_381_g1_scalar_mul(s2_2, p)                   // pub_2 · IC[2] (term 2)
  let r3 = builtin.bls12_381_g1_scalar_mul(s2_3, p)                   // pub_3 · IC[3] (term 3)
  let r4 = builtin.bls12_381_g1_scalar_mul(s2_4, p)                   // pub_4 · IC[4] (term 4)
  let r5 = builtin.bls12_381_g1_scalar_mul(s2_5, p)                   // pub_5 · IC[5] (term 5)
  let r6 = builtin.bls12_381_g1_scalar_mul(s2_6, p)                   // pub_6 · IC[6] (term 6)
  let r7 = builtin.bls12_381_g1_scalar_mul(s2_7, p)                   // pub_7 · IC[7] (term 7)

  let acc1 = builtin.bls12_381_g1_add(p, r1)                          // IC[0] + term 1
  let acc2 = builtin.bls12_381_g1_add(acc1, r2)                       // accumulate term 2
  let acc3 = builtin.bls12_381_g1_add(acc2, r3)                       // accumulate term 3
  let acc4 = builtin.bls12_381_g1_add(acc3, r4)                       // accumulate term 4
  let acc5 = builtin.bls12_381_g1_add(acc4, r5)                       // accumulate term 5
  let acc6 = builtin.bls12_381_g1_add(acc5, r6)                       // accumulate term 6
  let acc7 = builtin.bls12_381_g1_add(acc6, r7)                       // accumulate term 7 → vk_x

  expect _ = acc7                                                     // force chain (DCE guard; G5)

  True
}

// === TEST C32 — barrier control for the 32-byte core (clean marg_A) ===
// Replicates A's uncompress + the seven 32-byte Int loads via `expect _ = x`
// (G5 idiom). UPLC target: 1×G1_uncompress, ZERO of the measured builtins.
test bench_m4_msm_boundary_control_n32() {
  let p = builtin.bls12_381_g1_uncompress(g1_generator_compressed)    // replicate A's IC[i] prep

  expect _ = p                                                        // force p binding (G5)
  expect _ = s32_1                                                    // replicate A's pub_1 reference
  expect _ = s32_2                                                    // replicate A's pub_2 reference
  expect _ = s32_3                                                    // replicate A's pub_3 reference
  expect _ = s32_4                                                    // replicate A's pub_4 reference
  expect _ = s32_5                                                    // replicate A's pub_5 reference
  expect _ = s32_6                                                    // replicate A's pub_6 reference
  expect _ = s32_7                                                    // replicate A's pub_7 reference (new_committee_id slot)

  True
}

// === TEST D2 — barrier control for the 2-byte probe (clean marg_B) ===
test bench_m4_msm_boundary_control_n2() {
  let p = builtin.bls12_381_g1_uncompress(g1_generator_compressed)    // replicate B's IC[i] prep

  expect _ = p                                                        // force p binding (G5)
  expect _ = s2_1                                                     // replicate B's pub_1 reference
  expect _ = s2_2                                                     // replicate B's pub_2 reference
  expect _ = s2_3                                                     // replicate B's pub_3 reference
  expect _ = s2_4                                                     // replicate B's pub_4 reference
  expect _ = s2_5                                                     // replicate B's pub_5 reference
  expect _ = s2_6                                                     // replicate B's pub_6 reference
  expect _ = s2_7                                                     // replicate B's pub_7 reference

  True
}
