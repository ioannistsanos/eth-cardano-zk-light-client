//// M6 — Synthetic Phase A BOUNDARY: crypto + MSM-7 additivity measurement (Phase 1).
////
//// Boundary analogue of M5: combines the three boundary-Phase-A cryptographic
//// sequences into ONE Plutus V3 script and tests whether they compose ADDITIVELY
//// with the three independently-measured component marginals:
////   - Groth16 verify, D1 form (M1b): 4×miller_loop + 2×mul_miller_loop_result
////                                     + 1×final_verify        (UNCHANGED vs regular)
////   - BLS aggregate verify, REAL/D2 (M2-real): hash_to_group + 2×miller_loop
////                                     + 1×final_verify (NO mul) (UNCHANGED vs regular)
////   - MSM-7 (M4): 7×g1_scalar_mul + 7×g1_add  (boundary: regular 6 + new_committee_id)
////
//// The number of pairings is independent of public-input count, so the ONLY
//// crypto+MSM difference between boundary (M6) and regular (M5) is exactly ONE
//// extra scalar_mul + ONE extra g1_add — the 7th MSM term (new_committee_id).
////
//// DECISION (recorded): BLS uses the canonical CIP-381 D2 form (final_verify(ml1,
//// ml2) directly, NO mul_miller_loop_result) — what the real validator runs;
//// −2,174,038 CPU vs the thesis Table-2 product form. See docs/records.md D2.
////
//// SCOPE: crypto + MSM only. EXCLUDES datum/redeemer deserialization, anchor-
//// invariance, state-thread NFT continuity, and the datum write — measured on a
//// real boundary tx in Phase 4. Phase4_boundary_total − M6 = empirical boundary
//// "script overhead"; M6 does NOT measure it.
////
//// ADDITIVITY HYPOTHESIS H0 (locked BEFORE measurement; design-before-observation):
////   PRIMARY target = sum of the three MEASURED component marginals
////     1,354,670,882 (M1b) + 1,008,845,331 (M2-real) + 542,959,691 (M4 MSM-7)
////     = 2,906,475,904
////   H0: |marginal − 2,906,475,904| / 2,906,475,904 ≤ 0.05 % (band ±1,453,238).
////   Δ = marginal − 2,906,475,904 (signed) is the RESULT OF INTEREST = cross-
////   structure CEK; ~+160,000 expected (same structure as M5's measured +160,000).
////   SECONDARY reference (cost-model pure-builtin sum, no CEK):
////     1,354,222,882 + 1,008,917,927 + 542,015,691 = 2,905,156,500
////     expected gap to PRIMARY = +1,319,404 = aggregate per-builtin CEK in M1–M4:
////     +448,000 (M1b) − 72,596 (M2-real) + 944,000 (M4). [M4 CEK = 944,000, NOT
////     7×136,000 = 952,000 — the −8,000 reproducible M4 offset (M4-report) is
////     already inside the 542,959,691 marginal.]
////   TERTIARY (two measured composites): M6_marginal − M5_marginal (M5 =
////     2,829,077,091) ≈ M4_marginal − M3_marginal = 542,959,691 − 465,400,878
////     = 77,558,813 (Groth16+BLS identical; only the 7th MSM term differs).
////
//// marginal = bench_m6_core − bench_m6_control. The control replicates the EXACT
//// uncompress + sha2 setup union (4×G1_uncompress + 2×G2_uncompress + 1×sha2_256)
//// and all const references (incl. the SEVEN scalars), with NONE of the operation
//// builtins, so the subtraction isolates the union of operation builtins (+CEK).
////
//// Mock inputs are cost-faithful dummies (canonical generators / arbitrary
//// scalars); NONE is a real A/B/C/σ/apk/proof/committee — only the builtin call
//// SHAPE and COUNT determine cost. G6: the BLS message is derived at runtime via
//// sha2_256 so hash_to_group is not constant-folded (else `aiken export` panics).
////
//// See M1b/M2/M4 reports, docs/records.md (D1, D2, D3), M5-report.md, and
//// docs/aiken-gotchas.md (G5, G6, G7).

use aiken/builtin

// ---- Shared mock inputs (verbatim from m1_groth16 / m2_bls / m4_msm_boundary) ----

const g1_generator_compressed: ByteArray =
  #"97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb"

const g2_generator_compressed: ByteArray =
  #"93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8"

// 64-byte BLS signing preimage = attested_header_root (32 B) ‖ signing_domain
// (32 B), per thesis §2.1.3. sha2_256 of this yields the 32-byte signing root.
const mock_signing_preimage_64: ByteArray =
  #"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff0700000000000000000000000000000000000000000000000000000000000000"

// Ethereum BLS signature DST (RFC 9380 [72]; 43 ASCII bytes).
const bls_dst: ByteArray =
  #"424c535f5349475f424c53313233383147325f584d443a5348412d3235365f535357555f524f5f504f505f"

// Seven DISTINCT 32-byte mock scalars sᵢ = 2²⁵² + i (i = 1..7); each < group order r.
// s32_1..s32_6 + s32_7 (boundary new_committee_id slot), verbatim from m4_msm_boundary.ak.
const s32_1: Int = 0x1000000000000000000000000000000000000000000000000000000000000001
const s32_2: Int = 0x1000000000000000000000000000000000000000000000000000000000000002
const s32_3: Int = 0x1000000000000000000000000000000000000000000000000000000000000003
const s32_4: Int = 0x1000000000000000000000000000000000000000000000000000000000000004
const s32_5: Int = 0x1000000000000000000000000000000000000000000000000000000000000005
const s32_6: Int = 0x1000000000000000000000000000000000000000000000000000000000000006
const s32_7: Int = 0x1000000000000000000000000000000000000000000000000000000000000007

// === M6 measurement target — composite of the three boundary-Phase-A cores ===
test bench_m6_core() {
  // ----- Groth16 verify (M1b, D1 4-ML form) — UNCHANGED vs regular -----
  let g_g1 = builtin.bls12_381_g1_uncompress(g1_generator_compressed)   // G₁ operand carrier (α/A/L/C; mock stand-in)
  let g_g2 = builtin.bls12_381_g2_uncompress(g2_generator_compressed)   // G₂ operand carrier (β/B/−γ/−δ; mock stand-in)
  let g_ml1 = builtin.bls12_381_miller_loop(g_g1, g_g2)                 // ml1 → e(A, B)              (cost proxy)
  let g_ml2 = builtin.bls12_381_miller_loop(g_g1, g_g2)                 // ml2 → e(L, −γ)             (cost proxy)
  let g_ml3 = builtin.bls12_381_miller_loop(g_g1, g_g2)                 // ml3 → e(C, −δ)             (cost proxy)
  let g_ml4 = builtin.bls12_381_miller_loop(g_g1, g_g2)                 // ml4 → e(α, β)  [D1: reconstructed on-chain — no MlResult deser]
  let g_c1 = builtin.bls12_381_mul_miller_loop_result(g_ml1, g_ml2)     // ml1 · ml2
  let g_c2 = builtin.bls12_381_mul_miller_loop_result(g_c1, g_ml3)      // LHS = (ml1·ml2) · ml3
  let g_ok = builtin.bls12_381_final_verify(g_c2, g_ml4)               // LHS =? e(α,β)  (Groth16 verify; cost input-independent)

  // ----- BLS aggregate verify (M2-real, D2 NO-mul form) — UNCHANGED vs regular -----
  let b_g1 = builtin.bls12_381_g1_uncompress(g1_generator_compressed)   // g₁ ∈ G₁ (mock stand-in)
  let b_pk = builtin.bls12_381_g1_uncompress(g1_generator_compressed)   // apk ∈ G₁ (mock stand-in)
  let b_sig = builtin.bls12_381_g2_uncompress(g2_generator_compressed)  // σ ∈ G₂ (mock stand-in)
  let b_msg = builtin.sha2_256(mock_signing_preimage_64)                // signing root (runtime; defeats G6 fold)
  let b_hm = builtin.bls12_381_g2_hash_to_group(b_msg, bls_dst)         // H(m) ∈ G₂
  let b_ml1 = builtin.bls12_381_miller_loop(b_g1, b_sig)                // ml1 → e(g₁, σ)
  let b_ml2 = builtin.bls12_381_miller_loop(b_pk, b_hm)                 // ml2 → e(apk, H(m))
  let b_ok = builtin.bls12_381_final_verify(b_ml1, b_ml2)             // e(g₁,σ) =? e(apk,H(m))  [D2: NO mul_miller_loop_result]

  // ----- MSM-7 boundary accumulation (M4): vk_x = IC[0] + Σ pubᵢ·IC[i], i=1..7 -----
  let m_p = builtin.bls12_381_g1_uncompress(g1_generator_compressed)    // IC[i] ∈ G₁ (mock; reused — cost point-value-independent)
  let m_r1 = builtin.bls12_381_g1_scalar_mul(s32_1, m_p)                // pub₁ · IC[1] (term 1; n=4 words)
  let m_r2 = builtin.bls12_381_g1_scalar_mul(s32_2, m_p)                // pub₂ · IC[2] (term 2)
  let m_r3 = builtin.bls12_381_g1_scalar_mul(s32_3, m_p)                // pub₃ · IC[3] (term 3)
  let m_r4 = builtin.bls12_381_g1_scalar_mul(s32_4, m_p)                // pub₄ · IC[4] (term 4)
  let m_r5 = builtin.bls12_381_g1_scalar_mul(s32_5, m_p)                // pub₅ · IC[5] (term 5)
  let m_r6 = builtin.bls12_381_g1_scalar_mul(s32_6, m_p)                // pub₆ · IC[6] (term 6)
  let m_r7 = builtin.bls12_381_g1_scalar_mul(s32_7, m_p)                // pub₇ · IC[7] (term 7 — BOUNDARY new_committee_id slot)
  let m_acc1 = builtin.bls12_381_g1_add(m_p, m_r1)                      // IC[0] + term 1 (start MSM)
  let m_acc2 = builtin.bls12_381_g1_add(m_acc1, m_r2)                   // accumulate term 2
  let m_acc3 = builtin.bls12_381_g1_add(m_acc2, m_r3)                   // accumulate term 3
  let m_acc4 = builtin.bls12_381_g1_add(m_acc3, m_r4)                   // accumulate term 4
  let m_acc5 = builtin.bls12_381_g1_add(m_acc4, m_r5)                   // accumulate term 5
  let m_acc6 = builtin.bls12_381_g1_add(m_acc5, m_r6)                   // accumulate term 6
  let m_acc7 = builtin.bls12_381_g1_add(m_acc6, m_r7)                   // accumulate term 7 → vk_x (BOUNDARY)

  // keep all three sub-chain results live so none is dead-code-eliminated (G5)
  expect _ = g_ok                                                       // force Groth16 chain
  expect _ = b_ok                                                       // force BLS chain
  expect _ = m_acc7                                                     // force MSM-7 chain
  True
}

// === Control — same uncompress + sha2 + const-load union, NO operation builtins ===
// Replicates 4×G1_uncompress + 2×G2_uncompress + 1×sha2_256 + const refs (bls_dst,
// the SEVEN scalars) the cores load, and nothing else, so (core − control) isolates
// the operation builtins. UPLC-verified: ZERO miller_loop / mul_miller_loop_result /
// final_verify / hash_to_group / scalar_mul / g1_add.
test bench_m6_control() {
  let g_g1 = builtin.bls12_381_g1_uncompress(g1_generator_compressed)   // replicate Groth16 G₁ prep
  let g_g2 = builtin.bls12_381_g2_uncompress(g2_generator_compressed)   // replicate Groth16 G₂ prep
  let b_g1 = builtin.bls12_381_g1_uncompress(g1_generator_compressed)   // replicate BLS g₁ prep
  let b_pk = builtin.bls12_381_g1_uncompress(g1_generator_compressed)   // replicate BLS apk prep
  let b_sig = builtin.bls12_381_g2_uncompress(g2_generator_compressed)  // replicate BLS σ prep
  let b_msg = builtin.sha2_256(mock_signing_preimage_64)                // replicate BLS signing root
  let m_p = builtin.bls12_381_g1_uncompress(g1_generator_compressed)    // replicate MSM IC[i] prep

  expect _ = g_g1                                                       // force g_g1 (G5)
  expect _ = g_g2                                                       // force g_g2
  expect _ = b_g1                                                       // force b_g1
  expect _ = b_pk                                                       // force b_pk
  expect _ = b_sig                                                      // force b_sig
  expect _ = b_msg                                                      // force b_msg
  expect _ = m_p                                                        // force m_p
  expect _ = bls_dst                                                    // match core's hash_to_group DST load
  expect _ = s32_1                                                      // match core's scalar_mul arg loads (M3/M4-style)
  expect _ = s32_2
  expect _ = s32_3
  expect _ = s32_4
  expect _ = s32_5
  expect _ = s32_6
  expect _ = s32_7                                                      // 7th scalar (boundary new_committee_id slot)
  True
}
