//// M5 — Synthetic Phase A REGULAR: crypto + MSM additivity measurement (Phase 1).
////
//// Combines the three regular-Phase-A cryptographic sequences into ONE Plutus V3
//// script and measures their COMPOSITE on-chain cost, to test whether the three
//// independently-measured sequences (M1b, M2-real, M3) compose ADDITIVELY:
////   - Groth16 verify, D1 form (M1b): 4×miller_loop + 2×mul_miller_loop_result
////                                     + 1×final_verify
////   - BLS aggregate verify, REAL/D2 form (M2-real): hash_to_group + 2×miller_loop
////                                     + 1×final_verify   (NO mul_miller_loop_result)
////   - MSM-6 (M3): 6×g1_scalar_mul + 6×g1_add
////
//// DECISION (recorded): the BLS sub-sequence uses the canonical CIP-381 D2 form
//// (final_verify(ml1, ml2) directly, NO mul_miller_loop_result) — i.e. exactly
//// what the real Phase A validator runs. This is −2,174,038 CPU vs the thesis
//// Table-2 product form. See docs/records.md D2.
////
//// SCOPE: M5 measures ONLY the crypto + MSM portion. It DELIBERATELY EXCLUDES
//// datum/redeemer deserialization, anchor-invariance checks, NFT continuity, and
//// the datum write — those are measured on a real tx in Phase 4. The thesis
//// "~500 M script overhead" placeholder is (Phase4_total − M5); M5 does NOT
//// measure it.
////
//// ADDITIVITY HYPOTHESIS H0 (locked BEFORE measurement; design-before-observation):
////   PRIMARY target = sum of the three MEASURED component marginals
////     1,354,670,882 (M1b) + 1,008,845,331 (M2-real) + 465,400,878 (M3)
////     = 2,828,917,091
////   H0: |marginal − 2,828,917,091| / 2,828,917,091 ≤ 0.05 % (band ±1,414,459).
////   Δ = marginal − 2,828,917,091 (signed) is the RESULT OF INTEREST = the
////   cross-structure CEK of running the three sequences in one continuation
////   chain vs three separate ones (NOT a pass/fail to be "fixed").
////   SECONDARY reference (cost-model pure-builtin sum, no CEK):
////     1,354,222,882 + 1,008,917,927 + 464,584,878 = 2,827,725,687
////     expected gap to PRIMARY = +1,191,404 (aggregate per-builtin CEK already
////     inside M1–M4: +448,000 M1b − 72,596 M2-real + 816,000 M3).
////
//// marginal = bench_m5_core − bench_m5_control. The control replicates the EXACT
//// uncompress + sha2 setup union (4×G1_uncompress + 2×G2_uncompress + 1×sha2_256)
//// and all const references, with NONE of the operation builtins, so the
//// subtraction isolates the union of operation builtins (+ their per-builtin CEK).
////
//// Mock inputs are cost-faithful dummies (canonical generators / arbitrary
//// scalars); NONE is a real A/B/C/σ/apk/proof — only the builtin call SHAPE and
//// COUNT determine cost. G6: the BLS message is derived at runtime via sha2_256
//// so hash_to_group is not constant-folded (else `aiken export` panics).
////
//// See M1b/M2/M3 reports, docs/records.md (D1, D2, D3), and
//// docs/aiken-gotchas.md (G5, G6, G7).

use aiken/builtin

// ---- Shared mock inputs (copied verbatim from m1_groth16 / m2_bls / m3_msm) ----

// BLS12-381 G1 generator, compressed (48 B); canonical zkcrypto serialization.
const g1_generator_compressed: ByteArray =
  #"97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb"

// BLS12-381 G2 generator, compressed (96 B); canonical zkcrypto serialization.
const g2_generator_compressed: ByteArray =
  #"93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8"

// 64-byte BLS signing preimage = attested_header_root (32 B) ‖ signing_domain
// (32 B), per thesis §2.1.3. sha2_256 of this yields the 32-byte signing root.
const mock_signing_preimage_64: ByteArray =
  #"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff0700000000000000000000000000000000000000000000000000000000000000"

// Ethereum BLS signature DST (RFC 9380 [72]; 43 ASCII bytes).
const bls_dst: ByteArray =
  #"424c535f5349475f424c53313233383147325f584d443a5348412d3235365f535357555f524f5f504f505f"

// Six DISTINCT 32-byte mock scalars sᵢ = 2²⁵² + i (i = 1..6); each < group order r.
const s32_1: Int = 0x1000000000000000000000000000000000000000000000000000000000000001
const s32_2: Int = 0x1000000000000000000000000000000000000000000000000000000000000002
const s32_3: Int = 0x1000000000000000000000000000000000000000000000000000000000000003
const s32_4: Int = 0x1000000000000000000000000000000000000000000000000000000000000004
const s32_5: Int = 0x1000000000000000000000000000000000000000000000000000000000000005
const s32_6: Int = 0x1000000000000000000000000000000000000000000000000000000000000006

// === M5 measurement target — composite of the three regular-Phase-A cores ===
test bench_m5_core() {
  // ----- Groth16 verify (M1b, D1 4-miller-loop on-chain form) -----
  // One G1 + one G2 generator reused as the cost-faithful stand-in for every
  // G1/G2 operand of the verify equation (cost is input-value-independent).
  let g_g1 = builtin.bls12_381_g1_uncompress(g1_generator_compressed)   // G₁ operand carrier (α/A/L/C; mock stand-in)
  let g_g2 = builtin.bls12_381_g2_uncompress(g2_generator_compressed)   // G₂ operand carrier (β/B/−γ/−δ; mock stand-in)
  let g_ml1 = builtin.bls12_381_miller_loop(g_g1, g_g2)                 // ml1 → e(A, B)              (cost proxy)
  let g_ml2 = builtin.bls12_381_miller_loop(g_g1, g_g2)                 // ml2 → e(L, −γ)             (cost proxy)
  let g_ml3 = builtin.bls12_381_miller_loop(g_g1, g_g2)                 // ml3 → e(C, −δ)             (cost proxy)
  let g_ml4 = builtin.bls12_381_miller_loop(g_g1, g_g2)                 // ml4 → e(α, β)  [D1: reconstructed on-chain — no MlResult deser]
  let g_c1 = builtin.bls12_381_mul_miller_loop_result(g_ml1, g_ml2)     // ml1 · ml2
  let g_c2 = builtin.bls12_381_mul_miller_loop_result(g_c1, g_ml3)      // LHS = (ml1·ml2) · ml3
  let g_ok = builtin.bls12_381_final_verify(g_c2, g_ml4)               // LHS =? e(α,β)  (Groth16 verify; cost input-independent)

  // ----- BLS aggregate verify (M2-real, D2 canonical NO-mul form) -----
  let b_g1 = builtin.bls12_381_g1_uncompress(g1_generator_compressed)   // g₁ ∈ G₁ (mock stand-in)
  let b_pk = builtin.bls12_381_g1_uncompress(g1_generator_compressed)   // apk ∈ G₁ (mock stand-in)
  let b_sig = builtin.bls12_381_g2_uncompress(g2_generator_compressed)  // σ ∈ G₂ (mock stand-in)
  let b_msg = builtin.sha2_256(mock_signing_preimage_64)                // signing root (runtime; defeats G6 fold)
  let b_hm = builtin.bls12_381_g2_hash_to_group(b_msg, bls_dst)         // H(m) ∈ G₂
  let b_ml1 = builtin.bls12_381_miller_loop(b_g1, b_sig)                // ml1 → e(g₁, σ)
  let b_ml2 = builtin.bls12_381_miller_loop(b_pk, b_hm)                 // ml2 → e(apk, H(m))
  let b_ok = builtin.bls12_381_final_verify(b_ml1, b_ml2)             // e(g₁,σ) =? e(apk,H(m))  [D2: NO mul_miller_loop_result]

  // ----- MSM-6 public-input accumulation (M3): vk_x = IC[0] + Σ pubᵢ·IC[i] -----
  let m_p = builtin.bls12_381_g1_uncompress(g1_generator_compressed)    // IC[i] ∈ G₁ (mock; reused — cost point-value-independent)
  let m_r1 = builtin.bls12_381_g1_scalar_mul(s32_1, m_p)                // pub₁ · IC[1] (term 1; n=4 words)
  let m_r2 = builtin.bls12_381_g1_scalar_mul(s32_2, m_p)                // pub₂ · IC[2] (term 2)
  let m_r3 = builtin.bls12_381_g1_scalar_mul(s32_3, m_p)                // pub₃ · IC[3] (term 3)
  let m_r4 = builtin.bls12_381_g1_scalar_mul(s32_4, m_p)                // pub₄ · IC[4] (term 4)
  let m_r5 = builtin.bls12_381_g1_scalar_mul(s32_5, m_p)                // pub₅ · IC[5] (term 5)
  let m_r6 = builtin.bls12_381_g1_scalar_mul(s32_6, m_p)                // pub₆ · IC[6] (term 6)
  let m_acc1 = builtin.bls12_381_g1_add(m_p, m_r1)                      // IC[0] + term 1 (start MSM)
  let m_acc2 = builtin.bls12_381_g1_add(m_acc1, m_r2)                   // accumulate term 2
  let m_acc3 = builtin.bls12_381_g1_add(m_acc2, m_r3)                   // accumulate term 3
  let m_acc4 = builtin.bls12_381_g1_add(m_acc3, m_r4)                   // accumulate term 4
  let m_acc5 = builtin.bls12_381_g1_add(m_acc4, m_r5)                   // accumulate term 5
  let m_acc6 = builtin.bls12_381_g1_add(m_acc5, m_r6)                   // accumulate term 6 → vk_x

  // keep all three sub-chain results live so none is dead-code-eliminated (G5)
  expect _ = g_ok                                                       // force Groth16 chain
  expect _ = b_ok                                                       // force BLS chain
  expect _ = m_acc6                                                     // force MSM chain
  True
}

// === Control — same uncompress + sha2 + const-load union, NO operation builtins ===
// Replicates the union of the three component controls: 4×G1_uncompress +
// 2×G2_uncompress + 1×sha2_256, plus the same const references (bls_dst, the six
// scalars) the cores load — so every shared cost cancels and (core − control)
// isolates the operation builtins. UPLC-verified to contain ZERO miller_loop /
// mul_miller_loop_result / final_verify / hash_to_group / scalar_mul / g1_add.
test bench_m5_control() {
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
  expect _ = s32_1                                                      // match core's scalar_mul arg loads (M3-style)
  expect _ = s32_2
  expect _ = s32_3
  expect _ = s32_4
  expect _ = s32_5
  expect _ = s32_6
  True
}
