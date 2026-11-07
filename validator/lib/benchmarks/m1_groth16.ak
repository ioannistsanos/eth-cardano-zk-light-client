//// M1 — Groth16 verify-sequence cost measurement (Phase 1).
////
//// Measures the reported CPU/memory cost of the cryptographic core of
//// Groth16 verification on the Plutus V3 CEK machine:
////   3 x miller_loop + 2 x mul_miller_loop_result + 1 x final_verify
////
//// Theoretical sum-of-parts (builtinCostModelC.json [40]):
////   3 * 254_006_273 + 2 * 2_174_038 + 1 * 333_849_714 = 1_100_216_609 CPU steps.
////
//// MSM is measured separately (M3/M4); datum/redeemer parsing in Phase 4.
//// See docs/phase1-methodology.md.

use aiken/builtin

// BLS12-381 G1 generator, compressed (48 bytes).
// Canonical generator from the BLS12-381 spec / zkcrypto serialization,
// matching draft-irtf-cfrg-bls-signatures and RFC 9380 §4.2.1 (BLS12-381 G1).
// First byte 0x97 = 0x80 (compression flag) | 0x17 (x high byte); non-identity.
const g1_generator_compressed: ByteArray =
  #"97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb"

// BLS12-381 G2 generator, compressed (96 bytes).
// Canonical generator (zkcrypto serialization: c1 || c0, big-endian),
// matching draft-irtf-cfrg-bls-signatures and RFC 9380 §4.2.2 (BLS12-381 G2).
// First byte 0x93 = 0x80 (compression flag) | 0x13 (c1 high byte); non-identity.
const g2_generator_compressed: ByteArray =
  #"93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8"

// === M1 measurement target ===
// Executes the 6 builtin calls of the Groth16 verification core, on top of
// the two uncompress calls that prepare the group elements (uncompress is
// charged once each: the `let` bindings are evaluated once and shared).
// finalVerify is fed `combined2` as BOTH arguments: its cost is a flat
// constant (333_849_714) independent of inputs, so this avoids a 4th
// miller_loop while keeping the measurement cost-faithful. (The real
// on-chain verifier needs a 4th miller_loop to reconstruct e(alpha,beta);
// see docs/records.md D1 — out of M1's defined scope.)
// M1: 3-ML Table-2 scenario — e(α,β) assumed precomputed off-chain (pre-D1 baseline).
test bench_m1_groth16_core() {
  let g1 = builtin.bls12_381_g1_uncompress(g1_generator_compressed)   // G1 generator (mock stand-in)
  let g2 = builtin.bls12_381_g2_uncompress(g2_generator_compressed)   // G2 generator (mock stand-in)

  let ml1 = builtin.bls12_381_miller_loop(g1, g2)                     // pairing #1 (cost proxy; pre-D1 scenario)
  let ml2 = builtin.bls12_381_miller_loop(g1, g2)                     // pairing #2 (cost proxy)
  let ml3 = builtin.bls12_381_miller_loop(g1, g2)                     // pairing #3 (cost proxy)

  let combined = builtin.bls12_381_mul_miller_loop_result(ml1, ml2)   // combine #1·#2
  let combined2 = builtin.bls12_381_mul_miller_loop_result(combined, ml3)  // combine ·#3

  builtin.bls12_381_final_verify(combined2, combined2)                // 3-ML Table-2 form; e(α,β) precomputed (pre-D1), cost-faithful stand-in
}

// === M1b — realistic on-chain Groth16 sequence (confirms D1) ===
// The verifier that is actually realizable on Cardano needs a 4th miller_loop:
// CIP-381 has no MlResult serialization builtin, so e(alpha,beta) cannot be
// supplied precomputed and must be reconstructed on-chain. This is the
// realistic counterpart to bench_m1_groth16_core (Table 2's 3-ML scenario):
//   4 x miller_loop + 2 x mul_miller_loop_result + 1 x final_verify
// ml4 = miller_loop(g1, g2) stands in for the reconstructed e(alpha,beta)
// (g1 == alpha, g2 == beta in this mock).
//
// Marked `fail`: with mock generator points the verification equation does not
// hold (combined2 = e(g1,g2)^3 != ml4 = e(g1,g2)), so final_verify(combined2,
// ml4) returns False — the expected outcome on arbitrary points, so the test
// passes as a `fail` test. final_verify's cost is input-independent, so the
// measured cost equals that of a genuine verification. See docs/records.md D1.
// M1 vs M1b: +1 miller_loop (ml4 reconstructs e(α,β) on-chain; +254,006,273 CPU; D1).
test bench_m1b_groth16_realistic() fail {
  let g1 = builtin.bls12_381_g1_uncompress(g1_generator_compressed)   // G1 generator (mock stand-in)
  let g2 = builtin.bls12_381_g2_uncompress(g2_generator_compressed)   // G2 generator (mock stand-in)

  let ml1 = builtin.bls12_381_miller_loop(g1, g2)                     // ml1 → e(A, B)
  let ml2 = builtin.bls12_381_miller_loop(g1, g2)                     // ml2 → e(L, −γ)
  let ml3 = builtin.bls12_381_miller_loop(g1, g2)                     // ml3 → e(C, −δ)
  let ml4 = builtin.bls12_381_miller_loop(g1, g2)                     // ml4 → e(α, β) [D1: on-chain reconstruction]

  let combined = builtin.bls12_381_mul_miller_loop_result(ml1, ml2)   // ml1 · ml2
  let combined2 = builtin.bls12_381_mul_miller_loop_result(combined, ml3)  // LHS = combined · ml3

  builtin.bls12_381_final_verify(combined2, ml4)                      // LHS =? e(α,β)
}

// === Control ===
// Does EXACTLY the same non-pairing work as the core test — the same two
// uncompress calls and nothing else — so that (core - control) isolates the
// six pairing builtins with no over/under-count.
//
// UPLC-verified (aiken uplc decode): this body compiles to exactly
//   1 x bls12_381_G1_uncompress + 1 x bls12_381_G2_uncompress
// and NO other builtins; the core test compiles to those same two uncompress
// calls plus the 6 pairing builtins. The only difference between the two is
// the 6 measured builtins.
//
// Note on forcing: the `let _ = g1` / `let _ = g2` lines reference g1/g2 so
// Aiken's optimizer keeps their (failable) uncompress bindings. Binding to an
// unused name (e.g. `let _g1 = uncompress(...)`) is dead-code-eliminated and
// would yield zero uncompress cost — see docs/aiken-gotchas.md.
test bench_m1_control_setup() {
  let g1 = builtin.bls12_381_g1_uncompress(g1_generator_compressed)   // replicate core's G1 prep (cancels under subtraction)
  let g2 = builtin.bls12_381_g2_uncompress(g2_generator_compressed)   // replicate core's G2 prep

  let _ = g1                                                          // force g1 binding (G5)
  let _ = g2                                                          // force g2 binding (G5)

  True
}
