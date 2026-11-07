//// M2 — BLS aggregate-signature verification cost (sha2 barrier).
////
//// Defeats Aiken's constant-folding of bls12_381_g2_hash_to_group (gotcha G6
//// in docs/aiken-gotchas.md) by deriving the message at runtime:
////   msg = sha2_256(header_root ‖ domain) — exactly what the validator
//// computes per thesis §2.1.3. sha2_256 is NOT constant-folded by Aiken
//// v1.1.22 (G6 probe), so msg becomes a runtime ByteArray and hash_to_group's
//// first argument is no longer a compile-time constant.
////
//// Three tests + a single barrier control:
////   bench_m2_bls_core      — thesis Table-2 form (WITH mul_miller_loop_result)
////   bench_m2_bls_real      — canonical CIP-381 BLS verify (NO mul); models D2
////   bench_m2_bls_control   — same setup, NO measured builtins (barrier ctrl)
////
//// Theoretical sum-of-parts:
////   Σ_core (with mul): G2_hashToGroup(32) + 2×millerLoop + mul + finalVerify
////     = 167,055,667 + 508,012,546 + 2,174,038 + 333,849,714 = 1,011,091,965
////   Σ_real (no mul):   G2_hashToGroup(32) + 2×millerLoop + finalVerify
////     = 167,055,667 + 508,012,546 + 333,849,714             = 1,008,917,927
////
//// See docs/records.md D1 (Groth16 4th-ML) and D2 (BLS canonical form
//// uses no mul under CIP-381; thesis Table 2 over-counts by one mul).

use aiken/builtin

const g1_generator_compressed: ByteArray =
  #"97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb"

const g2_generator_compressed: ByteArray =
  #"93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8"

// 64-byte signing preimage = attested_header_root (32 B) ‖ signing_domain (32 B),
// per thesis §2.1.3. sha2_256 of this gives a 32-byte signing root which is
// then hashed to G2 via hash_to_group.
const mock_signing_preimage_64: ByteArray =
  #"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff0700000000000000000000000000000000000000000000000000000000000000"

// Ethereum BLS signature DST (RFC 9380 [72]; 43 ASCII bytes).
const bls_dst: ByteArray =
  #"424c535f5349475f424c53313233383147325f584d443a5348412d3235365f535357555f524f5f504f505f"

// === TEST 1 — core (thesis Table-2 form, WITH mul_miller_loop_result) ===
test bench_m2_bls_core() fail {
  let g1g = builtin.bls12_381_g1_uncompress(g1_generator_compressed)  // g₁ (mock stand-in)
  let pk = builtin.bls12_381_g1_uncompress(g1_generator_compressed)   // apk ∈ G₁ (mock stand-in)
  let sig = builtin.bls12_381_g2_uncompress(g2_generator_compressed)  // σ ∈ G₂ (mock stand-in)
  let msg = builtin.sha2_256(mock_signing_preimage_64)                // signing root (runtime; defeats G6)

  let hm = builtin.bls12_381_g2_hash_to_group(msg, bls_dst)           // hm → H(m) ∈ G₂
  let ml1 = builtin.bls12_381_miller_loop(g1g, sig)                   // ml1 → e(g₁, σ)
  let ml2 = builtin.bls12_381_miller_loop(pk, hm)                     // ml2 → e(apk, H(m))
  let c = builtin.bls12_381_mul_miller_loop_result(ml1, ml2)          // c = ml1 · ml2 (Table-2 product form)

  builtin.bls12_381_final_verify(c, ml1)                              // cost-faithful stand-in (not real verify); D2 → TEST 2
}

// === TEST 2 — real / D2 (canonical CIP-381 BLS verify, NO mul) ===
// The natural form on Plutus V3: e(g1, σ) == e(pk, H(m)) directly. This skips
// the mul_miller_loop_result that thesis Table 2 budgets and saves ~2.17 M.
test bench_m2_bls_real() fail {
  let g1g = builtin.bls12_381_g1_uncompress(g1_generator_compressed)  // g₁ (mock stand-in)
  let pk = builtin.bls12_381_g1_uncompress(g1_generator_compressed)   // apk ∈ G₁ (mock stand-in)
  let sig = builtin.bls12_381_g2_uncompress(g2_generator_compressed)  // σ ∈ G₂ (mock stand-in)
  let msg = builtin.sha2_256(mock_signing_preimage_64)                // signing root (runtime; defeats G6)

  let hm = builtin.bls12_381_g2_hash_to_group(msg, bls_dst)           // hm → H(m) ∈ G₂
  let ml1 = builtin.bls12_381_miller_loop(g1g, sig)                   // ml1 → e(g₁, σ)
  let ml2 = builtin.bls12_381_miller_loop(pk, hm)                     // ml2 → e(apk, H(m))

  builtin.bls12_381_final_verify(ml1, ml2)                            // e(g₁, σ) =? e(apk, H(m))
}

// === TEST 3 — barrier-control (same setup, NO measured builtins) ===
// Five keep-alives via `expect _ = x` so the two G1_uncompress + G2_uncompress
// + sha2_256(preimage) + reference to bls_dst all appear in the UPLC of the
// control, matching core/real and cancelling under subtraction.
test bench_m2_bls_control() {
  let g1g = builtin.bls12_381_g1_uncompress(g1_generator_compressed)  // replicate core's g₁ prep
  let pk = builtin.bls12_381_g1_uncompress(g1_generator_compressed)   // replicate core's apk prep
  let sig = builtin.bls12_381_g2_uncompress(g2_generator_compressed)  // replicate core's σ prep
  let msg = builtin.sha2_256(mock_signing_preimage_64)                // replicate core's signing root

  expect _ = g1g                                                      // force g1g binding (G5)
  expect _ = pk                                                       // force pk binding
  expect _ = sig                                                      // force sig binding
  expect _ = msg                                                      // force msg binding
  expect _ = bls_dst                                                  // force bls_dst reference

  True
}
