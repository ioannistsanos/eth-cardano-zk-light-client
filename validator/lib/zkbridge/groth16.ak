//// Phase-3 Layer 2 — the on-chain Groth16 verifier (obligations 1+2+9), COMMITMENT-AUGMENTED
//// per D19. The real gnark proof carries one Pedersen commitment (the emulated-arithmetic
//// range-check path), so verification = a BSB22 hash-to-field of the commitment (→ a 12th
//// public input), a Pedersen PoK pairing, the augmented 12-term MSM (+ the commitment point),
//// and the 4-Miller-loop main check. All deserialization is via STRICT CIP-381 uncompress.
////
//// The two riskiest seams are validated end-to-end by the toy proof (groth16_test.ak): the
//// #9 byte conventions (the uncompresses) and the expand_message_xmd-SHA256 hash-to-field
//// (which must be BIT-IDENTICAL to gnark or the 12th public differs and verification fails).
////
//// PoK simplification (D19, confirmed from gnark's BatchVerifyMultiVk source): with exactly
//// ONE commitment the batching challenge (gnark's second "G16-BSB22" hash) is r⁰=1, hence
//// UNUSED — so the on-chain verifier needs only the ONE "bsb22-commitment" hash, and the PoK
//// is the bare pairing check e(commitment, GSigmaNeg) == e(pok, −G).

use aiken/builtin
use aiken/collection/list
use zkbridge/points.{g1_from_uncompressed}
use zkbridge/types.{Groth16Proof, Groth16VerifyingKey}

// BLS12-381 scalar field modulus r (Fr).
const scalar_field: Int =
  52435875175126190479447740508185965837690552500527637822603658699938581184513

// DST for the BSB22 commitment hash-to-field (gnark constraint.CommitmentDst).
const bsb22_dst: ByteArray = "bsb22-commitment"

// 64 zero bytes — SHA-256 block size (Z_pad in RFC 9380 expand_message_xmd).
const sha256_z_pad: ByteArray =
  #"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"

// ── the BSB22 commitment hash-to-field (the new #9-class seam) ──
/// res = expand_message_xmd-SHA256("bsb22-commitment", commitment.Marshal(), 48 B) → big-endian
/// → mod r — bit-identical to gnark's fr.Hash. msg is the 96 B UNCOMPRESSED commitment (exactly
/// what gnark hashes), 48 output bytes (L = 16 + 32 for 128-bit security), ell = 2 SHA-256 blocks.
pub fn hash_to_field_bsb22(commitment_uncompressed: ByteArray) -> Int {
  hash_to_field(commitment_uncompressed, bsb22_dst)
}

/// expand_message_xmd-SHA256 (RFC 9380 §5.3, 48 B output) → big-endian → mod r, parameterized
/// by the DST. The DST is load-bearing: a wrong DST → a different field element (groth16_test
/// proves it). `hash_to_field_bsb22` fixes DST = "bsb22-commitment".
pub fn hash_to_field(message: ByteArray, dst: ByteArray) -> Int {
  // DST_prime = DST ‖ I2OSP(len(DST), 1)
  let dst_prime =
    builtin.append_bytearray(
      dst,
      builtin.integer_to_bytearray(True, 1, builtin.length_of_bytearray(dst)),
    )
  // msg_prime = Z_pad(64) ‖ msg ‖ I2OSP(48,2) ‖ I2OSP(0,1) ‖ DST_prime
  let msg_prime =
    sha256_z_pad
      |> builtin.append_bytearray(message)
      |> builtin.append_bytearray(builtin.integer_to_bytearray(True, 2, 48))
      |> builtin.append_bytearray(#"00")
      |> builtin.append_bytearray(dst_prime)
  let b0 = builtin.sha2_256(msg_prime)
  // b1 = SHA256(b0 ‖ 0x01 ‖ DST_prime)
  let b1 =
    builtin.sha2_256(
      b0
        |> builtin.append_bytearray(#"01")
        |> builtin.append_bytearray(dst_prime),
    )
  // b2 = SHA256((b0 XOR b1) ‖ 0x02 ‖ DST_prime)
  let b2 =
    builtin.sha2_256(
      builtin.xor_bytearray(False, b0, b1)
        |> builtin.append_bytearray(#"02")
        |> builtin.append_bytearray(dst_prime),
    )
  // uniform_bytes[0:48] = b1(32) ‖ b2[0:16]
  let uniform = builtin.append_bytearray(b1, builtin.slice_bytearray(0, 16, b2))
  builtin.bytearray_to_integer(True, uniform) % scalar_field
}

// ── coordinate / root packing (obligation 2) ──
// fold_fp: a 48-byte big-endian Fp coordinate → (lo, hi) = (coord mod 2^192, coord >> 192) =
// (big-endian last 24 bytes, big-endian first 24 bytes). Matches the circuit's FoldFp.
fn fold_fp(coordinate: ByteArray) -> (Int, Int) {
  (
    builtin.bytearray_to_integer(True, builtin.slice_bytearray(24, 24, coordinate)),
    builtin.bytearray_to_integer(True, builtin.slice_bytearray(0, 24, coordinate)),
  )
}

// pack_root: a 32-byte SSZ root → 2 Fr as big-endian 16-byte halves (.0 = high, .1 = low) —
// the LOCKED packRoot. Wrong endianness changes the Fr → the proof fails (obligation-2 risk).
pub fn pack_root(root: ByteArray) -> (Int, Int) {
  (
    builtin.bytearray_to_integer(True, builtin.slice_bytearray(0, 16, root)),
    builtin.bytearray_to_integer(True, builtin.slice_bytearray(16, 16, root)),
  )
}

// ── the 12 public inputs, re-derived from the datum/redeemer (obligations 1+2) ──
/// In gnark's declared order: PubkeysCommitment, ApkPacked[0..3], Count,
/// AttestedHeaderRootPacked[0..1], FinalizedHeaderRootPacked[0..1], FinalizedSlot, then the
/// BSB22 commitment hash (the 12th, derived on-chain).
/// the 11 DECLARED Option-P publics (no BSB22 hash) — shared by the regular + boundary paths.
fn declared_regular(
  pubkeys_commitment: ByteArray,
  apk_uncompressed: ByteArray,
  count: Int,
  attested_header_root: ByteArray,
  finalized_header_root: ByteArray,
  finalized_slot: Int,
) -> List<Int> {
  let apk_x = builtin.slice_bytearray(0, 48, apk_uncompressed)
  let apk_y = builtin.slice_bytearray(48, 48, apk_uncompressed)
  let (apk_x_lo, apk_x_hi) = fold_fp(apk_x)
  let (apk_y_lo, apk_y_hi) = fold_fp(apk_y)
  let (attested_0, attested_1) = pack_root(attested_header_root)
  let (finalized_0, finalized_1) = pack_root(finalized_header_root)
  [
    builtin.bytearray_to_integer(True, pubkeys_commitment),
    apk_x_lo,
    apk_x_hi,
    apk_y_lo,
    apk_y_hi,
    count,
    attested_0,
    attested_1,
    finalized_0,
    finalized_1,
    finalized_slot,
  ]
}

/// the FULL regular publics (11 declared + the BSB22 12th). Exposed for the re-derivation
/// cross-check in groth16_test (matches gnark's public witness + the appended commitment hash).
pub fn derive_publics(
  pubkeys_commitment: ByteArray,
  apk_uncompressed: ByteArray,
  count: Int,
  attested_header_root: ByteArray,
  finalized_header_root: ByteArray,
  finalized_slot: Int,
  commitment_uncompressed: ByteArray,
) -> List<Int> {
  list.concat(
    declared_regular(
      pubkeys_commitment,
      apk_uncompressed,
      count,
      attested_header_root,
      finalized_header_root,
      finalized_slot,
    ),
    [hash_to_field_bsb22(commitment_uncompressed)],
  )
}

// ── the augmented public-input MSM (obligation 2) ──
// L = ic[0] + Σ publics[i]·ic[i+1] + commitment_point.
fn msm(ic: List<ByteArray>, publics: List<Int>, commitment_point: G1Element) -> G1Element {
  expect [ic0, ..ic_rest] = ic
  let accumulated = fold_msm(ic_rest, publics, builtin.bls12_381_g1_uncompress(ic0))
  builtin.bls12_381_g1_add(accumulated, commitment_point)
}

fn fold_msm(ic: List<ByteArray>, publics: List<Int>, acc: G1Element) -> G1Element {
  when (ic, publics) is {
    ([ic_i, ..ic_rest], [pub_i, ..pub_rest]) -> {
      let term =
        builtin.bls12_381_g1_scalar_mul(pub_i, builtin.bls12_381_g1_uncompress(ic_i))
      fold_msm(ic_rest, pub_rest, builtin.bls12_381_g1_add(acc, term))
    }
    _ -> acc
  }
}

// ── the Pedersen PoK (single commitment): e(commitment, GSigmaNeg) == e(pok, −G) ──
fn pok_ok(
  commitment_point: G1Element,
  pok: G1Element,
  g: G2Element,
  g_sigma_neg: G2Element,
) -> Bool {
  builtin.bls12_381_final_verify(
    builtin.bls12_381_miller_loop(commitment_point, g_sigma_neg),
    builtin.bls12_381_miller_loop(pok, builtin.bls12_381_g2_neg(g)),
  )
}

// ── the main Groth16 pairing: e(A,B)·e(L,−γ)·e(C,−δ) == e(α,β) (4 Miller loops, D1) ──
fn main_ok(
  a: G1Element,
  b: G2Element,
  c: G1Element,
  l: G1Element,
  alpha: G1Element,
  beta: G2Element,
  neg_gamma: G2Element,
  neg_delta: G2Element,
) -> Bool {
  let ml1 = builtin.bls12_381_miller_loop(a, b)
  let ml2 = builtin.bls12_381_miller_loop(l, neg_gamma)
  let ml3 = builtin.bls12_381_miller_loop(c, neg_delta)
  let lhs =
    builtin.bls12_381_mul_miller_loop_result(
      builtin.bls12_381_mul_miller_loop_result(ml1, ml2),
      ml3,
    )
  let ml4 = builtin.bls12_381_miller_loop(alpha, beta)
  builtin.bls12_381_final_verify(lhs, ml4)
}

// ── the full commitment-augmented verification ──
// ── the shared verification core (generic over the declared-publics length) ──
/// Appends the BSB22 commitment hash to the declared publics, reconstructs the commitment point,
/// runs the augmented MSM + the Pedersen PoK + the 4-ML main check. Regular (11 declared) and
/// boundary (12 declared) share this — the regular path is toy-proven; the boundary is
/// structurally regular + 1 declared public + 1 IC (validated at the AWS full-512 boundary proof).
fn verify_core(
  vk: Groth16VerifyingKey,
  proof: Groth16Proof,
  declared_publics: List<Int>,
) -> Bool {
  let publics =
    list.concat(declared_publics, [hash_to_field_bsb22(proof.commitment)])
  let commitment_point = g1_from_uncompressed(proof.commitment)
  let l = msm(vk.ic, publics, commitment_point)
  and {
    // the Pedersen PoK (the commitment opening is known)
    pok_ok(
      commitment_point,
      builtin.bls12_381_g1_uncompress(proof.commitment_pok),
      builtin.bls12_381_g2_uncompress(vk.commitment_g),
      builtin.bls12_381_g2_uncompress(vk.commitment_g_sigma_neg),
    ),
    // the main Groth16 check
    main_ok(
      builtin.bls12_381_g1_uncompress(proof.a),
      builtin.bls12_381_g2_uncompress(proof.b),
      builtin.bls12_381_g1_uncompress(proof.c),
      l,
      builtin.bls12_381_g1_uncompress(vk.alpha),
      builtin.bls12_381_g2_uncompress(vk.beta),
      builtin.bls12_381_g2_neg(builtin.bls12_381_g2_uncompress(vk.gamma)),
      builtin.bls12_381_g2_neg(builtin.bls12_381_g2_uncompress(vk.delta)),
    ),
  }
}

/// REGULAR Phase-A verification — the 11 declared Option-P publics. Toy-proven (groth16_test).
pub fn verify_regular(
  vk: Groth16VerifyingKey,
  proof: Groth16Proof,
  pubkeys_commitment: ByteArray,
  apk_uncompressed: ByteArray,
  count: Int,
  attested_header_root: ByteArray,
  finalized_header_root: ByteArray,
  finalized_slot: Int,
) -> Bool {
  verify_core(
    vk,
    proof,
    declared_regular(
      pubkeys_commitment,
      apk_uncompressed,
      count,
      attested_header_root,
      finalized_header_root,
      finalized_slot,
    ),
  )
}

/// BOUNDARY Phase-A verification — the regular 11 declared + the 12th NextPubkeysCommitment.
/// Structurally verify_regular + 1 public + 1 IC; its first on-chain validation is the AWS
/// full-512 boundary proof (the boundary witness is full-size only, not toy-testable).
pub fn verify_boundary(
  vk: Groth16VerifyingKey,
  proof: Groth16Proof,
  pubkeys_commitment: ByteArray,
  apk_uncompressed: ByteArray,
  count: Int,
  attested_header_root: ByteArray,
  finalized_header_root: ByteArray,
  finalized_slot: Int,
  next_pubkeys_commitment: ByteArray,
) -> Bool {
  verify_core(
    vk,
    proof,
    list.concat(
      declared_regular(
        pubkeys_commitment,
        apk_uncompressed,
        count,
        attested_header_root,
        finalized_header_root,
        finalized_slot,
      ),
      [builtin.bytearray_to_integer(True, next_pubkeys_commitment)],
    ),
  )
}
