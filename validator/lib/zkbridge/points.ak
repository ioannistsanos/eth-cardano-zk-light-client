//// Shared BLS12-381 point reconstruction — the §2/§3 single-source link. Both the Groth16
//// verifier (groth16.ak — folds the apk's 96 B into ApkPacked for the MSM) and the BLS verifier
//// (bls.ak — reconstructs the apk POINT for the pairing) consume the SAME redeemer.apk (96 B
//// uncompressed X‖Y) through THIS one function, so the two consumers can never diverge.

use aiken/builtin

// BLS12-381 base field modulus p (Fp) — for the largest-y sign bit.
const base_field: Int =
  4002409555221667393417789825735904156556882819939007885332058136124031650490837864442687629129015664037894272559787

/// Reconstruct a CIP-381 G1 point from its uncompressed 96-byte X‖Y: compress to X with the ZCash
/// flags (compression 0x80 + the largest-y sign 0x20 when 2Y > p−1) then STRICT-uncompress
/// (validates on-curve + subgroup; rejects malformed). X's top 3 bits are 0 (X < 2^381), so the
/// flag OR is clean.
pub fn g1_from_uncompressed(uncompressed: ByteArray) -> G1Element {
  let y =
    builtin.bytearray_to_integer(True, builtin.slice_bytearray(48, 48, uncompressed))
  let sign_flag =
    if y * 2 > base_field - 1 {
      0x20
    } else {
      0x00
    }
  let first = builtin.index_bytearray(uncompressed, 0) + 0x80 + sign_flag
  let compressed =
    builtin.cons_bytearray(first, builtin.slice_bytearray(1, 47, uncompressed))
  builtin.bls12_381_g1_uncompress(compressed)
}
