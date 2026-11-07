//// Phase-3 Layer 3 — the on-chain BLS aggregate-signature verifier (obligation #3). The thesis's
//// hybrid split: the pairing-heavy sync-committee signature check runs ON-CHAIN via CIP-381
//// (§2.1.3/§3.3), NOT in-circuit. It verifies the real Ethereum sync-committee aggregate signature:
//// the signing-root chain (ForkData → Domain → SigningData, per [1b], anchors read from the
//// Layer-1-frozen datum), hashToGroup with the Ethereum DST, and the two-pairing aggregate check
//// e(g1, σ) == e(apk, H(m)) — the canonical CIP-381 form (no mulMlResult; D2).
////
//// The signing-root SSZ layout is a SILENT seam (a wrong byte fails only on a real signature) —
//// SELF-CHECKED by the real period-1600 σ verifying on-chain (bls_test.ak), with the domain +
//// signing_root cross-checks localizing any bug pre-pairing.

use aiken/builtin
use zkbridge/points.{g1_from_uncompressed}

// DOMAIN_SYNC_COMMITTEE (Ethereum consensus constant).
const domain_sync_committee: ByteArray = #"07000000"

// 28 zero bytes — the right-padding of the 4-byte fork Version to a 32-byte SSZ chunk (ForkData).
const fork_version_pad: ByteArray =
  #"00000000000000000000000000000000000000000000000000000000"

// The Ethereum sync-committee signature DST (RFC 9380 ciphersuite, 43 bytes):
// "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_". A DST mismatch fails silently on real signatures.
const ethereum_dst: ByteArray =
  #"424c535f5349475f424c53313233383147325f584d443a5348412d3235365f535357555f524f5f504f505f"

// The canonical BLS12-381 G1 generator, compressed (48 B) — uncompressed in the check.
const g1_generator_compressed: ByteArray =
  #"97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb"

// The 2/3 supermajority: ceil(512 * 2/3) = 342 (obligation #4; the threshold is enforced in bridge.ak).
pub const participation_threshold: Int = 342

/// compute_domain = DOMAIN_SYNC_COMMITTEE ‖ fork_data_root[0:28], where
/// fork_data_root = sha2_256( fork_version ‖ 28·0x00 ‖ genesis_validators_root ) — the 2-chunk
/// ForkData container (version right-padded to a 32-byte chunk).
pub fn compute_domain(
  fork_version: ByteArray,
  genesis_validators_root: ByteArray,
) -> ByteArray {
  let fork_data_root =
    builtin.sha2_256(
      fork_version
        |> builtin.append_bytearray(fork_version_pad)
        |> builtin.append_bytearray(genesis_validators_root),
    )
  builtin.append_bytearray(
    domain_sync_committee,
    builtin.slice_bytearray(0, 28, fork_data_root),
  )
}

/// compute_signing_root = sha2_256( object_root ‖ domain ) — the SigningData container.
pub fn compute_signing_root(object_root: ByteArray, domain: ByteArray) -> ByteArray {
  builtin.sha2_256(builtin.append_bytearray(object_root, domain))
}

/// The aggregate-signature verification (obligation #3): the signing-root chain from the datum
/// anchors + the redeemer's attested root, hashToGroup, and e(g1, σ) == e(apk, H(m)). σ is strict-
/// uncompressed (G2); apk is reconstructed from the SAME 96 B the Groth16 MSM folds (points.ak).
pub fn verify(
  fork_version: ByteArray,
  genesis_validators_root: ByteArray,
  attested_header_root: ByteArray,
  signature_compressed: ByteArray,
  apk_uncompressed: ByteArray,
) -> Bool {
  let domain = compute_domain(fork_version, genesis_validators_root)
  let signing_root = compute_signing_root(attested_header_root, domain)
  let message_point = builtin.bls12_381_g2_hash_to_group(signing_root, ethereum_dst)
  let signature = builtin.bls12_381_g2_uncompress(signature_compressed)
  let apk = g1_from_uncompressed(apk_uncompressed)
  let generator = builtin.bls12_381_g1_uncompress(g1_generator_compressed)
  // e(g1, σ) == e(apk, H(m)) — the canonical two-pairing aggregate check (no mulMlResult; D2).
  builtin.bls12_381_final_verify(
    builtin.bls12_381_miller_loop(generator, signature),
    builtin.bls12_381_miller_loop(apk, message_point),
  )
}
