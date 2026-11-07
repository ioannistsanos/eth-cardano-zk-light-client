//// Layer 0 — the canonical Phase-A on-chain types (datum / redeemer / proof / vk).
////
//// SEC-01 + Option-P correct, SUPERSEDING the stale shapes in
//// lib/benchmarks/m7_datum_size.ak:
////   - committee identifiers are 32 B Poseidon COMMITMENTS (was 48 B G1) — the
////     Family-B fix; fed to the verifier as ONE Fr (raw Poseidon, < r, unpacked).
////   - the vk `ic` list has length ℓ+2 = 13 (regular) / 14 (boundary): ℓ+1 for the Option-P
////     public layout of 11 / 12 Fr and one for the commitment (was 7 / 8 in m7's pre-Option-P shape).
////
//// On-chain Plutus Data is POSITIONAL (field names never appear in the CBOR), so the
//// descriptive field names cost nothing and the interface (field ORDER) is unchanged.
////
//// All points are stored COMPRESSED (G1 48 B / G2 96 B) and uncompressed on-chain at
//// Layer 2 via bls12_381_g{1,2}_uncompress — the #9 serialization seam.

use cardano/assets.{AssetName}

// ── Groth16 proof (D19: COMMITMENT-AUGMENTED) — 5 points ──
pub type Groth16Proof {
  a: ByteArray,
  // G1, 48 B compressed (A = Ar)
  b: ByteArray,
  // G2, 96 B compressed (B = Bs)
  c: ByteArray,
  // G1, 48 B compressed (C = Krs)
  commitment: ByteArray,
  // G1, 96 B UNCOMPRESSED X‖Y — gnark hashes Commitments[0].Marshal() for the BSB22 12th
  // public, so the validator hashes the SAME bytes AND reconstructs the point (groth16.ak)
  commitment_pok: ByteArray,
  // G1, 48 B compressed — the Pedersen proof of knowledge (CommitmentPok)
}

// ── Groth16 verifying key (D19: COMMITMENT-AUGMENTED) ──
//// ic = ℓ+2 G1 (the ℓ+1 Option-P IC + 1 commitment IC) = 13 regular / 14 boundary; plus the
//// Pedersen commitment key (2 G2). The full datum vk = 14/15 G1 + 5 G2 (D19).
pub type Groth16VerifyingKey {
  alpha: ByteArray,
  // G1, 48 B
  beta: ByteArray,
  // G2, 96 B
  gamma: ByteArray,
  // G2, 96 B
  delta: ByteArray,
  // G2, 96 B
  ic: List<ByteArray>,
  // G1, 48 B each — length 13 (regular) / 14 (boundary)
  commitment_g: ByteArray,
  // G2, 96 B — pedersen vk.G
  commitment_g_sigma_neg: ByteArray,
  // G2, 96 B — pedersen vk.GSigmaNeg = G^{-σ}
}

// ── the 8-field bridge datum (anchor vs mutable partition in the comments) ──
pub type Datum {
  finalized_header_root: ByteArray,
  // Bytes32 — mutable, every tx
  finalized_slot: Int,
  // uint64 — mutable, every tx
  current_committee_commitment: ByteArray,
  // Bytes32 Poseidon — mutable, boundary only
  next_committee_commitment: ByteArray,
  // Bytes32 Poseidon — mutable, boundary only
  fork_version: ByteArray,
  // Bytes4 — anchor (bit-identical every tx)
  genesis_validators_root: ByteArray,
  // Bytes32 — anchor
  verifying_key_regular: Groth16VerifyingKey,
  // 14 G1 + 5 G2 (1,152 B) — anchor
  verifying_key_boundary: Groth16VerifyingKey,
  // 15 G1 + 5 G2 (1,200 B) — anchor
}

// ── transition kind — the redeemer discriminant (which transition rules fire) ──
pub type TransitionKind {
  Regular
  Boundary
}

// ── the redeemer: ONLY the transient publics + proof + signature ──
//// The NEW state values (finalized_header_root, finalized_slot,
//// next_committee_commitment) are NOT carried here — they live in the OUTPUT datum,
//// bound to the proof, so the redeemer is minimal and IDENTICAL for Regular/Boundary
//// (the `kind` tag alone selects the rules; a field-divergent variant is unnecessary
//// and would let a boundary field ride a regular tx).
pub type Redeemer {
  kind: TransitionKind,
  proof: Groth16Proof,
  apk: ByteArray,
  // aggregate pubkey, UNCOMPRESSED G1 96 B (X‖Y) — Layer-2 finding (D19/§2): CIP-381 cannot read an
  // opaque point's coordinates, so the validator folds these 96 B into ApkPacked (4 Fr) for the
  // Groth16 MSM AND (Layer 3) reconstructs the BLS point from the SAME bytes (the single-source link).
  signature: ByteArray,
  // BLS aggregate signature, compressed G2 96 B
  count: Int,
  // participation → Count (1 Fr) + the ≥342 threshold
  attested_header_root: ByteArray,
  // Bytes32 transient → AttestedHeaderRootPacked (2 Fr) + the BLS signing_root
}

// ── the state-thread NFT's asset name ──
//// Shared by the minting policy (which ENFORCES it at the one-shot mint) and the spending
//// validator (which identifies the NFT as `(state_token, this)`). The (policy, name) pair is
//// the unique thread token; the one-shot policy guarantees the policy mints once, this name
//// pins the asset. (Plutus Data is positional, so the name is the only on-chain string.)
pub const bridge_state_token_name: AssetName = "zkbridge_state"
