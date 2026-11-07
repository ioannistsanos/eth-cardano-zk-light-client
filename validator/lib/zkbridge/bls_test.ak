//// Phase-3 Layer 3 gate — THE ALL-REAL POSITIVE: the real period-1600 Ethereum sync-committee
//// aggregate signature verifies on-chain through the full chain (datum anchors → fork_data_root →
//// domain → signing_root → hashToGroup(DST) → reconstructions → e(g1,σ)==e(apk,H)). Any byte off
//// — the ForkData layout, the [0:28] slice, SigningData, the DST, the reconstruction, the pairing
//// orientation — fails the pairing, so a pass proves the entire chain bit-correct. All-real data
//// (no toy, no AWS); generated from validator/fixtures/bls_regular_period1600.json.

use aiken/builtin
use zkbridge/bls
use zkbridge/points

// ── the real period-1600 instance ──
const signature: ByteArray =
  #"a29333064a2b8325fb735901b7b074dc5058cef518a5b8d885c2eac7b19a89b550486facf50f12a74eec5246b9084e690207f0924a9fc237f5dfbc712f02b3413660f0523d7bd465a202cfc4b12ddc451aadb4d7967bdd3f569932aa41237508"

const apk_uncompressed: ByteArray =
  #"07e8712375cb3ec0748d8f1e92eba1ff3b75baf1de7ddbb3aab34745ce511545dbd63d330143e1ff93b14cbd866cda8701c0e46b20269f6ce652b1e8f39260be61da84e112f732628f2ae9feb7c0db1434353c965068d204f13e999413ca1002"

const fork_version: ByteArray = #"05000000"

const genesis_validators_root: ByteArray =
  #"4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95"

const attested_header_root: ByteArray =
  #"7099a98d437bc51344b7cad28193da1a9d51d79fba141b4ebb2afcd81242a52d"

const expected_domain: ByteArray =
  #"07000000ad532ceb9ec5d246daad29da8aa157bfdab35e5f069f9db81f1da754"

const expected_signing_root: ByteArray =
  #"179e351be2b0bc73cd80dbd411b37c57ad5fa776d47ba99835cf48f568309f1f"

const count: Int = 510

// the toy Groth16 fixture apk (8-key, a VALID G1 point but the WRONG committee) — a wrong-apk negative
const toy_apk: ByteArray =
  #"009509fef0f7ce988760648d313397dbd56c2c0155926ca6fdb2f7562a8cf8ad116ccda3387e5958895ab3092cc4149016e3b3c5386a5db1fe70efa4451de851bfdb212c836ff048cbc021415ad4aefaf83d644443b1d12050054483623a4ea1"

const g1_generator: ByteArray =
  #"97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb"

// 1. domain cross-check (precise locus, pre-pairing).
test domain_matches_golden() {
  bls.compute_domain(fork_version, genesis_validators_root) == expected_domain
}

// 2. signing_root cross-check.
test signing_root_matches_golden() {
  bls.compute_signing_root(
    attested_header_root,
    bls.compute_domain(fork_version, genesis_validators_root),
  ) == expected_signing_root
}

// 3. THE LINCHPIN — the real period-1600 σ verifies on-chain under the real apk.
test real_signature_verifies() {
  bls.verify(
    fork_version,
    genesis_validators_root,
    attested_header_root,
    signature,
    apk_uncompressed,
  )
}

// 4. domain separation is load-bearing — a tampered fork_version → different domain → reject.
test tampered_fork_version_rejects() {
  bls.verify(
    #"06000000",
    genesis_validators_root,
    attested_header_root,
    signature,
    apk_uncompressed,
  ) == False
}

// 5. tampered gvr → different domain → reject.
test tampered_gvr_rejects() {
  let bad = builtin.cons_bytearray(
    0,
    builtin.slice_bytearray(1, 31, genesis_validators_root),
  )
  bls.verify(
    fork_version,
    bad,
    attested_header_root,
    signature,
    apk_uncompressed,
  ) == False
}

// 6. tampered attested root → different signing_root → reject.
test tampered_attested_root_rejects() {
  let bad = builtin.cons_bytearray(
    0,
    builtin.slice_bytearray(1, 31, attested_header_root),
  )
  bls.verify(
    fork_version,
    genesis_validators_root,
    bad,
    signature,
    apk_uncompressed,
  ) == False
}

// 7. a wrong apk (the toy 8-key aggregate — valid G1, wrong committee) → reject.
test wrong_apk_rejects() {
  bls.verify(
    fork_version,
    genesis_validators_root,
    attested_header_root,
    signature,
    toy_apk,
  ) == False
}

// 8. the DST is load-bearing — a wrong DST → a different H(m) → reject (inline, no validator change).
test wrong_dst_rejects() {
  let domain = bls.compute_domain(fork_version, genesis_validators_root)
  let signing_root = bls.compute_signing_root(attested_header_root, domain)
  let h_wrong = builtin.bls12_381_g2_hash_to_group(
    signing_root,
    "WRONG_DST_NOT_ETHEREUM",
  )
  let sig = builtin.bls12_381_g2_uncompress(signature)
  let apk = points.g1_from_uncompressed(apk_uncompressed)
  let gen = builtin.bls12_381_g1_uncompress(g1_generator)
  builtin.bls12_381_final_verify(
    builtin.bls12_381_miller_loop(gen, sig),
    builtin.bls12_381_miller_loop(apk, h_wrong),
  ) == False
}

// 9. #9 strict uncompress — a malformed σ rejects (not garbage).
test malformed_signature_rejects() fail {
  bls.verify(
    fork_version,
    genesis_validators_root,
    attested_header_root,
    #"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    apk_uncompressed,
  )
}

// 10. the threshold boundary (#4): 341 rejects, 342 meets — pins participation_threshold = 342.
test count_341_below_threshold() {
  !(341 >= bls.participation_threshold)
}

test count_342_meets_threshold() {
  342 >= bls.participation_threshold
}
