//// Phase-A spending validator. Layer 1 enforces the state-machine invariants that DON'T need
//// the crypto: state-thread NFT continuity (#8), anchor bit-identity (#5), and the structural
//// partition (committee commitments frozen on a regular tx). The crypto + value-update logic
//// slot into the `// Layer N` markers in later layers. Parameterized by the state-thread NFT's
//// policy id (the one-shot minting policy's hash).

use cardano/address.{Address, Script}
use cardano/assets.{PolicyId, Value, from_asset, from_lovelace, merge}
use cardano/transaction.{
  InlineDatum, Input, Output, OutputReference, Transaction, placeholder,
}
use zkbridge/bls
use zkbridge/groth16
use zkbridge/types.{
  Boundary, Datum, Groth16Proof, Groth16VerifyingKey, Redeemer, Regular,
  bridge_state_token_name,
}
use zkbridge/validation.{
  anchors_preserved, committee_rotated, committees_frozen, continuing_state_output,
  read_datum, slot_advances,
}
use zkbridge/real_n512_regular

validator bridge(state_token: PolicyId) {
  spend(
    datum: Option<Datum>,
    redeemer: Redeemer,
    utxo: OutputReference,
    self: Transaction,
  ) {
    expect Some(input_datum) = datum

    // Layer 1 — obligation #8: the state-thread NFT threads to EXACTLY ONE continuing output
    // at this script's address (no fork/dup, no escape/capture; burn implicitly rejected).
    let continuing = continuing_state_output(
      self,
      utxo,
      state_token,
      bridge_state_token_name,
    )
    // §2: read the new state from that output's inline datum (rejects missing/malformed).
    let output_datum = read_datum(continuing)

    // Layer 1 — obligation #5: the four protocol-anchor fields are bit-identical input↔output.
    expect anchors_preserved(input_datum, output_datum)

    when redeemer.kind is {
      Regular -> {
        // Layer 1 — partition: committee commitments are FROZEN on a regular tx (boundary-only
        // mutability; nothing binds them on the regular path, so they must not change).
        expect committees_frozen(input_datum, output_datum)
        // Layer 2 — obligations #1/#2/#9: Groth16 verify vs the 11 packed publics. pubkeys_commitment
        // ← input.current; the new finalized root/slot ← the OUTPUT datum (bound to the proof).
        expect
          groth16.verify_regular(
            input_datum.verifying_key_regular,
            redeemer.proof,
            input_datum.current_committee_commitment,
            redeemer.apk,
            redeemer.count,
            redeemer.attested_header_root,
            output_datum.finalized_header_root,
            output_datum.finalized_slot,
          )
        // Layer 3 — obligations #4 then #3: the 2/3 threshold (cheap) then the BLS aggregate verify
        // over the signing_root (domain anchors from the datum; apk reconstructed from the same 96 B).
        expect redeemer.count >= bls.participation_threshold
        expect
          bls.verify(
            input_datum.fork_version,
            input_datum.genesis_validators_root,
            redeemer.attested_header_root,
            redeemer.signature,
            redeemer.apk,
          )
        // Layer 4 — obligation #6: finalized_slot strictly forward-only (rollback defense).
        expect slot_advances(input_datum, output_datum)
        True
      }
      Boundary -> {
        // Layer 1 — partition: committee commitments MAY change on a boundary tx (Layer 5 binds
        // the rotation VALUES: current ← input.next, next ← proof.next_pubkeys_commitment).
        // Layer 2 — obligations #1/#2/#9: Groth16 verify vs the 12 packed publics. #7 bindings:
        // pubkeys_commitment ← input.NEXT (the signing committee), the 12th public ← output.next
        // (the new next installed). Structurally regular + 1 public; AWS-first (no toy boundary proof).
        expect
          groth16.verify_boundary(
            input_datum.verifying_key_boundary,
            redeemer.proof,
            input_datum.next_committee_commitment,
            redeemer.apk,
            redeemer.count,
            redeemer.attested_header_root,
            output_datum.finalized_header_root,
            output_datum.finalized_slot,
            output_datum.next_committee_commitment,
          )
        // Layer 3 — obligations #4 then #3: the 2/3 threshold then the BLS aggregate verify.
        expect redeemer.count >= bls.participation_threshold
        expect
          bls.verify(
            input_datum.fork_version,
            input_datum.genesis_validators_root,
            redeemer.attested_header_root,
            redeemer.signature,
            redeemer.apk,
          )
        // Layer 4 — obligation #6: finalized_slot strictly forward-only.
        expect slot_advances(input_datum, output_datum)
        // Layer 5 — obligation #7: the committee PROMOTION (output.current ← input.next). The
        // installation (output.next) is proof-bound (op-6); the signer (input.next) gates a real
        // boundary (the proof+BLS, no on-chain period arithmetic — see docs/records.md D21).
        expect committee_rotated(input_datum, output_datum)
        True
      }
    }
  }

  // Spend-only validator: any other script purpose is rejected.
  else(_) {
    fail
  }
}

// ─────────────────── Layer-2b: the first FULL-VALIDATOR emulated regular tx ───────────────────
// Layer 1 (NFT continuity + anchors + committee freeze) AND Layer 2 (Groth16 verify) end-to-end,
// the toy n=8 fixture's crypto inside the real validator. Generated from the fixture.

// §5 consistency tension: the toy fixture's count=8 < 342, so the FULL validator (now with Layer 3's
// threshold) correctly REJECTS it — proving Layer 1 + Layer 2 run AND the threshold polices,
// end-to-end. A bridge-level POSITIVE needs a consistent count≥342 instance — AWS-first (the real
// n=512 proof + real σ + count=510 align there). Layer 3's isolated correctness is bls_test.ak.
test full_validator_rejects_low_count() fail {
  bridge.spend(
    test_state_token,
    Some(test_input_datum()),
    test_redeemer(),
    test_own_ref(),
    test_tx(),
  )
}

// integration negative: a tampered redeemer count → verify_regular False → the spend rejects.
test full_validator_wrong_count_rejects() fail {
  let bad = Redeemer { ..test_redeemer(), count: test_count + 1 }
  bridge.spend(
    test_state_token,
    Some(test_input_datum()),
    bad,
    test_own_ref(),
    test_tx(),
  )
}

// ── fixture crypto ──
const test_vk_alpha: ByteArray =
  #"94b7e59a9b17b193b22370b811b07a7faa0b96c8afe6624f34f72d3b1dcc963cb01bd917c4267a934c4df1206683b920"

const test_vk_beta: ByteArray =
  #"ae89c28e2d0f6469321da5f54e963d84b90dae93da77cecb01879fb98425aab201eb0d614e01c2bc6bcea57cb35d048b1927c231c33f9bdf1c677a253213d62e8a649aa411bb5c4516cd6122400b6564ebed2abab596be42ba31465b64bac789"

const test_vk_gamma: ByteArray =
  #"b2338dda32ba316f40bf800792d7f3e593e2831bd0210684de9f24d1c5aaa9b1f30b27f35bd85637b2effc9477d5587017e146d2eba61f1e38b367fbfc89a49aebc67c1e0e8aa4106763da27a8f770ae42f79c398868be246afd89bc260d8861"

const test_vk_delta: ByteArray =
  #"90f1c93b966a82999cc1926244c5b289918b067834c40f5f6f9e95277443d0b53c7e65d11a28d0330045e144344d3f0707b07d0296d92e48bd67e5aa4d2accf65135aba9de23c2555062f6af5ae2872a85362a4099e703dc62f22f0c1a5a607d"

const test_vk_commitment_g: ByteArray =
  #"b97bce82c9ed12a9285583442f753a050ed7289c2302c002e5614ce5127c2e662a8127efb670a02dcbeb11ab4983392f03943a22f2940d5f49836f404c81aee29c8c75323ccc2328aad1893767462cb4e79bb4bc7e929ad221a7b2ea4b645377"

const test_vk_commitment_g_sigma_neg: ByteArray =
  #"aed8908b9fd5a455da52fd81719c5706c3df5d26c6c07b3a23fa5354e5e11520024258503aac828c677ec5ff92bc2adf101a2312fd65f27f45eaa1131813026826c6dbfebe5e6be391bb7502d84ef99ce4f4a55268554aeef6ff5089e41d59ac"

const test_proof_a: ByteArray =
  #"94b95cfe3e6e99d5b698d9ee2d92d1b5c94f2d7231d6871c6cd0e73a61fcc4ab6ef7acfec25e08f1333271c68a0cd809"

const test_proof_b: ByteArray =
  #"95d4fce477f2c8dd0358f728b7d83da31d950ec9f2e8cc8a264b41eb859b846eccd6a142458ec66dcd83a1197a0432b704a2b50ff53a6dbbc76e5633ea9e8fbdcae810db0ee34e69547ac639019e032b500f86114994f1439c7384923e1f7b02"

const test_proof_c: ByteArray =
  #"abaab30e3f1c5ea200985e93fc166522ad8a39c60a719b9f90e191599a9885ea79e3bd7d0fc85e52318d708366cf8d09"

const test_proof_commitment: ByteArray =
  #"0bb38d5db29b9e6d8ab98dec4ccb06f0b47bea1918b9197b5f4b199e43ff13795f5886a067da21a103f4570a14f57d79022d52ae22a988423192680284dd545cd840e3d133038337875a61b890112d8e0903053f63da3592daa8a13dd03c5f47"

const test_proof_commitment_pok: ByteArray =
  #"a420abe903cdd381750db9396be001745f20bb8c1f1edf851cfba35e18d2f8ba0d7c8dca783997e644b0ae2c9c4277f9"

const test_current_commitment: ByteArray =
  #"24e1330c0064f2e943db80522452f9fa4db3422554342655297820b11ad601d0"

const test_apk: ByteArray =
  #"009509fef0f7ce988760648d313397dbd56c2c0155926ca6fdb2f7562a8cf8ad116ccda3387e5958895ab3092cc4149016e3b3c5386a5db1fe70efa4451de851bfdb212c836ff048cbc021415ad4aefaf83d644443b1d12050054483623a4ea1"

const test_attested_root: ByteArray =
  #"7099a98d437bc51344b7cad28193da1a9d51d79fba141b4ebb2afcd81242a52d"

const test_finalized_root: ByteArray =
  #"201a1d12d634bcf8de5a9281d8cf5974cb775be0f8741a1cf0123e0383878599"

const test_count: Int = 8

const test_finalized_slot: Int = 13107200

fn test_ic() -> List<ByteArray> {
  [
    #"a72eeb7078a63f7a38153a9f59a205b3400a26228a39e033ce86bc067732e06a1268863b3a8d7c48852a155d6fcb2198",
    #"a5df12685638f1b97bc41481e901a4f8e0b1a2ff6cb976145dccba50aa0718ba2a99d328e90c435a34b7dfa890c0f828",
    #"b63c59c2d9bf3752a1f7cf3f36097cc3d534a22224053551e5658d62dfc13996a9d6a37dc8937aeebbff70169f69a135",
    #"8a077c730f9a2195c8593a933a3ea02e783c08a67e2546c00a07ec0badb4979ebc803ace5b19c43d97d05c16a7beb623",
    #"b9261b3fbe1aea09541d444cb119ae820c9bb23a68a2faff55acaea58ee4d646177be6f68ad9d817209dcf8c5e64ffd3",
    #"aa1c14956ac9744b98c584711bdcf717a47f95d76acf5357c2425ab77808995f1a0ba0990dcf28266f2793804f7932a3",
    #"a392303310a58a7ea60ccd43853066a0e9e20c315d0cd0dbf16772d243a66438170af14d927eed42796163e5f7b26e6a",
    #"a16f7cf4d669e8dfcc54e9f40e3d4ae2b27d47b5fa9f6eb9ebb6bcb04792d8e8339d12f47c1c9134d7d94acb99d86fbb",
    #"92f80fb2d3019d02bbde36edab15029faec25722ed60edc09c2eee6a5e144cebb28ec1ffbbc642a954f64d62d2b803ad",
    #"91dcf12bb705e135f2dacf830510e0b7e8da76865d4c3db82dea44c7369ff94f9da815b641aa591aab463898bb9f3b19",
    #"827f5d0cae5afa035b887854397d99e84687f5a66ab38f78aeade8cf37e51f7c1b901ba454fd91ec6e44f25f6cf1fd84",
    #"b00b9771bb1b6d7df9237420a1ab4f65ec25ddd46759ac08ba6700bb5ad6a13084e96434f7f06584c5957f8f274c61d4",
    #"b805314f13a0349534ce8f7e78c08dbb4983c8e0e55690c532a43024e85825d6a728853adb2b7967cf601679840990b9",
  ]
}

fn test_vk_record() -> Groth16VerifyingKey {
  Groth16VerifyingKey {
    alpha: test_vk_alpha,
    beta: test_vk_beta,
    gamma: test_vk_gamma,
    delta: test_vk_delta,
    ic: test_ic(),
    commitment_g: test_vk_commitment_g,
    commitment_g_sigma_neg: test_vk_commitment_g_sigma_neg,
  }
}

// ── mock infra (anchors held identical in↔out; only finalized_* change) ──
const test_state_token: ByteArray =
  #"5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e"

const test_script: ByteArray =
  #"b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1"

const test_next_commitment: ByteArray =
  #"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"

const test_fork: ByteArray = #"05000000"

const test_gvr: ByteArray =
  #"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

const test_old_finalized: ByteArray =
  #"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

fn test_datum(finalized_root: ByteArray, finalized_slot: Int) -> Datum {
  Datum {
    finalized_header_root: finalized_root,
    finalized_slot,
    current_committee_commitment: test_current_commitment,
    next_committee_commitment: test_next_commitment,
    fork_version: test_fork,
    genesis_validators_root: test_gvr,
    verifying_key_regular: test_vk_record(),
    verifying_key_boundary: test_vk_record(),
  }
}

fn test_input_datum() -> Datum {
  test_datum(test_old_finalized, test_finalized_slot - 1)
}

fn test_output_datum() -> Datum {
  test_datum(test_finalized_root, test_finalized_slot)
}

fn test_redeemer() -> Redeemer {
  Redeemer {
    kind: Regular,
    proof: Groth16Proof {
      a: test_proof_a,
      b: test_proof_b,
      c: test_proof_c,
      commitment: test_proof_commitment,
      commitment_pok: test_proof_commitment_pok,
    },
    apk: test_apk,
    signature: test_proof_b,
    count: test_count,
    attested_header_root: test_attested_root,
  }
}

fn test_address() -> Address {
  Address { payment_credential: Script(test_script), stake_credential: None }
}

fn test_nft_value() -> Value {
  merge(
    from_lovelace(2_000_000),
    from_asset(test_state_token, bridge_state_token_name, 1),
  )
}

fn test_own_ref() -> OutputReference {
  OutputReference {
    transaction_id: #"0101010101010101010101010101010101010101010101010101010101010101",
    output_index: 0,
  }
}

fn test_output(d: Datum) -> Output {
  Output {
    address: test_address(),
    value: test_nft_value(),
    datum: InlineDatum(d),
    reference_script: None,
  }
}

fn test_tx() -> Transaction {
  Transaction {
    ..placeholder,
    inputs: [
      Input {
        output_reference: test_own_ref(),
        output: test_output(test_input_datum()),
      },
    ],
    outputs: [test_output(test_output_datum())],
  }
}

// ── GATE 1 (redeemer seam) — the D24-unblocked ALL-REAL full-validator positive ──
// The real n=512 regular proof + the real period-1600 σ/apk (count 510) through bridge.spend's full
// Regular path (all five layers, ONE eval). The first time real n=512 meets the validator (today:
// groth16_test is toy n=8; bls_test is real-σ isolated; D20's 5.94B was additive blocks). Data lives
// in lib/zkbridge/real_n512_regular.ak (generated; commitment UNCOMPRESSED via proof_to_redeemer).
// Pre-registered ExUnits ~5.94B (verify_regular N-independent ≈ toy 4.60B + bls 1.19B + Layer-1).
test full_validator_real_regular_positive() {
  bridge.spend(
    real_n512_regular.state_token,
    Some(real_n512_regular.real_input_datum()),
    real_n512_regular.real_redeemer(),
    real_n512_regular.own_ref(),
    real_n512_regular.real_tx(),
  )
}
