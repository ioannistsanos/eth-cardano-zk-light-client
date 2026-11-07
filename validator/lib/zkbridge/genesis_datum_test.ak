//// Stage-1b — the datum CBOR seam: the load-bearing LOCAL closure of the Boot's #9-class risk.
////
//// The Boot tx ATTACHES the genesis datum as inline data, but NO script validates it at Boot (the
//// ledger only stores the bytes). The bytes are first DECODED at the AWS-gated FIRST SPEND — where
//// the ledger turns them into Option<Datum> and the validator casts `expect parsed: Datum`. If the
//// genesis bytes don't decode to a well-formed Datum, the bridge UTxO is UNSPENDABLE forever. This
//// test reproduces that exact first-spend decode LOCALLY (cbor.deserialise → expect Datum → ==),
//// so the unspendable-bridge risk surfaces here, for free, before any network step.
////
//// Aiken is the SOURCE OF TRUTH for the datum bytes (cbor.serialise of a constructed Datum); the
//// off-chain Boot builder (Stage-1c) embeds these bytes VERBATIM — it never hand-rolls the nested
//// positional CBOR. The toy n=8 vks make this the REHEARSAL genesis (frozen-anchor dead-end by
//// design, boot/README.md); the vk SHAPE is N-independent, so the datum size equals the
//// real n=512 deployment's.
////
//// Provenance + CONSISTENCY: the golden period-1600 values below must match the Go gate's pins
//// (prover/offchain/bootstrap/bootstrap_realpositive_test.go: realCurrentCommitment / realNext... /
//// realFinalizedHeaderRoot / slot 13107200) and bls_regular_period1600.json (fork_version, gvr);
//// the vks are prover/cmd/export_{fixture,boundary_fixture} → fixtures/groth16_{regular,boundary}_n8.json.
//// This file's vk hex is mechanically transcribed from those fixtures (regenerate if they change).

use aiken/builtin
use aiken/cbor
use zkbridge/types.{Datum, Groth16VerifyingKey}

// ── golden period-1600 genesis values (real full-512 gate output + the anchor constants) ──

const finalized_header_root: ByteArray =
  #"201a1d12d634bcf8de5a9281d8cf5974cb775be0f8741a1cf0123e0383878599"

const finalized_slot: Int = 13107200

const current_committee_commitment: ByteArray =
  #"10041e8ce930617c420c43546f39dc8d123cec24e199f3f51dfadcb448529e1e"

const next_committee_commitment: ByteArray =
  #"483e20c94d6075d0dd670d9b6fe7144456eecc96fadb501ac719e4473625510f"

const fork_version: ByteArray = #"05000000"

const genesis_validators_root: ByteArray =
  #"4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95"

fn vk_regular() -> Groth16VerifyingKey {
  Groth16VerifyingKey {
    alpha: #"94b7e59a9b17b193b22370b811b07a7faa0b96c8afe6624f34f72d3b1dcc963cb01bd917c4267a934c4df1206683b920",
    beta: #"ae89c28e2d0f6469321da5f54e963d84b90dae93da77cecb01879fb98425aab201eb0d614e01c2bc6bcea57cb35d048b1927c231c33f9bdf1c677a253213d62e8a649aa411bb5c4516cd6122400b6564ebed2abab596be42ba31465b64bac789",
    gamma: #"b2338dda32ba316f40bf800792d7f3e593e2831bd0210684de9f24d1c5aaa9b1f30b27f35bd85637b2effc9477d5587017e146d2eba61f1e38b367fbfc89a49aebc67c1e0e8aa4106763da27a8f770ae42f79c398868be246afd89bc260d8861",
    delta: #"90f1c93b966a82999cc1926244c5b289918b067834c40f5f6f9e95277443d0b53c7e65d11a28d0330045e144344d3f0707b07d0296d92e48bd67e5aa4d2accf65135aba9de23c2555062f6af5ae2872a85362a4099e703dc62f22f0c1a5a607d",
    ic: [
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
    ],
    commitment_g: #"b97bce82c9ed12a9285583442f753a050ed7289c2302c002e5614ce5127c2e662a8127efb670a02dcbeb11ab4983392f03943a22f2940d5f49836f404c81aee29c8c75323ccc2328aad1893767462cb4e79bb4bc7e929ad221a7b2ea4b645377",
    commitment_g_sigma_neg: #"aed8908b9fd5a455da52fd81719c5706c3df5d26c6c07b3a23fa5354e5e11520024258503aac828c677ec5ff92bc2adf101a2312fd65f27f45eaa1131813026826c6dbfebe5e6be391bb7502d84ef99ce4f4a55268554aeef6ff5089e41d59ac",
  }
}

fn vk_boundary() -> Groth16VerifyingKey {
  Groth16VerifyingKey {
    alpha: #"b22417f9938c3c1cdc7fbb76806603a0e31716df524bf8e9ef8eb4d4dedc24521055016e20491dd6ebb9851f32277b05",
    beta: #"9878ac5c12edbb43b7a57f63a433934691d8ea398e466c61b7cf134b286a7c1a75a6de24ccb27a0500c2f7385218a3da02e1395f7c3822e2c5b511ab14efe58d08e66dacd6891b6e3abd0015b338b228b2ebe2be242e1032d7d054aeea0d1acc",
    gamma: #"8a3dc4350b27d40880dc6633bc2d77f990c762d2d49ebdb7e63c4d1a084c350578fb5edf945373a46ae18e60b9d1e600006133b6b804f39ff5679d6f64888c8c3fe2765acf8a95c4b636e79d52ff2b1e2c02b67d669d893ee94739774ca945f3",
    delta: #"81200193e0c0a50fcdf47810ba2fc840948ca7e6e629b4ae5a8fbcb7ff9dadae91c8341f12273afc8b9d8284a3ed835501e79bf69b7964c8aa695d1027912ec5180838d3dc05694a2d6e76961163527cb897de30606f03a0a2b2ee1d3047f88c",
    ic: [
      #"a907f23125f102e778dba908d5a5a96f5008846c7dce03908116fc9786cc8ef112f30ecaab85e056d4de929287e78c7a",
      #"a87eee016e8aa30575e03419e6f98e06411c5f9f072b155f9a9800d51d1f5ac74887a3092bcdd464b3a83fe2676aaadf",
      #"94c1feef3a48410a8160182d75c825127e9a90b6e98e422dfb652909ed850ecec69bd513322124f3eb6565c92d74bcb2",
      #"953a22b39034ce8e6c670cdc1431af8e0df7c242eecab9d6d5a62d763d34f782ad8987a90aea56ee1c437492e607a91e",
      #"97063e9a0fd095d59c5a36dde0e0b3341f62cab45344821128d091f5e480f8e3fe4fa58b2613cea78e398bcfd905b435",
      #"8997a96d500700ba81ab6953f71d7e0f69dd4f4f7c6569f6d2349f6185df3454395a7ab03fd25d0f06428713e5c6e845",
      #"971dbeb1597943ef4699afc810878104ff0d22713a1e8ff65fd18ef88042f0f920019c64587268e42d7d69c2edd37a6e",
      #"aad6355b21b72fc22955bc655a27c1c154a3cdde2aff7494fc124fe8298b1a555e8e104c87467376127cccf48c7487d2",
      #"88d1f517df2857b36e7283c9204a1ec8b15bef793dbe7952b94e48de4b7d07a99d2e07ffded90edae1d32f23a34bbe31",
      #"b79f5b6f867e79fe90ed03e001b50e56c20e67b2db1fb37144135cd37739bd5b07fd852adafd552f7400c38389ba15fd",
      #"ac2ff5d5b2e77303615fa55e94caeb47de8ac901cfc5153c4e4f8f278511c6b2d3375bbef16264a22eb8ef5735854f70",
      #"84613107d0c24e6980cedb5577d749830d2f035f31035290640c3858623e7af2538375ed59f22aeb08e7903e2d9d793c",
      #"8f92d92d77edb95f64812f6e55de113d8c360377c5bd404490924a50a9da344793499f3e8cd8250dc77a7c5194db957d",
      #"97d2f37f48be4d1e3d6f6cead8a7c24e0a180bda13579a4e4ca31c2df0ca855440de707834a771efa4f2852cf62dad16",
    ],
    commitment_g: #"840da7063ac156aba0871e4d88e4159322610857a345b9f633050b571291e4b99da42a0f6a2f4e94605efc85a3c8d7e515934f03943708e67d0ff7b8ed6dbb000ec8479f817023b587c6e79fef7ac2805d4ef6cb41905117b9cefcda08a0756a",
    commitment_g_sigma_neg: #"9716c04385063adc79681f8353bfd9828b711e2c10c640c70fb2301f7cce1a6a05e356d981b52c54019d39cfba89f68b0f22bc3c878bf1675424d032fd81e9ec17ea9536384df504be50cfbe526fb8ffb1b21d5cde22cae31fcb1702ab02206f",
  }
}

fn genesis() -> Datum {
  Datum {
    finalized_header_root: finalized_header_root,
    finalized_slot: finalized_slot,
    current_committee_commitment: current_committee_commitment,
    next_committee_commitment: next_committee_commitment,
    fork_version: fork_version,
    genesis_validators_root: genesis_validators_root,
    verifying_key_regular: vk_regular(),
    verifying_key_boundary: vk_boundary(),
  }
}

// ── the seam tests ──

// size pin (the headline deployment number; N-independent — toy-vk VALUES don't change it).
test genesis_datum_size() {
  builtin.length_of_bytearray(cbor.serialise(genesis())) == 2632
}

// THE load-bearing one: reproduce the EXACT first-spend decode. cbor.serialise (Aiken authors the
// bytes) → cbor.deserialise (the ledger's CBOR decode) → expect Datum (the validator's cast) → ==.
test genesis_datum_roundtrips() {
  let bytes = cbor.serialise(genesis())
  expect Some(decoded) = cbor.deserialise(bytes)
  expect parsed: Datum = decoded
  parsed == genesis()
}

// byte-pin: sha2_256 of the EXACT bytes the Boot attaches. Doubles as the Stage-1c BYTE-IDENTITY
// anchor — the off-chain builder embeds these bytes and asserts sha2_256(embedded) == this pin, so
// it cannot drift from Aiken's serialise (the source of truth) without a hash collision. The 2632 B
// datum diagnostic hex is captured from this datum; sha2_256 is the durable, compact link.
test genesis_datum_bytepin() {
  builtin.sha2_256(cbor.serialise(genesis())) == #"86eeded99b2476e82de6ef198f83f906e14df9cee5fe67f860eb7a6e6c2fdad6"
}

// tampered-field negative: one wrong field ⇒ different bytes ⇒ the byte-pin/round-trip catch it.
test genesis_datum_tamper_changes_bytes() {
  let tampered = Datum { ..genesis(), finalized_slot: finalized_slot + 1 }
  cbor.serialise(tampered) != cbor.serialise(genesis())
}
