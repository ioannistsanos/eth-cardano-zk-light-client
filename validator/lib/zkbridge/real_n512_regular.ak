//// GATE-1 real-n=512 fixtures — the D24-unblocked all-real positive's data, as a self-contained lib
//// module that bridge.ak's `full_validator_real_regular_positive` test wires into `bridge.spend`.
//// The real n=512 regular proof + the real period-1600 σ/apk (count 510) + the real n=512 vks + a
//// consistent input/output datum, so all five layers verify in one eval (first time real n=512 meets
//// the validator). GENERATED from the fixtures (groth16_regular/boundary_n512.json, proof_to_redeemer
//// of proof_regular_n512.json, bls_regular_period1600.json) — regenerate if they change. The proof
//// `commitment` is the UNCOMPRESSED 96 B form (proof_to_redeemer / types.ak:26-28), NOT the compressed
//// proof_to_json fixture (the redeemer-seam subtlety #4).

use cardano/address.{Address, Script}
use cardano/assets.{PolicyId, Value, from_asset, from_lovelace, merge}
use cardano/transaction.{InlineDatum, Input, Output, OutputReference, Transaction, placeholder}
use zkbridge/types.{Datum, Groth16Proof, Groth16VerifyingKey, Redeemer, Regular, bridge_state_token_name}

// ── the real n=512 verifying keys (datum anchors) ──
pub fn real_vk_regular() -> Groth16VerifyingKey {
  Groth16VerifyingKey {
    alpha: #"aca2f634ad5259ac618d579801ebfb9955ae24051e015e1f05243ef4e521f50a69bbc0ad7abf896e9fbdd169f2984d93",
    beta: #"a38312b234095c6b762b0d50a67398f69ffb81aed11899dd1d0b7a949b0842ab611084ca095681b60ed21b6d104dd4090870673717a3091e8829aba397ed92ea0d0c0b262a5574cfa450b1dddbf1eb8e5413c07f6949d88df8e28dee4c36ec64",
    gamma: #"a1519f850e08ec21eea1fb750dd24a9546bf7b97c19624d62dcc359662fd2a2e5acc3d968c38264c0ef3e226a48d1a9a00f05f113fbdde4e0b9d7dbed14bba424944fc9b205af8e620e0d9ecc76506f4c28c2d5c6b2cdcac8ac6c8a55d7d50f8",
    delta: #"8a2c0ce96b0a62bc71b7a12e959faa20c33a8a4ebd8c45a9af5be5d5fa81033e55eef43cc3348cea3dbfea9b1ad53daa17dccdcf6172134062d0feeeb681858c9a8e48aaedbff6728268c9233bd44b91ea517f1882e3505f8b16a32db93bd315",
    ic: [
      #"a12a5a4a60ed7e8bf9c1dfc6e19fbb4d5cf166f63b0eaf4b4089743180d8ebb5aa8c6acdfa5bff29684c3dc548adb8a2",
      #"938995cfd5e38a8e24314d7c329cce38e59fcaf22758f78c6487f0b39d0986d50271ccc1777e7c14bb910ffc135be04d",
      #"89791036999aa86b8cf96bb14d621b890cdcf75aadf49d1f5fa6f4349e7b0e901ba3c8e2c958eb02c195bf9a674f4233",
      #"b8c769fa7468e8cc2d457c15b8b7fd702cb4218448b453b8c598994f9811f0a9f5e207b82081340f34e8fe49190fad92",
      #"a10a73db16bdfc91180ef86edd39a347a40894fb562097bbc500aea4d5d9d801490b56bee002f305c42f5b7e1734ed6b",
      #"b41f9bece3a34b3a8ee91dfc465d0eee9eff525169d64053da8742a6a25cd561e64ff11db76669d701a95566a7ec688c",
      #"87d51d9ec12a1a99de474827a114e80bc31a7bd1fa9a30b9dfbc4b518e0263ef979e57dd1fbd34fb0b68a0b6d32d4381",
      #"8f3455b03e5206243f5cb66e288101446472c3cdca71722ef0506a8ca8edce730da804ffd795e3c29025cb07c0e7bde6",
      #"b8c44521ac8e2464408e0cc84de306ac833d8f97d65bc004f23bdcc7865fc75d998603fb10d3615bcd492950c486f8bf",
      #"b2178e31d398a9a48f58b86788eb671dccda51f21e6982b3b5337e2f8a13337bd85be481a97fa42e6c3926ac6a0526c0",
      #"999e6a999799f53fb60a50d65d638e35fb209c966761f6091ffb13b5679bf2a14d49199d25875f4cf326b418d31a45e2",
      #"961a457a215ab81c86f599b4391575831e9b6fa206d764a2eedd86949dbe74920f9b67cda43385e35ff4a95e56d02633",
      #"853f162847b51fdc9d15a16fafe7b918ba7bc1b5b99ac79b429fc47772f1033ef3509b92f481712e0c051bde56d651fc",
    ],
    commitment_g: #"af4ea7a545578399fa3a7b31688c5801a6a956c5ba8afe13b0f59c8d0dc86e4fadc6492975dfcd8fa1781279b7fbb5ab047351fbe37e628acee3dbc32f917e0e6e93ec93d006f555937ffcd2edd4ade3cab04d722a1d75cbec6ceba4ecd0f7a4",
    commitment_g_sigma_neg: #"9630f74c40be707f4390c5d33ba28cdaf174e31c597a8c0ffc83f27b9a0ef8dbe38a01e7d4e377142a33cbacb76a4f3a0d619f116856f22555f120d8a45c1281848a737e0259af1a7331f4afc33d28dff538fe0e83bf18b96d75393d51382495",
  }
}

pub fn real_vk_boundary() -> Groth16VerifyingKey {
  Groth16VerifyingKey {
    alpha: #"a67164c9376fa5a16312081ac7e10959481aba9fc298b687186e8aaeb30db16c25de3cba248d4afd8840fabbb18ed891",
    beta: #"add282098d7511173100cfac863b19ae1596e45ea5d738e0b6fdf7b9ab4ad7f673d7bd6ac9f9b04933c8ebef8528c82c0829777c6761b7ff0c79b1730b477b30eb3a71091945adbf3e1b4ce187571c19c3a60f79d5bf39fb9c3f8cc8fff12c58",
    gamma: #"90abb094f34f04843516fa6e91c6e9abef4336320e48dce6a819080351f38f4ead6a558075432ca61e4357eec4220f6c099cdc1041a80ff84da43f07e3efd511ff78d54c710bea210f48b692581cc680deca636f66618a1418cd30e4a985ea0c",
    delta: #"849169c403829286a6d437e0fae815bcac6847fff38b49724205085f83b79c2867eb150946ca8c64014dffa3b656783801f2bb0fa0bd0a573d8d146807d50c60aa31c00d29d91a73c75a43a6574f44ab87cbac394fdcb83324af1e3e7a6e93ca",
    ic: [
      #"8c305a8ce9f465de5d5dfed95d6af56eb518a6bd6a5c1a257eadee4ecbc194a95b1c28e4509d4fa614af926777e96bd4",
      #"a26ea4e97dcd7ca50659697f3e0dd368e69a00f41772197544a3f369260df1b602c41cb559a7f59a7e6d6964e94c2085",
      #"998b5308ce4235d86899859cf937d97b99dcf28a44bb2e9f0a67321c895fc67775911eaa67e696948989653add368c30",
      #"878f262c181d7e086e3240dc5fc096fbc38e4899035311e31f6e1402ebd719fd0414bb1ba0b7e3f42411e3dda52c0bcf",
      #"8192bc637d4b3dd7dbbab76bb23ec596dadcd1deb3c41ca75a8f56464a14cb03a6b598f417928cb58f282c717c3ed891",
      #"ab2a11d71fa9ab4bff535ff481ee54ec9733580601a4d6eb292d8f16cdc0652db13a609ffa253f86bfb4f9a9c48b4f2f",
      #"ace09e1840fe08001748f0249cb1896443f0b6981d82bc9b31de4675498a9118c8a8ffc33339e972a80c1c5c6350baed",
      #"8dc58f78300cb918221e5abbddd0b434e39aeec1e71cbbe96f02e96409a4d485b1b0ed6f9c688fc1e26c2eca8090fb6d",
      #"ae78da65f66d92b2ee2e7250a2a35707df66f1af5628e401fb8a89bd4cb7338c2f4c400c316dbf08116e03506185606f",
      #"86768039c6fb28a03c765452b817ded419faf350f81a1f1f7cc2714d80446b0ba702f39c0af2a1317eec742bb5478e3d",
      #"ad4256d2ddbf9a3548bf9ca0412db30ce862791e61c11e9a2da5c581983da2f2e64d490cabd6503a9777abe12fd5c07a",
      #"ac2bbccaa6f6d3b9b3457877d7beb62878a77346b66131dc104089ec508c27aaaf214ab5f9dc3cfec7387c06f5004e21",
      #"a4beced3f137731e6c3e082672889f9b44bf1ca81e1f74ccc60e4f994417caae319d03d0425218abff62f06c587fb0b7",
      #"b52be1a0dea41a378fb8f18682172a55f14ed58046f5b40a8fb464fb94971731930cc1ddfa1eb6a2f08aee41285f8b72",
    ],
    commitment_g: #"81aecf24cbc5bc9a78a494affa932c2dfe63deb7b12c413e510478c40412a6d565699c9c31f286236c79e5b2fa1568ae0004414a97d175d8bc0f9bb6f41dcad657a684a4f3413084ee9c5a2c085b4a559c7a588fadfbea3c659305c7ba0b7d3c",
    commitment_g_sigma_neg: #"a9bcd7241f3a62b5048db78d928d8c74e58baa6cc7ea06386186db4ea88ffd284c639500fbb5e9a1f5d3161d6741d3d10daf23955f154e99a6032bdb67bc2f8c099fd04fe1dfae68a5a7af9e1b3cb10dd3719b87d45a977048f48133f4a3638b",
  }
}

// ── the real n=512 regular proof (commitment UNCOMPRESSED 96 B) ──
pub fn real_proof() -> Groth16Proof {
  Groth16Proof {
    a: #"a7891ea2110b29724559acb9cae29e465e9dc6bcf2f22e0ce417a6b4809d2f41650f2803c7e914778fda044cf4794975",
    b: #"971e3c7590840a667e7fd49283f0cb17de8c39bd761db16ee1e93fb66fdaa61dbdc8ffa3b240259fc25de44a640dc50f013c31dfe2527f9ef7711a240b0dee10351ea39a578a7aa397a820a34a86c3bce0488b595293156227b4a264eec1fdef",
    c: #"b9c2972c99eec2549f43a3a4204ca038853513d4a502b2bc83a7a9d8a1fcb264ad2b18c11e55ab4d97ad384639b7795f",
    commitment: #"0630a6f877e0c36f7d6d05940157c516d19b01a81a490bb9301d9ed2b9f4bb70119eb207d64883cef4e2e15754e277c911d9775e9ad9bed2ecf7d979cae94fa2b559a316c0f678e01244f13a83cbf97a0c9cee1f5ab8c2b05a107f482c0b37e2",
    commitment_pok: #"904d4780c14e53f558bcbe7220118717c8ecdcc104ad71b6d51acb121e3094ce8a5e508faab61885277950bd5ae9a983",
  }
}

// ── the real period-1600 σ / apk / publics + the genesis values ──
const real_signature: ByteArray =
  #"a29333064a2b8325fb735901b7b074dc5058cef518a5b8d885c2eac7b19a89b550486facf50f12a74eec5246b9084e690207f0924a9fc237f5dfbc712f02b3413660f0523d7bd465a202cfc4b12ddc451aadb4d7967bdd3f569932aa41237508"
const real_apk: ByteArray =
  #"07e8712375cb3ec0748d8f1e92eba1ff3b75baf1de7ddbb3aab34745ce511545dbd63d330143e1ff93b14cbd866cda8701c0e46b20269f6ce652b1e8f39260be61da84e112f732628f2ae9feb7c0db1434353c965068d204f13e999413ca1002"
const real_attested_root: ByteArray = #"7099a98d437bc51344b7cad28193da1a9d51d79fba141b4ebb2afcd81242a52d"
const real_count: Int = 510
const real_fork: ByteArray = #"05000000"
const real_gvr: ByteArray =
  #"4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95"
const real_current_commitment: ByteArray =
  #"10041e8ce930617c420c43546f39dc8d123cec24e199f3f51dfadcb448529e1e"
const real_next_commitment: ByteArray =
  #"483e20c94d6075d0dd670d9b6fe7144456eecc96fadb501ac719e4473625510f"
const real_finalized_root: ByteArray =
  #"201a1d12d634bcf8de5a9281d8cf5974cb775be0f8741a1cf0123e0383878599"
const old_finalized_root: ByteArray =
  #"0000000000000000000000000000000000000000000000000000000000000000"
const real_finalized_slot: Int = 13107200

fn real_datum(finalized_root: ByteArray, finalized_slot: Int) -> Datum {
  Datum {
    finalized_header_root: finalized_root,
    finalized_slot: finalized_slot,
    current_committee_commitment: real_current_commitment,
    next_committee_commitment: real_next_commitment,
    fork_version: real_fork,
    genesis_validators_root: real_gvr,
    verifying_key_regular: real_vk_regular(),
    verifying_key_boundary: real_vk_boundary(),
  }
}

pub fn real_input_datum() -> Datum {
  real_datum(old_finalized_root, real_finalized_slot - 1)
}

pub fn real_output_datum() -> Datum {
  real_datum(real_finalized_root, real_finalized_slot)
}

pub fn real_redeemer() -> Redeemer {
  Redeemer {
    kind: Regular,
    proof: real_proof(),
    apk: real_apk,
    signature: real_signature,
    count: real_count,
    attested_header_root: real_attested_root,
  }
}

// ── tx scaffold (NFT continuity: the spent input + one continuing output carry the state NFT) ──
pub const state_token: PolicyId =
  #"5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e"
const script_hash: ByteArray =
  #"b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1"

fn bridge_address() -> Address {
  Address { payment_credential: Script(script_hash), stake_credential: None }
}

fn nft_value() -> Value {
  merge(from_lovelace(2_000_000), from_asset(state_token, bridge_state_token_name, 1))
}

pub fn own_ref() -> OutputReference {
  OutputReference {
    transaction_id: #"0101010101010101010101010101010101010101010101010101010101010101",
    output_index: 0,
  }
}

fn bridge_output(d: Datum) -> Output {
  Output {
    address: bridge_address(),
    value: nft_value(),
    datum: InlineDatum(d),
    reference_script: None,
  }
}

pub fn real_tx() -> Transaction {
  Transaction {
    ..placeholder,
    inputs: [
      Input { output_reference: own_ref(), output: bridge_output(real_input_datum()) },
    ],
    outputs: [bridge_output(real_output_datum())],
  }
}
