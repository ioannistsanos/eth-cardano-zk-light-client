//// Phase-3 Layer 2 — the verifier gate: the REAL toy proof (n=8, format-identical to
//// n=512) verifies on-chain through the FULL commitment-augmented path. If toy_proof_verifies
//// passes, every convention is bit-correct (the 4-step verify, the augmented MSM, the point
//// reconstruction, the expand_message_xmd-SHA256 hash-to-field) and real n=512 is a value swap.
//// Generated from validator/fixtures/groth16_regular_n8.json (cmd/export_fixture).

use aiken/builtin
use zkbridge/groth16
use zkbridge/types.{Groth16Proof, Groth16VerifyingKey}

// ── vk ──
const vk_alpha: ByteArray =
  #"94b7e59a9b17b193b22370b811b07a7faa0b96c8afe6624f34f72d3b1dcc963cb01bd917c4267a934c4df1206683b920"

const vk_beta: ByteArray =
  #"ae89c28e2d0f6469321da5f54e963d84b90dae93da77cecb01879fb98425aab201eb0d614e01c2bc6bcea57cb35d048b1927c231c33f9bdf1c677a253213d62e8a649aa411bb5c4516cd6122400b6564ebed2abab596be42ba31465b64bac789"

const vk_gamma: ByteArray =
  #"b2338dda32ba316f40bf800792d7f3e593e2831bd0210684de9f24d1c5aaa9b1f30b27f35bd85637b2effc9477d5587017e146d2eba61f1e38b367fbfc89a49aebc67c1e0e8aa4106763da27a8f770ae42f79c398868be246afd89bc260d8861"

const vk_delta: ByteArray =
  #"90f1c93b966a82999cc1926244c5b289918b067834c40f5f6f9e95277443d0b53c7e65d11a28d0330045e144344d3f0707b07d0296d92e48bd67e5aa4d2accf65135aba9de23c2555062f6af5ae2872a85362a4099e703dc62f22f0c1a5a607d"

const vk_commitment_g: ByteArray =
  #"b97bce82c9ed12a9285583442f753a050ed7289c2302c002e5614ce5127c2e662a8127efb670a02dcbeb11ab4983392f03943a22f2940d5f49836f404c81aee29c8c75323ccc2328aad1893767462cb4e79bb4bc7e929ad221a7b2ea4b645377"

const vk_commitment_g_sigma_neg: ByteArray =
  #"aed8908b9fd5a455da52fd81719c5706c3df5d26c6c07b3a23fa5354e5e11520024258503aac828c677ec5ff92bc2adf101a2312fd65f27f45eaa1131813026826c6dbfebe5e6be391bb7502d84ef99ce4f4a55268554aeef6ff5089e41d59ac"

fn ic_list() -> List<ByteArray> {
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

// ── proof ──
const proof_a: ByteArray =
  #"94b95cfe3e6e99d5b698d9ee2d92d1b5c94f2d7231d6871c6cd0e73a61fcc4ab6ef7acfec25e08f1333271c68a0cd809"

const proof_b: ByteArray =
  #"95d4fce477f2c8dd0358f728b7d83da31d950ec9f2e8cc8a264b41eb859b846eccd6a142458ec66dcd83a1197a0432b704a2b50ff53a6dbbc76e5633ea9e8fbdcae810db0ee34e69547ac639019e032b500f86114994f1439c7384923e1f7b02"

const proof_c: ByteArray =
  #"abaab30e3f1c5ea200985e93fc166522ad8a39c60a719b9f90e191599a9885ea79e3bd7d0fc85e52318d708366cf8d09"

const proof_commitment: ByteArray =
  #"0bb38d5db29b9e6d8ab98dec4ccb06f0b47bea1918b9197b5f4b199e43ff13795f5886a067da21a103f4570a14f57d79022d52ae22a988423192680284dd545cd840e3d133038337875a61b890112d8e0903053f63da3592daa8a13dd03c5f47"

const proof_commitment_pok: ByteArray =
  #"a420abe903cdd381750db9396be001745f20bb8c1f1edf851cfba35e18d2f8ba0d7c8dca783997e644b0ae2c9c4277f9"

// ── re-derivation inputs ──
const current_commitment: ByteArray =
  #"24e1330c0064f2e943db80522452f9fa4db3422554342655297820b11ad601d0"

const apk_uncompressed: ByteArray =
  #"009509fef0f7ce988760648d313397dbd56c2c0155926ca6fdb2f7562a8cf8ad116ccda3387e5958895ab3092cc4149016e3b3c5386a5db1fe70efa4451de851bfdb212c836ff048cbc021415ad4aefaf83d644443b1d12050054483623a4ea1"

const attested_root: ByteArray =
  #"7099a98d437bc51344b7cad28193da1a9d51d79fba141b4ebb2afcd81242a52d"

const finalized_root: ByteArray =
  #"201a1d12d634bcf8de5a9281d8cf5974cb775be0f8741a1cf0123e0383878599"

const count: Int = 8

const finalized_slot: Int = 13107200

// ── gnark goldens ──
const expected_bsb22: ByteArray =
  #"4a1004fcb7265beccec255ac4f6d1b55491a28ca7b0f70a3cb3bbea02f01c9a2"

fn expected_publics() -> List<Int> {
  [
    builtin.bytearray_to_integer(
      True,
      #"24e1330c0064f2e943db80522452f9fa4db3422554342655297820b11ad601d0",
    ),
    builtin.bytearray_to_integer(
      True,
      #"0000000000000000fdb2f7562a8cf8ad116ccda3387e5958895ab3092cc41490",
    ),
    builtin.bytearray_to_integer(
      True,
      #"0000000000000000009509fef0f7ce988760648d313397dbd56c2c0155926ca6",
    ),
    builtin.bytearray_to_integer(
      True,
      #"0000000000000000cbc021415ad4aefaf83d644443b1d12050054483623a4ea1",
    ),
    builtin.bytearray_to_integer(
      True,
      #"000000000000000016e3b3c5386a5db1fe70efa4451de851bfdb212c836ff048",
    ),
    builtin.bytearray_to_integer(
      True,
      #"0000000000000000000000000000000000000000000000000000000000000008",
    ),
    builtin.bytearray_to_integer(
      True,
      #"000000000000000000000000000000007099a98d437bc51344b7cad28193da1a",
    ),
    builtin.bytearray_to_integer(
      True,
      #"000000000000000000000000000000009d51d79fba141b4ebb2afcd81242a52d",
    ),
    builtin.bytearray_to_integer(
      True,
      #"00000000000000000000000000000000201a1d12d634bcf8de5a9281d8cf5974",
    ),
    builtin.bytearray_to_integer(
      True,
      #"00000000000000000000000000000000cb775be0f8741a1cf0123e0383878599",
    ),
    builtin.bytearray_to_integer(
      True,
      #"0000000000000000000000000000000000000000000000000000000000c80000",
    ),
    builtin.bytearray_to_integer(True, expected_bsb22),
  ]
}

fn mock_vk() -> Groth16VerifyingKey {
  Groth16VerifyingKey {
    alpha: vk_alpha,
    beta: vk_beta,
    gamma: vk_gamma,
    delta: vk_delta,
    ic: ic_list(),
    commitment_g: vk_commitment_g,
    commitment_g_sigma_neg: vk_commitment_g_sigma_neg,
  }
}

fn mock_proof() -> Groth16Proof {
  Groth16Proof {
    a: proof_a,
    b: proof_b,
    c: proof_c,
    commitment: proof_commitment,
    commitment_pok: proof_commitment_pok,
  }
}

// ── layer-2 validation ──

// 1. the hash-to-field matches gnark bit-for-bit (the precise-locus check).
test bsb22_hash_matches_gnark() {
  groth16.hash_to_field_bsb22(proof_commitment) == builtin.bytearray_to_integer(
    True,
    expected_bsb22,
  )
}

// 2. the 12 publics re-derive exactly (packRoot + foldFp + commitment + the BSB22 12th).
test publics_rederive_matches() {
  groth16.derive_publics(
    current_commitment,
    apk_uncompressed,
    count,
    attested_root,
    finalized_root,
    finalized_slot,
    proof_commitment,
  ) == expected_publics()
}

// 3. THE LINCHPIN — the real toy proof verifies through the full augmented path.
test toy_proof_verifies() {
  groth16.verify_regular(
    mock_vk(),
    mock_proof(),
    current_commitment,
    apk_uncompressed,
    count,
    attested_root,
    finalized_root,
    finalized_slot,
  )
}

// 4a. wrong public (count) → reject.
test wrong_count_rejects() {
  groth16.verify_regular(
    mock_vk(),
    mock_proof(),
    current_commitment,
    apk_uncompressed,
    count + 1,
    attested_root,
    finalized_root,
    finalized_slot,
  ) == False
}

// 4b. wrong public (a flipped finalized root → packRoot is load-bearing) → reject.
test wrong_finalized_root_rejects() {
  let tampered = builtin.cons_bytearray(
    0,
    builtin.slice_bytearray(1, 31, finalized_root),
  )
  groth16.verify_regular(
    mock_vk(),
    mock_proof(),
    current_commitment,
    apk_uncompressed,
    count,
    attested_root,
    tampered,
    finalized_slot,
  ) == False
}

// 4c. the hash DST is load-bearing — a wrong DST → a different field element.
test wrong_dst_differs() {
  groth16.hash_to_field(proof_commitment, "wrong-commitment") != builtin.bytearray_to_integer(
    True,
    expected_bsb22,
  )
}

// 4d. #9 malformed bytes → strict uncompress REJECTS (not garbage).
test malformed_point_rejects() fail {
  let bad_vk = Groth16VerifyingKey {
    ..mock_vk(),
    alpha: #"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
  }
  groth16.verify_regular(
    bad_vk,
    mock_proof(),
    current_commitment,
    apk_uncompressed,
    count,
    attested_root,
    finalized_root,
    finalized_slot,
  )
}
