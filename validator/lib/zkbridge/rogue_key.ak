//// A BLS key pair that belongs to no sync committee, with its signature over the signing root of the
//// boundary fixture real_n512_boundary.ak (fork version 06000000, the live genesis_validators_root,
//// the attested header root of slot 14,671,872) under the sync-committee domain 0x07000000 and the
//// ciphersuite BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_. The public key is not the aggregate of any
//// subset of the period-1791 committee, so a redeemer carrying it must be rejected by the proof binding
//// of the aggregate public key even though the signature itself verifies.

/// The rogue public key, uncompressed (96 B, X‖Y), in the redeemer's apk encoding.
pub const rogue_apk: ByteArray =
  #"132c27acf24e7c3878ec977292d6978be08aa683928fcc90bba18ec8ea250ab411c7a3d6ff4f6f58ed5784c23f218d7f1059ce162cb02544a8de10dc764d46ce4da50898fc3109d2ec8ad3cfb4b10d15216064d6b34a9068289c795edd938f32"

/// The rogue key's signature over the fixture's signing root
/// d9477453c743e2487cdb8508fa9e06e5ef2a1d638df806f5f0383dc80e3d8904, compressed (96 B).
pub const rogue_signature: ByteArray =
  #"a1a130555c63ac35d323f95f3c3460c749c91d0ff1920c7f32f78c79dc8a46d7085ac063ff75a847f976a14f9452c4fd027b9a6d5a5a6c0706200aec5c265c1a0a2476797994d8729207c731ec75085b1c8601187c067949f210503b28edce14"
