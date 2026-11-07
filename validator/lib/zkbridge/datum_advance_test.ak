//// Datum-advance seam gates (spend.py / boot/datum.py) — the off-chain datum encoder reproduces
//// Aiken's cbor.serialise BYTE-FOR-BYTE for the spend-path OUTPUT datums (the analog of the redeemer
//// seam's gate-4). boot/datum.py builds these same datums from the vk JSON fixtures + period-1600
//// values; the sha2_256 byte-pins below are the INDEPENDENT Aiken oracle (datum.py prints the shas it
//// must match, then they are transcribed here — a datum.py encoding bug ⇒ sha mismatch ⇒ RED).
////
////   gate-b   : the REGULAR advance — real_n512_regular.real_output_datum() (real n=512 vks, finalized
////              advanced, committees frozen). The same datum gate-1 already accepts at 5.94B.
////   boundary : a committee_rotated-consistent advance — output.current <- input.next, output.next <-
////              new (op-6), finalized advanced. The rotation FIELD-MAPPING is byte-pinned LOCALLY; the
////              boundary proof-verify is correctly VM-tier (no local n=512 boundary proof exists).
////
//// vks reuse real_n512_regular's pub fns, so gate-b ALSO confirms that module's copy of the vk ==
//// the groth16_*_n512.json datum.py reads. Committees = period-1600; new_next + new_finalized are
//// SYNTHETIC for the boundary mapping (a layout/mapping gate needs no cryptographically-real successor).

use aiken/builtin
use aiken/cbor
use zkbridge/real_n512_regular
use zkbridge/types.{Datum}
use zkbridge/validation

// gate-b — datum.py's regular advance output == Aiken's real_output_datum (byte-identity via sha2_256).
test real_output_datum_bytepin() {
  builtin.sha2_256(cbor.serialise(real_n512_regular.real_output_datum())) == #"75d154eaecdd0c00b9b17b4fe5da9c901da8ca271bfe38cf4b0a472299a8e292"
}

// ── boundary-rotation fixture (committee_rotated-consistent; mirrors boot/datum.py advance_boundary) ──
const old_finalized: ByteArray =
  #"0000000000000000000000000000000000000000000000000000000000000000"

const new_finalized: ByteArray =
  #"201a1d12d634bcf8de5a9281d8cf5974cb775be0f8741a1cf0123e0383878599"

const current_old: ByteArray =
  #"10041e8ce930617c420c43546f39dc8d123cec24e199f3f51dfadcb448529e1e"

const next_old: ByteArray =
  #"483e20c94d6075d0dd670d9b6fe7144456eecc96fadb501ac719e4473625510f"

const new_next: ByteArray =
  #"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"

const fork_version: ByteArray = #"05000000"

const genesis_validators_root: ByteArray =
  #"4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95"

fn boundary_input() -> Datum {
  Datum {
    finalized_header_root: old_finalized,
    finalized_slot: 13107199,
    current_committee_commitment: current_old,
    next_committee_commitment: next_old,
    fork_version: fork_version,
    genesis_validators_root: genesis_validators_root,
    verifying_key_regular: real_n512_regular.real_vk_regular(),
    verifying_key_boundary: real_n512_regular.real_vk_boundary(),
  }
}

// the boundary OUTPUT after advance_boundary: current <- input.next (rotation), next <- new_next.
fn boundary_output() -> Datum {
  Datum {
    finalized_header_root: new_finalized,
    finalized_slot: 13107200,
    current_committee_commitment: next_old,
    // == input.next (committee_rotated)
    next_committee_commitment: new_next,
    fork_version: fork_version,
    genesis_validators_root: genesis_validators_root,
    verifying_key_regular: real_n512_regular.real_vk_regular(),
    verifying_key_boundary: real_n512_regular.real_vk_boundary(),
  }
}

// boundary byte-pin — datum.py's advance_boundary output == this committee_rotated-consistent datum.
test boundary_output_bytepin() {
  builtin.sha2_256(cbor.serialise(boundary_output())) == #"b6157e8b183fe120b049939d12b008871ffac1384a4c3df7257a5dcdc9807bed"
}

// the load-bearing rotation MAPPING, asserted in Aiken too (output.current == input.next, byte-for-byte).
test boundary_rotation_mapping() {
  boundary_output().current_committee_commitment == boundary_input().next_committee_commitment
}

// the validator's OWN predicate agrees this output is a valid committee rotation + a forward slot.
test boundary_committee_rotated_holds() {
  validation.committee_rotated(boundary_input(), boundary_output())
}

test boundary_slot_advances() {
  validation.slot_advances(boundary_input(), boundary_output())
}

// anchors held across the boundary advance (anchors_preserved holds — vks/fork/gvr bit-identical).
test boundary_anchors_preserved() {
  validation.anchors_preserved(boundary_input(), boundary_output())
}
