//// Full-validator tests of the bridge spending validator: the two real transactions as positive
//// cases, and single-field mutations of their fixtures as negative cases. Where the rejecting check
//// is a Bool-valued library function, a negative case is asserted twice: the validator rejects the
//// transaction, and the library check returns False on the same mutated values.

use aiken/builtin
use bridge
use cardano/address.{Address, Script, VerificationKey}
use cardano/assets.{from_lovelace}
use cardano/transaction.{DatumHash, InlineDatum, Input, Output, Transaction}
use zkbridge/bls
use zkbridge/groth16
use zkbridge/real_n512_boundary as boundary
use zkbridge/real_n512_regular as regular
use zkbridge/rogue_key
use zkbridge/types.{
  Boundary, Datum, Groth16Proof, Redeemer, Regular, bridge_state_token_name,
}
use zkbridge/validation

// ── positive cases: the two real transactions ──

/// The boundary transaction c8b296a9… (rotation of the live bridge) is accepted.
test boundary_update_accepted() {
  bridge.bridge.spend(
    boundary.state_token,
    Some(boundary.real_input_datum()),
    boundary.real_redeemer(),
    boundary.own_ref(),
    boundary.real_tx(),
  )
}

/// The regular transaction 90c3b3e1… (rehearsal bridge) is accepted.
test regular_update_accepted() {
  bridge.bridge.spend(
    regular.state_token,
    Some(regular.real_input_datum()),
    regular.real_redeemer(),
    regular.own_ref(),
    regular.real_tx(),
  )
}

// ── the validator entry points and transaction contexts of the two fixtures ──

fn boundary_spend(input: Datum, redeemer: Redeemer, tx: Transaction) -> Bool {
  bridge.bridge.spend(
    boundary.state_token,
    Some(input),
    redeemer,
    boundary.own_ref(),
    tx,
  )
}

fn regular_spend(input: Datum, redeemer: Redeemer, tx: Transaction) -> Bool {
  bridge.bridge.spend(
    regular.state_token,
    Some(input),
    redeemer,
    regular.own_ref(),
    tx,
  )
}

/// The boundary transaction context with the given consumed and produced datums.
fn boundary_tx(input: Datum, output: Datum) -> Transaction {
  Transaction {
    ..boundary.real_tx(),
    inputs: [
      Input {
        output_reference: boundary.own_ref(),
        output: boundary.bridge_output(input),
      },
    ],
    outputs: [boundary.bridge_output(output)],
  }
}

/// The boundary transaction context with the given continuing output.
fn boundary_tx_with_output(output: Output) -> Transaction {
  Transaction { ..boundary.real_tx(), outputs: [output] }
}

/// The regular transaction context with the given produced datum.
fn regular_tx(output: Datum) -> Transaction {
  let tx = regular.real_tx()
  expect [continuing] = tx.outputs
  Transaction {
    ..tx,
    outputs: [Output { ..continuing, datum: InlineDatum(output) }],
  }
}

// ── the library checks, wired as the validator wires them ──

fn boundary_proof_accepted(
  input: Datum,
  redeemer: Redeemer,
  output: Datum,
) -> Bool {
  groth16.verify_boundary(
    input.verifying_key_boundary,
    redeemer.proof,
    input.next_committee_commitment,
    redeemer.apk,
    redeemer.count,
    redeemer.attested_header_root,
    output.finalized_header_root,
    output.finalized_slot,
    output.next_committee_commitment,
  )
}

fn regular_proof_accepted(
  input: Datum,
  redeemer: Redeemer,
  output: Datum,
) -> Bool {
  groth16.verify_regular(
    input.verifying_key_regular,
    redeemer.proof,
    input.current_committee_commitment,
    redeemer.apk,
    redeemer.count,
    redeemer.attested_header_root,
    output.finalized_header_root,
    output.finalized_slot,
  )
}

fn signature_accepted(input: Datum, redeemer: Redeemer) -> Bool {
  bls.verify(
    input.fork_version,
    input.genesis_validators_root,
    redeemer.attested_header_root,
    redeemer.signature,
    redeemer.apk,
  )
}

/// The continuing state output of a boundary transaction context carries the bridge credential:
/// True whenever the check returns an output; the check aborts unless exactly one output qualifies.
fn continuing_output_found(tx: Transaction) -> Bool {
  let continuing =
    validation.continuing_state_output(
      tx,
      boundary.own_ref(),
      boundary.state_token,
      bridge_state_token_name,
    )
  continuing.address.payment_credential == Script(boundary.script_hash)
}

/// The byte string with the lowest bit of its last byte flipped.
fn flip_last_bit(bytes: ByteArray) -> ByteArray {
  let length = builtin.length_of_bytearray(bytes)
  let last = builtin.index_bytearray(bytes, length - 1)
  let flipped =
    if last % 2 == 0 {
      last + 1
    } else {
      last - 1
    }
  builtin.append_bytearray(
    builtin.slice_bytearray(0, length - 1, bytes),
    builtin.integer_to_bytearray(True, 1, flipped),
  )
}

// ── rollback and replay ──

/// Boundary: the produced finalized slot equals the consumed one.
test boundary_replay_same_slot_rejected() fail {
  let input = boundary.real_input_datum()
  let output =
    Datum {
      ..boundary.real_output_datum(),
      finalized_slot: boundary.consumed_finalized_slot,
    }
  boundary_spend(input, boundary.real_redeemer(), boundary_tx(input, output))
}

test boundary_replay_same_slot_predicates() {
  let input = boundary.real_input_datum()
  let output =
    Datum {
      ..boundary.real_output_datum(),
      finalized_slot: boundary.consumed_finalized_slot,
    }
  and {
    validation.slot_advances(input, output) == False,
    boundary_proof_accepted(input, boundary.real_redeemer(), output) == False,
  }
}

/// Boundary: the produced finalized slot is lower than the consumed one.
test boundary_rollback_lower_slot_rejected() fail {
  let input = boundary.real_input_datum()
  let output =
    Datum {
      ..boundary.real_output_datum(),
      finalized_slot: boundary.consumed_finalized_slot - 1,
    }
  boundary_spend(input, boundary.real_redeemer(), boundary_tx(input, output))
}

test boundary_rollback_lower_slot_predicates() {
  let input = boundary.real_input_datum()
  let output =
    Datum {
      ..boundary.real_output_datum(),
      finalized_slot: boundary.consumed_finalized_slot - 1,
    }
  and {
    validation.slot_advances(input, output) == False,
    boundary_proof_accepted(input, boundary.real_redeemer(), output) == False,
  }
}

/// Boundary: the real redeemer submitted again against the datum the transaction produced.
test boundary_update_resubmitted_against_produced_datum_rejected() fail {
  let produced = boundary.real_output_datum()
  boundary_spend(
    produced,
    boundary.real_redeemer(),
    boundary_tx(produced, produced),
  )
}

test boundary_update_resubmitted_against_produced_datum_predicates() {
  let produced = boundary.real_output_datum()
  and {
    validation.slot_advances(produced, produced) == False,
    boundary_proof_accepted(produced, boundary.real_redeemer(), produced) == False,
  }
}

/// Regular: the real redeemer submitted again against the datum the transaction produced (the proof
/// and the signature still verify; only the slot does not advance).
test regular_update_resubmitted_against_produced_datum_rejected() fail {
  let produced = regular.real_output_datum()
  regular_spend(produced, regular.real_redeemer(), regular_tx(produced))
}

test regular_update_resubmitted_against_produced_datum_predicates() {
  let produced = regular.real_output_datum()
  and {
    regular_proof_accepted(produced, regular.real_redeemer(), produced) == True,
    validation.slot_advances(produced, produced) == False,
  }
}

/// Regular: the produced finalized slot equals the consumed one.
test regular_replay_same_slot_rejected() fail {
  let input = regular.real_input_datum()
  let output =
    Datum { ..regular.real_output_datum(), finalized_slot: input.finalized_slot }
  regular_spend(input, regular.real_redeemer(), regular_tx(output))
}

test regular_replay_same_slot_predicates() {
  let input = regular.real_input_datum()
  let output =
    Datum { ..regular.real_output_datum(), finalized_slot: input.finalized_slot }
  and {
    validation.slot_advances(input, output) == False,
    regular_proof_accepted(input, regular.real_redeemer(), output) == False,
  }
}

// ── kind confusion ──

/// The boundary redeemer with its kind set to Regular, against the boundary datums.
test boundary_redeemer_with_regular_kind_rejected() fail {
  let redeemer = Redeemer { ..boundary.real_redeemer(), kind: Regular }
  boundary_spend(boundary.real_input_datum(), redeemer, boundary.real_tx())
}

test boundary_redeemer_with_regular_kind_predicate() {
  validation.committees_frozen(
    boundary.real_input_datum(),
    boundary.real_output_datum(),
  ) == False
}

/// The regular redeemer with its kind set to Boundary, against the regular datums.
test regular_redeemer_with_boundary_kind_rejected() fail {
  let redeemer = Redeemer { ..regular.real_redeemer(), kind: Boundary }
  regular_spend(regular.real_input_datum(), redeemer, regular.real_tx())
}

test regular_redeemer_with_boundary_kind_predicates() {
  let input = regular.real_input_datum()
  let output = regular.real_output_datum()
  let redeemer = Redeemer { ..regular.real_redeemer(), kind: Boundary }
  and {
    boundary_proof_accepted(input, redeemer, output) == False,
    validation.committee_rotated(input, output) == False,
  }
}

// ── committee substitution and rotation ──

/// Boundary: the produced current commitment is not the consumed next commitment.
test boundary_produced_current_not_promoted_rejected() fail {
  let input = boundary.real_input_datum()
  let output =
    Datum {
      ..boundary.real_output_datum(),
      current_committee_commitment: boundary.consumed_current_commitment,
    }
  boundary_spend(input, boundary.real_redeemer(), boundary_tx(input, output))
}

test boundary_produced_current_not_promoted_predicate() {
  let output =
    Datum {
      ..boundary.real_output_datum(),
      current_committee_commitment: boundary.consumed_current_commitment,
    }
  validation.committee_rotated(boundary.real_input_datum(), output) == False
}

/// Boundary: the produced next commitment is not the one the proof binds.
test boundary_produced_next_not_proof_bound_rejected() fail {
  let input = boundary.real_input_datum()
  let output =
    Datum {
      ..boundary.real_output_datum(),
      next_committee_commitment: boundary.consumed_next_commitment,
    }
  boundary_spend(input, boundary.real_redeemer(), boundary_tx(input, output))
}

test boundary_produced_next_not_proof_bound_predicate() {
  let input = boundary.real_input_datum()
  let output =
    Datum {
      ..boundary.real_output_datum(),
      next_committee_commitment: boundary.consumed_next_commitment,
    }
  boundary_proof_accepted(input, boundary.real_redeemer(), output) == False
}

/// Regular: the produced current commitment changes.
test regular_current_commitment_changed_rejected() fail {
  let produced = regular.real_output_datum()
  let output =
    Datum {
      ..produced,
      current_committee_commitment: produced.next_committee_commitment,
    }
  regular_spend(
    regular.real_input_datum(),
    regular.real_redeemer(),
    regular_tx(output),
  )
}

test regular_current_commitment_changed_predicate() {
  let produced = regular.real_output_datum()
  let output =
    Datum {
      ..produced,
      current_committee_commitment: produced.next_committee_commitment,
    }
  validation.committees_frozen(regular.real_input_datum(), output) == False
}

/// Regular: the produced next commitment changes.
test regular_next_commitment_changed_rejected() fail {
  let produced = regular.real_output_datum()
  let output =
    Datum {
      ..produced,
      next_committee_commitment: produced.current_committee_commitment,
    }
  regular_spend(
    regular.real_input_datum(),
    regular.real_redeemer(),
    regular_tx(output),
  )
}

test regular_next_commitment_changed_predicate() {
  let produced = regular.real_output_datum()
  let output =
    Datum {
      ..produced,
      next_committee_commitment: produced.current_committee_commitment,
    }
  validation.committees_frozen(regular.real_input_datum(), output) == False
}

// ── anchor tampering (boundary fixture; each anchor replaced by another valid value) ──

test anchor_regular_verifying_key_changed_rejected() fail {
  let input = boundary.real_input_datum()
  let output =
    Datum {
      ..boundary.real_output_datum(),
      verifying_key_regular: regular.real_vk_regular(),
    }
  boundary_spend(input, boundary.real_redeemer(), boundary_tx(input, output))
}

test anchor_regular_verifying_key_changed_predicate() {
  let output =
    Datum {
      ..boundary.real_output_datum(),
      verifying_key_regular: regular.real_vk_regular(),
    }
  validation.anchors_preserved(boundary.real_input_datum(), output) == False
}

test anchor_boundary_verifying_key_changed_rejected() fail {
  let input = boundary.real_input_datum()
  let output =
    Datum {
      ..boundary.real_output_datum(),
      verifying_key_boundary: regular.real_vk_boundary(),
    }
  boundary_spend(input, boundary.real_redeemer(), boundary_tx(input, output))
}

test anchor_boundary_verifying_key_changed_predicate() {
  let output =
    Datum {
      ..boundary.real_output_datum(),
      verifying_key_boundary: regular.real_vk_boundary(),
    }
  validation.anchors_preserved(boundary.real_input_datum(), output) == False
}

test anchor_fork_version_changed_rejected() fail {
  let input = boundary.real_input_datum()
  let output =
    Datum { ..boundary.real_output_datum(), fork_version: #"05000000" }
  boundary_spend(input, boundary.real_redeemer(), boundary_tx(input, output))
}

test anchor_fork_version_changed_predicate() {
  let output =
    Datum { ..boundary.real_output_datum(), fork_version: #"05000000" }
  validation.anchors_preserved(boundary.real_input_datum(), output) == False
}

test anchor_genesis_validators_root_changed_rejected() fail {
  let input = boundary.real_input_datum()
  let output =
    Datum {
      ..boundary.real_output_datum(),
      genesis_validators_root: boundary.consumed_finalized_root,
    }
  boundary_spend(input, boundary.real_redeemer(), boundary_tx(input, output))
}

test anchor_genesis_validators_root_changed_predicate() {
  let output =
    Datum {
      ..boundary.real_output_datum(),
      genesis_validators_root: boundary.consumed_finalized_root,
    }
  validation.anchors_preserved(boundary.real_input_datum(), output) == False
}

// ── fabricated finality ──

/// Boundary: a produced finalized slot one period ahead of the one the proof binds.
test boundary_fabricated_finalized_slot_rejected() fail {
  let input = boundary.real_input_datum()
  let output =
    Datum {
      ..boundary.real_output_datum(),
      finalized_slot: boundary.produced_finalized_slot + 8192,
    }
  boundary_spend(input, boundary.real_redeemer(), boundary_tx(input, output))
}

test boundary_fabricated_finalized_slot_predicates() {
  let input = boundary.real_input_datum()
  let output =
    Datum {
      ..boundary.real_output_datum(),
      finalized_slot: boundary.produced_finalized_slot + 8192,
    }
  and {
    validation.slot_advances(input, output) == True,
    boundary_proof_accepted(input, boundary.real_redeemer(), output) == False,
  }
}

/// Boundary: a produced finalized header root other than the one the proof binds.
test boundary_fabricated_finalized_root_rejected() fail {
  let input = boundary.real_input_datum()
  let output =
    Datum {
      ..boundary.real_output_datum(),
      finalized_header_root: boundary.consumed_finalized_root,
    }
  boundary_spend(input, boundary.real_redeemer(), boundary_tx(input, output))
}

test boundary_fabricated_finalized_root_predicate() {
  let input = boundary.real_input_datum()
  let output =
    Datum {
      ..boundary.real_output_datum(),
      finalized_header_root: boundary.consumed_finalized_root,
    }
  boundary_proof_accepted(input, boundary.real_redeemer(), output) == False
}

// ── tampered redeemer fields (boundary fixture) ──

/// The lowest bit of the last byte of the proof element a is flipped.
test boundary_proof_byte_tampered_rejected() fail {
  let proof = boundary.real_proof()
  let redeemer =
    Redeemer {
      ..boundary.real_redeemer(),
      proof: Groth16Proof { ..proof, a: flip_last_bit(proof.a) },
    }
  boundary_spend(boundary.real_input_datum(), redeemer, boundary.real_tx())
}

/// The proof check aborts on the tampered element: the strict uncompress rejects the bytes as a point.
test boundary_proof_byte_tampered_check_aborts() fail {
  let proof = boundary.real_proof()
  let redeemer =
    Redeemer {
      ..boundary.real_redeemer(),
      proof: Groth16Proof { ..proof, a: flip_last_bit(proof.a) },
    }
  boundary_proof_accepted(
    boundary.real_input_datum(),
    redeemer,
    boundary.real_output_datum(),
  ) == False
}

/// The proof element a is replaced by the regular fixture's proof element a (a valid point).
test boundary_proof_point_substituted_rejected() fail {
  let redeemer =
    Redeemer {
      ..boundary.real_redeemer(),
      proof: Groth16Proof {
        ..boundary.real_proof(),
        a: regular.real_proof().a,
      },
    }
  boundary_spend(boundary.real_input_datum(), redeemer, boundary.real_tx())
}

test boundary_proof_point_substituted_predicate() {
  let redeemer =
    Redeemer {
      ..boundary.real_redeemer(),
      proof: Groth16Proof {
        ..boundary.real_proof(),
        a: regular.real_proof().a,
      },
    }
  boundary_proof_accepted(
    boundary.real_input_datum(),
    redeemer,
    boundary.real_output_datum(),
  ) == False
}

/// The aggregate public key is replaced by the regular fixture's (a valid point).
test boundary_apk_substituted_rejected() fail {
  let redeemer =
    Redeemer { ..boundary.real_redeemer(), apk: regular.real_redeemer().apk }
  boundary_spend(boundary.real_input_datum(), redeemer, boundary.real_tx())
}

test boundary_apk_substituted_predicates() {
  let input = boundary.real_input_datum()
  let redeemer =
    Redeemer { ..boundary.real_redeemer(), apk: regular.real_redeemer().apk }
  and {
    boundary_proof_accepted(input, redeemer, boundary.real_output_datum()) == False,
    signature_accepted(input, redeemer) == False,
  }
}

/// The participation count is one below the real count.
test boundary_count_changed_rejected() fail {
  let redeemer =
    Redeemer { ..boundary.real_redeemer(), count: boundary.real_count - 1 }
  boundary_spend(boundary.real_input_datum(), redeemer, boundary.real_tx())
}

test boundary_count_changed_predicate() {
  let redeemer =
    Redeemer { ..boundary.real_redeemer(), count: boundary.real_count - 1 }
  boundary_proof_accepted(
    boundary.real_input_datum(),
    redeemer,
    boundary.real_output_datum(),
  ) == False
}

/// The attested header root is replaced by another 32-byte root.
test boundary_attested_root_changed_rejected() fail {
  let redeemer =
    Redeemer {
      ..boundary.real_redeemer(),
      attested_header_root: boundary.consumed_finalized_root,
    }
  boundary_spend(boundary.real_input_datum(), redeemer, boundary.real_tx())
}

test boundary_attested_root_changed_predicates() {
  let input = boundary.real_input_datum()
  let redeemer =
    Redeemer {
      ..boundary.real_redeemer(),
      attested_header_root: boundary.consumed_finalized_root,
    }
  and {
    boundary_proof_accepted(input, redeemer, boundary.real_output_datum()) == False,
    signature_accepted(input, redeemer) == False,
  }
}

/// The signature is replaced by the regular fixture's signature (a valid point).
test boundary_signature_substituted_rejected() fail {
  let redeemer =
    Redeemer {
      ..boundary.real_redeemer(),
      signature: regular.real_redeemer().signature,
    }
  boundary_spend(boundary.real_input_datum(), redeemer, boundary.real_tx())
}

test boundary_signature_substituted_predicates() {
  let input = boundary.real_input_datum()
  let redeemer =
    Redeemer {
      ..boundary.real_redeemer(),
      signature: regular.real_redeemer().signature,
    }
  and {
    boundary_proof_accepted(input, redeemer, boundary.real_output_datum()) == True,
    signature_accepted(input, redeemer) == False,
  }
}

/// The lowest bit of the last byte of the signature is flipped.
test boundary_signature_byte_tampered_rejected() fail {
  let redeemer =
    Redeemer {
      ..boundary.real_redeemer(),
      signature: flip_last_bit(boundary.real_signature),
    }
  boundary_spend(boundary.real_input_datum(), redeemer, boundary.real_tx())
}

/// The signature check aborts on the tampered bytes: the strict uncompress rejects them as a point.
test boundary_signature_byte_tampered_check_aborts() fail {
  let redeemer =
    Redeemer {
      ..boundary.real_redeemer(),
      signature: flip_last_bit(boundary.real_signature),
    }
  signature_accepted(boundary.real_input_datum(), redeemer) == False
}

// ── participation threshold ──

test participation_threshold_rejects_341() {
  ( 341 >= bls.participation_threshold ) == False
}

test participation_threshold_admits_342() {
  342 >= bls.participation_threshold
}

// ── state token and produced datum (boundary fixture) ──

/// The continuing output carries no state token.
test boundary_state_token_missing_from_output_rejected() fail {
  let output =
    Output {
      ..boundary.bridge_output(boundary.real_output_datum()),
      value: from_lovelace(boundary.bridge_lovelace),
    }
  boundary_spend(
    boundary.real_input_datum(),
    boundary.real_redeemer(),
    boundary_tx_with_output(output),
  )
}

test boundary_state_token_missing_from_output_check_aborts() fail {
  let output =
    Output {
      ..boundary.bridge_output(boundary.real_output_datum()),
      value: from_lovelace(boundary.bridge_lovelace),
    }
  continuing_output_found(boundary_tx_with_output(output))
}

/// Two outputs at the bridge credential carry a state token.
test boundary_state_token_in_two_outputs_rejected() fail {
  let output = boundary.bridge_output(boundary.real_output_datum())
  boundary_spend(
    boundary.real_input_datum(),
    boundary.real_redeemer(),
    Transaction { ..boundary.real_tx(), outputs: [output, output] },
  )
}

test boundary_state_token_in_two_outputs_check_aborts() fail {
  let output = boundary.bridge_output(boundary.real_output_datum())
  continuing_output_found(
    Transaction { ..boundary.real_tx(), outputs: [output, output] },
  )
}

/// The output carrying the state token sits at a payment credential other than the bridge's.
test boundary_state_token_to_other_credential_rejected() fail {
  let output =
    Output {
      ..boundary.bridge_output(boundary.real_output_datum()),
      address: Address {
        payment_credential: VerificationKey(
          #"00000000000000000000000000000000000000000000000000000000",
        ),
        stake_credential: None,
      },
    }
  boundary_spend(
    boundary.real_input_datum(),
    boundary.real_redeemer(),
    boundary_tx_with_output(output),
  )
}

test boundary_state_token_to_other_credential_check_aborts() fail {
  let output =
    Output {
      ..boundary.bridge_output(boundary.real_output_datum()),
      address: Address {
        payment_credential: VerificationKey(
          #"00000000000000000000000000000000000000000000000000000000",
        ),
        stake_credential: None,
      },
    }
  continuing_output_found(boundary_tx_with_output(output))
}

/// The spent input carries no state token.
test boundary_input_without_state_token_rejected() fail {
  let spent =
    Output {
      ..boundary.bridge_output(boundary.real_input_datum()),
      value: from_lovelace(boundary.bridge_lovelace),
    }
  boundary_spend(
    boundary.real_input_datum(),
    boundary.real_redeemer(),
    Transaction {
      ..boundary.real_tx(),
      inputs: [Input { output_reference: boundary.own_ref(), output: spent }],
    },
  )
}

test boundary_input_without_state_token_check_aborts() fail {
  let spent =
    Output {
      ..boundary.bridge_output(boundary.real_input_datum()),
      value: from_lovelace(boundary.bridge_lovelace),
    }
  continuing_output_found(
    Transaction {
      ..boundary.real_tx(),
      inputs: [Input { output_reference: boundary.own_ref(), output: spent }],
    },
  )
}

/// The continuing output carries the produced datum by hash instead of inline.
test boundary_output_datum_hash_rejected() fail {
  let produced: Data = boundary.real_output_datum()
  let output =
    Output {
      ..boundary.bridge_output(boundary.real_output_datum()),
      datum: DatumHash(builtin.blake2b_256(builtin.serialise_data(produced))),
    }
  boundary_spend(
    boundary.real_input_datum(),
    boundary.real_redeemer(),
    boundary_tx_with_output(output),
  )
}

test boundary_output_datum_hash_check_aborts() fail {
  let produced: Data = boundary.real_output_datum()
  let output =
    Output {
      ..boundary.bridge_output(boundary.real_output_datum()),
      datum: DatumHash(builtin.blake2b_256(builtin.serialise_data(produced))),
    }
  validation.read_datum(output).finalized_slot == boundary.produced_finalized_slot
}

// ── rogue aggregate key ──

/// The rogue key's signature over the real signing root verifies on its own.
test rogue_key_signature_verifies_alone() {
  let redeemer =
    Redeemer {
      ..boundary.real_redeemer(),
      apk: rogue_key.rogue_apk,
      signature: rogue_key.rogue_signature,
    }
  signature_accepted(boundary.real_input_datum(), redeemer)
}

/// The redeemer carrying the rogue key and its signature is rejected.
test rogue_key_rejected() fail {
  let redeemer =
    Redeemer {
      ..boundary.real_redeemer(),
      apk: rogue_key.rogue_apk,
      signature: rogue_key.rogue_signature,
    }
  boundary_spend(boundary.real_input_datum(), redeemer, boundary.real_tx())
}

test rogue_key_proof_binding_predicate() {
  let redeemer =
    Redeemer {
      ..boundary.real_redeemer(),
      apk: rogue_key.rogue_apk,
      signature: rogue_key.rogue_signature,
    }
  boundary_proof_accepted(
    boundary.real_input_datum(),
    redeemer,
    boundary.real_output_datum(),
  ) == False
}
