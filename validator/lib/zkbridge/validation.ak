//// Layer-1 validation helpers — pure functions over the transaction/datum, so the bridge
//// spending validator and the state-thread minting policy stay thin and every check is
//// unit-testable in isolation (validation_test.ak). The checks: state-thread NFT continuity
//// (#8 spend side), output-datum reading, anchor bit-identity (#5), the regular-path
//// committee freeze (the partition structure), and the one-shot mint (#8 mint side).

use aiken/collection/dict
use aiken/collection/list
use cardano/assets.{AssetName, PolicyId, quantity_of, tokens}
use cardano/transaction.{InlineDatum, Output, OutputReference, Transaction, find_input}
use zkbridge/types.{Datum}

/// The unique continuing state output (#8, the state-thread core). The spent input must carry
/// the NFT, and EXACTLY ONE output at this script's `payment_credential` must carry it. Fails
/// (rejects the tx) otherwise:
///   - no NFT in the spent input → not the real state UTxO;
///   - zero matching outputs → escape (NFT sent elsewhere) or burn → no fork survives;
///   - two matching outputs → fork/duplication.
/// Keying on the NFT (not just the address) disambiguates multiple script-address outputs;
/// keying on `payment_credential` (not the full Address) ignores a stake-credential change.
pub fn continuing_state_output(
  self: Transaction,
  own_reference: OutputReference,
  state_token: PolicyId,
  name: AssetName,
) -> Output {
  expect Some(own_input) = find_input(self.inputs, own_reference)
  expect quantity_of(own_input.output.value, state_token, name) == 1
  let own_credential = own_input.output.address.payment_credential
  let continuing =
    list.filter(
      self.outputs,
      fn(o) {
        o.address.payment_credential == own_credential && quantity_of(
          o.value,
          state_token,
          name,
        ) == 1
      },
    )
  expect [continuing_output] = continuing
  continuing_output
}

/// Parse the continuing output's INLINE datum into the bridge `Datum` (#8 / the new state).
/// Rejects a missing, hash-only, or malformed datum — the new state must be readable + well-formed.
pub fn read_datum(output: Output) -> Datum {
  expect InlineDatum(raw) = output.datum
  expect parsed: Datum = raw
  parsed
}

/// The four protocol-anchor fields are bit-identical input↔output (#5). Structural `==` over
/// the vk records (incl. every `ic` element), the 4-byte fork, and the 32-byte gvr; ANY
/// deviation → False.
pub fn anchors_preserved(input: Datum, output: Datum) -> Bool {
  and {
    input.verifying_key_regular == output.verifying_key_regular,
    input.verifying_key_boundary == output.verifying_key_boundary,
    input.fork_version == output.fork_version,
    input.genesis_validators_root == output.genesis_validators_root,
  }
}

/// The committee commitments are frozen (partition: committees are mutable boundary-only).
/// Used on the REGULAR path — the regular proof binds only `input.current`, so NOTHING binds
/// the output committee fields there; without this freeze a regular tx could write garbage
/// commitments and corrupt the next tx's state. False if either committee field moved.
pub fn committees_frozen(input: Datum, output: Datum) -> Bool {
  and {
    input.current_committee_commitment == output.current_committee_commitment,
    input.next_committee_commitment == output.next_committee_commitment,
  }
}

/// Layer 4 (obligation #6): the finalized slot is STRICTLY forward-only — the rollback defense.
/// Equal = replay/no-progress; lower = a rollback to a stale finality. Both rejected; only a
/// higher slot (real progress) passes. Applies on BOTH branches (it checks the slot advancing,
/// not its period — sound under the boundary's finality lag).
pub fn slot_advances(input: Datum, output: Datum) -> Bool {
  output.finalized_slot > input.finalized_slot
}

/// Layer 5 (obligation #7): the boundary committee PROMOTION — output.current ← input.next. The
/// boundary proof binds the signer (= input.next) and the new next (= output.next, op-6), but
/// NOT output.current (it is not a public input), so without this a valid-proof relayer could
/// write garbage to output.current and corrupt the next tx's committee. The one on-chain rotation
/// check Layer 5 adds; the period gating is the proof+BLS (see docs/records.md D21, no on-chain
/// period arithmetic). False if the promotion is violated.
pub fn committee_rotated(input: Datum, output: Datum) -> Bool {
  output.current_committee_commitment == input.next_committee_commitment
}

/// The one-shot mint (#8, mint side): the `seed` UTxO is consumed AND exactly one token
/// (`name`, quantity 1) is minted under `policy_id`. The seed's single on-chain existence
/// makes re-minting impossible — no later tx can include it — so this can succeed at most once.
pub fn is_one_shot_mint(
  self: Transaction,
  seed: OutputReference,
  policy_id: PolicyId,
  name: AssetName,
) -> Bool {
  let seed_consumed =
    when find_input(self.inputs, seed) is {
      Some(_) -> True
      None -> False
    }
  let minted_exactly_one =
    when dict.to_pairs(tokens(self.mint, policy_id)) is {
      [Pair(minted_name, quantity)] -> minted_name == name && quantity == 1
      _ -> False
    }
  seed_consumed && minted_exactly_one
}
