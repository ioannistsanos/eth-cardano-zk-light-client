//// Layer-1 validation suite — the strawman-rejects discipline on-chain. Every check has a
//// POSITIVE (valid transition passes) and the attack NEGATIVES (each malformation/attack
//// rejects), so each check is proven load-bearing, not decorative. `fail` tests cover the
//// `expect`-based rejects (continuity singleton, datum parse); `== False` tests cover the
//// Bool-returning checks (anchors, committee freeze, one-shot). Mock contexts are built from
//// transaction.placeholder + assets.from_asset; bytes are size-faithful, not meaningful.

use cardano/address.{Address, Script, VerificationKey}
use cardano/assets.{Value, from_asset, from_lovelace, merge}
use cardano/transaction.{
  InlineDatum, Input, NoDatum, Output, OutputReference, Transaction, placeholder,
}
use zkbridge/types.{Datum, Groth16VerifyingKey, bridge_state_token_name}
use zkbridge/validation.{
  anchors_preserved, committee_rotated, committees_frozen, continuing_state_output,
  is_one_shot_mint, read_datum, slot_advances,
}

// ── size-faithful mock bytes (lengths plausible; values not meaningful) ──
const bridge_script: ByteArray =
  #"b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1"

// 28
const state_token: ByteArray =
  #"5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e"

// 28
const attacker_key: ByteArray =
  #"a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7"

// 28
const own_tx_id: ByteArray =
  #"0101010101010101010101010101010101010101010101010101010101010101"

// 32
const seed_tx_id: ByteArray =
  #"0202020202020202020202020202020202020202020202020202020202020202"

// 32
const root_a: ByteArray =
  #"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

const root_b: ByteArray =
  #"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

const commit_c: ByteArray =
  #"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"

const commit_d: ByteArray =
  #"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"

const root_alt: ByteArray =
  #"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"

const commit_alt: ByteArray =
  #"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"

const g1: ByteArray =
  #"111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111"

const g1_alt: ByteArray =
  #"333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333"

const g2: ByteArray =
  #"222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222"

const fork: ByteArray = #"05000000"

const fork_alt: ByteArray = #"06000000"

// ── mock builders ──
fn bridge_address() -> Address {
  Address { payment_credential: Script(bridge_script), stake_credential: None }
}

fn attacker_address() -> Address {
  Address { payment_credential: VerificationKey(attacker_key), stake_credential: None }
}

fn nft_value() -> Value {
  merge(from_lovelace(2_000_000), from_asset(state_token, bridge_state_token_name, 1))
}

fn plain_value() -> Value {
  from_lovelace(2_000_000)
}

fn vk() -> Groth16VerifyingKey {
  Groth16VerifyingKey {
    alpha: g1,
    beta: g2,
    gamma: g2,
    delta: g2,
    ic: [g1],
    commitment_g: g2,
    commitment_g_sigma_neg: g2,
  }
}

fn vk_alt() -> Groth16VerifyingKey {
  Groth16VerifyingKey {
    alpha: g1_alt,
    beta: g2,
    gamma: g2,
    delta: g2,
    ic: [g1],
    commitment_g: g2,
    commitment_g_sigma_neg: g2,
  }
}

fn base_datum() -> Datum {
  Datum {
    finalized_header_root: root_a,
    finalized_slot: 13107200,
    current_committee_commitment: commit_c,
    next_committee_commitment: commit_d,
    fork_version: fork,
    genesis_validators_root: root_b,
    verifying_key_regular: vk(),
    verifying_key_boundary: vk(),
  }
}

fn own_ref() -> OutputReference {
  OutputReference { transaction_id: own_tx_id, output_index: 0 }
}

fn seed_ref() -> OutputReference {
  OutputReference { transaction_id: seed_tx_id, output_index: 1 }
}

fn output_at(addr: Address, value: Value, d: Datum) -> Output {
  Output { address: addr, value: value, datum: InlineDatum(d), reference_script: None }
}

fn own_input(value: Value, d: Datum) -> Input {
  Input { output_reference: own_ref(), output: output_at(bridge_address(), value, d) }
}

fn input_at(reference: OutputReference) -> Input {
  Input {
    output_reference: reference,
    output: Output {
      address: attacker_address(),
      value: plain_value(),
      datum: NoDatum,
      reference_script: None,
    },
  }
}

fn spend_tx(inputs: List<Input>, outputs: List<Output>) -> Transaction {
  Transaction { ..placeholder, inputs: inputs, outputs: outputs }
}

fn mint_tx(inputs: List<Input>, mint: Value) -> Transaction {
  Transaction { ..placeholder, inputs: inputs, mint: mint }
}

// ─────────────────────────── #8 NFT continuity ───────────────────────────

test continuity_positive() {
  let d = base_datum()
  let tx =
    spend_tx([own_input(nft_value(), d)], [output_at(bridge_address(), nft_value(), d)])
  read_datum(continuing_state_output(tx, own_ref(), state_token, bridge_state_token_name)) == d
}

// input without the NFT → not the real state UTxO (step 2).
test continuity_input_without_nft() fail {
  let d = base_datum()
  let tx =
    spend_tx([own_input(plain_value(), d)], [output_at(bridge_address(), nft_value(), d)])
  read_datum(continuing_state_output(tx, own_ref(), state_token, bridge_state_token_name)) == d
}

// continuing output carries no NFT (burn / absent) → empty filter → no singleton.
test continuity_output_without_nft() fail {
  let d = base_datum()
  let tx =
    spend_tx([own_input(nft_value(), d)], [output_at(bridge_address(), plain_value(), d)])
  read_datum(continuing_state_output(tx, own_ref(), state_token, bridge_state_token_name)) == d
}

// two script-address outputs carry the NFT → fork/duplication → not a singleton.
test continuity_two_nft_outputs() fail {
  let d = base_datum()
  let tx =
    spend_tx(
      [own_input(nft_value(), d)],
      [
        output_at(bridge_address(), nft_value(), d),
        output_at(bridge_address(), nft_value(), d),
      ],
    )
  read_datum(continuing_state_output(tx, own_ref(), state_token, bridge_state_token_name)) == d
}

// NFT sent to a NON-script (attacker) address → thread capture → excluded by payment_credential.
test continuity_nft_to_attacker() fail {
  let d = base_datum()
  let tx =
    spend_tx([own_input(nft_value(), d)], [output_at(attacker_address(), nft_value(), d)])
  read_datum(continuing_state_output(tx, own_ref(), state_token, bridge_state_token_name)) == d
}

// the continuing output's datum is missing (NoDatum) → malformed new state.
test continuity_malformed_datum() fail {
  let d = base_datum()
  let bad_output =
    Output {
      address: bridge_address(),
      value: nft_value(),
      datum: NoDatum,
      reference_script: None,
    }
  let tx = spend_tx([own_input(nft_value(), d)], [bad_output])
  read_datum(continuing_state_output(tx, own_ref(), state_token, bridge_state_token_name)) == d
}

// ─────────────────────────── #8 one-shot mint ───────────────────────────

test one_shot_positive() {
  let tx =
    mint_tx([input_at(seed_ref())], from_asset(state_token, bridge_state_token_name, 1))
  is_one_shot_mint(tx, seed_ref(), state_token, bridge_state_token_name)
}

// the seed UTxO is not consumed → re-mint vector → reject.
test one_shot_seed_not_consumed() {
  let tx =
    mint_tx([input_at(own_ref())], from_asset(state_token, bridge_state_token_name, 1))
  is_one_shot_mint(tx, seed_ref(), state_token, bridge_state_token_name) == False
}

// mint quantity ≠ 1 → reject (two of the token).
test one_shot_mint_quantity_two() {
  let tx =
    mint_tx([input_at(seed_ref())], from_asset(state_token, bridge_state_token_name, 2))
  is_one_shot_mint(tx, seed_ref(), state_token, bridge_state_token_name) == False
}

// a second asset name under the policy → more than one token → reject.
test one_shot_extra_token() {
  let mint =
    merge(
      from_asset(state_token, bridge_state_token_name, 1),
      from_asset(state_token, "imposter", 1),
    )
  let tx = mint_tx([input_at(seed_ref())], mint)
  is_one_shot_mint(tx, seed_ref(), state_token, bridge_state_token_name) == False
}

// ─────────────────────────── #5 anchor bit-identity ───────────────────────────

test anchors_positive() {
  anchors_preserved(base_datum(), base_datum())
}

// anchors are preserved even when the MUTABLE fields change (anchors check only the anchors).
test anchors_ignore_mutable() {
  let new_state =
    Datum {
      ..base_datum(),
      finalized_slot: 13107264,
      finalized_header_root: root_alt,
    }
  anchors_preserved(base_datum(), new_state)
}

test anchors_vk_regular_tampered() {
  let tampered = Datum { ..base_datum(), verifying_key_regular: vk_alt() }
  anchors_preserved(base_datum(), tampered) == False
}

test anchors_vk_boundary_tampered() {
  let tampered = Datum { ..base_datum(), verifying_key_boundary: vk_alt() }
  anchors_preserved(base_datum(), tampered) == False
}

test anchors_fork_tampered() {
  let tampered = Datum { ..base_datum(), fork_version: fork_alt }
  anchors_preserved(base_datum(), tampered) == False
}

test anchors_gvr_tampered() {
  let tampered = Datum { ..base_datum(), genesis_validators_root: root_alt }
  anchors_preserved(base_datum(), tampered) == False
}

// ─────────────────────────── partition: regular committee freeze ───────────────────────────

test committees_frozen_positive() {
  committees_frozen(base_datum(), base_datum())
}

// a regular tx that silently rotates a committee commitment → corruption → reject.
test committees_frozen_current_changed() {
  let rotated = Datum { ..base_datum(), current_committee_commitment: commit_alt }
  committees_frozen(base_datum(), rotated) == False
}

test committees_frozen_next_changed() {
  let rotated = Datum { ..base_datum(), next_committee_commitment: commit_alt }
  committees_frozen(base_datum(), rotated) == False
}

// ─────────────────────────── Layer 4: finalized_slot forward-only (#6) ───────────────────────────

// a higher finalized slot = real finality progress → accept.
test slot_advances_higher() {
  let next_state = Datum { ..base_datum(), finalized_slot: 13107264 }
  slot_advances(base_datum(), next_state)
}

// equal slot = replay / no progress → reject (strictly greater, not ≥).
test slot_advances_equal_rejects() {
  slot_advances(base_datum(), base_datum()) == False
}

// a lower slot = the rollback attack the rule defends against → reject.
test slot_advances_lower_rejects() {
  let rolled_back = Datum { ..base_datum(), finalized_slot: 13107136 }
  slot_advances(base_datum(), rolled_back) == False
}

// ─────────────────────────── Layer 5: boundary committee promotion (#7) ───────────────────────────

// the promotion output.current ← input.next (here input.next = commit_d), with the new next
// installed (proof-bound on-chain; here just a distinct value) → accept.
test committee_rotated_promotion() {
  let promoted =
    Datum {
      ..base_datum(),
      current_committee_commitment: commit_d,
      next_committee_commitment: commit_alt,
    }
  committee_rotated(base_datum(), promoted)
}

// output.current ≠ input.next → the promotion is violated (garbage written to current) → reject.
test committee_rotated_violation_rejects() {
  let bad = Datum { ..base_datum(), current_committee_commitment: commit_alt }
  committee_rotated(base_datum(), bad) == False
}

// The Regular-tx-attempting-rotation case is Layer 1's committees_frozen, not Layer 5 — see
// committees_frozen_current_changed above (a Regular tx moving `current` → reject). The partition:
// Regular freezes both committees; Boundary promotes (current ← input.next) + installs the
// proof-bound next.
