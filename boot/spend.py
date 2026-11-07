#!/usr/bin/env python3
"""boot/spend.py — the Phase-A SPEND transaction assembler/submitter (the relayer's submit step).

The spend twin of boot/assemble.py: assemble.py MINTS the state NFT + creates the genesis bridge UTxO;
spend.py CONSUMES the live bridge UTxO with a Groth16-proof redeemer and RE-creates it with the advanced
datum. Reuses assemble.py's plumbing (Blockfrost context, the wallet, boot_params.json) + the two proven
seams: boot/datum.py (the OUTPUT datum, byte-identical to Aiken) and boot/redeemer.py (the gate-4
redeemer, byte-identical to Aiken). The daemon imports build_live_spend(); the CLI wraps it.

Modes (mirror assemble.py):
  (default, offline)  STRUCTURAL dry-build with SYNTHETIC inputs — NO network, NO live UTxO. Assemble
                      the spend tx around the proven redeemer + output-datum bytes; run the structural
                      guards (spend-script == bridge address, NFT continuity, datum decodes + is a valid
                      advance, redeemer byte-identity to gate-4); report size/min-ADA. Validates the
                      assembly BEFORE the production Boot exists.
  --dry-build         LIVE read of the bridge UTxO + build + Blockfrost EVALUATE (real ExUnits/fee/size,
                      REJECTS if the script would fail) — NO submit. The D27 measurement source + the
                      pre-submit gate. Needs a live bridge UTxO (production Boot).
  --submit            --dry-build path + sign + submit + poll + the datum-update byte-confirmation.

Preview only, never mainnet. Keys + project_id from ~/.config/zkbridge/preview/ (outside git).
"""
from __future__ import annotations

import argparse
import hashlib
import json

import pycardano as pc

import datum as datum_mod
import redeemer as redeemer_mod
from assemble import (
    APPLIED_BLUEPRINT, COINS_PER_UTXO_BYTE, MAX_TX_SIZE, POLL_INTERVAL_S, POLL_TIMEOUT_S,
    REPO, STATE_TOKEN_NAME, band, build_context, fail, load_deployer, load_params,
)

FIXTURES = REPO / "validator" / "fixtures"
GENESIS_HEX = REPO / "boot" / "genesis_datum_period1600.hex"

# Offline structural placeholder ExUnits — the gate-1 (full_validator_real_regular_positive) measurement,
# so the offline size estimate is production-faithful. --dry-build replaces these with the live evaluation.
GATE1_EX_UNITS = pc.ExecutionUnits(mem=650_438, steps=5_944_631_108)


# ── shared builders (the daemon + both CLI paths use these) ──

def applied_spend_script() -> pc.PlutusV3Script:
    """The APPLIED bridge spending validator (parameterized by POLICY_ID via derive_params.py)."""
    for validator in json.loads(APPLIED_BLUEPRINT.read_text())["validators"]:
        if validator["title"] == "bridge.bridge.spend":
            return pc.PlutusV3Script(bytes.fromhex(validator["compiledCode"]))
    fail(f"bridge.bridge.spend not found in {APPLIED_BLUEPRINT}")


def make_output_datum(input_datum_bytes: bytes, kind: str, finalized_header_root: bytes,
                      finalized_slot: int, new_next_committee_commitment: bytes | None) -> bytes:
    """The OUTPUT inline datum: decode the on-chain INPUT datum, apply the validation.ak advance
    (anchors + (regular) committees carried), re-encode. byte-identical to Aiken (boot/datum.py gates)."""
    input_datum = datum_mod.decode_datum(input_datum_bytes)
    if kind == "regular":
        output = datum_mod.advance_regular(input_datum, finalized_header_root, finalized_slot)
    elif kind == "boundary":
        if new_next_committee_commitment is None:
            fail("boundary advance requires new_next_committee_commitment")
        output = datum_mod.advance_boundary(input_datum, finalized_header_root, finalized_slot,
                                            new_next_committee_commitment)
    else:
        fail(f"unknown kind {kind!r}")
    return datum_mod.datum_cbor(output)


def make_redeemer_data(kind: str, proof_redeemer: dict, bls: dict) -> redeemer_mod.Redeemer:
    """The on-chain redeemer (boot/redeemer.py — gate-4 byte-identical to Aiken). proof_redeemer is
    cmd/proof_to_redeemer's shape (commitment UNCOMPRESSED); bls carries apk/signature/count/attested."""
    transition = redeemer_mod.Regular() if kind == "regular" else redeemer_mod.Boundary()
    return redeemer_mod.build_redeemer(
        transition, proof_redeemer, bls["apk_uncompressed"], bls["signature"],
        bls["count"], bls["attested_header_root"],
    )


def bridge_nft(policy: pc.ScriptHash) -> pc.MultiAsset:
    return pc.MultiAsset({policy: pc.Asset({pc.AssetName(STATE_TOKEN_NAME): 1})})


# ── structural guards (fail-closed; the offline test + a sanity layer on the live path) ──

def guard_spend_script(script: pc.PlutusV3Script, bridge_address: pc.Address) -> None:
    derived = pc.plutus_script_hash(script).payload.hex()
    expected = bridge_address.payment_part.payload.hex()
    if derived != expected:
        fail(f"guard spend-script: hash {derived} != bridge address script {expected}")
    print(f"✓ guard spend-script == bridge address: {derived[:16]}…")


def guard_redeemer_bytepin(redeemer_data: redeemer_mod.Redeemer) -> None:
    cbor = redeemer_mod.redeemer_cbor(redeemer_data)
    sha = hashlib.sha256(cbor).hexdigest()
    if sha != redeemer_mod.AIKEN_PIN or len(cbor) != redeemer_mod.AIKEN_SIZE:
        fail(f"guard redeemer: sha {sha} / {len(cbor)} B != gate-4 {redeemer_mod.AIKEN_PIN} / {redeemer_mod.AIKEN_SIZE} B")
    print(f"✓ guard redeemer byte-identity (gate-4): sha2_256 {sha[:16]}… ({len(cbor)} B)")


def guard_output(output: pc.TransactionOutput, policy: pc.ScriptHash, bridge_address: pc.Address,
                 input_datum_bytes: bytes, kind: str) -> None:
    """The output carries (POLICY, zkbridge_state, 1) at the bridge address, the inline datum decodes,
    and the advance is valid per validation.ak (anchors held; regular freezes committees)."""
    held = output.amount.multi_asset.get(policy, {}).get(pc.AssetName(STATE_TOKEN_NAME), 0)
    if held != 1 or output.address != bridge_address:
        fail(f"guard output: NFT qty {held}, addr match {output.address == bridge_address}")
    raw = output.datum.cbor if hasattr(output.datum, "cbor") else bytes(output.datum)
    out_datum = datum_mod.decode_datum(raw)
    in_datum = datum_mod.decode_datum(input_datum_bytes)
    anchors_held = (out_datum.verifying_key_regular == in_datum.verifying_key_regular
                    and out_datum.verifying_key_boundary == in_datum.verifying_key_boundary
                    and out_datum.fork_version == in_datum.fork_version
                    and out_datum.genesis_validators_root == in_datum.genesis_validators_root)
    slot_forward = out_datum.finalized_slot > in_datum.finalized_slot
    if kind == "regular":
        committees_ok = (out_datum.current_committee_commitment == in_datum.current_committee_commitment
                         and out_datum.next_committee_commitment == in_datum.next_committee_commitment)
    else:
        committees_ok = out_datum.current_committee_commitment == in_datum.next_committee_commitment
    if not (anchors_held and slot_forward and committees_ok):
        fail(f"guard output advance: anchors_held={anchors_held} slot_forward={slot_forward} "
             f"committees_ok={committees_ok}")
    print(f"✓ guard output: (POLICY,zkbridge_state,1) @ bridge + inline datum decodes ({len(raw)} B) + "
          f"valid {kind} advance (anchors held, slot forward, committees {'frozen' if kind=='regular' else 'rotated'})")


# ── offline structural dry-build (default; runs NOW, no network) ──

def offline() -> None:
    print("── spend assembler (OFFLINE structural dry-build · no network · no live UTxO) ──")
    params = load_params()
    policy = pc.ScriptHash(bytes.fromhex(params["policy_id"]))
    bridge_address = pc.Address.from_primitive(params["bridge_address"])
    spend_script = applied_spend_script()
    guard_spend_script(spend_script, bridge_address)

    # input datum = the on-disk genesis (gate-a-proven bytes, toy-vk rehearsal anchors — the SHAPE is
    # N-independent, so the structure equals the production real-n=512 bridge's). regular advance.
    input_datum_bytes = bytes.fromhex(GENESIS_HEX.read_text().strip())
    input_slot = datum_mod.decode_datum(input_datum_bytes).finalized_slot
    new_finalized = bytes.fromhex("11" * 32)         # synthetic next-finality root (live: from beacon)
    new_slot = input_slot + 32                        # +1 epoch — slot_advances
    output_datum_bytes = make_output_datum(input_datum_bytes, "regular", new_finalized, new_slot, None)

    # redeemer = the gate-4 regular redeemer (the committed real-n=512 proof_redeemer + period-1600 σ).
    proof_redeemer = json.loads((FIXTURES / "proof_redeemer_regular_n512.json").read_text())["proof_redeemer"]
    bls = json.loads((FIXTURES / "bls_regular_period1600.json").read_text())
    redeemer_data = make_redeemer_data("regular", proof_redeemer, bls)
    guard_redeemer_bytepin(redeemer_data)

    # the new bridge output (NFT + output datum + min-ADA).
    class _Ctx:
        class protocol_param:
            coins_per_utxo_byte = COINS_PER_UTXO_BYTE

    bridge_output = pc.TransactionOutput(bridge_address, pc.Value(coin=0, multi_asset=bridge_nft(policy)),
                                         datum=pc.RawCBOR(output_datum_bytes))
    bridge_output.amount.coin = pc.min_lovelace(_Ctx(), output=bridge_output)
    guard_output(bridge_output, policy, bridge_address, input_datum_bytes, "regular")

    # assemble a SYNTHETIC spend tx (structure only — not balanced; --dry-build does the real balance).
    relayer = pc.Address(pc.VerificationKeyHash(b"\x11" * 28), network=pc.Network.TESTNET)
    redeemer = pc.Redeemer(redeemer_data, GATE1_EX_UNITS)
    redeemer.tag = pc.RedeemerTag.SPEND
    body = pc.TransactionBody(
        inputs=[pc.TransactionInput(pc.TransactionId(b"\xbb" * 32), 0),    # the bridge (script) input
                pc.TransactionInput(pc.TransactionId(b"\xff" * 32), 0)],   # relayer funding
        outputs=[bridge_output, pc.TransactionOutput(relayer, pc.Value(coin=5_000_000))],
        fee=900_000,
        collateral=[pc.TransactionInput(pc.TransactionId(b"\xcc" * 32), 0)],
    )
    witness = pc.TransactionWitnessSet(
        plutus_v3_script=[spend_script], redeemer=[redeemer],
        vkey_witnesses=[pc.VerificationKeyWitness(pc.VerificationKey(b"\x55" * 32), b"\x66" * 64)])
    tx_size = len(pc.Transaction(body, witness).to_cbor())
    min_ada = bridge_output.amount.coin

    print("\n── offline structural result (measured as-is) ──")
    print(f"  output datum   : {len(output_datum_bytes)} B  sha2_256 {hashlib.sha256(output_datum_bytes).hexdigest()[:16]}…")
    print(f"  bridge min-ADA : {min_ada} lovelace ≈ {min_ada/1e6:.4f} ADA")
    print(f"  tx (synthetic) : ~{tx_size} B  ({100*tx_size/MAX_TX_SIZE:.1f}% of {MAX_TX_SIZE}; {band(tx_size, (0, MAX_TX_SIZE))})")
    print("  ALL STRUCTURAL GUARDS GREEN — assembly is well-formed. Real ExUnits/fee/size + script")
    print("  acceptance come from --dry-build against the LIVE bridge UTxO (production Boot required).")


# ── live dry-build + submit (need the production bridge UTxO on Preview) ──

def find_bridge_utxo(context, bridge_address: pc.Address, policy: pc.ScriptHash):
    for utxo in context.utxos(str(bridge_address)):
        if utxo.output.amount.multi_asset.get(policy, {}).get(pc.AssetName(STATE_TOKEN_NAME), 0) == 1:
            return utxo
    fail("no bridge UTxO carrying the state NFT at the bridge address (production Boot not done yet?)")


def pure_ada_utxo(context, address: pc.Address):
    """A collateral candidate: a deployer UTxO with ONLY ADA (no multi-asset)."""
    for utxo in context.utxos(str(address)):
        if not utxo.output.amount.multi_asset and utxo.output.amount.coin >= 5_000_000:
            return utxo
    fail("no pure-ADA ≥5 tADA collateral UTxO at the relayer address (run assemble.py --prep-collateral)")


def build_live_spend(context, deployer: pc.Address, kind: str, finalized_header_root: bytes,
                     finalized_slot: int, new_next_committee_commitment: bytes | None,
                     proof_redeemer: dict, bls: dict):
    """Assemble the LIVE spend tx (the daemon's submit step + the CLI's dry-build/submit). Reads the live
    bridge UTxO + its inline datum, builds the advanced output datum + the gate-4 redeemer, returns the
    TransactionBuilder + the output datum bytes (the caller evaluates / signs / submits)."""
    params = load_params()
    policy = pc.ScriptHash(bytes.fromhex(params["policy_id"]))
    bridge_address = pc.Address.from_primitive(params["bridge_address"])
    spend_script = applied_spend_script()
    guard_spend_script(spend_script, bridge_address)

    bridge_utxo = find_bridge_utxo(context, bridge_address, policy)
    input_raw = (bridge_utxo.output.datum.cbor if hasattr(bridge_utxo.output.datum, "cbor")
                 else bytes(bridge_utxo.output.datum))
    output_datum_bytes = make_output_datum(input_raw, kind, finalized_header_root, finalized_slot,
                                           new_next_committee_commitment)
    redeemer_data = make_redeemer_data(kind, proof_redeemer, bls)

    bridge_output = pc.TransactionOutput(bridge_address, pc.Value(coin=0, multi_asset=bridge_nft(policy)),
                                         datum=pc.RawCBOR(output_datum_bytes))
    bridge_output.amount.coin = pc.min_lovelace(context, output=bridge_output)
    guard_output(bridge_output, policy, bridge_address, input_raw, kind)

    spend_redeemer = pc.Redeemer(redeemer_data)              # build() fills its ex_units in-place (evaluate)
    builder = pc.TransactionBuilder(context)
    builder.add_script_input(bridge_utxo, script=spend_script, redeemer=spend_redeemer)
    builder.add_input_address(deployer)                      # fund the fee
    builder.add_output(bridge_output)
    builder.collaterals = [pure_ada_utxo(context, deployer)]
    return builder, bridge_output, output_datum_bytes, spend_redeemer


def _phase_inputs(args) -> tuple:
    """CLI per-phase inputs (the daemon supplies these live from the prover + beacon)."""
    if not args.finalized_root or args.finalized_slot is None:
        fail("--dry-build / --submit require --finalized-root and --finalized-slot")
    new_next = bytes.fromhex(args.next_commitment) if args.next_commitment else None
    proof_redeemer = json.loads(open(args.proof).read())["proof_redeemer"] if args.proof else \
        json.loads((FIXTURES / "proof_redeemer_regular_n512.json").read_text())["proof_redeemer"]
    bls = json.loads(open(args.bls).read()) if args.bls else \
        json.loads((FIXTURES / "bls_regular_period1600.json").read_text())
    return args.kind, bytes.fromhex(args.finalized_root), args.finalized_slot, new_next, proof_redeemer, bls


def _emit_json(args, payload: dict) -> None:
    """Emit a machine-readable line the relayer daemon parses (prefixed so it's unambiguous in stdout).
    Additive: silent unless --emit-json is passed, so all existing (human) output is unchanged."""
    if getattr(args, "emit_json", False):
        print("RELAYER_JSON " + json.dumps(payload))


def dry_build(args) -> None:
    print("── spend --dry-build (LIVE read + Blockfrost EVALUATE · NO submit) ──")
    context = build_context()
    skey, deployer = load_deployer()
    kind, finalized_root, finalized_slot, new_next, proof_redeemer, bls = _phase_inputs(args)
    builder, bridge_output, output_datum_bytes, spend_redeemer = build_live_spend(
        context, deployer, kind, finalized_root, finalized_slot, new_next, proof_redeemer, bls)
    signed = builder.build_and_sign([skey], change_address=deployer)  # build EVALUATES (rejects if bad); local sign, NOT submitted
    ex = spend_redeemer.ex_units
    size = len(signed.to_cbor())
    fee = signed.transaction_body.fee
    print("\n── dry-build result (D27 source — measured as-is) ──")
    print(f"  ExUnits        : {ex.steps} steps / {ex.mem} mem")
    print(f"  fee            : {fee} lovelace ≈ {fee/1e6:.4f} ADA")
    print(f"  tx size        : {size} B  ({100*size/MAX_TX_SIZE:.1f}% of {MAX_TX_SIZE})")
    print(f"  output datum   : {len(output_datum_bytes)} B")
    print("  SCRIPT ACCEPTED by the live evaluation — NOT submitted (use --submit).")
    _emit_json(args, {"tx_hash": None, "ex_units_steps": ex.steps, "ex_units_mem": ex.mem,
                      "fee_lovelace": int(fee), "tx_size_bytes": size, "datum_confirmed": False})


def submit(args) -> None:
    print("── spend --submit (LIVE · Preview) ──")
    context = build_context()
    skey, deployer = load_deployer()
    kind, finalized_root, finalized_slot, new_next, proof_redeemer, bls = _phase_inputs(args)
    builder, bridge_output, output_datum_bytes, spend_redeemer = build_live_spend(
        context, deployer, kind, finalized_root, finalized_slot, new_next, proof_redeemer, bls)
    signed = builder.build_and_sign([skey], change_address=deployer)   # build EVALUATES (pre-submit gate)
    tx_id = str(signed.id)
    ex = spend_redeemer.ex_units
    print(f"  built + signed: {tx_id} ({len(signed.to_cbor())} B, fee {signed.transaction_body.fee}, "
          f"ExUnits {ex.steps} steps / {ex.mem} mem)")
    context.submit_tx(signed)
    print(f"  submitted — polling the bridge address for the advanced datum…")
    params = load_params()
    policy = pc.ScriptHash(bytes.fromhex(params["policy_id"]))
    bridge_address = pc.Address.from_primitive(params["bridge_address"])
    import time
    deadline = time.time() + POLL_TIMEOUT_S
    while time.time() < deadline:
        time.sleep(POLL_INTERVAL_S)
        for utxo in context.utxos(str(bridge_address)):
            if utxo.output.amount.multi_asset.get(policy, {}).get(pc.AssetName(STATE_TOKEN_NAME), 0) != 1:
                continue
            on_chain = (utxo.output.datum.cbor if hasattr(utxo.output.datum, "cbor")
                        else bytes(utxo.output.datum))
            if on_chain == output_datum_bytes:                # the datum-update byte-confirmation
                print(f"\n── SPEND CONFIRMED — {kind} ──")
                print(f"  tx hash       : {tx_id}")
                print(f"  new bridge UTxO: {utxo.input.transaction_id}#{utxo.input.index}")
                print(f"  datum update  : on-chain inline datum == boot/datum.py bytes ({len(on_chain)} B) ✓")
                _emit_json(args, {"tx_hash": tx_id, "ex_units_steps": ex.steps, "ex_units_mem": ex.mem,
                                  "fee_lovelace": int(signed.transaction_body.fee),
                                  "tx_size_bytes": len(signed.to_cbor()), "datum_confirmed": True})
                return
    fail(f"spend not confirmed within {POLL_TIMEOUT_S}s (tx {tx_id}; check the explorer)")


def main() -> None:
    ap = argparse.ArgumentParser(description="Phase-A spend tx assembler/submitter")
    ap.add_argument("--dry-build", action="store_true", help="live read + evaluate, no submit (D27)")
    ap.add_argument("--submit", action="store_true", help="live submit (Preview)")
    ap.add_argument("--kind", choices=["regular", "boundary"], default="regular")
    ap.add_argument("--finalized-root", help="new finalized_header_root (64 hex)")
    ap.add_argument("--finalized-slot", type=int, help="new finalized_slot")
    ap.add_argument("--next-commitment", help="boundary: new next_committee_commitment (64 hex)")
    ap.add_argument("--proof", help="proof_redeemer JSON (default: committed regular fixture)")
    ap.add_argument("--bls", help="BLS fixture JSON (default: committed regular fixture)")
    ap.add_argument("--emit-json", action="store_true", help="emit a machine-readable RELAYER_JSON line for the daemon")
    args = ap.parse_args()
    if args.dry_build:
        dry_build(args)
    elif args.submit:
        submit(args)
    else:
        offline()


if __name__ == "__main__":
    main()
