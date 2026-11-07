#!/usr/bin/env python3
"""Boot/init transaction assembler (§2.1.6) — PyCardano.

Three modes:
  (default, offline)  dry-build the Boot tx with synthetic inputs + static params; run the guards;
                      report vs the pre-registered numbers. No network. (Stage-1c-ii.)
  --prep-collateral   ensure the deployer wallet has ≥2 UTxOs — a Plutus mint needs a SEPARATE
                      collateral UTxO (collateral cannot be the seed input). Splits a single UTxO.
  --submit            LIVE Boot on Preview: build with live params + real UTxOs, run the three guards
                      IN ORDER (datum byte-identity sha2_256 FIRST, then param-identity, then output
                      self-check), sign with the throwaway skey, submit, poll to confirmation, query
                      the bridge address. REHEARSAL (toy vks ⇒ frozen-anchor dead-end bridge).

In all modes Aiken is the source of truth for the datum bytes (boot/genesis_datum_*.hex, pinned by
sha2_256 in validator/lib/zkbridge/genesis_datum_test.ak); the datum embeds VERBATIM via RawCBOR.
Keys + the Blockfrost project_id are read from OUTSIDE the repo (~/.config/zkbridge/preview/), never
committed. Preview only, never mainnet.
"""

import argparse
import hashlib
import json
import os
import sys
import time
from pathlib import Path

import pycardano as pc
from blockfrost import ApiUrls

REPO = Path(__file__).resolve().parent.parent
DATUM_HEX = REPO / "boot" / "genesis_datum_period1600.hex"
BOOT_PARAMS = REPO / "boot" / "boot_params.json"
APPLIED_BLUEPRINT = REPO / "validator" / "plutus.applied.json"
KEYDIR = Path(os.path.expanduser("~/.config/zkbridge/preview"))

EXPECTED_DATUM_SHA256 = "86eeded99b2476e82de6ef198f83f906e14df9cee5fe67f860eb7a6e6c2fdad6"
STATE_TOKEN_NAME = b"zkbridge_state"

# Known Conway protocol params (offline mode); --submit reads them LIVE and they match (verified).
COINS_PER_UTXO_BYTE = 4310
MIN_FEE_CONSTANT = 155381
MIN_FEE_COEFFICIENT = 44
MAX_TX_SIZE = 16384
PRICE_MEM = 0.0577
PRICE_STEP = 0.0000721

PRE = {"datum_size_b": 2632, "min_ada_lovelace": (11_000_000, 13_000_000),
       "tx_size_b": (3500, 5000), "fee_lovelace": (500_000, 800_000)}

COLLATERAL_LOVELACE = 5_000_000
POLL_INTERVAL_S = 20
POLL_TIMEOUT_S = 360


def fail(message: str) -> None:
    sys.stderr.write(f"HALT: {message}\n")
    sys.exit(1)


# ── shared ──

def load_datum_bytes(datum_hex_path: Path = DATUM_HEX, expected_sha: str = EXPECTED_DATUM_SHA256) -> bytes:
    """GUARD 1 (FIRST): the datum bytes are byte-identical to Aiken's serialise (sha2_256 pin). Defaults
    to the toy Stage-1b genesis; --datum-hex/--datum-sha override it for a value-swap Boot (vk_D24
    rehearsal now, vk_fresh scenario later) WITHOUT touching the toy genesis or its 86eeded9 pin."""
    if not datum_hex_path.exists():
        fail(f"datum hex not found: {datum_hex_path}")
    datum = bytes.fromhex(datum_hex_path.read_text().strip())
    digest = hashlib.sha256(datum).hexdigest()
    if digest != expected_sha:
        fail(f"datum BYTE-IDENTITY guard FAILED:\n  got    {digest}\n  expect {expected_sha}")
    print(f"✓ guard 1/3 datum byte-identity: sha2_256 == {expected_sha[:16]}… ({len(datum)} B)")
    return datum


def load_params() -> dict:
    if not BOOT_PARAMS.exists():
        fail(f"param-chain output not found: {BOOT_PARAMS} (run boot/derive_params.py first)")
    return json.loads(BOOT_PARAMS.read_text())


def applied_mint_script() -> pc.PlutusV3Script:
    if not APPLIED_BLUEPRINT.exists():
        fail(f"applied blueprint not found: {APPLIED_BLUEPRINT} (run boot/derive_params.py first)")
    for v in json.loads(APPLIED_BLUEPRINT.read_text())["validators"]:
        if v["title"].startswith("state_thread.state_thread_nft"):
            return pc.PlutusV3Script(bytes.fromhex(v["compiledCode"]))
    fail("state_thread_nft not found in the applied blueprint")


def build_context() -> pc.BlockFrostChainContext:
    env = KEYDIR / "blockfrost.env"
    if not env.exists():
        fail(f"{env} not found")
    pid = next(l.split("=", 1)[1].strip() for l in env.read_text().splitlines() if l.startswith("BLOCKFROST_PROJECT_ID="))
    if not pid.startswith("preview"):
        fail(f"project_id is not a Preview key (prefix '{pid[:8]}…')")
    return pc.BlockFrostChainContext(pid, base_url=ApiUrls.preview.value)


def load_deployer() -> tuple:
    skey = pc.PaymentSigningKey.load(str(KEYDIR / "payment.skey"))
    address = pc.Address.from_primitive((KEYDIR / "payment.addr").read_text().strip())
    return skey, address


def build_bridge_output(params: dict, datum: bytes, context, min_lovelace_fn) -> tuple:
    """Build the bridge UTxO (minADA + NFT + inline datum) and run guards 2 + 3."""
    policy_hex = params["policy_id"]
    policy = pc.ScriptHash(bytes.fromhex(policy_hex))
    nft = pc.MultiAsset({policy: pc.Asset({pc.AssetName(STATE_TOKEN_NAME): 1})})
    mint_script = applied_mint_script()

    # GUARD 2: the applied mint script's own hash == the POLICY_ID baked into the bridge.
    derived = pc.plutus_script_hash(mint_script).payload.hex()
    if derived != policy_hex:
        fail(f"guard 2/3 param-identity FAILED: mint hash {derived} != POLICY_ID {policy_hex}")
    print(f"✓ guard 2/3 param-identity: applied mint script hash == POLICY_ID {policy_hex[:16]}…")

    bridge_address = pc.Address.from_primitive(params["bridge_address"])
    output = pc.TransactionOutput(bridge_address, pc.Value(coin=0, multi_asset=nft), datum=pc.RawCBOR(datum))
    output.amount.coin = min_lovelace_fn(output)

    # GUARD 3: the output carries exactly (POLICY_ID, zkbridge_state, 1) at the bridge address.
    held = output.amount.multi_asset.get(policy, {}).get(pc.AssetName(STATE_TOKEN_NAME), 0)
    if held != 1 or output.address != bridge_address:
        fail(f"guard 3/3 output self-check FAILED: NFT qty {held}, addr match {output.address == bridge_address}")
    print(f"✓ guard 3/3 output self-check: (POLICY_ID, zkbridge_state, 1) at the bridge address")
    return output, nft, mint_script, bridge_address


def band(value, lo_hi):
    lo, hi = lo_hi
    return "within" if lo <= value <= hi else ("UNDER" if value < lo else "OVER")


# ── offline dry-build (default) ──

def offline(datum_hex_path: Path = DATUM_HEX, expected_sha: str = EXPECTED_DATUM_SHA256) -> None:
    print("── Boot assembler (OFFLINE dry-build · REHEARSAL · no network) ──")
    datum = load_datum_bytes(datum_hex_path, expected_sha)
    params = load_params()

    class _Ctx:
        class protocol_param:
            coins_per_utxo_byte = COINS_PER_UTXO_BYTE

    bridge_output, nft, mint_script, _ = build_bridge_output(
        params, datum, _Ctx(), lambda o: pc.min_lovelace(_Ctx(), output=o))
    min_ada = bridge_output.amount.coin

    deployer = pc.Address(pc.VerificationKeyHash(b"\x11" * 28), network=pc.Network.TESTNET)
    redeemer = pc.Redeemer(0, pc.ExecutionUnits(2_000_000, 500_000_000))
    redeemer.tag = pc.RedeemerTag.MINT
    body = pc.TransactionBody(
        inputs=[pc.TransactionInput(pc.TransactionId(b"\x22" * 32), 0)],
        outputs=[bridge_output, pc.TransactionOutput(deployer, pc.Value(coin=5_000_000))],
        fee=700_000, mint=nft, collateral=[pc.TransactionInput(pc.TransactionId(b"\x44" * 32), 0)],
    )
    witness = pc.TransactionWitnessSet(
        plutus_v3_script=[mint_script], redeemer=[redeemer],
        vkey_witnesses=[pc.VerificationKeyWitness(pc.VerificationKey(b"\x55" * 32), b"\x66" * 64)])
    tx_size = len(pc.Transaction(body, witness).to_cbor())
    fee = MIN_FEE_CONSTANT + MIN_FEE_COEFFICIENT * tx_size + int(PRICE_MEM * 2_000_000 + PRICE_STEP * 500_000_000)
    print("\n── offline vs pre-registrations ──")
    print(f"  datum {len(datum)} B (match) · minADA {min_ada} ≈ {min_ada/1e6:.2f} ADA ({band(min_ada, PRE['min_ada_lovelace'])})")
    print(f"  tx ~{tx_size} B ({band(tx_size, PRE['tx_size_b'])}, {100*tx_size/MAX_TX_SIZE:.1f}% of {MAX_TX_SIZE}) · fee ~{fee} ≈ {fee/1e6:.2f} ADA ({band(fee, PRE['fee_lovelace'])})")
    print("  SUBMISSION STUBBED — use --submit for the live Preview rehearsal.")


# ── prep collateral (split a single UTxO) ──

def prep_collateral() -> None:
    print("── prep collateral (ensure ≥2 UTxOs for seed + collateral) ──")
    context = build_context()
    skey, deployer = load_deployer()
    utxos = context.utxos(str(deployer))
    print(f"  deployer has {len(utxos)} UTxO(s)")
    if len(utxos) >= 2:
        for u in utxos:
            print(f"    {u.input.transaction_id}#{u.input.index}  {u.output.amount.coin/1e6:.2f} tADA")
        print("  ≥2 UTxOs already — no split needed.")
        return
    builder = pc.TransactionBuilder(context)
    builder.add_input_address(deployer)
    builder.add_output(pc.TransactionOutput(deployer, pc.Value(coin=COLLATERAL_LOVELACE)))
    signed = builder.build_and_sign([skey], change_address=deployer)
    tx_id = str(signed.id)
    context.submit_tx(signed)
    print(f"  split submitted: {tx_id} — polling for ≥2 UTxOs…")
    deadline = time.time() + POLL_TIMEOUT_S
    while time.time() < deadline:
        time.sleep(POLL_INTERVAL_S)
        u = context.utxos(str(deployer))
        if len(u) >= 2:
            print(f"  ✓ confirmed — {len(u)} UTxOs:")
            for x in u:
                print(f"    {x.input.transaction_id}#{x.input.index}  {x.output.amount.coin/1e6:.2f} tADA")
            return
    fail("split not confirmed within the poll window")


# ── live Boot submit ──

def find_utxo(context, address, ref: str):
    txid, ix = ref.split("#")
    for u in context.utxos(str(address)):
        if str(u.input.transaction_id) == txid and u.input.index == int(ix):
            return u
    fail(f"UTxO {ref} not found at the deployer address")


def submit_boot(seed_ref: str, collateral_ref: str, datum_hex_path: Path = DATUM_HEX,
                expected_sha: str = EXPECTED_DATUM_SHA256) -> None:
    print("── LIVE Boot submit (Preview · REHEARSAL · dead-end bridge) ──")
    context = build_context()
    skey, deployer = load_deployer()
    datum = load_datum_bytes(datum_hex_path, expected_sha)        # guard 1 (FIRST)
    params = load_params()
    bridge_output, nft, mint_script, bridge_address = build_bridge_output(  # guards 2 + 3
        params, datum, context, lambda o: pc.min_lovelace(context, output=o))
    min_ada = bridge_output.amount.coin

    seed = find_utxo(context, deployer, seed_ref)
    collateral = find_utxo(context, deployer, collateral_ref)
    print(f"  seed {seed_ref} ({seed.output.amount.coin/1e6:.2f} tADA) · collateral {collateral_ref} ({collateral.output.amount.coin/1e6:.2f} tADA)")

    redeemer = pc.Redeemer(0)  # the one-shot policy ignores its redeemer; ex_units filled by evaluation
    builder = pc.TransactionBuilder(context)
    builder.add_input(seed)                                       # the seed MUST be consumed (one-shot)
    builder.add_minting_script(mint_script, redeemer)
    builder.mint = nft
    builder.add_output(bridge_output)
    builder.collaterals = [collateral]
    signed = builder.build_and_sign([skey], change_address=deployer)

    tx_size = len(signed.to_cbor())
    fee = signed.transaction_body.fee
    # final pre-submit byte-identity: the on-chain inline datum == the pinned bytes.
    on_chain_datum = signed.transaction_body.outputs[0].datum
    embedded = on_chain_datum.cbor if hasattr(on_chain_datum, "cbor") else bytes(on_chain_datum)
    if hashlib.sha256(embedded).hexdigest() != expected_sha:
        fail("pre-submit: the BUILT tx's inline datum is not the pinned bytes")
    print(f"  ✓ built tx: {tx_size} B, fee {fee} lovelace; inline datum sha2_256 verified on the SIGNED tx")

    tx_id = str(signed.id)
    context.submit_tx(signed)
    print(f"  submitted: {tx_id} — polling the bridge address for the NFT…")
    policy = pc.ScriptHash(bytes.fromhex(params["policy_id"]))
    deadline = time.time() + POLL_TIMEOUT_S
    while time.time() < deadline:
        time.sleep(POLL_INTERVAL_S)
        for u in context.utxos(str(bridge_address)):
            if u.output.amount.multi_asset.get(policy, {}).get(pc.AssetName(STATE_TOKEN_NAME), 0) == 1:
                print("\n── REHEARSAL CONFIRMED — citable artifacts (measured as-is) ──")
                print(f"  tx hash        : {tx_id}")
                print(f"  bridge address : {params['bridge_address']}")
                print(f"  bridge UTxO    : {u.input.transaction_id}#{u.input.index}")
                print(f"  minADA (locked): {min_ada} lovelace ≈ {min_ada/1e6:.4f} ADA   (pre 11–13; {band(min_ada, PRE['min_ada_lovelace'])})")
                print(f"  tx size        : {tx_size} B   (pre 3.5–5 KB; {band(tx_size, PRE['tx_size_b'])}; {100*tx_size/MAX_TX_SIZE:.1f}% of {MAX_TX_SIZE})")
                print(f"  fee            : {fee} lovelace ≈ {fee/1e6:.4f} ADA   (pre 0.5–0.8; {band(fee, PRE['fee_lovelace'])})")
                print(f"  datum size     : {len(datum)} B   (pre 2632; {'match' if len(datum)==PRE['datum_size_b'] else 'DIFF'})")
                return
    fail(f"bridge UTxO not confirmed within {POLL_TIMEOUT_S}s (tx {tx_id} submitted; check the explorer)")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--prep-collateral", action="store_true")
    ap.add_argument("--submit", action="store_true")
    ap.add_argument("--seed", help="seed UTxO ref txid#ix (for --submit)")
    ap.add_argument("--collateral", help="collateral UTxO ref txid#ix (for --submit)")
    ap.add_argument("--datum-hex", help="value-swap: genesis datum hex file (default: toy Stage-1b genesis)")
    ap.add_argument("--datum-sha", help="value-swap: expected sha2_256 of --datum-hex (default: 86eeded9 toy pin)")
    args = ap.parse_args()
    datum_hex_path = Path(args.datum_hex) if args.datum_hex else DATUM_HEX
    expected_sha = args.datum_sha if args.datum_sha else EXPECTED_DATUM_SHA256
    if args.prep_collateral:
        prep_collateral()
    elif args.submit:
        if not args.seed or not args.collateral:
            fail("--submit requires --seed and --collateral")
        submit_boot(args.seed, args.collateral, datum_hex_path, expected_sha)
    else:
        offline(datum_hex_path, expected_sha)


if __name__ == "__main__":
    main()
