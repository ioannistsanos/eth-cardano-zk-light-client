#!/usr/bin/env python3
"""boot/datum.py — the live relayer's datum encoder/decoder + the spend-path datum-advance + its gates.

Mirrors boot/redeemer.py: PyCardano PlutusData classes mirror the Aiken Datum / Groth16VerifyingKey
(validator/lib/zkbridge/types.ak), so the off-chain encoding is BYTE-IDENTICAL to Aiken's
cbor.serialise (the source of truth). Positional Plutus Data (field ORDER is the interface); the 96 B
G2 points are ByteString (the 64-byte indefinite chunking, seam subtlety #3); the vk `ic` list is an
IndefiniteList (Plutus encodes a non-empty Data list as an indefinite-length array, as Aiken does).

The OUTPUT datum is the INPUT datum with only the MUTABLE fields swapped, EXACTLY per validation.ak:
  - Regular : finalized_header_root/slot advance; committees FROZEN; anchors bit-identical.
  - Boundary: + current_committee_commitment <- input.next (committee_rotated); next <- new (op-6).
advance_* COPY everything else from the (decoded) input datum, so anchors_preserved + committees_frozen
hold BY CONSTRUCTION (the anchors are never re-sourced, only carried).

Run as a script to verify the datum gates (the venv has the cbor2<6 pin):
    ~/.venvs/zkbridge-boot/bin/python boot/datum.py
  gate-a (genesis) is fully self-contained — byte-identical to boot/genesis_datum_period1600.hex +
  sha2_256 == the Aiken pin. gate-b (real n=512 regular output) + the boundary-rotation gate print the
  sha2_256 that the Aiken byte-pins in datum_advance_test.ak confirm (Aiken = the independent oracle).
"""
from __future__ import annotations

import dataclasses
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

from pycardano import PlutusData
from pycardano.serialization import ByteString, IndefiniteList

REPO = Path(__file__).resolve().parent.parent
FIXTURES = REPO / "validator" / "fixtures"
GENESIS_HEX = REPO / "boot" / "genesis_datum_period1600.hex"
GENESIS_VALUES = REPO / "boot" / "genesis_values_period1600.json"

# genesis_datum_test.ak genesis_datum_bytepin — Aiken's serialise of the genesis Datum.
GENESIS_PIN = "86eeded99b2476e82de6ef198f83f906e14df9cee5fe67f860eb7a6e6c2fdad6"

# Boundary-rotation gate (datum_advance_test.ak) — a SYNTHETIC committee_rotated-consistent fixture:
# the rotation MAPPING (output.current <- input.next, output.next <- new) is what is pinned; the
# committee VALUES need not be cryptographically real for a layout/mapping gate. Mirrored in Aiken.
BOUNDARY_NEW_NEXT = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
BOUNDARY_NEW_FINALIZED = "201a1d12d634bcf8de5a9281d8cf5974cb775be0f8741a1cf0123e0383878599"


# ── Groth16VerifyingKey = Constr 0 [alpha, beta, gamma, delta, ic, commitment_g, commitment_g_sigma_neg] ──
@dataclass
class Groth16VerifyingKey(PlutusData):
    CONSTR_ID = 0
    alpha: bytes              # G1 48 B
    beta: ByteString          # G2 96 B (>64 -> chunked)
    gamma: ByteString         # G2 96 B
    delta: ByteString         # G2 96 B
    ic: IndefiniteList        # List<G1 48 B> — Plutus Data list (indefinite array)
    commitment_g: ByteString  # G2 96 B
    commitment_g_sigma_neg: ByteString  # G2 96 B


# ── Datum = Constr 0 [8 fields] (types.ak:54-71) ──
@dataclass
class Datum(PlutusData):
    CONSTR_ID = 0
    finalized_header_root: bytes         # Bytes32 — mutable every tx
    finalized_slot: int                  # uint64  — mutable every tx
    current_committee_commitment: bytes  # Bytes32 — mutable boundary only
    next_committee_commitment: bytes     # Bytes32 — mutable boundary only
    fork_version: bytes                  # Bytes4  — anchor
    genesis_validators_root: bytes       # Bytes32 — anchor
    verifying_key_regular: Groth16VerifyingKey   # anchor
    verifying_key_boundary: Groth16VerifyingKey  # anchor


# ── encode / decode ──

def _vk_from_json(path: Path) -> Groth16VerifyingKey:
    """Build a vk record from a groth16_*_n{8,512}.json fixture (the same source the .ak files use)."""
    vk = json.loads(path.read_text())["vk"]
    return Groth16VerifyingKey(
        alpha=bytes.fromhex(vk["alpha"]),
        beta=ByteString(bytes.fromhex(vk["beta"])),
        gamma=ByteString(bytes.fromhex(vk["gamma"])),
        delta=ByteString(bytes.fromhex(vk["delta"])),
        ic=IndefiniteList([bytes.fromhex(point) for point in vk["ic"]]),
        commitment_g=ByteString(bytes.fromhex(vk["commitment_g"])),
        commitment_g_sigma_neg=ByteString(bytes.fromhex(vk["commitment_g_sigma_neg"])),
    )


def build_datum(*, finalized_header_root: str, finalized_slot: int,
                current_committee_commitment: str, next_committee_commitment: str,
                fork_version: str, genesis_validators_root: str,
                vk_regular: Groth16VerifyingKey, vk_boundary: Groth16VerifyingKey) -> Datum:
    """Construct a Datum from hex field values + vk records (the gate/genesis path)."""
    return Datum(
        finalized_header_root=bytes.fromhex(finalized_header_root),
        finalized_slot=finalized_slot,
        current_committee_commitment=bytes.fromhex(current_committee_commitment),
        next_committee_commitment=bytes.fromhex(next_committee_commitment),
        fork_version=bytes.fromhex(fork_version),
        genesis_validators_root=bytes.fromhex(genesis_validators_root),
        verifying_key_regular=vk_regular,
        verifying_key_boundary=vk_boundary,
    )


def datum_cbor(datum: Datum) -> bytes:
    out = datum.to_cbor()
    return bytes.fromhex(out) if isinstance(out, str) else out


def decode_datum(raw: bytes) -> Datum:
    """The live spend path: decode the on-chain inline datum bytes into a Datum (PyCardano cast)."""
    return Datum.from_cbor(raw)


# ── the spend-path advances (validation.ak) — anchors + (regular) committees CARRIED from input ──

def advance_regular(input_datum: Datum, finalized_header_root: bytes, finalized_slot: int) -> Datum:
    """Regular: finalized_* advance; committees FROZEN; anchors bit-identical (all carried)."""
    return dataclasses.replace(
        input_datum,
        finalized_header_root=finalized_header_root,
        finalized_slot=finalized_slot,
    )


def advance_boundary(input_datum: Datum, finalized_header_root: bytes, finalized_slot: int,
                     new_next_committee_commitment: bytes) -> Datum:
    """Boundary: finalized_* advance; current <- input.next (committee_rotated); next <- new (op-6);
    anchors bit-identical (carried)."""
    return dataclasses.replace(
        input_datum,
        finalized_header_root=finalized_header_root,
        finalized_slot=finalized_slot,
        current_committee_commitment=input_datum.next_committee_commitment,  # the rotation
        next_committee_commitment=new_next_committee_commitment,
    )


# ── gates ──

def _gate_a_genesis() -> bool:
    """gate-a (self-contained): the genesis datum (toy n=8 vks + genesis values) encodes BYTE-IDENTICAL
    to Aiken's on-disk serialise, AND decode->re-encode round-trips (the live decode path)."""
    values = json.loads(GENESIS_VALUES.read_text())
    genesis = build_datum(
        finalized_header_root=values["finalized_header_root"],
        finalized_slot=values["finalized_slot"],
        current_committee_commitment=values["current_committee_commitment"],
        next_committee_commitment=values["next_committee_commitment"],
        fork_version=values["fork_version"],
        genesis_validators_root=values["genesis_validators_root"],
        vk_regular=_vk_from_json(FIXTURES / "groth16_regular_n8.json"),
        vk_boundary=_vk_from_json(FIXTURES / "groth16_boundary_n8.json"),
    )
    got = datum_cbor(genesis)
    want = bytes.fromhex(GENESIS_HEX.read_text().strip())
    sha = hashlib.sha256(got).hexdigest()
    roundtrip = datum_cbor(decode_datum(want))
    ok = got == want and sha == GENESIS_PIN and roundtrip == want
    print(f"gate-a genesis  : size={len(got)} (Aiken {len(want)})  sha2_256={sha}")
    print(f"    build==Aiken={got == want}  pin_match={sha == GENESIS_PIN}  "
          f"decode->encode round-trip={roundtrip == want}  -> {'GREEN' if ok else 'RED'}")
    if not ok:
        print("    got_hex :", got.hex())
        print("    want_hex:", want.hex())
    return ok


def _gate_b_real_regular_output() -> str:
    """gate-b: reproduce real_n512_regular.real_output_datum() — real n=512 vks, finalized advanced,
    committees frozen. Returns the sha2_256 the Aiken bytepin confirms."""
    values = json.loads(GENESIS_VALUES.read_text())
    real_input = build_datum(
        finalized_header_root="00" * 32,                 # old_finalized (real_n512_regular.ak)
        finalized_slot=values["finalized_slot"] - 1,
        current_committee_commitment=values["current_committee_commitment"],
        next_committee_commitment=values["next_committee_commitment"],
        fork_version=values["fork_version"],
        genesis_validators_root=values["genesis_validators_root"],
        vk_regular=_vk_from_json(FIXTURES / "groth16_regular_n512.json"),
        vk_boundary=_vk_from_json(FIXTURES / "groth16_boundary_n512.json"),
    )
    output = advance_regular(real_input, bytes.fromhex(values["finalized_header_root"]),
                             values["finalized_slot"])
    cbor = datum_cbor(output)
    sha = hashlib.sha256(cbor).hexdigest()
    # by-construction self-checks (committees frozen, finalized advanced)
    assert output.current_committee_commitment == real_input.current_committee_commitment
    assert output.next_committee_commitment == real_input.next_committee_commitment
    assert output.finalized_slot > real_input.finalized_slot
    print(f"gate-b real-reg : size={len(cbor)}  sha2_256={sha}  (Aiken bytepin: real_output_datum)")
    return sha


def _gate_boundary_rotation() -> str:
    """boundary gate: a committee_rotated-consistent advance — assert the EXACT field mapping
    (output.current == input.next BYTE-FOR-BYTE; output.next == new) locally, return the sha2_256 the
    Aiken bytepin confirms. The proof-verify half is correctly VM-tier (no local n=512 boundary proof)."""
    values = json.loads(GENESIS_VALUES.read_text())
    boundary_input = build_datum(
        finalized_header_root="00" * 32,
        finalized_slot=values["finalized_slot"] - 1,
        current_committee_commitment=values["current_committee_commitment"],
        next_committee_commitment=values["next_committee_commitment"],
        fork_version=values["fork_version"],
        genesis_validators_root=values["genesis_validators_root"],
        vk_regular=_vk_from_json(FIXTURES / "groth16_regular_n512.json"),
        vk_boundary=_vk_from_json(FIXTURES / "groth16_boundary_n512.json"),
    )
    output = advance_boundary(boundary_input, bytes.fromhex(BOUNDARY_NEW_FINALIZED),
                              values["finalized_slot"], bytes.fromhex(BOUNDARY_NEW_NEXT))
    # THE load-bearing rotation mapping, byte-for-byte:
    rotated = output.current_committee_commitment == boundary_input.next_committee_commitment
    installed = output.next_committee_commitment == bytes.fromhex(BOUNDARY_NEW_NEXT)
    anchors_held = (output.verifying_key_regular == boundary_input.verifying_key_regular
                    and output.verifying_key_boundary == boundary_input.verifying_key_boundary
                    and output.fork_version == boundary_input.fork_version
                    and output.genesis_validators_root == boundary_input.genesis_validators_root)
    cbor = datum_cbor(output)
    sha = hashlib.sha256(cbor).hexdigest()
    print(f"boundary-rotate : size={len(cbor)}  sha2_256={sha}  (Aiken bytepin: boundary_output)")
    print(f"    rotation current<-input.next={rotated}  next<-new={installed}  anchors_held={anchors_held}"
          f"  -> {'GREEN' if rotated and installed and anchors_held else 'RED'}")
    if not (rotated and installed and anchors_held):
        raise SystemExit("boundary rotation mapping RED — see above")
    return sha


if __name__ == "__main__":
    print("── boot/datum.py gates ──")
    a_ok = _gate_a_genesis()
    b_sha = _gate_b_real_regular_output()
    boundary_sha = _gate_boundary_rotation()
    print("\n── Aiken byte-pins to set in validator/lib/zkbridge/datum_advance_test.ak ──")
    print(f"  real_output_datum  sha2_256 = #\"{b_sha}\"")
    print(f"  boundary_output    sha2_256 = #\"{boundary_sha}\"")
    raise SystemExit(0 if a_ok else 1)
