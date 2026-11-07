#!/usr/bin/env python3
"""boot/redeemer.py — the live relayer's redeemer encoder + the gate-4 byte-identity check.

PyCardano PlutusData classes mirror the Aiken `Redeemer` (validator/lib/zkbridge/types.ak), so the
off-chain encoding is BYTE-IDENTICAL to Aiken's cbor.serialise (the source of truth). The redeemer is
positional Plutus Data (field ORDER is the interface); the proof `commitment` is the UNCOMPRESSED 96 B
form (cmd/proof_to_redeemer) — NOT the compressed proof_to_json fixture.

Field types encode the Plutus 64-byte chunking (seam subtlety #3): fields ≤64 B are plain `bytes`
(a single CBOR byte string); fields >64 B (the 96 B G1/G2 points) are `ByteString`, which emits the
64-byte indefinite-length chunking the ledger + Aiken use.

Run as a script to verify gate 4 against the Aiken pin (redeemer_seam_test.ak redeemer_bytepin):
    ~/.venvs/zkbridge-boot/bin/python boot/redeemer.py [proof_redeemer.json]
Without an argument the committed fixture validator/fixtures/proof_redeemer_regular_n512.json is read.
"""
from __future__ import annotations

import hashlib
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Union

from pycardano import PlutusData
from pycardano.serialization import ByteString


# ── TransitionKind: Regular -> Constr 0 [] ; Boundary -> Constr 1 [] ──
@dataclass
class Regular(PlutusData):
    CONSTR_ID = 0


@dataclass
class Boundary(PlutusData):
    CONSTR_ID = 1


# ── Groth16Proof = Constr 0 [a, b, c, commitment, commitment_pok] (types.ak:19-31) ──
@dataclass
class Groth16Proof(PlutusData):
    CONSTR_ID = 0
    a: bytes  # G1 48 B compressed
    b: ByteString  # G2 96 B compressed (>64 → chunked)
    c: bytes  # G1 48 B compressed
    commitment: ByteString  # G1 96 B UNCOMPRESSED X‖Y (>64 → chunked)
    commitment_pok: bytes  # G1 48 B compressed


# ── Redeemer = Constr 0 [kind, proof, apk, signature, count, attested_header_root] (types.ak:85-98) ──
@dataclass
class Redeemer(PlutusData):
    CONSTR_ID = 0
    kind: Union[Regular, Boundary]
    proof: Groth16Proof
    apk: ByteString  # 96 B uncompressed (>64 → chunked)
    signature: ByteString  # 96 B compressed G2 (>64 → chunked)
    count: int
    attested_header_root: bytes  # 32 B


def build_redeemer(
    kind: Union[Regular, Boundary],
    proof_redeemer: dict,
    apk_hex: str,
    signature_hex: str,
    count: int,
    attested_root_hex: str,
) -> Redeemer:
    """Assemble the on-chain redeemer. proof_redeemer is cmd/proof_to_redeemer's `proof_redeemer`
    (commitment UNCOMPRESSED 96 B); apk/signature/attested come from the BLS fixture per phase."""
    pr = proof_redeemer
    return Redeemer(
        kind=kind,
        proof=Groth16Proof(
            a=bytes.fromhex(pr["a"]),
            b=ByteString(bytes.fromhex(pr["b"])),
            c=bytes.fromhex(pr["c"]),
            commitment=ByteString(bytes.fromhex(pr["commitment"])),
            commitment_pok=bytes.fromhex(pr["commitment_pok"]),
        ),
        apk=ByteString(bytes.fromhex(apk_hex)),
        signature=ByteString(bytes.fromhex(signature_hex)),
        count=count,
        attested_header_root=bytes.fromhex(attested_root_hex),
    )


def redeemer_cbor(r: Redeemer) -> bytes:
    out = r.to_cbor()
    return bytes.fromhex(out) if isinstance(out, str) else out


# ── GATE 4 — byte-identity with the Aiken source of truth (redeemer_seam_test.ak) ──
AIKEN_PIN = "e9e291c5fc619e4e3520de04d8a49b2fef078c230b9d83d71d5e1c4a9082b995"
AIKEN_SIZE = 606

if __name__ == "__main__":
    fixtures = Path(__file__).resolve().parent.parent / "validator" / "fixtures"
    # the proof file is cmd/proof_to_redeemer's output; the default is the committed real-n=512 fixture
    proof_path = Path(sys.argv[1]) if len(sys.argv) > 1 else fixtures / "proof_redeemer_regular_n512.json"
    with open(proof_path) as fh:
        proof_redeemer = json.load(fh)["proof_redeemer"]
    with open(fixtures / "bls_regular_period1600.json") as fh:
        bls = json.load(fh)

    redeemer = build_redeemer(
        Regular(),
        proof_redeemer,
        bls["apk_uncompressed"],
        bls["signature"],
        bls["count"],
        bls["attested_header_root"],
    )
    cbor = redeemer_cbor(redeemer)
    pin = hashlib.sha256(cbor).hexdigest()

    print(f"PyCardano redeemer: size={len(cbor)}  sha2_256={pin}")
    print(f"Aiken (truth)     : size={AIKEN_SIZE}  sha2_256={AIKEN_PIN}")
    if pin == AIKEN_PIN and len(cbor) == AIKEN_SIZE:
        print("GATE 4 GREEN — PyCardano redeemer is BYTE-IDENTICAL to Aiken's cbor.serialise")
        sys.exit(0)
    print("GATE 4 RED — byte mismatch (cbor hex below); investigate chunking / constr tags / field order")
    print("cbor_hex:", cbor.hex())
    sys.exit(1)
