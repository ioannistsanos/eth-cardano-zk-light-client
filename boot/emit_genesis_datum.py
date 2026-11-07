#!/usr/bin/env python3
"""boot/emit_genesis_datum.py — emit a genesis bridge-datum hex (Aiken-byte-identical via boot/datum.py).

The "value-swap" tool: writes the genesis Datum bytes for a chosen vk pair + finality/committee values,
so assemble.py can Boot a bridge with vks OTHER than the toy Stage-1b genesis — the D24-vk REHEARSAL
bridge (vk_D24 + the gate-1 input) now, and the scenario's vk_fresh bridge later. Reuses boot/datum.py's
encoder (byte-identical to Aiken's cbor.serialise), so the emitted hex is a drop-in for assemble.py's
--datum-hex (its printed sha2_256 feeds --datum-sha).

  ~/.venvs/zkbridge-boot/bin/python boot/emit_genesis_datum.py \
      --base-values boot/genesis_values_period1600.json \
      --vk-regular validator/fixtures/groth16_regular_n512.json \
      --vk-boundary validator/fixtures/groth16_boundary_n512.json \
      --finalized-root 0000000000000000000000000000000000000000000000000000000000000000 \
      --finalized-slot 13107199 \
      --out boot/genesis_datum_rehearsal_d24.hex
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

import datum as datum_mod


def main() -> None:
    ap = argparse.ArgumentParser(description="emit a genesis bridge-datum hex (value-swap)")
    ap.add_argument("--base-values", required=True, help="JSON with current/next/fork/gvr/finalized defaults")
    ap.add_argument("--vk-regular", required=True, help="groth16_regular_*.json (the vk pair's regular vk)")
    ap.add_argument("--vk-boundary", required=True, help="groth16_boundary_*.json (the vk pair's boundary vk)")
    ap.add_argument("--finalized-root", help="override the base finalized_header_root (hex)")
    ap.add_argument("--finalized-slot", type=int, help="override the base finalized_slot")
    ap.add_argument("--out", required=True, help="destination .hex file")
    args = ap.parse_args()

    values = json.loads(Path(args.base_values).read_text())
    finalized_root = args.finalized_root if args.finalized_root is not None else values["finalized_header_root"]
    finalized_slot = args.finalized_slot if args.finalized_slot is not None else values["finalized_slot"]

    datum = datum_mod.build_datum(
        finalized_header_root=finalized_root,
        finalized_slot=finalized_slot,
        current_committee_commitment=values["current_committee_commitment"],
        next_committee_commitment=values["next_committee_commitment"],
        fork_version=values["fork_version"],
        genesis_validators_root=values["genesis_validators_root"],
        vk_regular=datum_mod._vk_from_json(Path(args.vk_regular)),
        vk_boundary=datum_mod._vk_from_json(Path(args.vk_boundary)),
    )
    cbor = datum_mod.datum_cbor(datum)
    sha = hashlib.sha256(cbor).hexdigest()
    Path(args.out).write_text(cbor.hex() + "\n")
    print(f"wrote {args.out}: {len(cbor)} B  sha2_256 {sha}")


if __name__ == "__main__":
    main()
