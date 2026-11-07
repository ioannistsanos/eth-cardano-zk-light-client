#!/usr/bin/env python3
"""Stage-2 go/no-go preflight — READ-ONLY.

Confirms, before ANY submission, that the Preview rehearsal can proceed: the Blockfrost key works for
the Preview network, the faucet landed enough tADA, and a spendable seed UTxO exists. It NEVER builds,
signs, or submits a transaction — it only queries. Reads the deployer address + the Blockfrost
project_id from OUTSIDE the repo (~/.config/zkbridge/preview/), never from a committed file.

    ~/.venvs/zkbridge-boot/bin/python boot/preflight.py
"""

import os
import sys
from pathlib import Path

import requests

KEYDIR = Path(os.path.expanduser("~/.config/zkbridge/preview"))
ENV_FILE = KEYDIR / "blockfrost.env"
ADDR_FILE = KEYDIR / "payment.addr"

# the Boot needs minADA (~12.5) + fee (~0.5) + collateral (~5), all returned/locked except the fee.
MIN_REQUIRED_LOVELACE = 18_000_000


def fail(message: str) -> None:
    sys.stderr.write(f"NO-GO: {message}\n")
    sys.exit(1)


def load_project_id() -> str:
    if not ENV_FILE.exists():
        fail(f"{ENV_FILE} not found — create it with BLOCKFROST_PROJECT_ID=preview...")
    for line in ENV_FILE.read_text().splitlines():
        line = line.strip()
        if line.startswith("BLOCKFROST_PROJECT_ID="):
            return line.split("=", 1)[1].strip()
    fail(f"BLOCKFROST_PROJECT_ID not found in {ENV_FILE}")


def main() -> None:
    project_id = load_project_id()
    if not project_id.startswith("preview"):
        fail(f"project_id prefix is not 'preview' (got '{project_id[:8]}…') — wrong network key")
    if not ADDR_FILE.exists():
        fail(f"{ADDR_FILE} not found — re-run key generation")
    address = ADDR_FILE.read_text().strip()
    base = "https://cardano-preview.blockfrost.io/api/v0"
    headers = {"project_id": project_id}

    print("── Stage-2 go/no-go preflight (READ-ONLY) ──")
    print(f"  network  : Preview")
    print(f"  address  : {address}")

    # (1) key works + (2) faucet landed — the UTxO set at the address
    resp = requests.get(f"{base}/addresses/{address}/utxos", headers=headers, timeout=30)
    if resp.status_code == 403:
        fail("Blockfrost rejected the project_id (403) — key invalid or wrong network")
    if resp.status_code == 404:
        fail("address has no UTxOs (404) — faucet has not landed yet, or wrong address")
    if resp.status_code != 200:
        fail(f"Blockfrost error {resp.status_code}: {resp.text[:200]}")
    utxos = resp.json()
    print(f"  ✓ key works — Blockfrost responded for Preview")

    total = 0
    pure_ada = []  # candidate seeds (pure-ada UTxOs are the cleanest one-shot seed)
    for u in utxos:
        lovelace = sum(int(a["quantity"]) for a in u["amount"] if a["unit"] == "lovelace")
        is_pure = all(a["unit"] == "lovelace" for a in u["amount"])
        total += lovelace
        if is_pure:
            pure_ada.append((u["tx_hash"], u["output_index"], lovelace))
    print(f"  ✓ faucet landed — {len(utxos)} UTxO(s), total {total} lovelace ≈ {total/1e6:.2f} tADA")

    if total < MIN_REQUIRED_LOVELACE:
        fail(f"balance {total/1e6:.2f} tADA < required ~{MIN_REQUIRED_LOVELACE/1e6:.0f} tADA")
    if not pure_ada:
        fail("no pure-ada UTxO available to use as the one-shot seed")
    seed = max(pure_ada, key=lambda t: t[2])  # the largest pure-ada UTxO is the candidate seed
    print(f"  ✓ seed available — candidate {seed[0]}#{seed[1]} ({seed[2]/1e6:.2f} tADA)")

    print("\n  GO — all checks green. (No tx built/signed/submitted; awaiting explicit go.)")


if __name__ == "__main__":
    main()
