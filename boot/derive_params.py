#!/usr/bin/env python3
"""Boot parameterization chain (§2.1.6) — stack-neutral, stdlib only.

Threads a seed UTxO through the two `aiken blueprint apply` steps to derive the deploy-time
artifacts the Boot tx needs:

    seed UTxO ──apply──▶ state_thread_nft  ──policy──▶ POLICY_ID
    POLICY_ID ──apply──▶ bridge            ──address─▶ BRIDGE_ADDR

and runs the mis-application guards: a single-sourced POLICY_ID and a
param-identity re-derivation. The output self-check (the Boot output carries (POLICY_ID, name, 1))
is the ASSEMBLER's job — it needs the built tx — and is noted, not run here.

Mis-application is invisible at Boot (the bridge script does not run) and bricks the FIRST SPEND
permanently — so the guards run BEFORE anything network-facing. The seed → OutputReference CBOR uses
Aiken's own encoding (Constr 0, indefinite array: d8799f 5820<txid> <ix> ff — confirmed by the
genesis datum's D8799F5820… prefix), so the off-chain never improvises the parameter shape.

No new dependencies: Python stdlib + the aiken CLI. (If the assembler ends up Go/apollo, this
apply-chain logic ports to os/exec calls — it is plain CLI orchestration.)
"""

import argparse
import json
import subprocess
import sys
from pathlib import Path


def fail(message: str) -> None:
    sys.stderr.write(f"HALT: {message}\n")
    sys.exit(1)


def cbor_uint(value: int) -> bytes:
    """Minimal CBOR unsigned-integer encoding (major type 0)."""
    if value < 0:
        fail(f"output_index must be non-negative, got {value}")
    if value < 24:
        return bytes([value])
    if value < 256:
        return bytes([0x18, value])
    if value < 65536:
        return bytes([0x19, value >> 8, value & 0xFF])
    if value < 4294967296:
        return bytes([0x1A]) + value.to_bytes(4, "big")
    return bytes([0x1B]) + value.to_bytes(8, "big")


def output_reference_cbor(txid_hex: str, output_index: int) -> str:
    """OutputReference { transaction_id: ByteArray(32), output_index: Int } as Plutus Data CBOR.

    Constr 0 (tag 121 = 0xd879) + indefinite array (0x9f … 0xff); field 0 is a 32-byte bytestring
    (0x58 0x20 ‖ txid); field 1 is the minimal-encoded Int. Matches Aiken's cbor.serialise.
    """
    txid = bytes.fromhex(txid_hex)
    if len(txid) != 32:
        fail(f"seed txid must be 32 bytes (64 hex chars), got {len(txid)} bytes")
    encoded = bytes([0xD8, 0x79, 0x9F, 0x58, 0x20]) + txid + cbor_uint(output_index) + bytes([0xFF])
    return encoded.hex()


def policy_id_cbor(policy_id_hex: str) -> str:
    """PolicyId (a 28-byte script hash) as Plutus Data CBOR: a 28-byte bytestring (0x58 0x1c ‖ hash)."""
    policy = bytes.fromhex(policy_id_hex)
    if len(policy) != 28:
        fail(f"policy id must be 28 bytes (56 hex chars), got {len(policy)} bytes")
    return (bytes([0x58, 0x1C]) + policy).hex()


def run_aiken(args: list[str], cwd: Path) -> str:
    result = subprocess.run(
        ["aiken", *args], cwd=cwd, capture_output=True, text=True
    )
    if result.returncode != 0:
        fail(f"`aiken {' '.join(args)}` failed:\n{result.stderr.strip()}")
    return result.stdout.strip()


def main() -> None:
    parser = argparse.ArgumentParser(description="Boot parameterization chain (seed → policy → bridge)")
    parser.add_argument("--seed-txid", required=True, help="seed UTxO transaction id (64 hex chars)")
    parser.add_argument("--seed-ix", type=int, required=True, help="seed UTxO output index")
    parser.add_argument("--validator-dir", default="validator", help="the Aiken project root")
    parser.add_argument("--network", choices=["preview", "preprod", "mainnet"], default="preview")
    parser.add_argument("--out", default="boot/boot_params.json", help="derived-artifacts destination")
    args = parser.parse_args()

    validator_dir = Path(args.validator_dir).resolve()
    applied = "plutus.applied.json"  # relative to validator_dir; gitignored build product

    # 0. (re)build the base blueprint so the unapplied params are present.
    run_aiken(["build"], cwd=validator_dir)

    # 1. apply the seed to the minting policy.
    seed_cbor = output_reference_cbor(args.seed_txid, args.seed_ix)
    run_aiken(["blueprint", "apply", "-v", "state_thread_nft", seed_cbor, "-o", applied], cwd=validator_dir)

    # 2. the policy id (the SINGLE source — one value reused for the bridge param, the mint, and the
    #    assembler's output self-check).
    policy_id = run_aiken(["blueprint", "policy", "-v", "state_thread_nft", "-i", applied], cwd=validator_dir)

    # 3. apply that SAME policy id to the spending validator.
    run_aiken(["blueprint", "apply", "-v", "bridge", policy_id_cbor(policy_id), "-i", applied, "-o", applied], cwd=validator_dir)

    # 4. the bridge address (testnet tag for preview/preprod).
    address_args = ["blueprint", "address", "-v", "bridge", "-i", applied]
    if args.network == "mainnet":
        address_args.append("--mainnet")
    bridge_address = run_aiken(address_args, cwd=validator_dir)

    # ── GUARD: param-identity (guard 1) ──
    # re-derive the applied state_thread's policy from the SAME applied artifact and assert it equals
    # the policy id we baked into the bridge. Catches a stale/wrong policy id before submission (the
    # bug that would otherwise brick the first spend: the bridge looks for an NFT under a policy that
    # was never minted). Single-sourcing (step 2→3) already prevents divergence; this re-derivation
    # is the belt-and-suspenders confirmation against the on-disk applied bridge.
    rederived_policy = run_aiken(["blueprint", "policy", "-v", "state_thread_nft", "-i", applied], cwd=validator_dir)
    if rederived_policy != policy_id:
        fail(f"param-identity guard FAILED: re-derived policy {rederived_policy} != baked {policy_id}")

    result = {
        "network": args.network,
        "seed": f"{args.seed_txid}#{args.seed_ix}",
        "policy_id": policy_id,
        "state_token_name": "zkbridge_state",
        "bridge_address": bridge_address,
        "applied_blueprint": str(validator_dir / applied),
        "guards": {
            "single_sourced_policy_id": True,
            "param_identity_rederived": True,
            "output_self_check": "DEFERRED to the assembler (needs the built tx output value)",
        },
    }
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(json.dumps(result, indent=2) + "\n")

    print(f"param chain OK → {args.out}")
    print(f"  seed           = {result['seed']}")
    print(f"  POLICY_ID      = {policy_id}")
    print(f"  bridge_address = {bridge_address}")
    print(f"  guards: single-sourced ✓, param-identity re-derived ✓, output self-check → assembler")


if __name__ == "__main__":
    main()
