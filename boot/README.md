# Boot/init transaction tooling (§2.1.6)

Off-chain tooling that turns the off-chain-verified §2.1.6 bootstrap into the **genesis bridge UTxO**:
a one-shot NFT mint + an inline genesis datum at the parameterized bridge address. `bridge.ak` does
**not** run at Boot (nothing is spent from it) — only the one-shot minting policy executes — so there
is **no proof / BLS / threshold** on-chain here, and the whole flow is exercisable locally + on a free
**Preview** testnet (zero AWS dependency).

> **REHEARSAL vs PRODUCTION.** The committed artifacts use the **toy n=8 verifying keys** (the vk
> *shape* is N-independent, so the datum size / minADA / fee / tx size are the real deployment
> numbers). Those vks are **L1-frozen anchors** and Phase-C governance is out of scope, so the
> rehearsal bridge is a **dead-end by design** — it can never serve a real proof. A Boot with real
> n=512 vk *values* is a re-run of the identical tooling with those values swapped in; the runs that
> did so are listed in `docs/live-run-log.md`.

## Pieces

| file | role |
|---|---|
| `../prover/cmd/boot_genesis` (+ `../prover/offchain/boot`) | **Go gate-runner** — runs the §2.1.6 gate (`bootstrap.Verify`, abort-on-failure) and emits the genesis datum VALUES (fields 1–4 ONLY from the gate Result). |
| `genesis_datum_period1600.hex` | the canonical genesis datum **bytes**, authored by Aiken (`cbor.serialise`, the source of truth) — pinned by sha2_256 in `validator/lib/zkbridge/genesis_datum_test.ak`. |
| `derive_params.py` | the **parameterization chain**: seed → `state_thread_nft` → POLICY_ID → `bridge` → address, with the mis-application guards. |
| `assemble.py` | the **PyCardano assembler** — embeds the datum bytes verbatim, runs the byte-identity + output-self-check guards, dry-builds the Boot tx offline, reports vs the pre-registered numbers. The default mode makes no network call; `--submit` performs the live Boot on Preview (Stage 2). |

## Environment (one-time, no sudo, fully reversible)

The system Python has **no pip** and is **externally managed** (PEP 668), so use an **isolated venv
outside the repo** — nothing system-wide, removable with `rm -rf ~/.venvs/zkbridge-boot`:

```bash
python3 -m venv --without-pip ~/.venvs/zkbridge-boot         # venv module is present; ensurepip is not
curl -sS -o /tmp/get-pip.py https://bootstrap.pypa.io/get-pip.py
~/.venvs/zkbridge-boot/bin/python /tmp/get-pip.py            # bootstraps pip INSIDE the venv (no PEP-668 marker there)
~/.venvs/zkbridge-boot/bin/pip install -r boot/requirements.txt
```

> ⚠ **cbor2 pin (gotcha).** `pycardano 0.19.2` declares `cbor2>=5.6.5` (open-ended), but it uses the
> **cbor2 5.x** API — pip otherwise resolves `cbor2 6.x`, which breaks the import (`FrozenDict` /
> `_decoder` moved). `requirements.txt` pins `cbor2==5.9.0`. (pycardano defaults to the pure-Python
> `cbor2pure`; `CBOR_C_EXTENSION=1` selects the faster C extension — both work with the 5.x pin.)

## Run (local, no network)

```bash
# 1. the §2.1.6 gate → genesis values (from the prover/ module root)
cd prover && GOTOOLCHAIN=local go run ./cmd/boot_genesis && cd ..

# 2. the param chain (synthetic seed for a local rehearsal)
python3 boot/derive_params.py --seed-txid <64-hex> --seed-ix 0    # → boot/boot_params.json (+ plutus.applied.json)

# 3. the assembler — guards + dry-build + numbers (no submission without --submit)
~/.venvs/zkbridge-boot/bin/python boot/assemble.py
```

Ephemeral per-run outputs (`boot_params.json`, `genesis_values_*.json`, `validator/plutus.applied.json`)
are gitignored; the committed artifacts are code + the canonical datum hex.

## Stage 2 (Preview testnet)

Operator steps: obtain free tADA from the Preview faucet and create a free Blockfrost Preview project
key (kept outside the repo, in `~/.config/zkbridge/preview/`). Automated steps (`preflight.py`,
`derive_params.py`, `assemble.py --submit`): real seed → param chain → gate → assemble with **live**
protocol params + real UTxOs → sign (throwaway Preview keys, outside the tree) → submit → record the
tx hash, bridge address, real fee / tx size / minADA. **Preview only, zero real cost, never mainnet.**
The record of the first such run is `STAGE2_REHEARSAL.md`.
