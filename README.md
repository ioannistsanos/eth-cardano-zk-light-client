# eth-cardano-zk-light-client

This repository is the implementation and measurement artifact of the Master's thesis "Zero-Knowledge Verification of Ethereum Sync-Committee Light-Client Updates on Cardano: Design, Implementation, and Empirical Cost Analysis". It covers Phase A of the design, namely a gnark Groth16 circuit over BLS12-381 that proves an Ethereum sync-committee light-client update, an Aiken validator compiled to Plutus V3 that verifies the proof and the aggregate BLS signature through the CIP-381 builtins, and the relayer between the two chains.

## Repository layout

- `prover/`: Go module with the gnark circuits for the regular and the boundary update, the capture of light-client data and the construction of witnesses, the Groth16 setup and prover, and the relayer.
- `validator/`: Aiken project with the bridge spending validator, the one-shot minting policy of the state-thread token, their tests and the compiled blueprint `plutus.json`.
- `boot/`: Python scripts that derive the script parameters, assemble the bootstrap datum and transaction, and submit the update transactions.
- `benchmarks/`: raw logs, measurement reports, the cross-check of the cost-model values, the records of the adversarial validator tests (`benchmarks/adversarial/`) and the Koios and Beacon API responses behind the live run (`benchmarks/ledger-evidence/`).
- `docs/`: design notes, the runbook, the log of the live runs, the records of estimates against measurements, the measurement map and the security notes.

## Building and running

The toolchain versions are the ones pinned in `prover/go.mod`, `validator/aiken.toml` and `boot/requirements.txt`:

| Tool | Version |
|---|---|
| Go | 1.23.6 |
| gnark | v0.13.0 |
| gnark-crypto | v0.18.0 |
| Aiken | v1.1.22 |
| aiken-lang/stdlib | v2 |
| pycardano | 0.19.2 |
| blockfrost-python | 0.7.0 |

```
(cd prover && go build ./... && go vet ./...)
(cd validator && aiken build && aiken check)
pip install -r boot/requirements.txt
```

The tests are run with `aiken check` in `validator/` and with `go test ./...` in `prover/`:

```
(cd validator && aiken check)
(cd prover && go test ./...)
```

`aiken check` runs 152 checks in 18 modules. `go test ./...` covers 106 test functions in nine packages, of which `TestPubkeysRootSolves512` is skipped unless the environment variable `RUN_AWS_HEAVY` is set. The outputs of complete runs of both are in `benchmarks/adversarial/full-run/` (`aiken-check-full.log`, `go-test-all.log` and `go-test-all-times.txt`). The recorded Go run took 1 h 39 min 39 s.

The procedure of a run, from the trusted setup to the submission of the updates, is in `docs/c-runbook.md`. The bootstrap tooling is described in `boot/README.md`.

## Measurements

The measurement output of every raw log under `benchmarks/raw/` is kept exactly as produced. `benchmarks/INDEX.md` lists the logs with the date each was recorded and notes the five Phase-1 logs whose provenance header was edited after the run and the two whose first run was replaced by a second run the same day. The raw logs keep absolute paths, the earlier module path and commit identifiers of the development tree, which is not part of this repository. The records under `benchmarks/adversarial/` likewise keep absolute paths and the earlier Aiken package name of the development tree, while the Go module path in them is written as in this repository. `docs/measurements.md` gives, for the values that the thesis reports from this repository, the raw measurement with file and line, the summary line that states it and the kind of evidence.

The two headline totals, measured on the Cardano Preview testnet, are 7,094,172,930 CPU steps for a regular update and 7,265,427,726 CPU steps for a boundary update.

## On-chain deployment

The bridge ran on the Cardano Preview testnet.

The blueprint `validator/plutus.json` holds the two validators as compiled, before their parameters are applied:

| Validator | Parameter | Hash as compiled |
|---|---|---|
| `bridge.bridge.spend` | `state_token` | `fec7333b904ebecb11a59dcc3387151a25c53e85139cc80965e05bf6` |
| `state_thread.state_thread_nft.mint` | `seed` | `9aff5643e92faa23dde3a07f67354e011d48c6140a93616430a18f6d` |

A deployed bridge is an instance of these two with the parameters applied. The minting policy receives the seed output reference, and the spending validator receives the policy id that results. The policy id and the script address of an instance therefore differ from the two hashes above. For the bridge of the 60-update run they are:

| Item | Value |
|---|---|
| Bridge script address | `addr_test1wz4r4wxuu9z8s2r06kn0v28png4qvdcrf9pdkqku4al99kc8trwxs` |
| State-token policy id | `c52599c139b6126c5bd04c303a51a8f8d5bd1633660ddd06add30054` |

`boot/derive_params.py` derives both values from a seed output. The seed of a bridge is an input of its bootstrap transaction. The transaction ids of the bootstrap and of the updates, and the earlier bridges, are in `docs/live-run-log.md`.

## Status

This is a research prototype, with the following limits:

- The trusted setup was run by a single party. There was no multi-party ceremony.
- It has run on the Preview testnet only. There has been no mainnet run.
- There is one relayer, and it has no catch-up mode for gaps larger than one sync-committee period.
- The execution-layer path (Phase B) is designed in the thesis and is not implemented here.
- The code has not been audited.

## License and citation

The code is released under the Apache License 2.0 (`LICENSE`). `NOTICE` lists the third-party test vectors with their license, the third-party source excerpt and the data sources. Citation metadata is in `CITATION.cff`.

Thesis: "Zero-Knowledge Verification of Ethereum Sync-Committee Light-Client Updates on Cardano: Design, Implementation, and Empirical Cost Analysis". Author: Ioannis Tsanos. Supervisor: Dimitrios Mitropoulos. National and Kapodistrian University of Athens, MSc in Fintech, 2026.
