# RegularCircuit assembly — R1CS cost (D15)

The assembled regular Phase-A circuit (committee bind + op-2 + op-5 + op-3a + op-3b + op-4,
Option-P 11-Fr public layout). Record: `docs/records.md` **D15**.

| measurement | value |
|---|---|
| direct N=512 (full circuit) | **1,990,745 ≈ ~1.99M** (×2-deterministic) |
| small-N | N=8/16 = 1,057,328 / 1,074,256 (×2-deterministic) |
| small-N extrapolation | 2,123,792 — overshoots the direct ~6.6% (the D13/D15 pattern; direct authoritative) |
| public inputs | 11 Fr (Option-P; witness.Public() == 11) |
| vs thesis §2.1.3 | the 10–26M estimate **refuted ~5–13×** |

- Command: `go run ./cmd/measure_regular` (small-N + extrapolation, ×2-deterministic);
  `RUN_DIRECT_512=1` for the direct (RSS-heavy; ~5.5 GB peak watched on this box).
- Provenance: built + measured 2026-06-07.
- Machine: Intel i7-9750H @ 2.60GHz, 7.7 GB RAM, WSL2 6.6.114.1-microsoft-standard-WSL2,
  Go 1.23.6, gnark v0.13.0.
- Raw log: `benchmarks/raw/phase-2-circuit/regular-assembly-smallN.log` — a 2026-06-09 re-run
  (×2-deterministic; reproduces the small-N numbers above exactly — a regression check, HALT on
  mismatch). The direct N=512 count was first measured locally on 2026-06-07; it is recorded in
  the setup and proving logs of 2026-06-14 and 2026-06-15 (see the decomposition below).

## Decomposition of the direct count

1,990,745 = 929,169 + 1,041,435 + 20,141.

| term | constraints | source |
|---|---|---|
| committee region (Poseidon bind + op-2 + op-5), direct N=512 | **929,169** | `benchmarks/raw/phase-2-circuit/committee-bind-direct512.log:14` |
| finality and slot Merkle proofs (op-3a + op-3b + op-4) | **1,041,435** = 504,292 + 376,127 + 161,016 | the three rows below |
| — op-3a, header reconstruction (carries the shared SHA-256 lookup-table setup, 131,380, once) | 504,292 | `benchmarks/phase-2-circuit/op3a-headerreconstruct.md:38`; raw `benchmarks/raw/phase-2-circuit/op3a-headerreconstruct.log:8` |
| — op-3b, finality branch, marginal (507,507 − 131,380) | 376,127 | `benchmarks/phase-2-circuit/op3b-finalitybranch.md:60`; raw `benchmarks/raw/phase-2-circuit/op3b-finalitybranch.log:3` |
| — op-4, slot binding, marginal (292,396 − 131,380 = 3 × 53,672) | 161,016 | `benchmarks/phase-2-circuit/op4-slotbind.md:59`; raw `benchmarks/raw/phase-2-circuit/op4-slotbind.log:2,15` |
| public-input packing and wiring (remainder) | **20,141** = 1,990,745 − 929,169 − 1,041,435 | derived |

The direct count itself is recorded in `benchmarks/raw/phase-2-circuit/stage2-setup-regular.log:10`
and `benchmarks/raw/phase-2-circuit/stage3-prove-regular.log:9` (`nbConstraints=1990745`).
