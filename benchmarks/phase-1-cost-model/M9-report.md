# M9 — Point decompression (G1_uncompress, G2_uncompress)

Phase 1, measurement M9 (2026-10-04). Empirical CPU/memory cost of the two
decompression builtins, `bls12_381_g1_uncompress` and `bls12_381_g2_uncompress`.
The validator stores and receives every group element as bytes and decompresses
each one before use, so these two builtins are executed on every update. They
are not rows of the cost table of the thesis, which lists the pairing, MSM and
hash-to-curve builtins; M9 measures them and counts their executions.

See `docs/phase1-methodology.md`, `docs/aiken-gotchas.md` (G5) and
`benchmarks/cost-validation/README.md` (the deployed cost-model values).

## Prediction from the cost model

Both builtins have a constant cost (PlutusV3 parameters 211 and 227):

    bls12_381_G1_uncompress = 52,948,122 CPU steps (memory 18)
    bls12_381_G2_uncompress = 74,698,472 CPU steps (memory 36)

Each test executes one call, so its reported cost is the builtin charge plus the
evaluation overhead of the test body. The two test bodies differ only in the
builtin and its constant, so the overhead is the same in both and

    cpu(G2 test) − cpu(G1 test) = 74,698,472 − 52,948,122 = 21,750,350.

## Configuration

- **Aiken**: v1.1.22+39d6b04 — **Plutus**: V3 (Conway)
- **Hardware**: WSL2 Ubuntu 24.04, Intel i7-9750H @ 2.60 GHz (6c/12t),
  8,070,628 kB MemTotal; kernel 6.18.40.1-microsoft-standard-WSL2 x86_64
- **Command** (from `validator/`): `aiken check -m bench_m9 --seed 42`
- **Determinism**: 5 iterations byte-identical (md5
  `6e6cc56c4b8dd2d1b5abd16db4766c52` ×5)
- **Module**: `validator/lib/benchmarks/m9_uncompress.ak`

## Inputs

Two real points of the regular verification key,
`validator/fixtures/groth16_regular_n512.json`:

- G1: `vk.alpha`, 48 bytes compressed (the point decompressed at
  `validator/lib/zkbridge/groth16.ak:238`);
- G2: `vk.beta`, 96 bytes compressed (the point decompressed at
  `validator/lib/zkbridge/groth16.ak:239`).

## Method note

One call per test. `expect _ = p` references the binding, so that the optimizer
keeps the failable call (G5); an unreferenced binding would be eliminated and
cost nothing. There is no control test: the overhead of the test body is
identified from the two measurements themselves (it is equal in both and is a
whole number of machine steps).

## Measured

| test | CPU steps | memory |
|---|---:|---:|
| `bench_m9_g1_uncompress` | **53,108,222** | 1,118 |
| `bench_m9_g2_uncompress` | **74,858,572** | 1,136 |

## Predicted vs measured

| quantity | cost model | measured | measured − cost model |
|---|---:|---:|---:|
| one G1 decompression | 52,948,122 | 53,108,222 | 160,100 |
| one G2 decompression | 74,698,472 | 74,858,572 | 160,100 |
| G2 − G1 | 21,750,350 | 21,750,350 | **0** |

The overhead is the same in both tests: 160,100 = 10 machine steps × 16,000 +
100 start-up. The memory figures agree with it: 1,118 = 18 + 10 × 100 + 100 and
1,136 = 36 + 10 × 100 + 100. The G1 figure equals the control tests of M3
(53,108,222 / 1,118; `benchmarks/raw/phase-1-cost-model/M3-raw.log:17`), which
execute one `bls12_381_g1_uncompress` call.

**Result:** the per-call cost is the cost-model value; nothing is added to a
call beyond the machine steps of the surrounding program.

## Executions in the validator

Call sites of the two builtins on the two paths of `validator/validators/bridge.ak`
(regular: `groth16.verify_regular` at line 55 and `bls.verify` at line 69;
boundary: `groth16.verify_boundary` at line 87 and `bls.verify` at line 101),
with loops and helper functions unrolled:

| call site | builtin | point | regular | boundary |
|---|---|---|---:|---:|
| `validator/lib/zkbridge/groth16.ak:158` (`msm`) | G1 | `vk.ic[0]` | 1 | 1 |
| `validator/lib/zkbridge/groth16.ak:166` (`fold_msm`, once per public input) | G1 | `vk.ic[1..12]` regular, `vk.ic[1..13]` boundary | 12 | 13 |
| `validator/lib/zkbridge/points.ak:28`, called from `validator/lib/zkbridge/groth16.ak:222` | G1 | proof commitment | 1 | 1 |
| `validator/lib/zkbridge/groth16.ak:228` | G1 | proof of knowledge of the commitment | 1 | 1 |
| `validator/lib/zkbridge/groth16.ak:234` | G1 | proof A | 1 | 1 |
| `validator/lib/zkbridge/groth16.ak:236` | G1 | proof C | 1 | 1 |
| `validator/lib/zkbridge/groth16.ak:238` | G1 | `vk.alpha` | 1 | 1 |
| `validator/lib/zkbridge/points.ak:28`, called from `validator/lib/zkbridge/bls.ak:72` | G1 | aggregate public key (apk) | 1 | 1 |
| `validator/lib/zkbridge/bls.ak:73` | G1 | G1 generator | 1 | 1 |
| **G1 total** | | | **20** | **21** |
| `validator/lib/zkbridge/groth16.ak:229` | G2 | `vk.commitment_g` | 1 | 1 |
| `validator/lib/zkbridge/groth16.ak:230` | G2 | `vk.commitment_g_sigma_neg` | 1 | 1 |
| `validator/lib/zkbridge/groth16.ak:235` | G2 | proof B | 1 | 1 |
| `validator/lib/zkbridge/groth16.ak:239` | G2 | `vk.beta` | 1 | 1 |
| `validator/lib/zkbridge/groth16.ak:240` | G2 | `vk.gamma` | 1 | 1 |
| `validator/lib/zkbridge/groth16.ak:241` | G2 | `vk.delta` | 1 | 1 |
| `validator/lib/zkbridge/bls.ak:71` | G2 | aggregate signature | 1 | 1 |
| **G2 total** | | | **7** | **7** |

- The fold at line 166 runs once per public input: 12 for the regular update
  (11 declared inputs and the commitment hash) and 13 for the boundary update.
  The regular key has 13 `ic` points and the boundary key 14.
- No point is decompressed more than once. The proof commitment and the apk
  arrive uncompressed (96 bytes); `g1_from_uncompressed` rebuilds the compressed
  form by byte operations and decompresses it once.
- The other modules on the two paths (`validator/lib/zkbridge/validation.ak`,
  `validator/lib/zkbridge/types.ak`) contain no call of either builtin.

The counts were confirmed by execution. In a temporary copy of the validator
each builtin was wrapped in a function that emits a trace, and the traces were
counted: the full regular validator on the real N = 512 proof and signature
(the inputs of the test `full_validator_real_regular_positive`) gave 20 and 7;
`groth16.verify_boundary` on the N = 512 boundary proof and key of
`validator/fixtures/` gave 19 and 6 and returned true, and `bls.verify` gave 2
and 1, which is 21 and 7 for the boundary path.

## Charge per update

    regular:  20 × 52,948,122 + 7 × 74,698,472 = 1,058,962,440 + 522,889,304 = 1,581,851,744
    boundary: 21 × 52,948,122 + 7 × 74,698,472 = 1,111,910,562 + 522,889,304 = 1,634,799,866

These two sums enter the decomposition of the measured totals in
`benchmarks/phase-a/SUMMARY.md`, section 5.

## Raw output

See `benchmarks/raw/phase-1-cost-model/M9-raw.log`.
