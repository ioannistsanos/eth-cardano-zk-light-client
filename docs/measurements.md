# Measurements: where each value comes from

For every value that the thesis reports from this repository, this file gives the raw measurement
(file and line), the line of the summary that states it, and the kind of evidence:

- **measured**: the value is stored in a raw file under `benchmarks/raw/`;
- **derived**: the value is computed from stored values, and the formula is given;
- **test-backed**: the value is asserted by a test that runs with `aiken check`;
- **fixture-backed**: the value is computed from a committed fixture file.

Paths are relative to the repository root. Short names: **JSON** =
`benchmarks/raw/phase-a-scenario/tier3-1790-SUMMARY.json`; **D27 log** =
`benchmarks/raw/phase-a-rehearsal/D27-regular-rehearsal.log`; **P2/** =
`benchmarks/raw/phase-2-circuit/`; **SUMMARY** = `benchmarks/phase-a/SUMMARY.md`. The date of
every raw file is in `benchmarks/INDEX.md`.

## On-chain cost (Cardano Preview)

| Value | Kind | Raw measurement | Summary |
|---|---|---|---|
| 7,094,172,930 CPU steps, regular update | measured | JSON:19 and the 58 other regular entries (`ex_units_steps`); D27 log:11 (evaluation) and D27 log:14 (confirmed transaction) | SUMMARY:47 |
| 7,265,427,726 CPU steps, boundary update | measured | JSON:1159 | SUMMARY:47 |
| 611,176 memory units, regular update | measured | JSON:20 and the 58 other regular entries; D27 log:11,14 | SUMMARY:49 |
| 655,584 memory units, boundary update | measured | JSON:1160 | SUMMARY:49 |
| 995,880 lovelace, fee of a regular update | measured | JSON:21 and the 58 other regular entries; D27 log:11 | SUMMARY:52 |
| 1,010,791 lovelace, fee of the boundary update | measured | JSON:1161 | SUMMARY:52 |
| 6,676 B, transaction size of both kinds | measured | JSON:22 and JSON:1162; D27 log:11 | SUMMARY:51 |

## Decomposition of the on-chain cost

Each pair of values is regular update / boundary update.

| Value | Kind | Formula and evidence | Summary |
|---|---|---|---|
| 4,143,014,564 / 4,220,445,377, builtins of the cost table | derived | cost-model values times executions: 8 × 254,006,273 + 3 × 333,849,714 + 2 × 2,174,038 + 166,935,071 + 12 / 13 × 76,468,478 + 13 / 14 × 962,335 + 8,000,000 (the approximate hash-to-field row); the cost-model values are checked at `benchmarks/cost-validation/README.md:81-88` | SUMMARY:146 |
| 53,108,222 and 74,858,572, one G1 and one G2 point decompression | measured | `benchmarks/raw/phase-1-cost-model/M9-raw.log:16-17`: the cost-model values 52,948,122 and 74,698,472 plus 160,100 of evaluation overhead (lines 20-21); the cost-model values are checked at `benchmarks/cost-validation/README.md:90-91` | SUMMARY:124; `benchmarks/phase-1-cost-model/M9-report.md` |
| 20 G1 and 7 G2 decompressions / 21 G1 and 7 G2 | counted in the source | every call site is listed in `benchmarks/phase-1-cost-model/M9-report.md`, "Executions in the validator" | SUMMARY:147-148 |
| 1,581,851,744 / 1,634,799,866, point decompression | derived | 20 × 52,948,122 + 7 × 74,698,472 / 21 × 52,948,122 + 7 × 74,698,472 | SUMMARY:149 |
| 1,369,306,622 / 1,410,182,483, residual | derived | measured total − builtins of the cost table − point decompression: 7,094,172,930 − 4,143,014,564 − 1,581,851,744 / 7,265,427,726 − 4,220,445,377 − 1,634,799,866 | SUMMARY:150 |
| 2,951,158,366 / 3,044,982,349, everything outside the cost table | derived | measured total − builtins of the cost table; equal to point decompression + residual | SUMMARY:168 |

## Sizes

| Value | Kind | Evidence | Summary |
|---|---|---|---|
| 292-byte proof | measured | P2/`stage3-prove-regular.log:32`; P2/`stage3-prove-boundary.log:38`. The proof fixtures `validator/fixtures/proof_regular_n512.json` and `proof_boundary_n512.json` hold 288 bytes of points (48 + 96 + 48 + 48 + 48); the gnark binary adds a 4-byte prefix | SUMMARY:53 |
| 606-byte redeemer | test-backed | test `redeemer_size`, `validator/lib/zkbridge/redeemer_seam_test.ak:27-29` (asserts 606); the same size is pinned in `boot/redeemer.py:98` and checked by `python boot/redeemer.py` | SUMMARY:54 |
| 2,632-byte datum | measured and test-backed | D27 log:8,14; test `validator/lib/zkbridge/genesis_datum_test.ak:114`; each `boot/genesis_datum_*.hex` holds 5,264 hexadecimal characters | SUMMARY:55; `boot/STAGE2_REHEARSAL.md:31` |
| 1,152-byte verification key, regular | fixture-backed | computed from `validator/fixtures/groth16_regular_n512.json`: 14 G1 points (`alpha` and 13 `ic`) × 48 B + 5 G2 points (`beta`, `gamma`, `delta`, `commitment_g`, `commitment_g_sigma_neg`) × 96 B = 672 + 480; comment at `validator/lib/zkbridge/types.ak:68` | SUMMARY:56 |
| 1,200-byte verification key, boundary | fixture-backed | computed from `validator/fixtures/groth16_boundary_n512.json`: 15 G1 points (`alpha` and 14 `ic`) × 48 B + 5 G2 points × 96 B = 720 + 480; comment at `validator/lib/zkbridge/types.ak:70` | SUMMARY:56 |

## Bootstrap transaction

| Value | Kind | Raw measurement | Summary |
|---|---|---|---|
| 12.45 ADA deposit | measured | D27 log:8 (12,447,280 lovelace); `boot/STAGE2_REHEARSAL.md:28` | `docs/c-runbook.md:6`; `docs/live-run-log.md` sections 1 and 2 |
| 0.32 ADA bootstrap fee | measured | D27 log:8 (317,085 lovelace); `boot/STAGE2_REHEARSAL.md:30` | `docs/live-run-log.md` sections 1 and 2 |

## Constraint counts

| Value | Kind | Raw measurement or formula | Summary |
|---|---|---|---|
| 1,990,745, regular circuit | measured | P2/`stage2-setup-regular.log:10`; P2/`stage3-prove-regular.log:9` | `benchmarks/phase-2-circuit/regular-assembly.md:8`; SUMMARY:66 |
| 60,889,638, boundary circuit | measured | P2/`stage1-boundary-direct512.log:7`; P2/`stage2-setup-boundary.log:10`; P2/`stage3-prove-boundary.log:15` | `benchmarks/phase-2-circuit/boundary-assembly.md:10`; SUMMARY:66 |
| 929,169, committee region of the regular circuit | measured | P2/`committee-bind-direct512.log:14` | `benchmarks/phase-2-circuit/regular-assembly.md:30` |
| 0.38 million (380,929), Poseidon2 commitment over 512 keys | measured | P2/`poseidon-commit.log:22` | `docs/records.md`, D9 |
| 2,566,466, Poseidon2 commitment over the 48-byte compressed encoding of 512 keys (encoding not adopted) | measured | P2/`compressed-commit.log:10` | `docs/records.md`, D9 |
| 0.55 million (548,240), conditional sum and count | derived: 929,169 − 380,929 | P2/`committee-bind-direct512.log:14` and P2/`poseidon-commit.log:22`; the difference is noted at P2/`committee-bind-direct512.log:39-40` | `docs/records.md`, D13 |
| 1,041,435, finality and slot Merkle proofs | derived: 504,292 + 376,127 + 161,016 | P2/`op3a-headerreconstruct.log:8` (504,292); P2/`op3b-finalitybranch.log:3` (507,507, less the shared 131,380); P2/`op4-slotbind.log:2` (292,396, less the shared 131,380 at P2/`op4-slotbind.log:15`) | `benchmarks/phase-2-circuit/regular-assembly.md:31-34` |
| 20,141, public-input packing | derived: 1,990,745 − 929,169 − 1,041,435 | the three values above | `benchmarks/phase-2-circuit/regular-assembly.md:35` |
| 749,039, finality proof inside the assembled circuit | derived: (504,292 − 131,380) + (507,507 − 131,380) = 372,912 + 376,127 | P2/`op3a-headerreconstruct.log:8`; P2/`op3b-finalitybranch.log:3`; P2/`op4-slotbind.log:15` | `benchmarks/phase-2-circuit/op3b-finalitybranch.md:77` |
| 292,396, slot binding as a standalone circuit | measured | P2/`op4-slotbind.log:2` | `benchmarks/phase-2-circuit/op4-slotbind.md:25,49` |
| 54.8 million (54,786,825), merkleisation of the 512 keys in the boundary circuit | measured at N = 4, 8, 16 and extrapolated | P2/`pubkeys-root-smallN.log:7-11` | `docs/records.md`, D10 |
| 3,309,584, decompression and validation of the 512 keys | measured | P2/`decompress-pubkey-direct512.log:13` | `docs/records.md`, D11 |
| 1,739,496 and 2,652,648, assembled binding of the successor committee at N = 8 and N = 16 | measured | P2/`op6-assembled-smallN.log:7-8` | `docs/records.md`, D12 |
| 646.8 and 1,253.6 constraints per G1 addition | measured (slopes of a linear fit) | P2/`g1-add-measure.log:25` | `benchmarks/phase-2-circuit/g1-add-constraint-cost.md:51-54` |

## Proving time

| Value | Kind | Raw measurement or formula | Summary |
|---|---|---|---|
| 14.56 s, regular circuit, benchmark median of 5 | measured | P2/`stage3-prove-regular.log:29` (the five runs are on lines 24 to 28) | SUMMARY:67 |
| 428.46 s, boundary circuit, benchmark median of 5 | measured | P2/`stage3-prove-boundary.log:35` (the five runs are on lines 30 to 34) | SUMMARY:67 |
| 14.62 s, regular updates of the live run | derived: mean of `prove_seconds` over the 59 regular entries of JSON (14.617 s) | `benchmarks/raw/phase-a-scenario/timing_stats.out:3` | SUMMARY:68 |
| 432 s, boundary update of the live run | measured | JSON:1152 (432.030115326) | SUMMARY:68 |

## Timing of the 60-update run

| Value | Kind | Formula over the 59 regular entries of JSON | Computed value | Summary |
|---|---|---|---|---|
| 83 s, mean time per update | derived | mean of `total_seconds` − `poll_detect_seconds` | 83.30 s, `benchmarks/raw/phase-a-scenario/timing_stats.out:5` | SUMMARY:91 |
| 79 s, median time per update | derived | median of `total_seconds` − `poll_detect_seconds` | 78.97 s, `benchmarks/raw/phase-a-scenario/timing_stats.out:6` | SUMMARY:92 |
| 69 s, mean submission time | derived | mean of `submit_seconds` | 68.63 s, `benchmarks/raw/phase-a-scenario/timing_stats.out:7` | SUMMARY:93 |
| 379 s, mean interval between updates | derived | (last − first `completed_unix`) / 59 over all 60 entries = 22,346 / 59 | 378.75 s, `benchmarks/raw/phase-a-scenario/timing_stats.out:8` | SUMMARY:75 |

The derived timing values are computed by `benchmarks/phase-a/timing_stats.py`, which reads JSON and
writes the output file cited above.

## Values without a raw file

- The per-update data of the run on period 1788 (31 regular updates, 2026-06-26 to 2026-06-29) were
  not retained. The values of that run in `docs/live-run-log.md` (section 3) are the ones recorded at
  the time of the run.
- The off-chain verification times of the proofs and the split of the proving time into witness
  solving and proving in the 60-update run were read from the relayer output, which was not
  retained (`docs/live-run-log.md`, section 4).

## Transactions on Preview

| Transaction | Hash | Explorer |
|---|---|---|
| Boundary update (update 58 of the 60-update run, JSON:1158) | `c8b296a91ab7cf16756f3d5c169a06985544482d817a640d36917e61b1675b55` | <https://preview.cardanoscan.io/transaction/c8b296a91ab7cf16756f3d5c169a06985544482d817a640d36917e61b1675b55> or <https://preview.cexplorer.io/tx/c8b296a91ab7cf16756f3d5c169a06985544482d817a640d36917e61b1675b55> |
| Regular update (update 1 of the 60-update run, JSON:18) | `4ba8f81a370f1dd38fdacfcc07d887749486d683366227ac77d984f47a43ad42` | <https://preview.cardanoscan.io/transaction/4ba8f81a370f1dd38fdacfcc07d887749486d683366227ac77d984f47a43ad42> or <https://preview.cexplorer.io/tx/4ba8f81a370f1dd38fdacfcc07d887749486d683366227ac77d984f47a43ad42> |

Both transactions were found on the Preview chain on 2026-10-04 (blocks 4,430,575 and 4,429,953),
with the fees listed above. Explorers show a size of 6,675 B for them: the size computed by the
ledger leaves out the one-byte validity flag of the serialised transaction. 6,676 B is the length
of the serialised transaction as submitted (`tx_size_bytes`).
