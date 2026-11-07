# Index of raw measurement files

Every file under `benchmarks/raw/` with the date it was recorded. Where the file states its own
date, the line is given. Nine logs carry no date inside the file; for those the date below is the
day the log was recorded. The figures quoted in the thesis are mapped to these logs in
`docs/measurements.md`; the cross-check of the cost-model values is described in
`benchmarks/cost-validation/README.md`.

## Phase 1 — on-chain cost model (`benchmarks/raw/phase-1-cost-model/`)

| File | Recorded | Date in the file | Content |
|---|---|---|---|
| `M1-raw.log` | 2026-05-27 | line 2 (`Generated: 2026-05-27T12:01:52Z`) | `aiken check` output, Groth16 pairing sequence with 3 Miller loops |
| `M1b-raw.log` | 2026-05-27 | line 3 (`2026-05-27T15:59:17Z`) | `aiken check` output, pairing sequence with the fourth Miller loop |
| `M2-raw.log` | 2026-05-28 | line 2 (`2026-05-28T11:38:00Z`) | `aiken check` output, BLS signature verification sequence |
| `M3-raw.log` | 2026-05-28 | line 2 (`2026-05-28T15:10:36Z`) | `aiken check` output, public-input MSM with 6 inputs |
| `M4-raw.log` | 2026-05-28 | line 2 (`2026-05-28T16:38:26Z`) | `aiken check` output, public-input MSM with 7 inputs |
| `M5-raw.log` | 2026-05-29 | line 2 (`2026-05-29T11:21:12Z`) | `aiken check` output, synthetic regular composite |
| `M6-raw.log` | 2026-05-30 | line 2 (`2026-05-30T08:33:13Z`) | `aiken check` output, synthetic boundary composite |
| `M7-raw.log` | 2026-05-30 | line 2 (`2026-05-30T13:43:01Z`) | datum CBOR size measurement |
| `M8-raw.log` | 2026-05-30 | line 2 (`2026-05-30T15:12:23Z`) | memory consolidation over M1 to M7 |
| `M9-raw.log` | 2026-10-04 | line 2 (`2026-10-04T16:43:08Z`) | `aiken check` output, one G1 and one G2 point decompression |

## Phase 2 — circuits, setup and proving (`benchmarks/raw/phase-2-circuit/`)

| File | Recorded | Date in the file | Content |
|---|---|---|---|
| `g1-add-measure.log` | 2026-05-31 | none | constraint cost of non-native G1 addition (646.8 and 1,253.6 per addition, line 25) |
| `sha256-measure.log` | 2026-05-31 | none | constraint cost of in-circuit SHA-256 per compression block |
| `op4-slotbind.log` | 2026-06-01 | none | slot-binding circuit, 292,396 constraints (line 2); shared intercept 131,380 (line 15) |
| `op3a-headerreconstruct.log` | 2026-06-01 | none | header-reconstruction circuit, 504,292 constraints (line 8) |
| `op3b-finalitybranch.log` | 2026-06-03 | none | finality-branch circuit, 507,507 constraints (line 3) |
| `regular-assembly-smallN.log` | 2026-06-09 | line 1 | regular circuit at N=8 and N=16 with the extrapolation |
| `boundary-assembly-smallN.log` | 2026-06-09 | line 1 | boundary circuit at N=8 and N=16 with the extrapolation |
| `bootstrap-verify-cost.log` | 2026-06-10 | lines 1 and 20 | wall-clock cost of the off-chain bootstrap verification, two runs |
| `stage1-boundary-direct512.log` | 2026-06-14 | none | direct N=512 compile of the boundary circuit, 60,889,638 constraints (line 7) |
| `stage2-setup-regular.log` | 2026-06-14 | none (times of day only, 17:49 to 17:50) | trusted setup of the regular circuit, 1,990,745 constraints (line 10) |
| `stage2-setup-boundary.log` | 2026-06-14 | none (times of day only, 18:49 to 18:59 at the start) | trusted setup of the boundary circuit, 60,889,638 constraints (line 10) |
| `stage3-prove-regular.log` | 2026-06-15 | none (times of day only, 14:52 to 14:53) | five proving runs of the regular circuit, median 14.56 s (line 29) |
| `stage3-prove-boundary.log` | 2026-06-15 | lines 1 and 41 (`Mon Jun 15 15:26:25 UTC 2026` to `16:17:31 UTC`) | five proving runs of the boundary circuit, median 428.46 s (line 35) |
| `committee-bind-direct512.log` | 2026-10-04 | line 2 | direct N=512 compile of the committee region, 929,169 constraints (line 14) |
| `poseidon-commit.log` | 2026-10-04 | line 2 | Poseidon2 commitment over 512 keys, 380,929 constraints packed (line 22) |
| `compressed-commit.log` | 2026-10-05 | line 2 | Poseidon2 commitment over the 48-byte compressed encoding of 512 keys, 2,566,466 constraints (line 10) |
| `pubkeys-root-smallN.log` | 2026-10-04 | line 2 | SSZ merkleisation of the public keys at N=4, 8, 16, extrapolated to 54,786,825 constraints at N=512 (line 11) |
| `decompress-pubkey-direct512.log` | 2026-10-04 | line 2 | decompression and validation of 512 keys, 3,309,584 constraints (line 13) |
| `op6-assembled-smallN.log` | 2026-10-04 | line 2 | assembled successor-committee binding, 1,739,496 constraints at N=8 and 2,652,648 at N=16 (lines 7 and 8) |

The two setup logs were recorded the day before the proving runs: their times of day (17:49 and
18:49 onward) precede the regular proving run of 2026-06-15 at 14:52, which used the keys they
produced.

## Phase A — live runs on Cardano Preview

| File | Recorded | Date in the file | Content |
|---|---|---|---|
| `phase-a-rehearsal/D27-regular-rehearsal.log` | 2026-06-17 | line 1 | bootstrap transaction and one regular update on a rehearsal bridge |
| `phase-a-scenario/tier3-1790-SUMMARY.json` | 2026-07-01 | field `completed_unix` of each phase (1782864995 to 1782887341, that is 00:16:35 to 06:29:01 UTC) | per-phase record of the 60-update run: transaction hashes, execution units, fees, timings |
| `phase-a-scenario/timing_stats.out` | 2026-10-04 | none | output of `benchmarks/phase-a/timing_stats.py`, computed from the file above; not a measurement |

The nine logs without a date inside the file are `g1-add-measure.log`, `sha256-measure.log`,
`op4-slotbind.log`, `op3a-headerreconstruct.log`, `op3b-finalitybranch.log`,
`stage1-boundary-direct512.log`, `stage2-setup-regular.log`, `stage2-setup-boundary.log` and
`stage3-prove-regular.log`.

## Notes on the raw logs

In five Phase-1 logs the provenance header was edited on 2026-05-29: in `M1b-raw.log`, `M2-raw.log`,
`M3-raw.log`, `M4-raw.log` and `M5-raw.log` the commit identifier on the line `# Repo HEAD at run:`
was replaced, and no other line was changed.

`M1-raw.log` and `M1b-raw.log` hold the second run of 2026-05-27, which replaced the first run after
the control test was redesigned (M1) and the test was rewritten as a `fail` test (M1b). The first
runs are not retained in this repository.

The raw logs keep absolute paths, the earlier module path and commit identifiers of the development
tree, which is not part of this repository.

The header remark at `M2-raw.log` line 32 compares M2's excess with the M1b − M1 difference of the
replaced first run (112,000); the retained run gives 16,000, as `M2-report.md` states. Headers may name
documents by their names at the time of the run: `M1b-raw.log` line 2 names `docs/discrepancies.md`,
whose records are now kept in `docs/records.md`.
