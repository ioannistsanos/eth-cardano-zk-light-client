# Phase A — Empirical Results Summary (Cardano Preview, live)

Citation-grade summary of the Phase-A measurements. Every value carries a pin:
a raw file and line, a test, or a record of `docs/records.md` (labels D1 to
D31). Derived values (percentages, ratios) are marked "derived". This file
stands alone and can be read without the thesis. Short names in the pins:
**JSON** = `benchmarks/raw/phase-a-scenario/tier3-1790-SUMMARY.json`;
**D27 log** = `benchmarks/raw/phase-a-rehearsal/D27-regular-rehearsal.log`;
**P2/** = `benchmarks/raw/phase-2-circuit/`. The map from every value to its
evidence is `docs/measurements.md`.

## 1. Run identity & provenance

- Network: **Cardano Preview testnet**. Validator: the Plutus V3 spending
  validator + one-shot state-thread NFT policy compiled from `validator/`
  (Aiken **v1.1.22**, `plutus.json` blueprint; `validator/aiken.toml`).
- Prover: gnark **v0.13.0** / gnark-crypto **v0.18.0** on Go **1.23.6**
  (`prover/go.mod:3,6-7`); proving/setup hardware: GCP `n2-custom-12` (12 vCPU)
  class VMs (D23, D24; `docs/c-runbook.md`, step S1).
- Bridges (identified in the records by boot UTxO / address / policy):
  - **Period-1788 bridge** `87560d56…#0` — the (C) scenario: **31 regular
    updates confirmed on-chain**, span 2026-06-26 → 06-29
    (`docs/live-run-log.md` §3).
  - **Period-1790 bridge** `6d771d42…#0`, checkpoint `0x5244f60b…` — the
    Tier-3 run, **2026-07-01**: **60 phases = 59 regular + 1 boundary**
    (phase 58 = the 1790→1791 rotation, tx `c8b296a9…`)
    (`docs/live-run-log.md` §4; JSON:1158).
  - Earlier rehearsal bridges (D22 `a179dcc7…`, D27 `addr_test1wzv7typ…` /
    policy `40c0b53a…`) are recorded separately
    (`boot/STAGE2_REHEARSAL.md:15`; D27 log:4).
- The headline on-chain figures below are from the Tier-3 run (period-1790
  bridge, n=59 regular spends, 2026-07-01). They reproduce the D27 rehearsal
  measurement of 2026-06-17 (n=1) bit-for-bit — 7,094,172,930 steps / 611,176
  mem / 995,880 lovelace / 6,676 B (JSON:19-22; D27 log:11,14). The
  period-1788 run (31 regular spends, 2026-06-26 → 06-29) corroborates the
  regular figures only qualitatively: its per-update data were not retained
  (`docs/live-run-log.md` §3).
- Trusted-setup caveat: the keys come from a **single-party
  `groth16.Setup` demonstrator** — sound only under the operator's destruction
  of the trapdoor τ; production requires the MPC ceremony the thesis names
  (`docs/assembly-design.md`, "Trusted-setup honesty").

## 2. Headline results (on-chain, measured)

| Quantity | Regular | Boundary | Pin |
|---|---|---|---|
| CPU steps | **7,094,172,930** | **7,265,427,726** | JSON:19, D27 log:11,14 / JSON:1159 |
| % of 10,000,000,000 limit (derived) | 70.9 % | 72.7 % | from the row above |
| Memory units | **611,176** | **655,584** | JSON:20, D27 log:11,14 / JSON:1160 |
| % of 16,500,000 limit (derived) | 3.7 % | 4.0 % | from the row above |
| Tx size | **6,676 B** | **6,676 B** (same size) | JSON:22, D27 log:11 / JSON:1162 |
| Fee | **995,880 lovelace ×59 (constant)** | **1,010,791 lovelace** | JSON:21 and the 58 other regular entries, D27 log:11 / JSON:1161 |
| Proof (gnark binary) | **292 B** | **292 B** | P2/`stage3-prove-regular.log:32` / P2/`stage3-prove-boundary.log:38` |
| Redeemer (on-chain encoding) | **606 B** | **606 B** (kind-uniform) | test `validator/lib/zkbridge/redeemer_seam_test.ak:27-29`; D31 |
| Inline datum | **2,632 B** | **2,632 B** | D27 log:8,14; test `validator/lib/zkbridge/genesis_datum_test.ak:114` |
| vk in datum (compressed points) | **1,152 B** (14 G₁ + 5 G₂) | **1,200 B** (15 G₁ + 5 G₂) | computed from `validator/fixtures/groth16_regular_n512.json` (14 × 48 + 5 × 96) / `groth16_boundary_n512.json` (15 × 48 + 5 × 96); D19, D23 |

(The gnark `.vk` disk binaries are 1,264 / 1,312 B — a different artifact than
the datum form; do not conflate. P2/`stage2-setup-regular.log:15` /
P2/`stage2-setup-boundary.log:15`.)

## 3. Circuit & proving (off-chain, measured)

| Quantity | Regular | Boundary | Pin |
|---|---|---|---|
| R1CS constraints (direct N=512) | **1,990,745** | **60,889,638** | P2/`stage2-setup-regular.log:10` / P2/`stage1-boundary-direct512.log:7` |
| Proving time — benchmark, **n=5** | **14.56 s** (14.39/14.86) | **428.46 s** (426.97/432.02) | P2/`stage3-prove-regular.log:29` / P2/`stage3-prove-boundary.log:35` |
| Proving time — live | **14.62 s mean, n=59** (14.37–14.91) | **432.0 s — a single live run** (solver 70.8 + prover 361.0) | `benchmarks/raw/phase-a-scenario/timing_stats.out:3` (derived from JSON, `prove_seconds`) / JSON:1152; the solver/prover split has no raw file (`docs/live-run-log.md` §4) |
| Proving memory (peak) | **5.52 GiB** | **96.53 GiB** | P2/`stage3-prove-regular.log:30` / P2/`stage3-prove-boundary.log:36` |
| gnark `groth16.Verify` (off-chain) | **2.67 ms** | **2.85 ms** | read from the relayer output, no raw file (`docs/live-run-log.md` §4) |

The boundary proving time rests on the ×5 GCP benchmark plus one live run; the
regular figure has n=59 live samples.

Live pipeline cadence: **379 s/phase** (measured mean inter-update interval)
sustained over the 60-phase Tier-3 run (prove + submit + confirm;
`benchmarks/raw/phase-a-scenario/timing_stats.out:8`, derived from the field
`completed_unix` of JSON).

**Timing statistics (Tier-3 1790, regular phases, n = 59)** — recomputed
2026-09-24 from `benchmarks/raw/phase-a-scenario/tier3-1790-SUMMARY.json`
(`phases[]`, the 59 entries with `kind == "REGULAR"`; the single `BOUNDARY`
phase, the 58th in run order, is excluded); the script is
`benchmarks/phase-a/timing_stats.py` and its output
`benchmarks/raw/phase-a-scenario/timing_stats.out`. Fields used: `poll_detect_seconds`
(the wait for the next finalized checkpoint), `prove_seconds`,
`submit_seconds`, `total_seconds`.

| Statistic | Formula | Value |
|---|---|---|
| Per-update time excluding the checkpoint wait, mean | mean(`total_seconds` − `poll_detect_seconds`) | **83.3 s** |
| Per-update time excluding the checkpoint wait, median | median(`total_seconds` − `poll_detect_seconds`) | **79.0 s** |
| Submission stage, mean | mean(`submit_seconds`) | **68.6 s** |

`total_seconds − poll_detect_seconds` equals `prove_seconds + submit_seconds`
within 0.05 s on every phase (the residue is record-building time). Spread:
per-update 58.7–200.7 s; submission 44.1–186.0 s (median 64.4 s); proving
14.4–14.9 s (mean 14.6 s). Σ over the 59 phases: 4,914.44 s / 4,049.39 s /
862.38 s (per-update / submission / proving). The thesis (§3.3.2) quotes
≈ 83 s / ≈ 79 s / ≈ 69 s.

## 4. The central contrast (size-independence of verification)

The boundary circuit has **30.6×** the constraints of the regular (60,889,638
vs 1,990,745 — derived from D15/D16) and proving scales with it (~29×: 14.56 s
→ 428.46 s, D24). Verification does not: on-chain cost rises **+2.4 %**
(+171,254,796 steps, derived from D27/D31) and off-chain verify is
**2.85 ms ≈ 2.67 ms** (`docs/live-run-log.md` §4). Verification cost tracks the
public-input count and the validator's extra rotation checks, not the circuit
size — the 30.6× blow-up is entirely off-chain, invisible to the ledger (D31).

## 5. Cost-model fidelity

- **Eight builtin cost rows PASS** against the cost model deployed on Preview
  and on mainnet: the six rows of Table 1
  (`benchmarks/cost-validation/README.md:81-88`) and the two point-decompression
  builtins (`benchmarks/cost-validation/README.md:90-91`); check
  `benchmarks/cost-validation/crosscheck.py`. The M1b and M9 measurements below
  agree with these values in execution.
- **M1b**: the predicted 4th-millerLoop increment matched measurement to
  **0.0063 %** (254,006,273 predicted vs 254,022,273 measured, a difference
  of 16,000 steps; `benchmarks/raw/phase-1-cost-model/M1b-raw.log:27-28`;
  `benchmarks/phase-1-cost-model/M1b-groth16-realistic.md`; D1).
- **M9**: one `bls12_381_g1_uncompress` call measured **53,108,222** and one
  `bls12_381_g2_uncompress` call **74,858,572** — the cost-model values
  52,948,122 and 74,698,472 plus 160,100 of evaluation overhead in each test
  (`benchmarks/raw/phase-1-cost-model/M9-raw.log:16-17,20-21`;
  `benchmarks/phase-1-cost-model/M9-report.md`).
- **Decomposition of the measured totals (derived, not assumed)**: every
  builtin charge is the cost-model value times the number of executions; the
  residual is what remains of the measured total.

  | Component | Regular | Boundary | Arithmetic |
  |---|---:|---:|---|
  | 4 × millerLoop (Groth16 main equation) | 1,016,025,092 | 1,016,025,092 | 4 × 254,006,273 |
  | 2 × mulMlResult | 4,348,076 | 4,348,076 | 2 × 2,174,038 |
  | 1 × finalVerify (main equation) | 333,849,714 | 333,849,714 | |
  | 2 × millerLoop (commitment proof of knowledge) | 508,012,546 | 508,012,546 | 2 × 254,006,273 |
  | 1 × finalVerify (proof of knowledge) | 333,849,714 | 333,849,714 | |
  | hash-to-field of the commitment (approximate row) | 8,000,000 | 8,000,000 | approximation of the thesis cost table |
  | 12 / 13 × G1_scalarMul | 917,621,736 | 994,090,214 | 12 / 13 × 76,468,478 (= 76,433,006 + 8,868 × 4) |
  | 13 / 14 × G1_add | 12,510,355 | 13,472,690 | 13 / 14 × 962,335 |
  | 1 × G2_hashToGroup | 166,935,071 | 166,935,071 | 166,917,843 + 4,307 × 4 |
  | 2 × millerLoop (BLS) | 508,012,546 | 508,012,546 | 2 × 254,006,273 |
  | 1 × finalVerify (BLS) | 333,849,714 | 333,849,714 | |
  | **A. builtins of the cost table** | **4,143,014,564** | **4,220,445,377** | sum of the rows above |
  | 20 / 21 × G1_uncompress | 1,058,962,440 | 1,111,910,562 | 20 / 21 × 52,948,122 |
  | 7 × G2_uncompress | 522,889,304 | 522,889,304 | 7 × 74,698,472 |
  | **B. point decompression** | **1,581,851,744** | **1,634,799,866** | sum of the two rows above |
  | **C. residual** | **1,369,306,622** | **1,410,182,483** | measured − A − B |
  | **Measured total** | **7,094,172,930** | **7,265,427,726** | §2 |

      B (regular)  = 20 × 52,948,122 + 7 × 74,698,472 = 1,058,962,440 + 522,889,304 = 1,581,851,744
      B (boundary) = 21 × 52,948,122 + 7 × 74,698,472 = 1,111,910,562 + 522,889,304 = 1,634,799,866
      C (regular)  = 7,094,172,930 − 4,143,014,564 − 1,581,851,744 = 1,369,306,622
      C (boundary) = 7,265,427,726 − 4,220,445,377 − 1,634,799,866 = 1,410,182,483

  The execution counts of the two decompression builtins, with every call
  site, are in `benchmarks/phase-1-cost-model/M9-report.md` ("Executions in the
  validator"); the call sites of the rows of A are
  `validator/lib/zkbridge/groth16.ak:156-206` and
  `validator/lib/zkbridge/bls.ak:70-77`. A is the cost table of the thesis; A + B
  = 5,724,866,308 / 5,855,245,243 (58.4 % + 22.3 % of the regular total,
  58.1 % + 22.5 % of the boundary total). C (19.3 % / 19.4 %) is everything
  else: the Plutus interpreter, the handling of the script context, and the
  builtins not listed in A and B (SHA-256, byte-string, integer and data
  operations, three G2 negations). The hash-to-field row is an approximation,
  and C carries it. Measured − A = B + C = 2,951,158,366 / 3,044,982,349. For
  the regular update, 219,764,800 of C is already present when the validator
  is evaluated with `aiken check` on a minimal transaction (5,944,631,108 − A −
  B; test at `validator/validators/bridge.ak:337`), and 1,149,541,822 is the
  difference between the on-chain execution and that evaluation (D27). This
  replaces the design-time ~0.5 B "script overhead" placeholder.
- **Unit note (2026-09-12)**: `bls12_381_G2_hashToGroup` on the 32-byte
  signing root is charged **166,935,071** = 166,917,843 + 4,307 × **4** —
  the cost model measures ByteString arguments in 8-byte words
  (`((n − 1) quot 8) + 1`, `ExMemoryUsage.hs:315-324`; UPLC-verified). The
  earlier 167,055,667 (n = 32 bytes) was a unit error; the measured totals
  are unaffected, the residual above absorbs the +120,596.

## 6. Estimate vs measured (headline deltas)

| Quantity | Thesis estimate | Measured | Direction | Pin |
|---|---|---|---|---|
| Regular circuit R1CS | 10–26 M | 1,990,745 | refuted DOWN ~5–13× | D15 |
| Boundary circuit R1CS | 10–26 M + ~232 K | 60,889,638 | refuted UP (op-6 ~59 M) | D16 |
| Per-tx CPU (reg/bnd) | ~3.08 B / ~3.17 B | 7,094,172,930 / 7,265,427,726 | refuted UP ~2.3× (still 70.9 %/72.7 % of limit) | D27 / D31 |
| Script overhead | ~0.5 B placeholder | 2.95 B / 3.04 B outside the cost-table rows: point decompression 1.58 B / 1.63 B + residual 1.37 B / 1.41 B | refuted UP ~6× (residual alone ~2.7×) | §5 above (derived) |
| Datum size | ~1,580–1,600 B | 2,632 B | UP ~65 % | D18, D19 |
| vk sizes | ~672 / ~720 B | 1,152 / 1,200 B | UP (IC growth + commitment key) | D19, D23 |
| Proving time | 10–35 s | 14.56 s / 428.46 s | regular INSIDE; boundary UP ~12× | D24 |
| Proving memory | 16–32 GB | 5.52 / 96.53 GiB | regular DOWN; boundary UP ~3× | D24 |

## 7. Negative & control evidence

- Tampered-input rejects (circuit teeth): tampered leaf / tampered sibling /
  wrong-fold each REJECTED at the terminal state-root equality
  (`prover/circuits/common/op3b_test.go:139,152,200`); a tampered Poseidon digest fails the parity
  solve (`prover/circuits/common/poseidonparity_test.go`).
- Live negative: at the 1788→1789 boundary the relayer HALTED before the spend
  rather than submit against a rotated committee (D30) — the fix was
  then live-confirmed at Tier-3 (tx `c8b296a9…`).
- Determinism: fee and ExUnits constant across all 59 regular spends
  (995,880 lovelace ×59; JSON, fields `ex_units_steps`, `ex_units_mem` and
  `fee_lovelace` of the 59 regular entries).
- Byte identity: the deployed genesis datum is byte-identical to the off-chain
  artifact (D22; `boot/STAGE2_REHEARSAL.md:36`).

## 8. Citation-ready lines

1. "The regular Phase-A update transaction measures 7,094,172,930 CPU steps on
   the Cardano Preview testnet; the boundary transaction measures
   7,265,427,726." (D27; D31)
2. "Both transactions fit in one Cardano transaction with 29.1 % / 27.3 % CPU
   headroom and under 4 % of the memory limit." (derived; D27, D31)
3. "The boundary circuit is 30.6× larger than the regular, yet its on-chain
   verification costs only 2.4 % more — verification cost is effectively
   independent of circuit size." (D31)
4. "The transaction fee was constant at 995,880 lovelace (≈0.996 ADA) across
   all 59 regular updates; the boundary paid 1,010,791 (≈1.011 ADA)."
   (D27; D31)
5. "The Plutus cost model predicted the measured verifier increment to within
   0.0063 %." (D1; M1b)
6. "The real Groth16 proof is 292 bytes — five group elements in the
   commitment-augmented form, not the textbook 192-byte triple."
   (D19; D24)
7. "Proving takes 14.62 s (mean, n=59, 12 vCPU) for a regular update and
   432.0 s for the boundary." (`benchmarks/raw/phase-a-scenario/timing_stats.out`;
   `benchmarks/raw/phase-a-scenario/tier3-1790-SUMMARY.json`)

## 9. Pointers

- `docs/records.md` — the records D1 to D31 (D15/D16 circuits, D24 proving,
  D27/D31 on-chain, D30 rotation, D1 cost-model fidelity).
- `docs/live-run-log.md` — the log of the runs on Preview, with the result tables.
- `docs/measurements.md` — the map from every value to its raw evidence.
- `benchmarks/raw/phase-a-scenario/` — `tier3-1790-SUMMARY.json` (tx hashes,
  ExUnits and timings of each update) and `timing_stats.out`.
- `benchmarks/INDEX.md` — every raw file with the date it was recorded.
- `benchmarks/phase-1-cost-model/` — M1-M8 reports (the cost-model baseline).
