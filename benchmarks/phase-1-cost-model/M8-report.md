# M8 — Memory Consolidation (M1–M7)

Phase 1, measurement M8. Consolidation of the reported **memory** (execution-unit
`mem`) across all Phase-1 benchmarks M1–M7, confirming memory is **non-binding**
against the **16,500,000**-unit per-tx limit.

M8 is **confirmatory** (like M4 was for D3): no new measurement, no H₀. The
criterion is simply max `mem` ≪ 16,500,000, and each live re-run must match the
value already recorded in its M-report.

See the M1–M7 reports and `docs/records.md`.

## 1. Scope

- Consolidates the memory figures from M1–M7. Each benchmark was **re-run live**
  (read-only, G7 exact-match scoping: `aiken check -e -m <exact test names>
  --seed 42`) and its `mem` extracted; the live max is compared to the recorded
  M-report value (**Δ must be 0**).
- Criterion: max `mem` ≪ 16,500,000 (per-tx memory limit). No H₀, no ±0.05 %
  target.
- M7 (`bench_m7_datum_size`) is reported **separately** — its `mem` is the cost of
  the `serialise_data` / size test, **not** an EX-unit crypto verification.
- No `.ak` change; this is a consolidation of existing benchmarks.

## 2. Consolidation — live re-run matched recorded (Δ = 0)

| benchmark | max mem (live) | recorded (M-report) | Δ | % of 16,500,000 | max-mem test |
|---|---|---|---|---|---|
| M1 | 4,315 | 4,315 | 0 | 0.0262 % | `bench_m1_groth16_core` |
| M1b | 4,487 | 4,487 | 0 | 0.0272 % | `bench_m1b_groth16_realistic` |
| M2 | 3,629 | 3,629 | 0 | 0.0220 % | `bench_m2_bls_core` |
| M3 | 6,434 | 6,434 | 0 | 0.0390 % | `bench_m3_msm_core_n32/n2` |
| M4 | 7,270 | 7,270 | 0 | 0.0441 % | `bench_m4_msm_boundary_core_n32/n2` |
| M5 | 13,678 | 13,678 | 0 | 0.0829 % | `bench_m5_core` |
| **M6** | **14,514** | **14,514** | **0** | **0.0880 %** | `bench_m6_core` |
| M7 *(size test)* | 13,228 | — | — | 0.0802 % | `bench_m7_datum_size` |

Every Phase-A crypto benchmark (M1–M6) reproduced its recorded memory **to the
unit** (Δ = 0). Controls are far lower (M1 control 1,254; M3/M4 controls 1,118;
M5/M6 controls 3,648) — the max is always the core/composite test.

## 3. Peak

**M6 (boundary composite) at 14,514 units = 0.0880 %** of the 16,500,000 limit —
the largest of all Phase-A benchmarks (as expected: the boundary composite runs
the most builtins). Even the peak uses **< 0.1 %** of the memory budget.

## 4. M7 datum-size test (separate category)

`bench_m7_datum_size` = **13,228** units. This is the memory cost of **evaluating**
the datum construction + `serialise_data` (both representations) + the length
assertions — a size/serialisation test, **not** a crypto EX-unit run. It is not
comparable to the M1–M6 crypto figures but is reported for completeness; it is
also far below the limit (0.0802 %).

## 5. Conclusion — memory is NON-BINDING

Across all Phase-A benchmarks the peak memory (**14,514**, M6) is **0.088 %** of
the 16,500,000-unit ceiling — the limit is **never approached**. Memory is **not**
a binding constraint for Phase A.

**CPU steps are the governing resource.** The D1+D2+D3-corrected projections —
Phase A regular **~3.33 B**, boundary **~3.42 B** — sit against the
**10,000,000,000** CPU-step per-tx limit (~66 % headroom), whereas memory sits at
< 0.1 % of its limit. Phase A is **CPU-bound, not memory-bound**.

## 6. Determinism

`mem` is deterministic (from the cost model). Each extraction was run **×2** with
identical results for every benchmark (run 1 == run 2 — see `M8-raw.log`).

## 7. Raw output

See `benchmarks/raw/phase-1-cost-model/M8-raw.log`.
