# Bootstrap Verify — off-chain wall-clock cost (D17)

The one-time, deployer-side genesis verification (`offchain/bootstrap.Verify`, the 5 §2.1.6
conditions) on the REAL period-1600 fixtures. Record: `docs/records.md` **D17**.
(Filed under phase-2-circuit as the prover/off-chain bucket — the bootstrap is plain Go, not a
circuit.)

**Go wall-clock, machine-dependent — NOT comparable to the on-chain CPU-step budget, NOT the
proving time.** Headline: **end-to-end Verify ≈ 121–162 ms (median, across same-day runs)** on the
reference machine — sub-second-class for a one-time genesis computation.

| line | run A median | run B median | share (A / B) |
|---|---|---|---|
| **end-to-end Verify** | **161.85 ms** | **121.12 ms** | 100% |
| decompress prelude (1024 keys, serves d+e) | 116.79 ms | 83.47 ms | **74.2% / 74.1%** |
| (e) two Poseidon commitments | 36.59 ms | 25.96 ms | 23.2% / 23.1% |
| (d) BLS sync-aggregate (hashToG2 + pairing) | 2.72 ms | 1.80 ms | 1.7% / 1.6% |
| (a) current@gindex-86 + checkpoint | 669 µs | 688 µs | ~0.4% |
| (b) next@gindex-87 | 666 µs | 674 µs | ~0.4% |
| (c) finality@gindex-169 (K=1000-batched) | 9 µs | 9 µs | <0.01% |
| sum-of-medians vs end-to-end median (no-double-count check) | +2.7% | +7.0% | — |

- **Where the time goes:** key DECOMPRESSION dominates (~74%), the two
  Poseidon commitments second (~23%), the BLS verify a distant third (~2%), the SSZ walks
  negligible (<1%). The shares are stable across runs (±0.1%) even though the absolutes shift
  ~25% with the machine's turbo/thermal state — the shares are the machine-robust result.
- **Prediction check (pre-registered, reported as-is):** "decompression dominates, not the
  pairing" — CONFIRMED. Magnitude guesses were within ~2× (pairing slightly under, PubkeysRoot
  ~2× under).
- **Methodology revision (data-driven, reported as-is):** the design pre-registered MIN as the
  headline (additive-noise argument); measurement showed min is UNSTABLE across runs on this
  laptop-class machine (end-to-end min 96.8–146.3 ms across four same-day runs — turbo/thermal
  shifts the intrinsic baseline between loops), while medians are stable within a run and the
  medians-sum cross-check validates the no-double-count structure (+2.7%/+7.0%). MEDIAN is the
  reported headline; minima are shown, flagged.
- **No double-count:** decompression is timed ONCE as the shared prelude, exactly as `Verify`
  executes it (the prelude serves conditions d AND e); (d)/(e) are timed on pre-decompressed
  keys. The per-line medians sum to ≈ the end-to-end median (gap +2.7%/+7.0% = glue + variance).
- **Golden-datum determinism:** every end-to-end run (2×(100+10)) reproduced the real genesis
  datum exactly (current `0x10041e8c…`, next `0x483e20c9…`, finalized `0x201a1d12…`, slot
  13107200) — HALT-guarded.
- Command: `go run ./cmd/measure_bootstrap` (from `prover/`). N=100 samples/line, 10 warm-ups
  discarded, `runtime.GC()` before each sample.
- Provenance: measured 2026-06-10; loader = `bootstrap.LoadFromFixtures` (the same path
  `TestBootstrap_RealPositive` validates); decompression timed via `bootstrap.DecompressCommittee`
  (wraps the exact `Verify`-prelude internal).
- Machine: Intel i7-9750H @ 2.60GHz, 7.7 GB RAM, WSL2 6.6.114.1-microsoft-standard-WSL2,
  Go 1.23.6, gnark-crypto v0.18.0.
- Raw log (both runs, complete): `benchmarks/raw/phase-2-circuit/bootstrap-verify-cost.log`.
