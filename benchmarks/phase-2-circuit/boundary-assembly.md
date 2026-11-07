# BoundaryCircuit assembly — R1CS cost (D16)

The assembled boundary Phase-A circuit (the regular core + op-6 next-committee path, Option-P
12-Fr public layout). Record: `docs/records.md` **D16**.

| measurement | value |
|---|---|
| small-N | N=8/16 = **2,292,551 / 3,222,631** (×2-deterministic) |
| extrapolated N=512 | **60,887,591 ≈ ~60.9M** [slope ~116,260/key, intercept ~1,362,471] |
| **direct N=512 (GCP)** | **60,889,638 ≈ ~60.89M** — confirms the extrapolation to **+0.0034%** (+2,047 constraints); the **authoritative** boundary count — see **D16** |
| public inputs | 12 Fr (the regular 11 + NextPubkeysCommitment; witness.Public() == 12) |
| vs thesis §2.1.3(.A) | the boundary envelope (10–26M + op-6 ~232K) **refuted UPWARD ~2.3–6×**; op-6 ~232K → ~59M (**~254×**) — see D16 |

- Cross-check (two independent estimation ROUTES, not two directs): regular direct 1,990,745
  (D15) + op-6 composition ≈ 58.85M (SHA 54,786,825 per-node-extrapolated over the exact 1,023
  nodes, `benchmarks/raw/phase-2-circuit/pubkeys-root-smallN.log:11` + decompress 3,309,584
  direct-512, `benchmarks/raw/phase-2-circuit/decompress-pubkey-direct512.log:13` + Poseidon
  380,929, the same construction over 512 keys, `benchmarks/raw/phase-2-circuit/poseidon-commit.log:22`
  + container and branch hashes ≈ 0.37M: 7 evaluations (1 container + 6 walk steps) = 14 blocks
  × 26,751–26,836 per block = 374,514–375,704, the in-assembly marginal rates 749,039 / 28 blocks
  (`benchmarks/phase-2-circuit/op3b-finalitybranch.md:77`) and 53,672 / 2
  (`benchmarks/raw/phase-2-circuit/op4-slotbind.log:14`)) ≈ 60.84M — within 0.1% of both the
  extrapolation and the direct count. The sum is an estimate; the direct-512 count 60,889,638
  (GCP, above) is the authoritative number.
- Extrapolation caveat: the D13/D15 overshoots were ~6.6%/~16% ⇒ the direct likely lands
  ~51–57M; the upward refutation stands across the band. *(Outcome: the GCP direct landed
  **+0.0034% above** the extrapolation — the small-N overshoot pattern did not recur here; D16.)*
- Provability risk: see D16 ("the project's biggest physical unknown" — ~100 GB-class
  setup/prove expectation, no recorded fallback).
- Command: `go run ./cmd/measure_boundary` (small-N + extrapolation, ×2-deterministic).
- Provenance: built + measured 2026-06-07.
- Machine: Intel i7-9750H @ 2.60GHz, 7.7 GB RAM, WSL2 6.6.114.1-microsoft-standard-WSL2,
  Go 1.23.6, gnark v0.13.0.
- Raw log: `benchmarks/raw/phase-2-circuit/boundary-assembly-smallN.log` — a 2026-06-09 re-run
  (×2-deterministic; reproduces the small-N numbers above exactly — a regression check, HALT on
  mismatch). The direct N=512 raw log is `benchmarks/raw/phase-2-circuit/stage1-boundary-direct512.log`
  (2026-06-14, line 7).
