# Phase 1 — Cost-Calibration Summary (M1–M8)

Consolidation of the Phase-1 composite-transaction cost measurements. **Pure
synthesis** of the M1–M8 reports and `docs/records.md` — every figure here
is sourced from those (cited inline); no number is recomputed and no new finding
is introduced. Calibrates the cryptographic + MSM portion of a Phase A
transaction *before* the validator (Phase 3) and real proofs (Phase 2) exist.

## 1. Purpose & scope

Phase 1 measures the on-chain **CPU steps** and **memory units** of the
crypto + MSM building blocks of a Phase A transaction, on the Plutus V3 CEK
machine (figures from `builtinCostModelC.json` [40], deterministic — not
wall-clock). Inputs are **cost-faithful mocks**: correct builtin shapes / byte
lengths, not real proofs or keys (cost is input-independent for the pairing
builtins; size-faithful for the datum).

Phase 1 **is**: a per-building-block + composite cost calibration to refine the
thesis §3.2.2 Table 2 estimates before Phase 3.

Phase 1 **is NOT**: the real validator (no datum/redeemer parsing, anchor-
invariance, NFT continuity, or datum write — Phase 3/4); not real gnark proofs
(Phase 2); not a full-transaction measurement (Phase 4, on Preview testnet); not
Phase B (user verification). The "~500 M script overhead" remains an unmeasured
placeholder (see §8).

## 2. Benchmark index (M1–M8)

| Benchmark | Measures | Key result (CPU steps unless noted) | Report |
|---|---|---|---|
| M1 | Groth16 verify core, **3-ML** (Table-2 scenario) | marginal **1,100,648,609** (pre-D1 baseline) | `M1-groth16-sequence.md` |
| M1b | Groth16 verify, **4-ML** realistic on-chain form | marginal **1,354,670,882**; +**254,022,273** vs M1 (D1) | `M1b-groth16-realistic.md` |
| M2 | BLS aggregate verify | Table-2 form **1,011,131,369** / canonical no-mul **1,008,845,331** (D2: −2,174,038) | `M2-report.md` |
| M3 | MSM, 6 public inputs (regular) | marginal **465,400,878**; n = 64-bit words + 136K/scalarMul CEK (D3) | `M3-report.md` |
| M4 | MSM, 7 public inputs (boundary) | marginal **542,959,691** (confirms D3 at 7 inputs) | `M4-report.md` |
| M5 | Synthetic Phase A **regular** (M1b+M2-real+M3) | composite **2,829,077,091** vs Σ 2,828,917,091, Δ **+160,000** (D4) | `M5-report.md` |
| M6 | Synthetic Phase A **boundary** (M1b+M2-real+M4) | composite **2,906,635,904** vs Σ 2,906,475,904, Δ **+160,000**; M6−M5 = **77,558,813** (D5) | `M6-report.md` |
| M7 | Datum CBOR **size** (8 fields) | structured **1,656 B** / opaque 1,623 B; refutes thesis ~1,580–1,600 B (D6) | `M7-report.md` |
| M8 | **Memory** consolidation M1–M7 | peak **14,514** (M6) = **0.088 %** of 16.5 M; non-binding | `M8-report.md` |

M9 (2026-10-04, measured after this summary was written) covers the two point-decompression
builtins: **53,108,222** per G1 call and **74,858,572** per G2 call, the cost-model values
52,948,122 and 74,698,472 plus 160,100 of evaluation overhead in each test — `M9-report.md`.

## 3. Findings (D1–D6 + memory) — see `docs/records.md`

| D# | Type | Statement | Measured in | Thesis impact |
|---|---|---|---|---|
| D1 | **Correction** | On-chain Groth16 needs a 4th miller loop (CIP-381 has no MlResult deser); +**254,006,273** | M1 / M1b | Table 2 "3×millerLoop" undercounts (~+8 % of budget) |
| D2 | **Correction** (refinement) | Canonical CIP-381 BLS verify uses no `mul_miller_loop_result`; −**2,174,038** | M2 | Table 2 BLS row over-counts by one mul |
| D3 | **Correction** (clarification) | scalarMul cost-model n = **64-bit words** + **136,000** per-call CEK | M3 / M4 | Table 2 MSM rows → 465,400,878 / 542,959,691 |
| D4 | **Confirmation** | Regular crypto+MSM composes **additively**; +160,000 cross-structure CEK | M5 | Validates summation projection |
| D5 | **Confirmation** | Boundary additive; **boundary − regular = exactly one MSM term** (77,558,813) | M6 | Confirms circuit cost difference |
| D6 | **Correction** | Datum CBOR = **1,656 B** (structured); refutes ~1,580–1,600 B | M7 | §3.1.3 datum estimate replaced |
| (mem) | Confirmation | Peak memory **0.088 %** of 16.5 M → non-binding | M8 | Memory is not a constraint |

## 4. Phase-A cost picture — Table 2 (frozen) vs D-corrected

**Two number sets, kept strictly separate:**

| Phase A total | Thesis Table 2 (**FROZEN**) | D-corrected projection (`records.md`, feeds Ch. 4) | Headroom vs 10 B |
|---|---|---|---|
| Regular | **3.08 B** | **~3.33 B** | ~66.7 % |
| Boundary | **3.17 B** | **~3.42 B** | ~65.8 % |

Table 2 stays **frozen** in the thesis (design-before-observation). The corrected
figures are the **empirical replacement for Chapter 4** — this summary does **not**
edit Table 2. Correction path (per `records.md`): Table 2 **+ D1**
(+254,006,273) **− D2** (−2,174,038) **+ D3** (MSM line-item) ≈ ~3.33 B / ~3.42 B.

**Measured crypto+MSM composite** (the part Phase 1 actually measured):

| Component | Regular (M5) | Boundary (M6) | Source |
|---|---|---|---|
| Groth16 verify, 4-ML (D1) | 1,354,670,882 | 1,354,670,882 | M1b |
| BLS verify, no-mul (D2) | 1,008,845,331 | 1,008,845,331 | M2-real |
| MSM (6 / 7 inputs, D3) | 465,400,878 | 542,959,691 | M3 / M4 |
| Σ component marginals | 2,828,917,091 | 2,906,475,904 | M5 / M6 |
| + cross-structure CEK | +160,000 | +160,000 | M5 / M6 (D4/D5) |
| **= composite marginal** | **2,829,077,091** | **2,906,635,904** | M5 / M6 |

The composite (crypto+MSM) **+ the still-unmeasured ~500 M / ~520 M script-overhead
placeholder** ≈ the D-corrected ~3.33 B / ~3.42 B (§8). **Memory** (M8): peak
14,514 (M6) = 0.088 % of 16.5 M → **non-binding**.

## 5. Datum size (M7 / D6)

Locked **structured** datum = **1,656 B**; opaque comparison = 1,623 B. **Refutes**
the thesis §3.1.3 ~1,580–1,600 B (+56…76 B, ~4 %). Cause: vk CBOR overhead —
`vk_regular` 712 B / `vk_boundary` 762 B from Plutus's **>64-byte chunking** +
per-point length headers + indefinite-array wrappers. Two independent routes agree
byte-for-byte (Aiken `serialise_data` ⟷ pure-Python encoder). Tx-size context:
datum ≈ **10 %** of the 16,384 B tx limit; **non-binding** under reference scripts
(CIP-33, ~13.8 KB headroom).

## 6. Resource conclusion

**CPU steps govern.** Phase A regular ~3.33 B / boundary ~3.42 B vs the
**10 B** per-tx limit (~66 % headroom). **Memory** (0.088 %, M8), **datum size**
(~10 % of tx, M7), and **tx size** are all **non-binding**. The on-chain budget
imposes no constraint that would require special infrastructure. *(Off-chain
proving cost — single-machine feasibility — is a Phase-2 question, not measured
here; thesis estimate 10–35 s, UNKNOWN.)*

## 7. Thesis corrections ledger

| Thesis location | Thesis says | Empirical (Phase 1) | Source |
|---|---|---|---|
| Table 2 "3 × millerLoop (Groth16)" | 762,018,819 (3 ML) | 1,016,025,092 (4 ML), **+254,006,273** | D1 (M1/M1b) |
| Table 2 BLS "1 × mulMlResult + finalVerify" | includes one mul | **no mul**, −2,174,038 | D2 (M2) |
| Table 2 "MSM scalarMul (6 / 7 inputs)" | n ≈ 5.3 (anomalous) | n = 4 words + 136K CEK → 465,400,878 / 542,959,691 | D3 (M3/M4) |
| §3.1.3 datum size | ~1,580–1,600 B | **1,656 B** | D6 (M7) |
| **Phase A total** | **3.08 B / 3.17 B** | **~3.33 B / ~3.42 B** | D1+D2+D3 (`records.md`) |

## 8. What Phase 1 does NOT establish

- The **~500 M / ~520 M script-overhead** is an **UNMEASURED thesis placeholder**
  (§3.2.2); no Phase-1 benchmark touches it. It is, by construction, whatever a
  full Phase A tx costs **beyond** the crypto+MSM measured here (M1–M6 measured
  only crypto+MSM). Its expected composition — datum/redeemer deserialization,
  anchor-invariance checks, NFT continuity, script-context construction — is a
  **HYPOTHESIS** to be measured in **Phase 4**, not a Phase-1 result.
- The corrected ~3.33 B / ~3.42 B are **crypto+MSM projections** (measured
  crypto+MSM + the unmeasured overhead), **not** full-tx measurements.
- **Pending**: real proofs (Phase 2 gnark; R1CS counts, proving time/memory all
  UNKNOWN), the real Aiken validator (Phase 3), real-proof integration (Phase 3b),
  full-tx cost (Phase 4). **Phase B** (user verification) is out of scope entirely.

## 9. Determinism

All M1–M8 figures are deterministic (cost model, not wall-clock), captured via
**G7 exact-match** `aiken check -e -m <exact test names> --seed 42`, reproduced
byte-identically (md5 ×3 for the crypto benchmarks). **M8** re-ran M1–M7 live and
confirmed every memory figure matches its report (Δ = 0). The datum CBOR (M7)
reproduced byte-identically via two independent serializers.
