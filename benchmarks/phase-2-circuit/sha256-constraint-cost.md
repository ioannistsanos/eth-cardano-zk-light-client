# Phase 2a-2-i — In-circuit SHA-256 per-compression-block R1CS cost

## 1. Scope
Empirical R1CS constraint cost per **SHA-256 compression block** in-circuit — the
basis of the real circuit's operations 3 & 4 (SSZ Merkle proofs: finality branch +
slot binding). Confirms/refutes the thesis §4 estimate of **~30K constraints per
SHA-256 block** (refs [9][33]). Method: compile-only constraint counts
(`frontend.Compile` → `GetNbConstraints`) over 6 input sizes + linear regression on
block count. NOT a proving benchmark (except the one functional check, §6).

## 2. Setup
- gnark **v0.13.0**, go1.23.6, `GOTOOLCHAIN=local`.
- Gadget: `std/hash/sha2` (`sha2.New(api)` → `Write([]uints.U8)` → `Sum()`) +
  `std/math/uints` (`uints.New[uints.U32]`, `ByteAssertEq`). Template: `sha2_test.go`.
- **Native compile field: `ecc.BLS12_381.ScalarField()`** (matches the real
  Groth16/BLS12-381 circuit), NOT BN254.
- **Per-COMPRESSION-BLOCK** design: input lengths 32/96/160/224/288/608 bytes →
  **1/2/3/4/5/10 blocks** via `blocks(L)=⌈(L+9)/64⌉` (the +9 = mandatory `0x80` byte
  + 8-byte length). All inputs are secret witnesses (no constant-folding); values
  irrelevant to the count (compile-only, no witness). The digest is **consumed**
  (`ByteAssertEq` vs a 32-byte `Expected`) so the compression constraints can't be
  dead-code-eliminated — a constant 32-byte overhead that folds into the intercept.
- Each count compiled **×2** (deterministic; identical or HALT). Box: 7.7 GiB RAM.

## 3. Raw table (each count ×2-stable)
| bytes | blocks | constraints |
|---:|---:|---:|
| 32 | 1 | 158,438 |
| 96 | 2 | 186,065 |
| 160 | 3 | 213,693 |
| 224 | 4 | 241,321 |
| 288 | 5 | 268,948 |
| 608 | 10 | 407,085 |

Consecutive 1-block steps are 27,627–27,628 apart (perfectly uniform). Raw output:
`benchmarks/raw/phase-2-circuit/sha256-measure.log`.

## 4. Regression (constraints = intercept + slope·blocks)
| slope /block | intercept | R² |
|---:|---:|---:|
| **27,627.46** | 130,810.57 | **1.000000** |

Perfectly linear (R² = 1.000000). The **intercept (~130,811)** is the fixed
`uints`/lookup-table + range-check setup (+ the 32-byte `Expected` assertion),
**shared once** per circuit regardless of block count — it does NOT scale with the
number of SHA-256 calls. The slope is **tens of K, not near-zero → liveness
confirmed** (a dead-code-eliminated digest would give ~0).

## 5. Comparison — CONFIRM (with a padding correction)
- **vs thesis §4 ~30K/block: CONFIRM.** Measured **27,627/block** = ~8% below 30K —
  same order, unlike the G1-add ~10× refute (D7). In-circuit SHA-256 is
  bit-operation-heavy; gnark's lookup-assisted `uints` does **not** make it ~10×
  cheaper.
- **64-byte Merkle node = 2 compression blocks** (padding spills into a 2nd block).
  Direct cross-check: the functional circuit (§6) compiled a 64-byte input at
  **185,476** constraints; the regression predicts the canonical 2-block point
  (96 B) at 130,811 + 2·27,627 = **186,065** (exact match to the measured 96-B row).
  C(64) is 589 less than C(96) — 32 fewer input bytes × ~18/byte — so the
  per-input-byte term is ~0.3% of a node: **the per-block model is valid**.
- **Per-64-byte-node marginal = 2 × slope = 55,255** (+ the one shared intercept).
- **Ops 3 & 4 — two interpretations** (the padding gotcha):

  | op | thesis-as-written | block-corrected (measured) | ratio |
  |---|---|---|---|
  | op3 finality (14 node-hashes) | ~410,000 (≈14×30K) | **28 blocks × 27,627 = 773,569** | **1.89×** |
  | op4 slot (3 node-hashes) | ~87,000 (≈3×30K) | **6 blocks × 27,627 = 165,765** | **1.91×** |

  The thesis's **per-block ~30K is confirmed**; the ~1.9× gap is purely a
  **block-COUNT** error — it counts each 64-byte node-hash as **1** block, but
  padding makes it **2**. Combined, ops 3+4 = one shared intercept + 34 blocks =
  130,811 + 34·27,627 = **~1,070,129 (~1.07M)**.

## 6. Functional correctness
In-circuit SHA-256 of a known 64-byte message asserted equal to
`crypto/sha256.Sum256`, full Groth16 Setup→Prove→Verify over BLS12-381 → **PASS**
(185,476 constraints, 2 blocks; Setup+Prove ~56 s for the 185K-constraint circuit).
The proof is randomized (not byte-identical run-to-run, expected, not asserted);
only Verify is asserted. Constraint counts (§3) are deterministic.

## 7. D7-hypothesis impact — REVISED full-circuit projection (quantitative)
Combining (a) the measured per-block **27,627**, (b) the **×2-blocks-per-node**
padding correction, and (c) the 2a-1 G1-add result (op-1 = **331K–642K**):

| op | thesis §2.1.3 | revised (measured / derived) | status |
|---|---|---|---|
| 1 — Σ 512 unconditional G1 adds | 5–10M | **331K** (Add) – **642K** (AddUnified) | measured (2a-1) |
| 2 — Σ 512 conditional G1 adds + selects | 5–15M | ~0.4–0.8M (op-1-like + per-bit Select) | **NOT yet measured (est.)** |
| 3 — finality Merkle (28 blocks) | ~410K | **~773K** | measured (2a-2-i) |
| 4 — slot binding (6 blocks) | ~87K | **~166K** | measured (2a-2-i) |
| SHA-256 shared intercept (once) | — | **~131K** | measured (2a-2-i) |
| 5 — participation count | ~500 | <1K | thesis (tiny) |
| **TOTAL (regular, ops 1–5)** | **10–26M** | **~1.8–2.5M** | **~5–13× smaller** |

**Revised regular-circuit projection ≈ ~2M** (vs thesis 10–26M) — confirms D7's
order-of-magnitude **~1–3M** direction.

**Is SHA-256 now proportionally dominant? — YES, it became co-dominant/leading.**
- SHA-256 ops 3+4 (incl. shared intercept) ≈ **~1.07M**.
- G1-add ops 1+2 ≈ **~0.7–1.4M**.
- These are now the **same order**; the **single largest operation is op-3
  (finality Merkle, ~773K)** — a SHA-256 op.
- In the thesis, G1 ops were ~95–98% of the circuit and SHA ops ~2–5%. **In the
  revised picture they are roughly co-equal (~40–50% each).** SHA-256 did not
  shrink (CONFIRMED ~30K/block) while G1-add dropped ~10× (D7) — so SHA-256 rose
  from negligible to **proportionally co-dominant**, exactly the dynamic D7 flagged
  as pending. *(op-2 is still unmeasured; its measurement could tilt the G1/SHA
  balance — recorded as the remaining open item.)*

*Design-before-observation: these are the numbers as measured; the ~2M total and
the co-dominance verdict replace D7's "under test" projection for ops 3 & 4.*

## 8. Notes
- **Intercept is shared, not per-call.** A circuit with K SHA-256 blocks costs
  ~131K + K·27,627 — the ~131K `uints` lookup-table setup is paid **once**. So
  per-op estimates that add a fresh intercept per node-hash would over-count badly;
  ops 3+4 share one intercept.
- **Padding model caveat.** The slope is measured on canonical 32+64k inputs (≈64
  input bytes per block); a bare 64-byte node carries fewer input bytes than the
  96-byte canonical 2-block point, so `2×slope` over-counts a node by ~589 (~0.3%,
  the per-input-byte term) — negligible since SHA-256 is Permute-dominated.
- `blocks(L)=⌈(L+9)/64⌉`: 32 B→1, 64 B→**2**, ≤55 B→1, 56–119 B→2. The 64-byte
  node = 2 blocks is the crux of the ops-3/4 correction.
- Native field = BLS12-381 scalar field (matches the real Groth16/BLS12-381 circuit).
