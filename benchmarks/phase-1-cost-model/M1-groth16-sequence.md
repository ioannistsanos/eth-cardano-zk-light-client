# M1 — Groth16 Verify Sequence Cost

Phase 1, measurement M1. Empirical CPU/memory cost of the cryptographic core
of Groth16 verification (3 × `miller_loop` + 2 × `mul_miller_loop_result` +
1 × `final_verify`) on the Plutus V3 CEK machine, compared with the
theoretical sum-of-parts from `builtinCostModelC.json` [40].

See `docs/phase1-methodology.md` for the full methodology.

## Configuration

- **Aiken version**: v1.1.22+39d6b04
- **Plutus version**: V3 (Conway) — `plutus = "v3"` in `aiken.toml`
- **Cost model**: `builtinCostModelC.json` [40]; per-builtin constants as listed
  in `docs/phase1-methodology.md` (the model file is checked against a pinned
  commit of IntersectMBO/plutus in `benchmarks/cost-validation/`)
- **Hardware**: WSL2 Ubuntu 24.04, Intel(R) Core(TM) i7-9750H @ 2.60GHz
  (6 cores / 12 threads), 8,068,188 kB MemTotal
- **Kernel**: Linux 6.6.114.1-microsoft-standard-WSL2 x86_64
- **Measurement command** (run from `validator/`):
  `aiken check -m bench_m1 --seed 42`
- **Determinism**: 3 iterations produced byte-identical JSON (md5
  `5c03d8061654f851f2e541788a9bde7a` ×3). The reported cost is deterministic
  (it comes from the cost model, not wall-clock). `--seed 42` pins the
  top-level PRNG seed; M1 has no property tests, so the seed affects nothing.
- **Erratum (2026-05-29, doc hygiene — no measured value changed).** The md5
  above was captured over a **2-test** JSON (`{core, control}`) before
  `bench_m1b` was added to `m1_groth16.ak`. Because `aiken check -m` is a
  *substring* filter (gotcha **G7**), the documented `-m bench_m1` command now
  also matches `bench_m1b_groth16_realistic` and emits a 3-test JSON
  (md5 `5b6b9d4683ccfbddcc1d18ad791c5ac8`), so it no longer reproduces the hash
  above. All per-test cpu/mem reproduce to the byte. The original hash is
  recovered exactly (3× byte-identical, verified 2026-05-29) with an
  exact-match command that pins the 2-test set:
  `aiken check -e -m bench_m1_groth16_core -m bench_m1_control_setup --seed 42`
  → `5c03d8061654f851f2e541788a9bde7a`.

## Method note — control subtraction

`miller_loop` consumes *uncompressed* `G1Element`/`G2Element`, so the test
must `bls12_381_g1_uncompress` / `g2_uncompress` the hardcoded compressed
generators. Aiken does **not** constant-fold these (the control test below
costs ~128 M CPU, i.e. the two uncompress calls), so the uncompress cost is
present in the measured path.

To isolate the six pairing builtins, a control test (`bench_m1_control_setup`)
executes the **same two uncompress calls and nothing else** — no pairing
builtins and no other builtins. The isolated cost is then `core − control`.

This was verified at the UPLC level (`aiken uplc decode --cbor --hex` of
exported `pub fn` equivalents):

| Builtin | core | control |
|---|---|---|
| `bls12_381_G1_uncompress` | 1 | 1 |
| `bls12_381_G2_uncompress` | 1 | 1 |
| `bls12_381_millerLoop` | 3 | 0 |
| `bls12_381_mulMlResult` | 2 | 0 |
| `bls12_381_finalVerify` | 1 | 0 |

The **only** difference between the two compiled programs is the six measured
pairing builtins. `core − control` therefore isolates them with no over- or
under-count (it still includes the unavoidable CEK overhead of threading the
six builtins' `let` results — see Delta).

## Hypothesis

- **H₀**: Reported cost = Σ(individual builtin costs) = 1,100,216,609
  (the CEK machine charges exactly the sum of individual builtin costs).
- **H₁**: Reported cost > 1,100,216,609 (measurable CEK machine overhead for
  the Groth16 verify sequence, Δ = Reported − Σ).

Decision rule (per `docs/phase1-methodology.md` §9): `|Δ| / Σ < 1 %`
confirms the sum-of-parts model (H₀); a larger positive Δ quantifies CEK
overhead (H₁).

## Measured

Deterministic output — all three trials identical.

| Test | Trial | Reported CPU | Reported Memory |
|---|---|---|---|
| `bench_m1_groth16_core` | 1 | 1,228,471,303 | 4,315 |
| `bench_m1_groth16_core` | 2 | 1,228,471,303 | 4,315 |
| `bench_m1_groth16_core` | 3 | 1,228,471,303 | 4,315 |
| `bench_m1_groth16_core` | **Mean** | **1,228,471,303** | **4,315** |
| `bench_m1_control_setup` | 1–3 | 127,822,694 | 1,254 |

**Isolated six-builtin cost** (`core − control`):

| Quantity | CPU | Memory |
|---|---|---|
| core | 1,228,471,303 | 4,315 |
| control | 127,822,694 | 1,254 |
| **marginal (core − control)** | **1,100,648,609** | **3,061** |

## Theoretical (sum-of-parts)

| Builtin call | Cost (CPU steps) |
|---|---|
| 3 × `miller_loop` (254,006,273 each) | 762,018,819 |
| 2 × `mul_miller_loop_result` (2,174,038 each) | 4,348,076 |
| 1 × `final_verify` | 333,849,714 |
| **Σ (sum-of-parts)** | **1,100,216,609** |

## Delta

- Δ = marginal − Σ = 1,100,648,609 − 1,100,216,609 = **+432,000**
- Δ% = Δ / Σ × 100 = **+0.0393 %**
- |Δ%| < 1 % → **H₀ holds.**

The Δ is now a small **positive** value. It is the CEK machine overhead for
sequencing the six builtins: the five intermediate `let` bindings (`ml1`,
`ml2`, `ml3`, `combined`, `combined2`) and the final application, which the
control does not incur. Exact decomposition (all figures CPU steps):

```
control (uncompress ×2 + glue)              =   127,822,694
Σ (six pairing builtins, sum-of-parts)      = 1,100,216,609
control + Σ                                 = 1,228,039,303
core (measured)                             = 1,228,471,303
core − (control + Σ) = CEK threading        =       432,000
```

## Implication

The reported cost of the Groth16 verification core matches the sum-of-parts
cost model within **0.04 %** (< 1 %). **H₀ is supported**: the Plutus V3 CEK
machine charges essentially the sum of the individual builtin costs for the
3 × `miller_loop` + 2 × `mul_miller_loop_result` + 1 × `final_verify`
sequence. The residual +432,000 steps (0.04 %) is the measured CEK overhead
of threading the six builtins — negligible at this scale. The cryptographic
portion of thesis Table 2 (the Groth16 lines) is empirically verified for
these six builtins.

Consequence for the thesis's "~500 M script overhead" placeholder: that
overhead is **not** attributable to CEK overhead on the cryptographic
builtins (measured here at 0.04 % of their cost). It must originate
elsewhere — datum and redeemer deserialization, anchor-invariance checks, and
script-context construction — which Phase 4 measures directly on a real
transaction.

Memory: the isolated six-builtin sequence consumes 3,061 memory units
(core 4,315 − control 1,254), far below the 16,500,000 transaction budget (M8).

Scope note: M1 measures the **3 miller-loop** sequence as defined by the
thesis. A realistic on-chain Groth16 verifier needs a **4th** miller loop to
reconstruct `e(α,β)`, because CIP-381 has no `MlResult` serialization builtin —
see `docs/records.md` D1.

## Methodology refinement (control redesign)

The first M1 run used a control whose body was
`g1_equal(g1, g1) && g2_equal(g2, g2)`. That control contained **two
equality builtins that the core test did not**, so `core − control`
*under*-counted the pure six-pairing cost by exactly those two equality
builtins. The result was marginal = 1,098,973,530 and **Δ = −1,243,079
(−0.113 %)** — a *negative* delta, which is physically implausible if Δ is
supposed to be CEK overhead (overhead can only add cost).

That negative sign was the tell. Cross-checking, the residual
`control − (core − Σ) = 1,243,079` was numerically equal to `−Δ` — but that
identity is algebraically guaranteed (`control − (core − Σ) ≡ Σ − marginal ≡
−Δ`) and therefore proves nothing on its own. It did, however, lead to an
inspection of *what the control actually executed*, which revealed the two
stray `equal` builtins.

The redesigned control (this report) does **exactly** the core's two
uncompress calls and no other builtin (UPLC-verified, table above), so the
subtraction is clean. The delta flips to a small **positive** +432,000
(+0.039 %), consistent with the physical interpretation of CEK threading
overhead. Lessons learned recorded in `docs/aiken-gotchas.md`
(notably: an unused `let _g1 = uncompress(...)` is dead-code-eliminated,
whereas binding to a referenced name keeps the failable builtin).

## Raw output

See `benchmarks/raw/phase-1-cost-model/M1-raw.log`.
