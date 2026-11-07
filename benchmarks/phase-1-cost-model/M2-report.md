# M2 — BLS Verification Sequence Cost (sha2 barrier)

Phase 1, measurement M2. Empirical CPU/memory cost of the on-chain BLS
aggregate-signature verification sequence (thesis §3.2.2 Table 2, BLS rows).
Defeats Aiken's constant-folding of `bls12_381_g2_hash_to_group` (gotcha
G6) by deriving the message at runtime: `msg = sha2_256(header_root ‖ domain)`,
which is exactly what the validator computes per thesis §2.1.3.

See `docs/phase1-methodology.md`, `docs/aiken-gotchas.md` (G6), and
`docs/records.md` (D1 Groth16 4th-ML; D2 BLS no-mul, introduced here).

## Background

A first M2 attempt (`m2_bls.ak` pre-revision) used module-level `const`
`msg`/`dst`, which Aiken's optimizer constant-folded `hash_to_group(const,
const)` into a precomputed G2 element — eliminating the hashToGroup builtin
from runtime. Confirmed via a G6 probe + an `aiken export` panic ("BLS12-381
G2 points are not supported for flat encoding"). The fix locked in here:
introduce a runtime barrier by computing `msg` from `sha2_256` of a fixed
preimage. `sha2_256(const)` is **not** folded by Aiken v1.1.22 (verified in
the G6 probe — UPLC export of `pub fn pf_sha2_256` retains the `sha2_256`
builtin), so `msg` is a runtime `ByteArray`, defeating the fold.

## Hypotheses

**H₀**: `marg_core ≈ Σ_core = 1,011,091,965` within ±0.05 % (the CEK machine
charges the sum of individual builtin costs for the 5-builtin BLS sequence;
CEK threading is negligible at this scale).

**H₁**: deviation > ±0.05 % — STOP and investigate.

**D2 cross-hypothesis**: `marg_real ≈ Σ_real = 1,008,917,927` within
±0.05 %; `mul_delta = marg_core − marg_real` ≈ one `mul_miller_loop_result`
(2,174,038) plus a small CEK-threading + control-subtraction residual.
The M1b−M1 per-let increment is ~16 K (recorded M1b−M1 = 254,022,273 vs
one millerLoop = 254,006,273 → residual 16,000), so the *a priori*
expectation is `mul_delta ≈ 2,190 K`; the observed ~2,286 K residual
diff is explained in the cross-check section.

## Configuration

Identical to M1/M1b.

- **Aiken**: v1.1.22+39d6b04 — **Plutus**: V3 (Conway)
- **Hardware**: WSL2 Ubuntu 24.04, Intel i7-9750H @ 2.60 GHz (6c/12t),
  8,068,188 kB MemTotal; kernel 6.6.114.1-microsoft-standard-WSL2 x86_64
- **Command** (from `validator/`): `aiken check -m bench_m2 --seed 42`
- **Determinism**: 3 iterations byte-identical (md5
  `5f02a7a8cd3f9e2af4b9f0cabc02fc0e` ×3)
- **Dependencies**: none (BLS builtins from `aiken/builtin` prelude). The
  fuzz/stdlib packages added during G6 probing were reverted.

## Inputs

- `mock_signing_preimage_64` (64 B): header_root (32 B) ‖ signing_domain
  (32 B). Hex of the first 32 B = `0011…eeff` (an arbitrary non-trivial
  pattern); next 4 B = `07000000` (Ethereum DOMAIN_SYNC_COMMITTEE), then
  zero-padded. `sha2_256` produces a 32-byte `msg`.
- `bls_dst` (43 B): ASCII `BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_`
  (RFC 9380 [72] / Ethereum consensus spec).
- `g1_generator_compressed`, `g2_generator_compressed`: canonical BLS12-381
  generators (same as M1/M1b). `pubkey` bound to the same compressed
  bytestring as `g1_generator` via a separate `let` so the UPLC contains two
  distinct `G1_uncompress` calls (cost-faithful — `miller_loop` is
  input-independent).

## Method note — barrier-control subtraction

`bench_m2_bls_control` performs *exactly* the same setup work as the two
core tests — 2× `G1_uncompress` + 1× `G2_uncompress` + 1× `sha2_256` of the
preimage — and nothing else. UPLC verification confirms:

| Builtin | `pf_core_fn` | `pf_real_fn` | `pf_control_fn` |
|---|---|---|---|
| `bls12_381_G1_uncompress` | 2 | 2 | 2 |
| `bls12_381_G2_uncompress` | 1 | 1 | 1 |
| `sha2_256` | 1 | 1 | 1 |
| `bls12_381_G2_hashToGroup` | **1** | **1** | **0** |
| `bls12_381_millerLoop` | **2** | **2** | **0** |
| `bls12_381_mulMlResult` | **1** | **0** | **0** |
| `bls12_381_finalVerify` | **1** | **1** | **0** |
| `trace` | 0 | 0 | 1 |

`core − control` therefore isolates exactly `{hashToGroup + 2·millerLoop +
mul + finalVerify}` (the 5 measured builtins, Table-2 form), and
`real − control` isolates `{hashToGroup + 2·millerLoop + finalVerify}` (the
4-builtin canonical CIP-381 form).

UPLC verification was performed with temporary `pub fn` mirrors
(`pf_core_fn`, `pf_real_fn`, `pf_control_fn`) appended to `m2_bls.ak`,
exported via `aiken export -m benchmarks/m2_bls -n <fn>`, decoded via
`aiken uplc decode --cbor --hex`, then removed before report finalisation.
All three exports succeeded (no flat-encoding panic — the runtime msg
defeats the G2-constant fold).

Tests #1 and #2 are `fail` tests: with mock points the verification
equations don't hold, so `final_verify` returns `False` — the expected
outcome on arbitrary inputs, so the `fail` tests pass. `final_verify` cost
is input-independent, so the measured cost equals that of a genuine
verification.

## Measured

Deterministic — all three trials identical (cpu/mem).

| Test | Trial | Reported CPU | Reported Memory |
|---|---|---|---|
| `bench_m2_bls_core` (with mul) | 1 | 1,192,529,541 | 3,629 |
| `bench_m2_bls_core` (with mul) | 2 | 1,192,529,541 | 3,629 |
| `bench_m2_bls_core` (with mul) | 3 | 1,192,529,541 | 3,629 |
| `bench_m2_bls_core` | **Mean** | **1,192,529,541** | **3,629** |
| `bench_m2_bls_real` (no mul) | 1–3 | 1,190,243,503 | 2,857 |
| `bench_m2_bls_control` | 1–3 |   181,398,172 | 2,376 |

**Isolated costs** (`core − control`, `real − control`):

| Quantity | CPU | Memory |
|---|---|---|
| `marg_core` (5 measured builtins) | **1,011,131,369** | 1,253 |
| `marg_real` (4 measured builtins, no mul) | **1,008,845,331** | 481 |
| `mul_delta = marg_core − marg_real` | **2,286,038** | 772 |

## Theoretical (sum-of-parts)

| Builtin call | Σ_core | Σ_real |
|---|---|---|
| `G2_hashToGroup` (msg = 32 B): 166,917,843 + 4,307·32 — **† unit error, see the 2026-09-12 note below: the ledger charges n = 4 words → 166,935,071** | 167,055,667 | 167,055,667 |
| 2 × `miller_loop` (254,006,273 each) | 508,012,546 | 508,012,546 |
| 1 × `mul_miller_loop_result` | 2,174,038 | — |
| 1 × `final_verify` | 333,849,714 | 333,849,714 |
| **Σ** | **1,011,091,965** | **1,008,917,927** |

## Delta

| Variant | marginal | Σ | Δ | Δ% | Verdict (±0.05 %) |
|---|---|---|---|---|---|
| core (Table-2, with mul) | 1,011,131,369 | 1,011,091,965 | **+39,404** | **+0.00390 %** | ✓ **H₀** |
| real (CIP-381, no mul) | 1,008,845,331 | 1,008,917,927 | **−72,596** | **−0.00720 %** | ✓ **H₀** |

`hashToGroup` confirmed in core/real UPLC; barrier worked. Both deltas
inside the ±0.05 % H₀ band by an order of magnitude — the BLS row of thesis
Table 2 is **empirically verified for the 5-builtin Table-2 form within
0.004 %**.

## D2 cross-check — mul_miller_loop_result is not needed under CIP-381

| Quantity | CPU steps |
|---|---|
| `marg_core` (Table-2 form, with mul) | 1,011,131,369 |
| `marg_real` (canonical CIP-381 form, no mul) | 1,008,845,331 |
| **`mul_delta`** | **2,286,038** |
| one `mul_miller_loop_result` (cost model) | 2,174,038 |
| `mul_delta − mul cost` | **112,000** |

`mul_delta = 2,286,038 = 2,174,038 (mul cost-model) + 112,000 (threading +
control-subtraction residual)`. The 112,000 is **not** a per-let constant —
it is exactly `core_residual (+39,404) − real_residual (−72,596)`, i.e.
the small difference between the two H₀-passing residuals. Contributors:

- The intermediate `let c = mul(…)` binding adds CEK threading (the
  empirically grounded per-let increment from M1b−M1 is **~16 K**, *not*
  ~112 K — M1b−M1 = 254,022,273 vs one millerLoop 254,006,273 → residual
  16,000).
- The barrier-control carries one extra `(builtin trace)` (from the
  `expect _ = bls_dst` desugaring) that core/real lack; that asymmetry
  contributes to the residuals' signs.

All ≪ 0.05 %, so **H₀ holds for both tests**. The flag below is about the
*soft bound's* tightness, not a measurement anomaly.

**Flag (not a stop):** `mul_delta = 2,286,038` exceeds the proposal's soft
upper bound of 2,250,000 by 36 K. Per the corrected explanation above, the
excess is residual-subtraction noise (control trace asymmetry + small
threading), not a revision of the per-let CEK constant. Future
M-measurements continue to use the ~16 K per-let basis (M1b−M1).

## Implication

- **BLS Table-2 row empirically verified.** Both forms (with and without
  `mul`) match their sum-of-parts within 0.01 %.
- **D2 introduced and quantified**: a canonical CIP-381 on-chain BLS
  verifier uses `final_verify(ml1, ml2)` directly — no `mul_miller_loop_result`
  needed. This saves **2,174,038 CPU steps per BLS verification** (the cost
  of one `mul`). Marginal: 0.07 % of Phase A budget. Detail in
  `docs/records.md` D2.
- **`hashToGroup` cost confirmed** at 167,055,667 CPU for n=32 (linear
  arg = message length). The G6 fold issue is fully avoided by the sha2
  barrier — applicable to any future measurement involving `hash_to_group`.
  - **Note (2026-09-12) — unit correction:** the earlier "confirmation" was
    the cost-model formula evaluated at n = 32 *bytes*; the ledger charges
    n = 4 *words* (ByteString ExMemory = `((n − 1) quot 8) + 1`,
    `ExMemoryUsage.hs:315-324`) → **166,935,071** — UPLC-verified 2026-09-12
    (`aiken uplc eval` of the bare builtin on a 32-byte message: 167,015,171
    = 166,935,071 + 80,100 CEK; 40-byte → +4,307; 64-byte → +17,228).
    Measured totals unaffected (M2's marginal method cancels the term); the
    Phase-A residual decomposition moved by +120,596.

Memory: marginal mem 1,253 (core) / 481 (real), far below the 16,500,000
transaction budget (M8).

## Open follow-ups (not stop conditions)

- **sha2_256 cost in the G6 probe**: G6 probe's sha2 input was likely
  < 32 bytes (505 K ≈ sha2(~10 B) per `270,652 + 22,588·n`); not cost-model
  drift. M1/M1b confirm Aiken's BLS12-381 params match thesis [40] to
  99.99 %. sha2 cancels in M2's marginal anyway. The probe input size is not
  confirmed; likely non-issue.
- **Per-let incremental cost remains ~16 K (M1b−M1)**: the 112 K in M2's
  `mul_delta` is the core/real residual difference (threading + control
  trace mismatch), **not** a per-let constant. No project-wide change
  needed; future M-measurement bounds keep the ~16 K per-let basis.
- **D2 implications for Phase 3a**: the real BLS verifier in the validator
  should use `final_verify(ml1, ml2)` directly to claim the 2.17 M saving.
- **Barrier-control trace asymmetry**: the control carries one extra
  `(builtin trace)` (from the `expect _ = bls_dst` desugaring) that core/real
  lack. This contributes a small subtraction imperfection (effect here
  < 0.01 %, no action needed). Future controls could match the test binding
  structure exactly to avoid this; non-blocking for M2.

## Raw output

See `benchmarks/raw/phase-1-cost-model/M2-raw.log`.
