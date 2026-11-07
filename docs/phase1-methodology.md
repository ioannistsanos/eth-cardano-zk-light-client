# Phase 1 — M1: Groth16 Verify Sequence Cost Measurement

## 1. Research Question

What is the actual reported CPU step cost of a Plutus V3 script that
performs the cryptographic core of Groth16 verification (3 × millerLoop
+ 2 × mulMlResult + 1 × finalVerify), and how does it compare with the
theoretical prediction `Σ(individual builtin costs) = 1,100,216,609`
CPU steps?

## 2. Theoretical Baseline

From `builtinCostModelC.json` [40] and Table 2 of thesis §3.2.2:

| Builtin call | Cost (CPU steps) |
|---|---|
| millerLoop #1 | 254,006,273 |
| millerLoop #2 | 254,006,273 |
| millerLoop #3 | 254,006,273 |
| mulMlResult #1 | 2,174,038 |
| mulMlResult #2 | 2,174,038 |
| finalVerify #1 | 333,849,714 |
| **Σ (sum-of-parts)** | **1,100,216,609** |

## 3. Hypothesis

- **H₀ (null)**: Reported cost = Σ = 1,100,216,609.
  The Plutus interpreter charges exactly the sum of individual builtin costs.
- **H₁ (alternative)**: Reported cost > 1,100,216,609.
  The difference Δ = (Reported − Σ) represents the CEK machine overhead +
  script wrapping for the Groth16 verification sequence.

**Scientific payoff**:
- If H₀ holds: the thesis Table 2 cryptographic portion is empirically
  verified for the Groth16 part.
- If H₁ holds: Δ is the **measured CEK overhead** for one Groth16 verify
  sequence, refining the "~500M script overhead" placeholder in the thesis.

## 4. Operationalization

### 4.1 What is "reported cost"

When `aiken check` or `aiken test --bench` runs an Aiken test, the tool
evaluates the script on the Plutus Core CEK machine (the same one that
runs in cardano-node) and reports:

- `cpu`: total CPU steps consumed (the measured quantity)
- `mem`: total memory units consumed (recorded in parallel as M8)

This `cpu` value is what the ledger would charge if the same execution
occurred on-chain.

### 4.2 Mock inputs

The script needs **valid BLS12-381 elements** so that `finalVerify` does
not error on subgroup membership checks.

**Approach (Option A — simple)**:
- Use the generator points G₁, G₂ (well-known BLS12-381 constants)
- Construct non-identity multiples (e.g., scalar multiples of the generators)
  to avoid potential identity-element shortcuts in the cost model

Note: M1 is a **cost measurement**, not a soundness validation. The
inputs only need to be valid enough to traverse all the builtin calls.

### 4.3 Script structure

The test validator executes exactly the Groth16 verification core
(excluding MSM — that is measured separately in M3/M4):

```
groth16_verify_core(A, B, vk_x, gamma, C, delta, e_alpha_beta):
    ml1 = millerLoop(A, B)
    ml2 = millerLoop(vk_x, neg(gamma))
    ml3 = millerLoop(C, neg(delta))
    combined = mulMlResult(ml1, ml2)
    combined2 = mulMlResult(combined, ml3)
    return finalVerify(combined2, e_alpha_beta)
```

**Important boundary**: M1 measures ONLY the 6 builtin calls above. The
MSM (`Σ public_inputs[i] · IC[i+1] + IC[0]`) is measured separately as
M3 (regular, 6 inputs) and M4 (boundary, 7 inputs).

### 4.4 Aiken implementation skeleton

```aiken
use aiken/builtin

test bench_m1_groth16_verify_sequence() {
  // Mock valid G1/G2 elements (constructed from generator multiples)
  let g1_a   = ... // valid G1 point, not identity
  let g2_b   = ... // valid G2 point, not identity
  let g1_vkx = ... // valid G1 point
  let g2_neg_gamma = ... // valid G2 point (precomputed negation of gamma)
  let g1_c   = ... // valid G1 point
  let g2_neg_delta = ... // valid G2 point (precomputed negation of delta)
  let e_alpha_beta = ... // precomputed millerLoop result

  // === The measurement target: exactly these 6 calls ===
  let ml1 = builtin.bls12_381_miller_loop(g1_a, g2_b)
  let ml2 = builtin.bls12_381_miller_loop(g1_vkx, g2_neg_gamma)
  let ml3 = builtin.bls12_381_miller_loop(g1_c, g2_neg_delta)

  let combined  = builtin.bls12_381_mul_miller_loop_result(ml1, ml2)
  let combined2 = builtin.bls12_381_mul_miller_loop_result(combined, ml3)

  builtin.bls12_381_final_verify(combined2, e_alpha_beta)
}
```

Aiken syntax to be confirmed against v1.1.22 docs at implementation time.

## 5. Replication Protocol

- The reported cost is **deterministic** (it comes from the cost model,
  not from wall-clock measurement). Repeated execution returns the same
  value.
- Run 3 iterations to confirm tooling reproducibility (all three should
  yield identical cpu/mem values).
- Report mean (which equals each trial's value for deterministic outputs).

### 5.1 Determinism protocol

`aiken check` emits a JSON object whose top-level `seed` field is **random per
run** (it seeds the property-test PRNG). The per-test `execution_units`
(`cpu`/`mem`) are deterministic, but the raw JSON is therefore **not**
byte-identical across runs unless the seed is pinned.

Protocol for reproducible captures:

- Always pass a fixed seed: `aiken check -m <match> --seed 42` (any fixed
  integer works; 42 is the project convention).
- Capture all 3 iterations and confirm they are **byte-identical** (e.g.
  `md5sum`). With `--seed` pinned, the full JSON — including the `seed`
  field — is identical, so a single `diff`/`md5sum` check covers everything.
- M-measurements here have no property tests, so the seed never changes any
  measured quantity; pinning it is purely for byte-level reproducibility.

## 6. Reporting Format

Save to `benchmarks/phase-1-cost-model/M1-groth16-sequence.md`:

```markdown
# M1 — Groth16 Verify Sequence Cost

## Configuration
- Aiken version: v1.1.22+39d6b04
- Plutus version: V3 (Conway)
- Cost model: builtinCostModelC.json [40] (commit hash: ...)
- Hardware: WSL2 Ubuntu 24.04, <CPU model>, <RAM>

## Hypothesis
- H₀: Reported cost = Σ(individual builtin costs) = 1,100,216,609
- H₁: Reported cost > 1,100,216,609 (CEK overhead present)

## Measured

| Trial | Reported CPU | Reported Memory |
|---|---|---|
| 1 | <X> | <Y> |
| 2 | <X> | <Y> |
| 3 | <X> | <Y> |
| Mean | <X> | <Y> |

## Theoretical (sum-of-parts)
- 3 × millerLoop:     762,018,819
- 2 × mulMlResult:      4,348,076
- 1 × finalVerify:    333,849,714
- TOTAL:            1,100,216,609

## Delta
Δ = Measured − Theoretical = <X − 1,100,216,609>

## Implication
[Choose one based on result]
- If |Δ| / Σ < 1%: cost model accurately represents the sum-of-parts;
  the Groth16 cryptographic portion of Phase A Table 2 is verified
  empirically.
- If Δ > 0 significantly: a CEK overhead of <Δ> CPU steps is present per
  Groth16 verify sequence, refining the thesis "~500M script overhead"
  placeholder for this portion.

## Raw output
See benchmarks/raw/phase-1-cost-model/M1-raw.log
```

Also save raw Aiken output to:
`benchmarks/raw/phase-1-cost-model/M1-raw.log`

## 7. Limitations of M1

M1 does NOT measure:
1. Datum deserialization (CBOR decoding of the 8-field datum)
2. Redeemer parsing
3. Anchor field invariance checks (8 field comparisons)
4. Transaction body construction overhead at cardano-node
5. MSM cost (measured separately in M3/M4)

All these are captured in Phase 4 (real testnet transaction). M1 is an
**isolated cryptographic measurement** — simple, controlled, reproducible.

## 8. Threats to Validity

| Threat | Mitigation |
|---|---|
| Mock inputs trigger cost-model shortcuts | Use non-identity generator multiples |
| Aiken version drift from production cardano-node | Documented in Configuration; refetch builtinCostModelC.json |
| Cost model file mismatch | Hash the builtinCostModelC.json used; include hash in report |
| Plutus V3 protocol changes before thesis submission | Re-run if any protocol parameter update occurs before submission |
| Control test contains builtins absent from core (contaminates `core − control`) | UPLC-verify (`aiken uplc decode`) that core and control differ by **only** the measured builtins; a *negative* Δ is a red flag (overhead cannot be negative) |
| Dead-code elimination drops a "forcing" binding | Bind to a referenced name, not `let _x = …`; confirm the builtin survives in the decoded UPLC / in the measured cost |

### 8.1 Tooling discipline

Aiken v1.1.22 has several non-obvious behaviours that can silently corrupt a
measurement (wrong builtin identifiers, dead-code elimination of unused
`uncompress` bindings, non-TTY error swallowing, per-run random `seed`).
These were encountered and resolved during M1 and are documented in
`docs/aiken-gotchas.md`. Consult that file before adding a new
measurement (M2–M8) or debugging an unexpected `aiken check` result.

## 9. Mapping to Thesis Outcomes

Upon completion of M1:

- If **|Δ| / Σ < 1%**: thesis statement →
  *"Empirical measurement confirms the sum-of-parts cost model for the
  Groth16 verification sequence: measured <X> CPU steps vs theoretical
  1,100,216,609 CPU steps (delta < 1%)."*

- If **Δ > 0 significantly**: thesis statement →
  *"Empirical measurement reveals <Δ> additional CPU steps of CEK machine
  overhead in the Groth16 verification sequence, refining the thesis's
  preliminary '~500M script overhead' estimate."*

Both outcomes are publishable contributions. This is the value of proper
measurement design.

## 10. Relation to M2-M8

M1 establishes the template. Subsequent measurements follow the same
pattern with different sequences:

- M2: BLS verify sequence (hashToGroup + 2 × millerLoop + mulMlResult +
  finalVerify)
- M3: MSM with 6 inputs (6 × G1_scalarMul + 6 × G1_add) — regular Phase A
- M4: MSM with 7 inputs (7 × G1_scalarMul + 7 × G1_add) — boundary Phase A
- M5: M1 + M2 + M3 combined → synthetic Phase A regular approximation
- M6: M1 + M2 + M4 combined → synthetic Phase A boundary approximation
- M7: Datum CBOR encoding size (separate tooling, e.g., aiken blueprint)
- M8: Memory units recorded in parallel with M1-M6 (free byproduct)

## References

- [40] `builtinCostModelC.json` in IntersectMBO/plutus repository
- [12] Groth, J. (2016). "On the Size of Pairing-Based Non-Interactive Arguments"
- [13] CIP-0381 — Plutus support for pairings over BLS12-381
- Thesis §3.2.1, §3.2.2 — On-chain verification budget analysis
