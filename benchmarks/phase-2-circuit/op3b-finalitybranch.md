# Phase 2a-2-ii-C — Finality-branch Merkle circuit (operation 3b)

## 1. Scope
Operation 3b (the second half of op-3): prove `finalized_header_root` is the finalized
checkpoint root of the **attested** state — a **fixed 7-step** SSZ Merkle branch walk at
**FINALIZED_ROOT_GINDEX_ELECTRA = 169** (`0b10101001`, depth 7) from the
`finalized_header_root` leaf up to `BeaconBlockHeader.state_root`, with **mixed** sibling
sides **[R,L,L,R,L,R,L]** (`bit i = (169>>i)&1`; contrast op-4's all-left gindex-8 path).
Method: compile-only count (×2) + a full Groth16 functional check + a 3-negative mutation
suite — **all on a real Electra LightClientUpdate** — plus a real-data anchor that is the
repo's **first empirical confirmation of the 7-element Electra finality branch**.

## 2. Setup
- gnark **v0.13.0**, go1.23.6, native field **`ecc.BLS12_381.ScalarField()`**; `sha2` +
  `uints` via the shared `circuits/common/ssztree.go` `sszMerkleizer` (the same node-hash
  as op-3a/op-6; op-4 predates `ssztree.go`).
- **Leaf = `FinalizedHeaderRoot`** `[32]uints.U8` (public) — already a 32-byte root, so
  op-3b has **no in-circuit leaf encoding**: purely 7 node-hashes. **Target = `StateRoot`**
  (public in the standalone op; in the full circuit it is **op-3a's extracted internal
  wire** — the same authenticated `state_root` the op-6 walk terminates on).
  `FinalityBranch [7][32]` is the private witness. The fixed depth (the `[7]` array)
  forecloses variable-depth Merkle games structurally.
- Real witness: `testdata/lightclientupdate/electra_period_1600.json`, **extended from the
  same re-fetched update** (same-update verified 4 ways: `attested_state_root`, all 6
  committee siblings, `aggregate_pubkey`, all 512 pubkeys byte-identical) with
  `finalized_header` (5 beacon fields) + `finality_branch` (7 siblings).

## 3. Functional correctness — PASS (real instance, decisive)
- **Anchor (off-circuit, non-circular)**: `ssz.HashTreeRoot(finalized_header)` =
  `0x201a1d12…878599` → `Gindex169Walk` fold == the **real** attested `state_root`
  `0xf93876…888a6a`. Confirmed by **two independent implementations** (Python stdlib at
  fixture-extension time + Go `offchain/ssz`); Ethereum computed the target, so a wrong
  gindex/fold/depth cannot reach it.
- **Structural cross-check**: `finality_branch[0]` == the `Checkpoint.epoch` SSZ chunk
  `LE64(409600)‖24×00` **byte-for-byte** (gindex 169 = `Checkpoint.root` is the RIGHT
  child; its sibling 168 is the epoch leaf; epoch = finalized slot 13107200 / 32) — the
  gindex position confirmed semantically, not just cryptographically. The finalized slot
  is an exact epoch boundary, as a checkpoint must be.
- **Positive**: solver PASS + full **Groth16 Setup→Prove→Verify PASS** (507,507
  constraints) on the real instance.
- **Negatives** — each rejected at the **terminal** `ByteAssertEq(StateRoot)`
  (`op3b.go:61`; byte 249 = `0xf9`, the real state_root's first byte, vs the divergent
  fold). With valid-byte tampering the terminal equality is the only failable assertion,
  so the rejections are attributable:

  | mutation | result |
  |---|---|
  | tampered leaf (`finalized_header_root[0] ^= 1`) | REJECT — 249 vs 206 |
  | tampered sibling (`finality_branch[3][0] ^= 1`) | REJECT — 249 vs 83 |
  | wrong fold (step-0 side swapped) | REJECT — 249 vs 9 |

  The wrong-fold mutant is **derived from the production constant** (array value-copy +
  flip), so it remains a genuine mutant under any future edit of the constant.

## 4. Measured constraints (×2-stable; 3 independent invocations identical)
**op-3b (7-step branch walk) = 507,507.**

Decomposition (op-4 references: 53,672/node-hash, 131,380 intercept; **no leaf encoding**):
- 7 × 53,672 + 131,380 = **507,084** expected → measured **+0.08%**.
- **Marginal** (assembled circuit, intercept shared) = 507,507 − 131,380 = **376,127**.
- Implied per-node-hash = 376,127 / 7 = **53,732** — ~0.1% **above** op-4's 53,672:
  op-3b's step-0 leaf is 32 fully-variable bytes, vs op-4's leaf carrying 24 constant
  zero bytes (and op-3a's zero-chunk operands averaging 53,111). Per-node-hash ~53K
  confirmed for the third time.

## 5. Fork finding — first empirical 7-element Electra finality branch
Pre-Electra the finality gindex was **105** (depth **6**); Electra moved it to **169**
(depth **7**) — the depth **changed**, unlike gindices 86/87/8 (unchanged
Electra→Fulu). An earlier check against live data covered only the **committee** branch; this work
empirically pins the **finality** branch: the real update returns **7** siblings (vs 6 for
the committee branch **in the same update** — the per-branch depth contrast observed
live), and the [R,L,L,R,L,R,L] fold reaches the real state_root. A lagging API serving a
pre-Electra 6-element branch is caught by the arity HALT-gate (`loadFinalityInstance`).

## 6. Notes & op-3 complete
- **op-3 fully measured**: op-3a **504,292** + op-3b **507,507** standalone; assembled
  marginal = 372,912 + 376,127 = **749,039 ≈ ~749K** + one shared ~131K intercept —
  **confirms D8's block-corrected ~773K to ~3%** (the input-byte effect, as op-4). The
  thesis ~410K under-counted blocks ×2 (D14).
- **Assembly obligation**: in the full circuit, op-3b's `StateRoot` must be **wired from
  op-3a's extracted state_root** (the SC-2-style single-source discipline op-6 verified) —
  never a fresh witness.
- **Milestone**: with op-3b, **all regular+boundary circuit operations now exist as
  measured gadgets**; remaining work is **assembly** (`sync_committee/`, `boundary/`) +
  **bootstrap** (canonicity establishment, SEC-01 §8d).
- Correctness-first: all 7 hashes computed live (no shortcuts exist on this path anyway —
  every operand is variable).

Raw → `benchmarks/raw/phase-2-circuit/op3b-finalitybranch.log` (recorded 2026-06-03). Code and
tests: `prover/circuits/common/op3b.go`, `op3b_test.go`; fixture:
`prover/circuits/common/testdata/lightclientupdate/electra_period_1600.json`.
