# Phase 2a-2-ii-B — Header-reconstruction circuit (operation 3a)

## 1. Scope
Operation 3a (top box of Image-1): reconstruct the `BeaconBlockHeader` root from its
5 fields via the **full SSZ merkleization** (5 leaves → 8, **7 SHA-256** — the
complete tree, not a branch), bind it to `attested_header_root`, and **extract
`state_root`** (field 3) — the clean in-circuit value op-3b consumes. Method:
compile-only count (×2) + a **two-binding** functional Setup→Prove→Verify against an
authoritative Fulu vector.

## 2. Setup
- gnark **v0.13.0**, native field **`ecc.BLS12_381.ScalarField()`**. `sha2` + `uints`,
  plus shared in-circuit helpers `circuits/common/ssztree.go`
  (`encodeUint64ToSszLeaf`, `sszMerkleizer`, `sszZeroChunk`).
- `slot` + `proposer_index` taken as **numbers**, encoded in-circuit to their LE
  32-byte SSZ leaves (`encodeUint64ToSszLeaf`, the op-4-proven technique;
  `ToBinary(64)` range-checks < 2⁶⁴). `parent/state/body_root` are `[32]uints.U8`.
- **Full tree (7 SHA-256)**, structure identical to the validated
  `offchain/ssz.HashTreeRoot`. Correctness-first: all 7 hashes computed (no
  zero-subtree hardcoding — a separate later optimization).
- `ExtractedStateRoot` is **PUBLIC** here (standalone) for the test; in the full
  regular circuit it is an **INTERNAL wire** feeding op-3b (not public) — same
  isolated-op convention as op-4.

## 3. Functional correctness — PASS (two bindings, decisive)
Self-anchored (`ssz.HashTreeRoot == roots.yaml root`), then full Setup→Prove→Verify
over BLS12-381 → **PASS** (504,292 constraints). The Verify passing means **both**:
- **(a)** reconstructedRoot == authoritative `attested_header_root` =
  `0xa2672769…48a84800` ✓
- **(b)** `ExtractedStateRoot` == the vector's `state_root` =
  `0x77134de1…c044d328` ✓

This confirms the full-tree reconstruction **and** the `state_root` extraction
against an official vector — not our own reference. Proof randomized (expected);
counts deterministic.

## 4. Measured constraints (×2-stable)
**op-3a (full reconstruction, 7 SHA-256) = 504,292** (compile ×2 == functional-test
count).

**Decomposition** (vs op-4's measured references — 53,672/node-hash, 131,380
intercept, 569/leaf; single fixed circuit, no regression):
- 7 node-hashes × 53,672 = 375,704; + 131,380 intercept + 2×569 leaf-encoding ⇒
  expected ≈ 508,222.
- **Implied per-node-hash = (504,292 − 131,380 − 2×569) / 7 = 53,111 (≈ 99% of op-4's
  53,672).**

The ~1% gap is expected: op-3a's 7 hashes are **heterogeneous** in input composition
— some operands are constant zero chunks (`H(0,0)`, `H(body,0)`), slightly cheaper
than op-4's all-variable `digest‖sibling` hashes — and the borrowed intercept/leaf
constants are op-4's (op-3a has 2 leaf-encodings + 2 32-byte asserts vs op-4's 1+1).
So the *average* per-hash lands a touch below 53,672. **Per-node-hash confirmed
~53K, consistent with op-4.** op-3a standalone ≈ 504,292 = ~7 node-hashes + ~131K
shared intercept + 2 leaf encodings.

## 5. Notes & running op-3 picture
- `ExtractedStateRoot`: public in this standalone op (for the test's binding check);
  an **internal wire to op-3b** in the full circuit.
- Correctness-first: `H(0,0)` and `H(body,0)` computed live (no zero-subtree
  hardcoding — a separate later optimization could shave the all-constant nodes).
- op-4 (`slotbind.go`) left **untouched**; retrofitting it onto `ssztree.go` is a
  clean later gated refactor (op-4 functional test + 292,396 count as the gate).
- **op-3 progress**: op-3a (header reconstruction, **504,292**) measured here;
  **op-3b** — the finality branch at gindex **169**, with **mixed** sibling L/R sides
  `[R,L,L,R,L,R,L]` (7 steps, proving `finalized_header_root` ∈ the finalized state
  via `state_root`) — is **NEXT**. op-3 (the full finality path) is complete only
  after **both**.

Raw → `benchmarks/raw/phase-2-circuit/op3a-headerreconstruct.log`.
