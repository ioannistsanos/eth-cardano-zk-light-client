# Phase 2a-2-ii-A — Slot-binding Merkle circuit (operation 4)

## 1. Scope
Operation 4: prove `finalized_slot` is field 0 (**gindex 8**) of a
`BeaconBlockHeader`, binding to `finalized_header_root` via a **fixed 3-step SSZ
Merkle path** (8→4→2→1, sibling order **[L,L,L]**). First real Merkle circuit
(Image-2). Method: compile-only constraint count (×2-deterministic) + a 1/2/3-step
decomposition, plus a decisive functional Setup→Prove→Verify against an
**authoritative Fulu vector**.

## 2. Setup
- gnark **v0.13.0**, go1.23.6, native field **`ecc.BLS12_381.ScalarField()`**.
- `sha2` + `uints` gadgets. `finalized_slot` is taken as a **number**
  (`frontend.Variable`) and encoded **in-circuit** to its 32-byte SSZ leaf:
  8 little-endian bytes (`bits.ToBinary(64)` — which also **range-checks
  slot < 2⁶⁴**) + 24 zero bytes. Fixed **[L,L,L]** order (the slot leaf is the
  leftmost, so every step is `H(node, sibling)`).
- Siblings (3 × Bytes32) are a **private witness**, computed off-circuit by
  `offchain/ssz.SlotBranch` (the intermediate nodes of `HashTreeRoot`), from the
  **STEP-0-validated official Fulu `BeaconBlockHeader` vector** (`testdata/bbh/`).

## 3. Functional correctness — PASS (decisive)
Self-anchored to the authoritative root: `ssz.HashTreeRoot(h) == roots.yaml root`,
then the in-circuit 3-step path from `finalized_slot` reaches that root, full
**Setup→Prove→Verify over BLS12-381 → PASS** (292,396 constraints).
- `slot = 16101738745833384750`, official root `0xa2672769…48a84800`.
- The `offchain/ssz` refactor was regression-gated by re-running `headervector`:
  **PASS** (`htr == official root`, byte-identical to STEP-0).
- Proof is randomized (not byte-identical run-to-run, expected, not asserted);
  constraint counts are deterministic.

This confirms the in-circuit leaf LE-encoding, **[L,L,L]** sibling order, and
SHA-256 wiring are correct **against an official vector** (not our own reference).

## 4. Measured constraints (×2-stable)
| Merkle steps | constraints |
|---:|---:|
| 1 | 185,052 |
| 2 | 238,725 |
| **3 (op-4)** | **292,396** |

**Decomposition** (constraints = intercept + slope·steps):
- **per-Merkle-step (slope) = 53,672** — one 64-byte node-hash = 2 SHA-256
  compression blocks. Steps differ by ≤2 (53,673 / 53,671): essentially linear;
  the first step's leaf carries 24 constant-zero bytes, ~2 constraints cheaper
  than later digest inputs.
- **intercept = 131,380** = `uints`/lookup setup (~130,811, = D8 intercept) +
  leaf-encoding + 32-byte assert (≈ +569).
- `count(3)` = 131,380 + 3 × 53,672 = **292,396** (matches the functional test).

## 5. D8 cross-reference — compare the SLOPE, not the total
The standalone `count(3)` **includes the ~131K `uints` intercept**, which is paid
**once** and **shared with op-3** in the full circuit (not double-paid). So the
correct comparison to D8 is the **per-Merkle-step slope**, not the total count:

| quantity | measured | D8 reference | ratio |
|---|---:|---:|---:|
| per node-hash (2 blocks) | **53,672** | 2 × 27,627 = 55,255 | ~97% |
| op-4 marginal (3 node-hashes = 6 blocks) | 3 × 53,672 = **161,016** | 6 × 27,627 = 165,765 | ~97% |
| intercept (shared, once) | 131,380 | D8 ~130,811 | ~100% |
| **op-4 standalone circuit** | **292,396** | (161K marginal + 131K intercept) | — |

The measured per-node-hash (53,672) is **~3% below** D8's 2-block prediction
(55,255): a 64-byte node carries 64 input bytes vs D8's canonical 2-block sizes'
96 — the **input-byte effect D8 already flagged** (D8 saw the same ~589/node gap).
So D8's op-4 ~166K block-marginal is **confirmed to ~3%** (measured ~161K). The
in-circuit number→LE-leaf encoding costs only **~569 constraints** (folded into the
intercept) — cheap.

## 6. Notes
- **finalized_slot number↔bytes**: kept as a number (needed for the later on-chain
  `finalized_slot > datum.finalized_slot` numeric check) and encoded in-circuit to
  the LE 32-byte SSZ leaf (the SHA-256 form). `ToBinary(64)` also enforces the
  `slot < 2⁶⁴` validity bound.
- **Public-input form** (FinalizedSlot as 1 variable + HeaderRoot as 32 `U8`) is
  the isolated-op representation; the full circuit may pack public inputs differently.
- **Correctness-first, no optimization**: the constant zero-subtree (e.g. `sib2`'s
  `H(0,0)` and the `H(body,0)` leg) is hashed live; hardcoding those constants is a
  separate later optimization measurement.
- The vector is `ssz_random` (slot is a random `uint64`) — irrelevant to the
  merkleization proof. A realistic slot would come from a `light_client` vector or
  a real beacon-node header.

Raw → `benchmarks/raw/phase-2-circuit/op4-slotbind.log`.
