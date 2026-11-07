# Circuit Assembly — Design Decisions (interface freeze)

Record of the design decisions for the assembly of the regular and boundary circuits
(`prover/circuits/common/regular.go`, `prover/circuits/common/boundary.go`): the two
interface-freezing decisions taken BEFORE any assembly code, and the follow-ups that
depended on the assembled circuit's MEASURED numbers. Companion to SEC-01 (the
Family-B fix this assembles) and the op-* gadget records (D9–D14, `docs/records.md`).

## Decision 1 — DROP `committee_id`; store `pubkeys_commitment` (Q1)

`current_committee_id` + `next_committee_id` (48 B G1 each) are REPLACED 1-for-1
by `current_pubkeys_commitment` + `next_pubkeys_commitment` (32 B Poseidon `Fr`
each). Rationale: post-SEC-01 (Family-B) the full-committee aggregate has NO
on-chain consumer — op-1 (the ΣG1 binding) was dropped, and the BLS check uses
`apk` (the participating aggregate from op-2), not the committee aggregate. The
Poseidon commitment is the committee identity.

- The datum STAYS 8 FIELDS (replace-in-place — NOT 8→10).
- Size: −32 B from the swap (2 × 48→32 B; D6 1,656 B → ≈ 1,624 B). A LARGER
  vk-size delta comes from Decision 2 (Q5 moves ℓ → the IC-point count → the vk
  size). Both are re-measure at assembly, not hard numbers.
- Final 8 fields: `vk_regular`, `vk_boundary`, `fork_version`,
  `genesis_validators_root` (anchor); `finalized_header_root`, `finalized_slot`,
  `current_pubkeys_commitment`, `next_pubkeys_commitment` (mutable).

## Decision 2 — public-input layout = Option P (per-signal, packed); Option H deferred (Q5)

The 6 regular signals (`pubkeys_commitment`, `apk`, `count`,
`attested_header_root`, `finalized_header_root`, `finalized_slot`) + the 7th
boundary signal (`next_pubkeys_commitment`) are each exposed as Groth16 public
inputs, the wide ones PACKED: 32-byte roots → ~2 `Fr` each, the emulated-G1 `apk`
→ ~4 `Fr`, the rest 1 `Fr` — ≈ 11 `Fr` (regular) / ≈ 12 (boundary). This keeps
the thesis's per-signal "6 vs 7 inputs" design (§2.1.3 / §2.1.3.A) consistent
with the implementation.

Why P over H (a single SHA-256 public-input digest, ℓ = 1–2): P keeps
theory↔implementation consistent — the per-signal public design and Table 2 are
central and span multiple thesis sections. The on-chain budget has ample headroom
(≈ 6.6–6.9 B of the 10 B limit unused), so P's MSM (~840 M vs the thesis ~458 M)
fits comfortably; H's ~700 M saving solves a budget problem we do not have.
Option H is left as future work — a genuine optimization (MSM
~76–153 M, regular ≈ boundary, smaller vk), deferred to keep the documented
design intact, alongside the existing CIP-133 MSM hook.

## Built — RegularCircuit (2026-06-07, D15)

The regular assembly (op-1→bind + op-2 + op-5 + op-3a + op-3b + op-4) is built and
measured — Decision 2 realized.

**Measured: 1,990,745 (~1.99M)** R1CS (direct N=512, ×2-deterministic). Reconciles as
committee 929,169 (D13) + op-3a 504,292 + op-3b ~376K marginal + op-4 ~161K marginal =
**~1.97M ops** (the `uints` intercept ~131K paid ONCE across op-3a/3b/4) **+ ~20K
Option-P packing** (apk `Reduce` ×2 + `packCoordinate`/`packRoot` + the 11 asserts). The
thesis §2.1.3 10–26M estimate is refuted ~5–13×. (Small-N extrapolation gave 2.12M,
overshooting the direct by ~6.6% — the D13 extrapolation-overshoot pattern.) See D15.

**LOCKED: `packRoot` = big-endian 16-byte halves** (2026-06-07). A 32-byte SSZ root
packs to two native-`Fr` public inputs: `out[0] = bigEndian(root[0:16])`,
`out[1] = bigEndian(root[16:32])`, where `bigEndian(b) = Σ_{k<16} b[k]·256^(15−k)`. This
is a LOCKED public-input spec the **Phase-3 Plutus verifier MUST re-derive** on-chain
(`byteStringToInteger` over the two big-endian 16-byte halves) — a circuit-vs-Plutus
endianness mismatch breaks verification SILENTLY (not caught in-circuit). The unit test
pins it against an explicit big-endian reference (`big.Int.SetBytes`).

**The 11-Fr Option-P public layout** (confirmed by `witness.Public()` == 11):

| signal | Fr | packed how |
|---|---|---|
| `pubkeys_commitment` | 1 | Poseidon output (already 1 Fr) |
| `apk` | 4 | `packCoordinate(apk.X) ‖ packCoordinate(apk.Y)` — each coord's 6 emulated limbs fold to 2 Fr (REDUCED first → canonical, matching the validator's uncompressed point) |
| `count` | 1 | native (Σ bits) |
| `attested_header_root` | 2 | `packRoot` (big-endian halves) — op-3a's reconstructed root |
| `finalized_header_root` | 2 | `packRoot` (big-endian halves) — the datum-bound root |
| `finalized_slot` | 1 | native (uint64) |
| **total** | **11** | |

ℓ=11 → the Groth16 vk carries IC[0..11] = 12 G1 points (vk ≈ 13 G1 + 3 G2, vs the thesis
ℓ=6 → 8 G1 + 3 G2 — Option P's larger vk, the Q5 trade). The vk BYTE size + the on-chain
MSM (~11 scalarMuls) are follow-up #2 below. (As built, gnark's commitment adds one IC point and
a commitment key: 13 IC, vk = 14 G1 + 5 G2 for the regular circuit — D19, D23.)

**Location:** `RegularCircuit` lives in `circuits/common/` (package `common`), because the
gadgets it calls and `sszMerkleizer` are unexported. A package of its own would first have to
export those helpers (count-neutral renames) and would also move the fixture path used by
`offchain/bootstrap/bootstrap_realpositive_test.go` (`../../circuits/common/testdata/…`).

## Trusted-setup honesty — demonstrator (single-party) vs production (MPC)

The thesis specifies an MPC trusted-setup ceremony. The practical demonstrator runs gnark's
single-party `groth16.Setup` on a cloud machine for both circuits. The difference is a TRUST statement,
not an implementation detail: a single-party setup means the operator momentarily holds the
toxic waste (τ), and whoever holds τ can forge proofs that verify under the resulting vk.
Consequences, recorded so the two claims stop silently contradicting:
- The demonstrator vks (used for every Phase-3/4 measurement cited in Chapter 4) are sound
  ONLY under the assumption that the operator (the author) deleted the toxic waste —
  acceptable for a thesis demonstrator, and stated as such.
- PRODUCTION requires the MPC ceremony the thesis names (1-of-N honest contributors). The
  thesis's design claim stands; the demonstrator does not implement it.
- The thesis states this as its first limitation (Section 7.2): the measured deployment uses a
  single-party demonstration setup; a production deployment requires the MPC ceremony.
- No proving key, toxic waste or other setup artifact is stored in this repository.

## Follow-ups of the two decisions

Consequences of the two decisions for the design-stage description and figures, each with
the measurement that settled it.

1. Public-signal list (§2.1.3 + §2.1.3.A): `committee_id` → `pubkeys_commitment`,
   `new_committee_id` → `next_pubkeys_commitment`.
2. Cost table (§3.2.2 Table 2, the biggest cost change): the MSM rows (6/7 inputs,
   ~458/535 M) and the vk-composition rows (8 G1+3 G2 / 9 G1+3 G2) move under
   Option P (~11/12 Fr → ~11/12 IC G1, MSM ~840 M). Measured: the regular circuit
   (D15, ~1.99M / ℓ=11), the boundary circuit (D16), the key shapes and the MSM with
   the commitment term (D19, D23).
3. Datum description (§3.1.1): `committee_id` fields → commitment fields; the datum
   stays at 8 fields; size re-measured (D18, D19).
4. Bootstrap (§2.1.6): condition e (`committee_id = ΣG1 pubkeys`) → compute
   `pubkeys_commitment = Poseidon(pubkeys)` AND enforce coordinate canonicity (the
   load-bearing establishment point; mirrors op-6's `AssertIsLessOrEqual(x/y, p−1)`).
   Implemented in `prover/offchain/bootstrap/bootstrap.go`: x is checked against p−1 and
   y is recomputed by the decompression (D17).
5. Aiken obligation — the datum-rotation invariant: `next_pubkeys_commitment` (this
   boundary tx) → `current_pubkeys_commitment` (next period) — the on-chain hop closing
   the boundary SC-1 chain across periods. Implemented as `committee_rotated`
   (`validator/lib/zkbridge/validation.ak`, D21).
6. Boundary size (pairs with #2): the §2.1.3.A op-6 estimate ~232K → ~59M (~254×;
   D16/D11 — the gindex-174 pubkeys-vector merkleization + the 512 decompressions were
   uncounted) and the boundary envelope "10–26M + ~232K" → the measured total
   (extrapolated 60,887,591 ≈ ~60.9M; direct N=512 **60,889,638**, +0.0034% — D16, the
   authoritative count; direction UPWARD — the only upward size difference, against
   the regular circuit's downward one).

## Phase-3 Aiken obligations (the on-chain checks — a register, not a re-derivation)

The Plutus V3 spending validator (Phase-3) must enforce ALL of the following; the DETAIL of
each lives in its home file (pointers). This single list exists so a Phase-3 implementer
misses none — especially #2, where a circuit-vs-validator mismatch breaks verification
SILENTLY (the circuit stays internally consistent).

1. **Groth16 verify against the packed public inputs** — re-derive the 11 Fr (regular) / 12
   (boundary) from the datum/redeemer (`pubkeys_commitment` (= `datum.current` for a regular tx
   / `datum.NEXT` for a boundary tx — see #7), `apk` via `packCoordinate` on the
   uncompressed point, `count`, the two roots via `packRoot`, `finalized_slot`) and verify.
   → assembly-design "Built".
2. **`packRoot` big-endian re-derivation (the SILENT one)** — 32-byte roots → 2 Fr as
   big-endian 16-byte halves (`byteStringToInteger`); a wrong endianness breaks on-chain
   verification with NO in-circuit signal. → assembly-design "Built" (the LOCKED spec). Its
   sibling — the proof/vk SERIALIZATION seam — is #9.
3. **BLS aggregate-signature check** — `e(apk, ·) == e(sig, ·)` over the signing_root from
   `attested_header_root` + the anchor `fork_version`/`genesis_validators_root`; apk from the
   redeemer (bound to `ApkPacked` via #1). → SEC-01 (§2.1.3).
4. **Threshold `count ≥ 342`** — the 2/3 supermajority, on-chain (NOT in-circuit). → SEC-01.
5. **Anchor-field bit-identity** — `vk_regular`, `vk_boundary`, `fork_version`,
   `genesis_validators_root` bit-identical input↔output every Phase-A tx. → phase1-methodology.md.
6. **`finalized_slot` monotonicity** — `finalized_slot > datum.finalized_slot` (forward-only). → SEC-01.
7. **Datum-rotation invariant + the boundary's verification binding (boundary)** — the rotating
   update is signed by the NEW period's committee, so the boundary tx verifies the proof's
   `pubkeys_commitment` against **`datum.next_pubkeys_commitment`** (NOT `datum.current`, which
   is the REGULAR tx's binding). Mechanics: after bootstrap the datum holds (current=P,
   next=P+1); a period-P attested state's gindex-87 next is P+1 — already stored — so the
   rotation to (P+1, P+2) requires an attested state IN period P+1, whose sync aggregate only
   the P+1 committee (= datum.next) produces. Rotation on success: `current ← datum.next`
   (= the proof's verified `pubkeys_commitment`), `next ← proof.next_pubkeys_commitment` (P+2).
   PLUS period-advance gating: a rotation is valid only when the update's period has actually
   advanced past the datum's — the exact on-chain predicate (over `finalized_slot` periods, the
   only slot the validator sees) is designed at Phase-3 against the light-client spec's
   `update_has_finalized_next_sync_committee` analog, MINDING the finality-lag edge: at the
   very start of period P+1 the finalized header may still lie in late P, so a naive
   `period(new_finalized) > period(datum.finalized)` can reject a legitimate early-P+1
   boundary (harmless if the relayer waits ~2 epochs into the period; brick-prone if the
   predicate is written without this edge in mind). THE load-bearing hop that closes the
   boundary SC-1 chain across periods (SEC-01 §8d). The CIRCUIT side is already right — the
   boundary binds the signing committee via `PubkeysCommitment` and the installed committee via
   `NextPubkeysCommitment` (§2.1.3.A); this item makes the REGISTER carry which datum field
   each binds to (an explicitation of the implementer's contract, not a new requirement).
   → follow-up #5. (As built, the validator performs no period arithmetic: the boundary proof and
   the signature gate the rotation, and the validator checks `slot_advances` and
   `committee_rotated` — D21.)
8. **State-thread NFT continuity** — the one-shot NFT threads the datum across txs (no fork,
   no duplication). → SEC-01.
9. **Proof/vk SERIALIZATION seam (the second SILENT one — pairs with #2)** — the gnark-emitted
   Groth16 proof points (A: G1, B: G2, C: G1) and the datum-stored vks (α G1; β,γ,δ G2;
   IC[0..ℓ] G1) must deserialize on-chain to the same points gnark emitted: compressed-vs-
   uncompressed convention, the ZCash/eth2 flag bits, G2's c0/c1 component order, and each
   coordinate's byte order must match what CIP-381's bls12_381_G1/G2_uncompress expect — and
   the 11/12 packed public-input Fr (#1/#2) must be fed to the on-chain verifier in the
   circuit's declared order with the agreed integer encoding. #1/#2 cover the public-input
   PACKING; this covers the proof/vk BYTE ENCODINGS — a mismatch verifies nothing and fails
   with NO in-circuit signal (it surfaces only at the Phase-3b gnark↔Aiken bridge, the classic
   integration graveyard). → Phase-3b serialization bridge; CIP-381 [13].

None of these are in the circuits — the circuit emits the public signals; the validator checks
them. (#1/#2 are the packing bridge; #9 is the serialization bridge.)
