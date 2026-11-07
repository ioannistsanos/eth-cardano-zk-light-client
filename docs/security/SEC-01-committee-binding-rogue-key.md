# SEC-01 — Committee-binding rogue-key / sum-not-binding vulnerability

| Field | Value |
|---|---|
| **ID** | SEC-01 |
| **Title** | Plain-sum committee binding is unsound (rogue-key / sum-not-binding) |
| **Severity** | **Critical** — a malicious relayer can write arbitrary fabricated finality into the bridge datum |
| **Component** | Regular Phase A ZK circuit, operation 1 (committee membership via aggregate-pubkey binding, §2.1.3) + the on-chain BLS verification (§2.1.3) |
| **Status** | **CONFIRMED** (executable PoC). **Fix DESIGNED** (Family-B, §8a–§8d) and its **op-6/boundary half VERIFIED** (2b-iii — 4-GAP teeth + real-Electra anchor, D12). **Regular half underway**: **op-2 BUILT** (committee-bind region, D13 — ~0.93M, Option-A canonicity); **op-3b BUILT** (finality branch, D14 — 507,507, real-Electra anchored). **All circuit ops now exist as measured gadgets** — remaining: **assembly** + **bootstrap** (canonicity establishment) + datum wiring (stays 8 — commitments replace `committee_id`). See §9. **State at 2026-07-01: fix implemented in both circuits, the bootstrap and the validator, and exercised in the live runs (§9, last update).** |
| **Discovered** | 2026-06-01, in an analysis of the committed circuits |
| **Evidence** | [`prover/cmd/poc_rogue_key/main.go`](../../prover/cmd/poc_rogue_key/main.go) — real gnark-crypto BLS12-381, Ethereum DST |

---

## 1. Summary

The regular Phase A circuit binds the 512 sync-committee public keys (private
witness) to the public `committee_id` by a **plain G₁ sum**:
`committee_id == Σᵢ pubkeys[i]` (operation 1). `committee_id` is the protocol's
`aggregate_pubkey` field, committed in the BeaconState at **generalized index 175**.

A sum is **unique forward** (512 keys → 1 aggregate) but **not backward**
(1 aggregate → infinitely many 512-key sets). A malicious relayer can therefore
present a **different** 512-key set that sums to the **real** `committee_id`, choose
the **participating** keys to be ones it generated (known secret keys), self-sign an
attacker-chosen message corresponding to a **fabricated** `finalized_header_root`,
and pass **both** operation 1's sum **and** the on-chain BLS pairing check
`e(g₁, σ_agg) = e(apk, H(signing_root))` — **with no signature forgery**. The
fabricated finality is then written into the bridge oracle datum.

This is a textbook **rogue-key attack on plain BLS aggregate verification without
proof-of-possession on the keys being aggregated**. It is confirmed empirically (§5).

---

## 2. Threat model

The thesis's own stated model: the relayer's local committee caches are *"never
trusted by assumption"* and *"attempted dishonesty … is detected"* (§2.1.3). The ZK
proof plus on-chain verification exist precisely so the chain need **not** trust the
relayer. The attacker here is a **malicious relayer** (or any party able to submit a
Cardano transaction — the spending validator authenticates the *proof, signature,
and NFT continuity*, not the submitter's identity). The attacker knows only public
data: the current `datum.current_committee_id` (on-chain) and the protocol
constants.

---

## 3. The vulnerability

What the architecture binds, and what it does **not**:

- **`committee_id` (gindex 175)** is the `aggregate_pubkey` = the G₁ **sum** of the
  512 keys. It is authenticated against the BeaconState (at rotation/bootstrap) and
  stored in the datum. → Only the **sum** of the committee keys is ever pinned.
- **The 512 individual keys** are supplied as **private witness** to operations 1
  and 2. They are bound **only** by the sum constraint
  `Σ pubkeys[i] == committee_id` (op-1) — i.e. their **total**, never the
  individuals.
- **`apk`** (op-2, the participating-subset aggregate `Σ bits[i]·pubkeys[i]`) is a
  prover-computed public signal consumed by the **on-chain** BLS check. The circuit
  performs no signature verification.
- **`attested_header_root`** (the BLS message preimage) is a Groth16 public input,
  but it is **reconstructed inside the circuit from witness fields** (op-3a) — so it
  is "bound to the proof," **not** "bound to a real Ethereum header." Its only tie
  to reality is supposed to be the signature.
- **`σ_agg`** (the aggregate signature) is an **unconstrained redeemer field** — the
  attacker supplies it; the circuit never touches it.

Because `apk`'s underlying participating keys are not individually committed, the
attacker can make `apk` a point whose **discrete log it knows**, and then produce a
valid `σ_agg` itself.

---

## 4. The attack

Minimal-pubkey-size BLS: pubkeys ∈ G₁, signatures ∈ G₂, verify
`e(g₁, σ) = e(pk, H(m))`. A malicious relayer certifies a **fake**
`finalized_header_root`:

1. **Choose the participating set with known discrete logs.** Pick `S`,
   `|S| = 342` (the ⅔ threshold). Generate 342 attacker keypairs
   `pubkeys[k] = rₖ·g₁`, `rₖ` **known**. Then `apk = Σ_{k∈S} pubkeys[k] = x·g₁`
   where `x = Σ rₖ` is **known to the attacker**.
2. **Absorb the residual in the non-participants.** Set the 170 non-participating
   slots to valid G₁ points summing to `committee_id − apk` (169 arbitrary + 1
   computed as `committee_id − Σ(other 511)`). Now `Σ_{all 512} = committee_id`
   exactly → **op-1's sum passes**, and on-chain `committee_id == datum.current_committee_id`
   passes (the real value is public).
3. **Fabricate the header/finality witness.** All inputs to op-3a/op-3b/op-4 are
   witness; pick a large `finalized_slot* > datum.finalized_slot`, a fake
   `finalized_header_root*`, and consistent Merkle siblings → the circuit is
   satisfiable for `attested_header_root*`, `finalized_header_root*`, `finalized_slot*`.
4. **Self-sign — no forgery.** `m* = SHA-256(attested_header_root* ‖ domain)`;
   set `σ_agg = x·H(m*)`. This equals the honest aggregation `Σ_{k∈S} rₖ·H(m*)` of
   the attacker's **own** signatures — no key the attacker lacks is used.
5. **On-chain pairing accepts.**
   `e(g₁, σ_agg) = e(g₁, x·H(m*)) = e(x·g₁, H(m*)) = e(apk, H(m*))`. ✓
6. op-5 `count = 342 ≥ 342` ✓; Groth16 valid ✓; NFT continuity ✓; forward-only
   `finalized_slot* > datum.finalized_slot` ✓.

→ The bridge writes the **fabricated** `finalized_header_root*` into the datum.

---

## 5. Empirical proof (PoC)

[`prover/cmd/poc_rogue_key/main.go`](../../prover/cmd/poc_rogue_key/main.go) runs the
full attack with the **same library family as the prover** — gnark-crypto
BLS12-381 (`ecc/bls12-381`) — using **Ethereum's actual** hash-to-curve:
`bls12381.HashToG2(m*, dst)` = RFC-9380 `BLS12381G2_XMD:SHA-256_SSWU_RO_`, DST
`BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_`. Pairings via gnark-crypto's `Pair`
and `PairingCheck` (the same Miller-loop / final-exponentiation the Cardano CIP-381
builtins compute).

Result of a representative run (`go run ./cmd/poc_rogue_key`, **exit 0 =
ATTACK CONFIRMED**):

| Check | Result |
|---|---|
| `committee_id` (Σ 512 honest pubkeys) | `0xaaa62a43008aeeff08338efb724c030fd987dae0e34e041d7d5ab8280fd96785d29a55948409583b9d7f625cd55d3baf` (random per run) |
| `m*` (attacker-chosen signing-root stand-in) | `0x6308f20e866b21d8e0045e96bce8f3f203f2305fad53ccd6b03241637ade84c2` |
| **op-1 sum** — Σ(all 512 *attacker* keys) == `committee_id` | **PASS** |
| **No forgery** — `x·H(m*)` == `Σ rₖ·H(m*)` | **PASS** |
| **Decisive verify** — `e(g₁, σ_agg) == e(apk, H(m*))` | **TRUE** |
| **CIP-381 form** — `e(g₁,σ)·e(−apk,H(m*)) == 1` (millerLoop×2 + finalVerify) | **TRUE** |
| **Control** — same `σ_agg` vs honest same-index aggregate | **FALSE** |
| **Absorbing key** on curve / in prime-order subgroup | **true / true** |

The **control returning FALSE** rules out "the check passes for anything" — the
acceptance is specifically enabled by the attacker controlling the participating
keys. The **absorbing key being a valid on-curve, prime-order-subgroup point** shows
this attack is **orthogonal to on-curve / subgroup checks** on the witness G₁ points:
such checks would **not** catch it, and they are not subsumed by its fix. They remain
separately required.

---

## 6. Root cause

**Per-key binding is missing.** The trust chain pins only the **aggregate**
(gindex 175). Nothing in the regular circuit binds the **individual** keys to the
authentic committee, so op-1's sum is satisfiable by any key set with the right
total, and op-2's `apk` is attacker-controllable.

- **Ethereum's proof-of-possession does not transfer.** PoP (registration-time
  knowledge-of-secret-key) protects the **real** validator set's aggregate against
  rogue keys. The bridge **re-aggregates unauthenticated witness keys** with no PoP
  check; the attacker trivially "possesses" the keys it generated. PoP provides
  **zero** defense here.
- **The thesis cites the exact countermeasure but does not use it.**
  Boneh–Drijvers–Neven (reference [7]) defends precisely this with
  **hashed-coefficient** aggregation `apk = Σ H(pkᵢ, {pk})·pkᵢ` — the coefficients
  depend on the keys, so they cannot be freely offset. The circuit instead uses a
  **plain** sum `Σ pubkeys[i]`, which is rogue-key-vulnerable absent PoP on the
  aggregated keys.
- **The boundary (op-6) authenticates the right object but discards it.** op-6
  (§2.1.3.A) verifies `sync_committee_root = SHA-256(next_pubkeys_root ‖ agg_root)`
  at gindex 87, where `next_pubkeys_root = hash_tree_root(SyncCommittee.pubkeys)`
  (gindex 174) **is** the per-key commitment — but it is taken as an **opaque
  private witness** (never derived in-circuit from op-1/op-2's keys) and **only the
  aggregate is persisted** in the datum. So even the boundary never binds the
  individual signing keys, and the regular circuit has nothing per-key to bind
  against.

---

## 7. Impact

A malicious relayer can spend the unique bridge UTxO with a transaction that passes
every check and writes an **attacker-chosen `finalized_header_root`** (with an
attacker-chosen, forward-advanced `finalized_slot`) into the datum. The NFT
continuity check does not help — the attacker produces a normal update output
carrying the NFT. Downstream, every Phase B user builds Merkle-Patricia proofs
against this **fabricated** finality, so arbitrary false execution-layer claims
(balances, storage slots, events) are accepted cross-chain. This is a **total
compromise of the bridge's integrity guarantee**.

---

## 8. Fix direction (options — NOT yet decided)

A per-key commitment of the committee must be bound **in-circuit** to the witness
keys used in op-1/op-2:

1. **SSZ pubkeys-root (gindex 174), SHA-256.** Have the signing circuit derive
   `hash_tree_root(SyncCommittee.pubkeys)` in-circuit from the 512 witness keys and
   constrain it to a datum-stored value (the object op-6 already authenticates
   against the BeaconState). **Cost:** ≈ 1,023 SSZ node-hashes (512 leaf-hashes for
   the 48-byte keys + 511 internal), each a 64-byte `H` = **2** SHA-256 compression
   blocks (the D8 padding rule) at the measured ~53.7K constraints/node-hash ⇒
   **≈ 55M constraints** per regular proof. (This is ~2× the loose "~28M" figure,
   which assumes a single compression block per node-hash.) That alone would dwarf
   the rest of the regular circuit — current projection ~1.8–2.5M — by ~20×.

2. **SNARK-friendly commitment (Poseidon / Pedersen).** Commit the 512 keys with a
   SNARK-native hash (~10²–10³ constraints/element over ~1,024 Fr elements ⇒
   ~10⁵–10⁶ total — far cheaper), store that commitment in the datum as the
   committee identity, and derive it in-circuit on every update. The expensive
   SSZ↔commitment **translation** (proving the Poseidon commitment matches the
   gindex-174 SSZ root the BeaconState authenticates) is then paid **once per period**
   in the boundary circuit, not on every regular update. This is the approach taken
   by production sync-committee light clients (e.g. Helios, Telepathy).

Either option **changes the circuit, the datum schema, operation 6, and the bootstrap
procedure (§2.1.6)**. To be designed in a follow-up before op-2 is built.

> Note: option (2) is strongly preferred on cost grounds, but it adds a
> commitment-translation obligation at the boundary. The decision is deferred.

---

## 8a. Step-2a — Family-B (Poseidon) encoding decision (regular-path commitment)
**Date**: 2026-06-02 · **Evidence**: the probes
`prover/cmd/{measure_g1_validity, measure_compressed_commit, poc_encoding_sc4}`
and `measure_poseidon_commit`; record **D9** (`docs/records.md`).

Within option (2) above (the Poseidon commitment), the **encoding** fed to Poseidon is
decided: **commit the full point as its emulated `(x,y)` limbs (packed, 4 Fr/pubkey)** —
not the 48-byte compressed form.

- **Cost (regular path, measured)**: full-limb packed = **380,929 (~0.38M)/update** vs
  compressed = serialize+Poseidon (2.57M) + on-curve (0.23M) ≈ **~2.80M** ⇒ **~7.4×
  cheaper**. The regular path is 255/256 of all transactions, so this dominates.
- **Soundly simpler (SC-4 PoC, `poc_encoding_sc4`)**: the full-`(x,y)` commitment **pins
  the whole point**, so the regular path needs **no in-circuit on-curve/subgroup** — the
  Poseidon bind alone forces the authentic keys and closes the rogue-key attack. The PoC
  settles this symmetrically: a deterministically-constructed **off-curve `y_fake`** with
  the same lexicographic sign as `y_real` yields **identical compressed bytes** (the
  compressed commitment **accepts** it) but **different limbs** (the full-`(x,y)`
  commitment **rejects** it). So the compressed encoding would require an added
  **in-regular on-curve check** to pin `y`; the full-limb encoding does not.

**✅ 2b — RESOLVED in 2b-ii** (§8c, D11): op-6's per-point **subgroup**
check (~58,063/pt ⇒ **~30M/512**) is **redundant**: the **~3.31M** decompress-and-validate
(the bytes↔point tie op-6 needs **regardless**; ~2.52M at 2b-ii, ~3.31M after the 2b-iii F6
Y-canonicity assert — §8d, D11) already pins the point, so the **+30M
subgroup scalar-mul on top is what is dropped** — not a like-for-like swap. Justification (**corrected** — *not* "PoP guarantees subgroup",
the soft link: Ethereum's `process_deposit` does **not** unambiguously subgroup-check at
deposit, so that is **not relied upon**): (i) Links A–D **byte-pin** each pubkey's
compressed bytes to the real committee member (SHA collision-resistance), and (ii)
compression is **injective on the curve**, so **on-curve + sign-match + canonical-x**
recovers the **unique** real point — a wrong-subgroup point **cannot** share a real key's
bytes. Subgroup is thus **not a relayer attack surface**. **Conditional** on 2b-iii wiring
the derived `pubkeys_root` into the gindex-87 walk (**SC-2**, the headline 2b-iii risk);
fallback = full `AssertIsOnG1` (~30M).

**Scope**: this settles the **regular-path encoding** (cost + the SC-4 point-pinning
security). It does **not** verify the full op-6 SHA↔Poseidon single-source hinge
(SC-1…SC-6) — that is **Step 2b**.

---

## 8b. Step-2b-i — op-6 SHA side: gindex-174 merkleization (layout verified)
**Date**: 2026-06-02 · **Evidence**: `prover/circuits/common/pubkeysroot.go` and its tests; record **D10**.

The SHA side of the translation hinge — the in-circuit SSZ `hash_tree_root(SyncCommittee.pubkeys)`
(`Vector[Bytes48, 512]` → gindex-174 root, 1,023 node-hashes) — is built and its **layout verified
against the consensus `ssz_static/SyncCommittee` vector**: the off-circuit anchor
`H(pubkeys_root, agg_root) == container_root` (full 512; also confirms the gindex-175 `agg_root`),
and small-N {2,4} Groth16 Setup→Prove→Verify (end-to-end provable). **Boundary SHA-side cost ≈
~54.8M** (per-node ~53,426, matching D8).

- **Measured fact**: the layout (SC-5) and the ~54.8M cost.
- **AWS-deferred**: the full-512 **in-circuit** solver OOMs locally (~7 GB) — the local guarantee is
  the full-512 off-circuit anchor + the N-generic small-N Groth16.
- **2b-i does NOT establish** (→ 2b-ii/iii): the single-source tie of these pubkey bytes to the
  Poseidon limbs (SC-1/SC-4), the gindex-87 BeaconState walk that authenticates this root, and the
  subgroup-inheritance argument (§8a's 2b-to-verify).

---

## 8c. Step-2b-ii — op-6 decompress-and-validate: on-curve pins the point (subgroup redundant)
**Date**: 2026-06-02 · **Evidence**: `prover/circuits/common/decompresspubkey.go` and its tests; record **D11**.

Recover `(x,y)` from the compressed bytes (the SHA-side **single source**) via a witnessed
`y`-hint **pinned** by **on-curve + sign-match + canonical-x** (never an in-circuit sqrt).
Verified: the real point is **accepted**; an off-curve `y` (same sign) is **rejected by the
on-curve check** (the SC-4 fix has teeth in-circuit); the wrong-sign `−y` (the other curve
root) is **rejected by sign-match** (`0 == 1` — injectivity, executable); small-N {1,2}
Groth16 Setup→Prove→Verify proves the unit is genuinely provable. **Cost ~3.31M/512**
(per-pubkey ~6,495; N=512 direct = 3,309,584, extrapolation 3,327,561 agrees ~0.5% — the
2b-ii ~2.52M became ~3.31M when 2b-iii added the **F6 Y-canonicity** `AssertIsLessOrEqual`,
§8d/D11) ⇒ op-6 ≈ **~58.85M** (SHA 54,786,825 per-node-extrapolated over the exact 1,023 nodes +
decompress 3,309,584 direct-512 + Poseidon 380,929 + container and branch hashes ≈ 0.37M: 7 evaluations
(1 container + 6 walk steps) = 14 blocks × 26,751–26,836 per block = 374,514–375,704, the in-assembly
marginal rates 749,039 / 28 blocks and 53,672 / 2 — the `agg_root` leaf is a witness, not hashed
in-circuit), **not ~85M**; the sum is an estimate, the direct boundary count 60,889,638 (D16) is
authoritative. This is the op-6 **translation increment** (boundary-only, **excl. op-3a** which
is shared with the regular circuit), **not** the boundary circuit total — which also carries
ops 1–5 (op-1/op-2 aggregation alone is the ~10–26M thesis estimate).

- **Four-in-one**: the op-6 decompress discharges four things at once — **SC-1** (single
  source = the bytes), **SC-4** (on-curve pins `y`), **encoding-A limbs** (for
  Poseidon/op-1/op-2), and the **subgroup-saving**.
- **Headline 2b-iii risk (SC-2)**: on-curve-only soundness **holds only if** 2b-iii wires
  the derived `pubkeys_root` into the **gindex-87 BeaconState walk** — a gap there silently
  re-opens the subgroup attack the on-curve check no longer catches. This is 2b-iii's
  **single most important** verification target. Fallback: full `AssertIsOnG1` (~30M).
- **Flag-validity** (F1 → **✅ RESOLVED in 2b-iii**, 2026-06-03): the unit ignored
  byte0 **bit7** (compression, must = 1) and **bit6** (infinity, must = 0) — `x` is built only
  from the low 5 bits so flags don't contaminate it, but a malformed/infinity-flagged encoding
  was **not rejected** (flag-validity rode on SC-2 byte-pinning). **Fixed**: asserted
  `b0[7]=1 ∧ b0[6]=0` in the decompress unit (fail-closed; negatives `1==0` / `0==1`) — the unit
  is now self-sufficient and flag-validity no longer rides on SC-2.
- **Y-canonicity** (F6 → **✅ RESOLVED in 2b-iii**, 2026-06-03): the earlier claim
  here — that **`ToBitsCanonical` asserts `y' < p`** — was **wrong**; 2b-iii found it does **not**
  enforce canonicity (it returns the bits of the *reduced* value). The sign check stays sound, but
  the returned point's **Y limbs could be non-canonical**, and those feed the Poseidon commitment
  → a non-canonical `y` would yield a **different commitment for the same committee** (a
  **griefing/liveness** hole in SC-3, **not** a forgery; `x`+sign pin the point). **Fixed** by an
  explicit `AssertIsLessOrEqual(y, p−1)` (mirrors the x-check); the `y+p` negative now rejects.
- **Does NOT establish** (→ 2b-iii): SC-2 wiring, SC-3 (Poseidon persisted), the assembled
  hinge.

---

## 8d. Step-2b-iii — op-6 assembled hinge: SC-2 covered, real-Ethereum anchored
**Date**: 2026-06-03 · **Evidence**: `prover/circuits/common/op6assemble.go`, `op6assemble_test.go`
(the GAP suite) and `op6anchor_test.go` (the real-Ethereum anchor); records **D12** and **D11**
(updated count).

`AssembledOp6Circuit` wires ONE `Compressed[N]` witness through both paths: **Path-1**
`derivePubkeysRoot` → `H(·, agg_root)` → 6-step gindex-87 walk → `== c.StateRoot` (op-3a's
authenticated wire); **Path-2** `decompressAndValidate` the SAME bytes → Poseidon (encoding A)
`== NextPubkeysCommitment`. The SC-2 fix is **structural** — the derived root feeds the walk, the
walk terminates on op-3a's `c.StateRoot`, and there is **no** opaque `pubkeys_root` witness, **no**
fresh `state_root` witness, **no** second key array.

### Four-GAP mutation contrast (the teeth)
Each strawman re-introduces (test-only) a hole production closes by ABSENCE; the contrast —
strawman **SOLVES** with forged keys ∧ production **REJECTS** the same forged keys — is what proves
the *deletion* has teeth (a lone "production passes" would not).

| GAP | strawman | production (same forged keys) — assertion |
|---|---|---|
| **GAP-a source** (opaque `pubkeys_root`) | SOLVES | REJECTS — `ByteAssertEq(walk, StateRoot)` `65 == 13` |
| **GAP-a terminal** (fresh `state_root`) | SOLVES | REJECTS — `ByteAssertEq(walk, c.StateRoot)` `226 == 199` |
| **GAP-b** (two key arrays) | SOLVES | REJECTS — `67 == 203` |
| **GAP-c** (off-curve / wrong-sign `y`) | — | REJECTS — on-curve / sign-match (`0 == 1`) |

This establishes **SC-2** and, with it, **SC-3** (the commitment is correctly **computed** over the
same byte-pinned decompressed limbs; the datum **persistence/round-trip to the regular path** is part
of the later datum and regular-bind work; the datum stays at 8 fields, assembly-design Decision 1). **SC-2 being tight is what makes the ~30M→~3.31M
subgroup saving COVERED, not on credit** — the 2b-ii precondition (GAP-a) is proven, and it is
**N-invariant** (the gindex-87 walk is state-level, 6 steps at any N), so small-N proves it for full
size.

### Real-Ethereum anchor (layout fidelity)
A committed **Electra** `LightClientUpdate` fixture (period 1600, slot 13107272) anchors the layout
against real data: `PubkeysRoot(512) → H(·, Bytes48Root(agg)) → Gindex87Walk([T,T,T,F,T,F])` **== the
real `attested_header.beacon.state_root`** (`0xf9387606…f1888a6a`). **Non-circular**: the `state_root`
is Ethereum's independent ground truth and the branch encodes the real tree, so a wrong fold/layout
could not reach it. Confirms **both** the container layout `H(pubkeys_root, agg_root)` on **real**
Electra points (stronger than 2b-i's random-byte vector) **and** the fold orientation; gindex 87 is
**self-validated** (the match *means* 87, not assumed). A real committee pubkey also decompresses
cleanly through `decompressAndValidate`.

### F6 (Y-canonicity) — correctness finding folded in
2b-iii found that **`ToBitsCanonical` does NOT enforce canonicity** (it returns the bits of the
*reduced* value): the sign check stays sound, but the returned point's **Y limbs could be
non-canonical**, and those feed the Poseidon commitment → a non-canonical `y` yields a **different
commitment for the same committee** — a **griefing/liveness** hole in SC-3 (**not** a forgery;
`x`+sign pin the point). Fixed in the unit with an explicit `AssertIsLessOrEqual(y, p−1)`
(2026-06-03); decompress 2.52M → **3.31M** (D11). **F1** (flag-validity) was likewise asserted
(`b0[7]=1 ∧ b0[6]=0`). Both **✅ RESOLVED**.

### Honesty boundaries (what 2b-iii does NOT claim)
- **SC-1 scope**: proves the **SHA ↔ Poseidon** single-source (both paths index the one
  `Compressed[N]`). It does **NOT** yet prove **… ↔ op-1/op-2 aggregation** single-source — that
  extends naturally (op-1/op-2 read the same decompressed point) but is proven **then**, in the
  deferred co-existence, not here.
- **Increment, not total**: the **~59.0M** is the op-6 **translation increment** — boundary-only and
  **excludes op-3a** (header reconstruction, shared with the regular circuit). It is **NOT** the
  boundary circuit total (which also carries ops 1–5; op-1/op-2 aggregation alone is ~10–26M).
- **AWS owes measurement, not soundness**: the **full-512 ~59.0M count** and **real-committee N=512
  Setup→Prove→Verify** are AWS-deferred *measurements*; the **soundness (4-GAP) and layout (anchor)
  are established locally** (SC-2 is N-invariant; the anchor is full-512 off-circuit).

### Deferred (carry-forward)
- **Regular-path canonicity** (refined by **D13**): the regular bind needs **no** explicit
  canonicity assert — it inherits canonicity **structurally**: (i) the bind packs **all 512** →
  non-canonical *values* break the Poseidon match; (ii) op-2 aggregates **all 512** → the
  emulated arithmetic range-checks every limb (<2⁶⁴), blocking out-of-range pack-wrap; (iii) the
  match is against a **canonical** commitment (D13 locks: Lock-1/Lock-2/SC-1). **The load-bearing
  canonicity ESTABLISHMENT is at the commitment-creation points — op-6 (done, F6) and the
  BOOTSTRAP (deferred): the bootstrap MUST enforce X/Y canonicity like op-6, else a non-canonical
  commitment griefs the regular path.**
- **op-1/op-2 co-existence** — the regular bind now closes **Poseidon↔aggregation** single-source
  (D13/SC-1); the full **SHA↔Poseidon↔aggregation** chain awaits op-1/op-2 in the *boundary*
  circuit. **Bootstrap** commitment establishment (must enforce canonicity, above). **Datum** —
  commitments persist/round-trip (SC-3); the datum **stays 8** (commitments replace `committee_id`
  1-for-1, not 8→10; assembly-design Decision 1).

---

## 9. Status & affected work

- **op-2** (conditional key aggregation) — **FROZEN.** Its soundness premise (sum
  binding) is broken; its design must change to incorporate the per-key commitment
  (§8).
- **op-3b** (finality branch, gindex 169) — **FROZEN as forward construction.** Its
  SHA-256 Merkle internals are themselves *unaffected* by committee binding (like
  op-4/op-3a), but it is paused because the fix changes circuit assembly, the datum,
  and the public-input layout that op-3b would build on.
- **op-4** (slot binding, **292,396** constraints) and **op-3a** (header
  reconstruction, **504,292** constraints) — **STAND.** They are SHA-256 Merkle
  operations on header/finality structure, independent of the committee binding;
  their measurements are unaffected.

**UPDATE (post-2b-iii, 2026-06-03)** — the freeze *reason* above (no fix design) is now
**resolved**: the Family-B fix is **designed** (§8a–§8d) and its **op-6/boundary half is
verified** (2b-iii — SC-2 4-GAP teeth + real-Electra anchor; D12). The bullets above are kept
as the **discovery-time** record (true on 2026-06-01); the current status is:

- **op-2** — **BUILT** (2026-06-03, D13). The regular committee-binding region (Poseidon
  bind + op-2 single-sourced, **op-1 dropped**) is built and gated — op-2's `apk` now binds to
  the persisted commitment (**~0.93M** region; Option-A canonicity, the 3 locks). Remaining
  regular-path items: **bootstrap** (commitment establishment — must enforce canonicity) and the
  **datum** wiring — datum **stays 8** (commitments replace `committee_id`; assembly-design
  Decision 1) (Aiken/Phase-3).
- **op-3b** — **BUILT** (2026-06-03, D14). The finality-branch walk (gindex 169,
  `[R,L,L,R,L,R,L]`, **507,507** standalone / **376,127** marginal) is built and gated on the
  **real Electra instance**: positive solver + Groth16, three negatives all firing at the
  terminal `StateRoot` assert, and the two-implementation real-data anchor (first empirical
  **7-element** Electra finality branch — the **6→7 depth change** vs pre-Electra gindex 105
  pinned live; this extends the earlier check of the committee branch to the finality branch).
  **The last missing gadget**: all regular+boundary circuit operations now exist as measured
  gadgets — remaining: **assembly** (`sync_committee/` + `boundary/`; op-3b's `StateRoot` must
  be wired from op-3a's extracted state_root, the SC-2-style single-source), **bootstrap**
  (canonicity establishment), **datum** (stays 8 — commitments replace `committee_id`;
  assembly-design Decision 1) (Aiken/Phase-3).
- op-4 / op-3a still **STAND** (unaffected).

**UPDATE (2026-07-01)** — the remaining items are complete: the assembled circuits (D15, D16),
the bootstrap that establishes the commitments with the canonicity checks
(`prover/offchain/bootstrap/`, D17), the datum with the two commitments in place of
`committee_id` (D18, D19) and the rotation check of the validator (D21). The fix ran in the live
runs on Preview (`docs/live-run-log.md`).

---

## 10. References

- Thesis §2.1.2 (BLS aggregate signatures; `aggregate_pubkey` as committee identity),
  §2.1.3 (regular circuit ops 1–5; on-chain BLS check; `signing_root`), §2.1.3.A
  (boundary op-6; gindex 174/175), §2.1.6 (bootstrap).
- Reference [7] — Boneh, Drijvers & Neven, *Compact Multi-Signatures for Smaller
  Blockchains*, ASIACRYPT 2018 (hashed-coefficient aggregation vs. rogue-key
  attacks).
- Reference [11] — Ethereum's proof-of-possession at deposit.
- Reference [13] — CIP-381 (Plutus BLS12-381 builtins).
- Reference [72] — RFC 9380 (hash-to-curve).
- PoC: [`prover/cmd/poc_rogue_key/main.go`](../../prover/cmd/poc_rogue_key/main.go).
