# Known spec divergences (recorded, not fixed)

Implementation-vs-spec divergences that are acceptable for this design, recorded so that no reader
assumes full spec conformance. They are not soundness defects; each entry states why it is
acceptable here. The thesis states KD-1 as its third limitation (Section 7.2).

## KD-1 — the off-chain code does not reject the identity-element public key

**As stated in the thesis (Section 7.2, third limitation).** "Third, the off-chain code does not explicitly
reject the identity-element public key, a check that the BLS specifications require in the general
case, although the in-circuit key decompression does reject it. Such a key cannot belong to a
registered sync committee, since every validator proves possession of its key at deposit, and the
Poseidon2 commitment fixes the exact key set from bootstrap onward."

**The divergence.** The eth2 BLS spec requires KeyValidate on every pubkey; in particular
`fast_aggregate_verify` returns FALSE when any pubkey is the point at infinity. Two off-chain paths
omit that check:

- (i) `prover/offchain/bls/verify.go` — `FastAggregateVerify` (:27; `VerifySyncAggregate` :50
  delegates to it) aggregates via `sumG1` (:67) with no KeyValidate step (the comment at :25-26
  records the omission). The pairing identities e(P, inf) = e(inf, Q) = 1 then make the official
  `infinity_pubkey` conformance case verify TRUE where eth2 expects FALSE (by construction of the
  identities; not run against the actual vector, see "Test coverage" below). The `na_pubkeys_*`
  cases match eth2's expected FALSE through the empty-input early return (:28-30), a different
  mechanism than KeyValidate. The keys arrive as already-decoded `bls12381.G1Affine` values, so
  subgroup membership is whatever the decoder enforced upstream: gnark-crypto v0.18.0
  `G1Affine.SetBytes` (`ecc/bls12-381/marshal.go:891-892` → `setBytes(buf, true)`) runs the
  subgroup check on every decompressed point (:987-989) but returns the identity for the
  compressed-infinity encoding without any further check (:915-922).
- (ii) `prover/offchain/bootstrap/bootstrap.go` — `decompressCanonicalPubkey` (:180-192): the
  canonicity test strips the three flag bits (:183) and compares x ≤ p−1 (:184-186), then
  `point.SetBytes` (:188) accepts the compressed-infinity encoding as the identity element, so an
  infinity-flagged key would enter the committee commitment unrejected.

The in-circuit counterpart is `prover/circuits/common/decompresspubkey.go:76-77`
(`AssertIsEqual(b0[7], 1)` / `AssertIsEqual(b0[6], 0)`, commented at :72-75), exercised by
`TestDecompressRejectsInfinityFlag` (`prover/circuits/common/decompresspubkey_test.go:188`). It is
part of op-6 (boundary circuit) only; the regular circuit never decompresses keys.

**Why it is acceptable here.** (i) Every committee this code verifies is SSZ-authenticated (the
gindex-86/87 walks to authenticated state roots), and an infinity pubkey cannot enter the real
validator set: a deposit requires a BLS proof-of-possession that an infinity key cannot produce.
(ii) The direction is conservative: the in-circuit op-6 decompression rejects infinity-flagged keys
outright, while the off-chain bootstrap accepts them. A hypothetical infinity-key committee would
therefore produce a bootstrap commitment that the boundary circuit could never rotate — a liveness
failure on a committee that cannot occur in practice, not a forgery path. (iii) The on-chain BLS
check receives its aggregate key from the Groth16-bound public inputs, an aggregate of committed
real-committee keys, so the same edge is unreachable there.

**Test coverage.** The committed conformance vectors
(`prover/offchain/bls/testdata/fast_aggregate_verify/`: `valid` and `tampered_signature`) are 2 of
the eth2 suite's ~12 cases, chosen as a positive/tamper pair. `infinity_pubkey` and `na_pubkeys_*`
are not committed, so the test suite does not exercise this divergence.
