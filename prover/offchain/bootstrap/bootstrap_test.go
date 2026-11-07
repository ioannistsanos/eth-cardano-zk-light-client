package bootstrap

import (
	"crypto/sha256"
	"errors"
	"math/big"
	"strings"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fp"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bls12381"
	"github.com/consensys/gnark/test"

	"eth-cardano-zk-light-client/prover/circuits/common"
	"eth-cardano-zk-light-client/prover/offchain/bls"
	"eth-cardano-zk-light-client/prover/offchain/commitment"
	"eth-cardano-zk-light-client/prover/offchain/ssz"
)

// committeeSize is the real sync committee size (a power of two, required by ssz.PubkeysRoot).
const committeeSize = 512

// hashNodePair = SHA-256(left ‖ right) — the merkleizer's node hash, so the synthetic trees are
// consistent with the ssz walks by construction.
func hashNodePair(left, right [32]byte) [32]byte {
	return sha256.Sum256(append(append([]byte{}, left[:]...), right[:]...))
}

// aggregateSign produces Σ_{participating} secret_i·HashToG2(message) — the honest aggregate the
// current committee would publish in the sync_aggregate.
func aggregateSign(t *testing.T, secrets []big.Int, participating []bool, message [32]byte) bls12381.G2Affine {
	t.Helper()
	hashedMessage, err := bls12381.HashToG2(message[:], bls.EthereumDST)
	if err != nil {
		t.Fatalf("hash-to-G2: %v", err)
	}
	var aggregate bls12381.G2Jac
	for i := range secrets {
		if participating[i] {
			var signature bls12381.G2Affine
			signature.ScalarMultiplication(&hashedMessage, &secrets[i])
			var signatureJacobian bls12381.G2Jac
			signatureJacobian.FromAffine(&signature)
			aggregate.AddAssign(&signatureJacobian)
		}
	}
	var result bls12381.G2Affine
	result.FromJacobian(&aggregate)
	return result
}

// buildSyntheticBootstrap constructs a self-consistent genesis witness over TWO independent
// trees: the bootstrap tree (gindex-86 current committee → bootstrap_state_root) and the attested
// tree (gindex-87 next committee + gindex-169 finality joined at gindex 21 → attested_state_root),
// the current committee signing the attested header. Each branch is anchored to its OWN root
// (Gindex86Walk → bootstrap root; Gindex87/169Walk → attested root) — HALT if any diverges.
// Returns the witness + the expected current/next commitments.
func buildSyntheticBootstrap(t *testing.T) (*Bootstrap, fr.Element, fr.Element) {
	t.Helper()
	_, _, g1Generator, _ := bls12381.Generators()

	// ── current committee (signs; gindex 86 in the bootstrap state) ──
	currentKeys := make([]bls12381.G1Affine, committeeSize)
	currentSecrets := make([]big.Int, committeeSize)
	currentCompressed := make([][48]byte, committeeSize)
	for i := 0; i < committeeSize; i++ {
		currentSecrets[i] = *big.NewInt(int64(i + 1))
		currentKeys[i].ScalarMultiplication(&g1Generator, &currentSecrets[i])
		currentCompressed[i] = currentKeys[i].Bytes()
	}
	currentAggregate := currentKeys[0].Bytes() // any valid compressed point for the container
	currentCommitment := commitment.Commit(currentKeys)
	currentCommitteeRoot := ssz.SyncCommitteeRoot(ssz.PubkeysRoot(currentCompressed), ssz.Bytes48Root(currentAggregate))

	// ── next committee (installed; gindex 87 in the attested state) ──
	nextKeys := make([]bls12381.G1Affine, committeeSize)
	nextCompressed := make([][48]byte, committeeSize)
	for i := 0; i < committeeSize; i++ {
		secret := big.NewInt(int64(i + 1 + 100000))
		nextKeys[i].ScalarMultiplication(&g1Generator, secret)
		nextCompressed[i] = nextKeys[i].Bytes()
	}
	nextAggregate := nextKeys[0].Bytes()
	nextCommitment := commitment.Commit(nextKeys)
	nextCommitteeRoot := ssz.SyncCommitteeRoot(ssz.PubkeysRoot(nextCompressed), ssz.Bytes48Root(nextAggregate))

	// ── bootstrap tree (built independently via hashNodePair; gindex-86 path 86→43→21→10→5→2→1) ──
	bsSibling87 := sha256.Sum256([]byte{0xb0, 87})
	bsSibling42 := sha256.Sum256([]byte{0xb0, 42})
	bsSibling20 := sha256.Sum256([]byte{0xb0, 20})
	bsSibling11 := sha256.Sum256([]byte{0xb0, 11})
	bsSibling4 := sha256.Sum256([]byte{0xb0, 4})
	bsSibling3 := sha256.Sum256([]byte{0xb0, 3})
	bsNode43 := hashNodePair(currentCommitteeRoot, bsSibling87) // g43 = H(g86, g87)
	bsNode21 := hashNodePair(bsSibling42, bsNode43)             // g21 = H(g42, g43)
	bsNode10 := hashNodePair(bsSibling20, bsNode21)             // g10 = H(g20, g21)
	bsNode5 := hashNodePair(bsNode10, bsSibling11)              // g5  = H(g10, g11)
	bsNode2 := hashNodePair(bsSibling4, bsNode5)                // g2  = H(g4, g5)
	bootstrapStateRoot := hashNodePair(bsNode2, bsSibling3)     // g1  = H(g2, g3)
	currentBranch := [6][32]byte{bsSibling87, bsSibling42, bsSibling20, bsSibling11, bsSibling4, bsSibling3}

	bootstrapHeader := ssz.Header{
		Slot: 8192000, ProposerIndex: 11,
		ParentRoot: sha256.Sum256([]byte("bootstrap-parent")),
		StateRoot:  bootstrapStateRoot,
		BodyRoot:   sha256.Sum256([]byte("bootstrap-body")),
	}
	trustedBlockRoot := bootstrapHeader.HashTreeRoot()

	// ── attested tree (gindex-87 next + gindex-169 finality join at gindex 21) ──
	finalizedHeader := ssz.Header{
		Slot: 8192032, ProposerIndex: 7, // period 1000 — same period as the signature slot (P5)
		ParentRoot: sha256.Sum256([]byte("finalized-parent")),
		StateRoot:  sha256.Sum256([]byte("finalized-state")),
		BodyRoot:   sha256.Sum256([]byte("finalized-body")),
	}
	node169 := finalizedHeader.HashTreeRoot()
	atSibling86 := sha256.Sum256([]byte{0xa0, 86})
	atSibling168 := sha256.Sum256([]byte{0xa0, 168})
	atSibling85 := sha256.Sum256([]byte{0xa0, 85})
	atSibling20 := sha256.Sum256([]byte{0xa0, 20})
	atSibling11 := sha256.Sum256([]byte{0xa0, 11})
	atSibling4 := sha256.Sum256([]byte{0xa0, 4})
	atSibling3 := sha256.Sum256([]byte{0xa0, 3})
	atNode43 := hashNodePair(atSibling86, nextCommitteeRoot) // g43 = H(g86, g87)
	atNode84 := hashNodePair(atSibling168, node169)          // g84 = H(g168, g169)
	atNode42 := hashNodePair(atNode84, atSibling85)          // g42 = H(g84, g85)
	atNode21 := hashNodePair(atNode42, atNode43)             // g21 = H(g42, g43) ← the join
	atNode10 := hashNodePair(atSibling20, atNode21)          // g10 = H(g20, g21)
	atNode5 := hashNodePair(atNode10, atSibling11)           // g5  = H(g10, g11)
	atNode2 := hashNodePair(atSibling4, atNode5)             // g2  = H(g4, g5)
	attestedStateRoot := hashNodePair(atNode2, atSibling3)   // g1  = H(g2, g3)
	nextBranch := [6][32]byte{atSibling86, atNode42, atSibling20, atSibling11, atSibling4, atSibling3}
	finalityBranch := [7][32]byte{atSibling168, atSibling85, atNode43, atSibling20, atSibling11, atSibling4, atSibling3}

	// ── MANDATORY off-circuit anchor: EACH branch reproduces its OWN root (two distinct roots) ──
	if got := ssz.Gindex86Walk(currentCommitteeRoot, currentBranch); got != bootstrapStateRoot {
		t.Fatalf("anchor HALT: Gindex86Walk != bootstrap_state_root\n  got 0x%x\n  want 0x%x", got, bootstrapStateRoot)
	}
	if got := ssz.Gindex87Walk(nextCommitteeRoot, nextBranch); got != attestedStateRoot {
		t.Fatalf("anchor HALT: Gindex87Walk != attested_state_root\n  got 0x%x\n  want 0x%x", got, attestedStateRoot)
	}
	if got := ssz.Gindex169Walk(node169, finalityBranch); got != attestedStateRoot {
		t.Fatalf("anchor HALT: Gindex169Walk != attested_state_root\n  got 0x%x\n  want 0x%x", got, attestedStateRoot)
	}

	attestedHeader := ssz.Header{
		Slot: 8192064, ProposerIndex: 7,
		ParentRoot: sha256.Sum256([]byte("attested-parent")),
		StateRoot:  attestedStateRoot,
		BodyRoot:   sha256.Sum256([]byte("attested-body")),
	}

	// ── sync aggregate: the current committee signs the attested header's signing_root (d) ──
	forkVersion := [4]byte{0x05, 0x00, 0x00, 0x00}
	var genesisValidatorsRoot [32]byte
	for i := range genesisValidatorsRoot {
		genesisValidatorsRoot[i] = byte(i)
	}
	domain := bls.ComputeDomain(bls.DomainSyncCommittee, forkVersion, genesisValidatorsRoot)
	signingRoot := bls.ComputeSigningRoot(attestedHeader.HashTreeRoot(), domain)
	participationBits := make([]bool, committeeSize)
	for i := range participationBits {
		participationBits[i] = true // all 512 participate (≥ 342)
	}
	signature := aggregateSign(t, currentSecrets, participationBits, signingRoot)

	input := &Bootstrap{
		BootstrapHeader:        bootstrapHeader,
		TrustedBlockRoot:       trustedBlockRoot,
		CurrentCommittee:       SyncCommittee{Pubkeys: currentCompressed, AggregatePubkey: currentAggregate},
		CurrentCommitteeBranch: currentBranch,
		AttestedHeader:         attestedHeader,
		NextCommittee:          SyncCommittee{Pubkeys: nextCompressed, AggregatePubkey: nextAggregate},
		NextCommitteeBranch:    nextBranch,
		FinalizedHeader:        finalizedHeader,
		FinalityBranch:         finalityBranch,
		ParticipationBits:      participationBits,
		Signature:              signature.Bytes(),
		ForkVersion:            forkVersion,
		SignatureSlot:          8192065, // period 1000 — the finalized header's period (P5)
		GenesisValidatorsRoot:  genesisValidatorsRoot,
	}
	return input, currentCommitment, nextCommitment
}

// ─────────────────────────── positive ───────────────────────────

func TestBootstrap_PositiveVerifies(t *testing.T) {
	input, wantCurrent, wantNext := buildSyntheticBootstrap(t)
	result, err := Verify(input)
	if err != nil {
		t.Fatalf("positive FAILED (all 5 conditions should pass): %v", err)
	}
	if result.CurrentPubkeysCommitment != wantCurrent {
		t.Fatal("current_pubkeys_commitment mismatch")
	}
	if result.NextPubkeysCommitment != wantNext {
		t.Fatal("next_pubkeys_commitment mismatch")
	}
	if result.FinalizedSlot != input.FinalizedHeader.Slot {
		t.Fatalf("finalized_slot = %d, want %d", result.FinalizedSlot, input.FinalizedHeader.Slot)
	}
	if result.FinalizedHeaderRoot != input.FinalizedHeader.HashTreeRoot() {
		t.Fatal("finalized_header_root mismatch")
	}
	t.Logf("PASS: all 5 conditions verify → datum {current/next commitments, finalized root/slot}")
}

// ─────────────────────────── the six negatives (one per failure mode) ───────────────────────────

// (e) the LOAD-BEARING one: a non-canonical pubkey coordinate (x ≥ p) is rejected before any
// branch check — a rotten commitment would grief the regular path (a stuck bridge).
func TestBootstrap_NonCanonicalKeyRejected(t *testing.T) {
	input, _, _ := buildSyntheticBootstrap(t)
	var nonCanonical [48]byte
	fp.Modulus().FillBytes(nonCanonical[:]) // x-field = p (≥ p), big-endian
	nonCanonical[0] |= 0x80                 // set the compression flag
	input.CurrentCommittee.Pubkeys[3] = nonCanonical
	if _, err := Verify(input); !errors.Is(err, ErrNonCanonicalKey) {
		t.Fatalf("want ErrNonCanonicalKey, got %v", err)
	}
}

// (a) gindex-86 branch tampered → fails vs the BOOTSTRAP root.
func TestBootstrap_WrongCurrentBranchRejected(t *testing.T) {
	input, _, _ := buildSyntheticBootstrap(t)
	input.CurrentCommitteeBranch[0][0] ^= 0x01
	if _, err := Verify(input); !errors.Is(err, ErrCurrentCommitteeBranch) {
		t.Fatalf("want ErrCurrentCommitteeBranch, got %v", err)
	}
}

// (b) gindex-87 branch tampered → fails vs the ATTESTED root.
func TestBootstrap_WrongNextBranchRejected(t *testing.T) {
	input, _, _ := buildSyntheticBootstrap(t)
	input.NextCommitteeBranch[0][0] ^= 0x01
	if _, err := Verify(input); !errors.Is(err, ErrNextCommitteeBranch) {
		t.Fatalf("want ErrNextCommitteeBranch, got %v", err)
	}
}

// (c) gindex-169 branch tampered → fails vs the ATTESTED root.
func TestBootstrap_WrongFinalityBranchRejected(t *testing.T) {
	input, _, _ := buildSyntheticBootstrap(t)
	input.FinalityBranch[0][0] ^= 0x01
	if _, err := Verify(input); !errors.Is(err, ErrFinalityBranch) {
		t.Fatalf("want ErrFinalityBranch, got %v", err)
	}
}

// (d) a tampered sync aggregate signature → rejected.
func TestBootstrap_TamperedAggregateRejected(t *testing.T) {
	input, _, _ := buildSyntheticBootstrap(t)
	input.Signature[10] ^= 0x01
	if _, err := Verify(input); !errors.Is(err, ErrSyncAggregate) {
		t.Fatalf("want ErrSyncAggregate, got %v", err)
	}
}

// (a) the bootstrap header does not reconstruct to the trusted checkpoint → rejected.
func TestBootstrap_WrongCheckpointRejected(t *testing.T) {
	input, _, _ := buildSyntheticBootstrap(t)
	input.TrustedBlockRoot[0] ^= 0x01
	if _, err := Verify(input); !errors.Is(err, ErrCheckpoint) {
		t.Fatalf("want ErrCheckpoint, got %v", err)
	}
}

// ─────────────────────────── the Poseidon-match solve-anchor ───────────────────────────

// P5 (§3.1.6 pre-condition): the finalized header and the signature slot must lie in the same
// sync-committee period. Same period → the witness still verifies; a cross-period signature slot
// is rejected before any cryptographic work, with the sentinel.
func TestBootstrap_PeriodEqualityPasses(t *testing.T) {
	input, _, _ := buildSyntheticBootstrap(t)
	input.SignatureSlot = 8200191 // the last slot of period 1000 (8192000 + 8191)
	if _, err := Verify(input); err != nil {
		t.Fatalf("same-period signature slot should verify, got %v", err)
	}
}

func TestBootstrap_PeriodMismatchRejected(t *testing.T) {
	input, _, _ := buildSyntheticBootstrap(t)
	input.SignatureSlot = 8200192 // the first slot of period 1001 (finalized header is period 1000)
	_, err := Verify(input)
	if !errors.Is(err, ErrPeriodMismatch) {
		t.Fatalf("want ErrPeriodMismatch, got %v", err)
	}
	for _, want := range []string{"8192032", "period 1000", "8200192", "period 1001"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error should name both slots and periods (missing %q): %v", want, err)
		}
	}
}

func aggregateParticipating(keys []bls12381.G1Affine, bits []int) bls12381.G1Affine {
	var accumulator bls12381.G1Jac
	accumulator.X.SetOne()
	accumulator.Y.SetOne()
	accumulator.Z.SetZero() // (1,1,0) = point at infinity (matches the in-circuit identity start)
	for i := range keys {
		if bits[i] == 1 {
			var pointJacobian bls12381.G1Jac
			pointJacobian.FromAffine(&keys[i])
			accumulator.AddAssign(&pointJacobian)
		}
	}
	var result bls12381.G1Affine
	result.FromJacobian(&accumulator)
	return result
}

func frToVar(e fr.Element) frontend.Variable {
	var asBig big.Int
	e.BigInt(&asBig)
	return &asBig
}

// TestBootstrap_PoseidonMatchSolveAnchor proves the bootstrap's commitment (commitment.Commit) is
// what the in-circuit committeeBindAggregateCount produces: feed a (keys, commitment) pair built
// the bootstrap's way into CommitteeBindCircuit and confirm it SOLVES — so the genesis datum the
// bootstrap writes validates against the first regular update. The per-key Poseidon match is
// size-independent, so a small committee suffices to pin it for the 512-key bootstrap.
func TestBootstrap_PoseidonMatchSolveAnchor(t *testing.T) {
	const n = 8
	_, _, g1Generator, _ := bls12381.Generators()
	keys := make([]bls12381.G1Affine, n)
	for i := 0; i < n; i++ {
		secret := big.NewInt(int64(i + 1))
		keys[i].ScalarMultiplication(&g1Generator, secret)
	}
	commit := commitment.Commit(keys) // the bootstrap's commitment function

	bits := make([]int, n)
	count := 0
	for i := range bits {
		if i%3 != 0 {
			bits[i] = 1
			count++
		}
	}

	witness := common.NewCommitteeBindCircuit(n)
	for i := range keys {
		witness.Pubkeys[i] = sw_bls12381.NewG1Affine(keys[i])
		witness.Bits[i] = bits[i]
	}
	witness.PubkeysCommitment = frToVar(commit)
	witness.Apk = sw_bls12381.NewG1Affine(aggregateParticipating(keys, bits))
	witness.Count = count

	if err := test.IsSolved(common.NewCommitteeBindCircuit(n), witness, ecc.BLS12_381.ScalarField()); err != nil {
		t.Fatalf("Poseidon-match anchor FAILED — bootstrap commitment != in-circuit committeeBindAggregateCount: %v", err)
	}
	t.Logf("PASS: bootstrap commitment SOLVES CommitteeBindCircuit — genesis datum validates against the first regular update")
}
