package common

// RegularCircuit assembly tests. The DECISIVE test is the R7 single-source negative
// (TestRegular_StateRootSingleSource): a strawman with a SEPARATE op-3b state_root SOLVES
// a forged finalized_header_root, while production (shared c.StateRoot) REJECTS it — the
// proof the sharing is load-bearing, not incidental (a positive + count alone would pass
// even if two accidental witnesses both held the real value). Helpers bindPoints,
// aggregateApk, patternBits, sumBits, canonicalPacks, poseidonCommitFr (committeebind_test),
// foldFp, frElementToVar (op6assemble_test), packRootBigEndianReference (packing_test),
// toCircuitBytes32 are shared (package common).
//
// The real-Electra tests MOVED to offchain/witness (witness_test.go) — they now run through
// the PRODUCTION witness builder (witness.BuildRegular) with upgraded realism: the CURRENT
// committee's keys + the REAL sync_committee_bits (this file's old buildRealElectraRegular
// used the next committee as a stand-in with pattern bits). An in-package test here cannot
// import offchain/witness (import cycle: witness → common), hence the move.

import (
	"crypto/sha256"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bls12381"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/test"

	"eth-cardano-zk-light-client/prover/offchain/ssz"
)

// ─────────────────────────── off-circuit public-input references ───────────────────────────

// packApkRef is the off-circuit twin of the in-circuit packCoordinate over apk (the
// canonical (x,y)), matching what the validator computes from the uncompressed point.
func packApkRef(apk bls12381.G1Affine) [4]frontend.Variable {
	xLo, xHi := foldFp(apk.X)
	yLo, yHi := foldFp(apk.Y)
	return [4]frontend.Variable{frElementToVar(xLo), frElementToVar(xHi), frElementToVar(yLo), frElementToVar(yHi)}
}

// packRootRef is the off-circuit twin of packRoot (big-endian 16-byte halves).
func packRootRef(root [32]byte) [2]frontend.Variable {
	ref := packRootBigEndianReference(root)
	return [2]frontend.Variable{ref[0], ref[1]}
}

// ─────────────────────────── synthetic self-consistent instance ───────────────────────────

type syntheticRegular struct {
	points          []bls12381.G1Affine
	bits            []int
	commitment      fr.Element
	apk             bls12381.G1Affine
	count           int
	attestedHeader  ssz.Header
	attestedRoot    [32]byte
	finalizedHeader ssz.Header
	finalizedRoot   [32]byte
	finalityBranch  [7][32]byte
	slotBranch      [3][32]byte
}

// buildSyntheticRegular builds a fully self-consistent instance: a committee (keys →
// Poseidon commitment, bits → apk/count) and a finality chain wired BACKWARDS so every
// helper binds — finalized header → root + slot_branch; finality_branch[7] folds (gindex
// 169) to the attested header's state_root; the attested header (with that state_root) →
// attested_header_root. The committee side and the finality side are independent in-circuit
// (joined only by the on-chain BLS check), exactly as in production.
func buildSyntheticRegular(t *testing.T, n int, salt byte) *syntheticRegular {
	t.Helper()
	s := &syntheticRegular{}
	s.points = bindPoints(t, n)
	s.bits = patternBits(n)
	s.apk = aggregateApk(s.points, s.bits)
	s.count = sumBits(s.bits)
	s.commitment = poseidonCommitFr(canonicalPacks(s.points))

	s.finalizedHeader = ssz.Header{
		Slot:          13107200, // an epoch boundary, as a finalized checkpoint must be
		ProposerIndex: 99,
		ParentRoot:    sha256.Sum256([]byte{salt, 'f', 'p'}),
		StateRoot:     sha256.Sum256([]byte{salt, 'f', 's'}),
		BodyRoot:      sha256.Sum256([]byte{salt, 'f', 'b'}),
	}
	s.finalizedRoot = s.finalizedHeader.HashTreeRoot()
	s.slotBranch = s.finalizedHeader.SlotBranch()

	for i := 0; i < 7; i++ {
		s.finalityBranch[i] = sha256.Sum256([]byte{salt, 'F', byte(i)})
	}
	attestedStateRoot := ssz.Gindex169Walk(s.finalizedRoot, s.finalityBranch)

	s.attestedHeader = ssz.Header{
		Slot:          13107272,
		ProposerIndex: 7,
		ParentRoot:    sha256.Sum256([]byte{salt, 'a', 'p'}),
		StateRoot:     attestedStateRoot, // ← the fold; op-3a binds this, op-3b folds to it
		BodyRoot:      sha256.Sum256([]byte{salt, 'a', 'b'}),
	}
	s.attestedRoot = s.attestedHeader.HashTreeRoot()
	return s
}

func (s *syntheticRegular) production() *RegularCircuit {
	c := NewRegularCircuit(len(s.points))
	for i := range s.points {
		c.Pubkeys[i] = sw_bls12381.NewG1Affine(s.points[i])
		c.Bits[i] = s.bits[i]
	}
	c.Slot = s.attestedHeader.Slot
	c.ProposerIndex = s.attestedHeader.ProposerIndex
	c.ParentRoot = toCircuitBytes32(s.attestedHeader.ParentRoot)
	c.StateRoot = toCircuitBytes32(s.attestedHeader.StateRoot)
	c.BodyRoot = toCircuitBytes32(s.attestedHeader.BodyRoot)
	c.FinalizedHeaderRoot = toCircuitBytes32(s.finalizedRoot)
	for i := 0; i < 7; i++ {
		c.FinalityBranch[i] = toCircuitBytes32(s.finalityBranch[i])
	}
	for i := 0; i < 3; i++ {
		c.SlotBranch[i] = toCircuitBytes32(s.slotBranch[i])
	}
	c.PubkeysCommitment = frElementToVar(s.commitment)
	c.ApkPacked = packApkRef(s.apk)
	c.Count = s.count
	c.AttestedHeaderRootPacked = packRootRef(s.attestedRoot)
	c.FinalizedHeaderRootPacked = packRootRef(s.finalizedRoot)
	c.FinalizedSlot = s.finalizedHeader.Slot
	return c
}

// ─────────────────────────── positive ───────────────────────────

// TestRegular_PositiveSolves: the synthetic instance satisfies committee + op-3a + op-3b +
// op-4 + the Option-P packing, at N=8 and N=16 (solver).
func TestRegular_PositiveSolves(t *testing.T) {
	for _, n := range []int{8, 16} {
		s := buildSyntheticRegular(t, n, 0x01)
		if err := test.IsSolved(NewRegularCircuit(n), s.production(), ecc.BLS12_381.ScalarField()); err != nil {
			t.Fatalf("POSITIVE FAILED at N=%d (wiring/packing bug): %v", n, err)
		}
		t.Logf("PASS: N=%d regular assembly solves — committee + op-3a + op-3b + op-4 + Option-P packing", n)
	}
}

// TestRegular_ProvesSmallN: full Groth16 Setup->Prove->Verify at N=2.
func TestRegular_ProvesSmallN(t *testing.T) {
	const n = 2
	s := buildSyntheticRegular(t, n, 0x02)
	scalarField := ecc.BLS12_381.ScalarField()
	constraintSystem, err := frontend.Compile(scalarField, r1cs.NewBuilder, NewRegularCircuit(n))
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	provingKey, verifyingKey, err := groth16.Setup(constraintSystem)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	witness, err := frontend.NewWitness(s.production(), scalarField)
	if err != nil {
		t.Fatalf("witness: %v", err)
	}
	publicWitness, err := witness.Public()
	if err != nil {
		t.Fatalf("public: %v", err)
	}
	proof, err := groth16.Prove(constraintSystem, provingKey, witness)
	if err != nil {
		t.Fatalf("prove: %v", err)
	}
	if err := groth16.Verify(proof, verifyingKey, publicWitness); err != nil {
		t.Fatalf("verify: %v", err)
	}
	t.Logf("PASS: N=2 regular assembly Setup->Prove->Verify (%d constraints)", constraintSystem.GetNbConstraints())
}

// TestRegular_PublicInputCount: the Option-P public layout is exactly 11 Fr.
func TestRegular_PublicInputCount(t *testing.T) {
	s := buildSyntheticRegular(t, 8, 0x05)
	witness, err := frontend.NewWitness(s.production(), ecc.BLS12_381.ScalarField())
	if err != nil {
		t.Fatalf("witness: %v", err)
	}
	publicWitness, err := witness.Public()
	if err != nil {
		t.Fatalf("public: %v", err)
	}
	vector, ok := publicWitness.Vector().(fr.Vector)
	if !ok {
		t.Fatalf("unexpected public-vector type %T", publicWitness.Vector())
	}
	if len(vector) != 11 {
		t.Fatalf("public-input count = %d, want 11 (Option-P: commitment 1 + apk 4 + count 1 + 2 roots ×2 + slot 1)", len(vector))
	}
	t.Logf("PASS: witness.Public() == 11 Fr (Option-P layout)")
}

// ─────────────────────────── R7 single-source negative (decisive) ───────────────────────────

// strawmanRegularStateRoot re-introduces (test-only) a SEPARATE op-3b state_root, decoupling
// op-3b's walk terminal from op-3a's authenticated c.StateRoot — the hole production closes
// by sharing one variable.
type strawmanRegularStateRoot struct {
	RegularCircuit
	Op3bStateRoot [32]uints.U8
}

func (c *strawmanRegularStateRoot) Define(api frontend.API) error {
	return defineRegular(api, &c.RegularCircuit, &c.Op3bStateRoot)
}

// TestRegular_StateRootSingleSource — the load-bearing single-source proof. A forged
// finalized_header_root (a fake finality) folds to a fresh terminal. The strawman (separate
// Op3bStateRoot) SOLVES it (op-3b decoupled from op-3a) ∧ production (shared c.StateRoot)
// REJECTS it (op-3b must fold to op-3a's authenticated state_root). Strawman SOLVES ∧
// production REJECTS = the sharing is load-bearing.
func TestRegular_StateRootSingleSource(t *testing.T) {
	const n = 8
	s := buildSyntheticRegular(t, n, 0x01)

	// Forge a DIFFERENT finalized header (a fake finality the prover wants to inject).
	forgedFinalized := ssz.Header{
		Slot:          7777700, // different slot → different root than the real finalized header
		ProposerIndex: 1234,
		ParentRoot:    sha256.Sum256([]byte("forged parent")),
		StateRoot:     sha256.Sum256([]byte("forged state")),
		BodyRoot:      sha256.Sum256([]byte("forged body")),
	}
	forgedRoot := forgedFinalized.HashTreeRoot()
	forgedSlotBranch := forgedFinalized.SlotBranch()
	// op-3b would fold the forged root (via the real branch) to THIS — necessarily != the
	// attested state_root (different leaf, same branch, SHA collision resistance).
	forgedFold := ssz.Gindex169Walk(forgedRoot, s.finalityBranch)

	buildForged := func() *RegularCircuit {
		c := s.production() // real committee + real attested header (state_root R)
		c.FinalizedHeaderRoot = toCircuitBytes32(forgedRoot)
		for i := 0; i < 3; i++ {
			c.SlotBranch[i] = toCircuitBytes32(forgedSlotBranch[i])
		}
		c.FinalizedSlot = forgedFinalized.Slot
		c.FinalizedHeaderRootPacked = packRootRef(forgedRoot)
		return c
	}

	// STRAWMAN: op-3b's separate Op3bStateRoot = forgedFold → SOLVES (the hole exploitable).
	strawman := &strawmanRegularStateRoot{RegularCircuit: *buildForged(), Op3bStateRoot: toCircuitBytes32(forgedFold)}
	blankStrawman := &strawmanRegularStateRoot{RegularCircuit: *NewRegularCircuit(n)}
	if err := test.IsSolved(blankStrawman, strawman, ecc.BLS12_381.ScalarField()); err != nil {
		t.Fatalf("R7 NON-DECISIVE: strawman must SOLVE the forged finality (else the negative is vacuous): %v", err)
	}
	t.Logf("R7: strawman (separate op-3b state_root) SOLVES the forged finalized_header_root — hole exploitable")

	// PRODUCTION: op-3b uses the shared c.StateRoot (op-3a's real R) → REJECTS forgedFold != R.
	err := test.IsSolved(NewRegularCircuit(n), buildForged(), ecc.BLS12_381.ScalarField())
	if err == nil {
		t.Fatal("R7 HOLE: production SOLVED a forged finalized_header_root — single-source is NOT load-bearing")
	}
	t.Logf("R7 PASS: production REJECTS the same forged root (op-3b folds to op-3a's authenticated state_root): %v", err)
}
