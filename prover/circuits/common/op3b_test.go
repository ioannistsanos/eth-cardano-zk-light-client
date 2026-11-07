package common

// op-3b (finality branch, gindex 169) test suite — all on the REAL Electra
// period-1600 instance (testdata/lightclientupdate/, extended with
// finalized_header + finality_branch from the same re-fetched update):
//   - Go real-data anchor (off-circuit): HashTreeRoot(finalized_header) ->
//     Gindex169Walk [R,L,L,R,L,R,L] == real attested state_root. The second,
//     in-repo confirmation (the first was the independent Python verification at
//     fixture-extension time) — non-circular, Ethereum computed the state_root.
//   - positive: the real instance solves AND proves (full Groth16).
//   - negatives: tampered leaf / tampered sibling / one-step-swapped fold all
//     REJECT — the walk has teeth and the L/R constant is live in-circuit.

import (
	"strconv"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/test"

	"eth-cardano-zk-light-client/prover/offchain/ssz"
)

// loadFinalityInstance returns the real finalized header, the 7-sibling finality
// branch, and the attested state_root (the walk target) from the extended fixture.
// The arity gate is the fork check: 7 = Electra gindex 169 (depth 7); 6 would be
// the pre-Electra gindex-105 layout.
func loadFinalityInstance(t *testing.T) (ssz.Header, [7][32]byte, [32]byte) {
	t.Helper()
	fixture := loadLightClientUpdate(t)
	if len(fixture.FinalityBranch) != 7 {
		t.Fatalf("FORK MISMATCH (HALT): expected a depth-7 finality_branch (Electra gindex 169), got %d nodes (6 = pre-Electra gindex 105)", len(fixture.FinalityBranch))
	}
	slot, err := strconv.ParseUint(fixture.FinalizedHeader.Slot, 10, 64)
	if err != nil {
		t.Fatalf("finalized_header.slot: %v", err)
	}
	proposerIndex, err := strconv.ParseUint(fixture.FinalizedHeader.ProposerIndex, 10, 64)
	if err != nil {
		t.Fatalf("finalized_header.proposer_index: %v", err)
	}
	header := ssz.Header{
		Slot:          slot,
		ProposerIndex: proposerIndex,
		ParentRoot:    decodeHex32(t, fixture.FinalizedHeader.ParentRoot),
		StateRoot:     decodeHex32(t, fixture.FinalizedHeader.StateRoot),
		BodyRoot:      decodeHex32(t, fixture.FinalizedHeader.BodyRoot),
	}
	var branch [7][32]byte
	for i, siblingHex := range fixture.FinalityBranch {
		branch[i] = decodeHex32(t, siblingHex)
	}
	return header, branch, decodeHex32(t, fixture.AttestedStateRoot)
}

func finalityAssignment(finalizedHeaderRoot [32]byte, branch [7][32]byte, stateRoot [32]byte) *FinalityBranchCircuit {
	assignment := &FinalityBranchCircuit{
		FinalizedHeaderRoot: toCircuitBytes32(finalizedHeaderRoot),
		StateRoot:           toCircuitBytes32(stateRoot),
	}
	for i := range branch {
		assignment.FinalityBranch[i] = toCircuitBytes32(branch[i])
	}
	return assignment
}

func solveFinalityBranch(assignment *FinalityBranchCircuit) error {
	return test.IsSolved(&FinalityBranchCircuit{}, assignment, ecc.BLS12_381.ScalarField())
}

// TestFinalityBranchAnchorsToRealEthereum: HashTreeRoot(finalized_header) ->
// Gindex169Walk([R,L,L,R,L,R,L]) == real attested_header.beacon.state_root.
// NON-CIRCULAR: Ethereum computed the state_root, not us — a wrong gindex/fold
// cannot reach it. This is the in-repo Go confirmation of the independent Python
// pin run at fixture-extension time.
func TestFinalityBranchAnchorsToRealEthereum(t *testing.T) {
	header, branch, stateRoot := loadFinalityInstance(t)
	finalizedHeaderRoot := header.HashTreeRoot()
	computed := ssz.Gindex169Walk(finalizedHeaderRoot, branch)
	if computed != stateRoot {
		t.Fatalf("ANCHOR FAILED (HALT): our gindex-169 fold != real state_root\n"+
			"  computed = 0x%x\n  expected = 0x%x\n"+
			"  => the Go [R,L,L,R,L,R,L] fold differs from real Ethereum (the independent Python pin passed, so this is a Go-side bug)",
			computed, stateRoot)
	}
	t.Logf("PASS: gindex-169 fold reproduces REAL Ethereum (7-element Electra finality branch)")
	t.Logf("  finalized_header_root (leaf)  = 0x%x", finalizedHeaderRoot)
	t.Logf("  state_root (matched target)   = 0x%x", computed)
}

// TestFinalityBranch_PositiveSolvesOnRealData: the real instance satisfies the
// in-circuit walk (solver-level).
func TestFinalityBranch_PositiveSolvesOnRealData(t *testing.T) {
	header, branch, stateRoot := loadFinalityInstance(t)
	if err := solveFinalityBranch(finalityAssignment(header.HashTreeRoot(), branch, stateRoot)); err != nil {
		t.Fatalf("positive real instance must solve: %v", err)
	}
}

// TestFinalityBranch_ProvesOnRealData: full Groth16 Setup->Prove->Verify over
// BLS12-381 on the real instance (the decisive functional check, like op-3a/op-4).
func TestFinalityBranch_ProvesOnRealData(t *testing.T) {
	header, branch, stateRoot := loadFinalityInstance(t)
	assignment := finalityAssignment(header.HashTreeRoot(), branch, stateRoot)

	scalarField := ecc.BLS12_381.ScalarField()
	constraintSystem, err := frontend.Compile(scalarField, r1cs.NewBuilder, &FinalityBranchCircuit{})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	provingKey, verifyingKey, err := groth16.Setup(constraintSystem)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	witness, err := frontend.NewWitness(assignment, scalarField)
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
	t.Logf("PASS: real finality branch proven (%d constraints)", constraintSystem.GetNbConstraints())
}

// TestFinalityBranch_TamperedLeafRejected: flip one byte of finalized_header_root
// -> the fold no longer reaches state_root -> the terminal ByteAssertEq REJECTS.
func TestFinalityBranch_TamperedLeafRejected(t *testing.T) {
	header, branch, stateRoot := loadFinalityInstance(t)
	tamperedLeaf := header.HashTreeRoot()
	tamperedLeaf[0] ^= 0x01
	err := solveFinalityBranch(finalityAssignment(tamperedLeaf, branch, stateRoot))
	if err == nil {
		t.Fatal("HOLE: tampered finalized_header_root SOLVED — the walk has no teeth on the leaf")
	}
	t.Logf("rejected as expected (terminal StateRoot ByteAssertEq): %v", err)
}

// TestFinalityBranch_TamperedSiblingRejected: flip one byte of one branch sibling
// -> REJECT (teeth on the witness branch).
func TestFinalityBranch_TamperedSiblingRejected(t *testing.T) {
	header, branch, stateRoot := loadFinalityInstance(t)
	branch[3][0] ^= 0x01
	err := solveFinalityBranch(finalityAssignment(header.HashTreeRoot(), branch, stateRoot))
	if err == nil {
		t.Fatal("HOLE: tampered finality_branch sibling SOLVED — the walk has no teeth on the branch")
	}
	t.Logf("rejected as expected (terminal StateRoot ByteAssertEq): %v", err)
}

// wrongFoldFinalityCircuit is the MUTANT for the wrong-fold negative: identical to
// FinalityBranchCircuit except step 0 of the L/R pattern is swapped. Derived FROM
// the production constant (array copy + flip), so it tracks any future edit to it.
// On the REAL witness it must FAIL — proving the gindex169NodeIsRightChild constant
// is live in-circuit (the walk actually uses the per-step sides).
type wrongFoldFinalityCircuit struct {
	FinalizedHeaderRoot [32]uints.U8 `gnark:",public"`
	StateRoot           [32]uints.U8 `gnark:",public"`
	FinalityBranch      [7][32]uints.U8
}

func (c *wrongFoldFinalityCircuit) Define(api frontend.API) error {
	uintsAPI, err := uints.New[uints.U32](api)
	if err != nil {
		return err
	}
	mutatedPattern := gindex169NodeIsRightChild // value copy of the [7]bool array
	mutatedPattern[0] = !mutatedPattern[0]      // the single-step mutation (R->L at step 0)
	merkleizer := &sszMerkleizer{api: api}
	node := c.FinalizedHeaderRoot[:]
	for step := range c.FinalityBranch {
		if mutatedPattern[step] {
			node = merkleizer.parent(c.FinalityBranch[step][:], node)
		} else {
			node = merkleizer.parent(node, c.FinalityBranch[step][:])
		}
	}
	if err := merkleizer.Err(); err != nil {
		return err
	}
	for j := 0; j < 32; j++ {
		uintsAPI.ByteAssertEq(c.StateRoot[j], node[j])
	}
	return nil
}

// TestFinalityBranch_WrongFoldRejected: the step-0-swapped fold on the REAL witness
// must not reach the real state_root.
func TestFinalityBranch_WrongFoldRejected(t *testing.T) {
	header, branch, stateRoot := loadFinalityInstance(t)
	finalizedHeaderRoot := header.HashTreeRoot()
	mutantAssignment := &wrongFoldFinalityCircuit{
		FinalizedHeaderRoot: toCircuitBytes32(finalizedHeaderRoot),
		StateRoot:           toCircuitBytes32(stateRoot),
	}
	for i := range branch {
		mutantAssignment.FinalityBranch[i] = toCircuitBytes32(branch[i])
	}
	err := test.IsSolved(&wrongFoldFinalityCircuit{}, mutantAssignment, ecc.BLS12_381.ScalarField())
	if err == nil {
		t.Fatal("HOLE: the step-0-swapped fold SOLVED on the real witness — the L/R pattern is not live in-circuit")
	}
	t.Logf("rejected as expected (mutated fold misses the real state_root at the terminal ByteAssertEq): %v", err)
}
