package common

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

// TestHeaderReconstructProvesAgainstOfficialRoot: reconstruct the full
// BeaconBlockHeader root from the 5 fields of the validated Fulu vector and prove
// BOTH (a) reconstructedRoot == authoritative attested_header_root AND (b) the
// extracted state_root == the vector's state_root (the op-3b wire). Full
// Setup->Prove->Verify over BLS12-381. (Helpers loadHeader/officialRoot/
// toCircuitBytes32 are shared from slotbind_test.go — same package.)
func TestHeaderReconstructProvesAgainstOfficialRoot(t *testing.T) {
	header := loadHeader(t)
	root := header.HashTreeRoot()
	if root != officialRoot(t) {
		t.Fatalf("off-circuit htr != official roots.yaml root (data/ssz bug, not circuit)")
	}

	assignment := &HeaderReconstructCircuit{
		Slot:               header.Slot,
		ProposerIndex:      header.ProposerIndex,
		ParentRoot:         toCircuitBytes32(header.ParentRoot),
		StateRoot:          toCircuitBytes32(header.StateRoot),
		BodyRoot:           toCircuitBytes32(header.BodyRoot),
		AttestedHeaderRoot: toCircuitBytes32(root),
		ExtractedStateRoot: toCircuitBytes32(header.StateRoot),
	}

	scalarField := ecc.BLS12_381.ScalarField()
	constraintSystem, err := frontend.Compile(scalarField, r1cs.NewBuilder, &HeaderReconstructCircuit{})
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
	t.Logf("PASS: header reconstructed to official root 0x%x; state_root extracted 0x%x (%d constraints)",
		root, header.StateRoot, constraintSystem.GetNbConstraints())
}
