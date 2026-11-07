package common

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bls12381"
)

// TestG1AddUnifiedProvesOverBLS12381 confirms we drive the gadget correctly:
// with distinct known points P=3G, Q=5G, in-circuit AddUnified(P,Q) must equal
// the off-circuit P+Q=8G, proven end-to-end with Groth16 over BLS12-381.
//
// The Groth16 proof is randomized — NOT byte-identical run-to-run; expected, not
// asserted. We assert only that Verify passes. (Constraint counts, measured
// separately in cmd/measure_g1add, ARE deterministic.)
func TestG1AddUnifiedProvesOverBLS12381(t *testing.T) {
	_, _, generator, _ := bls12381.Generators()
	var pointP, pointQ, expectedSum bls12381.G1Affine
	pointP.ScalarMultiplication(&generator, big.NewInt(3)) // 3G
	pointQ.ScalarMultiplication(&generator, big.NewInt(5)) // 5G  (distinct, != +-P, nonzero)
	expectedSum.Add(&pointP, &pointQ)                      // 8G  (expected, off-circuit)

	scalarField := ecc.BLS12_381.ScalarField()
	constraintSystem, err := frontend.Compile(scalarField, r1cs.NewBuilder, &G1AddCheckCircuit{})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	provingKey, verifyingKey, err := groth16.Setup(constraintSystem)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	witness, err := frontend.NewWitness(&G1AddCheckCircuit{
		PointP:      sw_bls12381.NewG1Affine(pointP),
		PointQ:      sw_bls12381.NewG1Affine(pointQ),
		ExpectedSum: sw_bls12381.NewG1Affine(expectedSum),
	}, scalarField)
	if err != nil {
		t.Fatalf("witness: %v", err)
	}
	publicWitness, err := witness.Public()
	if err != nil {
		t.Fatalf("public witness: %v", err)
	}
	proof, err := groth16.Prove(constraintSystem, provingKey, witness)
	if err != nil {
		t.Fatalf("prove: %v", err)
	}
	if err := groth16.Verify(proof, verifyingKey, publicWitness); err != nil {
		t.Fatalf("verify: %v", err)
	}
	t.Logf("PASS: AddUnified(3G,5G)==8G verified over BLS12-381 (%d R1CS constraints)", constraintSystem.GetNbConstraints())
}
