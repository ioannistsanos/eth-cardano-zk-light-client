package common

import (
	"crypto/sha256"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/math/uints"
)

// TestSha256ProvesOverBLS12381 confirms we drive the sha2 gadget correctly: the
// in-circuit SHA-256 of a known 64-byte message (a Merkle-node-sized input) must
// equal crypto/sha256.Sum256 of the same bytes, proven end-to-end with Groth16
// over BLS12-381. The proof is randomized (not byte-identical, expected, not
// asserted); only Verify is asserted. Constraint counts (cmd/measure_sha256) are
// deterministic.
func TestSha256ProvesOverBLS12381(t *testing.T) {
	message := make([]byte, 64)
	for i := range message {
		message[i] = byte(i) // fixed known 64-byte input (0x00..0x3f)
	}
	digest := sha256.Sum256(message)

	scalarField := ecc.BLS12_381.ScalarField()
	constraintSystem, err := frontend.Compile(scalarField, r1cs.NewBuilder, NewSha256Circuit(len(message)))
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	provingKey, verifyingKey, err := groth16.Setup(constraintSystem)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	witness, err := frontend.NewWitness(&Sha256Circuit{
		In:       uints.NewU8Array(message),
		Expected: [32]uints.U8(uints.NewU8Array(digest[:])),
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
	t.Logf("PASS: in-circuit SHA-256(64B)==crypto/sha256 over BLS12-381 (%d constraints, %d blocks)",
		constraintSystem.GetNbConstraints(), Sha256Blocks(len(message)))
}
