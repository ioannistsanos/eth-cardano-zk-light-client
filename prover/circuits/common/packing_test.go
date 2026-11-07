package common

// packRoot endianness lock. packRoot is a PUBLIC-INPUT spec the Plutus verifier
// re-derives on-chain (byteStringToInteger over two 16-byte halves), so a circuit-vs-
// Plutus endianness mismatch is a SILENT on-chain break — not caught in-circuit (the
// circuit is internally consistent either way). This suite pins the in-circuit packRoot
// against an EXPLICIT big-endian off-circuit reference (the way the verifier computes
// it), on roots chosen to expose any byte-order/half-order bug.

import (
	"crypto/sha256"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/test"
)

// packRootBigEndianReference is the OFF-CIRCUIT reference computed EXPLICITLY big-endian
// (new(big.Int).SetBytes is big-endian) — the way the Plutus verifier re-derives the two
// public inputs. The in-circuit packRoot must reproduce this EXACTLY; this is the lock.
func packRootBigEndianReference(root [32]byte) [2]*big.Int {
	return [2]*big.Int{
		new(big.Int).SetBytes(root[0:16]),  // big-endian first 16 bytes
		new(big.Int).SetBytes(root[16:32]), // big-endian last 16 bytes
	}
}

type packRootTestCircuit struct {
	Root     [32]uints.U8
	Expected [2]frontend.Variable `gnark:",public"`
}

func (c *packRootTestCircuit) Define(api frontend.API) error {
	packed := packRoot(api, c.Root[:])
	api.AssertIsEqual(packed[0], c.Expected[0])
	api.AssertIsEqual(packed[1], c.Expected[1])
	return nil
}

func packRootAssignment(root [32]byte) *packRootTestCircuit {
	reference := packRootBigEndianReference(root)
	assignment := &packRootTestCircuit{
		Root:     toCircuitBytes32(root),
		Expected: [2]frontend.Variable{reference[0], reference[1]},
	}
	return assignment
}

// incrementingRoot[k] = k+1 — an asymmetric pattern (root[0]=1 … root[31]=32) so a
// little-endian or swapped-half bug produces a different integer than the reference.
func incrementingRoot() (root [32]byte) {
	for k := range root {
		root[k] = byte(k + 1)
	}
	return
}

// TestPackRoot_MatchesBigEndianHalves: in-circuit packRoot == the explicit big-endian
// off-circuit reference, on (a) a real SHA-256 root, (b) the incrementing pattern, and
// (c) {0xff, 0…0} — which puts the only nonzero byte in the MSB position, so a
// little-endian bug would yield 255 instead of 255·2^120 (a decisive endianness probe).
func TestPackRoot_MatchesBigEndianHalves(t *testing.T) {
	msbProbe := [32]byte{0xff} // 0xff at index 0, rest zero
	roots := map[string][32]byte{
		"sha256":       sha256.Sum256([]byte("regular-circuit packRoot endianness lock")),
		"incrementing": incrementingRoot(),
		"msb-probe":    msbProbe,
		"all-zero":     {},
	}
	for name, root := range roots {
		if err := test.IsSolved(&packRootTestCircuit{}, packRootAssignment(root), ecc.BLS12_381.ScalarField()); err != nil {
			t.Fatalf("packRoot != big-endian reference on %q (endianness/half-order bug): %v", name, err)
		}
	}
	// Decisive: the msb-probe's expected high half is 0xff·2^120, NOT 255.
	ref := packRootBigEndianReference(msbProbe)
	want := new(big.Int).Lsh(big.NewInt(0xff), 120)
	if ref[0].Cmp(want) != 0 || ref[1].Sign() != 0 {
		t.Fatalf("reference is not big-endian: got [%s, %s]", ref[0], ref[1])
	}
	t.Logf("PASS: packRoot == off-circuit big-endian 16-byte halves (the locked Plutus-verifier spec); msb-probe high half = 0xff·2^120")
}

// TestPackRoot_Proves: full Groth16 Setup->Prove->Verify over BLS12-381 (provability).
func TestPackRoot_Proves(t *testing.T) {
	assignment := packRootAssignment(sha256.Sum256([]byte("packRoot groth16")))
	scalarField := ecc.BLS12_381.ScalarField()
	constraintSystem, err := frontend.Compile(scalarField, r1cs.NewBuilder, &packRootTestCircuit{})
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
	t.Logf("PASS: packRoot Groth16 (%d constraints)", constraintSystem.GetNbConstraints())
}
