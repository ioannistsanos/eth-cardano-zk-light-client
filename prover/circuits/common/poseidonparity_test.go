// poseidonparity_test.go — the DIRECT circuit↔off-chain Poseidon2 digest weld: one tiny
// circuit runs exactly the production hashing construction (NewPoseidon2FromParameters +
// Merkle–Damgård with initial state 0 — the committeebind.go bind / op6assemble.go Path-2
// shape), parameterized by the surfaced commitment.Poseidon* constants, over
// commitment.Pack's field elements — and must reproduce commitment.Commit as its public
// digest. The existing solve tests weld each production circuit to Commit transitively
// (through the assigned public input); this welds the parameter constants themselves, so a
// parameter drift on either side (or in gnark/gnark-crypto's constructions) fails here
// directly, with a negative proving the equality is load-bearing.
package common

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash"
	poseidon2perm "github.com/consensys/gnark/std/permutation/poseidon2"
	"github.com/consensys/gnark/test"

	"eth-cardano-zk-light-client/prover/offchain/commitment"
)

type poseidonCommitmentParityCircuit struct {
	PackedElements []frontend.Variable
	ExpectedDigest frontend.Variable `gnark:",public"`
}

func (c *poseidonCommitmentParityCircuit) Define(api frontend.API) error {
	permutation, err := poseidon2perm.NewPoseidon2FromParameters(
		api, commitment.PoseidonWidth, commitment.PoseidonFullRounds, commitment.PoseidonPartialRounds)
	if err != nil {
		return err
	}
	hasher := hash.NewMerkleDamgardHasher(api, permutation, 0)
	hasher.Write(c.PackedElements...)
	api.AssertIsEqual(hasher.Sum(), c.ExpectedDigest)
	return nil
}

// parityPoints returns n on-curve G1 points (k·G for k=1..n), the same deterministic
// construction the commitment package's own tests use.
func parityPoints(n int) []bls12381.G1Affine {
	_, _, g1Generator, _ := bls12381.Generators()
	points := make([]bls12381.G1Affine, n)
	for i := range points {
		points[i].ScalarMultiplication(&g1Generator, big.NewInt(int64(i+1)))
	}
	return points
}

func parityAssignment(points []bls12381.G1Affine, digest fr.Element) (blank, assignment *poseidonCommitmentParityCircuit) {
	packed := commitment.Pack(points)
	packedVariables := make([]frontend.Variable, len(packed))
	for i := range packed {
		packedVariables[i] = frElementToVar(packed[i])
	}
	blank = &poseidonCommitmentParityCircuit{PackedElements: make([]frontend.Variable, len(packed))}
	assignment = &poseidonCommitmentParityCircuit{
		PackedElements: packedVariables,
		ExpectedDigest: frElementToVar(digest),
	}
	return blank, assignment
}

// TestPoseidonParity_CircuitMatchesOffchainCommit: the production-shape in-circuit hasher,
// built from the surfaced constants, reproduces the off-chain Commit digest exactly.
func TestPoseidonParity_CircuitMatchesOffchainCommit(t *testing.T) {
	points := parityPoints(4)
	blank, assignment := parityAssignment(points, commitment.Commit(points))
	if err := test.IsSolved(blank, assignment, ecc.BLS12_381.ScalarField()); err != nil {
		t.Fatalf("in-circuit Poseidon2 digest != off-chain commitment.Commit: %v", err)
	}
}

// TestPoseidonParity_WrongDigestRejects: the equality is load-bearing — a digest off by one
// fails the solve.
func TestPoseidonParity_WrongDigestRejects(t *testing.T) {
	points := parityPoints(4)
	tamperedDigest := commitment.Commit(points)
	var one fr.Element
	one.SetOne()
	tamperedDigest.Add(&tamperedDigest, &one)
	blank, assignment := parityAssignment(points, tamperedDigest)
	if err := test.IsSolved(blank, assignment, ecc.BLS12_381.ScalarField()); err == nil {
		t.Fatal("tampered digest solved — the parity equality is not binding")
	}
}
