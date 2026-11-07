// Command measure_poseidon_commit measures the in-circuit R1CS cost of a Poseidon2
// commitment over N BLS12-381 G1 sync-committee pubkeys — the per-update cost a
// SEC-01 Family-B fix would pay to re-bind the witness keys to a persisted
// commitment (docs/security/SEC-01-committee-binding-rogue-key.md). Compile-only,
// x2 (deterministic, HALT on mismatch). This is a COSTING PROBE for the SEC-01
// Family-A-vs-B decision and the Step-2a encoding decision (the full-limb 0.38M/1.14M
// source); NOT a Phase-A circuit, NOT the translation design.
//
// Faithful representation: pubkeys are the same emulated sw_bls12381.G1Affine type
// op-1/op-2 consume. BLS12381Fp is a 6x64-bit limb field, so each point is already
// 12 native-Fr limbs (.X.Limbs, .Y.Limbs) — the "Fp->Fr field decomposition" is
// gnark's real limb layout, reused at zero marginal cost, NOT an idealized single
// field element. Two encodings are measured:
//   - "limbs":  absorb all 12 raw limbs/pubkey (conservative high Fr-count).
//   - "packed": fold each coordinate's 6 limbs into 2 Fr by a FREE linear
//     combination (3x64=192 bits < 255-bit Fr) -> 4 Fr/pubkey.
//
// Poseidon2 over BLS12-381 Fr: t=2, R_F=6, R_P=50, d=5 (gnark-crypto canonical
// GetDefaultParameters), via NewPoseidon2FromParameters + Merkle-Damgard, which
// applies ONE width-2 permutation per absorbed Fr element. The default
// NewMerkleDamgardHasher(api) is NOT used (it only wires BLS12-377).
// Usage: go run ./cmd/measure_poseidon_commit
// SEC-01 Family-B encoding decision (Step-2a): docs/security/SEC-01-committee-binding-rogue-key.md
package main

import (
	"fmt"
	"math/big"
	"os"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/logger"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bls12381"
	"github.com/consensys/gnark/std/hash"
	poseidon2perm "github.com/consensys/gnark/std/permutation/poseidon2"
)

// poseidonCommitCircuit commits N emulated G1 pubkeys (witness) to a public Poseidon2
// digest. packed selects the limb encoding (12 raw limbs vs 4 packed Fr per pubkey).
type poseidonCommitCircuit struct {
	Pubkeys    []sw_bls12381.G1Affine
	Commitment frontend.Variable `gnark:",public"`

	packed bool // unexported: not part of the witness schema (cf. g1add useUnifiedAdd)
}

func newPoseidonCommitCircuit(numberOfPubkeys int, packed bool) *poseidonCommitCircuit {
	return &poseidonCommitCircuit{
		Pubkeys: make([]sw_bls12381.G1Affine, numberOfPubkeys),
		packed:  packed,
	}
}

func (c *poseidonCommitCircuit) Define(api frontend.API) error {
	// Canonical BLS12-381 Poseidon2 (t=2, R_F=6, R_P=50, d=5); round keys match
	// gnark-crypto GetDefaultParameters(). Merkle-Damgard => 1 permutation / Fr element.
	permutation, err := poseidon2perm.NewPoseidon2FromParameters(api, 2, 6, 50)
	if err != nil {
		return err
	}
	hasher := hash.NewMerkleDamgardHasher(api, permutation, 0)

	two64 := new(big.Int).Lsh(big.NewInt(1), 64)
	two128 := new(big.Int).Lsh(big.NewInt(1), 128)
	for i := range c.Pubkeys {
		if c.packed {
			hasher.Write(packCoordinate(api, c.Pubkeys[i].X.Limbs, two64, two128)...)
			hasher.Write(packCoordinate(api, c.Pubkeys[i].Y.Limbs, two64, two128)...)
		} else {
			// Raw emulated limbs: gnark's real Fp->Fr decomposition op-1/op-2 already produce.
			hasher.Write(c.Pubkeys[i].X.Limbs...)
			hasher.Write(c.Pubkeys[i].Y.Limbs...)
		}
	}
	api.AssertIsEqual(hasher.Sum(), c.Commitment)
	return nil
}

// packCoordinate folds 6 limbs (l0..l5, each < 2^64) into 2 native-Fr elements:
// lo = l0 + l1*2^64 + l2*2^128, hi = l3 + l4*2^64 + l5*2^128. Multiplication by a
// constant and addition are linear in R1CS, so this emits ZERO constraints.
func packCoordinate(api frontend.API, limbs []frontend.Variable, two64, two128 *big.Int) []frontend.Variable {
	lo := api.Add(limbs[0], api.Mul(limbs[1], two64), api.Mul(limbs[2], two128))
	hi := api.Add(limbs[3], api.Mul(limbs[4], two64), api.Mul(limbs[5], two128))
	return []frontend.Variable{lo, hi}
}

func main() {
	logger.Disable()
	scalarField := ecc.BLS12_381.ScalarField()
	fmt.Println("# Phase 2 (SEC-01 A-vs-B): Poseidon2 commitment over N BLS12-381 G1 pubkeys")
	fmt.Println("# Poseidon2/BLS12-381 Fr: t=2, R_F=6, R_P=50, d=5 (gnark-crypto canonical); Merkle-Damgard (1 perm/Fr)")
	fmt.Println("# faithful: pubkeys are emulated sw_bls12381.G1Affine -> 6x64-bit limbs/coord = 12 limbs/point")
	fmt.Println("# compile-only; x2 (determinism); HALT on mismatch")

	pubkeyCounts := []int{64, 128, 512}
	const familyA = 55_000_000.0 // Family A SSZ merkleization of 512 keys (~55M, from our ~53.7K/node-hash)

	for _, variant := range []struct {
		name        string
		packed      bool
		frPerPubkey int
	}{
		{"limbs  (12 Fr/pubkey, raw emulated limbs)", false, 12},
		{"packed (4 Fr/pubkey, free linear repack)", true, 4},
	} {
		fmt.Printf("\n## encoding = %s\n", variant.name)
		counts := make([]int, len(pubkeyCounts))
		for i, n := range pubkeyCounts {
			counts[i] = compileCountTwice(scalarField, n, variant.packed)
			fmt.Printf("N=%-4d constraints = %d\n", n, counts[i])
		}
		first, last := 0, len(pubkeyCounts)-1
		slope := float64(counts[last]-counts[first]) / float64(pubkeyCounts[last]-pubkeyCounts[first])
		intercept := float64(counts[first]) - slope*float64(pubkeyCounts[first])
		perPermutation := slope / float64(variant.frPerPubkey)
		fmt.Printf("-> linear fit: %.1f constraints/pubkey, intercept %.0f\n", slope, intercept)
		fmt.Printf("-> implied %.1f constraints/permutation (%d Fr/pubkey; ~186 predicted = 62 S-boxes x 3 muls)\n",
			perPermutation, variant.frPerPubkey)
		fmt.Printf("-> 512-pubkey commitment = %d constraints\n", counts[last])
		fmt.Printf("-> vs Family A SSZ ~55M/update: %.0fx cheaper per update\n", familyA/float64(counts[last]))
	}
}

func compileCountTwice(scalarField *big.Int, numberOfPubkeys int, packed bool) int {
	first := compileCount(scalarField, numberOfPubkeys, packed)
	second := compileCount(scalarField, numberOfPubkeys, packed)
	if first != second {
		fmt.Fprintf(os.Stderr, "HALT: non-deterministic count at N=%d packed=%v: %d != %d\n",
			numberOfPubkeys, packed, first, second)
		os.Exit(1)
	}
	return first
}

func compileCount(scalarField *big.Int, numberOfPubkeys int, packed bool) int {
	constraintSystem, err := frontend.Compile(scalarField, r1cs.NewBuilder, newPoseidonCommitCircuit(numberOfPubkeys, packed))
	if err != nil {
		fmt.Fprintf(os.Stderr, "HALT: compile failed at N=%d packed=%v: %v\n", numberOfPubkeys, packed, err)
		os.Exit(1)
	}
	return constraintSystem.GetNbConstraints()
}
