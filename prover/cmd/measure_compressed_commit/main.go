// Command measure_compressed_commit measures encoding B's REGULAR per-update cost:
// serialize each emulated G1 point to its canonical 48-byte compressed form in-circuit
// (ToBitsCanonical(x) for the bytes + ToBitsCanonical(y) and a y>(p-1)/2 comparison for
// the lex-largest sign — the "canonical-form / y-parity logic"), then Poseidon-absorb
// the packed bytes. This is B's serialize+Poseidon; B-regular ALSO needs on-curve
// (measure_g1_validity). Compile-only, x2. (Encoding A is bare Poseidon over limbs —
// see measure_poseidon_commit — with no serialization.) COSTING PROBE for the SEC-01
// Family-B encoding decision (Step-2a); see docs/security/SEC-01-committee-binding-rogue-key.md.
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
	"github.com/consensys/gnark/std/math/bits"
	"github.com/consensys/gnark/std/math/emulated"
	poseidon2perm "github.com/consensys/gnark/std/permutation/poseidon2"
)

type compressedCommitCircuit struct {
	Points     []sw_bls12381.G1Affine
	Commitment frontend.Variable `gnark:",public"`
}

func newCompressedCommitCircuit(n int) *compressedCommitCircuit {
	return &compressedCommitCircuit{Points: make([]sw_bls12381.G1Affine, n)}
}

func (c *compressedCommitCircuit) Define(api frontend.API) error {
	field, err := emulated.NewField[sw_bls12381.BaseField](api)
	if err != nil {
		return err
	}
	perm, err := poseidon2perm.NewPoseidon2FromParameters(api, 2, 6, 50)
	if err != nil {
		return err
	}
	hasher := hash.NewMerkleDamgardHasher(api, perm, 0)

	p := ecc.BLS12_381.BaseField()
	halfModulus := new(big.Int).Rsh(new(big.Int).Sub(p, big.NewInt(1)), 1) // (p-1)/2

	for i := range c.Points {
		xBits := field.ToBitsCanonical(&c.Points[i].X) // 381 canonical LE bits (x bytes)
		yBits := field.ToBitsCanonical(&c.Points[i].Y) // 381 canonical LE bits (for the sign)
		signLargest := bitsGreaterThanConstant(api, yBits, halfModulus)
		// Pack the 381 x-bits + the sign flag into 2 native-Fr elements (free linear).
		lo := bits.FromBinary(api, xBits[0:254])
		hi := bits.FromBinary(api, append(append([]frontend.Variable{}, xBits[254:381]...), signLargest))
		hasher.Write(lo, hi)
	}
	api.AssertIsEqual(hasher.Sum(), c.Commitment)
	return nil
}

// bitsGreaterThanConstant returns 1 iff the little-endian bit value > constant.
func bitsGreaterThanConstant(api frontend.API, valueLE []frontend.Variable, constant *big.Int) frontend.Variable {
	isGreater := frontend.Variable(0)
	isEqualSoFar := frontend.Variable(1)
	for i := len(valueLE) - 1; i >= 0; i-- {
		vi := valueLE[i]
		if constant.Bit(i) == 0 {
			isGreater = api.Add(isGreater, api.Mul(isEqualSoFar, vi)) // first vi=1 while-equal => greater
			isEqualSoFar = api.Mul(isEqualSoFar, api.Sub(1, vi))      // equal continues iff vi=0
		} else {
			isEqualSoFar = api.Mul(isEqualSoFar, vi) // equal continues iff vi=1
		}
	}
	return isGreater
}

func main() {
	logger.Disable()
	scalarField := ecc.BLS12_381.ScalarField()
	fmt.Println("# Phase 2a: encoding B — in-circuit compressed serialization + Poseidon (regular path)")
	fmt.Println("# Poseidon2/BLS12-381 t=2,R_F=6,R_P=50,d=5; faithful: 2x ToBitsCanonical + y-sign compare + Poseidon")
	fmt.Println("# compile-only; x2 (determinism); HALT on mismatch")
	ns := []int{64, 128, 512}
	counts := make([]int, len(ns))
	for i, n := range ns {
		counts[i] = compileTwice(scalarField, n)
		fmt.Printf("N=%-4d constraints = %d\n", n, counts[i])
	}
	last := len(ns) - 1
	slope := float64(counts[last]-counts[0]) / float64(ns[last]-ns[0])
	fmt.Printf("-> per-pubkey ~= %.0f constraints; 512 = %d (serialize+Poseidon, EXCLUDES the on-curve B also needs)\n", slope, counts[last])
}

func compileTwice(field *big.Int, n int) int {
	a, b := compile(field, n), compile(field, n)
	if a != b {
		fmt.Fprintf(os.Stderr, "HALT: non-deterministic at N=%d: %d!=%d\n", n, a, b)
		os.Exit(1)
	}
	return a
}

func compile(field *big.Int, n int) int {
	cs, err := frontend.Compile(field, r1cs.NewBuilder, newCompressedCommitCircuit(n))
	if err != nil {
		fmt.Fprintf(os.Stderr, "HALT: compile N=%d: %v\n", n, err)
		os.Exit(1)
	}
	return cs.GetNbConstraints()
}
