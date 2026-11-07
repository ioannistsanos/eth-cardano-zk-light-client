// Command measure_decompress_pubkey measures the R1CS cost of the 2b-ii op-6
// decompress-and-validate unit (on-curve + sign-match + canonical-x, per pubkey).
// Compile-only, x2 (deterministic, HALT on mismatch). Unlike the 2b-i SHA merkleization
// (~55M), this unit is small (~1.5-2.5M for 512), so N=512 compiles locally — measured
// directly, with a {64,128} slope as a safety net. Usage: go run ./cmd/measure_decompress_pubkey
package main

import (
	"fmt"
	"math/big"
	"os"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/logger"

	"eth-cardano-zk-light-client/prover/circuits/common"
)

func main() {
	logger.Disable()
	field := ecc.BLS12_381.ScalarField()
	fmt.Println("# 2b-ii: decompress-and-validate per-pubkey cost (on-curve + sign + canonical-x)")
	fmt.Println("# compile-only; x2 (determinism); HALT on mismatch")

	small := []int{64, 128}
	counts := make([]int, len(small))
	for i, n := range small {
		counts[i] = compileTwice(field, n)
		fmt.Printf("N=%-4d constraints = %d\n", n, counts[i])
	}
	slope := float64(counts[1]-counts[0]) / float64(small[1]-small[0])
	intercept := float64(counts[0]) - slope*float64(small[0])
	fmt.Printf("-> per-pubkey slope = %.0f ; intercept = %.0f\n", slope, intercept)
	fmt.Printf("-> EXTRAPOLATED 512 = %.0f (~%.2fM)\n", slope*512+intercept, (slope*512+intercept)/1e6)

	fmt.Println("\n# direct 512 compile (expected feasible, ~1.5-2.5M)")
	got := compileTwice(field, 512)
	fmt.Printf("N=512  constraints = %d (~%.2fM)\n", got, float64(got)/1e6)
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
	constraintSystem, err := frontend.Compile(field, r1cs.NewBuilder, common.NewDecompressPubkeyCircuit(n))
	if err != nil {
		fmt.Fprintf(os.Stderr, "HALT: compile N=%d: %v\n", n, err)
		os.Exit(1)
	}
	return constraintSystem.GetNbConstraints()
}
