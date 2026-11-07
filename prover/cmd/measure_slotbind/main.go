// Command measure_slotbind measures the slot-binding circuit (op-4) R1CS cost over
// the BLS12-381 scalar field, compile-only (x2). It compiles 1/2/3 Merkle steps to
// decompose: slope = per Merkle step (one 64-byte node-hash = 2 SHA-256
// compression blocks), intercept = leaf-encoding + uints/lookup setup. The 3-step
// count is the real op-4 cost. Usage: go run ./cmd/measure_slotbind
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
	scalarField := ecc.BLS12_381.ScalarField()
	fmt.Println("# Phase 2a-2-ii-A: slot-binding Merkle circuit (op-4) R1CS cost")
	fmt.Println("# native field = BLS12-381 scalar field; compile-only; each count x2")
	fmt.Printf("%-8s %14s\n", "steps", "constraints")

	counts := map[int]int{}
	for _, steps := range []int{1, 2, 3} {
		firstCount := compileCount(scalarField, steps)
		secondCount := compileCount(scalarField, steps)
		if firstCount != secondCount {
			fmt.Fprintf(os.Stderr, "HALT: non-deterministic count steps=%d: %d != %d\n", steps, firstCount, secondCount)
			os.Exit(1)
		}
		fmt.Printf("%-8d %14d\n", steps, firstCount)
		counts[steps] = firstCount
	}
	slope := float64(counts[3]-counts[1]) / 2.0
	intercept := float64(counts[1]) - slope
	fmt.Printf("\n# decomposition: constraints = intercept + slope*steps\n")
	fmt.Printf("per-Merkle-step (1 node-hash = 64B = 2 compression blocks) = %.1f\n", slope)
	fmt.Printf("intercept (leaf-encoding + uints/lookup setup + 32B assert) = %.1f\n", intercept)
	fmt.Printf("linearity check: c2 == intercept+2*slope ? %v (c2=%d, pred=%.0f)\n",
		counts[2] == int(intercept+2*slope+0.5), counts[2], intercept+2*slope)
	fmt.Printf("op-4 (3 steps) MEASURED = %d\n", counts[3])
	fmt.Printf("# D8 ref: 27,627/compression block => 2*D8=%.0f/node-hash, 6 blocks=%.0f\n", 2*27627.46, 6*27627.46)
}

func compileCount(scalarField *big.Int, steps int) int {
	constraintSystem, err := frontend.Compile(scalarField, r1cs.NewBuilder, common.NewSlotBindCircuit(steps))
	if err != nil {
		fmt.Fprintf(os.Stderr, "HALT: compile failed steps=%d: %v\n", steps, err)
		os.Exit(1)
	}
	return constraintSystem.GetNbConstraints()
}
