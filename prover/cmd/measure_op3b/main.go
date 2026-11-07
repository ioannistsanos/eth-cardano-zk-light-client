// Command measure_op3b measures the finality-branch circuit (op-3b, gindex 169)
// R1CS cost over the BLS12-381 scalar field, compile-only (x2). Decomposes the
// fixed 7-node-hash walk against op-4's measured per-node-hash (53,672) and
// intercept (131,380) — op-3b has NO leaf encoding (the leaf is already a 32-byte
// root). Usage: go run ./cmd/measure_op3b
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
	fmt.Println("# op-3b: finality-branch circuit (gindex 169, [R,L,L,R,L,R,L]) R1CS cost")
	fmt.Println("# native field = BLS12-381 scalar field; compile-only; x2 (determinism)")

	firstCount := compileCount(scalarField)
	secondCount := compileCount(scalarField)
	if firstCount != secondCount {
		fmt.Fprintf(os.Stderr, "HALT: non-deterministic count: %d != %d\n", firstCount, secondCount)
		os.Exit(1)
	}
	fmt.Printf("op-3b (7-step finality branch walk) MEASURED = %d\n", firstCount)

	// Decompose against op-4's measured references (single fixed circuit, no regression).
	const perNodeHash = 53672.0     // op-4 measured per 64-byte node-hash
	const uintsIntercept = 131380.0 // op-4/D8 uints/lookup intercept
	expected := 7*perNodeHash + uintsIntercept
	impliedPerHash := (float64(firstCount) - uintsIntercept) / 7
	fmt.Printf("\n# decomposition (op-4 references: 53,672/node-hash, 131,380 intercept; NO leaf encoding)\n")
	fmt.Printf("7 node-hashes x 53,672 = %.0f   (the assembled-circuit MARGINAL, intercept shared)\n", 7*perNodeHash)
	fmt.Printf("+ 131,380 intercept => expected standalone ~= %.0f\n", expected)
	fmt.Printf("implied per-node-hash = (total - 131,380) / 7 = %.0f   (vs op-4 53,672)\n", impliedPerHash)
	fmt.Printf("op-3a standalone reference = 504,292 (7 hashes + intercept + 2 leaf-encodings)\n")
}

func compileCount(scalarField *big.Int) int {
	constraintSystem, err := frontend.Compile(scalarField, r1cs.NewBuilder, &common.FinalityBranchCircuit{})
	if err != nil {
		fmt.Fprintf(os.Stderr, "HALT: compile failed: %v\n", err)
		os.Exit(1)
	}
	return constraintSystem.GetNbConstraints()
}
