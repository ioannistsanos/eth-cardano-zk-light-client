// Command measure_headerreconstruct measures the header-reconstruction circuit
// (op-3a) R1CS cost over the BLS12-381 scalar field, compile-only (x2). Decomposes
// the single fixed 7-SHA-256 tree against op-4's measured per-node-hash (53,672)
// and intercept (131,380). Usage: go run ./cmd/measure_headerreconstruct
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
	fmt.Println("# Phase 2a-2-ii-B: header-reconstruction circuit (op-3a) R1CS cost")
	fmt.Println("# native field = BLS12-381 scalar field; compile-only; x2 (determinism)")

	firstCount := compileCount(scalarField)
	secondCount := compileCount(scalarField)
	if firstCount != secondCount {
		fmt.Fprintf(os.Stderr, "HALT: non-deterministic count: %d != %d\n", firstCount, secondCount)
		os.Exit(1)
	}
	fmt.Printf("op-3a (full reconstruction, 7 SHA-256) MEASURED = %d\n", firstCount)

	// Decompose against op-4's measured references (single fixed circuit, no regression).
	const perNodeHash = 53672.0     // op-4 measured per 64-byte node-hash
	const uintsIntercept = 131380.0 // op-4/D8 uints/lookup intercept
	const leafEncoding = 569.0      // op-4 measured per LE-leaf encoding
	expected := 7*perNodeHash + uintsIntercept + 2*leafEncoding
	impliedPerHash := (float64(firstCount) - uintsIntercept - 2*leafEncoding) / 7
	fmt.Printf("\n# decomposition (op-4 references: 53,672/node-hash, 131,380 intercept, 569/leaf)\n")
	fmt.Printf("7 node-hashes x 53,672 = %.0f\n", 7*perNodeHash)
	fmt.Printf("+ 131,380 intercept + 2x569 leaf-encoding => expected ~= %.0f\n", expected)
	fmt.Printf("implied per-node-hash = (total - 131,380 - 2x569) / 7 = %.0f   (vs op-4 53,672)\n", impliedPerHash)
}

func compileCount(scalarField *big.Int) int {
	constraintSystem, err := frontend.Compile(scalarField, r1cs.NewBuilder, &common.HeaderReconstructCircuit{})
	if err != nil {
		fmt.Fprintf(os.Stderr, "HALT: compile failed: %v\n", err)
		os.Exit(1)
	}
	return constraintSystem.GetNbConstraints()
}
