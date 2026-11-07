// Command measure_sha256 measures the R1CS constraint cost per SHA-256
// compression block (Phase 2a-2-i), in-circuit via gnark std/hash/sha2, over the
// BLS12-381 scalar field. Compile-only (no Setup/Prove): GetNbConstraints() after
// frontend.Compile, each size x2 (deterministic) or HALT. Linear regression over
// the 6 canonical 32+64k sizes (blocks 1..10): slope = per compression block.
//
// Usage: go run ./cmd/measure_sha256
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

// input bytes -> SHA-256 compression blocks: 32->1, 96->2, 160->3, 224->4,
// 288->5, 608->10  (blocks(L)=ceil((L+9)/64); all 32+64k, injective in blocks).
var sizes = []int{32, 96, 160, 224, 288, 608}

func main() {
	logger.Disable() // silence gnark compile logs; this tool prints only its table
	scalarField := ecc.BLS12_381.ScalarField()

	fmt.Println("# Phase 2a-2-i: in-circuit SHA-256 per-compression-block R1CS cost")
	fmt.Println("# native field = BLS12-381 scalar field; compile-only; each count x2 (determinism)")
	fmt.Printf("%-8s %8s %14s\n", "bytes", "blocks", "constraints")

	var xValues, yValues []float64
	for _, sizeBytes := range sizes {
		firstCount := compileCount(scalarField, sizeBytes)
		secondCount := compileCount(scalarField, sizeBytes)
		if firstCount != secondCount {
			fmt.Fprintf(os.Stderr, "HALT: non-deterministic count for %d bytes: %d != %d\n", sizeBytes, firstCount, secondCount)
			os.Exit(1)
		}
		blocks := common.Sha256Blocks(sizeBytes)
		fmt.Printf("%-8d %8d %14d\n", sizeBytes, blocks, firstCount)
		xValues = append(xValues, float64(blocks))
		yValues = append(yValues, float64(firstCount))
	}

	slope, intercept, rSquared := linearFit(xValues, yValues)
	fmt.Printf("\n# regression: constraints = intercept + slope*blocks\n")
	fmt.Printf("slope (per compression block) = %.2f\n", slope)
	fmt.Printf("intercept (uints/lookup setup + 32B assert) = %.2f\n", intercept)
	fmt.Printf("R2 = %.6f\n", rSquared)

	fmt.Printf("\n# Merkle-node + ops 3 & 4 mapping (node-hash = 64B = 2 compression blocks)\n")
	fmt.Printf("per-64B-node marginal = 2*slope = %.0f\n", 2*slope)
	fmt.Printf("op3 finality: 14 node-hashes = 28 blocks => 28*slope = %.0f  (+1 shared intercept)\n", 28*slope)
	fmt.Printf("op4 slot:      3 node-hashes =  6 blocks =>  6*slope = %.0f  (+1 shared intercept)\n", 6*slope)
}

func compileCount(scalarField *big.Int, lengthBytes int) int {
	constraintSystem, err := frontend.Compile(scalarField, r1cs.NewBuilder, common.NewSha256Circuit(lengthBytes))
	if err != nil {
		fmt.Fprintf(os.Stderr, "HALT: compile failed (%d bytes): %v\n", lengthBytes, err)
		os.Exit(1)
	}
	return constraintSystem.GetNbConstraints()
}

func linearFit(xValues, yValues []float64) (slope, intercept, rSquared float64) {
	count := float64(len(xValues))
	var sumX, sumY, sumXSquared, sumXY float64
	for i := range xValues {
		sumX += xValues[i]
		sumY += yValues[i]
		sumXSquared += xValues[i] * xValues[i]
		sumXY += xValues[i] * yValues[i]
	}
	slope = (count*sumXY - sumX*sumY) / (count*sumXSquared - sumX*sumX)
	intercept = (sumY - slope*sumX) / count
	mean := sumY / count
	var totalSumOfSquares, residualSumOfSquares float64
	for i := range xValues {
		deviation := yValues[i] - mean
		totalSumOfSquares += deviation * deviation
		residual := yValues[i] - (intercept + slope*xValues[i])
		residualSumOfSquares += residual * residual
	}
	rSquared = 1 - residualSumOfSquares/totalSumOfSquares
	return
}
