// Command measure_g1add measures the R1CS constraint cost of non-native
// BLS12-381 G1 addition (Phase 2a-1) for curve.Add (incomplete) and
// curve.AddUnified (complete), over the BLS12-381 scalar field.
//
// Compile-only (no Setup/Prove): GetNbConstraints() after frontend.Compile.
// Each (method,N) is compiled TWICE; counts must match (deterministic) or it
// HALTs. Prints a raw table, a CUMULATIVE regression after every N (so a partial
// run still yields the slope), and a final per-method fit + safety premium.
//
// Usage: go run ./cmd/measure_g1add [N ...]   (default 1 2 10 50 100 200)
//
// Default N is capped at 200 deliberately: on a small box (~8 GiB) the ~10M-
// constraint 512-add compile would swap-thrash/OOM, and a memory failure is not
// a clean cap. The per-add slope from N<=200 (R2~=1) projects 512 reliably; the
// full 512-add circuit is measured properly on AWS in Phase 2a-3.
package main

import (
	"fmt"
	"math/big"
	"os"
	"strconv"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/logger"

	"eth-cardano-zk-light-client/prover/circuits/common"
)

var defaultAdditionCounts = []int{1, 2, 10, 50, 100, 200}

type addMethod struct {
	name       string
	useUnified bool
}

func main() {
	logger.Disable() // silence gnark's compile logs; this tool prints only its own table
	additionCounts := defaultAdditionCounts
	if args := os.Args[1:]; len(args) > 0 {
		additionCounts = nil
		for _, arg := range args {
			additionCount, err := strconv.Atoi(arg)
			if err != nil || additionCount < 1 {
				fmt.Fprintf(os.Stderr, "bad N %q\n", arg)
				os.Exit(2)
			}
			additionCounts = append(additionCounts, additionCount)
		}
	}

	scalarField := ecc.BLS12_381.ScalarField()
	methods := []addMethod{{"Add", false}, {"AddUnified", true}}

	fmt.Println("# Phase 2a-1: non-native BLS12-381 G1-add R1CS constraint cost")
	fmt.Println("# native field = BLS12-381 scalar field; compile-only; each count x2 (determinism)")
	fmt.Printf("%-12s %6s %14s %12s\n", "method", "N", "constraints", "elapsed")

	counts := map[string][]float64{}
	var xValues []float64
	for _, additionCount := range additionCounts {
		for _, method := range methods {
			start := time.Now()
			firstCount := compileCount(scalarField, additionCount, method.useUnified)
			secondCount := compileCount(scalarField, additionCount, method.useUnified) // determinism re-compile
			if firstCount != secondCount {
				fmt.Fprintf(os.Stderr, "HALT: non-deterministic %s N=%d: %d != %d\n", method.name, additionCount, firstCount, secondCount)
				os.Exit(1)
			}
			fmt.Printf("%-12s %6d %14d %12s\n", method.name, additionCount, firstCount, time.Since(start).Round(time.Millisecond))
			counts[method.name] = append(counts[method.name], float64(firstCount))
		}
		xValues = append(xValues, float64(additionCount))
		if len(xValues) >= 2 {
			fmt.Printf("# fit(N<=%d):", additionCount)
			for _, method := range methods {
				slope, intercept, rSquared := linearFit(xValues, counts[method.name])
				fmt.Printf("  %s[slope=%.1f icpt=%.1f R2=%.6f 512x=%.0f]", method.name, slope, intercept, rSquared, 512*slope)
			}
			fmt.Println()
		}
	}

	fmt.Println("\n# FINAL regression (constraints = intercept + slope*N)")
	fmt.Printf("%-12s %14s %14s %10s %16s\n", "method", "slope/add", "intercept", "R2", "512*slope")
	var slopes [2]float64
	for i, method := range methods {
		slope, intercept, rSquared := linearFit(xValues, counts[method.name])
		slopes[i] = slope
		fmt.Printf("%-12s %14.2f %14.2f %10.6f %16.0f\n", method.name, slope, intercept, rSquared, 512*slope)
	}
	fmt.Printf("# safety premium (AddUnified - Add): %.2f /add (%.1f%%)\n",
		slopes[1]-slopes[0], 100*(slopes[1]-slopes[0])/slopes[0])
}

func compileCount(scalarField *big.Int, additionCount int, useUnified bool) int {
	constraintSystem, err := frontend.Compile(scalarField, r1cs.NewBuilder, common.NewG1AddCircuit(additionCount, useUnified))
	if err != nil {
		fmt.Fprintf(os.Stderr, "HALT: compile failed N=%d unified=%v: %v\n", additionCount, useUnified, err)
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
