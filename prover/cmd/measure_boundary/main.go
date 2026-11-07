// Command measure_boundary measures the assembled BoundaryCircuit R1CS cost over the
// BLS12-381 scalar field, compile-only (x2). Small N={8,16} + extrapolation always; the
// direct N=512 is env-gated (RUN_DIRECT_512=1) and RSS-HEAVY (op-6's gindex-174 SHA side
// over 512 keys, ~54.8M — likely the boundary's local ceiling; full-512 + real proving are
// AWS). Usage: go run ./cmd/measure_boundary   (or RUN_DIRECT_512=1 for the direct 512).
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
	fmt.Println("# BoundaryCircuit assembly R1CS cost; native field = BLS12-381 scalar; compile-only; x2")

	var smallCounts []int
	for _, n := range []int{8, 16} {
		count := compileCountDeterministic(scalarField, n)
		smallCounts = append(smallCounts, count)
		fmt.Printf("N=%-3d constraints = %d\n", n, count)
	}
	slope := float64(smallCounts[1]-smallCounts[0]) / 8.0
	intercept := float64(smallCounts[0]) - slope*8.0
	extrapolated := slope*512.0 + intercept
	fmt.Printf("-> EXTRAPOLATED N=512 = %.0f (~%.1fM)   [slope %.1f/key, intercept %.0f]\n", extrapolated, extrapolated/1e6, slope, intercept)

	if os.Getenv("RUN_DIRECT_512") != "" {
		fmt.Println("\n# direct N=512 compile (RUN_DIRECT_512=1; RSS-heavy — op-6 SHA side)")
		count := compileCountDeterministic(scalarField, 512)
		fmt.Printf("N=512 constraints = %d (~%.2fM)\n", count, float64(count)/1e6)
	} else {
		fmt.Println("\n# direct N=512 compile SKIPPED (set RUN_DIRECT_512=1; RSS-heavy; full-512 + real proving are AWS)")
	}
}

func compileCountDeterministic(scalarField *big.Int, n int) int {
	first := compileCount(scalarField, n)
	second := compileCount(scalarField, n)
	if first != second {
		fmt.Fprintf(os.Stderr, "HALT: non-deterministic count at N=%d: %d != %d\n", n, first, second)
		os.Exit(1)
	}
	return first
}

func compileCount(scalarField *big.Int, n int) int {
	constraintSystem, err := frontend.Compile(scalarField, r1cs.NewBuilder, common.NewBoundaryCircuit(n))
	if err != nil {
		fmt.Fprintf(os.Stderr, "HALT: compile failed at N=%d: %v\n", n, err)
		os.Exit(1)
	}
	return constraintSystem.GetNbConstraints()
}
