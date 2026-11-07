// Command measure_regular measures the assembled RegularCircuit R1CS cost over the
// BLS12-381 scalar field, compile-only (x2 for determinism). Small N={8,16} +
// extrapolation always; the direct N=512 is env-gated (RUN_DIRECT_512=1) and
// RSS-heavy — it is the authoritative count vs the ~1.97M D8 projection
// (committee 929,169 + op-3a 504,292 + op-3b ~376K marginal + op-4 ~161K marginal,
// the uints intercept shared ONCE across op-3a/3b/4). Usage: go run ./cmd/measure_regular
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
	fmt.Println("# RegularCircuit assembly R1CS cost; native field = BLS12-381 scalar; compile-only; x2")

	var smallCounts []int
	for _, n := range []int{8, 16} {
		count := compileCountDeterministic(scalarField, n)
		smallCounts = append(smallCounts, count)
		fmt.Printf("N=%-3d constraints = %d\n", n, count)
	}
	// Linear extrapolation to 512 (committee + op-2 are the per-key terms; the SHA ops are fixed).
	slope := float64(smallCounts[1]-smallCounts[0]) / 8.0
	intercept := float64(smallCounts[0]) - slope*8.0
	extrapolated := slope*512.0 + intercept
	fmt.Printf("-> EXTRAPOLATED N=512 = %.0f (~%.2fM)   [slope %.1f/key, intercept %.0f]\n", extrapolated, extrapolated/1e6, slope, intercept)

	if os.Getenv("RUN_DIRECT_512") != "" {
		fmt.Println("\n# direct N=512 compile (RUN_DIRECT_512=1; RSS-heavy)")
		count := compileCountDeterministic(scalarField, 512)
		fmt.Printf("N=512 constraints = %d (~%.2fM)\n", count, float64(count)/1e6)
	} else {
		fmt.Println("\n# direct N=512 compile SKIPPED (set RUN_DIRECT_512=1; projection ~1.97M)")
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
	constraintSystem, err := frontend.Compile(scalarField, r1cs.NewBuilder, common.NewRegularCircuit(n))
	if err != nil {
		fmt.Fprintf(os.Stderr, "HALT: compile failed at N=%d: %v\n", n, err)
		os.Exit(1)
	}
	return constraintSystem.GetNbConstraints()
}
