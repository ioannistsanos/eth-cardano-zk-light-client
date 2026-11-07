// Command measure_committee_bind measures the R1CS cost of the regular committee-binding
// region (Poseidon bind + op-2 conditional aggregation + op-5 count) under the SEC-01
// Family-B fix. Compile-only, x2 (deterministic, HALT on mismatch), at SMALL N={8,16}
// with extrapolation to 512. The bind alone is ~0.38M (D9); op-2 (the G1 aggregation) is
// the dominant term — cross-check the per-key slope against the D7 emulated-G1-add cost.
// Usage: go run ./cmd/measure_committee_bind
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
	fmt.Println("# regular committee-bind: R1CS cost (bind + op-2 aggregation + op-5 count)")
	fmt.Println("# compile-only; x2 (determinism); HALT on mismatch; small N + extrapolation")
	small := []int{8, 16}
	counts := make([]int, len(small))
	for i, n := range small {
		counts[i] = compileTwice(field, n)
		fmt.Printf("N=%-3d constraints = %d\n", n, counts[i])
	}
	slope := float64(counts[1]-counts[0]) / float64(small[1]-small[0])
	intercept := float64(counts[0]) - slope*float64(small[0])
	fmt.Printf("-> per-key slope = %.0f ; intercept = %.0f\n", slope, intercept)
	fmt.Printf("-> EXTRAPOLATED N=512 = %.0f (~%.2fM)\n", slope*512+intercept, (slope*512+intercept)/1e6)
	fmt.Println("# bind ~0.38M (D9); op-2 (emulated G1 aggregation) dominant — refutes the thesis ~5-15M/op estimate (cf. D7)")
	// Direct N=512 compile is env-gated (RUN_DIRECT_512=1). It is small (measured 929,169
	// ~0.93M, peak ~1.5GB, no OOM) but heavy enough to keep out of every default run;
	// the extrapolation above is the default. (Post-crash principle: env-gate heavy runs.)
	if os.Getenv("RUN_DIRECT_512") != "" {
		fmt.Println("\n# direct N=512 compile (RUN_DIRECT_512=1)")
		direct := compileTwice(field, 512)
		fmt.Printf("N=512 constraints = %d (~%.2fM)\n", direct, float64(direct)/1e6)
	} else {
		fmt.Println("\n# direct N=512 compile SKIPPED (set RUN_DIRECT_512=1; measured 929,169 ~0.93M)")
	}
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
	constraintSystem, err := frontend.Compile(field, r1cs.NewBuilder, common.NewCommitteeBindCircuit(n))
	if err != nil {
		fmt.Fprintf(os.Stderr, "HALT: compile N=%d: %v\n", n, err)
		os.Exit(1)
	}
	return constraintSystem.GetNbConstraints()
}
