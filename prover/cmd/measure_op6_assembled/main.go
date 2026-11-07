// Command measure_op6_assembled measures the R1CS cost of the assembled op-6
// translation hinge (SEC-01 2b-iii) — Path-1 (SHA merkleize + gindex-87 walk + op-3a)
// + Path-2 (decompress + Poseidon). Compile-only, x2 (deterministic, HALT on mismatch),
// at SMALL N={8,16} only: the full-512 assembled (~59M) is AWS-deferred and would OOM
// locally. The SC-2 wiring is N-invariant (the gindex-87 walk is state-level, 6 steps at
// any N), so small-N compiles confirm the wiring builds deterministically.
// Usage: go run ./cmd/measure_op6_assembled
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
	fmt.Println("# 2b-iii: assembled op-6 translation hinge — R1CS cost (small N; full-512 AWS-deferred)")
	fmt.Println("# compile-only; x2 (determinism); HALT on mismatch")
	for _, n := range []int{8, 16} {
		count := compileTwice(field, n)
		fmt.Printf("N=%-3d constraints = %d (~%.2fM)\n", n, count, float64(count)/1e6)
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
	constraintSystem, err := frontend.Compile(field, r1cs.NewBuilder, common.NewAssembledOp6Circuit(n))
	if err != nil {
		fmt.Fprintf(os.Stderr, "HALT: compile N=%d: %v\n", n, err)
		os.Exit(1)
	}
	return constraintSystem.GetNbConstraints()
}
