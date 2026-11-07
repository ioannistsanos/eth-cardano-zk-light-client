// Command measure_pubkeys_root measures the R1CS constraint cost of the 2b-i
// 512-Bytes48 SSZ merkleization (op-6 SHA side, gindex-174 root). Compile-only, x2
// (deterministic, HALT on mismatch). Measures small N for a clean per-pubkey slope and
// prints the extrapolated 512 first (safety net), then ATTEMPTS the direct 512 compile
// (best-effort; ~55M may exceed local memory). Usage: go run ./cmd/measure_pubkeys_root
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
	fmt.Println("# 2b-i: SSZ merkleization of 512 BLS pubkeys (gindex-174 root) — R1CS cost")
	fmt.Println("# compile-only; x2 (determinism); HALT on mismatch")

	// Small N only — compiling large SSZ circuits is very slow locally (N=64/~7M took
	// >100s and ~1.5GB), so the count is extrapolated from feasibly-small N to 512.
	small := []int{4, 8, 16}
	counts := make([]int, len(small))
	for i, n := range small {
		counts[i] = compileTwice(field, n)
		fmt.Printf("N=%-4d constraints = %d  (node-hashes = %d)\n", n, counts[i], 2*n-1)
	}
	last := len(small) - 1
	slope := float64(counts[last]-counts[0]) / float64(small[last]-small[0])
	intercept := float64(counts[0]) - slope*float64(small[0])
	perNodeHash := slope / 2 // each pubkey adds 2 node-hashes (1 leaf + ~1 internal, amortized)
	fmt.Printf("-> per-pubkey slope = %.0f (=> ~%.0f / node-hash) ; intercept = %.0f\n", slope, perNodeHash, intercept)
	fmt.Printf("-> EXTRAPOLATED N=512 (1023 node-hashes) = %.0f (~%.1fM)\n", slope*512+intercept, (slope*512+intercept)/1e6)
	fmt.Println("# direct 512 compile is infeasible locally (needs AWS); cross-check vs D8 per-node ~53,672")
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
	constraintSystem, err := frontend.Compile(field, r1cs.NewBuilder, common.NewPubkeysRootCircuit(n))
	if err != nil {
		fmt.Fprintf(os.Stderr, "HALT: compile N=%d: %v\n", n, err)
		os.Exit(1)
	}
	return constraintSystem.GetNbConstraints()
}
