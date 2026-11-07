// Command measure_g1_validity measures the per-pubkey R1CS cost of G1 point VALIDITY
// for the SEC-01 Family-B SC-4 analysis: on-curve (AssertIsOnCurve) and full subgroup
// (AssertIsOnG1 = on-curve + a prime-order scalar-multiplication). On-curve is what
// encoding B must add to EVERY regular update (to pin y); the subgroup check is what
// op-6 must do for BOTH encodings (the relayer controls op-6's witness). Compile-only,
// x2 (deterministic, HALT on mismatch). COSTING PROBE for the SEC-01 Family-B encoding
// decision (Step-2a); see docs/security/SEC-01-committee-binding-rogue-key.md.
package main

import (
	"fmt"
	"math/big"
	"os"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/logger"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bls12381"
)

type g1ValidityCircuit struct {
	Points   []sw_bls12381.G1Affine
	subgroup bool // false = AssertIsOnCurve; true = AssertIsOnG1 (+ prime-order scalar-mul)
}

func newG1ValidityCircuit(n int, subgroup bool) *g1ValidityCircuit {
	return &g1ValidityCircuit{Points: make([]sw_bls12381.G1Affine, n), subgroup: subgroup}
}

func (c *g1ValidityCircuit) Define(api frontend.API) error {
	g1, err := sw_bls12381.NewG1(api)
	if err != nil {
		return err
	}
	for i := range c.Points {
		if c.subgroup {
			g1.AssertIsOnG1(&c.Points[i])
		} else {
			g1.AssertIsOnCurve(&c.Points[i])
		}
	}
	return nil
}

func main() {
	logger.Disable()
	scalarField := ecc.BLS12_381.ScalarField()
	fmt.Println("# Phase 2a: G1 validity per-pubkey cost (on-curve vs subgroup)")
	fmt.Println("# compile-only; x2 (determinism); HALT on mismatch")
	for _, v := range []struct {
		name     string
		subgroup bool
		ns       []int
	}{
		{"AssertIsOnCurve (on-curve only — B-regular's add)", false, []int{64, 128, 512}},
		{"AssertIsOnG1 (on-curve + subgroup scalar-mul — op-6, both encodings)", true, []int{8, 16, 32}},
	} {
		fmt.Printf("\n## %s\n", v.name)
		counts := make([]int, len(v.ns))
		for i, n := range v.ns {
			counts[i] = compileTwice(scalarField, n, v.subgroup)
			fmt.Printf("N=%-4d constraints = %d\n", n, counts[i])
		}
		last := len(v.ns) - 1
		slope := float64(counts[last]-counts[0]) / float64(v.ns[last]-v.ns[0])
		fmt.Printf("-> per-pubkey ~= %.0f constraints; extrapolated 512 = %.0f\n", slope, slope*512)
	}
}

func compileTwice(field *big.Int, n int, subgroup bool) int {
	a := compile(field, n, subgroup)
	b := compile(field, n, subgroup)
	if a != b {
		fmt.Fprintf(os.Stderr, "HALT: non-deterministic at N=%d subgroup=%v: %d!=%d\n", n, subgroup, a, b)
		os.Exit(1)
	}
	return a
}

func compile(field *big.Int, n int, subgroup bool) int {
	cs, err := frontend.Compile(field, r1cs.NewBuilder, newG1ValidityCircuit(n, subgroup))
	if err != nil {
		fmt.Fprintf(os.Stderr, "HALT: compile N=%d subgroup=%v: %v\n", n, subgroup, err)
		os.Exit(1)
	}
	return cs.GetNbConstraints()
}
