// Package common holds reusable gnark circuit gadgets for the Phase-2 prover.
//
// g1add.go exercises non-native (emulated) BLS12-381 G1 point addition via the
// high-level sw_emulated.Curve gadget — the same path the real sync-committee
// circuit will use for committee key aggregation (operations 1 & 2). Used by
// cmd/measure_g1add (per-addition R1CS cost) and g1add_test.go (functional check).
package common

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bls12381"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated"
)

// newCurve builds the emulated BLS12-381 G1 curve gadget (base field Fp, scalar
// field Fr) — cf. gnark's own sw_bls12381/pairing.go:60.
func newCurve(api frontend.API) (*sw_emulated.Curve[emulated.BLS12381Fp, emulated.BLS12381Fr], error) {
	return sw_emulated.New[emulated.BLS12381Fp, emulated.BLS12381Fr](api, sw_emulated.GetBLS12381Params())
}

// G1AddCircuit performs N INDEPENDENT additions PointsA[i] + PointsB[i] (no
// accumulator, no dependency between adds). useUnifiedAdd selects the method:
//
//	false -> curve.Add        (incomplete/"unsafe": assumes the operands differ and are nonzero)
//	true  -> curve.AddUnified (complete: handles equal / inverse / infinity)
//
// PointsA, PointsB are secret witnesses, so the adds cannot be constant-folded.
// Their VALUES are irrelevant to the constraint count (compile is value-independent),
// so no witness is assigned for the measurement. Results are intentionally
// unused: the emulated ops (MulMod/Div/Reduce) assert their relations and
// register limb range-checks at call time, so the constraints are emitted
// regardless of a downstream consumer (validated empirically by the linearity
// and the sane magnitude of the measured per-add slope).
type G1AddCircuit struct {
	PointsA []sw_bls12381.G1Affine
	PointsB []sw_bls12381.G1Affine

	useUnifiedAdd bool // unexported: not part of the witness schema
}

// NewG1AddCircuit allocates a circuit doing numberOfAdditions independent additions.
func NewG1AddCircuit(numberOfAdditions int, useUnifiedAdd bool) *G1AddCircuit {
	return &G1AddCircuit{
		PointsA:       make([]sw_bls12381.G1Affine, numberOfAdditions),
		PointsB:       make([]sw_bls12381.G1Affine, numberOfAdditions),
		useUnifiedAdd: useUnifiedAdd,
	}
}

func (c *G1AddCircuit) Define(api frontend.API) error {
	curve, err := newCurve(api)
	if err != nil {
		return err
	}
	for i := range c.PointsA {
		if c.useUnifiedAdd {
			curve.AddUnified(&c.PointsA[i], &c.PointsB[i])
		} else {
			curve.Add(&c.PointsA[i], &c.PointsB[i])
		}
	}
	return nil
}

// G1AddCheckCircuit asserts AddUnified(PointP, PointQ) == ExpectedSum — the
// functional correctness circuit, proven end-to-end in g1add_test.go.
type G1AddCheckCircuit struct {
	PointP      sw_bls12381.G1Affine
	PointQ      sw_bls12381.G1Affine
	ExpectedSum sw_bls12381.G1Affine
}

func (c *G1AddCheckCircuit) Define(api frontend.API) error {
	curve, err := newCurve(api)
	if err != nil {
		return err
	}
	curve.AssertIsEqual(curve.AddUnified(&c.PointP, &c.PointQ), &c.ExpectedSum)
	return nil
}
