// boundary.go — the assembled BOUNDARY Phase-A circuit: the regular core (committee bind +
// op-2 + op-5 + op-3a + op-3b + op-4, via defineRegularCore) PLUS op-6 (nextCommitteePath),
// which makes op-6's gindex-87 walk terminal the THIRD consumer of the ONE c.StateRoot —
// op-3a BINDS it (→ attested_header_root), op-3b CONSUMES it (the finality fold), op-6
// CONSUMES it (the next-committee walk). Structural single-source, one variable, three readers;
// TestBoundary_Op6StateRootSingleSource (R7) proves the op-6 consumer load-bearing.
//
// Two committees: CURRENT (signs — Pubkeys (x,y), the regular core's bind + op-2 + op-5) and
// NEXT (installed — Compressed bytes, op-6's SHA→state_root + Poseidon→NextPubkeysCommitment).
// They DIFFER by design. The …↔aggregation-ACROSS-PERIODS half (NextPubkeysCommitment →
// a future regular update's current_pubkeys_commitment) is the DATUM ROTATION, enforced
// ON-CHAIN (Phase-3 Aiken), NOT in this circuit — see assembly-design "Phase-3 Aiken
// obligations" #7.
//
// 12-Fr Option-P public layout = the regular 11 + NextPubkeysCommitment (1 Fr, raw Poseidon).
//
// LOCATION (conscious, temporary): lives in package common alongside RegularCircuit — the move
// to circuits/boundary/ is the deferred export refactor once the assembly is proven.
package common

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bls12381"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"
)

type BoundaryCircuit struct {
	RegularCircuit // committee + op-3a + op-3b + op-4; THE shared StateRoot; the 6 regular publics

	// op-6 (next committee) witness — the SHA side reads Compressed; Path-2 decompresses it.
	Compressed              [][48]uints.U8
	YHint                   []emulated.Element[sw_bls12381.BaseField]
	AggRoot                 [32]uints.U8
	NextSyncCommitteeBranch [6][32]uints.U8

	NextPubkeysCommitment frontend.Variable `gnark:",public"` // 12th Fr — raw Poseidon (unpacked)
}

// NewBoundaryCircuit allocates the circuit for numberOfKeys committee keys (current + next
// both sized n; n=512 real).
func NewBoundaryCircuit(numberOfKeys int) *BoundaryCircuit {
	return &BoundaryCircuit{
		RegularCircuit: *NewRegularCircuit(numberOfKeys),
		Compressed:     make([][48]uints.U8, numberOfKeys),
		YHint:          make([]emulated.Element[sw_bls12381.BaseField], numberOfKeys),
	}
}

func (c *BoundaryCircuit) Define(api frontend.API) error {
	return defineBoundary(api, c, nil, op6Overrides{})
}

// defineBoundary creates the shared resources ONCE and runs the regular core (defineRegularCore)
// + op-6 (nextCommitteePath), both fed the SAME c.StateRoot — so the ~131K uints intercept is
// paid once and op-6 is the THIRD consumer of op-3a's authenticated state_root. op3bOverride /
// op6Override are nil/empty in production; the R7 strawmen inject a separate op-3b / op-6
// state_root to prove each sharing is load-bearing.
func defineBoundary(api frontend.API, c *BoundaryCircuit, op3bStateRootOverride *[32]uints.U8, op6Override op6Overrides) error {
	uintsAPI, err := uints.New[uints.U32](api)
	if err != nil {
		return err
	}
	field, err := emulated.NewField[sw_bls12381.BaseField](api)
	if err != nil {
		return err
	}
	curve, err := newCurve(api)
	if err != nil {
		return err
	}
	g1, err := sw_bls12381.NewG1(api)
	if err != nil {
		return err
	}
	merkleizer := &sszMerkleizer{api: api}

	// ── regular core: committee + op-3a (binds c.StateRoot) + op-3b (consumes) + op-4 + packing ──
	if err := defineRegularCore(api, &c.RegularCircuit, uintsAPI, field, curve, merkleizer, op3bStateRootOverride); err != nil {
		return err
	}

	// ── op-6: the THIRD consumer of c.StateRoot (the gindex-87 walk terminal) ──
	return nextCommitteePath(api, field, g1, uintsAPI, merkleizer,
		c.Compressed, c.YHint, c.AggRoot, c.NextSyncCommitteeBranch, c.StateRoot, c.NextPubkeysCommitment, op6Override)
}
