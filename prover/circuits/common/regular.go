// regular.go — the assembled REGULAR Phase-A circuit (SEC-01 Family-B): committee bind +
// op-2 + op-5 (committeeBindAggregateCount), op-3a (reconstructHeaderRoot), op-3b
// (finalityWalk), op-4 (slotWalk), exposed via the Option-P public layout (11 Fr).
//
// The two SINGLE-SOURCE wires are STRUCTURAL — one variable, two consumers, no second
// witness + AssertIsEqual:
//
//	c.StateRoot           → reconstructHeaderRoot (op-3a binds it to attested_header_root,
//	                        as field 3) AND finalityWalk (op-3b's walk terminal). The
//	                        SC-2 discipline: op-3b folds to op-3a's AUTHENTICATED state_root.
//	c.FinalizedHeaderRoot → finalityWalk (op-3b LEAF) AND slotWalk (op-4 ROOT terminal).
//
// The R7 single-source negative (regular_test.go) proves this sharing is LOAD-BEARING
// (a strawman with a separate op-3b state_root solves a forged finality; production rejects).
//
// LOCATION: the assembled regular circuit lives in package common because the gadgets it calls
// (committeeBindAggregateCount, finalityWalk, slotWalk, reconstructHeaderRoot, packRoot/
// packCoordinate) and the sszMerkleizer type are UNEXPORTED. A package of its own would first
// have to export those (count-neutral renames).
//
// The BLS aggregate-signature check (apk over the signing root) and the 2/3 threshold
// (count ≥ 342) are ON-CHAIN (Plutus, §2.1.3), NOT in this circuit.
package common

import (
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bls12381"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"
)

type RegularCircuit struct {
	// ── committee witness (n keys; 512 real) ──
	Pubkeys []sw_bls12381.G1Affine // (x,y), decompressed off-chain — feeds bind + op-2
	Bits    []frontend.Variable    // participation bits — feeds op-2 + op-5

	// ── attested-header witness (op-3a reconstructs its root); StateRoot is THE shared wire ──
	Slot, ProposerIndex             frontend.Variable
	ParentRoot, StateRoot, BodyRoot [32]uints.U8

	// ── finality witnesses ──
	FinalizedHeaderRoot [32]uints.U8    // op-3b LEAF = op-4 ROOT (ONE wire)
	FinalityBranch      [7][32]uints.U8 // op-3b gindex-169 siblings
	SlotBranch          [3][32]uints.U8 // op-4 gindex-8 siblings

	// ── PUBLIC (Option P, 11 Fr) ──
	PubkeysCommitment         frontend.Variable    `gnark:",public"` // 1  (= datum.current_pubkeys_commitment)
	ApkPacked                 [4]frontend.Variable `gnark:",public"` // 4  (packCoordinate apk.X ‖ apk.Y)
	Count                     frontend.Variable    `gnark:",public"` // 1  (Σ bits)
	AttestedHeaderRootPacked  [2]frontend.Variable `gnark:",public"` // 2  (packRoot; the BLS message basis)
	FinalizedHeaderRootPacked [2]frontend.Variable `gnark:",public"` // 2  (packRoot; datum-bound)
	FinalizedSlot             frontend.Variable    `gnark:",public"` // 1  (datum-bound)
}

// NewRegularCircuit allocates the circuit for numberOfKeys committee keys.
func NewRegularCircuit(numberOfKeys int) *RegularCircuit {
	return &RegularCircuit{
		Pubkeys: make([]sw_bls12381.G1Affine, numberOfKeys),
		Bits:    make([]frontend.Variable, numberOfKeys),
	}
}

func (c *RegularCircuit) Define(api frontend.API) error {
	return defineRegular(api, c, nil)
}

// defineRegular is the shared body. op3bStateRootOverride is nil in PRODUCTION — op-3b's
// finalityWalk terminates on c.StateRoot, the SAME wire op-3a authenticates (the structural
// single-source). The R7 mutation-test strawman passes a SEPARATE state_root to decouple
// op-3b's walk from op-3a (the hole production closes by sharing one variable), exactly as
// op-6's op6Overrides re-introduce the SC-2 holes for the GAP tests.
func defineRegular(api frontend.API, c *RegularCircuit, op3bStateRootOverride *[32]uints.U8) error {
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
	merkleizer := &sszMerkleizer{api: api}
	return defineRegularCore(api, c, uintsAPI, field, curve, merkleizer, op3bStateRootOverride)
}

// defineRegularCore is the regular core wiring (committee bind + op-2 + op-5 + op-3a + op-3b +
// op-4 + the Option-P packing/asserts), taking the shared resources created ONCE by the caller.
// The BoundaryCircuit reuses it (defineBoundary) so the regular core and op-6 share the same
// uintsAPI/field/curve/merkleizer — the ~131K uints intercept is paid once — and feed the SAME
// c.StateRoot to op-3a (binds), op-3b (consumes here), and op-6 (consumes in nextCommitteePath).
func defineRegularCore(
	api frontend.API,
	c *RegularCircuit,
	uintsAPI *uints.BinaryField[uints.U32],
	field *emulated.Field[sw_bls12381.BaseField],
	curve *sw_emulated.Curve[emulated.BLS12381Fp, emulated.BLS12381Fr],
	merkleizer *sszMerkleizer,
	op3bStateRootOverride *[32]uints.U8,
) error {
	two64 := new(big.Int).Lsh(big.NewInt(1), 64)
	two128 := new(big.Int).Lsh(big.NewInt(1), 128)

	// ── ① committee: Poseidon bind (== PubkeysCommitment) + op-2 apk + op-5 count ──
	apk, count, err := committeeBindAggregateCount(api, curve, field, c.Pubkeys, c.Bits, c.PubkeysCommitment)
	if err != nil {
		return err
	}
	// apk → 4 Fr (packCoordinate X ‖ Y) == ApkPacked. Reduce first so the limbs are the
	// CANONICAL base-2^64 representation — matching how the validator packs the uncompressed
	// point on-chain (else a lazily-unreduced apk would pack to a different value).
	reducedApkX := field.Reduce(&apk.X)
	reducedApkY := field.Reduce(&apk.Y)
	apkXPacked := packCoordinate(api, reducedApkX.Limbs, two64, two128)
	apkYPacked := packCoordinate(api, reducedApkY.Limbs, two64, two128)
	api.AssertIsEqual(apkXPacked[0], c.ApkPacked[0])
	api.AssertIsEqual(apkXPacked[1], c.ApkPacked[1])
	api.AssertIsEqual(apkYPacked[0], c.ApkPacked[2])
	api.AssertIsEqual(apkYPacked[1], c.ApkPacked[3])
	api.AssertIsEqual(count, c.Count)

	// ── ② op-3a: reconstruct the attested header → bind c.StateRoot (field 3) ──
	reconstructedRoot, err := reconstructHeaderRoot(api, uintsAPI, c.Slot, c.ProposerIndex, c.ParentRoot, c.StateRoot, c.BodyRoot)
	if err != nil {
		return err
	}
	attestedPacked := packRoot(api, reconstructedRoot)
	api.AssertIsEqual(attestedPacked[0], c.AttestedHeaderRootPacked[0])
	api.AssertIsEqual(attestedPacked[1], c.AttestedHeaderRootPacked[1])

	// ── ③ op-3b: finality branch — finalityWalk consumes the SAME c.StateRoot (single-source) ──
	op3bStateRoot := c.StateRoot
	if op3bStateRootOverride != nil { // R7 strawman ONLY: a separate, decoupled state_root
		op3bStateRoot = *op3bStateRootOverride
	}
	if err := finalityWalk(uintsAPI, merkleizer, c.FinalizedHeaderRoot, c.FinalityBranch, op3bStateRoot); err != nil {
		return err
	}

	// ── ④ op-4: slot binding — c.FinalizedHeaderRoot is op-3b's LEAF = op-4's ROOT (ONE wire) ──
	if err := slotWalk(api, uintsAPI, merkleizer, c.FinalizedSlot, c.SlotBranch[:], c.FinalizedHeaderRoot); err != nil {
		return err
	}
	finalizedPacked := packRoot(api, c.FinalizedHeaderRoot[:])
	api.AssertIsEqual(finalizedPacked[0], c.FinalizedHeaderRootPacked[0])
	api.AssertIsEqual(finalizedPacked[1], c.FinalizedHeaderRootPacked[1])

	return nil
}
