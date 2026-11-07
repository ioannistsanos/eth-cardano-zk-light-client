// committeebind.go — the regular-path committee-binding region under the SEC-01
// Family-B fix (the regular half of the fix; boundary half = op-6, done in 2b-iii).
//
// op-1 (the unconditional Σ pubkeys = committee_id plain-sum) is DROPPED — it was the
// binding SEC-01 broke and the thesis itself called it "not strictly required for
// security". The binding is now the Poseidon commitment over the individual keys:
//
//	bind:  Poseidon(pack(x,y) for all 512) == PubkeysCommitment   (= datum.current_pubkeys_commitment)
//	op-2:  apk   = Σ bits[i]·pubkeys[i]   (the participating aggregate, for the on-chain BLS check)
//	op-5:  count = Σ bits[i]              (threshold ≥342 is enforced ON-CHAIN, not here)
//
// SC-1 (single source) is STRUCTURAL: ONE Pubkeys[] array feeds both the bind and op-2,
// and ONE Bits[] feeds both op-2 and op-5 — no second array, no equality check.
//
// Canonicity (Option A, no explicit AssertIsLessOrEqual): the bind packs ALL 512 keys so
// any non-canonical VALUE breaks the Poseidon match; op-2 aggregates ALL 512 keys so the
// emulated arithmetic range-checks every limb (<2^64), blocking out-of-range pack-wrap;
// the match is against a CANONICAL commitment established at op-6 (done) / bootstrap
// (done — canonicity-first Verify: the rejection chain at bootstrap.go:94-103 plus the
// decompressCanonicalPubkey round-trip at :162-174). Settled empirically (the 8-case
// Option-A probe).
package common

import (
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bls12381"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/hash"
	"github.com/consensys/gnark/std/math/emulated"
	poseidon2perm "github.com/consensys/gnark/std/permutation/poseidon2"
)

type CommitteeBindCircuit struct {
	// THE single key witness ((x,y), decompressed off-chain) — feeds the bind AND op-2.
	Pubkeys []sw_bls12381.G1Affine
	Bits    []frontend.Variable // participation bits — feeds op-2 AND op-5

	PubkeysCommitment frontend.Variable    `gnark:",public"` // = datum.current_pubkeys_commitment
	Apk               sw_bls12381.G1Affine `gnark:",public"` // op-2 output (for the BLS check)
	Count             frontend.Variable    `gnark:",public"` // op-5 output (Σ bits)
}

// NewCommitteeBindCircuit allocates the circuit for numberOfKeys committee keys.
func NewCommitteeBindCircuit(numberOfKeys int) *CommitteeBindCircuit {
	return &CommitteeBindCircuit{
		Pubkeys: make([]sw_bls12381.G1Affine, numberOfKeys),
		Bits:    make([]frontend.Variable, numberOfKeys),
	}
}

func (c *CommitteeBindCircuit) Define(api frontend.API) error {
	curve, err := newCurve(api)
	if err != nil {
		return err
	}
	field, err := emulated.NewField[sw_bls12381.BaseField](api)
	if err != nil {
		return err
	}
	apk, count, err := committeeBindAggregateCount(api, curve, field, c.Pubkeys, c.Bits, c.PubkeysCommitment)
	if err != nil {
		return err
	}
	curve.AssertIsEqual(&apk, &c.Apk)
	api.AssertIsEqual(count, c.Count)
	return nil
}

// committeeBindAggregateCount runs the regular committee-binding region on ONE key
// witness: the Poseidon bind (asserts the commitment internally), op-2 conditional
// aggregation, and op-5 count. SC-1 is structural — the single pubkeys/bits slices feed
// every step (no second array). curve + field are created ONCE by the caller and passed
// in (so the assembly shares them with op-6 rather than paying the emulated-field setup
// twice); the Poseidon hasher is built here. Returns apk + count as WIRES (the caller
// exposes/packs them — the assembly's Option-P public layout needs apk as a wire, not a
// pre-asserted value); the standalone wrapper asserts them == its public Apk/Count.
func committeeBindAggregateCount(
	api frontend.API,
	curve *sw_emulated.Curve[emulated.BLS12381Fp, emulated.BLS12381Fr],
	field *emulated.Field[sw_bls12381.BaseField],
	pubkeys []sw_bls12381.G1Affine,
	bits []frontend.Variable,
	pubkeysCommitment frontend.Variable,
) (sw_bls12381.G1Affine, frontend.Variable, error) {
	// ── Poseidon bind (Option A: NO AssertIsLessOrEqual — canonicity is structural) ──
	permutation, err := poseidon2perm.NewPoseidon2FromParameters(api, 2, 6, 50)
	if err != nil {
		return sw_bls12381.G1Affine{}, nil, err
	}
	hasher := hash.NewMerkleDamgardHasher(api, permutation, 0)
	two64 := new(big.Int).Lsh(big.NewInt(1), 64)
	two128 := new(big.Int).Lsh(big.NewInt(1), 128)
	for i := range pubkeys {
		hasher.Write(packCoordinate(api, pubkeys[i].X.Limbs, two64, two128)...)
		hasher.Write(packCoordinate(api, pubkeys[i].Y.Limbs, two64, two128)...)
	}
	api.AssertIsEqual(hasher.Sum(), pubkeysCommitment)

	// ── op-2 conditional aggregation (apk) + op-5 count, single-sourced on pubkeys/bits ──
	zero := field.Zero()
	accumulator := &sw_bls12381.G1Affine{X: *zero, Y: *zero} // identity (0,0): AddUnified's neutral
	count := frontend.Variable(0)
	for i := range pubkeys {
		api.AssertIsBoolean(bits[i])
		// curve.AddUnified is REQUIRED here, NOT curve.Add. This is a conditional
		// accumulator that starts at the identity (0,0) and can hit edge cases —
		// accumulator == identity (first add), or accumulator == pubkeys[i] (a repeated
		// key → point doubling). curve.Add is the INCOMPLETE formula (it assumes the two
		// operands are distinct and nonzero) and would be silently WRONG/UNSOUND at those
		// edges. Do NOT "optimize" this to curve.Add for speed. (Deliberate; see
		// docs/security/SEC-01-committee-binding-rogue-key.md.)
		candidate := curve.AddUnified(accumulator, &pubkeys[i])
		accumulator = curve.Select(bits[i], candidate, accumulator)
		count = api.Add(count, bits[i])
	}
	return *accumulator, count, nil
}
