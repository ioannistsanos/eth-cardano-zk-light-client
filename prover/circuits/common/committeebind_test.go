package common

// Regular committee-bind suite (Option A + locking tests). Lock-1: the BIND catches a
// non-canonical VALUE on a NON-participating key (it packs all keys). Lock-2: op-2's
// range-check catches an out-of-range limb on a NON-participating key (it aggregates all
// keys) — with K chosen so the bind PASSES, isolating op-2. SC-1: a two-array strawman
// (bind over real, op-2 over forged) SOLVES while production (one array) REJECTS — locks
// that op-2 aggregates the COMMITTED keys (Lock-2's soundness rests on this).

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fp"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bls12381"
	"github.com/consensys/gnark/std/hash"
	"github.com/consensys/gnark/std/math/emulated"
	poseidon2perm "github.com/consensys/gnark/std/permutation/poseidon2"
	"github.com/consensys/gnark/test"

	"eth-cardano-zk-light-client/prover/offchain/commitment"
)

// ─────────────────────────── off-circuit helpers ───────────────────────────

func bindPoints(t *testing.T, n int) []bls12381.G1Affine {
	t.Helper()
	pts := make([]bls12381.G1Affine, n)
	for i := range pts {
		pts[i], _ = validPoint(t)
	}
	return pts
}

// aggregateApk = Σ_{bits[i]=1} pts[i] (the participating aggregate), matching the
// in-circuit identity-start AddUnified accumulation.
func aggregateApk(pts []bls12381.G1Affine, bits []int) bls12381.G1Affine {
	var acc bls12381.G1Jac
	acc.X.SetOne()
	acc.Y.SetOne()
	acc.Z.SetZero() // (1,1,0) = point at infinity (neutral)
	for i := range pts {
		if bits[i] == 1 {
			var pj bls12381.G1Jac
			pj.FromAffine(&pts[i])
			acc.AddAssign(&pj)
		}
	}
	var out bls12381.G1Affine
	out.FromJacobian(&acc)
	return out
}

// canonicalPacks / poseidonCommitFr DELEGATE to the extracted production twin in
// offchain/commitment/ — byte-identical, kept as package-common wrappers so the
// locking-test call sites (which feed deliberately-crafted packs to poseidonCommitFr) and the
// cross-file helper-sharing convention stay unchanged.
func canonicalPacks(pts []bls12381.G1Affine) []fr.Element { return commitment.Pack(pts) }

func poseidonCommitFr(elems []fr.Element) fr.Element { return commitment.CommitElements(elems) }

// outOfRangeX returns x's limbs with limb[0] += 2^64 (out of range); its pack is
// (canonical_X_lo + 2^64, canonical_X_hi).
func outOfRangeX(x fp.Element) emulated.Element[sw_bls12381.BaseField] {
	var b big.Int
	x.BigInt(&b)
	mask := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 64), big.NewInt(1))
	tmp := new(big.Int).Set(&b)
	vals := make([]*big.Int, 6)
	for i := 0; i < 6; i++ {
		vals[i] = new(big.Int).And(tmp, mask)
		tmp.Rsh(tmp, 64)
	}
	vals[0].Add(vals[0], new(big.Int).Lsh(big.NewInt(1), 64))
	limbs := make([]frontend.Variable, 6)
	for i := range vals {
		limbs[i] = vals[i]
	}
	return emulated.Element[sw_bls12381.BaseField]{Limbs: limbs}
}

func sumBits(bits []int) int {
	s := 0
	for _, b := range bits {
		s += b
	}
	return s
}

func bindAssign(pts []bls12381.G1Affine, bits []int, pubkeysCommitment fr.Element, apk bls12381.G1Affine) *CommitteeBindCircuit {
	a := NewCommitteeBindCircuit(len(pts))
	for i := range pts {
		a.Pubkeys[i] = sw_bls12381.NewG1Affine(pts[i])
		a.Bits[i] = bits[i]
	}
	a.PubkeysCommitment = frElementToVar(pubkeysCommitment)
	a.Apk = sw_bls12381.NewG1Affine(apk)
	a.Count = sumBits(bits)
	return a
}

func solveBind(a *CommitteeBindCircuit) error {
	return test.IsSolved(NewCommitteeBindCircuit(len(a.Pubkeys)), a, ecc.BLS12_381.ScalarField())
}

func patternBits(n int) []int { // deterministic mix
	bits := make([]int, n)
	for i := range bits {
		if i%3 != 0 {
			bits[i] = 1
		}
	}
	return bits
}

// ─────────────────────────── positive ───────────────────────────

func TestCommitteeBind_PositiveSolves(t *testing.T) {
	for _, n := range []int{8, 16} {
		pts := bindPoints(t, n)
		bits := patternBits(n)
		k := poseidonCommitFr(canonicalPacks(pts))
		apk := aggregateApk(pts, bits)
		if err := solveBind(bindAssign(pts, bits, k, apk)); err != nil {
			t.Fatalf("POSITIVE FAILED at N=%d: %v", n, err)
		}
		t.Logf("PASS: N=%d committee-bind solves (bind matches K, op-2 → apk, count single-sourced)", n)
	}
}

func TestCommitteeBind_ProvesSmallN(t *testing.T) {
	const n = 2
	field := ecc.BLS12_381.ScalarField()
	pts := bindPoints(t, n)
	bits := []int{1, 1}
	a := bindAssign(pts, bits, poseidonCommitFr(canonicalPacks(pts)), aggregateApk(pts, bits))
	cs, err := frontend.Compile(field, r1cs.NewBuilder, NewCommitteeBindCircuit(n))
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	pk, vk, err := groth16.Setup(cs)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	w, err := frontend.NewWitness(a, field)
	if err != nil {
		t.Fatalf("witness: %v", err)
	}
	pw, err := w.Public()
	if err != nil {
		t.Fatalf("public: %v", err)
	}
	proof, err := groth16.Prove(cs, pk, w)
	if err != nil {
		t.Fatalf("prove: %v", err)
	}
	if err := groth16.Verify(proof, vk, pw); err != nil {
		t.Fatalf("verify: %v", err)
	}
	t.Logf("PASS: N=%d committee-bind Setup→Prove→Verify (%d constraints)", n, cs.GetNbConstraints())
}

// ─────────────────────────── Lock-1: bind catches non-canonical VALUE on a bits=0 key ───────────────────────────

func TestCommitteeBind_Lock1_BindCatchesValue(t *testing.T) {
	const n = 8
	pts := bindPoints(t, n)
	bits := patternBits(n)
	bits[1] = 0 // key[1] NON-participating
	a := bindAssign(pts, bits, poseidonCommitFr(canonicalPacks(pts)), aggregateApk(pts, bits))
	a.Pubkeys[1].Y = nonCanonicalY(pts[1].Y) // y+p on the non-participating key
	if err := solveBind(a); err == nil {
		t.Fatalf("Lock-1 FAILED: non-canonical y+p on a bits=0 key ACCEPTED — bind does not pack all keys")
	} else {
		t.Logf("Lock-1 PASS: y+p on bits=0 key REJECTED by the bind: %v", err)
	}
}

// ─────────────────────────── Lock-2: op-2 range-checks a bits=0 key (bind passes, op-2 catches) ───────────────────────────

func TestCommitteeBind_Lock2_Op2RangeChecksAll(t *testing.T) {
	const n = 8
	pts := bindPoints(t, n)
	bits := patternBits(n)
	bits[1] = 0 // key[1] NON-participating
	// K matches the OUT-OF-RANGE pack (so the bind PASSES) → isolates op-2's range-check.
	packs := canonicalPacks(pts)
	var twoTo64 fr.Element
	twoTo64.SetBigInt(new(big.Int).Lsh(big.NewInt(1), 64))
	packs[4*1].Add(&packs[4*1], &twoTo64) // key[1] X_lo += 2^64
	a := bindAssign(pts, bits, poseidonCommitFr(packs), aggregateApk(pts, bits))
	a.Pubkeys[1].X = outOfRangeX(pts[1].X) // out-of-range limb on the non-participating key
	if err := solveBind(a); err == nil {
		t.Fatalf("Lock-2 FAILED: out-of-range limb on a bits=0 key ACCEPTED — op-2 does NOT range-check non-participating keys (pack-wrap forgery OPEN)")
	} else {
		t.Logf("Lock-2 PASS: out-of-range limb on bits=0 key REJECTED by op-2's range-check (bind passed): %v", err)
	}
}

// ─────────────────────────── SC-1: single-source (two-array strawman vs production) ───────────────────────────

type committeeBindStrawman struct {
	BindPubkeys       []sw_bls12381.G1Affine // feeds the bind
	AggPubkeys        []sw_bls12381.G1Affine // feeds op-2
	Bits              []frontend.Variable
	PubkeysCommitment frontend.Variable    `gnark:",public"`
	Apk               sw_bls12381.G1Affine `gnark:",public"`
	Count             frontend.Variable    `gnark:",public"`
}

func (c *committeeBindStrawman) Define(api frontend.API) error {
	curve, err := newCurve(api)
	if err != nil {
		return err
	}
	field, err := emulated.NewField[sw_bls12381.BaseField](api)
	if err != nil {
		return err
	}
	perm, err := poseidon2perm.NewPoseidon2FromParameters(api, 2, 6, 50)
	if err != nil {
		return err
	}
	hasher := hash.NewMerkleDamgardHasher(api, perm, 0)
	two64 := new(big.Int).Lsh(big.NewInt(1), 64)
	two128 := new(big.Int).Lsh(big.NewInt(1), 128)
	for i := range c.BindPubkeys { // bind over BindPubkeys
		hasher.Write(packCoordinate(api, c.BindPubkeys[i].X.Limbs, two64, two128)...)
		hasher.Write(packCoordinate(api, c.BindPubkeys[i].Y.Limbs, two64, two128)...)
	}
	api.AssertIsEqual(hasher.Sum(), c.PubkeysCommitment)
	zero := field.Zero()
	acc := &sw_bls12381.G1Affine{X: *zero, Y: *zero}
	count := frontend.Variable(0)
	for i := range c.AggPubkeys { // op-2 over AggPubkeys
		api.AssertIsBoolean(c.Bits[i])
		acc = curve.Select(c.Bits[i], curve.AddUnified(acc, &c.AggPubkeys[i]), acc)
		count = api.Add(count, c.Bits[i])
	}
	curve.AssertIsEqual(acc, &c.Apk)
	api.AssertIsEqual(count, c.Count)
	return nil
}

func TestCommitteeBind_SC1_StrawmanExploitable(t *testing.T) {
	const n = 8
	real := bindPoints(t, n)
	forged := bindPoints(t, n)
	bits := patternBits(n)
	straw := &committeeBindStrawman{
		BindPubkeys: make([]sw_bls12381.G1Affine, n),
		AggPubkeys:  make([]sw_bls12381.G1Affine, n),
		Bits:        make([]frontend.Variable, n),
	}
	for i := 0; i < n; i++ {
		straw.BindPubkeys[i] = sw_bls12381.NewG1Affine(real[i])  // bind authenticates the REAL committee
		straw.AggPubkeys[i] = sw_bls12381.NewG1Affine(forged[i]) // op-2 aggregates FORGED keys
		straw.Bits[i] = bits[i]
	}
	straw.PubkeysCommitment = frElementToVar(poseidonCommitFr(canonicalPacks(real)))
	straw.Apk = sw_bls12381.NewG1Affine(aggregateApk(forged, bits)) // forged apk
	straw.Count = sumBits(bits)
	blank := &committeeBindStrawman{BindPubkeys: make([]sw_bls12381.G1Affine, n), AggPubkeys: make([]sw_bls12381.G1Affine, n), Bits: make([]frontend.Variable, n)}
	if err := test.IsSolved(blank, straw, ecc.BLS12_381.ScalarField()); err != nil {
		t.Fatalf("STRAWMAN DID NOT SOLVE (test failed to capture the hole — HALT): %v", err)
	}
	t.Logf("SC-1 PASS: two-array strawman SOLVES — forged apk while the commitment is over the real committee (hole exploitable)")
}

func TestCommitteeBind_SC1_ProductionRejects(t *testing.T) {
	const n = 8
	real := bindPoints(t, n)
	forged := bindPoints(t, n)
	bits := patternBits(n)
	// production (one array): forged keys, but K over the REAL committee + forged apk.
	a := bindAssign(forged, bits, poseidonCommitFr(canonicalPacks(real)), aggregateApk(forged, bits))
	if err := solveBind(a); err == nil {
		t.Fatalf("PRODUCTION ACCEPTED forged keys against a real-committee commitment (REAL HOLE — HALT): SC-1 not closed")
	} else {
		t.Logf("SC-1 PASS: production REJECTS — one array forces forged through the bind, Poseidon(forged) != K(real): %v", err)
	}
}
