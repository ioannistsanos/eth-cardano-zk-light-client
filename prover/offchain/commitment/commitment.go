// Package commitment computes the per-key Poseidon2 commitment that binds a sync
// committee's pubkeys — the SEC-01 Family-B committee identity that replaced the broken
// op-1 G₁ sum. It is the OFF-CIRCUIT TWIN of the in-circuit committeeBindAggregateCount
// (circuits/common/committeebind.go): the SAME field-element pack order (X_lo, X_hi, Y_lo,
// Y_hi per point) and the SAME Poseidon2 Merkle–Damgård hasher (gnark-crypto's canonical
// BLS12-381 instance — params 2/6/50, init 0, Compress). Production code that must reproduce
// the circuit's commitment off-chain — the bootstrap's condition (e), and witness building —
// shares THIS one source, so the value it computes is byte-identical to what the circuit
// binds; otherwise the genesis datum the bootstrap writes would never validate against the
// first regular update (the Poseidon-match). Extracted verbatim from the op6assemble_test /
// committeebind_test off-circuit twins; the circuit-solve tests pin the match.
//
// Canonicity caveat (condition (e)): a point with a non-canonical X or Y coordinate (≥ p)
// folds into a DIFFERENT pack and thus a different commitment for the SAME committee. The
// caller MUST enforce X/Y canonicity BEFORE Commit (the bootstrap's big.Int ≤ p−1 checks,
// mirroring the in-circuit decompresspubkey AssertIsLessOrEqual) — this package packs
// whatever coordinates it is given.
package commitment

import (
	"math/big"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fp"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	poseidon2 "github.com/consensys/gnark-crypto/ecc/bls12-381/fr/poseidon2"
)

// The Poseidon2 parameter set of the commitment hash — ONE shape shared by every consumer:
// the in-circuit committee bind (circuits/common/committeebind.go), op-6 Path-2
// (circuits/common/op6assemble.go), and this off-chain twin. gnark-crypto's canonical
// BLS12-381 instance (NewMerkleDamgardHasher, zero initial state) is exactly
// NewParameters(PoseidonWidth, PoseidonFullRounds, PoseidonPartialRounds) with the round
// keys seeded from the parameter string. poseidonparameters_test.go pins that equivalence,
// and circuits/common/poseidonparity_test.go pins the in-circuit construction to the same
// digest — so a silent upstream default change fails a test instead of splitting the sides.
const (
	PoseidonWidth         = 2
	PoseidonFullRounds    = 6
	PoseidonPartialRounds = 50
)

// FoldFp folds an Fp coordinate into (lo, hi) = (value mod 2^192, value >> 192) — the
// off-circuit twin of the in-circuit packCoordinate over the 6 emulated 64-bit limbs.
func FoldFp(e fp.Element) (lo, hi fr.Element) {
	var b big.Int
	e.BigInt(&b)
	mask192 := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 192), big.NewInt(1))
	lo.SetBigInt(new(big.Int).And(&b, mask192))
	hi.SetBigInt(new(big.Int).Rsh(&b, 192))
	return
}

// PackPoint packs a G1 point into [X_lo, X_hi, Y_lo, Y_hi] — the in-circuit field-element
// order. (A non-canonical X or Y produces a different pack — see the package canonicity note.)
func PackPoint(p bls12381.G1Affine) [4]fr.Element {
	xLo, xHi := FoldFp(p.X)
	yLo, yHi := FoldFp(p.Y)
	return [4]fr.Element{xLo, xHi, yLo, yHi}
}

// Pack flattens PackPoint over points → the committee's [X_lo,X_hi,Y_lo,Y_hi,…] Fr packs.
func Pack(points []bls12381.G1Affine) []fr.Element {
	elems := make([]fr.Element, 0, 4*len(points))
	for _, p := range points {
		fr4 := PackPoint(p)
		elems = append(elems, fr4[0], fr4[1], fr4[2], fr4[3])
	}
	return elems
}

// CommitElements is the Poseidon2 Merkle–Damgård commitment over pre-packed Fr elements —
// the low-level entry (the locking tests feed deliberately-crafted packs here).
func CommitElements(elems []fr.Element) fr.Element {
	hasher := poseidon2.NewMerkleDamgardHasher()
	for i := range elems {
		b := elems[i].Bytes()
		hasher.Write(b[:])
	}
	var out fr.Element
	out.SetBytes(hasher.Sum(nil))
	return out
}

// Commit is CommitElements(Pack(points)) — a committee's pubkeys_commitment.
func Commit(points []bls12381.G1Affine) fr.Element {
	return CommitElements(Pack(points))
}
