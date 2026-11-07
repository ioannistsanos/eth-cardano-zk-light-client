package commitment

import (
	"encoding/hex"
	"math/big"
	"testing"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fp"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	poseidon2 "github.com/consensys/gnark-crypto/ecc/bls12-381/fr/poseidon2"
)

func frHex(e fr.Element) string { b := e.Bytes(); return hex.EncodeToString(b[:]) }

// deterministicPoints returns n on-curve G1 points (k·G for k=1..n) — self-contained,
// no dependency on circuits/common test helpers.
func deterministicPoints(n int) []bls12381.G1Affine {
	_, _, g1Gen, _ := bls12381.Generators()
	pts := make([]bls12381.G1Affine, n)
	for i := range pts {
		pts[i].ScalarMultiplication(&g1Gen, big.NewInt(int64(i+1)))
	}
	return pts
}

// inlineOriginalCommit is a VERBATIM copy of the pre-extraction off-circuit twin
// (op6assemble_test.poseidonCommitOffCircuit): pack each point X_lo,X_hi,Y_lo,Y_hi via the
// mod-2^192 fold, then Poseidon2 Merkle–Damgård. Independent of the package code, so the
// equivalence test proves the extraction is byte-faithful to the original twin.
func inlineOriginalCommit(points []bls12381.G1Affine) fr.Element {
	fold := func(c fp.Element) (lo, hi fr.Element) {
		var b big.Int
		c.BigInt(&b)
		mask192 := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 192), big.NewInt(1))
		lo.SetBigInt(new(big.Int).And(&b, mask192))
		hi.SetBigInt(new(big.Int).Rsh(&b, 192))
		return
	}
	hasher := poseidon2.NewMerkleDamgardHasher()
	for _, P := range points {
		xLo, xHi := fold(P.X)
		yLo, yHi := fold(P.Y)
		for _, fe := range []fr.Element{xLo, xHi, yLo, yHi} {
			b := fe.Bytes()
			hasher.Write(b[:])
		}
	}
	var out fr.Element
	out.SetBytes(hasher.Sum(nil))
	return out
}

// TestCommit_EquivalentToInlineOriginal: the extracted Commit is byte-identical to a verbatim
// inline copy of the pre-extraction twin, over several committee sizes — the move is faithful.
func TestCommit_EquivalentToInlineOriginal(t *testing.T) {
	for _, n := range []int{1, 2, 5, 8, 16} {
		pts := deterministicPoints(n)
		if got, want := Commit(pts), inlineOriginalCommit(pts); got != want {
			t.Fatalf("Commit != inline original at n=%d:\n got  %s\n want %s", n, frHex(got), frHex(want))
		}
	}
}

// TestCommit_GoldenValue pins the ABSOLUTE commitment of a fixed input (the G1 generator)
// to a hardcoded constant — an external anchor that catches a change in pack order, fold
// width, endianness, or the Poseidon2 params even if both the package and an inline copy
// changed together.
func TestCommit_GoldenValue(t *testing.T) {
	const wantHex = "4df3ca8a29f6b37c04fefb167022ae638df17383caf668b718bf3b65aa320652"
	got := frHex(Commit(deterministicPoints(1))) // Commit([1·G]) = Commit([generator])
	t.Logf("Commit([G1 generator]) = %s", got)
	if got != wantHex {
		t.Fatalf("golden mismatch:\n got  %s\n want %s", got, wantHex)
	}
}

// TestCommit_Deterministic: Poseidon2 is deterministic — the same committee → the same value.
func TestCommit_Deterministic(t *testing.T) {
	pts := deterministicPoints(4)
	if Commit(pts) != Commit(pts) {
		t.Fatal("Commit not deterministic")
	}
}
