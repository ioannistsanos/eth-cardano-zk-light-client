// Command poc_encoding_sc4 settles the SC-4 encoding question OFF-CIRCUIT with real
// gnark-crypto BLS12-381, SYMMETRICALLY: does the commitment encoding pin the full
// point or only part of it?
//
//   - Encoding B (48-byte COMPRESSED): a DIFFERENT, OFF-CURVE y_fake with the same sign
//     yields the SAME compressed bytes, so a Poseidon-over-compressed commitment
//     ACCEPTS it -> B is unsound WITHOUT an in-circuit on-curve check in the regular path.
//   - Encoding A (full x,y limbs): the SAME y_fake changes the committed bytes/limbs, so
//     a Poseidon-over-(x,y) commitment REJECTS it -> A pins the WHOLE point; no in-regular
//     validity needed (1c stays at op-6).
//
// The off-curve y_fake is constructed DETERMINISTICALLY (never inconclusive): the only
// on-curve y at a given x are {y_real, p-y_real}, which have OPPOSITE lexicographic
// signs, so ANY same-sign value != y_real is necessarily off-curve. Usage:
// go run ./cmd/poc_encoding_sc4
// SEC-01 Family-B encoding decision (Step-2a): docs/security/SEC-01-committee-binding-rogue-key.md
package main

import (
	"fmt"
	"math/big"
	"os"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fp"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

// compressG1 reproduces gnark-crypto's compressed encoding of an (x, sign) pair:
// big-endian x with the top byte carrying the compression flag (0x80) and, when y is
// the lexicographically-largest root, the sign flag (0x20). It depends ONLY on x and the
// sign bit — which is exactly why two different y with the same sign collide here.
func compressG1(x fp.Element, largest bool) [48]byte {
	b := x.Bytes() // canonical 48-byte big-endian; top 3 bits are free (p < 2^381)
	b[0] |= 0x80
	if largest {
		b[0] |= 0x20
	}
	return b
}

func isOnCurveG1(x, y fp.Element) bool {
	var lhs, rhs, four fp.Element
	four.SetUint64(4) // BLS12-381 G1: y^2 = x^3 + 4
	lhs.Square(&y)
	rhs.Square(&x).Mul(&rhs, &x).Add(&rhs, &four)
	return lhs.Equal(&rhs)
}

func main() {
	_, _, g1, _ := bls12381.Generators()
	var s fr.Element
	if _, err := s.SetRandom(); err != nil {
		halt(err.Error())
	}
	var sBig big.Int
	s.BigInt(&sBig)
	var P bls12381.G1Affine
	P.ScalarMultiplication(&g1, &sBig) // honest on-curve, in-subgroup point
	xReal, yReal := P.X, P.Y

	// Deterministic off-curve y_fake with the SAME lexicographic sign as y_real.
	var yFake fp.Element
	if yReal.LexicographicallyLargest() {
		var one fp.Element
		one.SetUint64(1)
		yFake.Neg(&one) // p-1, lexicographically largest
		if yFake.Equal(&yReal) {
			var two fp.Element
			two.SetUint64(2)
			yFake.Neg(&two) // p-2, still largest
		}
	} else {
		yFake.SetUint64(1) // lexicographically smallest
		if yFake.Equal(&yReal) {
			yFake.SetUint64(2)
		}
	}

	// Guarantees (assert; the construction makes these always hold).
	if yFake.Equal(&yReal) {
		halt("yFake == yReal")
	}
	if yFake.LexicographicallyLargest() != yReal.LexicographicallyLargest() {
		halt("yFake sign != yReal sign")
	}
	if isOnCurveG1(xReal, yFake) {
		halt("yFake unexpectedly ON curve")
	}

	compReal := compressG1(xReal, yReal.LexicographicallyLargest())
	compFake := compressG1(xReal, yFake.LexicographicallyLargest())
	libBytes := P.Bytes()
	matchesLib := compReal == libBytes         // sanity: our compress == gnark-crypto's
	bAccepts := compReal == compFake           // B: identical committed compressed bytes
	aRejects := yReal.Bytes() != yFake.Bytes() // A: full-y encoding differs

	fmt.Println("# SC-4 encoding settle (real BLS12-381) — symmetric")
	fmt.Printf("our compress(x,sign) == gnark-crypto P.Bytes() (sanity): %v\n", matchesLib)
	fmt.Printf("y_fake != y_real: %v ; same sign: %v ; (x,y_fake) on curve: %v\n",
		!yFake.Equal(&yReal),
		yFake.LexicographicallyLargest() == yReal.LexicographicallyLargest(),
		isOnCurveG1(xReal, yFake))
	fmt.Printf("[B compressed] compressed(x,y_fake) == compressed(x,y_real): %v   <- B ACCEPTS the off-curve fake\n", bAccepts)
	fmt.Printf("[A full x,y ]  bytes(y_real) != bytes(y_fake): %v                <- A REJECTS it (different commitment)\n", aRejects)
	fmt.Println()
	if matchesLib && bAccepts && aRejects && !isOnCurveG1(xReal, yFake) {
		fmt.Println("VERDICT (symmetric):")
		fmt.Println(" B (compressed): an OFF-CURVE y_fake with the same sign yields the SAME compressed bytes,")
		fmt.Println("   so a Poseidon-over-compressed commitment ACCEPTS it -> B is UNSOUND without an in-circuit")
		fmt.Println("   on-curve check; the regular path must add on-curve to pin y.")
		fmt.Println(" A (full x,y limbs): the SAME y_fake changes the committed bytes/limbs, so a Poseidon-over-")
		fmt.Println("   (x,y) commitment REJECTS it -> A PINS the whole point; no in-regular validity needed (1c at op-6).")
		os.Exit(0)
	}
	halt("inconclusive — should not happen with the deterministic construction")
}

func halt(m string) { fmt.Fprintln(os.Stderr, "HALT: "+m); os.Exit(1) }
