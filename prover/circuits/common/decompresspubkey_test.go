package common

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
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/test"
)

// validPoint returns a valid (subgroup) G1 point P = s·g1 and its compressed 48 bytes,
// with a decompress round-trip sanity (SetBytes(P.Bytes()) == P). Generated, not from
// the ssz_static vector, because those pubkeys are random non-points (2b-i layout only);
// the decompress unit is point-generic.
func validPoint(t *testing.T) (bls12381.G1Affine, [48]byte) {
	t.Helper()
	_, _, g1, _ := bls12381.Generators()
	var s fr.Element
	if _, err := s.SetRandom(); err != nil {
		t.Fatal(err)
	}
	var sBig big.Int
	s.BigInt(&sBig)
	var P bls12381.G1Affine
	P.ScalarMultiplication(&g1, &sBig)
	compressed := P.Bytes() // [48]byte, compressed
	var Q bls12381.G1Affine
	if _, err := Q.SetBytes(compressed[:]); err != nil {
		t.Fatalf("SetBytes: %v", err)
	}
	if !Q.Equal(&P) {
		t.Fatalf("decompress(compress(P)) != P")
	}
	return P, compressed
}

func onCurveG1(x, y fp.Element) bool {
	var lhs, rhs, four fp.Element
	four.SetUint64(4) // y^2 = x^3 + 4
	lhs.Square(&y)
	rhs.Square(&x).Mul(&rhs, &x).Add(&rhs, &four)
	return lhs.Equal(&rhs)
}

func emulatedY(y fp.Element) emulated.Element[sw_bls12381.BaseField] {
	var yBig big.Int
	y.BigInt(&yBig)
	return emulated.ValueOf[sw_bls12381.BaseField](yBig)
}

// solveDecompress runs the unit over one pubkey with the given y-hint via the SOLVER
// (no Groth16). Returns the solver error (nil = accepted).
func solveDecompress(compressed [48]byte, y fp.Element) error {
	assignment := NewDecompressPubkeyCircuit(1)
	assignment.Compressed[0] = toCircuitBytes48(compressed)
	assignment.YHint[0] = emulatedY(y)
	return test.IsSolved(NewDecompressPubkeyCircuit(1), assignment, ecc.BLS12_381.ScalarField())
}

// Positive: the unit ACCEPTS the real point (x from bytes, y = real y). Also gates the
// byte/bit endianness — a wrong x would fail on-curve with the real y.
func TestDecompressAcceptsRealPoint(t *testing.T) {
	P, compressed := validPoint(t)
	if err := solveDecompress(compressed, P.Y); err != nil {
		t.Fatalf("POSITIVE FAILED (endianness/API bug): real point rejected: %v", err)
	}
	t.Logf("PASS: decompress accepts the real point (recovered (x,y)=P)")
}

// Negative 1 — ON-CURVE teeth: an off-curve y with the SAME sign yields the SAME
// compressed bytes but must be rejected by the on-curve check (the SC-4 fix in-circuit).
func TestDecompressRejectsOffCurveY(t *testing.T) {
	P, compressed := validPoint(t)
	yFake := P.Y
	one := fp.One()
	found := false
	for i := 0; i < 8; i++ {
		yFake.Add(&yFake, &one)
		if yFake.LexicographicallyLargest() == P.Y.LexicographicallyLargest() && !onCurveG1(P.X, yFake) {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("could not construct same-sign off-curve y")
	}
	if err := solveDecompress(compressed, yFake); err == nil {
		t.Fatalf("NEGATIVE FAILED (ON-CURVE HAS NO TEETH): off-curve y ACCEPTED")
	} else {
		t.Logf("PASS: off-curve y rejected by on-curve: %v", err)
	}
}

// Negative 2 — SIGN-MATCH teeth: the OTHER on-curve root -y (= p-y) is on-curve but has
// the opposite sign, so sign-match must reject it (pins the UNIQUE root = injectivity).
func TestDecompressRejectsWrongSignY(t *testing.T) {
	P, compressed := validPoint(t)
	var negY fp.Element
	negY.Neg(&P.Y)
	if !onCurveG1(P.X, negY) {
		t.Fatalf("(x,-y) unexpectedly not on curve")
	}
	if negY.LexicographicallyLargest() == P.Y.LexicographicallyLargest() {
		t.Fatalf("-y unexpectedly same sign as y")
	}
	if err := solveDecompress(compressed, negY); err == nil {
		t.Fatalf("NEGATIVE FAILED (SIGN-MATCH HAS NO TEETH): wrong-sign y ACCEPTED")
	} else {
		t.Logf("PASS: wrong-sign -y rejected by sign-match: %v", err)
	}
}

// End-to-end: the unit is genuinely Setup->Prove->Verify-able at small N.
func TestDecompressProvesSmallN(t *testing.T) {
	field := ecc.BLS12_381.ScalarField()
	for _, n := range []int{1, 2} {
		assignment := NewDecompressPubkeyCircuit(n)
		for i := 0; i < n; i++ {
			P, compressed := validPoint(t)
			assignment.Compressed[i] = toCircuitBytes48(compressed)
			assignment.YHint[i] = emulatedY(P.Y)
		}
		constraintSystem, err := frontend.Compile(field, r1cs.NewBuilder, NewDecompressPubkeyCircuit(n))
		if err != nil {
			t.Fatalf("compile N=%d: %v", n, err)
		}
		provingKey, verifyingKey, err := groth16.Setup(constraintSystem)
		if err != nil {
			t.Fatalf("setup N=%d: %v", n, err)
		}
		witness, err := frontend.NewWitness(assignment, field)
		if err != nil {
			t.Fatalf("witness N=%d: %v", n, err)
		}
		publicWitness, err := witness.Public()
		if err != nil {
			t.Fatalf("public N=%d: %v", n, err)
		}
		proof, err := groth16.Prove(constraintSystem, provingKey, witness)
		if err != nil {
			t.Fatalf("prove N=%d: %v", n, err)
		}
		if err := groth16.Verify(proof, verifyingKey, publicWitness); err != nil {
			t.Fatalf("verify N=%d: %v", n, err)
		}
		t.Logf("PASS: N=%d Groth16 Setup->Prove->Verify (%d constraints)", n, constraintSystem.GetNbConstraints())
	}
}

// solveDecompressY is solveDecompress with a pre-built emulated y-hint (the
// non-canonical-y test needs raw limbs that emulatedY/ValueOf would reduce).
func solveDecompressY(compressed [48]byte, y emulated.Element[sw_bls12381.BaseField]) error {
	assignment := NewDecompressPubkeyCircuit(1)
	assignment.Compressed[0] = toCircuitBytes48(compressed)
	assignment.YHint[0] = y
	return test.IsSolved(NewDecompressPubkeyCircuit(1), assignment, ecc.BLS12_381.ScalarField())
}

// nonCanonicalY builds an emulated y-hint whose limbs literally encode y + p (a
// non-canonical representative in [p, 2p), ≡ y mod p). emulated.ValueOf would reduce
// it mod p, so the 6 BLS12381Fp limbs are decomposed by hand. In-circuit, on-curve
// passes ((y+p)^2 ≡ y^2 mod p) but ToBitsCanonical (y < p) must reject it.
func nonCanonicalY(y fp.Element) emulated.Element[sw_bls12381.BaseField] {
	var yBig big.Int
	y.BigInt(&yBig)
	yPlusP := new(big.Int).Add(&yBig, ecc.BLS12_381.BaseField()) // y + p, in [p, 2p)
	mask := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 64), big.NewInt(1))
	tmp := new(big.Int).Set(yPlusP)
	limbs := make([]frontend.Variable, 6) // BLS12381Fp = 6 × 64-bit limbs
	for i := 0; i < 6; i++ {
		limbs[i] = new(big.Int).And(tmp, mask)
		tmp.Rsh(tmp, 64)
	}
	return emulated.Element[sw_bls12381.BaseField]{Limbs: limbs}
}

// Negative — GAP-d (F1): a byte0 with the infinity flag (bit 6) set is malformed; the
// flag check must reject it even though x and the real y are otherwise consistent (x is
// built only from bits 4:0, so it is unchanged — only the flag check has teeth here).
func TestDecompressRejectsInfinityFlag(t *testing.T) {
	P, compressed := validPoint(t)
	compressed[0] |= 0x40 // set infinity flag — a real pubkey is never the identity
	if err := solveDecompress(compressed, P.Y); err == nil {
		t.Fatalf("NEGATIVE FAILED (FLAG CHECK HAS NO TEETH): infinity-flagged byte0 ACCEPTED")
	} else {
		t.Logf("PASS: infinity-flagged byte0 rejected by the flag check: %v", err)
	}
}

// Negative — GAP-d (F1): a byte0 with the compression flag (bit 7) cleared is not a
// compressed encoding; the flag check must reject it.
func TestDecompressRejectsCompressionClear(t *testing.T) {
	P, compressed := validPoint(t)
	compressed[0] &= 0x7F // clear compression flag — not a compressed point
	if err := solveDecompress(compressed, P.Y); err == nil {
		t.Fatalf("NEGATIVE FAILED (FLAG CHECK HAS NO TEETH): compression-clear byte0 ACCEPTED")
	} else {
		t.Logf("PASS: compression-clear byte0 rejected by the flag check: %v", err)
	}
}

// Negative — F6 (Y-canonicity): a non-canonical y' = y + p (≥ p) passes on-curve
// (≡ y mod p) and sign, and ToBitsCanonical does NOT reject it (it returns reduced
// bits); the explicit AssertIsLessOrEqual(y, p-1) must reject it, so the point's Y
// limbs that feed the Poseidon commitment are canonical (deterministic commitment).
func TestDecompressRejectsNonCanonicalY(t *testing.T) {
	P, compressed := validPoint(t)
	if err := solveDecompressY(compressed, nonCanonicalY(P.Y)); err == nil {
		t.Fatalf("NEGATIVE FAILED (Y-CANONICITY HAS NO TEETH): non-canonical y+p ACCEPTED")
	} else {
		t.Logf("PASS: non-canonical y+p rejected by AssertIsLessOrEqual: %v", err)
	}
}
