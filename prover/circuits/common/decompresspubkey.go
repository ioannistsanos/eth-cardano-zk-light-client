// decompresspubkey.go — op-6 decompress-and-validate unit (SEC-01 Family-B 2b-ii):
// from a compressed 48-byte BLS pubkey (the SHA-side bytes, byte-pinned to the real
// committee member by the gindex-174 inheritance — Links A–D), recover the affine
// point (x,y) that Poseidon (encoding A) + op-1/op-2 need, via a witnessed y-hint
// PINNED by ON-CURVE + SIGN-MATCH + CANONICAL-X (never an in-circuit sqrt). Compression
// is injective on the curve, so these recover EXACTLY the real point => the prime-order
// subgroup check is redundant (SEC-01 §8c), GIVEN the bytes are byte-pinned (SC-2, 2b-iii).
// Four-in-one: SC-1 (single source = bytes), SC-4 (pins y), encoding-A limbs, subgroup-saving.
package common

import (
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bls12381"
	"github.com/consensys/gnark/std/math/bits"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"
)

type DecompressPubkeyCircuit struct {
	Compressed [][48]uints.U8                            // SHA-side bytes (the single source)
	YHint      []emulated.Element[sw_bls12381.BaseField] // decompression hint, pinned by on-curve+sign
}

// NewDecompressPubkeyCircuit allocates the circuit for numberOfPubkeys pubkeys.
func NewDecompressPubkeyCircuit(numberOfPubkeys int) *DecompressPubkeyCircuit {
	return &DecompressPubkeyCircuit{
		Compressed: make([][48]uints.U8, numberOfPubkeys),
		YHint:      make([]emulated.Element[sw_bls12381.BaseField], numberOfPubkeys),
	}
}

func (c *DecompressPubkeyCircuit) Define(api frontend.API) error {
	field, err := emulated.NewField[sw_bls12381.BaseField](api)
	if err != nil {
		return err
	}
	g1, err := sw_bls12381.NewG1(api)
	if err != nil {
		return err
	}
	for i := range c.Compressed {
		decompressAndValidate(api, field, g1, c.Compressed[i], c.YHint[i])
	}
	return nil
}

// decompressAndValidate recovers the affine point (x,y) from one compressed 48-byte
// BLS pubkey and RETURNS it, pinning it with FLAG-VALIDITY + CANONICAL-X + ON-CURVE +
// SIGN-MATCH (never an in-circuit sqrt). The standalone DecompressPubkeyCircuit calls
// it per pubkey (validation only); the 2b-iii op-6 assembly calls it and consumes the
// returned point's limbs for the Poseidon commitment (and, when added, op-1/op-2). The
// flag asserts (GAP-d, F1) make the unit self-sufficient: a malformed/infinity-flagged
// byte0 is rejected HERE, not left to SC-2 byte-pinning.
func decompressAndValidate(
	api frontend.API,
	field *emulated.Field[sw_bls12381.BaseField],
	g1 *sw_bls12381.G1,
	compressed [48]uints.U8,
	yHint emulated.Element[sw_bls12381.BaseField],
) sw_bls12381.G1Affine {
	p := ecc.BLS12_381.BaseField()
	pMinus1 := new(big.Int).Sub(p, big.NewInt(1))
	halfModulus := new(big.Int).Rsh(pMinus1, 1) // (p-1)/2
	pMinus1Elem := field.NewElement(pMinus1)

	// (1) x from 48 big-endian bytes; byte[0] top 3 bits = flags (compression/inf/sign),
	//     low 5 bits = x's 5 MSBs. Collect x's 381 bits MSB-first, reverse to LE for FromBits.
	b0 := bits.ToBinary(api, compressed[0].Val, bits.WithNbDigits(8)) // LE bits of byte0
	// (GAP-d, F1) flag-validity: a compressed encoding MUST set the compression flag
	// (bit 7) and clear the infinity flag (bit 6); otherwise byte0 is malformed (a real
	// pubkey is never the identity) and the recovered x is meaningless. Without these,
	// such a byte0 would be silently reinterpreted as an ordinary affine point.
	api.AssertIsEqual(b0[7], 1)
	api.AssertIsEqual(b0[6], 0)
	signBit := b0[5] // 0x20 = lexicographically-largest flag
	var msbFirst []frontend.Variable
	for k := 4; k >= 0; k-- { // byte0 low 5 bits = x bits 380..376
		msbFirst = append(msbFirst, b0[k])
	}
	for j := 1; j < 48; j++ {
		bj := bits.ToBinary(api, compressed[j].Val, bits.WithNbDigits(8))
		for k := 7; k >= 0; k-- {
			msbFirst = append(msbFirst, bj[k])
		}
	}
	le := make([]frontend.Variable, len(msbFirst))
	for k := range msbFirst {
		le[k] = msbFirst[len(msbFirst)-1-k]
	}
	x := field.FromBits(le...)
	field.AssertIsLessOrEqual(x, pMinus1Elem) // canonical: x <= p-1

	// (2) ON-CURVE with the y-hint -> pins y to a root of y^2 = x^3 + 4.
	point := sw_bls12381.G1Affine{X: *x, Y: yHint}
	g1.AssertIsOnCurve(&point)

	// (3) CANONICAL-Y (F6): ToBitsCanonical does NOT reject a non-canonical
	// (>= p) witness — it returns the bits of the REDUCED value — so enforce y <= p-1
	// explicitly, mirroring the x check. The returned point's Y limbs feed the op-6
	// Poseidon commitment (encoding A), which must be a deterministic function of the
	// committee; a non-canonical y would yield a DIFFERENT commitment for the same point
	// (a griefing/liveness hole, not a forgery — x and sign already pin the point).
	field.AssertIsLessOrEqual(&yHint, pMinus1Elem)

	// (4) SIGN-MATCH: lexicographically-largest(y) == signBit -> pins WHICH root = real point.
	yBits := field.ToBitsCanonical(&yHint)
	api.AssertIsEqual(bitsGreaterThanConstant(api, yBits, halfModulus), signBit)

	return point
}

// bitsGreaterThanConstant returns 1 iff the little-endian bit value > constant.
func bitsGreaterThanConstant(api frontend.API, valueLE []frontend.Variable, constant *big.Int) frontend.Variable {
	isGreater := frontend.Variable(0)
	isEqualSoFar := frontend.Variable(1)
	for i := len(valueLE) - 1; i >= 0; i-- {
		vi := valueLE[i]
		if constant.Bit(i) == 0 {
			isGreater = api.Add(isGreater, api.Mul(isEqualSoFar, vi))
			isEqualSoFar = api.Mul(isEqualSoFar, api.Sub(1, vi))
		} else {
			isEqualSoFar = api.Mul(isEqualSoFar, vi)
		}
	}
	return isGreater
}
