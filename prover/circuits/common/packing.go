// packing.go — Option-P public-input packing for the assembled circuits. A 32-byte
// SSZ root packs into TWO native-Fr public inputs as big-endian 16-byte halves. This
// byte-endianness is a LOCKED public-input spec: the Plutus verifier re-derives the
// SAME two integers on-chain (byteStringToInteger over the two 16-byte halves), so a
// circuit-vs-Plutus endianness mismatch breaks on-chain verification SILENTLY — the
// circuit stays internally consistent, and the divergence only surfaces at Phase-3.
// The endianness-locking unit test (packing_test.go) pins it against an explicit
// big-endian off-circuit reference. The G1 apk packs via packCoordinate
// (op6assemble.go, the 6-limb fold), reused unchanged.
package common

import (
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
)

// packRoot folds a 32-byte SSZ root into two native-Fr field elements as big-endian
// 16-byte halves: out[0] = bigEndian(root[0:16]), out[1] = bigEndian(root[16:32]),
// where bigEndian(b) = Σ_{k<16} b[k]·256^(15−k). Each uints.U8 is already range-checked
// to <256, so each half is <2^128<r (injective base-256). The fold is a FREE linear
// combination (constant coefficients) — the cost is only the caller's equality asserts.
// This is the LOCKED Option-P public-input encoding the Plutus verifier re-derives.
func packRoot(api frontend.API, root []uints.U8) [2]frontend.Variable {
	packBigEndianHalf := func(half []uints.U8) frontend.Variable {
		accumulator := frontend.Variable(0)
		for k := 0; k < 16; k++ {
			weight := new(big.Int).Lsh(big.NewInt(1), uint(8*(15-k))) // 256^(15-k), big-endian
			accumulator = api.Add(accumulator, api.Mul(half[k].Val, weight))
		}
		return accumulator
	}
	return [2]frontend.Variable{packBigEndianHalf(root[0:16]), packBigEndianHalf(root[16:32])}
}
