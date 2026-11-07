// ssztree.go — reusable in-circuit SSZ building blocks (gnark): uint64 leaf
// encoding, the zero chunk, and the 64-byte node-hash. Used by the Merkle
// operations (op-3a here, op-3b next). The in-circuit counterpart of the
// off-circuit offchain/ssz helpers (validated against the official Fulu root).
package common

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/sha2"
	"github.com/consensys/gnark/std/math/bits"
	"github.com/consensys/gnark/std/math/uints"
)

// encodeUint64ToSszLeaf encodes a uint64 (a circuit variable) to its 32-byte SSZ
// leaf chunk: 8 little-endian bytes + 24 zero bytes. ToBinary(64) also range-checks
// value < 2^64. (In-circuit counterpart of offchain/ssz.Uint64Chunk.)
func encodeUint64ToSszLeaf(api frontend.API, uintsAPI *uints.BinaryField[uints.U32], value frontend.Variable) []uints.U8 {
	littleEndianBits := bits.ToBinary(api, value, bits.WithNbDigits(64))
	leaf := make([]uints.U8, 32)
	for k := 0; k < 8; k++ {
		leaf[k] = uintsAPI.ByteValueOf(bits.FromBinary(api, littleEndianBits[8*k:8*k+8]))
	}
	for k := 8; k < 32; k++ {
		leaf[k] = uints.NewU8(0)
	}
	return leaf
}

// sszZeroChunk returns a 32-byte zero leaf (the SSZ padding chunk).
func sszZeroChunk() []uints.U8 {
	zeroChunk := make([]uints.U8, 32)
	for k := range zeroChunk {
		zeroChunk[k] = uints.NewU8(0)
	}
	return zeroChunk
}

// sszMerkleizer computes SSZ parent nodes H(left || right) and latches the first
// sha2-construction error, checked once with Err() after the tree is built.
type sszMerkleizer struct {
	api frontend.API
	err error
}

func (m *sszMerkleizer) parent(left, right []uints.U8) []uints.U8 {
	if m.err != nil {
		return nil
	}
	hasher, err := sha2.New(m.api)
	if err != nil {
		m.err = err
		return nil
	}
	hasher.Write(left)
	hasher.Write(right)
	return hasher.Sum()
}

func (m *sszMerkleizer) Err() error { return m.err }
