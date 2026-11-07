// sha256.go exercises gnark's in-circuit SHA-256 (std/hash/sha2) — the basis of
// the real circuit's operations 3 & 4 (SSZ Merkle proofs). Used by
// cmd/measure_sha256 (per-compression-block R1CS cost) and sha256_test.go
// (functional check). See benchmarks/phase-2-circuit/sha256-constraint-cost.md.
package common

import (
	"fmt"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/sha2"
	"github.com/consensys/gnark/std/math/uints"
)

// Sha256Blocks returns the number of SHA-256 compression blocks for an L-byte
// message: ceil((L+9)/64) — the +9 is the mandatory 0x80 byte + 8-byte length.
// Note blocks(32)=1 but blocks(64)=2 (the padding spills into a second block).
func Sha256Blocks(lengthBytes int) int { return (lengthBytes + 72) / 64 }

// Sha256Circuit hashes In with one sha2.Sum and asserts the digest equals
// Expected (32 bytes). The digest is CONSUMED (ByteAssertEq) so the compression
// constraints cannot be dead-code-eliminated; the assertion is a constant 32-byte
// overhead (folds into the regression intercept, not the per-block slope). For
// compile-only measurement In/Expected are unassigned (values are irrelevant to
// the count); the functional test assigns a known message + crypto/sha256 digest.
type Sha256Circuit struct {
	In       []uints.U8
	Expected [32]uints.U8
}

// NewSha256Circuit allocates a circuit hashing an input of lengthBytes bytes.
func NewSha256Circuit(lengthBytes int) *Sha256Circuit {
	return &Sha256Circuit{In: make([]uints.U8, lengthBytes)}
}

func (c *Sha256Circuit) Define(api frontend.API) error {
	hasher, err := sha2.New(api)
	if err != nil {
		return err
	}
	uintsAPI, err := uints.New[uints.U32](api)
	if err != nil {
		return err
	}
	hasher.Write(c.In)
	digest := hasher.Sum()
	if len(digest) != 32 {
		return fmt.Errorf("unexpected digest length %d", len(digest))
	}
	for i := range c.Expected {
		uintsAPI.ByteAssertEq(c.Expected[i], digest[i])
	}
	return nil
}
