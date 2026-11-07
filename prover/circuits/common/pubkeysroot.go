// pubkeysroot.go — operation-6 SHA side (2b-i of the SEC-01 Family-B translation
// hinge): in-circuit SSZ hash_tree_root of SyncCommittee.pubkeys = Vector[Bytes48, N]
// (N a power of two; the real committee is 512 = 2^9). Per-pubkey leaf =
// SHA-256(pk[0:32] ‖ (pk[32:48] ‖ 16 zero bytes)); then a perfect balanced tree (no
// padding, no length-mixing — it is a Vector, not a List). 2N-1 node-hashes via the
// shared sszMerkleizer.parent (1,023 for N=512). This is ONLY the SHA side; the
// single-source tie to the Poseidon limbs (2b-iii), the gindex-87 BeaconState walk
// (2b-iii) and subgroup-inheritance (2b-ii) are NOT here.
package common

import (
	"fmt"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
)

type PubkeysRootCircuit struct {
	Pubkeys      [][48]uints.U8
	ExpectedRoot [32]uints.U8 `gnark:",public"` // the gindex-174 root (public here; an internal wire in op-6)
}

// NewPubkeysRootCircuit allocates the circuit for numberOfPubkeys pubkeys (a power of two).
func NewPubkeysRootCircuit(numberOfPubkeys int) *PubkeysRootCircuit {
	return &PubkeysRootCircuit{Pubkeys: make([][48]uints.U8, numberOfPubkeys)}
}

func (c *PubkeysRootCircuit) Define(api frontend.API) error {
	uintsAPI, err := uints.New[uints.U32](api)
	if err != nil {
		return err
	}
	root, err := derivePubkeysRoot(api, c.Pubkeys)
	if err != nil {
		return err
	}
	for j := 0; j < 32; j++ {
		uintsAPI.ByteAssertEq(c.ExpectedRoot[j], root[j])
	}
	return nil
}

// derivePubkeysRoot computes the in-circuit SSZ hash_tree_root of
// SyncCommittee.pubkeys = Vector[Bytes48, N] (N a power of two) and RETURNS the
// gindex-174 root (32 bytes). It is the shared core used by the standalone
// PubkeysRootCircuit (which asserts it against the public ExpectedRoot) and — via the
// 2b-iii assembly — by op-6 (which feeds it forward into the gindex-87 BeaconState
// walk instead of asserting it against a witness; that substitution is the SC-2 fix).
// Per-pubkey leaf = SHA-256(pk[0:32] ‖ (pk[32:48] ‖ 16 zero bytes)); then a perfect
// balanced tree (no padding, no length-mixing — it is a Vector, not a List).
func derivePubkeysRoot(api frontend.API, pubkeys [][48]uints.U8) ([]uints.U8, error) {
	// Guard: the balanced halving assumes a power-of-two leaf count (512 = 2^9 for the
	// real committee); a non-power-of-two N would silently drop the trailing node
	// (len/2 truncation) and mis-merkleize. Fail compilation instead. (F7.)
	if n := len(pubkeys); n == 0 || n&(n-1) != 0 {
		return nil, fmt.Errorf("derivePubkeysRoot requires a power-of-two pubkey count, got %d", n)
	}
	merkleizer := &sszMerkleizer{api: api}
	zero := sszZeroChunk() // 32 zero bytes; the leaf uses the first 16

	// Leaf root per pubkey: H(pk[0:32] ‖ (pk[32:48] ‖ 16 zero bytes)).
	level := make([][]uints.U8, len(pubkeys))
	for i := range pubkeys {
		chunk0 := pubkeys[i][0:32]
		chunk1 := append(append([]uints.U8{}, pubkeys[i][32:48]...), zero[:16]...)
		level[i] = merkleizer.parent(chunk0, chunk1)
	}
	// Balanced merkleization (len is 2^k → no padding): halve until one node remains.
	for len(level) > 1 {
		next := make([][]uints.U8, len(level)/2)
		for i := range next {
			next[i] = merkleizer.parent(level[2*i], level[2*i+1])
		}
		level = next
	}
	if merkleizer.Err() != nil {
		return nil, merkleizer.Err()
	}
	return level[0], nil
}
