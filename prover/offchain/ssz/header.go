// Package ssz provides minimal off-circuit SSZ helpers for the Ethereum
// BeaconBlockHeader (Phase-0, fork-invariant): deserialization, hash_tree_root,
// and the slot-binding Merkle branch (gindex 8). Pure Go (crypto/sha256), no
// gnark — reusable for witness building and vector validation. Validated in
// STEP-0 against an official Fulu consensus-spec-tests vector.
package ssz

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
)

type Header struct {
	Slot, ProposerIndex             uint64
	ParentRoot, StateRoot, BodyRoot [32]byte
}

func hashPair(left, right []byte) [32]byte {
	return sha256.Sum256(append(append([]byte{}, left...), right...))
}

// Uint64Chunk is the 32-byte SSZ chunk of a uint64: 8 little-endian bytes + 24 zero bytes.
func Uint64Chunk(value uint64) (chunk [32]byte) {
	binary.LittleEndian.PutUint64(chunk[:8], value)
	return
}

// Deserialize parses the fixed 112-byte SSZ encoding (8+8+32+32+32).
func Deserialize(serialized []byte) (Header, error) {
	var header Header
	if len(serialized) != 112 {
		return header, fmt.Errorf("expected 112-byte SSZ, got %d", len(serialized))
	}
	header.Slot = binary.LittleEndian.Uint64(serialized[0:8])
	header.ProposerIndex = binary.LittleEndian.Uint64(serialized[8:16])
	copy(header.ParentRoot[:], serialized[16:48])
	copy(header.StateRoot[:], serialized[48:80])
	copy(header.BodyRoot[:], serialized[80:112])
	return header, nil
}

// HashTreeRoot: 5 leaves padded to 8, 7 SHA-256 (validated vs the official root).
func (h Header) HashTreeRoot() [32]byte {
	var zeroChunk [32]byte
	slotLeaf := Uint64Chunk(h.Slot)
	proposerLeaf := Uint64Chunk(h.ProposerIndex)
	slotProposerNode := hashPair(slotLeaf[:], proposerLeaf[:])
	parentStateNode := hashPair(h.ParentRoot[:], h.StateRoot[:])
	bodyZeroNode := hashPair(h.BodyRoot[:], zeroChunk[:])
	zeroPairNode := hashPair(zeroChunk[:], zeroChunk[:])
	leftSubtreeRoot := hashPair(slotProposerNode[:], parentStateNode[:])
	rightSubtreeRoot := hashPair(bodyZeroNode[:], zeroPairNode[:])
	return hashPair(leftSubtreeRoot[:], rightSubtreeRoot[:])
}

// SlotBranch returns the 3 sibling hashes along the slot path (gindex 8 -> 1) —
// the private witness for the slot-binding proof. The slot leaf is the leftmost,
// so every step is H(node, sibling) (running node is the LEFT child):
//
//	siblingProposerLeaf = Uint64Chunk(proposer_index)     (node 9)
//	siblingParentState  = H(parent_root, state_root)      (node 5)
//	siblingBodySubtree  = H(H(body_root, 0), H(0, 0))     (node 3)
//
// These are exactly the intermediate nodes of HashTreeRoot.
func (h Header) SlotBranch() [3][32]byte {
	var zeroChunk [32]byte
	bodyZeroNode := hashPair(h.BodyRoot[:], zeroChunk[:])
	zeroPairNode := hashPair(zeroChunk[:], zeroChunk[:])
	proposerSibling := Uint64Chunk(h.ProposerIndex)
	parentStateSibling := hashPair(h.ParentRoot[:], h.StateRoot[:])
	bodySubtreeSibling := hashPair(bodyZeroNode[:], zeroPairNode[:])
	return [3][32]byte{proposerSibling, parentStateSibling, bodySubtreeSibling}
}
