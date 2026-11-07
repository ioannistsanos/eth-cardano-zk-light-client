// headerreconstruct.go — operation 3a (header reconstruction, top box of Image-1):
// reconstruct the BeaconBlockHeader root from its 5 fields via the FULL SSZ
// merkleization (5 leaves -> 8, 7 SHA-256 — the complete tree, not a branch), bind
// it to attested_header_root, and EXTRACT state_root (field 3) as the clean
// in-circuit value that op-3b consumes.
//
// Full reconstruction (vs op-4's branch walk) is what makes every field available
// — especially state_root. slot and proposer_index are taken as NUMBERS and encoded
// in-circuit to their little-endian 32-byte SSZ leaves (encodeUint64ToSszLeaf, the
// op-4-proven technique). Correctness-first: all 7 hashes computed (no zero-subtree
// hardcoding — a separate later optimization).
package common

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
)

type HeaderReconstructCircuit struct {
	// 5 BeaconBlockHeader fields (private witness).
	Slot          frontend.Variable // uint64
	ProposerIndex frontend.Variable // uint64
	ParentRoot    [32]uints.U8
	StateRoot     [32]uints.U8
	BodyRoot      [32]uints.U8

	AttestedHeaderRoot [32]uints.U8 `gnark:",public"`
	// ExtractedStateRoot is PUBLIC in this standalone op so the test can check it
	// equals the vector's state_root. In the full regular circuit this becomes an
	// INTERNAL wire feeding op-3b directly (not a public input).
	ExtractedStateRoot [32]uints.U8 `gnark:",public"`
}

func (c *HeaderReconstructCircuit) Define(api frontend.API) error {
	uintsAPI, err := uints.New[uints.U32](api)
	if err != nil {
		return err
	}
	reconstructedRoot, err := reconstructHeaderRoot(api, uintsAPI, c.Slot, c.ProposerIndex, c.ParentRoot, c.StateRoot, c.BodyRoot)
	if err != nil {
		return err
	}

	// Binding 1: the reconstructed root == attested_header_root (public).
	for j := 0; j < 32; j++ {
		uintsAPI.ByteAssertEq(c.AttestedHeaderRoot[j], reconstructedRoot[j])
	}
	// Binding 2: the extracted state_root == the witness state_root used in the
	// reconstruction (in the full circuit this wire goes straight into op-3b).
	for j := 0; j < 32; j++ {
		uintsAPI.ByteAssertEq(c.ExtractedStateRoot[j], c.StateRoot[j])
	}
	return nil
}

// reconstructHeaderRoot performs the full SSZ merkleization of the 5-field
// BeaconBlockHeader (5 leaves padded to 8, 7 SHA-256) and RETURNS the reconstructed
// root. Shared by the standalone HeaderReconstructCircuit (op-3a, which binds it to
// attested_header_root) and by the 2b-iii op-6 assembly, which reuses op-3a's EXACT
// reconstruction so the assembly's state_root terminal is the SAME authenticated wire.
// slot and proposer_index are taken as numbers and encoded in-circuit to LE leaves.
func reconstructHeaderRoot(api frontend.API, uintsAPI *uints.BinaryField[uints.U32], slot, proposerIndex frontend.Variable, parentRoot, stateRoot, bodyRoot [32]uints.U8) ([]uints.U8, error) {
	// Encode the two uint64 fields to their LE 32-byte SSZ leaves.
	slotLeaf := encodeUint64ToSszLeaf(api, uintsAPI, slot)
	proposerLeaf := encodeUint64ToSszLeaf(api, uintsAPI, proposerIndex)
	zeroChunk := sszZeroChunk()

	// Full SSZ merkleization of the 5-field header (5 leaves padded to 8, 7 SHA-256).
	merkleizer := &sszMerkleizer{api: api}
	slotProposerNode := merkleizer.parent(slotLeaf, proposerLeaf)
	parentStateNode := merkleizer.parent(parentRoot[:], stateRoot[:])
	bodyZeroNode := merkleizer.parent(bodyRoot[:], zeroChunk)
	zeroPairNode := merkleizer.parent(zeroChunk, zeroChunk)
	leftSubtreeRoot := merkleizer.parent(slotProposerNode, parentStateNode)
	rightSubtreeRoot := merkleizer.parent(bodyZeroNode, zeroPairNode)
	reconstructedRoot := merkleizer.parent(leftSubtreeRoot, rightSubtreeRoot)
	if merkleizer.Err() != nil {
		return nil, merkleizer.Err()
	}
	return reconstructedRoot, nil
}
