// slotbind.go — operation 4 (slot binding): prove finalized_slot is field 0
// (gindex 8) of a BeaconBlockHeader, binding to finalized_header_root via a fixed
// SSZ Merkle path (8->4->2->1, sibling order [L,L,L] — the slot leaf is leftmost,
// so the running node is always the LEFT child: every step H(node, sibling)).
//
// finalized_slot is taken as a NUMBER (frontend.Variable) — needed for later
// numeric checks (on-chain finalized_slot > datum.slot) — and encoded IN-CIRCUIT
// to its 32-byte SSZ leaf (8 little-endian bytes + 24 zero bytes), the form
// SHA-256 needs. Number<->bytes: leaf[k] = (slot >> 8k) & 0xff for k<8, else 0.
// Siblings are private witnesses, computed off-circuit by offchain/ssz.SlotBranch.
// Correctness-first: no optimization (no zero-subtree hardcoding).
package common

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
)

type SlotBindCircuit struct {
	FinalizedSlot frontend.Variable `gnark:",public"`
	HeaderRoot    [32]uints.U8      `gnark:",public"`
	HeaderBranch  [][32]uints.U8    // private; len = number of Merkle steps (3 for op-4)
}

// NewSlotBindCircuit allocates the circuit with `steps` Merkle steps (3 = real
// op-4; smaller values are used only for the cost decomposition in measure_slotbind).
func NewSlotBindCircuit(steps int) *SlotBindCircuit {
	return &SlotBindCircuit{HeaderBranch: make([][32]uints.U8, steps)}
}

func (c *SlotBindCircuit) Define(api frontend.API) error {
	uintsAPI, err := uints.New[uints.U32](api)
	if err != nil {
		return err
	}
	merkleizer := &sszMerkleizer{api: api}
	return slotWalk(api, uintsAPI, merkleizer, c.FinalizedSlot, c.HeaderBranch, c.HeaderRoot)
}

// slotWalk encodes finalizedSlot to its 32-byte SSZ leaf and folds it up the all-left
// gindex-8 path (every step H(node, sibling) — the slot leaf is leftmost) to
// finalizedHeaderRoot — op-4's terminal. Shared by the standalone SlotBindCircuit (where
// finalizedHeaderRoot is the public input) and, later, the assembled regular/boundary
// circuits (where it is op-3b's LEAF wire — the same finalized_header_root op-3b walks up
// to state_root). Uses the shared ssztree helpers (encodeUint64ToSszLeaf +
// merkleizer.parent — the same SHA-256 node-hash op-3a/op-3b use); the caller creates
// uintsAPI + merkleizer once (uintsAPI carries the shared ~131K `uints` intercept). The
// pre-terminal Err() check guards against parent's nil-on-error reaching ByteAssertEq.
func slotWalk(
	api frontend.API,
	uintsAPI *uints.BinaryField[uints.U32],
	merkleizer *sszMerkleizer,
	finalizedSlot frontend.Variable,
	branch [][32]uints.U8,
	finalizedHeaderRoot [32]uints.U8,
) error {
	node := encodeUint64ToSszLeaf(api, uintsAPI, finalizedSlot)
	for step := range branch {
		node = merkleizer.parent(node, branch[step][:])
	}
	if err := merkleizer.Err(); err != nil {
		return err
	}
	// The computed root must equal the public finalized_header_root.
	for j := 0; j < 32; j++ {
		uintsAPI.ByteAssertEq(finalizedHeaderRoot[j], node[j])
	}
	return nil
}
