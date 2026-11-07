// op3b.go — operation 3b (finality branch): prove finalized_header_root is the
// finalized checkpoint root of the ATTESTED state — a 7-step Merkle branch walk at
// FINALIZED_ROOT_GINDEX_ELECTRA = 169 (0b10101001, depth 7), from the
// finalized_header_root leaf up to BeaconBlockHeader.state_root.
//
// Mixed sibling sides [R,L,L,R,L,R,L] (unlike op-4's all-left gindex-8 path), so the
// walk branches per step like op-6's gindex-87 walk. Reuses sszMerkleizer.parent
// (consistent with op-3a/op-6; op-4 predates ssztree.go). The leaf is already a
// 32-byte root — no in-circuit leaf encoding; op-3b is purely 7 node-hashes.
//
// Isolated-op convention: StateRoot is PUBLIC here so the standalone tests can pin
// it; in the full regular/boundary circuit it is op-3a's extracted INTERNAL wire —
// the same authenticated state_root the op-6 walk terminates on. FinalizedHeaderRoot
// remains a public input in the full circuit (the datum-bound Phase-A output).
//
// Fork note: pre-Electra the finality gindex was 105 (depth 6) — the depth CHANGED
// 6->7 at Electra, unlike gindices 86/87/8. The [R,L,L,R,L,R,L] constant and
// the 7-element branch are pinned against a REAL Electra LightClientUpdate
// (op3b_test.go anchor + the independent Step-1 verification; fixture period 1600).
package common

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
)

// gindex169NodeIsRightChild[i] = (169 >> i) & 1 — the Electra FINALIZED_ROOT_GINDEX
// (169 = 0b10101001) path, finalized_header_root leaf (step 0) to BeaconState root
// (step 6). Right child => sibling on the left: H(sibling, node); else H(node,
// sibling). Compile-time constant, mixed [R,L,L,R,L,R,L].
var gindex169NodeIsRightChild = [7]bool{true, false, false, true, false, true, false}

type FinalityBranchCircuit struct {
	FinalizedHeaderRoot [32]uints.U8    `gnark:",public"`
	StateRoot           [32]uints.U8    `gnark:",public"` // op-3a's extracted wire in the full circuit
	FinalityBranch      [7][32]uints.U8 // private; the 7 gindex-169 siblings
}

func (c *FinalityBranchCircuit) Define(api frontend.API) error {
	uintsAPI, err := uints.New[uints.U32](api)
	if err != nil {
		return err
	}
	merkleizer := &sszMerkleizer{api: api}
	return finalityWalk(uintsAPI, merkleizer, c.FinalizedHeaderRoot, c.FinalityBranch, c.StateRoot)
}

// finalityWalk folds finalizedHeaderRoot up its 7-node gindex-169 finality branch
// (sibling sides per gindex169NodeIsRightChild) and asserts the result equals
// stateRoot — op-3b's terminal. Shared by the standalone FinalityBranchCircuit
// (where stateRoot is the public input) and, later, the assembled regular/boundary
// circuits (where stateRoot is op-3a's authenticated wire — the single-source). The
// caller creates uintsAPI + merkleizer once (uintsAPI carries the shared ~131K
// `uints` intercept). The pre-terminal Err() check guards against parent's
// nil-on-error reaching ByteAssertEq.
func finalityWalk(
	uintsAPI *uints.BinaryField[uints.U32],
	merkleizer *sszMerkleizer,
	finalizedHeaderRoot [32]uints.U8,
	branch [7][32]uints.U8,
	stateRoot [32]uints.U8,
) error {
	node := finalizedHeaderRoot[:]
	for step := range branch {
		if gindex169NodeIsRightChild[step] {
			node = merkleizer.parent(branch[step][:], node)
		} else {
			node = merkleizer.parent(node, branch[step][:])
		}
	}
	if err := merkleizer.Err(); err != nil {
		return err
	}
	// The walk must terminate on the attested state_root.
	for j := 0; j < 32; j++ {
		uintsAPI.ByteAssertEq(stateRoot[j], node[j])
	}
	return nil
}
