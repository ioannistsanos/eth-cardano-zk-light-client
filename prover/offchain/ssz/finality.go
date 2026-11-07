package ssz

// Off-circuit SSZ helper for op-3b (the finality branch): fold finalized_header_root
// up the 7-node finality_branch (Electra FINALIZED_ROOT_GINDEX 169) to the BeaconState
// root (== attested_header.beacon.state_root). Pure Go (crypto/sha256 via hashPair),
// the off-circuit counterpart of circuits/common/op3b.go — used for witness building
// and the real-data anchor. Fork note: pre-Electra the finality gindex was 105
// (depth 6); the depth CHANGED 6->7 at Electra — unlike gindices 86/87/8 — so the
// 7-element branch is fork-sensitive and is pinned against a real Electra
// LightClientUpdate (op3b_test.go anchor; fixture period 1600).

// gindex169NodeIsRightChild[i] = (169 >> i) & 1: the path of FINALIZED_ROOT_GINDEX
// (Electra, 169 = 0b10101001) from the finalized_header_root leaf (step 0) up to the
// BeaconState root (step 6). At a right-child step the running node is the right
// child, so its sibling is on the LEFT: H(sibling, node); otherwise H(node, sibling).
// Mixed [R,L,L,R,L,R,L] — unlike the all-left slot path (gindex 8).
var gindex169NodeIsRightChild = [7]bool{true, false, false, true, false, true, false}

// Gindex169Walk folds finalized_header_root up its 7-node finality_branch to the
// BeaconState root (== the attested BeaconBlockHeader.state_root).
func Gindex169Walk(finalizedHeaderRoot [32]byte, branch [7][32]byte) [32]byte {
	node := finalizedHeaderRoot
	for step := 0; step < 7; step++ {
		if gindex169NodeIsRightChild[step] {
			node = hashPair(branch[step][:], node[:])
		} else {
			node = hashPair(node[:], branch[step][:])
		}
	}
	return node
}
