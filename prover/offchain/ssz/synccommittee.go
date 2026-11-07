package ssz

// Off-circuit SSZ helpers for the SyncCommittee containers and their Merkle branches to
// the BeaconState root: the SyncCommittee container root (SyncCommitteeRoot, shared by
// both committees), the next_sync_committee_branch walk (gindex 87 — op-6 / SEC-01
// Family-B 2b-iii), and the current_sync_committee_branch walk (gindex 86 — the bootstrap
// condition (a)). Pure Go (crypto/sha256 via hashPair), the off-circuit counterpart of the
// in-circuit Path-1 in circuits/common/op6assemble.go — used to build synthetic witnesses
// and to anchor against real LightClientUpdate / LightClientBootstrap data.

// SyncCommitteeRoot is hash_tree_root(SyncCommittee) = H(pubkeys_root, aggregate_root) —
// the gindex-87 container composed from gindex-174 (pubkeys) and gindex-175 (aggregate).
func SyncCommitteeRoot(pubkeysRoot, aggregateRoot [32]byte) [32]byte {
	return hashPair(pubkeysRoot[:], aggregateRoot[:])
}

// gindex87NodeIsRightChild[i] = (87 >> i) & 1: the path of NEXT_SYNC_COMMITTEE_GINDEX
// (Electra, 87 = 0b1010111) from the SyncCommittee leaf (step 0) up to the BeaconState
// root (step 5). At a right-child step the running node is the right child, so its
// sibling is on the LEFT: H(sibling, node); otherwise the node is the left child:
// H(node, sibling). Mixed L/R, unlike the all-left slot path (gindex 8).
var gindex87NodeIsRightChild = [6]bool{true, true, true, false, true, false}

// Gindex87Walk folds the SyncCommittee container root up its 6-node
// next_sync_committee_branch to the BeaconState root (== BeaconBlockHeader.state_root).
func Gindex87Walk(syncCommitteeRoot [32]byte, branch [6][32]byte) [32]byte {
	node := syncCommitteeRoot
	for step := 0; step < 6; step++ {
		if gindex87NodeIsRightChild[step] {
			node = hashPair(branch[step][:], node[:])
		} else {
			node = hashPair(node[:], branch[step][:])
		}
	}
	return node
}

// gindex86NodeIsRightChild[i] = (86 >> i) & 1: the path of CURRENT_SYNC_COMMITTEE_GINDEX
// (Electra, 86 = 0b1010110) from the SyncCommittee leaf (step 0) up to the BeaconState
// root (step 5). The current (gindex 86) and next (gindex 87) SyncCommittee containers are
// the two children of the SAME parent (gindex 43 = 86>>1 = 87>>1), so the two paths are
// IDENTICAL except at step 0: 86 is a LEFT child (bit0=0 -> H(node, sibling)), 87 a RIGHT
// child (bit0=1 -> H(sibling, node)). One bit differs — pinned in synccommittee_test.go.
var gindex86NodeIsRightChild = [6]bool{false, true, true, false, true, false}

// Gindex86Walk folds the SyncCommittee container root up its 6-node
// current_sync_committee_branch to the BeaconState root. This is the bootstrap's condition
// (a): the gindex-86 branch targets the BOOTSTRAP BeaconBlockHeader.state_root — DISTINCT
// from the attested header's state_root that the gindex-87 (next) and gindex-169 (finality)
// walks target. The current-committee counterpart of Gindex87Walk (one bit differs, step 0).
func Gindex86Walk(syncCommitteeRoot [32]byte, branch [6][32]byte) [32]byte {
	node := syncCommitteeRoot
	for step := 0; step < 6; step++ {
		if gindex86NodeIsRightChild[step] {
			node = hashPair(branch[step][:], node[:])
		} else {
			node = hashPair(node[:], branch[step][:])
		}
	}
	return node
}
