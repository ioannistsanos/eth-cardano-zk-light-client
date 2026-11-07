package ssz

import "testing"

// referenceGindexWalk folds a leaf up a branch, deriving left/right at each step DIRECTLY
// from the gindex bits ((gindex>>step)&1) rather than a precomputed array — the independent
// reference that ties Gindex86Walk's hardcoded gindex86NodeIsRightChild to the actual
// gindex 86 (a transposed array entry would diverge here).
func referenceGindexWalk(gindex uint64, leaf [32]byte, branch [][32]byte) [32]byte {
	node := leaf
	for step := 0; step < len(branch); step++ {
		if (gindex>>uint(step))&1 == 1 {
			node = hashPair(branch[step][:], node[:])
		} else {
			node = hashPair(node[:], branch[step][:])
		}
	}
	return node
}

// syntheticLeafAndBranch builds a deterministic (no randomness) SyncCommitteeRoot stand-in
// and a 6-node branch with distinct byte fills, so step-0 order swaps produce distinct nodes.
func syntheticLeafAndBranch() ([32]byte, [6][32]byte) {
	var leaf [32]byte
	for i := range leaf {
		leaf[i] = byte(0x10 + i)
	}
	var branch [6][32]byte
	for step := range branch {
		for i := range branch[step] {
			branch[step][i] = byte(0x80 + step*0x10 + i)
		}
	}
	return leaf, branch
}

// TestGindex86Walk_SyntheticAnchor: Gindex86Walk reproduces the independent bit-derived
// reference fold for gindex 86 over a synthetic branch — the off-circuit anchor that the
// hardcoded gindex86NodeIsRightChild equals the actual CURRENT_SYNC_COMMITTEE_GINDEX path.
func TestGindex86Walk_SyntheticAnchor(t *testing.T) {
	leaf, branch := syntheticLeafAndBranch()
	got := Gindex86Walk(leaf, branch)
	want := referenceGindexWalk(86, leaf, branch[:])
	if got != want {
		t.Fatalf("Gindex86Walk != reference fold for gindex 86:\n got  %x\n want %x", got, want)
	}
}

// TestGindex86Walk_OneBitDiffersFromGindex87: the current (86) and next (87) paths are
// siblings under gindex 43 — identical at steps 1..5, differing ONLY at step 0 (the leaf
// level). Pins (1) each array equals its gindex bits and the two differ at exactly index 0,
// and (2) on a shared (leaf, branch) the divergence is exactly step-0's hash order, nothing
// downstream — so the mirror is right by one bit, not by accident.
func TestGindex86Walk_OneBitDiffersFromGindex87(t *testing.T) {
	// (1) array-level: each equals its gindex bits; they differ only at index 0.
	for step := 0; step < 6; step++ {
		if gindex86NodeIsRightChild[step] != ((86>>uint(step))&1 == 1) {
			t.Fatalf("gindex86NodeIsRightChild[%d]=%v != (86>>%d)&1", step, gindex86NodeIsRightChild[step], step)
		}
		if gindex87NodeIsRightChild[step] != ((87>>uint(step))&1 == 1) {
			t.Fatalf("gindex87NodeIsRightChild[%d]=%v != (87>>%d)&1", step, gindex87NodeIsRightChild[step], step)
		}
		sameStep := gindex86NodeIsRightChild[step] == gindex87NodeIsRightChild[step]
		if step == 0 && sameStep {
			t.Fatal("step 0 must differ (86 left child, 87 right child)")
		}
		if step != 0 && !sameStep {
			t.Fatalf("steps 1..5 must match (siblings under gindex 43); differ at %d", step)
		}
	}

	// (2) walk-level: rebuild both walks from a shared step-0 split + identical steps 1..5,
	// and confirm they equal Gindex86/87Walk respectively — so the ONLY divergence is step 0.
	leaf, branch := syntheticLeafAndBranch()
	node86 := hashPair(leaf[:], branch[0][:]) // 86: left child  -> H(node, sibling)
	node87 := hashPair(branch[0][:], leaf[:]) // 87: right child -> H(sibling, node)
	for step := 1; step < 6; step++ {         // steps 1..5 identical for both gindices
		if gindex86NodeIsRightChild[step] {
			node86 = hashPair(branch[step][:], node86[:])
			node87 = hashPair(branch[step][:], node87[:])
		} else {
			node86 = hashPair(node86[:], branch[step][:])
			node87 = hashPair(node87[:], branch[step][:])
		}
	}
	if got := Gindex86Walk(leaf, branch); got != node86 {
		t.Fatalf("Gindex86Walk != hand-rolled (step0 left + shared steps):\n got  %x\n want %x", got, node86)
	}
	if got := Gindex87Walk(leaf, branch); got != node87 {
		t.Fatalf("Gindex87Walk != hand-rolled (step0 right + shared steps):\n got  %x\n want %x", got, node87)
	}
	if node86 == node87 {
		t.Fatal("86 and 87 walks coincide — step-0 order must diverge for distinct leaf/sibling")
	}
}
