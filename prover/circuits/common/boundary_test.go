package common

// BoundaryCircuit assembly tests. The DECISIVE test is the op-6 R7 negative
// (TestBoundary_Op6StateRootSingleSource): a strawman with a SEPARATE op-6 state_root SOLVES a
// forged next-committee binding while production (shared c.StateRoot) REJECTS — the FIRST direct
// test that defineBoundary feeds op-6 the same wire op-3a binds + op-3b consumes (neither the
// regular R7 nor the op-6 GAP suite tests the boundary's own three-consumer wiring).
//
// The synthetic positive needs BOTH op-3b's gindex-169 fold AND op-6's gindex-87 walk to reach
// the ONE c.StateRoot, so buildSyntheticBoundary joins the finality (gindex 169) and committee
// (gindex 87) branches in a partial BeaconState tree at their common ancestor gindex 21 — built
// against the EXISTING gindex patterns (hashNodePair = the merkleizer's H(left‖right)) and
// MANDATORILY cross-checked off-circuit via ssz.Gindex169Walk + ssz.Gindex87Walk before the
// circuit (a two-branch-tree bug is a cheap false-negative here, not a soundness hole).
//
// HONESTY BOUNDARY (op-6-SC-1 style): the synthetic binds the circuit STRUCTURALLY — current
// committee committed/aggregated, next committee SHA-walked + Poseidon-committed, all on one
// state_root. It does NOT model a signature (BLS is on-chain); current ≠ next keys (realistic).

import (
	"crypto/sha256"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fp"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bls12381"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/test"

	"eth-cardano-zk-light-client/prover/offchain/ssz"
)

// hashNodePair = SHA-256(left ‖ right) — the same node-hash as the in-circuit merkleizer.parent
// and the off-circuit ssz walks, so the synthetic tree is consistent with both by construction.
func hashNodePair(left, right [32]byte) [32]byte {
	return sha256.Sum256(append(append([]byte{}, left[:]...), right[:]...))
}

type syntheticBoundary struct {
	// current committee (signs)
	currentPoints     []bls12381.G1Affine
	bits              []int
	apk               bls12381.G1Affine
	count             int
	currentCommitment fr.Element
	// next committee (installed, op-6)
	nextPoints     []bls12381.G1Affine
	nextCompressed [][48]byte
	yHints         []fp.Element
	aggRoot        [32]byte
	node87         [32]byte // sync_committee_root = H(pubkeys_root, agg_root)
	nextCommitment fr.Element
	// finality + the joined state
	finalizedHeader         ssz.Header
	finalizedRoot           [32]byte
	slotBranch              [3][32]byte
	finalityBranch          [7][32]byte
	nextSyncCommitteeBranch [6][32]byte
	stateRoot               [32]byte
	attestedHeader          ssz.Header
	attestedRoot            [32]byte
}

// buildSyntheticBoundary builds a self-consistent boundary instance: a current committee
// (bind/apk/count), a next committee (op-6 SHA + Poseidon), and the two-branch BeaconState tree
// joining finality (gindex 169) and committee (gindex 87) at gindex 21 so BOTH walks reach the
// one state_root — cross-checked off-circuit before use.
func buildSyntheticBoundary(t *testing.T, n int, salt byte) *syntheticBoundary {
	t.Helper()
	s := &syntheticBoundary{}

	// ── current committee (signs) ──
	s.currentPoints = bindPoints(t, n)
	s.bits = patternBits(n)
	s.apk = aggregateApk(s.currentPoints, s.bits)
	s.count = sumBits(s.bits)
	s.currentCommitment = poseidonCommitFr(canonicalPacks(s.currentPoints))

	// ── next committee (installed, op-6: SHA side reads Compressed; Path-2 decompresses it) ──
	for i := 0; i < n; i++ {
		point, compressed := validPoint(t)
		s.nextPoints = append(s.nextPoints, point)
		s.nextCompressed = append(s.nextCompressed, compressed)
		s.yHints = append(s.yHints, point.Y)
	}
	pubkeysRoot := ssz.PubkeysRoot(s.nextCompressed) // gindex-174 merkleize
	_, aggBytes := validPoint(t)
	s.aggRoot = ssz.Bytes48Root(aggBytes)                    // gindex-175
	s.node87 = ssz.SyncCommitteeRoot(pubkeysRoot, s.aggRoot) // gindex-87 leaf = H(pubkeys_root, agg)
	s.nextCommitment = poseidonCommitFr(canonicalPacks(s.nextPoints))

	// ── finality: finalized header → root (node_169), slot_branch, slot ──
	s.finalizedHeader = ssz.Header{
		Slot: 13107200, ProposerIndex: 99,
		ParentRoot: sha256.Sum256([]byte{salt, 'f', 'p'}),
		StateRoot:  sha256.Sum256([]byte{salt, 'f', 's'}),
		BodyRoot:   sha256.Sum256([]byte{salt, 'f', 'b'}),
	}
	node169 := s.finalizedHeader.HashTreeRoot()
	s.finalizedRoot = node169
	s.slotBranch = s.finalizedHeader.SlotBranch()

	// ── two-branch BeaconState tree: committee subtree (g87) + finality subtree (g169) join at
	//    g21. Synthetic fillers from salt; build via the gindex child positions (H(left,right)). ──
	node86 := sha256.Sum256([]byte{salt, 'n', 86})
	node168 := sha256.Sum256([]byte{salt, 'n', 168})
	node85 := sha256.Sum256([]byte{salt, 'n', 85})
	node20 := sha256.Sum256([]byte{salt, 'n', 20})
	node11 := sha256.Sum256([]byte{salt, 'n', 11})
	node4 := sha256.Sum256([]byte{salt, 'n', 4})
	node3 := sha256.Sum256([]byte{salt, 'n', 3})
	node43 := hashNodePair(node86, s.node87) // g43 = H(g86, g87)
	node84 := hashNodePair(node168, node169) // g84 = H(g168, g169)
	node42 := hashNodePair(node84, node85)   // g42 = H(g84, g85)
	node21 := hashNodePair(node42, node43)   // g21 = H(g42, g43)  ← the join
	node10 := hashNodePair(node20, node21)   // g10 = H(g20, g21)
	node5 := hashNodePair(node10, node11)    // g5  = H(g10, g11)
	node2 := hashNodePair(node4, node5)      // g2  = H(g4, g5)
	s.stateRoot = hashNodePair(node2, node3) // g1  = H(g2, g3) = state_root
	s.finalityBranch = [7][32]byte{node168, node85, node43, node20, node11, node4, node3}
	s.nextSyncCommitteeBranch = [6][32]byte{node86, node42, node20, node11, node4, node3}

	// ── MANDATORY off-circuit anchor: BOTH existing walks must reproduce the synthetic root ──
	if got := ssz.Gindex169Walk(node169, s.finalityBranch); got != s.stateRoot {
		t.Fatalf("two-branch anchor HALT: Gindex169Walk != state_root\n  got 0x%x\n  want 0x%x", got, s.stateRoot)
	}
	if got := ssz.Gindex87Walk(s.node87, s.nextSyncCommitteeBranch); got != s.stateRoot {
		t.Fatalf("two-branch anchor HALT: Gindex87Walk != state_root\n  got 0x%x\n  want 0x%x", got, s.stateRoot)
	}

	// ── attested header (StateRoot = the joined state_root) → attested_root (op-3a target) ──
	s.attestedHeader = ssz.Header{
		Slot: 13107272, ProposerIndex: 7,
		ParentRoot: sha256.Sum256([]byte{salt, 'a', 'p'}),
		StateRoot:  s.stateRoot,
		BodyRoot:   sha256.Sum256([]byte{salt, 'a', 'b'}),
	}
	s.attestedRoot = s.attestedHeader.HashTreeRoot()
	return s
}

func (s *syntheticBoundary) production() *BoundaryCircuit {
	c := NewBoundaryCircuit(len(s.currentPoints))
	// regular core
	for i := range s.currentPoints {
		c.Pubkeys[i] = sw_bls12381.NewG1Affine(s.currentPoints[i])
		c.Bits[i] = s.bits[i]
	}
	c.Slot = s.attestedHeader.Slot
	c.ProposerIndex = s.attestedHeader.ProposerIndex
	c.ParentRoot = toCircuitBytes32(s.attestedHeader.ParentRoot)
	c.StateRoot = toCircuitBytes32(s.attestedHeader.StateRoot)
	c.BodyRoot = toCircuitBytes32(s.attestedHeader.BodyRoot)
	c.FinalizedHeaderRoot = toCircuitBytes32(s.finalizedRoot)
	for i := 0; i < 7; i++ {
		c.FinalityBranch[i] = toCircuitBytes32(s.finalityBranch[i])
	}
	for i := 0; i < 3; i++ {
		c.SlotBranch[i] = toCircuitBytes32(s.slotBranch[i])
	}
	c.PubkeysCommitment = frElementToVar(s.currentCommitment)
	c.ApkPacked = packApkRef(s.apk)
	c.Count = s.count
	c.AttestedHeaderRootPacked = packRootRef(s.attestedRoot)
	c.FinalizedHeaderRootPacked = packRootRef(s.finalizedRoot)
	c.FinalizedSlot = s.finalizedHeader.Slot
	// op-6 (next committee)
	for i := range s.nextPoints {
		c.Compressed[i] = toCircuitBytes48(s.nextCompressed[i])
		c.YHint[i] = emulatedY(s.yHints[i])
	}
	c.AggRoot = toCircuitBytes32(s.aggRoot)
	for i := 0; i < 6; i++ {
		c.NextSyncCommitteeBranch[i] = toCircuitBytes32(s.nextSyncCommitteeBranch[i])
	}
	c.NextPubkeysCommitment = frElementToVar(s.nextCommitment)
	return c
}

// ─────────────────────────── positive ───────────────────────────

func TestBoundary_PositiveSolves(t *testing.T) {
	for _, n := range []int{8, 16} {
		s := buildSyntheticBoundary(t, n, 0x01)
		if err := test.IsSolved(NewBoundaryCircuit(n), s.production(), ecc.BLS12_381.ScalarField()); err != nil {
			t.Fatalf("BOUNDARY positive FAILED at N=%d (wiring bug): %v", n, err)
		}
		t.Logf("PASS: N=%d boundary solves — regular core + op-6 (next committee), op-3b fold AND op-6 walk both reach the ONE state_root", n)
	}
}

func TestBoundary_ProvesSmallN(t *testing.T) {
	const n = 2
	s := buildSyntheticBoundary(t, n, 0x02)
	scalarField := ecc.BLS12_381.ScalarField()
	constraintSystem, err := frontend.Compile(scalarField, r1cs.NewBuilder, NewBoundaryCircuit(n))
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	provingKey, verifyingKey, err := groth16.Setup(constraintSystem)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	witness, err := frontend.NewWitness(s.production(), scalarField)
	if err != nil {
		t.Fatalf("witness: %v", err)
	}
	publicWitness, err := witness.Public()
	if err != nil {
		t.Fatalf("public: %v", err)
	}
	proof, err := groth16.Prove(constraintSystem, provingKey, witness)
	if err != nil {
		t.Fatalf("prove: %v", err)
	}
	if err := groth16.Verify(proof, verifyingKey, publicWitness); err != nil {
		t.Fatalf("verify: %v", err)
	}
	t.Logf("PASS: N=2 boundary Setup->Prove->Verify (%d constraints)", constraintSystem.GetNbConstraints())
}

func TestBoundary_PublicInputCount(t *testing.T) {
	s := buildSyntheticBoundary(t, 8, 0x05)
	witness, err := frontend.NewWitness(s.production(), ecc.BLS12_381.ScalarField())
	if err != nil {
		t.Fatalf("witness: %v", err)
	}
	publicWitness, err := witness.Public()
	if err != nil {
		t.Fatalf("public: %v", err)
	}
	vector, ok := publicWitness.Vector().(fr.Vector)
	if !ok {
		t.Fatalf("unexpected public-vector type %T", publicWitness.Vector())
	}
	if len(vector) != 12 {
		t.Fatalf("public-input count = %d, want 12 (the regular 11 + NextPubkeysCommitment)", len(vector))
	}
	t.Logf("PASS: witness.Public() == 12 Fr (Option-P: regular 11 + next_pubkeys_commitment)")
}

// ─────────────────────────── op-6 R7 single-source negative (decisive) ───────────────────────────

// strawmanBoundaryOp6StateRoot decouples op-6's walk terminal from op-3a's authenticated
// c.StateRoot via a separate Op6StateRoot — the hole production closes by feeding op-6 the
// shared wire.
type strawmanBoundaryOp6StateRoot struct {
	BoundaryCircuit
	Op6StateRoot [32]uints.U8
}

func (c *strawmanBoundaryOp6StateRoot) Define(api frontend.API) error {
	return defineBoundary(api, &c.BoundaryCircuit, nil, op6Overrides{terminal: c.Op6StateRoot[:]})
}

// TestBoundary_Op6StateRootSingleSource — the load-bearing proof that op-6 shares the one
// c.StateRoot. A forged next_sync_committee_branch makes op-6 walk to a DIFFERENT state_root.
// The strawman (separate Op6StateRoot = that forged fold) SOLVES — op-6 authenticates a forged
// next committee decoupled from op-3a — while production (op-6 → c.StateRoot) REJECTS.
func TestBoundary_Op6StateRootSingleSource(t *testing.T) {
	const n = 8
	s := buildSyntheticBoundary(t, n, 0x01)

	forgedBranch := s.nextSyncCommitteeBranch
	forgedBranch[0][0] ^= 0x01                             // tamper one gindex-87 sibling
	forgedFold := ssz.Gindex87Walk(s.node87, forgedBranch) // != s.stateRoot (SHA collision resistance)

	buildForged := func() *BoundaryCircuit {
		c := s.production()
		for i := 0; i < 6; i++ {
			c.NextSyncCommitteeBranch[i] = toCircuitBytes32(forgedBranch[i])
		}
		return c
	}

	// STRAWMAN: op-6's separate Op6StateRoot = forgedFold → SOLVES (op-6 decoupled from op-3a).
	strawman := &strawmanBoundaryOp6StateRoot{BoundaryCircuit: *buildForged(), Op6StateRoot: toCircuitBytes32(forgedFold)}
	blankStrawman := &strawmanBoundaryOp6StateRoot{BoundaryCircuit: *NewBoundaryCircuit(n)}
	if err := test.IsSolved(blankStrawman, strawman, ecc.BLS12_381.ScalarField()); err != nil {
		t.Fatalf("R7 NON-DECISIVE: strawman must SOLVE the forged next-committee branch (else the negative is vacuous): %v", err)
	}
	t.Logf("R7: strawman (separate op-6 state_root) SOLVES the forged next_sync_committee_branch — op-6 hole exploitable")

	// PRODUCTION: op-6 → c.StateRoot (op-3a's real state_root) → REJECTS (forgedFold != real).
	err := test.IsSolved(NewBoundaryCircuit(n), buildForged(), ecc.BLS12_381.ScalarField())
	if err == nil {
		t.Fatal("R7 HOLE: production SOLVED a forged next-committee binding — op-6 single-source is NOT load-bearing")
	}
	t.Logf("R7 PASS: production REJECTS the same forged branch (op-6 folds to op-3a's authenticated state_root): %v", err)
}
