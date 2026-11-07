package common

// 2b-iii assembled op-6 suite. The CENTERPIECE is the GAP-a mutation contrast: each
// strawman (which re-introduces a hole the production circuit closes by ABSENCE) must
// SOLVE with forged keys + the real root/terminal (hole exploitable), while production
// REJECTS the SAME forged keys (hole unrepresentable). The contrast — strawman solves
// AND production rejects — is the teeth, not "production passes". Helpers validPoint,
// emulatedY, onCurveG1, toCircuitBytes32, toCircuitBytes48 are shared (package common).

import (
	"crypto/sha256"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fp"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/test"

	"eth-cardano-zk-light-client/prover/offchain/commitment"
	"eth-cardano-zk-light-client/prover/offchain/ssz"
)

// ─────────────────────────── off-circuit Poseidon (encoding A) ───────────────────────────
//
// foldFp / poseidonCommitOffCircuit now DELEGATE to the extracted production twin in
// offchain/commitment/ — one source of truth, byte-identical (the commitment-
// package equivalence + golden tests pin it). Kept as package-common wrappers so the existing
// call sites (and the cross-file helper-sharing convention) are unchanged; the circuit-solve
// gate then confirms the in-circuit Poseidon still matches this off-circuit twin. (packPointFr
// relocated fully to commitment.PackPoint — no remaining direct caller once canonicalPacks
// delegates to commitment.Pack.)

func foldFp(e fp.Element) (lo, hi fr.Element) { return commitment.FoldFp(e) }

func poseidonCommitOffCircuit(points []bls12381.G1Affine) fr.Element {
	return commitment.Commit(points)
}

func frElementToVar(e fr.Element) frontend.Variable {
	b := new(big.Int)
	e.BigInt(b)
	return b
}

// ─────────────────────────── synthetic committee (off-circuit) ───────────────────────────

type syntheticOp6 struct {
	points       []bls12381.G1Affine
	compressed   [][48]byte
	yHints       []fp.Element
	pubkeysRoot  [32]byte
	aggRoot      [32]byte
	branch       [6][32]byte
	stateRoot    [32]byte
	header       ssz.Header
	attestedRoot [32]byte
	commitment   fr.Element
}

// buildSyntheticOp6 generates a self-consistent committee of n valid points and the full
// Path-1 SSZ structure (pubkeys_root -> H(.,agg) -> gindex-87 walk -> state_root -> header)
// plus the Poseidon commitment. salt diversifies the branch so two committees differ.
func buildSyntheticOp6(t *testing.T, n int, salt byte) *syntheticOp6 {
	t.Helper()
	s := &syntheticOp6{}
	for i := 0; i < n; i++ {
		P, compressed := validPoint(t)
		s.points = append(s.points, P)
		s.compressed = append(s.compressed, compressed)
		s.yHints = append(s.yHints, P.Y)
	}
	s.pubkeysRoot = ssz.PubkeysRoot(s.compressed)
	aggP, _ := validPoint(t)
	aggBytes := aggP.Bytes()
	s.aggRoot = ssz.Bytes48Root(aggBytes)
	for i := 0; i < 6; i++ {
		s.branch[i] = sha256.Sum256([]byte{salt, byte(i)})
	}
	s.stateRoot = ssz.Gindex87Walk(ssz.SyncCommitteeRoot(s.pubkeysRoot, s.aggRoot), s.branch)
	s.header = ssz.Header{
		Slot: 1234, ProposerIndex: 7,
		ParentRoot: sha256.Sum256([]byte{salt, 'p'}),
		StateRoot:  s.stateRoot,
		BodyRoot:   sha256.Sum256([]byte{salt, 'b'}),
	}
	s.attestedRoot = s.header.HashTreeRoot()
	s.commitment = poseidonCommitOffCircuit(s.points)
	return s
}

// fillKeys writes the committee's keys (Compressed + YHint) and the Poseidon commitment.
func (s *syntheticOp6) fillKeys(c *AssembledOp6Circuit) {
	for i := range s.points {
		c.Compressed[i] = toCircuitBytes48(s.compressed[i])
		c.YHint[i] = emulatedY(s.yHints[i])
	}
	c.NextPubkeysCommitment = frElementToVar(s.commitment)
}

// fillSHA writes the Path-1 SSZ structure + the op-3a header (the authenticated side).
func (s *syntheticOp6) fillSHA(c *AssembledOp6Circuit) {
	c.AggRoot = toCircuitBytes32(s.aggRoot)
	for i := 0; i < 6; i++ {
		c.NextSyncCommitteeBranch[i] = toCircuitBytes32(s.branch[i])
	}
	c.Slot = s.header.Slot
	c.ProposerIndex = s.header.ProposerIndex
	c.ParentRoot = toCircuitBytes32(s.header.ParentRoot)
	c.StateRoot = toCircuitBytes32(s.header.StateRoot)
	c.BodyRoot = toCircuitBytes32(s.header.BodyRoot)
	c.AttestedHeaderRoot = toCircuitBytes32(s.attestedRoot)
}

func (s *syntheticOp6) production() *AssembledOp6Circuit {
	c := NewAssembledOp6Circuit(len(s.points))
	s.fillKeys(c)
	s.fillSHA(c)
	return c
}

// ─────────────────────────── strawman circuits (test-only) ───────────────────────────

// GAP-a source: re-introduces an opaque PubkeysRootWitness; the walk uses it instead of
// the derived root (the merkleizer still runs, its output discarded — the SEC-01 shape).
type strawmanOp6SourceCircuit struct {
	AssembledOp6Circuit
	PubkeysRootWitness [32]uints.U8
}

func (c *strawmanOp6SourceCircuit) Define(api frontend.API) error {
	return defineAssembledOp6(api, &c.AssembledOp6Circuit, op6Overrides{walkRoot: c.PubkeysRootWitness[:]})
}

// GAP-a terminal: re-introduces a fresh Op6StateRoot; the walk asserts == it instead of
// op-3a's authenticated c.StateRoot.
type strawmanOp6TerminalCircuit struct {
	AssembledOp6Circuit
	Op6StateRoot [32]uints.U8
}

func (c *strawmanOp6TerminalCircuit) Define(api frontend.API) error {
	return defineAssembledOp6(api, &c.AssembledOp6Circuit, op6Overrides{terminal: c.Op6StateRoot[:]})
}

// GAP-b: a second key array; SHA Path-1 reads c.Compressed, decompress Path-2 reads this.
type strawmanOp6TwoArrayCircuit struct {
	AssembledOp6Circuit
	CompressedForDecompress [][48]uints.U8
}

func (c *strawmanOp6TwoArrayCircuit) Define(api frontend.API) error {
	return defineAssembledOp6(api, &c.AssembledOp6Circuit, op6Overrides{decompressBytes: c.CompressedForDecompress})
}

// ─────────────────────────── positive ───────────────────────────

const assembledField = ecc.BLS12_381

// TestAssembledOp6_PositiveSolves: one witness; derived root walks to state_root (SC-2),
// Poseidon commits the same keys (SC-3), op-3a -> AttestedHeaderRoot. Solver (fast/light).
func TestAssembledOp6_PositiveSolves(t *testing.T) {
	for _, n := range []int{8, 16} {
		s := buildSyntheticOp6(t, n, 0x01)
		if err := test.IsSolved(NewAssembledOp6Circuit(n), s.production(), assembledField.ScalarField()); err != nil {
			t.Fatalf("POSITIVE FAILED at N=%d (wiring bug): %v", n, err)
		}
		t.Logf("PASS: N=%d assembled solves — derived root walks to state_root (SC-2) + Poseidon (SC-3)", n)
	}
}

// TestAssembledOp6_ProvesSmallN: end-to-end Setup->Prove->Verify at small N=2 (the
// op-3a + gindex-87 walk floor makes larger N heavy; full-size proving is AWS-deferred).
func TestAssembledOp6_ProvesSmallN(t *testing.T) {
	const n = 2
	field := assembledField.ScalarField()
	s := buildSyntheticOp6(t, n, 0x02)
	constraintSystem, err := frontend.Compile(field, r1cs.NewBuilder, NewAssembledOp6Circuit(n))
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	provingKey, verifyingKey, err := groth16.Setup(constraintSystem)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	witness, err := frontend.NewWitness(s.production(), field)
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
	t.Logf("PASS: N=%d assembled Setup->Prove->Verify (%d constraints)", n, constraintSystem.GetNbConstraints())
}

// ─────────────────────────── GAP-a source (the centerpiece) ───────────────────────────

func TestGapA_Source_StrawmanExploitable(t *testing.T) {
	const n = 8
	real := buildSyntheticOp6(t, n, 0x11)
	forged := buildSyntheticOp6(t, n, 0x22)
	straw := &strawmanOp6SourceCircuit{AssembledOp6Circuit: *NewAssembledOp6Circuit(n)}
	forged.fillKeys(&straw.AssembledOp6Circuit) // forged keys committed
	real.fillSHA(&straw.AssembledOp6Circuit)    // real SHA structure + header (authenticated)
	straw.PubkeysRootWitness = toCircuitBytes32(real.pubkeysRoot)
	if err := test.IsSolved(&strawmanOp6SourceCircuit{AssembledOp6Circuit: *NewAssembledOp6Circuit(n)}, straw, assembledField.ScalarField()); err != nil {
		t.Fatalf("STRAWMAN DID NOT SOLVE (test failed to capture the hole — HALT): %v", err)
	}
	t.Logf("PASS: GAP-a source strawman SOLVES — forged keys authenticated via the witnessed real root (hole exploitable)")
}

func TestGapA_Source_ProductionRejects(t *testing.T) {
	const n = 8
	real := buildSyntheticOp6(t, n, 0x11)
	forged := buildSyntheticOp6(t, n, 0x22)
	attack := NewAssembledOp6Circuit(n)
	forged.fillKeys(attack) // forged keys + Poseidon(forged) — so only the walk can fail
	real.fillSHA(attack)    // real agg/branch/state_root/header
	if err := test.IsSolved(NewAssembledOp6Circuit(n), attack, assembledField.ScalarField()); err == nil {
		t.Fatalf("PRODUCTION ACCEPTED FORGED KEYS (REAL HOLE — HALT): GAP-a source not closed")
	} else {
		t.Logf("PASS: GAP-a source production REJECTS — merkleize(forged) != real root, walk can't reach state_root: %v", err)
	}
}

// ─────────────────────────── GAP-a terminal ───────────────────────────

func TestGapA_Terminal_StrawmanExploitable(t *testing.T) {
	const n = 8
	real := buildSyntheticOp6(t, n, 0x33)
	forged := buildSyntheticOp6(t, n, 0x44)
	straw := &strawmanOp6TerminalCircuit{AssembledOp6Circuit: *NewAssembledOp6Circuit(n)}
	forged.fillKeys(&straw.AssembledOp6Circuit) // forged keys + forged agg/branch (self-consistent walk)
	forged.fillSHA(&straw.AssembledOp6Circuit)
	straw.StateRoot = toCircuitBytes32(real.header.StateRoot) // op-3a authenticates the REAL state_root
	straw.AttestedHeaderRoot = toCircuitBytes32(real.attestedRoot)
	straw.Slot = real.header.Slot
	straw.ProposerIndex = real.header.ProposerIndex
	straw.ParentRoot = toCircuitBytes32(real.header.ParentRoot)
	straw.BodyRoot = toCircuitBytes32(real.header.BodyRoot)
	straw.Op6StateRoot = toCircuitBytes32(forged.stateRoot) // fresh terminal = forged walk result
	if err := test.IsSolved(&strawmanOp6TerminalCircuit{AssembledOp6Circuit: *NewAssembledOp6Circuit(n)}, straw, assembledField.ScalarField()); err != nil {
		t.Fatalf("STRAWMAN DID NOT SOLVE (test failed to capture the hole — HALT): %v", err)
	}
	t.Logf("PASS: GAP-a terminal strawman SOLVES — forged walk reaches a fresh terminal while op-3a authenticates real (hole exploitable)")
}

func TestGapA_Terminal_ProductionRejects(t *testing.T) {
	const n = 8
	real := buildSyntheticOp6(t, n, 0x33)
	forged := buildSyntheticOp6(t, n, 0x44)
	attack := forged.production()                              // forged keys + forged agg/branch -> forged.stateRoot
	attack.StateRoot = toCircuitBytes32(real.header.StateRoot) // but op-3a terminal = REAL state_root
	attack.AttestedHeaderRoot = toCircuitBytes32(real.attestedRoot)
	attack.Slot = real.header.Slot
	attack.ProposerIndex = real.header.ProposerIndex
	attack.ParentRoot = toCircuitBytes32(real.header.ParentRoot)
	attack.BodyRoot = toCircuitBytes32(real.header.BodyRoot)
	if err := test.IsSolved(NewAssembledOp6Circuit(n), attack, assembledField.ScalarField()); err == nil {
		t.Fatalf("PRODUCTION ACCEPTED FORGED KEYS (REAL HOLE — HALT): GAP-a terminal not closed")
	} else {
		t.Logf("PASS: GAP-a terminal production REJECTS — forged walk != c.StateRoot (op-3a's authenticated wire): %v", err)
	}
}

// ─────────────────────────── GAP-b (two-array) ───────────────────────────

func TestGapB_StrawmanExploitable(t *testing.T) {
	const n = 8
	real := buildSyntheticOp6(t, n, 0x55)
	forged := buildSyntheticOp6(t, n, 0x66)
	straw := &strawmanOp6TwoArrayCircuit{AssembledOp6Circuit: *NewAssembledOp6Circuit(n)}
	real.fillSHA(&straw.AssembledOp6Circuit) // SHA Path-1 authenticates the REAL committee
	for i := 0; i < n; i++ {
		straw.Compressed[i] = toCircuitBytes48(real.compressed[i]) // SHA reads real
	}
	straw.CompressedForDecompress = make([][48]uints.U8, n)
	for i := 0; i < n; i++ {
		straw.CompressedForDecompress[i] = toCircuitBytes48(forged.compressed[i]) // Poseidon reads forged
		straw.YHint[i] = emulatedY(forged.yHints[i])
	}
	straw.NextPubkeysCommitment = frElementToVar(forged.commitment)
	if err := test.IsSolved(&strawmanOp6TwoArrayCircuit{AssembledOp6Circuit: *NewAssembledOp6Circuit(n), CompressedForDecompress: make([][48]uints.U8, n)}, straw, assembledField.ScalarField()); err != nil {
		t.Fatalf("STRAWMAN DID NOT SOLVE (test failed to capture the hole — HALT): %v", err)
	}
	t.Logf("PASS: GAP-b strawman SOLVES — real keys authenticated, forged keys committed (SC-1 break exploitable)")
}

func TestGapB_ProductionRejectsFork(t *testing.T) {
	const n = 8
	real := buildSyntheticOp6(t, n, 0x55)
	forged := buildSyntheticOp6(t, n, 0x66)
	attack := NewAssembledOp6Circuit(n)
	real.fillSHA(attack) // real agg/branch/state_root/header
	for i := 0; i < n; i++ {
		attack.Compressed[i] = toCircuitBytes48(forged.compressed[i]) // single array -> forged drives BOTH paths
		attack.YHint[i] = emulatedY(forged.yHints[i])
	}
	attack.NextPubkeysCommitment = frElementToVar(forged.commitment)
	if err := test.IsSolved(NewAssembledOp6Circuit(n), attack, assembledField.ScalarField()); err == nil {
		t.Fatalf("PRODUCTION ACCEPTED THE FORK (REAL HOLE — HALT): GAP-b not closed")
	} else {
		t.Logf("PASS: GAP-b production REJECTS — one array forces forged through SHA too, walk can't reach real state_root: %v", err)
	}
}

// ─────────────────────────── GAP-c (decompress teeth at assembled level) ───────────────────────────

func offCurveSameSignY(t *testing.T, P bls12381.G1Affine) fp.Element {
	t.Helper()
	yFake := P.Y
	one := fp.One()
	for i := 0; i < 16; i++ {
		yFake.Add(&yFake, &one)
		if yFake.LexicographicallyLargest() == P.Y.LexicographicallyLargest() && !onCurveG1(P.X, yFake) {
			return yFake
		}
	}
	t.Fatalf("could not construct same-sign off-curve y")
	return fp.Element{}
}

func TestGapC_Assembled_OffCurveY(t *testing.T) {
	const n = 8
	s := buildSyntheticOp6(t, n, 0x77)
	attack := s.production()
	attack.YHint[0] = emulatedY(offCurveSameSignY(t, s.points[0])) // one off-curve y
	if err := test.IsSolved(NewAssembledOp6Circuit(n), attack, assembledField.ScalarField()); err == nil {
		t.Fatalf("ASSEMBLED ACCEPTED OFF-CURVE Y (decompress teeth lost in assembly — HALT)")
	} else {
		t.Logf("PASS: GAP-c assembled off-curve y REJECTED by on-curve (decompress teeth survive): %v", err)
	}
}

func TestGapC_Assembled_WrongSignY(t *testing.T) {
	const n = 8
	s := buildSyntheticOp6(t, n, 0x88)
	attack := s.production()
	var negY fp.Element
	negY.Neg(&s.points[0].Y) // the other on-curve root, wrong sign
	attack.YHint[0] = emulatedY(negY)
	if err := test.IsSolved(NewAssembledOp6Circuit(n), attack, assembledField.ScalarField()); err == nil {
		t.Fatalf("ASSEMBLED ACCEPTED WRONG-SIGN Y (decompress teeth lost in assembly — HALT)")
	} else {
		t.Logf("PASS: GAP-c assembled wrong-sign y REJECTED by sign-match (decompress teeth survive): %v", err)
	}
}
