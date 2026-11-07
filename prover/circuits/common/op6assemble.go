// op6assemble.go — the assembled op-6 translation hinge (SEC-01 Family-B 2b-iii).
// ONE Compressed[N] witness feeds BOTH paths:
//
//	Path-1 (authenticate): derivePubkeysRoot (gindex 174) -> H(.,AggRoot) (gindex 87)
//	  -> 6-step next_sync_committee_branch walk -> == c.StateRoot (op-3a's authenticated
//	  wire). The terminal ByteAssertEq on c.StateRoot, plus the ABSENCE of any opaque
//	  pubkeys_root / state_root witness, is the SC-2 fix (GAP-a closed by deletion).
//	Path-2 (commit): decompressAndValidate the SAME bytes -> (x,y) limbs -> Poseidon
//	  (encoding A) == c.NextPubkeysCommitment (SC-3). SC-1 (both paths read c.Compressed)
//	  is structural, not an equality check.
//
// This is the boundary TRANSLATION INCREMENT, not the whole boundary circuit; op-1/op-2
// aggregation (sharing the same decompressed point) is the deferred co-existence item, so
// 2b-iii proves SHA<->Poseidon single-source, not yet SHA<->Poseidon<->aggregation.
package common

import (
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bls12381"
	"github.com/consensys/gnark/std/hash"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"
	poseidon2perm "github.com/consensys/gnark/std/permutation/poseidon2"
)

// gindex87NodeIsRightChild[i] = (87 >> i) & 1 — the Electra NEXT_SYNC_COMMITTEE_GINDEX
// (87 = 0b1010111) path, leaf (step 0) to BeaconState root (step 5). Right child =>
// sibling on the left: H(sibling, node); else H(node, sibling). Compile-time constant.
var gindex87NodeIsRightChild = [6]bool{true, true, true, false, true, false}

type AssembledOp6Circuit struct {
	// THE single key witness — feeds BOTH paths (SC-1, structural). No second key array,
	// no opaque pubkeys_root witness, no fresh state_root witness exist (GAP-a/b absent).
	Compressed [][48]uints.U8
	YHint      []emulated.Element[sw_bls12381.BaseField] // Path-2 decompress hints

	AggRoot                 [32]uints.U8    // gindex-175 aggregate_pubkey root (pinned by the walk)
	NextSyncCommitteeBranch [6][32]uints.U8 // gindex-87 -> state_root (Electra depth 6)

	// op-3a header sub-struct (the attested header the branch roots at). StateRoot is
	// field 3 — the walk terminal and op-3b's wire; bound to AttestedHeaderRoot here.
	Slot, ProposerIndex             frontend.Variable
	ParentRoot, StateRoot, BodyRoot [32]uints.U8
	AttestedHeaderRoot              [32]uints.U8 `gnark:",public"`

	NextPubkeysCommitment frontend.Variable `gnark:",public"` // Poseidon(encoding A) -> datum (SC-3)
}

// NewAssembledOp6Circuit allocates the circuit for numberOfPubkeys pubkeys (power of two).
func NewAssembledOp6Circuit(numberOfPubkeys int) *AssembledOp6Circuit {
	return &AssembledOp6Circuit{
		Compressed: make([][48]uints.U8, numberOfPubkeys),
		YHint:      make([]emulated.Element[sw_bls12381.BaseField], numberOfPubkeys),
	}
}

func (c *AssembledOp6Circuit) Define(api frontend.API) error {
	return defineAssembledOp6(api, c, op6Overrides{})
}

// op6Overrides re-introduce, FOR THE MUTATION-TEST STRAWMEN ONLY, the holes the
// production circuit closes by ABSENCE. A nil/zero field = production behaviour.
type op6Overrides struct {
	walkRoot        []uints.U8     // GAP-a source: walk uses this opaque witness, not the derived root
	terminal        []uints.U8     // GAP-a terminal: walk asserts == this fresh witness, not c.StateRoot
	decompressBytes [][48]uints.U8 // GAP-b: decompress reads this 2nd array, not c.Compressed
}

// defineAssembledOp6 is the STANDALONE op-6 composition: op-3a (binds c.StateRoot to the
// public attested_header_root) followed by nextCommitteePath (the op-6 core, sharing that
// state_root as its walk terminal). It preserves the mutation-test scaffolding — the GAP
// strawmen call THIS with op6Overrides, so de-embedding op-3a from the core is a one-word
// rename at their call sites. The boundary circuit instead calls nextCommitteePath
// directly, sharing its OWN single op-3a state_root into both this path and op-3b.
func defineAssembledOp6(api frontend.API, c *AssembledOp6Circuit, ov op6Overrides) error {
	uintsAPI, err := uints.New[uints.U32](api)
	if err != nil {
		return err
	}
	field, err := emulated.NewField[sw_bls12381.BaseField](api)
	if err != nil {
		return err
	}
	g1, err := sw_bls12381.NewG1(api)
	if err != nil {
		return err
	}
	merkleizer := &sszMerkleizer{api: api}

	// ── op-3a: bind the attested header (state_root is field 3) — produces the
	//    authenticated state_root wire nextCommitteePath's walk terminates on. ─────
	reconstructedRoot, err := reconstructHeaderRoot(api, uintsAPI, c.Slot, c.ProposerIndex, c.ParentRoot, c.StateRoot, c.BodyRoot)
	if err != nil {
		return err
	}
	for j := 0; j < 32; j++ {
		uintsAPI.ByteAssertEq(c.AttestedHeaderRoot[j], reconstructedRoot[j])
	}

	// ── op-6 core (Path-1 authenticate + Path-2 commit), sharing c.StateRoot ─────
	return nextCommitteePath(api, field, g1, uintsAPI, merkleizer,
		c.Compressed, c.YHint, c.AggRoot, c.NextSyncCommitteeBranch, c.StateRoot, c.NextPubkeysCommitment, ov)
}

// nextCommitteePath is the op-6 translation core — Path-1 (authenticate: derive the
// pubkeys_root, walk gindex-87 to stateRoot) + Path-2 (commit: decompress the SAME bytes,
// Poseidon == nextPubkeysCommitment) — WITHOUT op-3a. stateRoot is a SHARED wire (the walk
// terminal): the boundary circuit feeds ONE op-3a-authenticated state_root into BOTH this
// path AND op-3b's finalityWalk, so the single-source is structural. The caller creates
// field/g1/uintsAPI/merkleizer once (uintsAPI carries the shared ~131K uints intercept). ov
// re-introduces the SC-1/SC-2 holes for the mutation-test strawmen ONLY (nil = production).
func nextCommitteePath(
	api frontend.API,
	field *emulated.Field[sw_bls12381.BaseField],
	g1 *sw_bls12381.G1,
	uintsAPI *uints.BinaryField[uints.U32],
	merkleizer *sszMerkleizer,
	compressed [][48]uints.U8,
	yHint []emulated.Element[sw_bls12381.BaseField],
	aggRoot [32]uints.U8,
	branch [6][32]uints.U8,
	stateRoot [32]uints.U8,
	nextPubkeysCommitment frontend.Variable,
	ov op6Overrides,
) error {
	// ── Path-1 (authenticate) ──────────────────────────────────────────────────
	derivedPubkeysRoot, err := derivePubkeysRoot(api, compressed)
	if err != nil {
		return err
	}
	walkRoot := derivedPubkeysRoot
	if ov.walkRoot != nil { // GAP-a source strawman ONLY
		walkRoot = ov.walkRoot
	}
	syncCommitteeRoot := merkleizer.parent(walkRoot, aggRoot[:]) // gindex 174,175 -> 87
	node := syncCommitteeRoot
	for step := range branch { // gindex-87 walk
		sibling := branch[step][:]
		if gindex87NodeIsRightChild[step] {
			node = merkleizer.parent(sibling, node)
		} else {
			node = merkleizer.parent(node, sibling)
		}
	}
	if merkleizer.Err() != nil {
		return merkleizer.Err()
	}
	terminal := stateRoot[:]
	if ov.terminal != nil { // GAP-a terminal strawman ONLY
		terminal = ov.terminal
	}
	for j := 0; j < 32; j++ { // SC-2 terminal: walk == op-3a's authenticated state_root
		uintsAPI.ByteAssertEq(node[j], terminal[j])
	}

	// ── Path-2 (commit): SAME bytes -> decompress -> Poseidon (encoding A) ──────
	decompressBytes := compressed
	if ov.decompressBytes != nil { // GAP-b two-array strawman ONLY
		decompressBytes = ov.decompressBytes
	}
	permutation, err := poseidon2perm.NewPoseidon2FromParameters(api, 2, 6, 50)
	if err != nil {
		return err
	}
	hasher := hash.NewMerkleDamgardHasher(api, permutation, 0)
	two64 := new(big.Int).Lsh(big.NewInt(1), 64)
	two128 := new(big.Int).Lsh(big.NewInt(1), 128)
	for i := range decompressBytes {
		point := decompressAndValidate(api, field, g1, decompressBytes[i], yHint[i])
		hasher.Write(packCoordinate(api, point.X.Limbs, two64, two128)...)
		hasher.Write(packCoordinate(api, point.Y.Limbs, two64, two128)...)
	}
	api.AssertIsEqual(hasher.Sum(), nextPubkeysCommitment)
	return nil
}

// packCoordinate folds 6 emulated limbs (each < 2^64) into 2 native-Fr elements via a
// FREE linear combination: lo = l0 + l1·2^64 + l2·2^128, hi = l3 + l4·2^64 + l5·2^128.
// Same recipe (4 Fr/pubkey) as cmd/measure_poseidon_commit — the regular-circuit bind
// must pack identically for the commitment to match (encoding A).
func packCoordinate(api frontend.API, limbs []frontend.Variable, two64, two128 *big.Int) []frontend.Variable {
	lo := api.Add(limbs[0], api.Mul(limbs[1], two64), api.Mul(limbs[2], two128))
	hi := api.Add(limbs[3], api.Mul(limbs[4], two64), api.Mul(limbs[5], two128))
	return []frontend.Variable{lo, hi}
}
