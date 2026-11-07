package common

// 2b-iii real-data anchor (layout fidelity). Off-circuit only: confirm our gindex-87
// fold [T,T,T,F,T,F] + container layout H(pubkeys_root, agg_root) reproduce a REAL
// Electra LightClientUpdate's attested_header.beacon.state_root. NON-CIRCULAR: the
// state_root is independent ground truth (Ethereum computed it, not us), and the branch
// encodes the real tree — so a wrong fold/layout cannot reach it. Fixture is committed
// (testdata/lightclientupdate/), so CI is offline/deterministic. Soundness already
// stands from commits 1+2 (the GAP-a contrast); this is layout fidelity.

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"

	"eth-cardano-zk-light-client/prover/offchain/ssz"
)

type lightClientUpdateFixture struct {
	Provenance struct {
		ForkVersion  string `json:"fork_version"`
		AttestedSlot string `json:"attested_slot"`
		Period       int    `json:"period"`
	} `json:"_provenance"`
	Pubkeys                 []string `json:"pubkeys"`
	AggregatePubkey         string   `json:"aggregate_pubkey"`
	NextSyncCommitteeBranch []string `json:"next_sync_committee_branch"`
	AttestedStateRoot       string   `json:"attested_state_root"`
	// op-3b extension (same update, re-fetched + verified identical): the finalized
	// header (5 beacon fields) + the depth-7 Electra finality_branch (gindex 169).
	FinalizedHeader struct {
		Slot          string `json:"slot"`
		ProposerIndex string `json:"proposer_index"`
		ParentRoot    string `json:"parent_root"`
		StateRoot     string `json:"state_root"`
		BodyRoot      string `json:"body_root"`
	} `json:"finalized_header"`
	FinalityBranch []string `json:"finality_branch"`
	// regular real-Electra positive extension (same update): the attested header's 5
	// beacon fields (op-3a reconstructs its root 0x7099a98d…).
	AttestedHeader struct {
		Slot          string `json:"slot"`
		ProposerIndex string `json:"proposer_index"`
		ParentRoot    string `json:"parent_root"`
		StateRoot     string `json:"state_root"`
		BodyRoot      string `json:"body_root"`
	} `json:"attested_header"`
}

func decodeHex32(t *testing.T, s string) [32]byte {
	t.Helper()
	raw, err := hex.DecodeString(strings.TrimPrefix(s, "0x"))
	if err != nil || len(raw) != 32 {
		t.Fatalf("bad 32-byte hex %q: %v (len %d)", s, err, len(raw))
	}
	var out [32]byte
	copy(out[:], raw)
	return out
}

func loadLightClientUpdate(t *testing.T) lightClientUpdateFixture {
	t.Helper()
	fileBytes, err := os.ReadFile(filepath.Join("testdata", "lightclientupdate", "electra_period_1600.json"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var fixture lightClientUpdateFixture
	if err := json.Unmarshal(fileBytes, &fixture); err != nil {
		t.Fatalf("parse fixture: %v", err)
	}
	if len(fixture.Pubkeys) != 512 {
		t.Fatalf("expected 512 pubkeys, got %d", len(fixture.Pubkeys))
	}
	return fixture
}

// TestOp6AnchorsToRealEthereum: PubkeysRoot(512) -> H(., Bytes48Root(agg)) ->
// Gindex87Walk([T,T,T,F,T,F]) == real attested_header.beacon.state_root.
func TestOp6AnchorsToRealEthereum(t *testing.T) {
	fixture := loadLightClientUpdate(t)

	// Fork verification: a depth-6 next_sync_committee_branch => gindex 87.
	if len(fixture.NextSyncCommitteeBranch) != 6 {
		t.Fatalf("FORK MISMATCH (HALT): expected a depth-6 branch (gindex 87), got %d nodes", len(fixture.NextSyncCommitteeBranch))
	}

	pubkeys := make([][48]byte, len(fixture.Pubkeys))
	for i, s := range fixture.Pubkeys {
		pubkeys[i] = decodeHex48(t, s)
	}
	aggregate := decodeHex48(t, fixture.AggregatePubkey)
	var branch [6][32]byte
	for i, s := range fixture.NextSyncCommitteeBranch {
		branch[i] = decodeHex32(t, s)
	}
	stateRoot := decodeHex32(t, fixture.AttestedStateRoot)

	pubkeysRoot := ssz.PubkeysRoot(pubkeys)                                // gindex 174 (container layout)
	aggregateRoot := ssz.Bytes48Root(aggregate)                            // gindex 175
	syncCommitteeRoot := ssz.SyncCommitteeRoot(pubkeysRoot, aggregateRoot) // gindex 87 leaf
	computed := ssz.Gindex87Walk(syncCommitteeRoot, branch)                // -> BeaconState root

	if computed != stateRoot {
		t.Fatalf("ANCHOR FAILED (LAYOUT FINDING — HALT): our fold != real state_root\n"+
			"  computed = 0x%x\n  expected = 0x%x\n"+
			"  => our [T,T,T,F,T,F] gindex-87 fold or H(pubkeys_root,agg_root) layout differs from real Ethereum",
			computed, stateRoot)
	}
	t.Logf("PASS: gindex-87 fold + container layout reproduce REAL Ethereum (fork=%s, attested_slot=%s, period=%d)",
		fixture.Provenance.ForkVersion, fixture.Provenance.AttestedSlot, fixture.Provenance.Period)
	t.Logf("  pubkeys_root (gindex 174)       = 0x%x", pubkeysRoot)
	t.Logf("  sync_committee_root (gindex 87) = 0x%x", syncCommitteeRoot)
	t.Logf("  state_root (matched)            = 0x%x", stateRoot)
}

// TestOp6RealKeyDecompresses (bonus): the 2b-ii decompress-and-validate unit accepts a
// REAL committee pubkey (authentic compressed G1), not just generated points.
func TestOp6RealKeyDecompresses(t *testing.T) {
	fixture := loadLightClientUpdate(t)
	compressed := decodeHex48(t, fixture.Pubkeys[0])
	var point bls12381.G1Affine
	if _, err := point.SetBytes(compressed[:]); err != nil {
		t.Fatalf("real pubkey[0] is not a valid compressed G1 point: %v", err)
	}
	if err := solveDecompress(compressed, point.Y); err != nil {
		t.Fatalf("decompressAndValidate REJECTED a real committee key (decompress broken on authentic data): %v", err)
	}
	t.Logf("PASS: decompress-and-validate accepts real Electra committee pubkey[0] (on-curve+sign+canonical recovered (x,y))")
}
