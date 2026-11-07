package beacon

import (
	"encoding/json"
	"fmt"
	"os"
)

// The fixture output structs mirror offchain/bootstrap/fixtures.go byte-for-byte (same JSON tags,
// 0x-hex strings, decimal-string slots, header flattened) so the captured files load through the
// EXISTING LoadFromFixtures unchanged. An extra _provenance block is decorative (json.Unmarshal
// ignores unknown fields) — it matches the hand-fetched period-1600 fixtures' format.

// Provenance records where + when each fixture was fetched (traceability, like the period-1600 set).
type Provenance struct {
	Source   string `json:"source"`
	Endpoint string `json:"endpoint"`
	Fetched  string `json:"fetched"`
	Period   uint64 `json:"period"`
	Note     string `json:"note"`
}

type fixHeader struct {
	Slot          string `json:"slot"`
	ProposerIndex string `json:"proposer_index"`
	ParentRoot    string `json:"parent_root"`
	StateRoot     string `json:"state_root"`
	BodyRoot      string `json:"body_root"`
}

func toFixHeader(h apiHeader) fixHeader {
	return fixHeader{
		Slot:          h.Beacon.Slot,
		ProposerIndex: h.Beacon.ProposerIndex,
		ParentRoot:    h.Beacon.ParentRoot,
		StateRoot:     h.Beacon.StateRoot,
		BodyRoot:      h.Beacon.BodyRoot,
	}
}

type bootstrapFixtureOut struct {
	Provenance           Provenance `json:"_provenance"`
	BlockRoot            string     `json:"block_root"`
	Header               fixHeader  `json:"header"`
	CurrentSyncCommittee struct {
		Pubkeys         []string `json:"pubkeys"`
		AggregatePubkey string   `json:"aggregate_pubkey"`
	} `json:"current_sync_committee"`
	CurrentBranch []string `json:"current_sync_committee_branch"`
}

type updateFixtureOut struct {
	Provenance      Provenance `json:"_provenance"`
	Pubkeys         []string   `json:"pubkeys"`
	AggregatePubkey string     `json:"aggregate_pubkey"`
	NextBranch      []string   `json:"next_sync_committee_branch"`
	FinalizedHeader fixHeader  `json:"finalized_header"`
	FinalityBranch  []string   `json:"finality_branch"`
	AttestedHeader  fixHeader  `json:"attested_header"`
	SyncAggregate   struct {
		Bits      string `json:"sync_committee_bits"`
		Signature string `json:"sync_committee_signature"`
	} `json:"sync_aggregate"`
	SignatureSlot         string `json:"signature_slot"`
	GenesisValidatorsRoot string `json:"genesis_validators_root"`
	ForkVersion           string `json:"fork_version"`
}

func writeJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", " ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, append(b, '\n'), 0o644); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

// WriteBootstrapFixture serialises a fetched bootstrap (the β file) at the schema LoadFromFixtures
// reads; blockRoot is the root the bootstrap was fetched at (the trusted checkpoint).
func WriteBootstrapFixture(path string, b *Bootstrap, blockRoot string, prov Provenance) error {
	var out bootstrapFixtureOut
	out.Provenance = prov
	out.BlockRoot = blockRoot
	out.Header = toFixHeader(b.Header)
	out.CurrentSyncCommittee.Pubkeys = b.CurrentSyncCommittee.Pubkeys
	out.CurrentSyncCommittee.AggregatePubkey = b.CurrentSyncCommittee.AggregatePubkey
	out.CurrentBranch = b.CurrentSyncCommitteeBranch
	return writeJSON(path, out)
}

// WriteUpdateFixture serialises an α file. The attested/finalized/aggregate come from u (a
// LightClientUpdate or a finality update); the NEXT committee + branch are passed separately,
// because a finality update carries none — a regular fixture borrows its period's next committee
// (LoadFromFixtures requires a 6-element next branch even though BuildRegular ignores it).
func WriteUpdateFixture(path string, u *Update, nextPubkeys []string, nextAgg string, nextBranch []string, forkVersion, gvr string, prov Provenance) error {
	var out updateFixtureOut
	out.Provenance = prov
	out.Pubkeys = nextPubkeys
	out.AggregatePubkey = nextAgg
	out.NextBranch = nextBranch
	out.FinalizedHeader = toFixHeader(u.FinalizedHeader)
	out.FinalityBranch = u.FinalityBranch
	out.AttestedHeader = toFixHeader(u.AttestedHeader)
	out.SyncAggregate.Bits = u.SyncAggregate.Bits
	out.SyncAggregate.Signature = u.SyncAggregate.Signature
	out.SignatureSlot = u.SignatureSlot
	out.GenesisValidatorsRoot = gvr
	out.ForkVersion = forkVersion
	return writeJSON(path, out)
}
