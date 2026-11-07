// fixtures.go — load a Bootstrap witness from the curated period-1600 JSON fixtures: the
// LightClientBootstrap fixture (β: bootstrap header + current committee + gindex-86 branch +
// block_root) and the extended LightClientUpdate fixture (attested/next/finality + the
// sync_aggregate + fork_version/genesis_validators_root). Extracted from
// bootstrap_realpositive_test.go (the real-positive test now calls this) so that
// cmd/measure_bootstrap — and the future deployer tooling — load through the SAME path the
// test validates; error-returning (no testing.T). Parsing uses the error-latch idiom
// (first error wins, checked once at the end — the sszMerkleizer pattern).
package bootstrap

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strconv"

	"eth-cardano-zk-light-client/prover/offchain/ssz"
)

type fixtureBeaconHeader struct {
	Slot          string `json:"slot"`
	ProposerIndex string `json:"proposer_index"`
	ParentRoot    string `json:"parent_root"`
	StateRoot     string `json:"state_root"`
	BodyRoot      string `json:"body_root"`
}

type bootstrapFixture struct {
	BlockRoot            string              `json:"block_root"`
	Header               fixtureBeaconHeader `json:"header"`
	CurrentSyncCommittee struct {
		Pubkeys         []string `json:"pubkeys"`
		AggregatePubkey string   `json:"aggregate_pubkey"`
	} `json:"current_sync_committee"`
	CurrentBranch []string `json:"current_sync_committee_branch"`
}

type updateFixture struct {
	Pubkeys         []string            `json:"pubkeys"`
	AggregatePubkey string              `json:"aggregate_pubkey"`
	NextBranch      []string            `json:"next_sync_committee_branch"`
	FinalizedHeader fixtureBeaconHeader `json:"finalized_header"`
	FinalityBranch  []string            `json:"finality_branch"`
	AttestedHeader  fixtureBeaconHeader `json:"attested_header"`
	SyncAggregate   struct {
		Bits      string `json:"sync_committee_bits"`
		Signature string `json:"sync_committee_signature"`
	} `json:"sync_aggregate"`
	SignatureSlot         string `json:"signature_slot"`
	GenesisValidatorsRoot string `json:"genesis_validators_root"`
	ForkVersion           string `json:"fork_version"`
}

func readFixtureJSON(path string, destination any) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}
	if err := json.Unmarshal(raw, destination); err != nil {
		return fmt.Errorf("unmarshal %s: %w", path, err)
	}
	return nil
}

// fixtureParser latches the first parse error; every accessor is a no-op after that, and
// LoadFromFixtures checks the latch once at the end.
type fixtureParser struct {
	err error
}

func (p *fixtureParser) hexBytes(s string, n int) []byte {
	if p.err != nil {
		return nil
	}
	if len(s) < 2 {
		p.err = fmt.Errorf("hex %q: missing 0x prefix", s)
		return nil
	}
	b, err := hex.DecodeString(s[2:])
	if err != nil || len(b) != n {
		p.err = fmt.Errorf("hex %q: want %d bytes, got %d (err %v)", s, n, len(b), err)
		return nil
	}
	return b
}

func (p *fixtureParser) bytes32(s string) (out [32]byte) { copy(out[:], p.hexBytes(s, 32)); return }
func (p *fixtureParser) bytes48(s string) (out [48]byte) { copy(out[:], p.hexBytes(s, 48)); return }
func (p *fixtureParser) bytes4(s string) (out [4]byte)   { copy(out[:], p.hexBytes(s, 4)); return }

func (p *fixtureParser) uint64Field(name, s string) uint64 {
	if p.err != nil {
		return 0
	}
	value, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		p.err = fmt.Errorf("%s %q: %v", name, s, err)
		return 0
	}
	return value
}

func (p *fixtureParser) header(h fixtureBeaconHeader) ssz.Header {
	return ssz.Header{
		Slot:          p.uint64Field("slot", h.Slot),
		ProposerIndex: p.uint64Field("proposer_index", h.ProposerIndex),
		ParentRoot:    p.bytes32(h.ParentRoot),
		StateRoot:     p.bytes32(h.StateRoot),
		BodyRoot:      p.bytes32(h.BodyRoot),
	}
}

func (p *fixtureParser) compressedKeys(pubkeys []string) [][48]byte {
	out := make([][48]byte, len(pubkeys))
	for i, pk := range pubkeys {
		out[i] = p.bytes48(pk)
	}
	return out
}

func (p *fixtureParser) branch6(b []string) (out [6][32]byte) {
	if p.err != nil {
		return
	}
	if len(b) != 6 {
		p.err = fmt.Errorf("branch length %d, want 6", len(b))
		return
	}
	for i := range out {
		out[i] = p.bytes32(b[i])
	}
	return
}

func (p *fixtureParser) branch7(b []string) (out [7][32]byte) {
	if p.err != nil {
		return
	}
	if len(b) != 7 {
		p.err = fmt.Errorf("branch length %d, want 7", len(b))
		return
	}
	for i := range out {
		out[i] = p.bytes32(b[i])
	}
	return
}

// participationBits parses the 64-byte SSZ bitvector (little-endian bit order) → 512 bools.
func (p *fixtureParser) participationBits(s string) []bool {
	b := p.hexBytes(s, 64)
	if p.err != nil {
		return nil
	}
	bits := make([]bool, 512)
	for i := 0; i < 512; i++ {
		bits[i] = (b[i/8]>>(i%8))&1 == 1
	}
	return bits
}

// LoadFromFixtures assembles the Bootstrap witness from the two curated fixture files and
// returns it together with the update's signature_slot (for the caller's period checks).
func LoadFromFixtures(bootstrapFixturePath, updateFixturePath string) (*Bootstrap, uint64, error) {
	var beta bootstrapFixture
	if err := readFixtureJSON(bootstrapFixturePath, &beta); err != nil {
		return nil, 0, err
	}
	var update updateFixture
	if err := readFixtureJSON(updateFixturePath, &update); err != nil {
		return nil, 0, err
	}

	parser := &fixtureParser{}
	var signature [96]byte
	copy(signature[:], parser.hexBytes(update.SyncAggregate.Signature, 96))

	input := &Bootstrap{
		BootstrapHeader:        parser.header(beta.Header),
		TrustedBlockRoot:       parser.bytes32(beta.BlockRoot),
		CurrentCommittee:       SyncCommittee{Pubkeys: parser.compressedKeys(beta.CurrentSyncCommittee.Pubkeys), AggregatePubkey: parser.bytes48(beta.CurrentSyncCommittee.AggregatePubkey)},
		CurrentCommitteeBranch: parser.branch6(beta.CurrentBranch),
		AttestedHeader:         parser.header(update.AttestedHeader),
		NextCommittee:          SyncCommittee{Pubkeys: parser.compressedKeys(update.Pubkeys), AggregatePubkey: parser.bytes48(update.AggregatePubkey)},
		NextCommitteeBranch:    parser.branch6(update.NextBranch),
		FinalizedHeader:        parser.header(update.FinalizedHeader),
		FinalityBranch:         parser.branch7(update.FinalityBranch),
		ParticipationBits:      parser.participationBits(update.SyncAggregate.Bits),
		Signature:              signature,
		ForkVersion:            parser.bytes4(update.ForkVersion),
		GenesisValidatorsRoot:  parser.bytes32(update.GenesisValidatorsRoot),
	}
	signatureSlot := parser.uint64Field("signature_slot", update.SignatureSlot)
	input.SignatureSlot = signatureSlot
	if parser.err != nil {
		return nil, 0, parser.err
	}
	return input, signatureSlot, nil
}
