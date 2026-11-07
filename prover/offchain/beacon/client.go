// Package beacon is a minimal READ-ONLY Ethereum beacon light-client fetcher — the S1 capture
// client for the end-to-end scenario (docs/c-runbook.md).
// It hits the three light-client endpoints publicnode.com serves (the archival source the
// period-1600 fixtures came from), plus /genesis and /config/fork_schedule, and re-serialises
// each response into the EXISTING fixture schema (offchain/bootstrap/fixtures.go) so the captured
// data flows through the SAME validated LoadFromFixtures → Verify / BuildRegular / BuildBoundary
// path. No writes to the chain, no auth, no token.
package beacon

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"
)

// DefaultBase is the archival mainnet endpoint that served the period-1600 fixtures (_provenance).
const DefaultBase = "https://ethereum-beacon-api.publicnode.com"

const (
	SlotsPerPeriod = 8192 // 256 epochs
	SlotsPerEpoch  = 32
	SecondsPerSlot = 12
)

// Client is a thin HTTP wrapper over the beacon REST API (read-only).
type Client struct {
	Base string
	HTTP *http.Client
}

// NewClient returns a client against base (or DefaultBase when empty), 30 s per-request timeout.
func NewClient(base string) *Client {
	if base == "" {
		base = DefaultBase
	}
	return &Client{Base: base, HTTP: &http.Client{Timeout: 30 * time.Second}}
}

func (c *Client) getJSON(path string, out any) error {
	resp, err := c.HTTP.Get(c.Base + path)
	if err != nil {
		return fmt.Errorf("GET %s: %w", path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: HTTP %d: %s", path, resp.StatusCode, snippet(body))
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("decode %s: %w (body: %s)", path, err, snippet(body))
	}
	return nil
}

func snippet(b []byte) string {
	if len(b) > 240 {
		return string(b[:240]) + "…"
	}
	return string(b)
}

// ── beacon response shapes (LightClientHeader nests the header under .beacon) ──

type apiBeaconHeader struct {
	Slot          string `json:"slot"`
	ProposerIndex string `json:"proposer_index"`
	ParentRoot    string `json:"parent_root"`
	StateRoot     string `json:"state_root"`
	BodyRoot      string `json:"body_root"`
}

type apiHeader struct {
	Beacon apiBeaconHeader `json:"beacon"`
}

type apiSyncCommittee struct {
	Pubkeys         []string `json:"pubkeys"`
	AggregatePubkey string   `json:"aggregate_pubkey"`
}

type apiSyncAggregate struct {
	Bits      string `json:"sync_committee_bits"`
	Signature string `json:"sync_committee_signature"`
}

// Bootstrap is GET /eth/v1/beacon/light_client/bootstrap/{root} → .data.
type Bootstrap struct {
	Header                     apiHeader        `json:"header"`
	CurrentSyncCommittee       apiSyncCommittee `json:"current_sync_committee"`
	CurrentSyncCommitteeBranch []string         `json:"current_sync_committee_branch"`
}

// Update is one LightClientUpdate (updates[i].data) OR a LightClientFinalityUpdate (.data —
// its NextSyncCommittee / NextSyncCommitteeBranch are absent, so empty).
type Update struct {
	AttestedHeader          apiHeader        `json:"attested_header"`
	NextSyncCommittee       apiSyncCommittee `json:"next_sync_committee"`
	NextSyncCommitteeBranch []string         `json:"next_sync_committee_branch"`
	FinalizedHeader         apiHeader        `json:"finalized_header"`
	FinalityBranch          []string         `json:"finality_branch"`
	SyncAggregate           apiSyncAggregate `json:"sync_aggregate"`
	SignatureSlot           string           `json:"signature_slot"`
}

// Genesis is GET /eth/v1/beacon/genesis → .data (genesis_time for the boundary wall-clock).
type Genesis struct {
	GenesisTime           string `json:"genesis_time"`
	GenesisValidatorsRoot string `json:"genesis_validators_root"`
	GenesisForkVersion    string `json:"genesis_fork_version"`
}

// FetchBootstrap pulls the LightClientBootstrap (current committee + gindex-86 branch) at a root.
func (c *Client) FetchBootstrap(blockRoot string) (*Bootstrap, error) {
	var env struct {
		Data Bootstrap `json:"data"`
	}
	if err := c.getJSON("/eth/v1/beacon/light_client/bootstrap/"+blockRoot, &env); err != nil {
		return nil, err
	}
	return &env.Data, nil
}

// FetchUpdate pulls the single canonical LightClientUpdate for a period (attested + next
// committee + finality + aggregate). updates?start_period=N&count=1 returns an array.
func (c *Client) FetchUpdate(period uint64) (*Update, error) {
	var env []struct {
		Data Update `json:"data"`
	}
	if err := c.getJSON(fmt.Sprintf("/eth/v1/beacon/light_client/updates?start_period=%d&count=1", period), &env); err != nil {
		return nil, err
	}
	if len(env) == 0 {
		return nil, fmt.Errorf("updates start_period=%d: empty array", period)
	}
	return &env[0].Data, nil
}

// FetchFinalityUpdate pulls the LATEST finality update (no next committee). Polled intra-period.
func (c *Client) FetchFinalityUpdate() (*Update, error) {
	var env struct {
		Data Update `json:"data"`
	}
	if err := c.getJSON("/eth/v1/beacon/light_client/finality_update", &env); err != nil {
		return nil, err
	}
	return &env.Data, nil
}

// FetchGenesis pulls genesis_time + genesis_validators_root (network constants).
func (c *Client) FetchGenesis() (*Genesis, error) {
	var env struct {
		Data Genesis `json:"data"`
	}
	if err := c.getJSON("/eth/v1/beacon/genesis", &env); err != nil {
		return nil, err
	}
	return &env.Data, nil
}

// FetchForkVersionAtEpoch resolves the fork_version active at an epoch from /config/fork_schedule
// (the highest scheduled fork with epoch ≤ the target) — used in the BLS domain.
func (c *Client) FetchForkVersionAtEpoch(epoch uint64) (string, error) {
	var env struct {
		Data []struct {
			CurrentVersion string `json:"current_version"`
			Epoch          string `json:"epoch"`
		} `json:"data"`
	}
	if err := c.getJSON("/eth/v1/config/fork_schedule", &env); err != nil {
		return "", err
	}
	best, haveBest := "", false
	var bestEpoch uint64
	for _, f := range env.Data {
		e, err := strconv.ParseUint(f.Epoch, 10, 64)
		if err != nil {
			continue
		}
		if e <= epoch && (!haveBest || e >= bestEpoch) {
			best, bestEpoch, haveBest = f.CurrentVersion, e, true
		}
	}
	if !haveBest {
		return "", fmt.Errorf("no fork scheduled at or before epoch %d", epoch)
	}
	return best, nil
}

// FetchHeadSlot returns the current head slot (for period / boundary computation).
func (c *Client) FetchHeadSlot() (uint64, error) {
	var env struct {
		Data struct {
			Header struct {
				Message struct {
					Slot string `json:"slot"`
				} `json:"message"`
			} `json:"header"`
		} `json:"data"`
	}
	if err := c.getJSON("/eth/v1/beacon/headers/head", &env); err != nil {
		return 0, err
	}
	return strconv.ParseUint(env.Data.Header.Message.Slot, 10, 64)
}
