package relayer

import (
	"encoding/json"
	"os"
	"testing"

	"eth-cardano-zk-light-client/prover/offchain/bootstrap"
)

// Relative to this package dir (prover/offchain/relayer): the period-1600 fixtures + the committed
// bls fixture (the SAME inputs cmd/export_bls_fixture used).
const (
	period1600Bootstrap = "../bootstrap/testdata/electra_bootstrap_period_1600.json"
	period1600Update    = "../../circuits/common/testdata/lightclientupdate/electra_period_1600.json"
	blsFixturePath      = "../../../validator/fixtures/bls_regular_period1600.json"
)

// The BLS-helper gate: BuildBLSFields (the daemon's live producer) reproduces the committed
// bls_regular_period1600.json BYTE-FOR-BYTE from the period-1600 inputs — apk / count / σ / attested /
// fork / gvr. Those exact fields fed the D27 on-chain spend, so this ties the live helper to a
// proven-on-chain instance before any live use. (Boundary fields are exercised VM-tier — no committed
// boundary σ fixture, same gap as D27 boundary.)
func TestBuildBLSFields_RegularMatchesFixture(t *testing.T) {
	input, _, err := bootstrap.LoadFromFixtures(period1600Bootstrap, period1600Update)
	if err != nil {
		t.Fatalf("load fixtures: %v", err)
	}
	got, err := BuildBLSFields(input, Regular)
	if err != nil {
		t.Fatalf("BuildBLSFields(Regular): %v", err)
	}

	var want struct {
		Signature             string `json:"signature"`
		ApkUncompressed       string `json:"apk_uncompressed"`
		ForkVersion           string `json:"fork_version"`
		GenesisValidatorsRoot string `json:"genesis_validators_root"`
		AttestedHeaderRoot    string `json:"attested_header_root"`
		Count                 int    `json:"count"`
	}
	raw, err := os.ReadFile(blsFixturePath)
	if err != nil {
		t.Fatalf("read bls fixture: %v", err)
	}
	if err := json.Unmarshal(raw, &want); err != nil {
		t.Fatalf("decode bls fixture: %v", err)
	}

	if got.ApkUncompressed != want.ApkUncompressed {
		t.Fatalf("apk: got %s want %s", got.ApkUncompressed, want.ApkUncompressed)
	}
	if got.Signature != want.Signature {
		t.Fatalf("signature: got %s want %s", got.Signature, want.Signature)
	}
	if got.Count != want.Count {
		t.Fatalf("count: got %d want %d", got.Count, want.Count)
	}
	if got.AttestedHeaderRoot != want.AttestedHeaderRoot {
		t.Fatalf("attested root: got %s want %s", got.AttestedHeaderRoot, want.AttestedHeaderRoot)
	}
	if got.ForkVersion != want.ForkVersion {
		t.Fatalf("fork: got %s want %s", got.ForkVersion, want.ForkVersion)
	}
	if got.GenesisValidatorsRoot != want.GenesisValidatorsRoot {
		t.Fatalf("gvr: got %s want %s", got.GenesisValidatorsRoot, want.GenesisValidatorsRoot)
	}
	t.Logf("BLS-fields gate GREEN — apk/count(%d)/σ/attested/fork/gvr byte-identical to bls_regular_period1600.json", got.Count)
}

// TestBuildBLSFields_BoundaryAggregatesSigningCommittee reproduces the live boundary HALT on committed
// data, then (post Change-A) confirms the fix. The period-1600 boundary fixture's signing committee is
// CurrentCommittee = C₁₆₀₀ (the keys that actually signed THIS attested header) — the SAME committee the
// regular path aggregates. The pre-fix code aggregated NextCommittee = C₁₆₀₁ (the successor, NOT the
// signer), so the real σ failed to verify: the exact "σ does not verify off-chain … kind=BOUNDARY" HALT
// seen at the live B_1789. After the fix both kinds read CurrentCommittee, so the σ verifies and the
// boundary apk is byte-identical to the regular apk on the same fixture.
//
// SCOPE: this proves only the CONSUMER (BuildBLSFields reads the signing committee from CurrentCommittee).
// It does NOT exercise the live buildWitness override / the relayer's signer rotation (Changes B+C) — the
// 1600 fixture's CurrentCommittee already equals its signer, so the LIVE boundary stays broken until B+C.
func TestBuildBLSFields_BoundaryAggregatesSigningCommittee(t *testing.T) {
	input, _, err := bootstrap.LoadFromFixtures(period1600Bootstrap, period1600Update)
	if err != nil {
		t.Fatalf("load fixtures: %v", err)
	}

	boundary, err := BuildBLSFields(input, Boundary)
	if err != nil {
		t.Fatalf("BuildBLSFields(Boundary) must verify the σ under the signing committee: %v", err)
	}
	regular, err := BuildBLSFields(input, Regular)
	if err != nil {
		t.Fatalf("BuildBLSFields(Regular): %v", err)
	}

	// consistency: the boundary must aggregate the SAME signing committee the regular path does, or the
	// on-chain bls.verify (over redeemer.apk) and the Groth16 apk public would disagree again.
	if boundary.ApkUncompressed != regular.ApkUncompressed {
		t.Fatalf("boundary apk %s != regular apk %s — the boundary aggregated the wrong committee",
			boundary.ApkUncompressed, regular.ApkUncompressed)
	}
	if boundary.Count != regular.Count {
		t.Fatalf("boundary count %d != regular count %d", boundary.Count, regular.Count)
	}
	t.Logf("boundary BLS gate GREEN — σ verifies under the signing committee; apk(%d participants) byte-identical to the regular path", boundary.Count)
}
