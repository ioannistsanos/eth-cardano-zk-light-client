package boot

import "testing"

// the real period-1600 fixtures (the same the bootstrap real-positive test + measure_bootstrap use),
// relative to this package directory (prover/offchain/boot).
const (
	realBootstrapFixture = "../bootstrap/testdata/electra_bootstrap_period_1600.json"
	realUpdateFixture    = "../../circuits/common/testdata/lightclientupdate/electra_period_1600.json"
	vkRegularFixture     = "../../../validator/fixtures/groth16_regular_n8.json"
	vkBoundaryFixture    = "../../../validator/fixtures/groth16_boundary_n8.json"

	// the golden genesis values — IDENTICAL to bootstrap_realpositive_test.go's pins AND to the
	// constants the Aiken genesis datum embeds (validator/lib/zkbridge/genesis_datum_test.ak). This
	// triple-pin (Go gate / Go gate-runner / Aiken datum) is the consistency the design's one-line
	// note promises; the assembler's sha2_256 check is the ultimate cross-check.
	goldenCurrentCommitment   = "10041e8ce930617c420c43546f39dc8d123cec24e199f3f51dfadcb448529e1e"
	goldenNextCommitment      = "483e20c94d6075d0dd670d9b6fe7144456eecc96fadb501ac719e4473625510f"
	goldenFinalizedHeaderRoot = "201a1d12d634bcf8de5a9281d8cf5974cb775be0f8741a1cf0123e0383878599"
	goldenForkVersion         = "05000000"
	goldenGenesisValidators   = "4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95"
)

// TestBuildGenesisValues_RealPositive: the §2.1.6 gate runs on real period-1600 data and the
// assembled genesis values match the golden datum the Aiken seam test pins. Fields 1-4 come from the
// gate Result; 5-6 are the anchors; 7-8 echo the vk fixture paths.
func TestBuildGenesisValues_RealPositive(t *testing.T) {
	values, err := BuildGenesisValues(realBootstrapFixture, realUpdateFixture, vkRegularFixture, vkBoundaryFixture)
	if err != nil {
		t.Fatalf("BuildGenesisValues rejected real period-1600 data: %v", err)
	}

	checks := []struct {
		name, got, want string
	}{
		{"finalized_header_root", values.FinalizedHeaderRoot, goldenFinalizedHeaderRoot},
		{"current_committee_commitment", values.CurrentCommitteeCommitment, goldenCurrentCommitment},
		{"next_committee_commitment", values.NextCommitteeCommitment, goldenNextCommitment},
		{"fork_version", values.ForkVersion, goldenForkVersion},
		{"genesis_validators_root", values.GenesisValidatorsRoot, goldenGenesisValidators},
		{"verifying_key_regular_fixture", values.VerifyingKeyRegularFixture, vkRegularFixture},
		{"verifying_key_boundary_fixture", values.VerifyingKeyBoundaryFixture, vkBoundaryFixture},
	}
	for _, check := range checks {
		if check.got != check.want {
			t.Errorf("%s = %s, want %s", check.name, check.got, check.want)
		}
	}
	if values.FinalizedSlot != 13107200 {
		t.Errorf("finalized_slot = %d, want 13107200", values.FinalizedSlot)
	}
	t.Logf("PASS: §2.1.6 gate → genesis values match the golden datum (current 0x%s…, slot %d)", values.CurrentCommitteeCommitment[:12], values.FinalizedSlot)
}

// TestBuildGenesisValues_LoadFailureAborts: a missing bootstrap fixture yields no values (the abort
// semantics — there is no genesis datum without a passing gate). The gate's own rejection paths
// (non-canonical key, branch mismatch, BLS failure) are covered by the bootstrap package's
// TestBootstrap_*Rejected; BuildGenesisValues propagates those sentinels verbatim.
func TestBuildGenesisValues_LoadFailureAborts(t *testing.T) {
	values, err := BuildGenesisValues("../bootstrap/testdata/does_not_exist.json", realUpdateFixture, vkRegularFixture, vkBoundaryFixture)
	if err == nil {
		t.Fatalf("expected an abort on a missing fixture, got values: %+v", values)
	}
	if values != nil {
		t.Errorf("expected nil values on abort, got %+v", values)
	}
}
