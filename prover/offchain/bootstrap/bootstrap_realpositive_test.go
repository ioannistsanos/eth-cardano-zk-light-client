package bootstrap

// TestBootstrap_RealPositive runs Verify on REAL mainnet period-1600 data assembled from two
// publicnode.com sources: the LightClientBootstrap (current committee + gindex-86 branch + header,
// offchain/bootstrap/testdata/electra_bootstrap_period_1600.json) and the LightClientUpdate
// (attested/next/finality + the sync_aggregate, circuits/common/testdata/lightclientupdate/
// electra_period_1600.json — the same fixture the regular/op-3b/op-6 anchors use). Verify must
// ACCEPT, producing the real genesis datum. Loading goes through LoadFromFixtures (fixtures.go) —
// the same production loader cmd/measure_bootstrap uses, so this test validates that path too.
//
// This CLOSES COMMIT C's caveat: condition (d) here is the WHOLE BLS path on a REAL Ethereum
// signature — compute_domain(0x07000000, fork_version 0x05000000 resolved at signature_slot's epoch
// 409602, pre-Fulu; mainnet gvr) -> compute_signing_root(htr(attested)=0x7099a98d…) ->
// FastAggregateVerify over the bootstrap's 510 participating current-committee keys vs the update's
// sync_aggregate.signature — not just the ssz_static construction vectors. Its passing is ALSO the
// cross-source consistency proof: the bootstrap committee IS the update's signers (a wrong
// committee/fork/gvr would fail the pairing).
//
// HONESTY BOUNDARY: this proves Verify accepts real data end-to-end + the real BLS path. It does NOT
// exercise the rejection paths (real keys are canonical, so the canonicity/branch/checkpoint
// negatives stay TestBootstrap_*Rejected's job), the on-chain mint (Phase-3 Aiken), and it is a
// DEMONSTRATION genesis (period 1600), not the deployment genesis. It COMPLEMENTS the synthetic.

import (
	"encoding/hex"
	"testing"

	"eth-cardano-zk-light-client/prover/offchain/bls"
)

const (
	realPositiveBootstrapFixture = "testdata/electra_bootstrap_period_1600.json"
	realPositiveUpdateFixture    = "../../circuits/common/testdata/lightclientupdate/electra_period_1600.json"
	// golden datum (pinned from the gate run) — a regression guard on the real commitments.
	realCurrentCommitment   = "10041e8ce930617c420c43546f39dc8d123cec24e199f3f51dfadcb448529e1e"
	realNextCommitment      = "483e20c94d6075d0dd670d9b6fe7144456eecc96fadb501ac719e4473625510f"
	realFinalizedHeaderRoot = "201a1d12d634bcf8de5a9281d8cf5974cb775be0f8741a1cf0123e0383878599"
)

func TestBootstrap_RealPositive(t *testing.T) {
	input, signatureSlot, err := LoadFromFixtures(realPositiveBootstrapFixture, realPositiveUpdateFixture)
	if err != nil {
		t.Fatalf("load fixtures: %v", err)
	}

	// cross-source period consistency (precondition; the BLS verify in Verify is the definitive tie)
	if signatureSlot/8192 != 1600 || input.BootstrapHeader.Slot/8192 != 1600 {
		t.Fatalf("period mismatch: bootstrap_slot %d, signature_slot %d (want both period 1600)", input.BootstrapHeader.Slot, signatureSlot)
	}
	participation := 0
	for _, bit := range input.ParticipationBits {
		if bit {
			participation++
		}
	}
	if participation < bls.ParticipationThreshold {
		t.Fatalf("participation %d < threshold %d", participation, bls.ParticipationThreshold)
	}

	result, err := Verify(input)
	if err != nil {
		t.Fatalf("REAL POSITIVE FAILED — Verify rejected real period-1600 data: %v", err)
	}

	current := result.CurrentPubkeysCommitment.Bytes()
	next := result.NextPubkeysCommitment.Bytes()
	if hex.EncodeToString(current[:]) != realCurrentCommitment {
		t.Fatalf("current_pubkeys_commitment = %x, want %s", current[:], realCurrentCommitment)
	}
	if hex.EncodeToString(next[:]) != realNextCommitment {
		t.Fatalf("next_pubkeys_commitment = %x, want %s", next[:], realNextCommitment)
	}
	if hex.EncodeToString(result.FinalizedHeaderRoot[:]) != realFinalizedHeaderRoot {
		t.Fatalf("finalized_header_root = %x, want %s", result.FinalizedHeaderRoot, realFinalizedHeaderRoot)
	}
	if result.FinalizedSlot != 13107200 {
		t.Fatalf("finalized_slot = %d, want 13107200", result.FinalizedSlot)
	}
	t.Logf("PASS: real period-1600 genesis verifies end-to-end (gate (iv) BLS on a real signature, %d/512 participation)", participation)
	t.Logf("  datum = {current 0x%s, next 0x%s, finalized_root 0x%s, finalized_slot 13107200}", realCurrentCommitment, realNextCommitment, realFinalizedHeaderRoot)
}
