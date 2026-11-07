package relayer

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"testing"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"

	"eth-cardano-zk-light-client/prover/offchain/bootstrap"
	"eth-cardano-zk-light-client/prover/offchain/commitment"
	"eth-cardano-zk-light-client/prover/offchain/witness"
)

// The Tier-2 boundary-rotation gate, on the REAL period-1788->1789 rotation fixture (the literal rollover
// that HALTed at B_1789; the committee commitments cross-validate against the live datum). Unlike the
// period-1600 Tier-1 fixture — whose CurrentCommittee already equalled its signer, so the override was a
// no-op there — this fixture loads through a PLACEHOLDER β, so the loaded CurrentCommittee is NOT the
// signer. The buildWitness override (applySigningCommittee) is therefore LOAD-BEARING here: it routes the
// bridge's NEXT (C_1789, the committee that signed update@1789) into input.CurrentCommittee, which makes
// the proof's pubkeys_commitment equal datum.next = 0037525b... (what bridge.ak:90 checks). With the
// override stubbed, assertion (1) below fails — that is the proof B+C are doing the work.
const (
	rotation1788Update      = "testdata/rotation/electra_period_1788.json" // -> its next = C_1789 (the signer)
	rotation1789Update      = "testdata/rotation/electra_period_1789.json" // the boundary: signed by C_1789, next = C_1790
	rotationBetaPlaceholder = "../bootstrap/testdata/electra_bootstrap_period_1600.json"

	// commit(C_1789) — cross-validated == the 1788 bridge's datum.next (the on-chain verify_boundary target).
	rotationDatumNext = "0037525bb6a5cb7a7471339e8c47bc1503f92ea51136ca6d796bf761749bbcc6"
	// commit(C_1790) — the new next op-6 installs (output.next after the rotation).
	rotationNewNext = "4b0faa29c3a3a3e480e9323e36da8a596cac9b2adce2c4771140613e1ac92e3d"
)

// nextCommitteeHexes reads an update fixture's `pubkeys` (its next sync committee) as the relayer caches
// them: 0x-prefixed compressed hexes.
func nextCommitteeHexes(t *testing.T, path string) []string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var fixture struct {
		Pubkeys []string `json:"pubkeys"`
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}
	if len(fixture.Pubkeys) != 512 {
		t.Fatalf("%s: want 512 pubkeys, got %d", path, len(fixture.Pubkeys))
	}
	return fixture.Pubkeys
}

func commitmentHexOf(t *testing.T, pubkeys [][48]byte) string {
	t.Helper()
	keys, err := bootstrap.DecompressCommittee(pubkeys)
	if err != nil {
		t.Fatalf("decompress: %v", err)
	}
	element := commitment.Commit(keys)
	committed := element.Bytes()
	return hex.EncodeToString(committed[:])
}

// boundaryPubkeysCommitmentHex builds the boundary witness (which also enforces the op-6 gindex-87 anchor,
// witness.go:124) and returns its pubkeys_commitment — the public the on-chain verify_boundary checks.
func boundaryPubkeysCommitmentHex(t *testing.T, input *bootstrap.Bootstrap) string {
	t.Helper()
	assignment, err := witness.BuildBoundary(input, 512)
	if err != nil {
		t.Fatalf("BuildBoundary(512): %v", err)
	}
	value, ok := assignment.PubkeysCommitment.(interface{ Text(int) string })
	if !ok {
		t.Fatalf("unexpected PubkeysCommitment type %T", assignment.PubkeysCommitment)
	}
	return fmt.Sprintf("%064s", value.Text(16))
}

// referenceAggregate independently sums input.CurrentCommittee over the bits → 96 B X||Y hex — the same
// point BuildBLSFields and BuildBoundary both produce, so equality proves apk == the proof's apk.
func referenceAggregate(t *testing.T, input *bootstrap.Bootstrap) string {
	t.Helper()
	keys, err := bootstrap.DecompressCommittee(input.CurrentCommittee.Pubkeys)
	if err != nil {
		t.Fatalf("decompress: %v", err)
	}
	var jacobian bls12381.G1Jac
	for i := range keys {
		if i < len(input.ParticipationBits) && input.ParticipationBits[i] {
			var key bls12381.G1Jac
			key.FromAffine(&keys[i])
			jacobian.AddAssign(&key)
		}
	}
	var apk bls12381.G1Affine
	apk.FromJacobian(&jacobian)
	raw := apk.RawBytes()
	return hex.EncodeToString(raw[:])
}

// TestBoundaryRotation_OverrideAlignsWitnessBLSAndCommitment is the Tier-2 gate: on the real 1788->1789
// rotation, the buildWitness override routes the SIGNER (C_1789) into the apk-source so the proof's
// pubkeys_commitment, the BLS apk, and the on-chain datum.next all agree on C_1789.
func TestBoundaryRotation_OverrideAlignsWitnessBLSAndCommitment(t *testing.T) {
	input, _, err := bootstrap.LoadFromFixtures(rotationBetaPlaceholder, rotation1789Update)
	if err != nil {
		t.Fatalf("load boundary input: %v", err)
	}
	signerC1789 := nextCommitteeHexes(t, rotation1788Update) // C_1789 = update@1788's next

	// load-bearing sanity: the loaded CurrentCommittee is the β PLACEHOLDER, NOT the signer — so its
	// commitment is not datum.next. (Exactly what the 1600 Tier-1 fixture could not show.) The override
	// below is what fixes it; with applySigningCommittee stubbed, assertion (1) fails on this same line.
	if loaded := boundaryPubkeysCommitmentHex(t, input); loaded == rotationDatumNext {
		t.Fatalf("loaded CurrentCommittee already commits to datum.next %s — fixture does not exercise the override", rotationDatumNext)
	}

	// THE FIX: route the boundary's signer (C_1789) into input.CurrentCommittee — the same call buildWitness makes.
	if err := applySigningCommittee(input, Boundary, nil, signerC1789); err != nil {
		t.Fatalf("applySigningCommittee: %v", err)
	}

	// (1) bridge.ak:90 — the proof's pubkeys_commitment must equal datum.next = commit(C_1789) = 0037525b...
	if got := boundaryPubkeysCommitmentHex(t, input); got != rotationDatumNext {
		t.Fatalf("pubkeys_commitment = %s, want datum.next %s (the on-chain verify_boundary target)", got, rotationDatumNext)
	}

	// (2) BuildBLSFields succeeds — the real σ@1789 verifies under Σ C_1789 — and its apk equals the
	// independent reference aggregate of C_1789 (= the proof's apk, both reading input.CurrentCommittee).
	fields, err := BuildBLSFields(input, Boundary)
	if err != nil {
		t.Fatalf("BuildBLSFields(Boundary) after override: %v", err)
	}
	if reference := referenceAggregate(t, input); fields.ApkUncompressed != reference {
		t.Fatalf("BLS apk %s != reference aggregate of C_1789 %s", fields.ApkUncompressed, reference)
	}
	t.Logf("Tier-2 GREEN: pubkeys_commitment == datum.next %s; σ@1789 verifies under Σ C_1789 (count %d); apk == proof's apk; op-6 anchor OK",
		rotationDatumNext, fields.Count)
}

// TestRotateSigningCommittee_PromotesNextThenAdvances is the Change-C rotation: after a boundary, the
// incoming next (C_1789) becomes the current signer and the boundary update's next (C_1790) becomes the
// new cached next — so the trailing period-1789 regulars verify under C_1789.
func TestRotateSigningCommittee_PromotesNextThenAdvances(t *testing.T) {
	signerC1789 := nextCommitteeHexes(t, rotation1788Update)
	newNextC1790 := nextCommitteeHexes(t, rotation1789Update)

	r := &LiveRelayer{
		currentSignerPubkeys: []string{"0xthe-rotated-out-current"}, // C_1788 stand-in (discarded by the rotation)
		cachedNextPubkeys:    signerC1789,                           // C_1789 — the incoming committee
		current:              &phaseBeacon{nextPubkeys: newNextC1790, nextAgg: "agg", nextBranch: []string{"branch"}},
	}
	r.rotateSigningCommittee()

	if !slices.Equal(r.currentSignerPubkeys, signerC1789) {
		t.Fatal("currentSignerPubkeys not promoted to C_1789 (the incoming next)")
	}
	if !slices.Equal(r.cachedNextPubkeys, newNextC1790) {
		t.Fatal("cachedNextPubkeys not advanced to C_1790 (the boundary update's next)")
	}
	// confirm the RIGHT committees moved (not just that the slices shifted).
	promotedKeys, err := compressedKeysFromHex(r.currentSignerPubkeys)
	if err != nil {
		t.Fatalf("promoted keys: %v", err)
	}
	advancedKeys, err := compressedKeysFromHex(r.cachedNextPubkeys)
	if err != nil {
		t.Fatalf("advanced keys: %v", err)
	}
	if got := commitmentHexOf(t, promotedKeys); got != rotationDatumNext {
		t.Fatalf("promoted current commits to %s, want C_1789 %s", got, rotationDatumNext)
	}
	if got := commitmentHexOf(t, advancedKeys); got != rotationNewNext {
		t.Fatalf("new cached next commits to %s, want C_1790 %s", got, rotationNewNext)
	}
	t.Logf("Change-C rotation GREEN: current <- C_1789 (%s…), next <- C_1790 (%s…)", rotationDatumNext[:12], rotationNewNext[:12])
}
