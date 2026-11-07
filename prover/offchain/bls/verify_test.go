package bls

import (
	"path/filepath"
	"testing"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
)

// ── Gate 1: the BLS primitive, anchored to a real eth2 fast_aggregate_verify conformance pair ──
//
// consensus-spec-tests v1.5.0 bls/fast_aggregate_verify valid_/tampered_signature_3d7576f3c0e3570a
// (same pubkeys + message, signature differs). Validates the EXACT ciphersuite: DST, hash-to-G2,
// pairing, and G1-pubkey / G2-signature compressed serialization — a mismatch fails silently on
// real data, so an external conformance vector (not a self-signed round-trip) is required here.

func loadAndVerifyFAV(t *testing.T, caseDir string) (verdict, expected bool) {
	t.Helper()
	var vector struct {
		Input struct {
			Pubkeys   []string `yaml:"pubkeys"`
			Message   string   `yaml:"message"`
			Signature string   `yaml:"signature"`
		} `yaml:"input"`
		Output bool `yaml:"output"`
	}
	loadYAML(t, filepath.Join("testdata", "fast_aggregate_verify", caseDir, "data.yaml"), &vector)

	pubkeys := make([]bls12381.G1Affine, len(vector.Input.Pubkeys))
	for i, pk := range vector.Input.Pubkeys {
		pubkeys[i] = decodeG1(t, pk)
	}
	message := mustHex32(t, vector.Input.Message)
	signature, ok := decodeG2OK(t, vector.Input.Signature)
	if !ok {
		return false, vector.Output // malformed signature → does not verify
	}
	got, err := FastAggregateVerify(pubkeys, message, signature)
	if err != nil {
		return false, vector.Output
	}
	return got, vector.Output
}

func TestFastAggregateVerify_SpecVectorValid(t *testing.T) {
	verdict, expected := loadAndVerifyFAV(t, "valid")
	if !expected {
		t.Fatal("vector sanity: valid case must have output=true")
	}
	if verdict != expected {
		t.Fatalf("valid conformance vector: verdict=%v, want %v", verdict, expected)
	}
}

func TestFastAggregateVerify_SpecVectorTampered(t *testing.T) {
	verdict, expected := loadAndVerifyFAV(t, "tampered_signature")
	if expected {
		t.Fatal("vector sanity: tampered case must have output=false")
	}
	if verdict != expected {
		t.Fatalf("tampered conformance vector: verdict=%v, want %v", verdict, expected)
	}
}

// ── Gate 2 + Gate 3: self-signed round-trip + negatives over the full condition-(d) path ──

// syncCommitteeSigningRoot exercises the whole glue: compute_domain(DOMAIN_SYNC_COMMITTEE,
// fork_version, gvr) → compute_signing_root(object_root, domain) → the 32-byte signed message.
func syncCommitteeSigningRoot() [32]byte {
	var objectRoot, genesisValidatorsRoot [32]byte
	for i := range objectRoot {
		objectRoot[i] = byte(0xa0 + i)
	}
	for i := range genesisValidatorsRoot {
		genesisValidatorsRoot[i] = byte(i)
	}
	forkVersion := [4]byte{0x05, 0x00, 0x00, 0x00}
	domain := ComputeDomain(DomainSyncCommittee, forkVersion, genesisValidatorsRoot)
	return ComputeSigningRoot(objectRoot, domain)
}

// Gate 2: an honest aggregate over the full committee verifies — both the raw primitive and the
// VerifySyncAggregate entry point (count reported).
func TestVerifySyncAggregate_SelfSignedRoundTrip(t *testing.T) {
	const committeeSize = ParticipationThreshold + 1 // 343
	pubkeys, secrets := deterministicCommittee(committeeSize)
	message := syncCommitteeSigningRoot()
	bits := allTrue(committeeSize)
	signature := aggregateSign(t, secrets, bits, message)

	if ok, err := FastAggregateVerify(pubkeys, message, signature); err != nil || !ok {
		t.Fatalf("FastAggregateVerify round-trip: ok=%v err=%v", ok, err)
	}
	verified, count, err := VerifySyncAggregate(pubkeys, bits, message, signature)
	if err != nil {
		t.Fatalf("VerifySyncAggregate err: %v", err)
	}
	if !verified || count != committeeSize {
		t.Fatalf("VerifySyncAggregate: verified=%v count=%d (want true, %d)", verified, count, committeeSize)
	}
}

// Gate 3a: a tampered aggregate signature (valid G2 point, wrong value) is rejected.
func TestVerifySyncAggregate_TamperedSignatureRejected(t *testing.T) {
	const committeeSize = ParticipationThreshold + 1
	pubkeys, secrets := deterministicCommittee(committeeSize)
	message := syncCommitteeSigningRoot()
	bits := allTrue(committeeSize)
	signature := aggregateSign(t, secrets, bits, message)

	// tamper: σ' = σ + G2 generator (still a valid point, wrong signature)
	_, _, _, g2Generator := bls12381.Generators()
	var signatureJacobian, generatorJacobian bls12381.G2Jac
	signatureJacobian.FromAffine(&signature)
	generatorJacobian.FromAffine(&g2Generator)
	signatureJacobian.AddAssign(&generatorJacobian)
	var tampered bls12381.G2Affine
	tampered.FromJacobian(&signatureJacobian)

	verified, _, err := VerifySyncAggregate(pubkeys, bits, message, tampered)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if verified {
		t.Fatal("tampered signature ACCEPTED")
	}
}

// Gate 3b: participation below the 2/3 threshold is rejected even with a valid signature over
// the participants — the count gate fires before/independent of the pairing.
func TestVerifySyncAggregate_BelowThresholdRejected(t *testing.T) {
	const committeeSize = ParticipationThreshold + 1
	pubkeys, secrets := deterministicCommittee(committeeSize)
	message := syncCommitteeSigningRoot()
	bits := make([]bool, committeeSize)
	for i := 0; i < ParticipationThreshold-1; i++ { // 341 < 342
		bits[i] = true
	}
	signature := aggregateSign(t, secrets, bits, message)

	verified, count, err := VerifySyncAggregate(pubkeys, bits, message, signature)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if count != ParticipationThreshold-1 {
		t.Fatalf("count=%d, want %d", count, ParticipationThreshold-1)
	}
	if verified {
		t.Fatalf("below-threshold participation (%d < %d) ACCEPTED", count, ParticipationThreshold)
	}
}

// Gate 3 boundary: exactly 342 participants (count == threshold) is accepted — confirms the
// gate is ≥, not >.
func TestVerifySyncAggregate_AtThresholdAccepted(t *testing.T) {
	const committeeSize = ParticipationThreshold + 1
	pubkeys, secrets := deterministicCommittee(committeeSize)
	message := syncCommitteeSigningRoot()
	bits := make([]bool, committeeSize)
	for i := 0; i < ParticipationThreshold; i++ { // exactly 342
		bits[i] = true
	}
	signature := aggregateSign(t, secrets, bits, message)

	verified, count, err := VerifySyncAggregate(pubkeys, bits, message, signature)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !verified || count != ParticipationThreshold {
		t.Fatalf("at-threshold: verified=%v count=%d (want true, %d)", verified, count, ParticipationThreshold)
	}
}
