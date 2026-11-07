package bls

import (
	"bytes"
	"path/filepath"
	"testing"
)

// ── Gate 1b: the signing_root construction, anchored to real eth2 SSZ conformance vectors ──
//
// consensus-spec-tests v1.5.0 ssz_static/{ForkData,SigningData} (ssz_random case_0). These pin
// the two SHA-256 SSZ container roots that compose compute_signing_root, isolated in C (NOT
// left only for D's deferred real positive) — a wrong field order / padding / concatenation
// here would fail silently on real Ethereum signatures.

// TestComputeForkDataRoot_SpecVector: ComputeForkDataRoot reproduces the ssz_static/ForkData
// hash_tree_root — the core of compute_domain.
func TestComputeForkDataRoot_SpecVector(t *testing.T) {
	var value struct {
		CurrentVersion        string `yaml:"current_version"`
		GenesisValidatorsRoot string `yaml:"genesis_validators_root"`
	}
	var roots struct {
		Root string `yaml:"root"`
	}
	loadYAML(t, filepath.Join("testdata", "ssz_static", "ForkData", "value.yaml"), &value)
	loadYAML(t, filepath.Join("testdata", "ssz_static", "ForkData", "roots.yaml"), &roots)

	got := ComputeForkDataRoot(mustHex4(t, value.CurrentVersion), mustHex32(t, value.GenesisValidatorsRoot))
	if want := mustHex32(t, roots.Root); got != want {
		t.Fatalf("fork_data_root mismatch:\n got  %x\n want %x", got, want)
	}
}

// TestComputeSigningRoot_SpecVector: ComputeSigningRoot reproduces the ssz_static/SigningData
// hash_tree_root over a real (object_root, domain) pair.
func TestComputeSigningRoot_SpecVector(t *testing.T) {
	var value struct {
		ObjectRoot string `yaml:"object_root"`
		Domain     string `yaml:"domain"`
	}
	var roots struct {
		Root string `yaml:"root"`
	}
	loadYAML(t, filepath.Join("testdata", "ssz_static", "SigningData", "value.yaml"), &value)
	loadYAML(t, filepath.Join("testdata", "ssz_static", "SigningData", "roots.yaml"), &roots)

	got := ComputeSigningRoot(mustHex32(t, value.ObjectRoot), mustHex32(t, value.Domain))
	if want := mustHex32(t, roots.Root); got != want {
		t.Fatalf("signing_root mismatch:\n got  %x\n want %x", got, want)
	}
}

// TestComputeDomain_Wiring: compute_domain = domain_type ‖ fork_data_root[0:28]. With
// ComputeForkDataRoot vector-anchored above, this confirms the 4-byte DOMAIN_SYNC_COMMITTEE
// prefix + the 28-byte truncation — so the whole compute_domain→compute_signing_root path is
// real-eth2-validated piece by piece.
func TestComputeDomain_Wiring(t *testing.T) {
	forkVersion := [4]byte{0x05, 0x00, 0x00, 0x00}
	var genesisValidatorsRoot [32]byte
	for i := range genesisValidatorsRoot {
		genesisValidatorsRoot[i] = byte(i)
	}
	domain := ComputeDomain(DomainSyncCommittee, forkVersion, genesisValidatorsRoot)
	forkDataRoot := ComputeForkDataRoot(forkVersion, genesisValidatorsRoot)

	if !bytes.Equal(domain[0:4], DomainSyncCommittee[:]) {
		t.Fatalf("domain[0:4] = %x, want DOMAIN_SYNC_COMMITTEE %x", domain[0:4], DomainSyncCommittee)
	}
	if !bytes.Equal(domain[4:32], forkDataRoot[0:28]) {
		t.Fatalf("domain[4:32] = %x, want fork_data_root[0:28] %x", domain[4:32], forkDataRoot[0:28])
	}
	if DomainSyncCommittee != [4]byte{0x07, 0x00, 0x00, 0x00} {
		t.Fatalf("DOMAIN_SYNC_COMMITTEE = %x, want 0x07000000", DomainSyncCommittee)
	}
}
