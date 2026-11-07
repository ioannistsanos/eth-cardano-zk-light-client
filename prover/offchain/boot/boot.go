// Package boot is the off-chain Boot/init genesis assembler's Go half (§2.1.6). It runs the
// §2.1.6 gate (bootstrap.Verify — the five pre-conditions transitively + the five cryptographic
// conditions (a)-(e), HALT-on-first-failure = the thesis's abort semantics) on real beacon data and
// emits the genesis DATUM VALUES: the four gate-derived fields (committee commitments + finalized
// header root/slot) taken ONLY from the gate's Result, plus the two pre-condition anchors
// (fork_version, genesis_validators_root) and references to the two verifying-key fixtures.
//
// It does NOT author the datum CBOR — Aiken is the source of truth for the datum bytes
// (validator/lib/zkbridge/genesis_datum_test.ak: cbor.serialise of the constructed Datum, pinned by
// sha2_256). This package produces the VALUES (for provenance + the consistency cross-check against
// that Aiken datum); the assembler embeds the Aiken-authored bytes and re-checks the sha2_256 pin.
//
// Discipline: fields 1-4 come ONLY from bootstrap.Verify's Result (never fabricated); any gate
// failure returns the per-condition sentinel and no values — there is no genesis datum without a
// passing gate.
package boot

import (
	"encoding/hex"
	"fmt"

	"eth-cardano-zk-light-client/prover/offchain/bootstrap"
)

// GenesisValues is the eight-field genesis datum's provenance record: the six scalar field values
// (hex / int) plus the two verifying-key fixture paths. The committee commitments + finalized
// header root/slot are the gate output; fork_version + genesis_validators_root are the pre-condition
// anchors (cross-checked by gate condition (d) — a wrong value fails the real BLS verify).
type GenesisValues struct {
	// gate-derived (bootstrap.Verify Result) — datum fields 1-4
	FinalizedHeaderRoot        string `json:"finalized_header_root"`        // 32 B hex
	FinalizedSlot              uint64 `json:"finalized_slot"`               // uint64
	CurrentCommitteeCommitment string `json:"current_committee_commitment"` // 32 B Poseidon hex
	NextCommitteeCommitment    string `json:"next_committee_commitment"`    // 32 B Poseidon hex
	// pre-condition anchors — datum fields 5-6
	ForkVersion           string `json:"fork_version"`            // 4 B hex
	GenesisValidatorsRoot string `json:"genesis_validators_root"` // 32 B hex
	// the verifying keys — datum fields 7-8 (referenced by fixture path; the bytes live there + in
	// the Aiken datum). The toy n=8 vks make this the REHEARSAL genesis (frozen-anchor dead-end).
	VerifyingKeyRegularFixture  string `json:"verifying_key_regular_fixture"`
	VerifyingKeyBoundaryFixture string `json:"verifying_key_boundary_fixture"`
}

// BuildGenesisValues runs the §2.1.6 gate on the given bootstrap + update fixtures and assembles the
// genesis datum values. It returns the per-condition sentinel from bootstrap.Verify on any gate
// failure (the abort semantics) and the values only on full success. The vk fixture paths are
// recorded verbatim (the bytes are not re-read here — the Aiken datum embeds them).
func BuildGenesisValues(bootstrapFixturePath, updateFixturePath, vkRegularFixture, vkBoundaryFixture string) (*GenesisValues, error) {
	input, _, err := bootstrap.LoadFromFixtures(bootstrapFixturePath, updateFixturePath)
	if err != nil {
		return nil, fmt.Errorf("load bootstrap fixtures: %w", err)
	}

	// THE GATE (§2.1.6 conditions (a)-(e), abort-on-first-failure). No datum without it.
	result, err := bootstrap.Verify(input)
	if err != nil {
		return nil, fmt.Errorf("§2.1.6 gate rejected the bootstrap (abort): %w", err)
	}

	// fields 1-4 ONLY from the gate Result (never fabricated).
	currentCommitment := result.CurrentPubkeysCommitment.Bytes()
	nextCommitment := result.NextPubkeysCommitment.Bytes()

	return &GenesisValues{
		FinalizedHeaderRoot:        hex.EncodeToString(result.FinalizedHeaderRoot[:]),
		FinalizedSlot:              result.FinalizedSlot,
		CurrentCommitteeCommitment: hex.EncodeToString(currentCommitment[:]),
		NextCommitteeCommitment:    hex.EncodeToString(nextCommitment[:]),
		// fields 5-6: the pre-condition anchors (the same fork/gvr the gate fed to condition (d)).
		ForkVersion:           hex.EncodeToString(input.ForkVersion[:]),
		GenesisValidatorsRoot: hex.EncodeToString(input.GenesisValidatorsRoot[:]),
		// fields 7-8: the verifying keys, by fixture reference.
		VerifyingKeyRegularFixture:  vkRegularFixture,
		VerifyingKeyBoundaryFixture: vkBoundaryFixture,
	}, nil
}
