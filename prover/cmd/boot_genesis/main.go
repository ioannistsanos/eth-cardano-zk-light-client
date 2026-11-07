// Command boot_genesis runs the §2.1.6 gate on real beacon fixtures and emits the genesis datum
// VALUES (JSON) for the Boot/init transaction. It is the Go half of the Boot assembler: it enforces
// the abort semantics (no genesis datum without a passing gate) and records the eight-field
// provenance. It does NOT author the datum CBOR — Aiken is the source of truth for the datum bytes
// (validator/lib/zkbridge/genesis_datum_test.ak); the assembler embeds those bytes and re-checks the
// sha2_256 pin. The emitted values are the consistency cross-check against that Aiken datum.
//
// Run from the prover/ module root:
//
//	go run ./cmd/boot_genesis            # → ../validator/fixtures/genesis_values_period1600.json
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"eth-cardano-zk-light-client/prover/offchain/boot"
)

func main() {
	bootstrapFixture := flag.String("bootstrap-fixture", "offchain/bootstrap/testdata/electra_bootstrap_period_1600.json", "the LightClientBootstrap fixture")
	updateFixture := flag.String("update-fixture", "circuits/common/testdata/lightclientupdate/electra_period_1600.json", "the companion LightClientUpdate fixture")
	vkRegular := flag.String("vk-regular", "../validator/fixtures/groth16_regular_n8.json", "the regular verifying-key fixture (datum field 7)")
	vkBoundary := flag.String("vk-boundary", "../validator/fixtures/groth16_boundary_n8.json", "the boundary verifying-key fixture (datum field 8)")
	outPath := flag.String("out", "../boot/genesis_values_period1600.json", "genesis-values destination")
	flag.Parse()

	values, err := boot.BuildGenesisValues(*bootstrapFixture, *updateFixture, *vkRegular, *vkBoundary)
	if err != nil {
		fmt.Fprintf(os.Stderr, "HALT (§2.1.6 abort): %v\n", err)
		os.Exit(1)
	}

	encoded, err := json.MarshalIndent(values, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "HALT: marshal: %v\n", err)
		os.Exit(1)
	}
	if err := os.WriteFile(*outPath, append(encoded, '\n'), 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "HALT: write %s: %v\n", *outPath, err)
		os.Exit(1)
	}

	fmt.Printf("§2.1.6 gate PASSED — genesis values written to %s\n", *outPath)
	fmt.Printf("  finalized_header_root        = %s\n", values.FinalizedHeaderRoot)
	fmt.Printf("  finalized_slot               = %d\n", values.FinalizedSlot)
	fmt.Printf("  current_committee_commitment = %s\n", values.CurrentCommitteeCommitment)
	fmt.Printf("  next_committee_commitment    = %s\n", values.NextCommitteeCommitment)
	fmt.Printf("  fork_version                 = %s\n", values.ForkVersion)
	fmt.Printf("  genesis_validators_root      = %s\n", values.GenesisValidatorsRoot)
	fmt.Printf("  vk_regular / vk_boundary     = %s | %s\n", values.VerifyingKeyRegularFixture, values.VerifyingKeyBoundaryFixture)
	fmt.Printf("  (datum BYTES are Aiken-authored; sha2_256 pin checked at the assembler — REHEARSAL, toy vks)\n")
}
