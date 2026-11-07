// Command export_bls_fixture produces the REAL period-1600 sync-committee aggregate-signature
// fixture for Phase-3 Layer 3 (the on-chain BLS verifier). The bootstrap fixture already carries
// the real signature + participation bits + fork_version + gvr + attested header; this loads them,
// aggregates the participating committee keys into the real apk (~510 participants), computes the
// golden domain + signing_root via offchain/bls, and writes them as hex-in-JSON.
//
// PUBLIC data only (a signature + an aggregate pubkey + anchors); no secrets. All local, no prove —
// the real σ already exists. The producer HALTs unless the real σ verifies off-chain under the real
// apk and count >= the 2/3 threshold (so the fixture is a valid, threshold-meeting instance).
// Run from the prover/ module root:
//
//	go run ./cmd/export_bls_fixture   # writes ../validator/fixtures/bls_regular_period1600.json
package main

import (
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"

	"eth-cardano-zk-light-client/prover/offchain/bls"
	"eth-cardano-zk-light-client/prover/offchain/bootstrap"
)

type blsFixture struct {
	Circuit               string `json:"circuit"`
	Period                int    `json:"period"`
	Note                  string `json:"note"`
	Signature             string `json:"signature"`               // 96 B compressed G2 (sync_aggregate)
	ApkUncompressed       string `json:"apk_uncompressed"`        // 96 B X‖Y — the ~510-participant aggregate
	ForkVersion           string `json:"fork_version"`            // 4 B (datum anchor)
	GenesisValidatorsRoot string `json:"genesis_validators_root"` // 32 B (datum anchor)
	AttestedHeaderRoot    string `json:"attested_header_root"`    // 32 B (redeemer transient)
	Count                 int    `json:"count"`
	ExpectedDomain        string `json:"expected_domain"`       // 32 B golden (pre-pairing cross-check)
	ExpectedSigningRoot   string `json:"expected_signing_root"` // 32 B golden (pre-pairing cross-check)
}

func main() {
	bootstrapFixture := flag.String("bootstrap-fixture", "offchain/bootstrap/testdata/electra_bootstrap_period_1600.json", "the LightClientBootstrap fixture (β)")
	updateFixture := flag.String("update-fixture", "circuits/common/testdata/lightclientupdate/electra_period_1600.json", "the LightClientUpdate fixture (α)")
	outPath := flag.String("out", "../validator/fixtures/bls_regular_period1600.json", "fixture destination")
	flag.Parse()

	input, signatureSlot, err := bootstrap.LoadFromFixtures(*bootstrapFixture, *updateFixture)
	if err != nil {
		halt("load fixtures: %v", err)
	}

	// decompress the full 512 current committee; aggregate the bits-selected participants → the apk.
	currentKeys, err := bootstrap.DecompressCommittee(input.CurrentCommittee.Pubkeys)
	if err != nil {
		halt("decompress current committee: %v", err)
	}
	var aggregateJacobian bls12381.G1Jac
	participants := make([]bls12381.G1Affine, 0, len(currentKeys))
	for i := range currentKeys {
		if i < len(input.ParticipationBits) && input.ParticipationBits[i] {
			var keyJacobian bls12381.G1Jac
			keyJacobian.FromAffine(&currentKeys[i])
			aggregateJacobian.AddAssign(&keyJacobian)
			participants = append(participants, currentKeys[i])
		}
	}
	var aggregatePublicKey bls12381.G1Affine
	aggregatePublicKey.FromJacobian(&aggregateJacobian)
	count := len(participants)

	attestedHeaderRoot := input.AttestedHeader.HashTreeRoot()
	domain := bls.ComputeDomain(bls.DomainSyncCommittee, input.ForkVersion, input.GenesisValidatorsRoot)
	signingRoot := bls.ComputeSigningRoot(attestedHeaderRoot, domain)

	// sanity: the real σ MUST verify off-chain under the real apk, and meet the threshold.
	var signature bls12381.G2Affine
	if _, err := signature.SetBytes(input.Signature[:]); err != nil {
		halt("signature decode: %v", err)
	}
	verified, err := bls.FastAggregateVerify(participants, signingRoot, signature)
	if err != nil {
		halt("FastAggregateVerify: %v", err)
	}
	if !verified {
		halt("the real σ does NOT verify off-chain under the real apk — fixture invalid")
	}
	if count < bls.ParticipationThreshold {
		halt("participation count %d < threshold %d", count, bls.ParticipationThreshold)
	}

	apkUncompressed := aggregatePublicKey.RawBytes() // 96 B clean X‖Y

	output := blsFixture{
		Circuit:               "regular",
		Period:                int(signatureSlot / 8192),
		Note:                  "REAL period-1600 Ethereum sync-committee aggregate-signature instance (~510 participants). PUBLIC data; verifies off-chain via bls.FastAggregateVerify. The Layer-3 all-real positive. Different instance from the toy Groth16 fixture (8-key apk, count 8) — see §5 consistency tension.",
		Signature:             hex.EncodeToString(input.Signature[:]),
		ApkUncompressed:       hex.EncodeToString(apkUncompressed[:]),
		ForkVersion:           hex.EncodeToString(input.ForkVersion[:]),
		GenesisValidatorsRoot: hex.EncodeToString(input.GenesisValidatorsRoot[:]),
		AttestedHeaderRoot:    hex.EncodeToString(attestedHeaderRoot[:]),
		Count:                 count,
		ExpectedDomain:        hex.EncodeToString(domain[:]),
		ExpectedSigningRoot:   hex.EncodeToString(signingRoot[:]),
	}

	encoded, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		halt("marshal: %v", err)
	}
	if err := os.WriteFile(*outPath, append(encoded, '\n'), 0o644); err != nil {
		halt("write %s: %v", *outPath, err)
	}

	fmt.Printf("wrote %s\n", *outPath)
	fmt.Printf("  period = %d, participation count = %d (>= %d ✓)\n", output.Period, count, bls.ParticipationThreshold)
	fmt.Printf("  fork_version = %s\n", output.ForkVersion)
	fmt.Printf("  the REAL period-1600 σ verifies off-chain under the real apk ✓\n")
}

func halt(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "HALT: "+format+"\n", args...)
	os.Exit(1)
}
