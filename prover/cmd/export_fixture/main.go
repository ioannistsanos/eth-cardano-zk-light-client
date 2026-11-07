// Command export_fixture produces the TOY (n=8) regular Groth16 fixture that Phase-3 Layer 2
// (the Aiken on-chain verifier) tests the #9 serialization seam against. It is the OFF-CHAIN
// half of #9: it extracts the individual compressed points from the gnark vk/proof via
// gnark-crypto's .Bytes() (the ZCash/eth2 compressed encoding CIP-381's uncompress expects)
// and the apk's uncompressed X‖Y via .RawBytes(), and writes them as hex-in-JSON.
//
// The n=8 vk is FORMAT-IDENTICAL to the real n=512 (12 IC for the ℓ=11 regular public layout,
// 3-point proof — both committee-size-independent), so a toy proof that verifies on-chain pins
// every byte convention; the real n=512 is later a value swap into the same format.
//
// This is a TOY artifact: the setup is single-party and its proving key is ephemeral (in-memory,
// never written), so there is no toxic-waste concern — only the PUBLIC vk + proof + public
// inputs are emitted. Run from the prover/ module root:
//
//	go run ./cmd/export_fixture            # writes ../validator/fixtures/groth16_regular_n8.json
package main

import (
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/consensys/gnark-crypto/ecc"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark/backend/groth16"
	groth16bls "github.com/consensys/gnark/backend/groth16/bls12-381"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"

	"eth-cardano-zk-light-client/prover/circuits/common"
	"eth-cardano-zk-light-client/prover/offchain/bootstrap"
	"eth-cardano-zk-light-client/prover/offchain/commitment"
	"eth-cardano-zk-light-client/prover/offchain/witness"
)

type fixtureFile struct {
	N               int           `json:"n"`
	Circuit         string        `json:"circuit"`
	Note            string        `json:"note"`
	VerifyingKey    fixtureVk     `json:"vk"`
	Proof           fixtureProof  `json:"proof"`
	Inputs          fixtureInputs `json:"inputs"`
	ExpectedPublics []string      `json:"expected_publics"`
	// the gnark-golden BSB22 commitment hash (the 12th public input, derived on-chain) — the
	// precise-locus cross-check for the on-chain expand_message_xmd-SHA256 hash-to-field (D19).
	ExpectedBsb22Hash string `json:"expected_bsb22_hash"`
}

type fixtureVk struct {
	Alpha string   `json:"alpha"` // G1 compressed, 48 B
	Beta  string   `json:"beta"`  // G2 compressed, 96 B
	Gamma string   `json:"gamma"` // G2 compressed, 96 B
	Delta string   `json:"delta"` // G2 compressed, 96 B
	Ic    []string `json:"ic"`    // G1 compressed × (ℓ+2) = 13 for regular (incl. the commitment IC)
	// the Pedersen commitment key (D19): vk.CommitmentKeys[0] = {G, GSigmaNeg}, both G2
	CommitmentG         string `json:"commitment_g"`           // G2 compressed, 96 B
	CommitmentGSigmaNeg string `json:"commitment_g_sigma_neg"` // G2 compressed, 96 B
}

type fixtureProof struct {
	A string `json:"a"` // G1 compressed, 48 B
	B string `json:"b"` // G2 compressed, 96 B
	C string `json:"c"` // G1 compressed, 48 B (Krs)
	// the commitment + its PoK (D19). The commitment is UNCOMPRESSED 96 B because gnark hashes
	// Commitments[0].Marshal() (96 B) for the BSB22 12th-public-input; the validator hashes the
	// SAME bytes and reconstructs the point. CommitmentPok is compressed (point only).
	Commitment    string `json:"commitment"`     // G1 UNCOMPRESSED, 96 B (RawBytes / Marshal)
	CommitmentPok string `json:"commitment_pok"` // G1 compressed, 48 B
}

type fixtureInputs struct {
	CurrentCommitteeCommitment string `json:"current_committee_commitment"` // 32 B (Poseidon, n=8)
	ApkUncompressed            string `json:"apk_uncompressed"`             // 96 B clean X‖Y (RawBytes)
	Count                      int    `json:"count"`
	AttestedHeaderRoot         string `json:"attested_header_root"`  // 32 B
	FinalizedHeaderRoot        string `json:"finalized_header_root"` // 32 B
	FinalizedSlot              uint64 `json:"finalized_slot"`
}

func main() {
	bootstrapFixture := flag.String("bootstrap-fixture", "offchain/bootstrap/testdata/electra_bootstrap_period_1600.json", "the LightClientBootstrap fixture (β)")
	updateFixture := flag.String("update-fixture", "circuits/common/testdata/lightclientupdate/electra_period_1600.json", "the LightClientUpdate fixture (α)")
	numberOfKeys := flag.Int("n", 8, "committee size (toy; the vk shape is N-independent)")
	outPath := flag.String("out", "../validator/fixtures/groth16_regular_n8.json", "fixture destination")
	flag.Parse()

	input, _, err := bootstrap.LoadFromFixtures(*bootstrapFixture, *updateFixture)
	if err != nil {
		halt("load fixtures: %v", err)
	}

	assignment, err := witness.BuildRegular(input, *numberOfKeys)
	if err != nil {
		halt("build witness: %v", err)
	}

	scalarField := ecc.BLS12_381.ScalarField()
	constraintSystem, err := frontend.Compile(scalarField, r1cs.NewBuilder, common.NewRegularCircuit(*numberOfKeys))
	if err != nil {
		halt("compile: %v", err)
	}
	provingKey, verifyingKey, err := groth16.Setup(constraintSystem)
	if err != nil {
		halt("setup: %v", err)
	}
	_ = provingKey // ephemeral toxic waste — never persisted

	fullWitness, err := frontend.NewWitness(assignment, scalarField)
	if err != nil {
		halt("witness: %v", err)
	}
	publicWitness, err := fullWitness.Public()
	if err != nil {
		halt("public witness: %v", err)
	}
	proof, err := groth16.Prove(constraintSystem, provingKey, fullWitness)
	if err != nil {
		halt("prove: %v", err)
	}
	// the produced proof MUST verify off-chain before we export it as the on-chain fixture.
	if err := groth16.Verify(proof, verifyingKey, publicWitness); err != nil {
		halt("the produced proof does not verify off-chain: %v", err)
	}

	concreteVerifyingKey, ok := verifyingKey.(*groth16bls.VerifyingKey)
	if !ok {
		halt("verifying key is not the BLS12-381 concrete type")
	}
	concreteProof, ok := proof.(*groth16bls.Proof)
	if !ok {
		halt("proof is not the BLS12-381 concrete type")
	}

	// D19: assert the SINGLE-commitment shape the on-chain verifier is designed for.
	if len(concreteVerifyingKey.CommitmentKeys) != 1 {
		halt("expected exactly 1 commitment key (D19), got %d", len(concreteVerifyingKey.CommitmentKeys))
	}
	if len(concreteProof.Commitments) != 1 {
		halt("expected exactly 1 proof commitment (D19), got %d", len(concreteProof.Commitments))
	}

	icHex := make([]string, len(concreteVerifyingKey.G1.K))
	for i := range concreteVerifyingKey.G1.K {
		icHex[i] = compressedG1Hex(concreteVerifyingKey.G1.K[i])
	}

	// re-aggregate the participating committee keys (the SAME apk the circuit binds) for its
	// uncompressed X‖Y — the redeemer form the on-chain verifier folds into ApkPacked (§2).
	currentKeys, err := bootstrap.DecompressCommittee(input.CurrentCommittee.Pubkeys[:*numberOfKeys])
	if err != nil {
		halt("decompress current committee: %v", err)
	}
	var aggregateJacobian bls12381.G1Jac
	participationCount := 0
	for i := range currentKeys {
		if input.ParticipationBits[i] {
			var keyJacobian bls12381.G1Jac
			keyJacobian.FromAffine(&currentKeys[i])
			aggregateJacobian.AddAssign(&keyJacobian)
			participationCount++
		}
	}
	var aggregatePublicKey bls12381.G1Affine
	aggregatePublicKey.FromJacobian(&aggregateJacobian)
	apkUncompressed := aggregatePublicKey.RawBytes() // 96 B, clean X‖Y (mUncompressed mask = 0x00)

	// the gnark-golden BSB22 hash of the commitment = HashToField("bsb22-commitment",
	// Commitments[0].Marshal()) — exactly what gnark's Verify appends as the 12th public input.
	bsb22Elements, err := fr.Hash(concreteProof.Commitments[0].Marshal(), []byte("bsb22-commitment"), 1)
	if err != nil {
		halt("bsb22 hash: %v", err)
	}
	bsb22Bytes := bsb22Elements[0].Bytes()

	pubkeysCommitment := commitment.Commit(currentKeys) // the n=8 Poseidon commitment
	commitmentBytes := pubkeysCommitment.Bytes()
	attestedHeaderRoot := input.AttestedHeader.HashTreeRoot()
	finalizedHeaderRoot := input.FinalizedHeader.HashTreeRoot()

	publicVector, ok := publicWitness.Vector().(fr.Vector)
	if !ok {
		halt("unexpected public-vector type")
	}
	expectedPublics := make([]string, len(publicVector))
	for i := range publicVector {
		element := publicVector[i].Bytes() // 32 B big-endian
		expectedPublics[i] = hex.EncodeToString(element[:])
	}

	output := fixtureFile{
		N:       *numberOfKeys,
		Circuit: "regular",
		Note:    "TOY n=8 fixture for the Phase-3 Layer-2 #9 serialization seam; vk shape is N-independent (13 IC), so format-identical to real n=512. PUBLIC artifacts only (no proving key).",
		VerifyingKey: fixtureVk{
			Alpha:               compressedG1Hex(concreteVerifyingKey.G1.Alpha),
			Beta:                compressedG2Hex(concreteVerifyingKey.G2.Beta),
			Gamma:               compressedG2Hex(concreteVerifyingKey.G2.Gamma),
			Delta:               compressedG2Hex(concreteVerifyingKey.G2.Delta),
			Ic:                  icHex,
			CommitmentG:         compressedG2Hex(concreteVerifyingKey.CommitmentKeys[0].G),
			CommitmentGSigmaNeg: compressedG2Hex(concreteVerifyingKey.CommitmentKeys[0].GSigmaNeg),
		},
		Proof: fixtureProof{
			A:             compressedG1Hex(concreteProof.Ar),
			B:             compressedG2Hex(concreteProof.Bs),
			C:             compressedG1Hex(concreteProof.Krs),
			Commitment:    uncompressedG1Hex(concreteProof.Commitments[0]),
			CommitmentPok: compressedG1Hex(concreteProof.CommitmentPok),
		},
		Inputs: fixtureInputs{
			CurrentCommitteeCommitment: hex.EncodeToString(commitmentBytes[:]),
			ApkUncompressed:            hex.EncodeToString(apkUncompressed[:]),
			Count:                      participationCount,
			AttestedHeaderRoot:         hex.EncodeToString(attestedHeaderRoot[:]),
			FinalizedHeaderRoot:        hex.EncodeToString(finalizedHeaderRoot[:]),
			FinalizedSlot:              input.FinalizedHeader.Slot,
		},
		ExpectedPublics:   expectedPublics,
		ExpectedBsb22Hash: hex.EncodeToString(bsb22Bytes[:]),
	}

	encoded, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		halt("marshal: %v", err)
	}
	if err := os.WriteFile(*outPath, append(encoded, '\n'), 0o644); err != nil {
		halt("write %s: %v", *outPath, err)
	}

	fmt.Printf("wrote %s\n", *outPath)
	fmt.Printf("  vk ic count        = %d (expect 12 — ℓ=11 regular, N-independent)\n", len(icHex))
	fmt.Printf("  public inputs      = %d (expect 11)\n", len(expectedPublics))
	fmt.Printf("  participation count= %d, finalized_slot = %d\n", participationCount, input.FinalizedHeader.Slot)
	fmt.Printf("  commitment fields  = 1 commitment (96 B uncompressed) + pok (48 B) + key {g, g_sigma_neg} (D19)\n")
	fmt.Printf("  proof verifies off-chain ✓ (the fixture is a valid commitment-augmented proof)\n")
}

func compressedG1Hex(point bls12381.G1Affine) string {
	encoded := point.Bytes() // 48 B compressed, ZCash flags
	return hex.EncodeToString(encoded[:])
}

func uncompressedG1Hex(point bls12381.G1Affine) string {
	encoded := point.RawBytes() // 96 B uncompressed X‖Y (= Marshal); what gnark hashes
	return hex.EncodeToString(encoded[:])
}

func compressedG2Hex(point bls12381.G2Affine) string {
	encoded := point.Bytes() // 96 B compressed, c1‖c0, ZCash flags
	return hex.EncodeToString(encoded[:])
}

func halt(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "HALT: "+format+"\n", args...)
	os.Exit(1)
}
