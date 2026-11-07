// Command export_boundary_fixture produces the TOY (n=8) BOUNDARY Groth16 verifying-key fixture
// that Phase-3's Boot/init genesis datum embeds as datum.verifying_key_boundary. It is the boundary
// twin of cmd/export_fixture (which produces the regular vk + a toy proof): it extracts the
// individual compressed vk points via gnark-crypto's .Bytes() (the ZCash/eth2 compressed encoding
// CIP-381's uncompress expects) and writes them as hex-in-JSON.
//
// VK-ONLY, by necessity. Unlike the regular fixture, this one carries NO proof and NO public inputs:
// witness.BuildBoundary is full-size-only — the real gindex-87 next-committee branch can only reach
// the real attested state_root with the full 512-key next committee, so there is no n=8 boundary
// WITNESS and hence no n=8 boundary proof (a real boundary proof is AWS-gated). The vk, however,
// needs no witness: NewBoundaryCircuit(8) compiles and groth16.Setup yields a valid vk whose SHAPE
// (15 G1 + 5 G2, ic = ℓ+2 = 14 for the ℓ=12 boundary public layout) is N-INDEPENDENT — every public
// is a fixed-size Fr, none scales with the committee size — so the n=8 boundary vk is FORMAT-IDENTICAL
// to the real n=512, exactly as the regular toy vk is. The real n=512 vk is later a value swap into
// the same format (the production Boot, post-AWS). The off-chain "proof verifies" gate the regular
// exporter runs is replaced here by structural shape assertions (ic == 14, exactly 1 commitment key
// — the D19 commitment-augmented shape); the vk's soundness for REAL proofs is validated at AWS-gated
// boundary proving, not here.
//
// TOY artifact: single-party setup, proving key ephemeral (in-memory, never written) — no toxic-waste
// concern, only the PUBLIC vk is emitted. Resource note: the n=8 boundary setup holds ~1.85 GB of
// proving key in memory transiently (discarded immediately); it takes some seconds. Run from the
// prover/ module root:
//
//	go run ./cmd/export_boundary_fixture   # writes ../validator/fixtures/groth16_boundary_n8.json
package main

import (
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/consensys/gnark-crypto/ecc"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark/backend/groth16"
	groth16bls "github.com/consensys/gnark/backend/groth16/bls12-381"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"

	"eth-cardano-zk-light-client/prover/circuits/common"
)

// boundaryFixtureFile is the VK-only shape — no proof/inputs (see the package doc for why).
type boundaryFixtureFile struct {
	N            int       `json:"n"`
	Circuit      string    `json:"circuit"`
	Note         string    `json:"note"`
	VerifyingKey fixtureVk `json:"vk"`
}

type fixtureVk struct {
	Alpha string   `json:"alpha"` // G1 compressed, 48 B
	Beta  string   `json:"beta"`  // G2 compressed, 96 B
	Gamma string   `json:"gamma"` // G2 compressed, 96 B
	Delta string   `json:"delta"` // G2 compressed, 96 B
	Ic    []string `json:"ic"`    // G1 compressed × (ℓ+2) = 14 for boundary (incl. the commitment IC)
	// the Pedersen commitment key (D19): vk.CommitmentKeys[0] = {G, GSigmaNeg}, both G2
	CommitmentG         string `json:"commitment_g"`           // G2 compressed, 96 B
	CommitmentGSigmaNeg string `json:"commitment_g_sigma_neg"` // G2 compressed, 96 B
}

func main() {
	numberOfKeys := flag.Int("n", 8, "committee size (toy; the vk shape is N-independent)")
	outPath := flag.String("out", "../validator/fixtures/groth16_boundary_n8.json", "fixture destination")
	flag.Parse()

	scalarField := ecc.BLS12_381.ScalarField()
	constraintSystem, err := frontend.Compile(scalarField, r1cs.NewBuilder, common.NewBoundaryCircuit(*numberOfKeys))
	if err != nil {
		halt("compile boundary circuit: %v", err)
	}
	provingKey, verifyingKey, err := groth16.Setup(constraintSystem)
	if err != nil {
		halt("setup: %v", err)
	}
	_ = provingKey // ephemeral toxic waste — never persisted (~1.85 GB held transiently, then discarded)

	concreteVerifyingKey, ok := verifyingKey.(*groth16bls.VerifyingKey)
	if !ok {
		halt("verifying key is not the BLS12-381 concrete type")
	}

	// D19: assert the SINGLE-commitment shape the on-chain verifier is designed for.
	if len(concreteVerifyingKey.CommitmentKeys) != 1 {
		halt("expected exactly 1 commitment key (D19), got %d", len(concreteVerifyingKey.CommitmentKeys))
	}
	// boundary public layout is ℓ=12 (regular 11 + NextPubkeysCommitment) ⇒ ic = ℓ+2 = 14.
	if len(concreteVerifyingKey.G1.K) != 14 {
		halt("expected ic length 14 (ℓ=12 boundary + 2), got %d — the boundary vk is not format-identical", len(concreteVerifyingKey.G1.K))
	}

	icHex := make([]string, len(concreteVerifyingKey.G1.K))
	for i := range concreteVerifyingKey.G1.K {
		icHex[i] = compressedG1Hex(concreteVerifyingKey.G1.K[i])
	}

	output := boundaryFixtureFile{
		N:       *numberOfKeys,
		Circuit: "boundary",
		Note:    "TOY n=8 BOUNDARY vk for the Phase-3 Boot genesis datum (datum.verifying_key_boundary). VK-ONLY: no n=8 boundary witness exists (BuildBoundary is full-size-only), so no proof — the vk SHAPE (15 G1 + 5 G2, ic=14) is N-independent, hence format-identical to real n=512. PUBLIC artifact only (no proving key).",
		VerifyingKey: fixtureVk{
			Alpha:               compressedG1Hex(concreteVerifyingKey.G1.Alpha),
			Beta:                compressedG2Hex(concreteVerifyingKey.G2.Beta),
			Gamma:               compressedG2Hex(concreteVerifyingKey.G2.Gamma),
			Delta:               compressedG2Hex(concreteVerifyingKey.G2.Delta),
			Ic:                  icHex,
			CommitmentG:         compressedG2Hex(concreteVerifyingKey.CommitmentKeys[0].G),
			CommitmentGSigmaNeg: compressedG2Hex(concreteVerifyingKey.CommitmentKeys[0].GSigmaNeg),
		},
	}

	encoded, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		halt("marshal: %v", err)
	}
	if err := os.WriteFile(*outPath, append(encoded, '\n'), 0o644); err != nil {
		halt("write %s: %v", *outPath, err)
	}

	fmt.Printf("wrote %s\n", *outPath)
	fmt.Printf("  vk ic count   = %d (expect 14 — ℓ=12 boundary, N-independent)\n", len(icHex))
	fmt.Printf("  vk G1 total   = %d (alpha + %d ic; expect 15)\n", 1+len(icHex), len(icHex))
	fmt.Printf("  vk G2 total   = 5 (beta, gamma, delta, commitment_g, commitment_g_sigma_neg)\n")
	fmt.Printf("  commitment key= 1 (D19 commitment-augmented shape) — VK-ONLY (no n=8 boundary proof; AWS-gated)\n")
}

func compressedG1Hex(point bls12381.G1Affine) string {
	encoded := point.Bytes() // 48 B compressed, ZCash flags
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
