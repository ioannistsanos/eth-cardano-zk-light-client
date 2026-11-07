// Command vk_to_json reads a gnark .vk binary (the public verifying key from groth16_setup) and
// emits the vk-only hex-in-JSON fixture (the form the Boot genesis datum embeds) + asserts the
// commitment-augmented shape. The existing export_{fixture,boundary_fixture} do an in-memory n=8
// setup and CANNOT read a real .vk file; this reads the scp'd n=512 .vk via vk.ReadFrom.
// Public artifact only (the vk is safe; the pk/τ never leave the setup VM).
//
//	go run ./cmd/vk_to_json -vk <path>/vk_regular_n512.vk  -circuit regular  -ic 13 > groth16_regular_n512.json
//	go run ./cmd/vk_to_json -vk <path>/vk_boundary_n512.vk -circuit boundary -ic 14 > groth16_boundary_n512.json
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
)

type vkFixture struct {
	N            int       `json:"n"`
	Circuit      string    `json:"circuit"`
	Note         string    `json:"note"`
	VerifyingKey fixtureVk `json:"vk"`
}

type fixtureVk struct {
	Alpha               string   `json:"alpha"`
	Beta                string   `json:"beta"`
	Gamma               string   `json:"gamma"`
	Delta               string   `json:"delta"`
	Ic                  []string `json:"ic"`
	CommitmentG         string   `json:"commitment_g"`
	CommitmentGSigmaNeg string   `json:"commitment_g_sigma_neg"`
}

func main() {
	vkPath := flag.String("vk", "", "path to the gnark .vk binary (required)")
	circuit := flag.String("circuit", "", "regular | boundary (required)")
	expectIc := flag.Int("ic", 0, "expected ic length: 13 regular / 14 boundary (required)")
	flag.Parse()
	if *vkPath == "" || *circuit == "" || *expectIc == 0 {
		halt("-vk, -circuit, -ic are required")
	}

	file, err := os.Open(*vkPath)
	if err != nil {
		halt("open vk: %v", err)
	}
	defer file.Close()

	verifyingKey := groth16.NewVerifyingKey(ecc.BLS12_381)
	if _, err := verifyingKey.ReadFrom(file); err != nil {
		halt("read vk: %v", err)
	}
	concrete, ok := verifyingKey.(*groth16bls.VerifyingKey)
	if !ok {
		halt("vk is not the BLS12-381 concrete type")
	}

	// D19 shape asserts: exactly one Pedersen commitment key, ic length ℓ+2.
	if len(concrete.CommitmentKeys) != 1 {
		halt("expected exactly 1 commitment key (D19), got %d", len(concrete.CommitmentKeys))
	}
	if len(concrete.G1.K) != *expectIc {
		halt("expected ic length %d (ℓ+2), got %d — shape DIVERGENCE from the toy vk", *expectIc, len(concrete.G1.K))
	}

	icHex := make([]string, len(concrete.G1.K))
	for i := range concrete.G1.K {
		icHex[i] = compressedG1Hex(concrete.G1.K[i])
	}

	output := vkFixture{
		N:       512,
		Circuit: *circuit,
		Note:    "REAL n=512 demonstrator-setup verifying key (single-party groth16.Setup; pk/τ destroyed on the VM). PUBLIC, vk-only (no proof). Shape is N-independent — identical to the toy n=8 vk: alpha + ic G1 + 5 G2, one Pedersen commitment key (D19).",
		VerifyingKey: fixtureVk{
			Alpha:               compressedG1Hex(concrete.G1.Alpha),
			Beta:                compressedG2Hex(concrete.G2.Beta),
			Gamma:               compressedG2Hex(concrete.G2.Gamma),
			Delta:               compressedG2Hex(concrete.G2.Delta),
			Ic:                  icHex,
			CommitmentG:         compressedG2Hex(concrete.CommitmentKeys[0].G),
			CommitmentGSigmaNeg: compressedG2Hex(concrete.CommitmentKeys[0].GSigmaNeg),
		},
	}
	encoded, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		halt("marshal: %v", err)
	}
	os.Stdout.Write(append(encoded, '\n'))
	fmt.Fprintf(os.Stderr, "SHAPE OK: %d G1 (alpha + %d ic) + 5 G2 (beta,gamma,delta,commitment_g,commitment_g_sigma_neg) + %d commitment key\n",
		1+len(icHex), len(icHex), len(concrete.CommitmentKeys))
}

func compressedG1Hex(point bls12381.G1Affine) string {
	encoded := point.Bytes()
	return hex.EncodeToString(encoded[:])
}

func compressedG2Hex(point bls12381.G2Affine) string {
	encoded := point.Bytes()
	return hex.EncodeToString(encoded[:])
}

func halt(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "HALT: "+format+"\n", args...)
	os.Exit(1)
}
