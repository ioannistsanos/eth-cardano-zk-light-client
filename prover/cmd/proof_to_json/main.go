// Command proof_to_json reads a gnark .proof binary (from groth16_prove) and emits the proof-only
// hex-in-JSON fixture (the form the on-chain redeemer carries) + asserts the commitment-augmented
// 5-element shape (D19). Public artifact only (the proof is safe; the pk/τ never leave the prove VM).
// Mirrors cmd/vk_to_json: the existing prove writes the gnark BINARY .proof; this reads it back via
// proof.ReadFrom and re-emits the compressed points as hex.
//
//	go run ./cmd/proof_to_json -proof <path>/proof_regular_n512.proof  -circuit regular  > proof_regular_n512.json
//	go run ./cmd/proof_to_json -proof <path>/proof_boundary_n512.proof -circuit boundary > proof_boundary_n512.json
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

type proofFixture struct {
	N       int          `json:"n"`
	Circuit string       `json:"circuit"`
	Note    string       `json:"note"`
	Proof   fixtureProof `json:"proof"`
}

type fixtureProof struct {
	Ar            string `json:"ar"`
	Bs            string `json:"bs"`
	Krs           string `json:"krs"`
	Commitment    string `json:"commitment"`
	CommitmentPok string `json:"commitment_pok"`
}

func main() {
	proofPath := flag.String("proof", "", "path to the gnark .proof binary (required)")
	circuit := flag.String("circuit", "", "regular | boundary (required)")
	flag.Parse()
	if *proofPath == "" || *circuit == "" {
		halt("-proof and -circuit are required")
	}

	file, err := os.Open(*proofPath)
	if err != nil {
		halt("open proof: %v", err)
	}
	defer file.Close()

	proof := groth16.NewProof(ecc.BLS12_381)
	if _, err := proof.ReadFrom(file); err != nil {
		halt("read proof: %v", err)
	}
	concrete, ok := proof.(*groth16bls.Proof)
	if !ok {
		halt("proof is not the BLS12-381 concrete type")
	}

	// D19 shape assert: exactly one Pedersen commitment (BSB22) + its batched PoK — the 5-element
	// proof (Ar, Bs, Krs, Commitment, CommitmentPok), NOT the vanilla 3-element (Ar, Bs, Krs).
	if len(concrete.Commitments) != 1 {
		halt("expected exactly 1 commitment (D19), got %d — shape DIVERGENCE from the design", len(concrete.Commitments))
	}

	output := proofFixture{
		N:       512,
		Circuit: *circuit,
		Note:    "REAL n=512 demonstrator proof over the real period-1600 witness (single-party groth16.Setup; pk/τ never left the VM, destroyed at stage end). PUBLIC. Commitment-augmented 5-element (D19): Ar(G1)+Bs(G2)+Krs(G1)+Commitment(G1)+CommitmentPok(G1), compressed points — 292 B as gnark binary, not the design-time vanilla 192 B. On-chain redeemer form differs (uncompressed).",
		Proof: fixtureProof{
			Ar:            compressedG1Hex(concrete.Ar),
			Bs:            compressedG2Hex(concrete.Bs),
			Krs:           compressedG1Hex(concrete.Krs),
			Commitment:    compressedG1Hex(concrete.Commitments[0]),
			CommitmentPok: compressedG1Hex(concrete.CommitmentPok),
		},
	}
	encoded, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		halt("marshal: %v", err)
	}
	os.Stdout.Write(append(encoded, '\n'))
	fmt.Fprintf(os.Stderr, "SHAPE OK: 4 G1 (ar, krs, commitment, commitment_pok) + 1 G2 (bs) + %d Pedersen commitment = 5-element commitment-augmented\n", len(concrete.Commitments))
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
