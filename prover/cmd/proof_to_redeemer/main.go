// Command proof_to_redeemer reads a proof fixture (proof_{circuit}_n512.json from cmd/proof_to_json)
// and emits the REDEEMER-shaped proof: a / b / c / commitment_pok pass through COMPRESSED, but the
// `commitment` is re-emitted UNCOMPRESSED (96 B = G1.Marshal(), X‖Y). The on-chain Aiken redeemer
// needs the commitment uncompressed (types.ak:26-28: gnark hashes Commitments[0].Marshal() for the
// BSB22 12th public, so the validator hashes the SAME 96 B AND reconstructs the point) — whereas
// proof_to_json exports it compressed (48 B). This is the redeemer-seam subtlety #4 (full_system_build_3).
//
//	go run ./cmd/proof_to_redeemer -in validator/fixtures/proof_regular_n512.json
package main

import (
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
)

type proofFixtureJSON struct {
	N       int    `json:"n"`
	Circuit string `json:"circuit"`
	Proof   struct {
		Ar            string `json:"ar"`
		Bs            string `json:"bs"`
		Krs           string `json:"krs"`
		Commitment    string `json:"commitment"`
		CommitmentPok string `json:"commitment_pok"`
	} `json:"proof"`
}

type redeemerProof struct {
	A             string `json:"a"`              // G1 48 B compressed (Ar)
	B             string `json:"b"`              // G2 96 B compressed (Bs)
	C             string `json:"c"`              // G1 48 B compressed (Krs)
	Commitment    string `json:"commitment"`     // G1 96 B UNCOMPRESSED X‖Y (Marshal) — the seam fix
	CommitmentPok string `json:"commitment_pok"` // G1 48 B compressed (CommitmentPok)
}

func main() {
	in := flag.String("in", "", "input proof_{circuit}_n512.json (from cmd/proof_to_json) (required)")
	flag.Parse()
	if *in == "" {
		halt("-in is required")
	}

	raw, err := os.ReadFile(*in)
	if err != nil {
		halt("read %s: %v", *in, err)
	}
	var fixture proofFixtureJSON
	if err := json.Unmarshal(raw, &fixture); err != nil {
		halt("unmarshal: %v", err)
	}

	// Decompress the commitment: compressed 48 B → G1 point → uncompressed 96 B Marshal (X‖Y).
	// decompress(compress(P)) == P, then Marshal(P) is the exact 96 B gnark hashed for the 12th public.
	commCompressed, err := hex.DecodeString(fixture.Proof.Commitment)
	if err != nil {
		halt("commitment hex: %v", err)
	}
	var commitment bls12381.G1Affine
	if _, err := commitment.SetBytes(commCompressed); err != nil {
		halt("commitment decompress: %v", err)
	}
	commUncompressed := commitment.Marshal() // 96 B uncompressed X‖Y
	if len(commUncompressed) != 96 {
		halt("commitment Marshal expected 96 B, got %d", len(commUncompressed))
	}

	output := map[string]any{
		"n":       fixture.N,
		"circuit": fixture.Circuit,
		"note":    "REDEEMER-shaped proof: a/b/c/commitment_pok compressed; commitment UNCOMPRESSED 96 B (Marshal X‖Y) per types.ak:26-28 — NOT the compressed proof_to_json form. Feeds the Aiken redeemer + the daemon's redeemer encoder.",
		"proof_redeemer": redeemerProof{
			A:             fixture.Proof.Ar,
			B:             fixture.Proof.Bs,
			C:             fixture.Proof.Krs,
			Commitment:    hex.EncodeToString(commUncompressed),
			CommitmentPok: fixture.Proof.CommitmentPok,
		},
	}
	encoded, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		halt("marshal: %v", err)
	}
	os.Stdout.Write(append(encoded, '\n'))
	fmt.Fprintf(os.Stderr, "OK (%s): commitment %d B compressed → %d B uncompressed (Marshal X‖Y)\n",
		fixture.Circuit, len(commCompressed), len(commUncompressed))
}

func halt(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "HALT: "+format+"\n", args...)
	os.Exit(1)
}
