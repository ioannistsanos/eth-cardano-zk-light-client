package bls

import (
	"encoding/hex"
	"math/big"
	"os"
	"strings"
	"testing"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"gopkg.in/yaml.v3"
)

// ── hex + YAML loaders for the consensus-spec-tests vectors ──

func mustHexBytes(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.TrimPrefix(s, "0x"))
	if err != nil {
		t.Fatalf("hex decode %q: %v", s, err)
	}
	return b
}

func mustHex32(t *testing.T, s string) (out [32]byte) {
	t.Helper()
	b := mustHexBytes(t, s)
	if len(b) != 32 {
		t.Fatalf("expected 32 bytes, got %d for %q", len(b), s)
	}
	copy(out[:], b)
	return
}

func mustHex4(t *testing.T, s string) (out [4]byte) {
	t.Helper()
	b := mustHexBytes(t, s)
	if len(b) != 4 {
		t.Fatalf("expected 4 bytes, got %d for %q", len(b), s)
	}
	copy(out[:], b)
	return
}

func loadYAML(t *testing.T, path string, dst any) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if err := yaml.Unmarshal(raw, dst); err != nil {
		t.Fatalf("yaml %s: %v", path, err)
	}
}

func decodeG1(t *testing.T, s string) bls12381.G1Affine {
	t.Helper()
	var p bls12381.G1Affine
	if _, err := p.SetBytes(mustHexBytes(t, s)); err != nil {
		t.Fatalf("G1 SetBytes %q: %v", s, err)
	}
	return p
}

// decodeG2OK decodes a compressed G2 point, returning ok=false if it is not a valid encoding
// (a tampered signature may decode to a wrong-but-valid point, or fail to decode — both must
// yield a non-verifying verdict).
func decodeG2OK(t *testing.T, s string) (bls12381.G2Affine, bool) {
	t.Helper()
	var p bls12381.G2Affine
	if _, err := p.SetBytes(mustHexBytes(t, s)); err != nil {
		return p, false
	}
	return p, true
}

// ── deterministic synthetic committee (Gate 2/3 — no randomness, reproducible) ──

// deterministicCommittee returns n keypairs with secret_i = i+1, pubkey_i = (i+1)·g1.
func deterministicCommittee(n int) ([]bls12381.G1Affine, []big.Int) {
	_, _, g1Generator, _ := bls12381.Generators()
	pubkeys := make([]bls12381.G1Affine, n)
	secrets := make([]big.Int, n)
	for i := 0; i < n; i++ {
		secrets[i] = *big.NewInt(int64(i + 1))
		pubkeys[i].ScalarMultiplication(&g1Generator, &secrets[i])
	}
	return pubkeys, secrets
}

// aggregateSign produces the aggregate signature Σ_{participating} secret_i·H(message) over G2
// (the honest aggregate of the participants' individual signatures).
func aggregateSign(t *testing.T, secrets []big.Int, participating []bool, message [32]byte) bls12381.G2Affine {
	t.Helper()
	hashedMessage, err := bls12381.HashToG2(message[:], EthereumDST)
	if err != nil {
		t.Fatalf("hash-to-G2: %v", err)
	}
	var aggregate bls12381.G2Jac
	for i := range secrets {
		if i < len(participating) && participating[i] {
			var signature bls12381.G2Affine
			signature.ScalarMultiplication(&hashedMessage, &secrets[i])
			var signatureJacobian bls12381.G2Jac
			signatureJacobian.FromAffine(&signature)
			aggregate.AddAssign(&signatureJacobian)
		}
	}
	var result bls12381.G2Affine
	result.FromJacobian(&aggregate)
	return result
}

func allTrue(n int) []bool {
	bits := make([]bool, n)
	for i := range bits {
		bits[i] = true
	}
	return bits
}
