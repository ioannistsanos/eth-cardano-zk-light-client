package common

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/golang/snappy"

	"eth-cardano-zk-light-client/prover/offchain/ssz"
)

func toCircuitBytes32(value [32]byte) [32]uints.U8 { return [32]uints.U8(uints.NewU8Array(value[:])) }

func loadHeader(t *testing.T) ssz.Header {
	t.Helper()
	compressedVector, err := os.ReadFile(filepath.Join("testdata", "bbh", "serialized.ssz_snappy"))
	if err != nil {
		t.Fatalf("read vector: %v", err)
	}
	serializedHeader, err := snappy.Decode(nil, compressedVector)
	if err != nil {
		t.Fatalf("snappy: %v", err)
	}
	header, err := ssz.Deserialize(serializedHeader)
	if err != nil {
		t.Fatalf("deserialize: %v", err)
	}
	return header
}

func officialRoot(t *testing.T) [32]byte {
	t.Helper()
	fileBytes, err := os.ReadFile(filepath.Join("testdata", "bbh", "roots.yaml"))
	if err != nil {
		t.Fatalf("read roots.yaml: %v", err)
	}
	hexStart := strings.Index(string(fileBytes), "0x")
	decodedRoot, err := hex.DecodeString(string(fileBytes)[hexStart+2 : hexStart+2+64])
	if err != nil {
		t.Fatalf("parse root: %v", err)
	}
	var root [32]byte
	copy(root[:], decodedRoot)
	return root
}

// TestSlotBindProvesAgainstOfficialRoot: build the 3 siblings off-circuit from the
// validated Fulu vector, self-anchor ssz.HashTreeRoot to the AUTHORITATIVE
// roots.yaml root, then prove in-circuit that the 3-step path from finalized_slot
// reaches that root. Full Setup->Prove->Verify over BLS12-381.
// (Proof randomized — not byte-identical, expected; counts deterministic.)
func TestSlotBindProvesAgainstOfficialRoot(t *testing.T) {
	header := loadHeader(t)
	root := header.HashTreeRoot()
	if root != officialRoot(t) {
		t.Fatalf("off-circuit htr != official roots.yaml root (data/ssz bug, not circuit)")
	}
	branch := header.SlotBranch()

	assignment := NewSlotBindCircuit(3)
	assignment.FinalizedSlot = header.Slot
	assignment.HeaderRoot = toCircuitBytes32(root)
	for step := 0; step < 3; step++ {
		assignment.HeaderBranch[step] = toCircuitBytes32(branch[step])
	}

	scalarField := ecc.BLS12_381.ScalarField()
	constraintSystem, err := frontend.Compile(scalarField, r1cs.NewBuilder, NewSlotBindCircuit(3))
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	provingKey, verifyingKey, err := groth16.Setup(constraintSystem)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	witness, err := frontend.NewWitness(assignment, scalarField)
	if err != nil {
		t.Fatalf("witness: %v", err)
	}
	publicWitness, err := witness.Public()
	if err != nil {
		t.Fatalf("public: %v", err)
	}
	proof, err := groth16.Prove(constraintSystem, provingKey, witness)
	if err != nil {
		t.Fatalf("prove: %v", err)
	}
	if err := groth16.Verify(proof, verifyingKey, publicWitness); err != nil {
		t.Fatalf("verify: %v", err)
	}
	t.Logf("PASS: slot %d bound to official root 0x%x over BLS12-381 (%d constraints)",
		header.Slot, root, constraintSystem.GetNbConstraints())
}
