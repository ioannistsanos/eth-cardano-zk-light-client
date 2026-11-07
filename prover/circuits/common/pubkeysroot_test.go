package common

import (
	"crypto/sha256"
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
	"github.com/consensys/gnark/test"
	"gopkg.in/yaml.v3"

	"eth-cardano-zk-light-client/prover/offchain/ssz"
)

type syncCommitteeVector struct {
	Pubkeys         []string `yaml:"pubkeys"`
	AggregatePubkey string   `yaml:"aggregate_pubkey"`
}

func decodeHex48(t *testing.T, s string) [48]byte {
	t.Helper()
	raw, err := hex.DecodeString(strings.TrimPrefix(strings.Trim(s, "'\""), "0x"))
	if err != nil || len(raw) != 48 {
		t.Fatalf("bad 48-byte hex %q: %v (len %d)", s, err, len(raw))
	}
	var out [48]byte
	copy(out[:], raw)
	return out
}

func loadSyncCommittee(t *testing.T) (pubkeys [][48]byte, aggregate [48]byte) {
	t.Helper()
	fileBytes, err := os.ReadFile(filepath.Join("testdata", "synccommittee", "value.yaml"))
	if err != nil {
		t.Fatalf("read value.yaml: %v", err)
	}
	var v syncCommitteeVector
	if err := yaml.Unmarshal(fileBytes, &v); err != nil {
		t.Fatalf("parse value.yaml: %v", err)
	}
	if len(v.Pubkeys) != 512 {
		t.Fatalf("expected 512 pubkeys, got %d", len(v.Pubkeys))
	}
	pubkeys = make([][48]byte, len(v.Pubkeys))
	for i, s := range v.Pubkeys {
		pubkeys[i] = decodeHex48(t, s)
	}
	return pubkeys, decodeHex48(t, v.AggregatePubkey)
}

func syncCommitteeContainerRoot(t *testing.T) [32]byte {
	t.Helper()
	fileBytes, err := os.ReadFile(filepath.Join("testdata", "synccommittee", "roots.yaml"))
	if err != nil {
		t.Fatalf("read roots.yaml: %v", err)
	}
	i := strings.Index(string(fileBytes), "0x")
	raw, err := hex.DecodeString(string(fileBytes)[i+2 : i+2+64])
	if err != nil {
		t.Fatalf("parse root: %v", err)
	}
	var out [32]byte
	copy(out[:], raw)
	return out
}

func toCircuitBytes48(b [48]byte) [48]uints.U8 { return [48]uints.U8(uints.NewU8Array(b[:])) }

// anchoredPubkeysRoot validates that our OFF-CIRCUIT pubkeys_root composes with the
// agg_root to the authoritative container root: H(pubkeys_root, agg_root) ==
// roots.yaml root. This pins the gindex-174 value (AND, as a free byproduct, the
// gindex-175 agg_root layout) to consensus WITHOUT trusting our own merkleizer.
func anchoredPubkeysRoot(t *testing.T) ([][48]byte, [32]byte) {
	t.Helper()
	pubkeys, aggregate := loadSyncCommittee(t)
	pubkeysRoot := ssz.PubkeysRoot(pubkeys)
	aggRoot := ssz.Bytes48Root(aggregate)
	container := sha256.Sum256(append(append([]byte{}, pubkeysRoot[:]...), aggRoot[:]...))
	if container != syncCommitteeContainerRoot(t) {
		t.Fatalf("off-circuit pubkeys_root not anchored: H(pubkeys_root,agg_root) != container root")
	}
	return pubkeys, pubkeysRoot
}

func TestPubkeysRootAnchorsToConsensus(t *testing.T) {
	_, root := anchoredPubkeysRoot(t)
	t.Logf("PASS: off-circuit pubkeys_root anchored to consensus container root = 0x%x", root)
}

// SC-5: the in-circuit 512-Bytes48 merkleization SOLVES to the anchored consensus root
// (layout-exactness / satisfiability) — via the SOLVER, NOT a 55M Groth16 setup.
func TestPubkeysRootSolves512(t *testing.T) {
	// AWS-only: the full-512 in-circuit solver (test.IsSolved over 1,023 SHA-256) OOMs
	// locally (~7GB, crashed WSL). The LOCAL layout guarantee (SC-5) is the full-512
	// off-circuit anchor (TestPubkeysRootAnchorsToConsensus) + the N-generic small-N
	// Groth16 (TestPubkeysRootProvesSmallN). Set RUN_AWS_HEAVY=1 to run it on AWS.
	if os.Getenv("RUN_AWS_HEAVY") == "" {
		t.Skip("full-512 in-circuit solver OOMs locally (~7GB); AWS-only — set RUN_AWS_HEAVY=1")
	}
	pubkeys, pubkeysRoot := anchoredPubkeysRoot(t)
	assignment := NewPubkeysRootCircuit(512)
	for i := range pubkeys {
		assignment.Pubkeys[i] = toCircuitBytes48(pubkeys[i])
	}
	assignment.ExpectedRoot = toCircuitBytes32(pubkeysRoot)
	if err := test.IsSolved(NewPubkeysRootCircuit(512), assignment, ecc.BLS12_381.ScalarField()); err != nil {
		t.Fatalf("solver failed (in-circuit layout != consensus): %v", err)
	}
	t.Logf("PASS: in-circuit 512-Bytes48 merkleization solves to consensus pubkeys_root 0x%x", pubkeysRoot)
}

// end-to-end: the construction is Groth16-provable at small, structurally-identical N.
func TestPubkeysRootProvesSmallN(t *testing.T) {
	pubkeys, _ := anchoredPubkeysRoot(t)
	field := ecc.BLS12_381.ScalarField()
	// Small N for end-to-end provability sanity. Kept tiny because Groth16
	// Setup+Prove on BLS12-381 is slow (calibration: op-3a's 504K constraints take
	// ~122s), so even N=8/16 (~0.8M/~1.7M) exceed a practical local budget. N=2/4 are
	// structurally identical (Bytes48 leaf + balanced tree) and prove the same point.
	for _, n := range []int{2, 4} {
		root := ssz.PubkeysRoot(pubkeys[:n])
		assignment := NewPubkeysRootCircuit(n)
		for i := 0; i < n; i++ {
			assignment.Pubkeys[i] = toCircuitBytes48(pubkeys[i])
		}
		assignment.ExpectedRoot = toCircuitBytes32(root)
		constraintSystem, err := frontend.Compile(field, r1cs.NewBuilder, NewPubkeysRootCircuit(n))
		if err != nil {
			t.Fatalf("compile N=%d: %v", n, err)
		}
		provingKey, verifyingKey, err := groth16.Setup(constraintSystem)
		if err != nil {
			t.Fatalf("setup N=%d: %v", n, err)
		}
		witness, err := frontend.NewWitness(assignment, field)
		if err != nil {
			t.Fatalf("witness N=%d: %v", n, err)
		}
		publicWitness, err := witness.Public()
		if err != nil {
			t.Fatalf("public N=%d: %v", n, err)
		}
		proof, err := groth16.Prove(constraintSystem, provingKey, witness)
		if err != nil {
			t.Fatalf("prove N=%d: %v", n, err)
		}
		if err := groth16.Verify(proof, verifyingKey, publicWitness); err != nil {
			t.Fatalf("verify N=%d: %v", n, err)
		}
		t.Logf("PASS: N=%d Groth16 Setup->Prove->Verify; root 0x%x (%d constraints)", n, root, constraintSystem.GetNbConstraints())
	}
}
