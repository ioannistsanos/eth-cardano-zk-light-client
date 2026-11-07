package witness

// The real boundary proof of the on-chain fixture (validator/lib/zkbridge/real_n512_boundary.ak)
// verifies under the boundary verifying key of the consumed datum, with the twelve public inputs
// assembled from the fixture's redeemer and datum fields by this package's packing code; a single
// changed public input makes the same proof fail.

import (
	"encoding/hex"
	"math/big"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr/pedersen"
	"github.com/consensys/gnark/backend/groth16"
	groth16bls "github.com/consensys/gnark/backend/groth16/bls12-381"
	gnarkwitness "github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/frontend"

	"eth-cardano-zk-light-client/prover/circuits/common"
)

const realBoundaryFixturePath = "../../../validator/lib/zkbridge/real_n512_boundary.ak"

// realBoundaryFixture holds the fixture fields the verification needs, as the module declares them.
type realBoundaryFixture struct {
	verifyingKey           groth16bls.VerifyingKey
	proof                  groth16bls.Proof
	consumedNextCommitment []byte
	producedNextCommitment []byte
	aggregatePublicKey     bls12381.G1Affine
	count                  int64
	attestedHeaderRoot     [32]byte
	producedFinalizedRoot  [32]byte
	producedFinalizedSlot  int64
	consumedFinalizedSlot  int64
}

var hexLiteral = regexp.MustCompile(`#"([0-9a-f]*)"`)

// functionBody returns the source of the named public function up to its closing brace.
func functionBody(t *testing.T, source, name string) string {
	t.Helper()
	start := strings.Index(source, "pub fn "+name+"()")
	if start < 0 {
		t.Fatalf("fixture: function %s not found", name)
	}
	end := strings.Index(source[start:], "\n}\n")
	if end < 0 {
		t.Fatalf("fixture: function %s has no closing brace", name)
	}
	return source[start : start+end]
}

// namedHexFields maps `field: #"hex"` declarations of a function body to their bytes.
func namedHexFields(t *testing.T, body string) map[string][]byte {
	t.Helper()
	pattern := regexp.MustCompile(`(\w+): #"([0-9a-f]+)"`)
	fields := map[string][]byte{}
	for _, match := range pattern.FindAllStringSubmatch(body, -1) {
		fields[match[1]] = decodeHex(t, match[2])
	}
	return fields
}

// listHexField returns the hex literals of the named list field of a function body, in order.
func listHexField(t *testing.T, body, name string) [][]byte {
	t.Helper()
	start := strings.Index(body, name+": [")
	if start < 0 {
		t.Fatalf("fixture: list field %s not found", name)
	}
	end := strings.Index(body[start:], "]")
	if end < 0 {
		t.Fatalf("fixture: list field %s is not closed", name)
	}
	var items [][]byte
	for _, match := range hexLiteral.FindAllStringSubmatch(body[start:start+end], -1) {
		items = append(items, decodeHex(t, match[1]))
	}
	return items
}

func constantHex(t *testing.T, source, name string) []byte {
	t.Helper()
	pattern := regexp.MustCompile(`pub const ` + name + `: ByteArray =\s*#"([0-9a-f]+)"`)
	match := pattern.FindStringSubmatch(source)
	if match == nil {
		t.Fatalf("fixture: constant %s not found", name)
	}
	return decodeHex(t, match[1])
}

func constantInt(t *testing.T, source, name string) int64 {
	t.Helper()
	pattern := regexp.MustCompile(`pub const ` + name + `: Int = (\d+)`)
	match := pattern.FindStringSubmatch(source)
	if match == nil {
		t.Fatalf("fixture: constant %s not found", name)
	}
	value, err := strconv.ParseInt(match[1], 10, 64)
	if err != nil {
		t.Fatalf("fixture: constant %s: %v", name, err)
	}
	return value
}

func decodeHex(t *testing.T, text string) []byte {
	t.Helper()
	value, err := hex.DecodeString(text)
	if err != nil {
		t.Fatalf("fixture: hex %q: %v", text, err)
	}
	return value
}

func g1FromBytes(t *testing.T, what string, encoded []byte) bls12381.G1Affine {
	t.Helper()
	var point bls12381.G1Affine
	if _, err := point.SetBytes(encoded); err != nil {
		t.Fatalf("%s: not a valid G1 encoding (%d bytes): %v", what, len(encoded), err)
	}
	return point
}

func g2FromBytes(t *testing.T, what string, encoded []byte) bls12381.G2Affine {
	t.Helper()
	var point bls12381.G2Affine
	if _, err := point.SetBytes(encoded); err != nil {
		t.Fatalf("%s: not a valid G2 encoding (%d bytes): %v", what, len(encoded), err)
	}
	return point
}

func bytes32(t *testing.T, what string, value []byte) (out [32]byte) {
	t.Helper()
	if len(value) != 32 {
		t.Fatalf("%s: want 32 bytes, got %d", what, len(value))
	}
	copy(out[:], value)
	return out
}

// loadRealBoundaryFixture reads the fixture module: the consumed datum's boundary verifying key, the
// redeemer's proof, aggregate public key, count and attested header root, and the produced datum's
// finalized header root, finalized slot and next-committee commitment.
func loadRealBoundaryFixture(t *testing.T) *realBoundaryFixture {
	t.Helper()
	raw, err := os.ReadFile(filepath.Clean(realBoundaryFixturePath))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	source := string(raw)
	fixture := &realBoundaryFixture{}

	keyBody := functionBody(t, source, "real_vk_boundary")
	keyFields := namedHexFields(t, keyBody)
	fixture.verifyingKey.G1.Alpha = g1FromBytes(t, "vk alpha", keyFields["alpha"])
	fixture.verifyingKey.G2.Beta = g2FromBytes(t, "vk beta", keyFields["beta"])
	fixture.verifyingKey.G2.Gamma = g2FromBytes(t, "vk gamma", keyFields["gamma"])
	fixture.verifyingKey.G2.Delta = g2FromBytes(t, "vk delta", keyFields["delta"])
	for i, encoded := range listHexField(t, keyBody, "ic") {
		fixture.verifyingKey.G1.K = append(fixture.verifyingKey.G1.K, g1FromBytes(t, "vk ic["+strconv.Itoa(i)+"]", encoded))
	}
	if len(fixture.verifyingKey.G1.K) != 14 {
		t.Fatalf("vk ic: want 14 points for the twelve public inputs plus the constant wire and one commitment, got %d", len(fixture.verifyingKey.G1.K))
	}
	fixture.verifyingKey.CommitmentKeys = []pedersen.VerifyingKey{{
		G:         g2FromBytes(t, "vk commitment_g", keyFields["commitment_g"]),
		GSigmaNeg: g2FromBytes(t, "vk commitment_g_sigma_neg", keyFields["commitment_g_sigma_neg"]),
	}}
	// one commitment, committing to no public input: the commitment hash is over the commitment point alone
	fixture.verifyingKey.PublicAndCommitmentCommitted = [][]int{{}}
	if err := fixture.verifyingKey.Precompute(); err != nil {
		t.Fatalf("vk precompute: %v", err)
	}

	proofFields := namedHexFields(t, functionBody(t, source, "real_proof"))
	fixture.proof.Ar = g1FromBytes(t, "proof a", proofFields["a"])
	fixture.proof.Bs = g2FromBytes(t, "proof b", proofFields["b"])
	fixture.proof.Krs = g1FromBytes(t, "proof c", proofFields["c"])
	if len(proofFields["commitment"]) != 96 {
		t.Fatalf("proof commitment: want the 96-byte uncompressed form, got %d bytes", len(proofFields["commitment"]))
	}
	fixture.proof.Commitments = []bls12381.G1Affine{g1FromBytes(t, "proof commitment", proofFields["commitment"])}
	fixture.proof.CommitmentPok = g1FromBytes(t, "proof commitment_pok", proofFields["commitment_pok"])

	fixture.consumedNextCommitment = constantHex(t, source, "consumed_next_commitment")
	fixture.producedNextCommitment = constantHex(t, source, "produced_next_commitment")
	fixture.aggregatePublicKey = g1FromBytes(t, "redeemer apk", constantHex(t, source, "real_apk"))
	fixture.count = constantInt(t, source, "real_count")
	fixture.attestedHeaderRoot = bytes32(t, "attested root", constantHex(t, source, "real_attested_root"))
	fixture.producedFinalizedRoot = bytes32(t, "produced finalized root", constantHex(t, source, "produced_finalized_root"))
	fixture.producedFinalizedSlot = constantInt(t, source, "produced_finalized_slot")
	fixture.consumedFinalizedSlot = constantInt(t, source, "consumed_finalized_slot")
	return fixture
}

// publicAssignment is the BoundaryCircuit assignment with only its public fields set: the consumed
// datum's next-committee commitment (the signing committee), the redeemer's aggregate public key
// (packPoint), count and attested header root (packRootHalves), the produced datum's finalized header
// root (packRootHalves), finalized slot and next-committee commitment.
func (fixture *realBoundaryFixture) publicAssignment() *common.BoundaryCircuit {
	assignment := common.NewBoundaryCircuit(512)
	assignment.PubkeysCommitment = new(big.Int).SetBytes(fixture.consumedNextCommitment)
	assignment.ApkPacked = packPoint(fixture.aggregatePublicKey)
	assignment.Count = fixture.count
	assignment.AttestedHeaderRootPacked = packRootHalves(fixture.attestedHeaderRoot)
	assignment.FinalizedHeaderRootPacked = packRootHalves(fixture.producedFinalizedRoot)
	assignment.FinalizedSlot = fixture.producedFinalizedSlot
	assignment.NextPubkeysCommitment = new(big.Int).SetBytes(fixture.producedNextCommitment)
	return assignment
}

// publicWitnessOf builds the public witness of an assignment through frontend.NewWitness.
func publicWitnessOf(t *testing.T, assignment *common.BoundaryCircuit) (gnarkwitness.Witness, fr.Vector) {
	t.Helper()
	publicWitness, err := frontend.NewWitness(assignment, ecc.BLS12_381.ScalarField(), frontend.PublicOnly())
	if err != nil {
		t.Fatalf("public witness: %v", err)
	}
	vector, ok := publicWitness.Vector().(fr.Vector)
	if !ok {
		t.Fatalf("public witness vector has type %T", publicWitness.Vector())
	}
	return publicWitness, vector
}

// TestRealBoundaryFixture_ProofVerifiesUnderConsumedDatumKey: the fixture's proof verifies under
// the consumed datum's boundary verifying key against the twelve public inputs assembled from the
// fixture's fields.
func TestRealBoundaryFixture_ProofVerifiesUnderConsumedDatumKey(t *testing.T) {
	fixture := loadRealBoundaryFixture(t)
	publicWitness, values := publicWitnessOf(t, fixture.publicAssignment())
	if len(values) != 12 {
		t.Fatalf("public inputs: want 12, got %d", len(values))
	}
	for i := range values {
		t.Logf("public[%2d] = %064s", i, values[i].Text(16))
	}
	if err := groth16.Verify(&fixture.proof, &fixture.verifyingKey, publicWitness); err != nil {
		t.Fatalf("groth16.Verify: %v", err)
	}
	t.Logf("groth16.Verify: the boundary proof verifies under the consumed datum's boundary verifying key (count %d, slot %d)",
		fixture.count, fixture.producedFinalizedSlot)
}

// TestRealBoundaryFixture_ChangedPublicInputRejected: the same proof fails when one public input is
// changed (the count, the finalized slot, or the produced next-committee commitment).
func TestRealBoundaryFixture_ChangedPublicInputRejected(t *testing.T) {
	fixture := loadRealBoundaryFixture(t)
	cases := []struct {
		name   string
		mutate func(assignment *common.BoundaryCircuit)
	}{
		{"count plus one", func(a *common.BoundaryCircuit) { a.Count = fixture.count + 1 }},
		{"finalized slot equal to the consumed slot", func(a *common.BoundaryCircuit) { a.FinalizedSlot = fixture.consumedFinalizedSlot }},
		{"produced next commitment replaced by the consumed one", func(a *common.BoundaryCircuit) {
			a.NextPubkeysCommitment = new(big.Int).SetBytes(fixture.consumedNextCommitment)
		}},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			assignment := fixture.publicAssignment()
			testCase.mutate(assignment)
			publicWitness, _ := publicWitnessOf(t, assignment)
			err := groth16.Verify(&fixture.proof, &fixture.verifyingKey, publicWitness)
			if err == nil {
				t.Fatal("groth16.Verify accepted the proof with a changed public input")
			}
			t.Logf("groth16.Verify rejects the changed public input: %v", err)
		})
	}
}
