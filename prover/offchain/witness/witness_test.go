package witness

// The witness-builder validation suite — the trust-before-AWS story. A wrong witness would
// otherwise fail only at the full-512 AWS solve, after paying for the instance; these layers
// validate everything EXCEPT that solve locally:
//
//	layer 1 — golden-datum cross-checks at FULL 512 (commitment / next commitment / packed
//	          roots / slot land on the bootstrap pipeline's independently-validated goldens)
//	layer 2 — the off-circuit SSZ anchors (BUILDER-INTERNAL: BuildRegular HALTs unless the
//	          gindex-169 fold reaches the attested state_root; BuildBoundary additionally
//	          HALTs unless the gindex-87 walk does — a successful build IS the anchor pass)
//	layer 3 — the REAL signature verifies under the BUILDER's apk (a single transposed
//	          bit↔key fails the pairing — the cryptographic alignment check)
//	layer 4 — the builder's output SOLVES in-circuit at small N (regular only — the
//	          documented asymmetry: op-6 merkleizes all N keys, so no truncated boundary
//	          instance exists against the real branch) + full Groth16 at N=2 on real data
//	layer 5 — witness.Public() == 11 / 12 Fr at FULL 512 (no solving needed)
//	(+ the full-size-only guard: BuildBoundary refuses n < 512)
//
// These tests SUPERSEDE the old regular_test.go real-Electra tests with strictly more
// realism: signers = the CURRENT committee with the REAL sync_committee_bits (vs the next
// committee as a stand-in with pattern bits).

import (
	"fmt"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/test"

	"eth-cardano-zk-light-client/prover/circuits/common"
	"eth-cardano-zk-light-client/prover/offchain/bls"
	"eth-cardano-zk-light-client/prover/offchain/bootstrap"
	"eth-cardano-zk-light-client/prover/offchain/commitment"
)

const (
	bootstrapFixturePath = "../bootstrap/testdata/electra_bootstrap_period_1600.json"
	updateFixturePath    = "../../circuits/common/testdata/lightclientupdate/electra_period_1600.json"

	// the golden datum (the bootstrap pipeline's independently-validated outputs) + the pinned
	// real attested_header_root (op-3a's reconstruction target).
	goldenCurrentCommitment = "10041e8ce930617c420c43546f39dc8d123cec24e199f3f51dfadcb448529e1e"
	goldenNextCommitment    = "483e20c94d6075d0dd670d9b6fe7144456eecc96fadb501ac719e4473625510f"
	goldenFinalizedRoot     = "201a1d12d634bcf8de5a9281d8cf5974cb775be0f8741a1cf0123e0383878599"
	realAttestedHeaderRoot  = "7099a98d437bc51344b7cad28193da1a9d51d79fba141b4ebb2afcd81242a52d"
	goldenFinalizedSlot     = 13107200
	realParticipationCount  = 510
	realCommitteeSize       = 512
)

func loadInput(t *testing.T) *bootstrap.Bootstrap {
	t.Helper()
	input, signatureSlot, err := bootstrap.LoadFromFixtures(bootstrapFixturePath, updateFixturePath)
	if err != nil {
		t.Fatalf("load fixtures: %v", err)
	}
	if signatureSlot/8192 != 1600 {
		t.Fatalf("signature_slot %d not in period 1600", signatureSlot)
	}
	return input
}

func variableHex32(t *testing.T, value frontend.Variable) string {
	t.Helper()
	asBig, ok := value.(interface{ Text(int) string })
	if !ok {
		t.Fatalf("unexpected variable type %T", value)
	}
	return fmt.Sprintf("%064s", asBig.Text(16))
}

func packedRootHex(t *testing.T, packed [2]frontend.Variable) string {
	t.Helper()
	half0, ok0 := packed[0].(interface{ Text(int) string })
	half1, ok1 := packed[1].(interface{ Text(int) string })
	if !ok0 || !ok1 {
		t.Fatalf("unexpected packed-root types %T/%T", packed[0], packed[1])
	}
	return fmt.Sprintf("%032s%032s", half0.Text(16), half1.Text(16))
}

// ─────────────────────────── layer 1 + 5: goldens + public counts (full 512) ───────────────────────────

func TestBuildRegular_GoldenPublics(t *testing.T) {
	input := loadInput(t)
	assignment, err := BuildRegular(input, realCommitteeSize)
	if err != nil {
		t.Fatalf("BuildRegular(512): %v", err)
	}

	if got := variableHex32(t, assignment.PubkeysCommitment); got != goldenCurrentCommitment {
		t.Fatalf("PubkeysCommitment = %s, want golden current %s — HALT, the witness is wrong", got, goldenCurrentCommitment)
	}
	if got := packedRootHex(t, assignment.FinalizedHeaderRootPacked); got != goldenFinalizedRoot {
		t.Fatalf("FinalizedHeaderRootPacked unpacks to %s, want golden %s", got, goldenFinalizedRoot)
	}
	if got := packedRootHex(t, assignment.AttestedHeaderRootPacked); got != realAttestedHeaderRoot {
		t.Fatalf("AttestedHeaderRootPacked unpacks to %s, want the pinned real root %s", got, realAttestedHeaderRoot)
	}
	if assignment.FinalizedSlot != uint64(goldenFinalizedSlot) {
		t.Fatalf("FinalizedSlot = %v, want %d", assignment.FinalizedSlot, goldenFinalizedSlot)
	}
	if assignment.Count != realParticipationCount {
		t.Fatalf("Count = %v, want %d", assignment.Count, realParticipationCount)
	}

	witnessObject, err := frontend.NewWitness(assignment, ecc.BLS12_381.ScalarField())
	if err != nil {
		t.Fatalf("NewWitness(512): %v", err)
	}
	publicWitness, err := witnessObject.Public()
	if err != nil {
		t.Fatalf("public: %v", err)
	}
	vector, ok := publicWitness.Vector().(fr.Vector)
	if !ok {
		t.Fatalf("unexpected public-vector type %T", publicWitness.Vector())
	}
	if len(vector) != 11 {
		t.Fatalf("public-input count = %d, want 11", len(vector))
	}
	t.Logf("PASS: full-512 regular witness — commitment/roots/slot/count all golden; Public() == 11 Fr")
}

func TestBuildBoundary_GoldenPublics(t *testing.T) {
	input := loadInput(t)
	assignment, err := BuildBoundary(input, realCommitteeSize)
	if err != nil {
		t.Fatalf("BuildBoundary(512): %v", err)
	}

	if got := variableHex32(t, assignment.NextPubkeysCommitment); got != goldenNextCommitment {
		t.Fatalf("NextPubkeysCommitment = %s, want golden next %s — HALT, the witness is wrong", got, goldenNextCommitment)
	}
	if got := variableHex32(t, assignment.PubkeysCommitment); got != goldenCurrentCommitment {
		t.Fatalf("embedded PubkeysCommitment = %s, want golden current %s", got, goldenCurrentCommitment)
	}

	witnessObject, err := frontend.NewWitness(assignment, ecc.BLS12_381.ScalarField())
	if err != nil {
		t.Fatalf("NewWitness(512): %v", err)
	}
	publicWitness, err := witnessObject.Public()
	if err != nil {
		t.Fatalf("public: %v", err)
	}
	vector, ok := publicWitness.Vector().(fr.Vector)
	if !ok {
		t.Fatalf("unexpected public-vector type %T", publicWitness.Vector())
	}
	if len(vector) != 12 {
		t.Fatalf("public-input count = %d, want 12", len(vector))
	}
	t.Logf("PASS: full-512 boundary witness — next commitment golden (87-anchor passed inside the builder); Public() == 12 Fr")
}

// ─────────────────────────── layer 3: the real σ verifies under the builder's apk ───────────────────────────

func TestBuildRegular_SignatureVerifiesUnderBuilderApk(t *testing.T) {
	input := loadInput(t)
	assignment, err := BuildRegular(input, realCommitteeSize)
	if err != nil {
		t.Fatalf("BuildRegular(512): %v", err)
	}

	// independent reference: decompress + bits-filter + aggregate HERE (not via the builder).
	currentKeys, err := bootstrap.DecompressCommittee(input.CurrentCommittee.Pubkeys)
	if err != nil {
		t.Fatalf("decompress: %v", err)
	}
	participants := make([]bls12381.G1Affine, 0, realCommitteeSize)
	for i := range currentKeys {
		if input.ParticipationBits[i] {
			participants = append(participants, currentKeys[i])
		}
	}
	var aggregateJacobian bls12381.G1Jac
	for i := range participants {
		var keyJacobian bls12381.G1Jac
		keyJacobian.FromAffine(&participants[i])
		aggregateJacobian.AddAssign(&keyJacobian)
	}
	var referenceApk bls12381.G1Affine
	referenceApk.FromJacobian(&aggregateJacobian)

	// the REAL signature verifies under this aggregate (one transposed bit fails the pairing).
	domain := bls.ComputeDomain(bls.DomainSyncCommittee, input.ForkVersion, input.GenesisValidatorsRoot)
	signingRoot := bls.ComputeSigningRoot(input.AttestedHeader.HashTreeRoot(), domain)
	var signature bls12381.G2Affine
	if _, err := signature.SetBytes(input.Signature[:]); err != nil {
		t.Fatalf("signature decode: %v", err)
	}
	verified, err := bls.FastAggregateVerify(participants, signingRoot, signature)
	if err != nil || !verified {
		t.Fatalf("HALT: the real σ does NOT verify under the reference aggregate (err %v) — bit↔key alignment broken", err)
	}

	// the builder's ApkPacked equals the σ-verified aggregate's pack.
	xLo, xHi := commitment.FoldFp(referenceApk.X)
	yLo, yHi := commitment.FoldFp(referenceApk.Y)
	reference := [4]fr.Element{xLo, xHi, yLo, yHi}
	for i := range reference {
		want := frToVariable(reference[i])
		gotText, okGot := assignment.ApkPacked[i].(interface{ Text(int) string })
		wantText, okWant := want.(interface{ Text(int) string })
		if !okGot || !okWant || gotText.Text(16) != wantText.Text(16) {
			t.Fatalf("ApkPacked[%d] = %v, want the σ-verified aggregate's pack %v", i, assignment.ApkPacked[i], want)
		}
	}
	t.Logf("PASS: the real sync_aggregate σ verifies under the BUILDER's apk (510 participants) — bit↔key alignment cryptographically confirmed")
}

// ─────────────────────────── layer 4: in-circuit solves of the builder's output (regular) ───────────────────────────

// TestBuildRegular_RealElectraSolves: the production builder's output solves in-circuit at
// small N — the same code path as the full-512 witness, on the real period-1600 data
// (supersedes the old regular_test real-Electra positive, with real bits + the real signers).
func TestBuildRegular_RealElectraSolves(t *testing.T) {
	input := loadInput(t)
	for _, n := range []int{8, 16} {
		assignment, err := BuildRegular(input, n)
		if err != nil {
			t.Fatalf("BuildRegular(%d): %v", n, err)
		}
		if err := test.IsSolved(common.NewRegularCircuit(n), assignment, ecc.BLS12_381.ScalarField()); err != nil {
			t.Fatalf("REAL-ELECTRA positive FAILED at N=%d (builder wiring bug): %v", n, err)
		}
		t.Logf("PASS: N=%d — the builder's real-data witness solves (current-committee keys + real bits + real finality)", n)
	}
}

// TestBuildRegular_RealElectraProves: full Groth16 Setup→Prove→Verify at N=2 on the builder's
// real-data output (the moved pipeline check; full-512 proving is AWS stage 3).
func TestBuildRegular_RealElectraProves(t *testing.T) {
	input := loadInput(t)
	assignment, err := BuildRegular(input, 2)
	if err != nil {
		t.Fatalf("BuildRegular(2): %v", err)
	}
	scalarField := ecc.BLS12_381.ScalarField()
	constraintSystem, err := frontend.Compile(scalarField, r1cs.NewBuilder, common.NewRegularCircuit(2))
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	provingKey, verifyingKey, err := groth16.Setup(constraintSystem)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	witnessObject, err := frontend.NewWitness(assignment, scalarField)
	if err != nil {
		t.Fatalf("witness: %v", err)
	}
	publicWitness, err := witnessObject.Public()
	if err != nil {
		t.Fatalf("public: %v", err)
	}
	proof, err := groth16.Prove(constraintSystem, provingKey, witnessObject)
	if err != nil {
		t.Fatalf("prove: %v", err)
	}
	if err := groth16.Verify(proof, verifyingKey, publicWitness); err != nil {
		t.Fatalf("verify: %v", err)
	}
	t.Logf("PASS: real-data Groth16 N=2 through the production builder (%d constraints)", constraintSystem.GetNbConstraints())
}

// ─────────────────────────── the full-size-only guard (boundary) ───────────────────────────

func TestBuildBoundary_TruncatedRefused(t *testing.T) {
	input := loadInput(t)
	if _, err := BuildBoundary(input, 8); err == nil {
		t.Fatal("BuildBoundary(8) must refuse: no truncated boundary instance exists against the real gindex-87 branch")
	} else {
		t.Logf("PASS: truncated boundary refused as documented: %v", err)
	}
}
