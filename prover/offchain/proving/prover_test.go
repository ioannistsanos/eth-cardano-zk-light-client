package proving

import (
	"testing"

	"eth-cardano-zk-light-client/prover/offchain/bootstrap"
)

// Relative to this package dir (prover/offchain/proving): the period-1600 fixtures. BuildRegular is
// N-parameterized, so it subsets the committee to the first n keys — the toy regular path is
// in-circuit-solvable + setup-able locally at n=8 (no real demonstrator artifacts needed).
const (
	toyBootstrapFixture = "../bootstrap/testdata/electra_bootstrap_period_1600.json"
	toyUpdateFixture    = "../../circuits/common/testdata/lightclientupdate/electra_period_1600.json"
)

// TestProverEquivalence_ToyRegular proves the in-process Prover.Prove path is EQUIVALENT to the
// standalone RunProve (the D24-measured path): both Verify-OK + IDENTICAL public witness + same
// 292 B proof. NOT byte-identity (Groth16 proofs are randomized — fresh r,s per call). Runs at toy
// n=8 LOCALLY (a quick toy setup; the real n=512 pks are destroyed, so n=512 is a VM-tier check).
func TestProverEquivalence_ToyRegular(t *testing.T) {
	const n = 8
	scratchDir := t.TempDir() // outside the repo → passes RefuseScratchInsideGitRepository
	outputDir := t.TempDir()
	paths := ArtifactPaths{OutputDir: outputDir, ScratchDir: scratchDir, Kind: Regular, NumberOfKeys: n}

	// toy n=8 regular setup → toy pk/ccs/vk
	if _, err := RunSetup(paths); err != nil {
		t.Fatalf("toy RunSetup(regular, n=8): %v", err)
	}

	input, _, err := bootstrap.LoadFromFixtures(toyBootstrapFixture, toyUpdateFixture)
	if err != nil {
		t.Fatalf("load fixtures: %v", err)
	}

	// in-process: load the toy regular artifacts ONCE, prove
	prover, err := LoadProver(outputDir, scratchDir, n, Regular)
	if err != nil {
		t.Fatalf("LoadProver: %v", err)
	}
	inProcess, err := prover.Prove(Regular, input)
	if err != nil {
		t.Fatalf("in-process Prove: %v", err)
	}
	if !inProcess.VerifyOK {
		t.Fatal("in-process proof did not Verify under the vk")
	}

	// standalone: RunProve (the D24 path) on the SAME toy artifacts + input
	standalone, err := RunProve(paths, toyBootstrapFixture, toyUpdateFixture, 1)
	if err != nil {
		t.Fatalf("standalone RunProve: %v", err)
	}

	// EQUIVALENCE — same public witness (deterministic), same proof shape. (Bytes differ: randomized.)
	if len(inProcess.Publics) != len(standalone.ReferencePublics) {
		t.Fatalf("public count: in-process %d vs standalone %d", len(inProcess.Publics), len(standalone.ReferencePublics))
	}
	for i := range inProcess.Publics {
		if inProcess.Publics[i] != standalone.ReferencePublics[i] {
			t.Fatalf("public[%d] differs: in-process %s vs standalone %s", i, inProcess.Publics[i], standalone.ReferencePublics[i])
		}
	}
	if inProcess.ProofBytes != standalone.ProofBytes {
		t.Fatalf("proof size: in-process %d B vs standalone %d B", inProcess.ProofBytes, standalone.ProofBytes)
	}

	t.Logf("EQUIVALENCE OK — both Verify-OK, %d identical publics, proof %d B (in-process %.3fs / standalone %.3fs prove)",
		len(inProcess.Publics), inProcess.ProofBytes, inProcess.ProveSeconds, standalone.ProveSecondsMedian)
}
