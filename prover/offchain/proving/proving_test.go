package proving

// The committed regression for the setup/prove entrypoint logic — toy-N only (the full-512
// runs are the AWS stages). TestSetupProveRoundTrip_RegularToy is the end-to-end logic gate:
// setup → artifacts land in the RIGHT dirs (vk in output; pk/ccs in scratch) → prove loads
// them, the real-data witness proves, Verify is nil, publics stable, proof persisted. The
// boundary prove cannot run at toy N (the builder is full-size only — its cmd path shares
// the same code); the boundary SETUP path is exercised manually at toy N (witness-independent)
// and kept out of this suite for runtime. The scratch-guard unit makes the τ-never-committable
// rule structural.

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRefuseScratchInsideGitRepository(t *testing.T) {
	clean := t.TempDir()
	if err := RefuseScratchInsideGitRepository(clean); err != nil {
		t.Fatalf("clean temp dir refused: %v", err)
	}
	repo := t.TempDir()
	if err := os.MkdirAll(filepath.Join(repo, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	inside := filepath.Join(repo, "scratch")
	if err := RefuseScratchInsideGitRepository(inside); err == nil {
		t.Fatal("scratch inside a git repository must be REFUSED (the τ-never-committable guard)")
	} else {
		t.Logf("PASS: refused as required: %v", err)
	}
}

func TestArtifactPaths_EmbedSizeAndSplitDirs(t *testing.T) {
	paths := ArtifactPaths{OutputDir: "/out", ScratchDir: "/scratch", Kind: Boundary, NumberOfKeys: 8}
	if got := paths.VerifyingKeyPath(); got != "/out/vk_boundary_n8.vk" {
		t.Fatalf("vk path %q", got)
	}
	if got := paths.ProvingKeyPath(); got != "/scratch/pk_boundary_n8.pk" {
		t.Fatalf("pk path %q (must be under SCRATCH)", got)
	}
	if got := paths.ConstraintSystemPath(); got != "/scratch/ccs_boundary_n8.ccs" {
		t.Fatalf("ccs path %q (must be under SCRATCH)", got)
	}
	if got := paths.ProofPath(); got != "/out/proof_boundary_n8.proof" {
		t.Fatalf("proof path %q", got)
	}
}

// TestSetupProveRoundTrip_RegularToy — the end-to-end entrypoint logic at n=2 on the real
// fixtures (heavy: one toy Groth16 setup + one prove, ~minutes; the per-iteration Verify is
// the correctness gate).
func TestSetupProveRoundTrip_RegularToy(t *testing.T) {
	outputDir := t.TempDir()
	scratchDir := t.TempDir()
	paths := ArtifactPaths{OutputDir: outputDir, ScratchDir: scratchDir, Kind: Regular, NumberOfKeys: 2}

	setupResult, err := RunSetup(paths)
	if err != nil {
		t.Fatalf("RunSetup: %v", err)
	}
	if setupResult.ConstraintCount <= 0 {
		t.Fatal("constraint count not reported")
	}
	// the dir discipline: vk in OUTPUT; pk + ccs in SCRATCH; nothing key-shaped in OUTPUT.
	for _, mustExist := range []string{paths.VerifyingKeyPath(), paths.ProvingKeyPath(), paths.ConstraintSystemPath()} {
		if _, err := os.Stat(mustExist); err != nil {
			t.Fatalf("missing artifact %s: %v", mustExist, err)
		}
	}
	outputEntries, err := os.ReadDir(outputDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range outputEntries {
		if filepath.Ext(entry.Name()) == ".pk" || filepath.Ext(entry.Name()) == ".ccs" {
			t.Fatalf("τ-bearing artifact %s leaked into the OUTPUT dir", entry.Name())
		}
	}

	proveResult, err := RunProve(paths,
		"../bootstrap/testdata/electra_bootstrap_period_1600.json",
		"../../circuits/common/testdata/lightclientupdate/electra_period_1600.json",
		2)
	if err != nil {
		t.Fatalf("RunProve: %v", err)
	}
	if proveResult.PublicInputCount != 11 {
		t.Fatalf("public inputs = %d, want 11", proveResult.PublicInputCount)
	}
	if !proveResult.PublicsStableAcross {
		t.Fatal("publics not stable across iterations")
	}
	if _, err := os.Stat(paths.ProofPath()); err != nil {
		t.Fatalf("proof not persisted: %v", err)
	}
	if _, err := os.Stat(paths.PublicWitnessPath()); err != nil {
		t.Fatalf("public witness not persisted: %v", err)
	}
	t.Logf("PASS: toy round-trip — setup (%d constraints, %.1fs) → prove ×%d (median %.2fs, Verify nil every iteration) → artifacts in the right dirs",
		setupResult.ConstraintCount, setupResult.SetupSeconds, proveResult.Iterations, proveResult.ProveSecondsMedian)
}
