// Command groth16_prove produces REAL measured Groth16 proofs (stage 3): loads pk/ccs from
// the SCRATCH dir + vk from the OUTPUT dir, builds the real period-1600 witness via the
// validated builder (its gindex-169/87 anchors re-guard here), and measures groth16.Prove
// over -iterations runs. The timer wraps groth16.Prove ONLY (it internally includes witness
// solving); witness build, NewWitness and Verify sit outside. EVERY iteration must
// groth16.Verify (proofs are randomized — Verify is the correctness gate); the public
// witness must be identical across iterations, and at n=512 it must hit the bootstrap
// goldens. Median is the headline statistic (the D17 lesson).
//
// PRE-REGISTERED expectations (recorded before any real run; results reported as-is):
// regular prove ~3–20 s; boundary prove ~60–600 s; peak RSS regular ~8–30 GiB, boundary
// ~60–200 GiB (the design-stage estimates of 10–35 s / 16–32 GB were made for a 10–26M
// circuit; the boundary is ~61M — expect upward refutation).
// Usage (toy, local logic validation — regular only; the boundary witness is full-size only):
//
//	go run ./cmd/groth16_prove -circuit regular -n 8 -iterations 2 -output-dir /tmp/zk-out -scratch-dir /tmp/zk-scratch
//
// Real (AWS): -n 512 -iterations 5, both circuits.
package main

import (
	"flag"
	"fmt"
	"os"

	"eth-cardano-zk-light-client/prover/offchain/proving"
)

func main() {
	circuitFlag := flag.String("circuit", "", "circuit: regular | boundary (required)")
	numberOfKeys := flag.Int("n", proving.RealCommitteeSize, "committee size (512 = real; anything else is a TOY logic run)")
	outputDir := flag.String("output-dir", "", "proof/public/log destination — the only dir that ever leaves the machine (required)")
	scratchDir := flag.String("scratch-dir", "", "where setup left pk/ccs (required)")
	iterations := flag.Int("iterations", 5, "prove iterations (median reported; >=5 for the citable numbers)")
	bootstrapFixture := flag.String("bootstrap-fixture", "offchain/bootstrap/testdata/electra_bootstrap_period_1600.json", "the LightClientBootstrap fixture (β)")
	updateFixture := flag.String("update-fixture", "circuits/common/testdata/lightclientupdate/electra_period_1600.json", "the LightClientUpdate fixture (α)")
	flag.Parse()

	kind, err := proving.ParseCircuitKind(*circuitFlag)
	if err != nil {
		halt(err.Error())
	}
	if *outputDir == "" || *scratchDir == "" {
		halt("-output-dir and -scratch-dir are required")
	}

	fmt.Println(proving.DemonstratorBanner)
	if *numberOfKeys != proving.RealCommitteeSize {
		fmt.Println(proving.ToySizeBanner)
	}
	fmt.Printf("# groth16_prove circuit=%s n=%d iterations=%d\n", kind, *numberOfKeys, *iterations)
	fmt.Println("# timer = groth16.Prove only (includes internal witness solving); Verify gated every iteration")

	paths := proving.ArtifactPaths{OutputDir: *outputDir, ScratchDir: *scratchDir, Kind: kind, NumberOfKeys: *numberOfKeys}
	result, err := proving.RunProve(paths, *bootstrapFixture, *updateFixture, *iterations)
	if err != nil {
		halt(err.Error())
	}
	if err := proving.GoldenPublicChecks(kind, *numberOfKeys, result.ReferencePublics); err != nil {
		halt(err.Error())
	}

	for i, seconds := range result.ProveSecondsAll {
		fmt.Printf("iteration %d: prove = %.2fs (Verify OK)\n", i, seconds)
	}
	fmt.Printf("prove wall-clock      = median %.2fs  min %.2fs  p95 %.2fs  over %d iterations\n",
		result.ProveSecondsMedian, result.ProveSecondsMin, result.ProveSecondsP95, result.Iterations)
	fmt.Printf("peak RSS              = %.2f GiB (process high-water mark, incl. pk load)\n", result.PeakRssGib)
	fmt.Printf("public inputs         = %d Fr (stable across iterations: %v)\n", result.PublicInputCount, result.PublicsStableAcross)
	fmt.Printf("proof  -> %s (%d bytes)\n", paths.ProofPath(), result.ProofBytes)
	fmt.Printf("publics-> %s\n", paths.PublicWitnessPath())
	fmt.Println("REMINDER: the scratch dir holds τ-bearing material (pk) — destroy it (and the volume) at stage end.")
}

func halt(message string) {
	fmt.Fprintln(os.Stderr, "HALT: "+message)
	os.Exit(1)
}
