// Command groth16_setup runs the SINGLE-PARTY DEMONSTRATOR trusted setup (stage 2) for one
// Phase-A circuit: compile → groth16.Setup → vk to the OUTPUT dir (the only dir that ever
// leaves the machine), pk + ccs to the SCRATCH dir (τ-bearing; never transferred; destroyed
// at stage end; refused if inside any git repository). NOT an MPC — see the banner and
// docs/assembly-design.md "Trusted-setup honesty".
//
// Disk note (runbook): at the real size the boundary pk+ccs are tens of GB (raw
// serialization); size the scratch volume ~50–100 GB before running on the instance.
// Usage (toy, local logic validation):
//
//	go run ./cmd/groth16_setup -circuit regular  -n 8 -output-dir /tmp/zk-out -scratch-dir /tmp/zk-scratch
//	go run ./cmd/groth16_setup -circuit boundary -n 8 -output-dir /tmp/zk-out -scratch-dir /tmp/zk-scratch
//
// Real (AWS): the same with -n 512.
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
	outputDir := flag.String("output-dir", "", "vk destination — the only dir that ever leaves the machine (required)")
	scratchDir := flag.String("scratch-dir", "", "pk/ccs destination — τ-bearing, never transferred, outside any git repo (required)")
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
	fmt.Printf("# groth16_setup circuit=%s n=%d output=%s scratch=%s\n", kind, *numberOfKeys, *outputDir, *scratchDir)

	paths := proving.ArtifactPaths{OutputDir: *outputDir, ScratchDir: *scratchDir, Kind: kind, NumberOfKeys: *numberOfKeys}
	result, err := proving.RunSetup(paths)
	if err != nil {
		halt(err.Error())
	}

	fmt.Printf("constraints           = %d\n", result.ConstraintCount)
	fmt.Printf("compile wall-clock    = %.1fs\n", result.CompileSeconds)
	fmt.Printf("setup wall-clock      = %.1fs\n", result.SetupSeconds)
	fmt.Printf("peak RSS              = %.2f GiB (process high-water mark)\n", result.PeakRssGib)
	fmt.Printf("vk  -> %s (%d bytes)\n", paths.VerifyingKeyPath(), result.VerifyingKeyBytes)
	fmt.Printf("pk  -> %s (%d bytes)  [SCRATCH — never leaves; destroy at stage end]\n", paths.ProvingKeyPath(), result.ProvingKeyBytes)
	fmt.Printf("ccs -> %s (%d bytes)  [SCRATCH]\n", paths.ConstraintSystemPath(), result.ConstraintBytes)
}

func halt(message string) {
	fmt.Fprintln(os.Stderr, "HALT: "+message)
	os.Exit(1)
}
