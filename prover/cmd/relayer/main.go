// Command relayer is the live ZK-bridge relayer daemon entrypoint: poll Ethereum finality → discern
// regular/boundary on its own → prove in-process → submit on Cardano via spend.py. It wires the live
// beacon Poller + Executor (offchain/relayer.LiveRelayer) into the proven orchestration Loop.
//
//	--mode dry-run  (default, SAFE): read-only — seed + poll N advancing updates + discern + witness +
//	                BuildBLSFields, NO prove/spend. Validates the real beacon wiring at our pace.
//	--mode live     (VM-tier): LoadProver (pk_fresh) + the full --plan run + spend.py --submit +
//	                self-stop. Needs the fresh setup + the scenario Boot's bridge.
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
	"time"

	"eth-cardano-zk-light-client/prover/offchain/beacon"
	"eth-cardano-zk-light-client/prover/offchain/proving"
	"eth-cardano-zk-light-client/prover/offchain/relayer"
)

func main() {
	mode := flag.String("mode", "dry-run", "dry-run (read-only, no prove/spend) | live (the VM scenario)")
	planStr := flag.String("plan", "regular*,regular,regular", "scripted shape: regular* = SPEND regulars until the rollover (variable count) + spend the boundary, then the listed trailing steps")
	bootstrapRoot := flag.String("bootstrap-root", "", "the trusted checkpoint (the committee the scenario Boot installed) — REQUIRED")
	beaconBase := flag.String("beacon", beacon.DefaultBase, "beacon REST base")
	scratchDir := flag.String("scratch-dir", "/tmp/zkbridge-relayer", "proving keys, constraint systems and per-phase witness fixtures")
	outDir := flag.String("out", "benchmarks/raw/phase-a-scenario", "STATUS / phase-record output dir (live)")
	outputDir := flag.String("output-dir", "", "the directory of the verification keys (live)")
	python := flag.String("python", "", "venv python for spend.py (live)")
	spendPy := flag.String("spend-py", "boot/spend.py", "path to spend.py (live)")
	pollInterval := flag.Duration("poll-interval", 30*time.Second, "finality poll interval")
	boundaryDeadline := flag.Duration("boundary-wait-deadline", 6*time.Hour, "max wait for the rollover (a boundary step)")
	dryPhases := flag.Int("dry-phases", 2, "dry-run: number of advancing updates to validate")
	flag.Parse()

	if err := os.MkdirAll(*scratchDir, 0o755); err != nil {
		log.Fatalf("scratch dir: %v", err)
	}
	client := beacon.NewClient(*beaconBase)
	logf := func(format string, args ...any) { fmt.Printf(format+"\n", args...) }

	switch *mode {
	case "dry-run":
		root := *bootstrapRoot
		if root == "" { // the dry-run has no scenario Boot — derive a current checkpoint to seed from.
			derived, err := relayer.DeriveCurrentCheckpoint(client)
			if err != nil {
				log.Fatalf("derive checkpoint: %v", err)
			}
			root = derived
			logf("dry-run: derived current checkpoint %s…", root[:14])
		}
		lr := &relayer.LiveRelayer{Client: client, ScratchDir: *scratchDir, PollInterval: *pollInterval, Log: logf}
		if err := lr.DryRun(root, *dryPhases); err != nil {
			log.Fatalf("dry-run: %v", err)
		}
	case "live":
		if *bootstrapRoot == "" || *outputDir == "" || *python == "" {
			log.Fatal("live mode requires --bootstrap-root (the scenario Boot's checkpoint) + --output-dir (pk_fresh) + --python")
		}
		plan, err := parsePlan(*planStr)
		if err != nil {
			log.Fatal(err)
		}
		prover, err := proving.LoadProver(*outputDir, *scratchDir, 512, proving.Regular, proving.Boundary)
		if err != nil {
			log.Fatalf("LoadProver (pk_fresh): %v", err)
		}
		lr := &relayer.LiveRelayer{Client: client, Prover: prover, ScratchDir: *scratchDir,
			Python: *python, SpendPy: *spendPy, PollInterval: *pollInterval, Log: logf}
		cache, err := lr.Seed(*bootstrapRoot)
		if err != nil {
			log.Fatalf("seed: %v", err)
		}
		if err := os.MkdirAll(*outDir, 0o755); err != nil {
			log.Fatalf("out dir: %v", err)
		}
		loop := &relayer.Loop{
			Poller: lr, Executor: lr, Cache: cache, Plan: plan, OutDir: *outDir,
			BoundaryWaitDeadline: *boundaryDeadline, Log: logf,
			Stop: func(reason string) {
				logf("SELF-STOP: %s — sudo shutdown -h now", reason)
				_ = exec.Command("sudo", "shutdown", "-h", "now").Run()
			},
		}
		if err := loop.Run(); err != nil {
			log.Fatalf("relayer run: %v", err)
		}
	default:
		log.Fatalf("unknown --mode %q (want dry-run | live)", *mode)
	}
}

func parsePlan(s string) ([]relayer.PlanStep, error) {
	var plan []relayer.PlanStep
	for _, part := range strings.Split(s, ",") {
		switch strings.TrimSpace(strings.ToLower(part)) {
		case "regular":
			plan = append(plan, relayer.StepRegular)
		case "boundary":
			plan = append(plan, relayer.StepBoundary)
		case "regular*":
			plan = append(plan, relayer.StepRegularsUntilBoundary)
		default:
			return nil, fmt.Errorf("unknown plan step %q (want regular | boundary | regular*)", part)
		}
	}
	if len(plan) == 0 {
		return nil, fmt.Errorf("empty --plan")
	}
	return plan, nil
}
