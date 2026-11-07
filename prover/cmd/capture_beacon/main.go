// Command capture_beacon is the S1 live-capture client for the end-to-end scenario. In --dry-run it
// validates the full fetch→parse→verify path + the polling-timing logic against live mainnet, with
// NO sync-committee boundary needed (run at our pace before the timed S2 capture). The timed S2
// straddle (--capture) is added once the dry-run validates the schema.
//
//	go run ./cmd/capture_beacon -dry-run -out-dir /tmp/beacon-dryrun -dry-poll-min 20
package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"eth-cardano-zk-light-client/prover/offchain/beacon"
)

func main() {
	dryRun := flag.Bool("dry-run", false, "validate fetch→parse→verify + the poller against live mainnet (no boundary needed)")
	base := flag.String("base", beacon.DefaultBase, "beacon API base URL (archival mainnet)")
	outDir := flag.String("out-dir", "", "output dir for fixtures (required)")
	dryPollMin := flag.Int("dry-poll-min", 20, "dry-run: minutes to poll finality_update (validates distinct-slot detection)")
	fetchedUTC := flag.String("fetched-utc", time.Now().UTC().Format("2006-01-02T15:04:05Z"), "the _provenance timestamp")
	flag.Parse()

	if *outDir == "" {
		halt("-out-dir is required")
	}
	if err := os.MkdirAll(*outDir, 0o755); err != nil {
		halt("mkdir out-dir: " + err.Error())
	}
	log := func(format string, args ...any) { fmt.Printf(format+"\n", args...) }

	switch {
	case *dryRun:
		fmt.Println("# capture_beacon --dry-run (read-only; validates the client before the timed S2 capture)")
		if err := beacon.DryRun(*base, *outDir, *fetchedUTC, *dryPollMin, log); err != nil {
			halt(err.Error())
		}
	default:
		halt("specify -dry-run (the timed -capture straddle is wired after the dry-run validates the schema)")
	}
}

func halt(message string) {
	fmt.Fprintln(os.Stderr, "HALT: "+message)
	os.Exit(1)
}
