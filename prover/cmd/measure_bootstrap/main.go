// Command measure_bootstrap measures the OFF-CHAIN bootstrap Verify wall-clock cost (D17)
// on the REAL period-1600 fixtures — the one-time deployer-side genesis
// verification. Wall-clock and machine-dependent, UNLIKE the R1CS counts (D15/D16): NOT
// comparable to the on-chain CPU-step budget, and NOT the proving time.
//
// Methodology: N=100 measured samples per line after 10 discarded warm-ups; runtime.GC()
// before each sample; the golden datum is asserted on EVERY end-to-end run (the wall-clock
// analogue of measure_*'s ×2-determinism — time is noisy, the output must not be; HALT on
// mismatch). The MEDIAN is the headline statistic (min/p95 shown): the design pre-registered
// min (the additive-noise argument), but measurement showed min is UNSTABLE across runs on
// this laptop-class machine — the turbo/thermal state shifts the intrinsic baseline between
// loops (observed end-to-end min 97.7 vs 146.2 ms across two same-day runs, medians stable
// within ~8%) — so medians carry the number and the minima are flagged. Decompression is
// timed ONCE as the shared prelude line, exactly as Verify executes it (the bootstrap.go
// prelude serves conditions d AND e); (d)/(e) are timed on pre-decompressed keys — so the
// per-condition MEDIANS sum to ≈ the end-to-end median, and the residual gap is REPORTED,
// not hidden. The µs-class line (c) is K=1000-batched per sample for timer stability.
// Usage: go run ./cmd/measure_bootstrap   (from prover/)
package main

import (
	"encoding/hex"
	"fmt"
	"os"
	"runtime"
	"sort"
	"time"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"

	"eth-cardano-zk-light-client/prover/offchain/bls"
	"eth-cardano-zk-light-client/prover/offchain/bootstrap"
	"eth-cardano-zk-light-client/prover/offchain/commitment"
	"eth-cardano-zk-light-client/prover/offchain/ssz"
)

const (
	warmupRuns        = 10
	measuredRuns      = 100
	finalityWalkBatch = 1000 // line (c) is µs-class; batch K iterations per sample

	bootstrapFixturePath = "offchain/bootstrap/testdata/electra_bootstrap_period_1600.json"
	updateFixturePath    = "circuits/common/testdata/lightclientupdate/electra_period_1600.json"

	goldenCurrentCommitment   = "10041e8ce930617c420c43546f39dc8d123cec24e199f3f51dfadcb448529e1e"
	goldenNextCommitment      = "483e20c94d6075d0dd670d9b6fe7144456eecc96fadb501ac719e4473625510f"
	goldenFinalizedHeaderRoot = "201a1d12d634bcf8de5a9281d8cf5974cb775be0f8741a1cf0123e0383878599"
	goldenFinalizedSlot       = 13107200
)

func main() {
	input, _, err := bootstrap.LoadFromFixtures(bootstrapFixturePath, updateFixturePath)
	if err != nil {
		halt(fmt.Sprintf("load fixtures: %v", err))
	}

	fmt.Println("# bootstrap Verify wall-clock cost (D17) — real period-1600 fixtures; one-time deployer-side genesis verification")
	fmt.Println("# Go wall-clock, machine-dependent — NOT comparable to on-chain CPU steps, NOT proving time")
	fmt.Printf("# %s %s/%s, %d CPUs (full machine line: benchmarks/phase-2-circuit/bootstrap-verify-cost.md)\n",
		runtime.Version(), runtime.GOOS, runtime.GOARCH, runtime.NumCPU())
	fmt.Printf("# N=%d samples/line (%d warm-ups discarded), runtime.GC() before each; MEDIAN is the headline (min/p95 shown — min is unstable across runs on this machine: turbo/thermal shifts the baseline); golden-datum assert EVERY end-to-end run\n", measuredRuns, warmupRuns)
	fmt.Println("# decompression timed ONCE as the shared prelude (Verify's actual structure); (d)/(e) exclude it — the lines sum to ~ the end-to-end total; gap reported")
	fmt.Println()

	// ── end-to-end Verify (the headline): warm-up + N timed runs, golden-checked EVERY run ──
	for i := 0; i < warmupRuns; i++ {
		assertGolden(mustVerify(input))
	}
	endToEnd := make([]time.Duration, measuredRuns)
	for i := range endToEnd {
		runtime.GC()
		start := time.Now()
		result, err := bootstrap.Verify(input)
		endToEnd[i] = time.Since(start)
		if err != nil {
			halt(fmt.Sprintf("Verify rejected on run %d: %v", i, err))
		}
		assertGolden(result)
	}
	endMin, endMedian, endP95 := stats(endToEnd)
	fmt.Printf("end-to-end Verify                  min=%v  median=%v  p95=%v   golden %d/%d (+%d warm-ups)\n",
		round(endMin), round(endMedian), round(endP95), measuredRuns, measuredRuns, warmupRuns)

	// pre-decompress ONCE — the (d)/(e) inputs (mirrors Verify's prelude structure)
	currentKeys, err := bootstrap.DecompressCommittee(input.CurrentCommittee.Pubkeys)
	if err != nil {
		halt(fmt.Sprintf("decompress current: %v", err))
	}
	nextKeys, err := bootstrap.DecompressCommittee(input.NextCommittee.Pubkeys)
	if err != nil {
		halt(fmt.Sprintf("decompress next: %v", err))
	}

	// ── the per-condition breakdown (each line min over N samples) ──
	decompressLine := timeSamples(func() {
		if _, err := bootstrap.DecompressCommittee(input.CurrentCommittee.Pubkeys); err != nil {
			halt(fmt.Sprintf("decompress current (timed): %v", err))
		}
		if _, err := bootstrap.DecompressCommittee(input.NextCommittee.Pubkeys); err != nil {
			halt(fmt.Sprintf("decompress next (timed): %v", err))
		}
	})
	conditionA := timeSamples(func() {
		currentCommitteeRoot := ssz.SyncCommitteeRoot(
			ssz.PubkeysRoot(input.CurrentCommittee.Pubkeys),
			ssz.Bytes48Root(input.CurrentCommittee.AggregatePubkey))
		if ssz.Gindex86Walk(currentCommitteeRoot, input.CurrentCommitteeBranch) != input.BootstrapHeader.StateRoot {
			halt("(a) gindex-86 walk diverged")
		}
		if input.BootstrapHeader.HashTreeRoot() != input.TrustedBlockRoot {
			halt("(a) checkpoint diverged")
		}
	})
	conditionB := timeSamples(func() {
		nextCommitteeRoot := ssz.SyncCommitteeRoot(
			ssz.PubkeysRoot(input.NextCommittee.Pubkeys),
			ssz.Bytes48Root(input.NextCommittee.AggregatePubkey))
		if ssz.Gindex87Walk(nextCommitteeRoot, input.NextCommitteeBranch) != input.AttestedHeader.StateRoot {
			halt("(b) gindex-87 walk diverged")
		}
	})
	conditionC := timeSamplesBatched(finalityWalkBatch, func() {
		finalizedHeaderRoot := input.FinalizedHeader.HashTreeRoot()
		if ssz.Gindex169Walk(finalizedHeaderRoot, input.FinalityBranch) != input.AttestedHeader.StateRoot {
			halt("(c) gindex-169 walk diverged")
		}
	})
	conditionD := timeSamples(func() {
		attestedHeaderRoot := input.AttestedHeader.HashTreeRoot()
		domain := bls.ComputeDomain(bls.DomainSyncCommittee, input.ForkVersion, input.GenesisValidatorsRoot)
		signingRoot := bls.ComputeSigningRoot(attestedHeaderRoot, domain)
		var signature bls12381.G2Affine
		if _, err := signature.SetBytes(input.Signature[:]); err != nil {
			halt(fmt.Sprintf("(d) signature decode: %v", err))
		}
		verified, _, err := bls.VerifySyncAggregate(currentKeys, input.ParticipationBits, signingRoot, signature)
		if err != nil || !verified {
			halt(fmt.Sprintf("(d) sync aggregate did not verify (err %v)", err))
		}
	})
	conditionE := timeSamples(func() {
		_ = commitment.Commit(currentKeys)
		_ = commitment.Commit(nextKeys)
	})

	var sumOfMinima, sumOfMedians time.Duration
	report := func(label string, samples []time.Duration, batched bool) {
		minimum, median, p95 := stats(samples)
		note := ""
		if batched {
			note = fmt.Sprintf("   (K=%d-batched)", finalityWalkBatch)
		}
		fmt.Printf("%-34s min=%v  median=%v  p95=%v%s\n", label, round(minimum), round(median), round(p95), note)
		sumOfMinima += minimum
		sumOfMedians += median
	}
	fmt.Println()
	report("decompress prelude (serves d+e)", decompressLine, false)
	report("(a) current@gindex-86 + checkpoint", conditionA, false)
	report("(b) next@gindex-87", conditionB, false)
	report("(c) finality@gindex-169", conditionC, true)
	report("(d) BLS sync-aggregate", conditionD, false)
	report("(e) two Poseidon commitments", conditionE, false)

	// Two sum-vs-total cross-checks. The MEDIANS line is the meaningful one (the no-double-count
	// structural check): per-line medians sum to ≈ the end-to-end median. The minima line is
	// shown but NOT meaningful for additivity — each line's minimum comes from its own loop at
	// its own machine state (turbo/thermal), so minima are neither additive nor cross-loop
	// comparable on this machine.
	mediansGap := endMedian - sumOfMedians
	fmt.Printf("\nsum of line medians = %v vs end-to-end median = %v -> gap %+v (%+.1f%%)   [the no-double-count cross-check]\n",
		round(sumOfMedians), round(endMedian), round(mediansGap), 100*float64(mediansGap)/float64(endMedian))
	minimaGap := endMin - sumOfMinima
	fmt.Printf("sum of line minima  = %v vs end-to-end min    = %v -> gap %+v (%+.1f%%)   [minima: per-loop machine states differ — not additive, shown for transparency]\n",
		round(sumOfMinima), round(endMin), round(minimaGap), 100*float64(minimaGap)/float64(endMin))
}

// timeSamples returns measuredRuns wall-clock samples of work (one execution per sample),
// runtime.GC() before each.
func timeSamples(work func()) []time.Duration {
	samples := make([]time.Duration, measuredRuns)
	for i := range samples {
		runtime.GC()
		start := time.Now()
		work()
		samples[i] = time.Since(start)
	}
	return samples
}

// timeSamplesBatched runs work batchSize times per sample and reports the per-execution time —
// for µs-class work below single-shot timer stability.
func timeSamplesBatched(batchSize int, work func()) []time.Duration {
	samples := make([]time.Duration, measuredRuns)
	for i := range samples {
		runtime.GC()
		start := time.Now()
		for k := 0; k < batchSize; k++ {
			work()
		}
		samples[i] = time.Since(start) / time.Duration(batchSize)
	}
	return samples
}

func stats(samples []time.Duration) (minimum, median, p95 time.Duration) {
	sorted := append([]time.Duration(nil), samples...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	return sorted[0], sorted[len(sorted)/2], sorted[(len(sorted)*95)/100]
}

// round trims durations to a readable precision (µs for sub-ms values, 10µs above).
func round(d time.Duration) time.Duration {
	if d < time.Millisecond {
		return d.Round(time.Microsecond)
	}
	return d.Round(10 * time.Microsecond)
}

func mustVerify(input *bootstrap.Bootstrap) *bootstrap.Result {
	result, err := bootstrap.Verify(input)
	if err != nil {
		halt(fmt.Sprintf("Verify rejected: %v", err))
	}
	return result
}

func assertGolden(result *bootstrap.Result) {
	current := result.CurrentPubkeysCommitment.Bytes()
	next := result.NextPubkeysCommitment.Bytes()
	if hex.EncodeToString(current[:]) != goldenCurrentCommitment ||
		hex.EncodeToString(next[:]) != goldenNextCommitment ||
		hex.EncodeToString(result.FinalizedHeaderRoot[:]) != goldenFinalizedHeaderRoot ||
		result.FinalizedSlot != goldenFinalizedSlot {
		halt("golden datum mismatch — the output must be deterministic")
	}
}

func halt(message string) {
	fmt.Fprintln(os.Stderr, "HALT: "+message)
	os.Exit(1)
}
