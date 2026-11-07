package beacon

import (
	"encoding/hex"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"eth-cardano-zk-light-client/prover/offchain/bootstrap"
	"eth-cardano-zk-light-client/prover/offchain/ssz"
	"eth-cardano-zk-light-client/prover/offchain/witness"
)

// Logf is the progress sink (a plain func so callers wire it to stdout / a file).
type Logf func(format string, args ...any)

func hex32(s string) (out [32]byte, err error) {
	b, err := hex.DecodeString(strings.TrimPrefix(s, "0x"))
	if err != nil {
		return out, err
	}
	if len(b) != 32 {
		return out, fmt.Errorf("want 32 bytes, got %d", len(b))
	}
	copy(out[:], b)
	return out, nil
}

// blockRootHex computes the SSZ hash_tree_root of a beacon header → 0x-hex (the bootstrap key).
func blockRootHex(h apiHeader) (string, error) {
	slot, err := strconv.ParseUint(h.Beacon.Slot, 10, 64)
	if err != nil {
		return "", fmt.Errorf("slot: %w", err)
	}
	proposer, err := strconv.ParseUint(h.Beacon.ProposerIndex, 10, 64)
	if err != nil {
		return "", fmt.Errorf("proposer_index: %w", err)
	}
	parent, err := hex32(h.Beacon.ParentRoot)
	if err != nil {
		return "", fmt.Errorf("parent_root: %w", err)
	}
	state, err := hex32(h.Beacon.StateRoot)
	if err != nil {
		return "", fmt.Errorf("state_root: %w", err)
	}
	body, err := hex32(h.Beacon.BodyRoot)
	if err != nil {
		return "", fmt.Errorf("body_root: %w", err)
	}
	hdr := ssz.Header{Slot: slot, ProposerIndex: proposer, ParentRoot: parent, StateRoot: state, BodyRoot: body}
	root := hdr.HashTreeRoot()
	return "0x" + hex.EncodeToString(root[:]), nil
}

func finalizedSlotOf(u *Update) (uint64, error) {
	return strconv.ParseUint(u.FinalizedHeader.Beacon.Slot, 10, 64)
}

// ── golden-verify: each captured (β, α) pair re-loaded through the SAME validated path ──

func goldenGenesis(betaPath, updatePath string) error {
	input, _, err := bootstrap.LoadFromFixtures(betaPath, updatePath)
	if err != nil {
		return fmt.Errorf("load: %w", err)
	}
	if _, err := bootstrap.Verify(input); err != nil {
		return fmt.Errorf("bootstrap.Verify: %w", err)
	}
	return nil
}

func goldenRegular(betaPath, updatePath string) error {
	input, _, err := bootstrap.LoadFromFixtures(betaPath, updatePath)
	if err != nil {
		return fmt.Errorf("load: %w", err)
	}
	if _, err := witness.BuildRegular(input, len(input.CurrentCommittee.Pubkeys)); err != nil {
		return fmt.Errorf("BuildRegular (gindex-169 anchor): %w", err)
	}
	return nil
}

func goldenBoundary(betaPath, updatePath string) error {
	input, _, err := bootstrap.LoadFromFixtures(betaPath, updatePath)
	if err != nil {
		return fmt.Errorf("load: %w", err)
	}
	if _, err := witness.BuildBoundary(input, len(input.NextCommittee.Pubkeys)); err != nil {
		return fmt.Errorf("BuildBoundary (gindex-87 anchor): %w", err)
	}
	return nil
}

// pollDistinct polls finality_update until durationMin elapses, capturing each STRICTLY-advancing
// finalized slot exactly once (a re-fetch of the same latest is skipped); transient errors retry.
func (c *Client) pollDistinct(durationMin, intervalSec int, log Logf) []*Update {
	var captured []*Update
	var last uint64
	start := time.Now()
	for time.Since(start) < time.Duration(durationMin)*time.Minute {
		u, err := c.FetchFinalityUpdate()
		if err != nil {
			log("  poll error (retrying): %v", err)
			time.Sleep(time.Duration(intervalSec) * time.Second)
			continue
		}
		slot, err := finalizedSlotOf(u)
		if err != nil {
			log("  parse finalized slot (retrying): %v", err)
			time.Sleep(time.Duration(intervalSec) * time.Second)
			continue
		}
		if slot > last {
			captured = append(captured, u)
			if last == 0 {
				log("  first finalized slot %d (epoch %d)", slot, slot/SlotsPerEpoch)
			} else {
				log("  NEW finalized slot %d (Δ %d slots, +%s elapsed)", slot, slot-last, time.Since(start).Round(time.Second))
			}
			last = slot
		}
		time.Sleep(time.Duration(intervalSec) * time.Second)
	}
	return captured
}

const provNote = "S1 capture client (offchain/beacon); golden-verified via bootstrap.Verify/Build*"

// DryRun validates the WHOLE fetch→parse→verify path + the poller-timing logic against live
// mainnet, with NO boundary needed (S1 gate). It (1) assembles a mid-period genesis from real data
// and runs bootstrap.Verify + BuildRegular + BuildBoundary, then (2) polls finality_update for
// dryPollMin minutes exercising the identical distinct-finalized-slot detector.
func DryRun(base, outDir, fetchedUTC string, dryPollMin int, log Logf) error {
	c := NewClient(base)

	gen, err := c.FetchGenesis()
	if err != nil {
		return fmt.Errorf("genesis: %w", err)
	}
	genesisTime, err := strconv.ParseUint(gen.GenesisTime, 10, 64)
	if err != nil {
		return fmt.Errorf("genesis_time: %w", err)
	}
	head, err := c.FetchHeadSlot()
	if err != nil {
		return fmt.Errorf("head: %w", err)
	}
	period := head / SlotsPerPeriod
	boundary := (period + 1) * SlotsPerPeriod
	boundaryUnix := genesisTime + boundary*SecondsPerSlot
	log("head slot %d → period %d; next boundary slot %d (unix %d), gvr %s",
		head, period, boundary, boundaryUnix, gen.GenesisValidatorsRoot)

	// (1) single-fetch genesis on the FINALIZED period (committee-consistent), then verify.
	fu, err := c.FetchFinalityUpdate()
	if err != nil {
		return fmt.Errorf("finality_update: %w", err)
	}
	finSlot, err := finalizedSlotOf(fu)
	if err != nil {
		return fmt.Errorf("finalized slot: %w", err)
	}
	q := finSlot / SlotsPerPeriod
	log("latest finalized slot %d → assembling a period-%d genesis to verify", finSlot, q)

	canonical, err := c.FetchUpdate(q)
	if err != nil {
		return fmt.Errorf("updates(period %d): %w", q, err)
	}
	root, err := blockRootHex(canonical.FinalizedHeader)
	if err != nil {
		return fmt.Errorf("compute bootstrap root: %w", err)
	}
	bs, err := c.FetchBootstrap(root)
	if err != nil {
		return fmt.Errorf("bootstrap(%s): %w", root, err)
	}
	sigSlot, err := strconv.ParseUint(canonical.SignatureSlot, 10, 64)
	if err != nil {
		return fmt.Errorf("signature_slot: %w", err)
	}
	fork, err := c.FetchForkVersionAtEpoch(sigSlot / SlotsPerEpoch)
	if err != nil {
		return fmt.Errorf("fork_version: %w", err)
	}
	log("fork_version at epoch %d = %s", sigSlot/SlotsPerEpoch, fork)

	prov := Provenance{Source: base, Fetched: fetchedUTC, Period: q, Note: "DRY-RUN — " + provNote}
	betaPath := filepath.Join(outDir, "dryrun_bootstrap.json")
	updPath := filepath.Join(outDir, "dryrun_update.json")
	provB := prov
	provB.Endpoint = "/eth/v1/beacon/light_client/bootstrap/" + root
	provU := prov
	provU.Endpoint = fmt.Sprintf("/eth/v1/beacon/light_client/updates?start_period=%d&count=1", q)
	if err := WriteBootstrapFixture(betaPath, bs, root, provB); err != nil {
		return err
	}
	if err := WriteUpdateFixture(updPath, canonical, canonical.NextSyncCommittee.Pubkeys, canonical.NextSyncCommittee.AggregatePubkey, canonical.NextSyncCommitteeBranch, fork, gen.GenesisValidatorsRoot, provU); err != nil {
		return err
	}

	if err := goldenGenesis(betaPath, updPath); err != nil {
		return fmt.Errorf("GENESIS golden-verify FAILED (bootstrap.Verify rejected real data — likely a period-edge committee mismatch; re-run mid-period): %w", err)
	}
	log("✓ bootstrap.Verify ACCEPTED real mainnet data (conditions a–e)")
	if err := goldenRegular(betaPath, updPath); err != nil {
		return fmt.Errorf("regular witness FAILED: %w", err)
	}
	log("✓ BuildRegular PASSED (gindex-169 finality anchor)")
	if err := goldenBoundary(betaPath, updPath); err != nil {
		return fmt.Errorf("boundary witness FAILED: %w", err)
	}
	log("✓ BuildBoundary PASSED (gindex-87 next-committee anchor)")

	// (2) poller-timing validation against live mainnet.
	log("polling finality_update for %d min (30 s interval) — validating distinct-slot detection…", dryPollMin)
	captured := c.pollDistinct(dryPollMin, 30, log)
	advances := len(captured) - 1
	if advances < 0 {
		advances = 0
	}
	log("poller saw %d distinct finalized slot(s) = %d advance(s) in %d min", len(captured), advances, dryPollMin)
	if len(captured) < 2 {
		return fmt.Errorf("poller saw %d distinct slot(s) in %d min — need ≥2 (≥1 real advance) to validate advance-detection; re-run a longer -dry-poll-min", len(captured), dryPollMin)
	}
	log("✓ DRY-RUN CLEAN — fetch→parse→verify + the poller both validated")
	return nil
}
