package relayer

// The REAL wiring: LiveRelayer implements both Poller + Executor against the live beacon, the resident
// prover (pk_fresh), and spend.py. It shares beacon state between Next (poll) and Execute (the per-phase
// crypto+submit), so it is one struct. DryRun is the read-only offline validation (real beacon poll →
// discern → witness → BuildBLSFields, NO prove/spend). The witness-build mirrors capture.go's validated
// WriteBootstrapFixture/WriteUpdateFixture → bootstrap.LoadFromFixtures path.
//
// Offline (now): DryRun (regular witness path, real mainnet) + the spend.py shell-out/parse
// (TestRunSpendPyParse) + the seeding gate. VM-tier: Execute's prover.Prove (pk_fresh) + spend.py
// --submit (live bridge); the boundary witness is covered by capture.go's goldenBoundary (the boundary σ
// gap stands).

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"eth-cardano-zk-light-client/prover/offchain/beacon"
	"eth-cardano-zk-light-client/prover/offchain/bootstrap"
	"eth-cardano-zk-light-client/prover/offchain/commitment"
	"eth-cardano-zk-light-client/prover/offchain/proving"
	"eth-cardano-zk-light-client/prover/offchain/ssz"
)

// phaseBeacon is the full beacon data for the phase being executed (set by Next, used by Execute).
type phaseBeacon struct {
	update      *beacon.Update // the finality update (regular) or the LightClientUpdate (boundary)
	nextPubkeys []string       // next committee (regular: the cached period filler; boundary: the new next)
	nextAgg     string
	nextBranch  []string
}

// LiveRelayer is the live Poller + Executor. Prover is nil in dry-run (no prove). The cached bootstrap
// (β) + the period's next committee (the regular-witness branch filler) + fork/gvr are seeded once.
type LiveRelayer struct {
	Client       *beacon.Client
	Prover       *proving.Prover
	ScratchDir   string
	Python       string        // venv python for spend.py
	SpendPy      string        // path to boot/spend.py
	PollInterval time.Duration // finality poll cadence (default 15s)
	Log          func(format string, args ...any)

	bootstrapPath        string   // the written β fixture (cached committee)
	currentSignerPubkeys []string // the committee signing the CURRENT period (β.current at seed; rotates at each boundary)
	cachedNextPubkeys    []string
	cachedNextAgg        string
	cachedNextBranch     []string
	fork, gvr            string
	lastPeriod           uint64
	current              *phaseBeacon // the phase being executed (set by the most recent Next)
}

func (r *LiveRelayer) logf(format string, args ...any) {
	if r.Log != nil {
		r.Log(format, args...)
	}
}

// Seed fetches the genesis bootstrap (β) at bootstrapRoot + its period's next committee + fork/gvr,
// writes the cached β fixture, and returns the seeded Cache (committee commitments via bootstrap.Verify
// — matching the on-chain genesis datum; see SeedCacheFromFixtures + the seeding gate).
func (r *LiveRelayer) Seed(bootstrapRoot string) (*Cache, error) {
	bs, err := r.Client.FetchBootstrap(bootstrapRoot)
	if err != nil {
		return nil, fmt.Errorf("FetchBootstrap(%s): %w", bootstrapRoot, err)
	}
	gen, err := r.Client.FetchGenesis()
	if err != nil {
		return nil, fmt.Errorf("FetchGenesis: %w", err)
	}
	r.gvr = gen.GenesisValidatorsRoot
	r.bootstrapPath = filepath.Join(r.ScratchDir, "relayer_bootstrap.json")
	prov := beacon.Provenance{Source: r.Client.Base, Endpoint: "/bootstrap/" + bootstrapRoot, Note: "relayer seed β"}
	if err := beacon.WriteBootstrapFixture(r.bootstrapPath, bs, bootstrapRoot, prov); err != nil {
		return nil, err
	}

	finality, err := r.Client.FetchFinalityUpdate()
	if err != nil {
		return nil, fmt.Errorf("FetchFinalityUpdate (seed): %w", err)
	}
	finalizedSlot, err := parseUint(finality.FinalizedHeader.Beacon.Slot)
	if err != nil {
		return nil, fmt.Errorf("seed finalized slot: %w", err)
	}
	period := finalizedSlot / beacon.SlotsPerPeriod
	canonical, err := r.Client.FetchUpdate(period)
	if err != nil {
		return nil, fmt.Errorf("FetchUpdate(%d) (seed next committee): %w", period, err)
	}
	sigSlot, err := parseUint(canonical.SignatureSlot)
	if err != nil {
		return nil, fmt.Errorf("seed signature slot: %w", err)
	}
	fork, err := r.Client.FetchForkVersionAtEpoch(sigSlot / beacon.SlotsPerEpoch)
	if err != nil {
		return nil, fmt.Errorf("FetchForkVersionAtEpoch: %w", err)
	}
	r.fork = fork
	// the seed's CURRENT committee signs the regulars of period cache.CurrentPeriod; it rotates to the
	// cached next at each boundary (rotateSigningCommittee).
	r.currentSignerPubkeys = bs.CurrentSyncCommittee.Pubkeys
	r.cachedNextPubkeys = canonical.NextSyncCommittee.Pubkeys
	r.cachedNextAgg = canonical.NextSyncCommittee.AggregatePubkey
	r.cachedNextBranch = canonical.NextSyncCommitteeBranch

	alphaPath := filepath.Join(r.ScratchDir, "relayer_seed_update.json")
	provU := beacon.Provenance{Source: r.Client.Base, Period: period, Note: "relayer seed α"}
	if err := beacon.WriteUpdateFixture(alphaPath, canonical, r.cachedNextPubkeys, r.cachedNextAgg,
		r.cachedNextBranch, fork, r.gvr, provU); err != nil {
		return nil, err
	}
	cache, err := SeedCacheFromFixtures(r.bootstrapPath, alphaPath)
	if err != nil {
		return nil, err
	}
	r.lastPeriod = cache.CurrentPeriod
	return cache, nil
}

// DeriveCurrentCheckpoint returns a current finalized block root usable as a bootstrap checkpoint — for
// the dry-run, which has no scenario Boot to take a root from. Mirrors capture.go: latest finalized
// period → its canonical update → the finalized header's SSZ root (0x-hex).
func DeriveCurrentCheckpoint(client *beacon.Client) (string, error) {
	fu, err := client.FetchFinalityUpdate()
	if err != nil {
		return "", err
	}
	finalizedSlot, err := parseUint(fu.FinalizedHeader.Beacon.Slot)
	if err != nil {
		return "", err
	}
	canonical, err := client.FetchUpdate(finalizedSlot / beacon.SlotsPerPeriod)
	if err != nil {
		return "", err
	}
	root, err := finalizedRoot(canonical)
	if err != nil {
		return "", err
	}
	return "0x" + hex.EncodeToString(root[:]), nil
}

// Next polls finality until an ADVANCING update appears; on a period rollover it fetches the new
// period's LightClientUpdate (the new next committee for op-6) + computes its commitment. Returns the
// orchestration Update; sets r.current (the beacon data Execute will use).
func (r *LiveRelayer) Next(sinceFinalizedSlot uint64) (*Update, error) {
	for {
		fu, err := r.Client.FetchFinalityUpdate()
		if err != nil {
			r.logf("poll error (retrying): %v", err)
			time.Sleep(5 * time.Second)
			continue
		}
		finalizedSlot, err := parseUint(fu.FinalizedHeader.Beacon.Slot)
		if err != nil {
			return nil, fmt.Errorf("finalized slot: %w", err)
		}
		if finalizedSlot <= sinceFinalizedSlot {
			interval := r.PollInterval
			if interval <= 0 {
				interval = 15 * time.Second
			}
			time.Sleep(interval)
			continue
		}
		sigSlot, err := parseUint(fu.SignatureSlot)
		if err != nil {
			return nil, fmt.Errorf("signature slot: %w", err)
		}
		root, err := finalizedRoot(fu)
		if err != nil {
			return nil, fmt.Errorf("finalized root: %w", err)
		}
		u := &Update{SignatureSlot: sigSlot, FinalizedSlot: finalizedSlot, FinalizedRoot: root}

		if period := sigSlot / beacon.SlotsPerPeriod; period > r.lastPeriod {
			canonical, ferr := r.Client.FetchUpdate(period)
			if ferr != nil {
				return nil, fmt.Errorf("FetchUpdate(%d) on rollover: %w", period, ferr)
			}
			commit, cerr := committeeCommitment(canonical.NextSyncCommittee.Pubkeys)
			if cerr != nil {
				return nil, fmt.Errorf("new next commitment: %w", cerr)
			}
			u.NewNextCommitment = &commit
			r.current = &phaseBeacon{update: canonical, nextPubkeys: canonical.NextSyncCommittee.Pubkeys,
				nextAgg: canonical.NextSyncCommittee.AggregatePubkey, nextBranch: canonical.NextSyncCommitteeBranch}
			r.lastPeriod = period
		} else {
			r.current = &phaseBeacon{update: fu, nextPubkeys: r.cachedNextPubkeys,
				nextAgg: r.cachedNextAgg, nextBranch: r.cachedNextBranch}
		}
		return u, nil
	}
}

// buildWitness writes the per-phase α from r.current + loads (β, α) into a *bootstrap.Bootstrap.
func (r *LiveRelayer) buildWitness(kind Decision) (*bootstrap.Bootstrap, error) {
	if r.current == nil {
		return nil, fmt.Errorf("no current beacon data (Next not called)")
	}
	alphaPath := filepath.Join(r.ScratchDir, "relayer_phase_update.json")
	prov := beacon.Provenance{Source: r.Client.Base, Note: "relayer phase α (" + kind.String() + ")"}
	if err := beacon.WriteUpdateFixture(alphaPath, r.current.update, r.current.nextPubkeys,
		r.current.nextAgg, r.current.nextBranch, r.fork, r.gvr, prov); err != nil {
		return nil, err
	}
	input, _, err := bootstrap.LoadFromFixtures(r.bootstrapPath, alphaPath)
	if err != nil {
		return nil, fmt.Errorf("LoadFromFixtures: %w", err)
	}
	// route the phase's signing committee into input.CurrentCommittee (β from LoadFromFixtures is frozen
	// at the seed period; a boundary's signer is the incoming next, not β.current).
	if err := applySigningCommittee(input, kind, r.currentSignerPubkeys, r.cachedNextPubkeys); err != nil {
		return nil, err
	}
	return input, nil
}

// compressedKeysFromHex parses 0x-prefixed compressed-pubkey hexes (the beacon/cache form) into the
// [][48]byte the bootstrap.SyncCommittee carries.
func compressedKeysFromHex(pubkeys []string) ([][48]byte, error) {
	out := make([][48]byte, len(pubkeys))
	for i, pk := range pubkeys {
		raw, err := hex.DecodeString(strings.TrimPrefix(pk, "0x"))
		if err != nil {
			return nil, fmt.Errorf("pubkey %d hex: %w", i, err)
		}
		if len(raw) != 48 {
			return nil, fmt.Errorf("pubkey %d: want 48 bytes, got %d", i, len(raw))
		}
		copy(out[i][:], raw)
	}
	return out, nil
}

// applySigningCommittee routes the phase's SIGNING committee into input.CurrentCommittee — the apk-source
// BuildRegular (proof apk + pubkeys_commitment) and BuildBLSFields both read. A regular's signer is the
// tracked current committee; a boundary's is the bridge's NEXT (the incoming committee that signed the
// rollover update = datum.next). LoadFromFixtures' β is frozen at the seed period, so this override keeps
// the witness correct across rotations — and makes the proof's pubkeys_commitment equal datum.next, which
// the on-chain verify_boundary binds.
func applySigningCommittee(input *bootstrap.Bootstrap, kind Decision, currentSigner, cachedNext []string) error {
	signerHex := currentSigner
	if kind == Boundary {
		signerHex = cachedNext
	}
	keys, err := compressedKeysFromHex(signerHex)
	if err != nil {
		return fmt.Errorf("signing committee: %w", err)
	}
	input.CurrentCommittee.Pubkeys = keys
	return nil
}

// rotateSigningCommittee promotes the just-confirmed boundary's committees — the pubkey-side twin of the
// loop's Cache.Rotate: the incoming next becomes the current signer; the boundary update's next becomes
// the new cached next. Called ONLY after a boundary spend confirms (a failed boundary must not rotate).
func (r *LiveRelayer) rotateSigningCommittee() {
	r.currentSignerPubkeys = r.cachedNextPubkeys
	r.cachedNextPubkeys = r.current.nextPubkeys
	r.cachedNextAgg = r.current.nextAgg
	r.cachedNextBranch = r.current.nextBranch
}

// Execute runs one phase: witness → prover.Prove → BuildBLSFields → spend.py --submit. VM-tier.
func (r *LiveRelayer) Execute(kind Decision, u *Update) (*ExecResult, error) {
	input, err := r.buildWitness(kind)
	if err != nil {
		return nil, fmt.Errorf("witness: %w", err)
	}
	proveStart := time.Now()
	proof, err := r.Prover.Prove(toCircuitKind(kind), input)
	proveSeconds := time.Since(proveStart).Seconds()
	if err != nil {
		return nil, fmt.Errorf("prove: %w", err)
	}
	fields, err := BuildBLSFields(input, kind)
	if err != nil {
		return nil, fmt.Errorf("bls fields: %w", err)
	}
	submitStart := time.Now()
	spend, err := r.runSpendPy(kind, u, fields, proof)
	if err != nil {
		return nil, fmt.Errorf("spend.py: %w", err)
	}
	if kind == Boundary {
		// the boundary confirmed: rotate the signing committee so the trailing regulars (now signed by
		// the promoted committee) verify. AFTER the spend — a failed boundary must not rotate.
		r.rotateSigningCommittee()
	}
	return &ExecResult{ProveSeconds: proveSeconds, SubmitSeconds: time.Since(submitStart).Seconds(), Spend: spend}, nil
}

func toCircuitKind(kind Decision) proving.CircuitKind {
	if kind == Boundary {
		return proving.Boundary
	}
	return proving.Regular
}

// DryRun is the read-only offline validation: seed from real mainnet, then poll `phases` advancing
// updates and for each run Discern → witness-build → BuildBLSFields — NO prove, NO spend. Validates the
// real beacon→discern→witness→BLS wiring. (Regulars only in practice; a rollover is ~27 h away.)
func (r *LiveRelayer) DryRun(bootstrapRoot string, phases int) error {
	cache, err := r.Seed(bootstrapRoot)
	if err != nil {
		return fmt.Errorf("seed: %w", err)
	}
	r.logf("seeded: period %d, current %s…, finalized slot %d", cache.CurrentPeriod,
		CommitmentHex(cache.CurrentCommitteeCommitment)[:12], cache.LastFinalizedSlot)
	for i := 0; i < phases; i++ {
		u, err := r.Next(cache.LastFinalizedSlot)
		if err != nil {
			return fmt.Errorf("phase %d poll: %w", i, err)
		}
		decision := cache.Discern(u.SignatureSlot, u.FinalizedSlot)
		input, err := r.buildWitness(decision)
		if err != nil {
			return fmt.Errorf("phase %d witness: %w", i, err)
		}
		fields, err := BuildBLSFields(input, decision)
		if err != nil {
			return fmt.Errorf("phase %d bls: %w", i, err)
		}
		r.logf("dry phase %d: %s slot %d, apk %s…, count %d (witness+BLS OK; no prove/spend)",
			i, decision, u.FinalizedSlot, fields.ApkUncompressed[:12], fields.Count)
		cache.AdvanceRegular(u.FinalizedSlot)
	}
	r.logf("DRY-RUN CLEAN — %d phases poll→discern→witness→BuildBLSFields, no prove/spend", phases)
	return nil
}

// runSpendPy writes proof_redeemer.json + bls.json, shells out spend.py --submit --emit-json, parses
// the RELAYER_JSON line into a SpendResult.
func (r *LiveRelayer) runSpendPy(kind Decision, u *Update, fields *BLSRedeemerFields, proof *proving.PhaseProof) (*SpendResult, error) {
	proofPath := filepath.Join(r.ScratchDir, "proof_redeemer.json")
	blsPath := filepath.Join(r.ScratchDir, "bls.json")
	if err := writeJSONFile(proofPath, map[string]any{"proof_redeemer": map[string]string{
		"a": proof.A, "b": proof.B, "c": proof.C, "commitment": proof.Commitment, "commitment_pok": proof.CommitmentPok,
	}}); err != nil {
		return nil, err
	}
	if err := writeJSONFile(blsPath, map[string]any{
		"apk_uncompressed": fields.ApkUncompressed, "signature": fields.Signature, "count": fields.Count,
		"attested_header_root": fields.AttestedHeaderRoot, "fork_version": fields.ForkVersion,
		"genesis_validators_root": fields.GenesisValidatorsRoot,
	}); err != nil {
		return nil, err
	}
	args := []string{r.SpendPy, "--submit", "--emit-json", "--kind", strings.ToLower(kind.String()),
		"--finalized-root", hex.EncodeToString(u.FinalizedRoot[:]),
		"--finalized-slot", strconv.FormatUint(u.FinalizedSlot, 10), "--proof", proofPath, "--bls", blsPath}
	if kind == Boundary && u.NewNextCommitment != nil {
		args = append(args, "--next-commitment", hex.EncodeToString(u.NewNextCommitment[:]))
	}
	out, err := exec.Command(r.Python, args...).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("spend.py failed: %w\n%s", err, out)
	}
	return parseSpendJSON(string(out))
}

// parseSpendJSON extracts the RELAYER_JSON line spend.py --emit-json prints into a SpendResult.
func parseSpendJSON(output string) (*SpendResult, error) {
	for _, line := range strings.Split(output, "\n") {
		if rest, ok := strings.CutPrefix(strings.TrimSpace(line), "RELAYER_JSON "); ok {
			var s SpendResult
			if err := json.Unmarshal([]byte(rest), &s); err != nil {
				return nil, fmt.Errorf("parse RELAYER_JSON: %w", err)
			}
			return &s, nil
		}
	}
	return nil, fmt.Errorf("no RELAYER_JSON line in spend.py output:\n%s", output)
}

func writeJSONFile(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o644)
}

// ── small helpers ──

// committeeCommitment is Poseidon over the committee's decompressed pubkeys — the 32-byte commitment the
// datum stores + the proof binds (commitment.Commit, the same path bootstrap.Verify uses). The beacon
// gives compressed pubkeys as hex strings; decode each to the 48-byte form DecompressCommittee expects.
func committeeCommitment(compressedPubkeys []string) ([32]byte, error) {
	raw := make([][48]byte, len(compressedPubkeys))
	for i, s := range compressedPubkeys {
		b, err := hex.DecodeString(strings.TrimPrefix(s, "0x"))
		if err != nil {
			return [32]byte{}, fmt.Errorf("pubkey %d: %w", i, err)
		}
		if len(b) != 48 {
			return [32]byte{}, fmt.Errorf("pubkey %d: want 48 bytes, got %d", i, len(b))
		}
		copy(raw[i][:], b)
	}
	keys, err := bootstrap.DecompressCommittee(raw)
	if err != nil {
		return [32]byte{}, err
	}
	fe := commitment.Commit(keys)
	return fe.Bytes(), nil
}

// finalizedRoot is the SSZ hash_tree_root of an update's finalized header (mirrors capture.go).
func finalizedRoot(u *beacon.Update) ([32]byte, error) {
	h := u.FinalizedHeader.Beacon
	slot, err := parseUint(h.Slot)
	if err != nil {
		return [32]byte{}, err
	}
	proposer, err := parseUint(h.ProposerIndex)
	if err != nil {
		return [32]byte{}, err
	}
	parent, err := hex32(h.ParentRoot)
	if err != nil {
		return [32]byte{}, err
	}
	state, err := hex32(h.StateRoot)
	if err != nil {
		return [32]byte{}, err
	}
	body, err := hex32(h.BodyRoot)
	if err != nil {
		return [32]byte{}, err
	}
	return ssz.Header{Slot: slot, ProposerIndex: proposer, ParentRoot: parent, StateRoot: state, BodyRoot: body}.HashTreeRoot(), nil
}

func parseUint(s string) (uint64, error) { return strconv.ParseUint(s, 10, 64) }

func hex32(s string) ([32]byte, error) {
	var out [32]byte
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
