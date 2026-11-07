package relayer

// The orchestration loop — the relayer daemon's main loop, COMPOSING the already-proven parts. It is
// pure orchestration (NO crypto imports): it walks the scripted plan, polls for advancing finality,
// discerns each update LIVE, runs the per-phase crypto+submit via an injected Executor, rotates the
// cache on a boundary, records D26/D27/D28, and self-stops. The two injected seams (Poller, Executor)
// make the whole flow offline-testable with mocks — the real Poller is the beacon poll; the real
// Executor is the witness->Prove->BuildBLSFields->spend.py pipeline (each proven separately: capture
// DryRun, prover toy-equivalence, the BLS-field gate, the D27 on-chain spend).
//
// ── LIVE SCHEDULING (VM-tier, the (C) scenario — see docs/c-runbook.md §2) ──
// The plan is "regular*,regular,regular": StepRegularsUntilBoundary ("regular*") SPENDS advancing
// regulars until it detects + spends the rollover (the VARIABLE pre-boundary count), then the two
// trailing StepRegular steps. The pre-boundary run is OPEN-ENDED — a boundary there is EXPECTED (the
// step's exit) — so "started too close to B → HALT" no longer applies to it; the operator only needs to
// BIRTH the relayer BEFORE the boundary B (regular* is forgiving on the early side). The guards stay
// intact: a trailing StepRegular HALTs on an UNEXPECTED (second) boundary; a discern Halt (multi-
// boundary) still HALTs. Cadence ~6m31s/advance (S1) → birth ~30-90 min before B does ~4-12 regulars.

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Update is the orchestration-relevant projection of a beacon finality / light-client update.
type Update struct {
	SignatureSlot     uint64
	FinalizedSlot     uint64
	FinalizedRoot     [32]byte
	NewNextCommitment *[32]byte // boundary only — the op-6 successor committee commitment to install
}

// ErrSourceExhausted: the poller has no further advancing update (a mock end, or a real poll deadline).
var ErrSourceExhausted = fmt.Errorf("update source exhausted")

// Poller yields the next ADVANCING finality update (finalizedSlot > since). Real impl: poll
// beacon.FetchFinalityUpdate every interval. Mock: replay a scripted sequence.
type Poller interface {
	Next(sinceFinalizedSlot uint64) (*Update, error)
}

// SpendResult is spend.py's on-chain outcome (D27), parsed from its output.
type SpendResult struct {
	TxHash       string `json:"tx_hash"`
	ExUnitsSteps uint64 `json:"ex_units_steps"`
	ExUnitsMem   uint64 `json:"ex_units_mem"`
	FeeLovelace  uint64 `json:"fee_lovelace"`
	TxSizeBytes  int    `json:"tx_size_bytes"`
}

// ExecResult is one phase's crypto+submit outcome (the measured parts) the Executor returns.
type ExecResult struct {
	ProveSeconds  float64
	SubmitSeconds float64
	Spend         *SpendResult
}

// Executor runs one phase's witness-build -> Prove -> BuildBLSFields -> spend.py --submit. Real impl
// wires those; a mock returns a canned ExecResult (or an error, exercising the auto-HALT path) — so the
// orchestration is proven without pk, a live bridge, or a boundary σ fixture.
type Executor interface {
	Execute(kind Decision, update *Update) (*ExecResult, error)
}

// PhaseResult is one completed phase's full record: D26 (relayer timing) + D27 (on-chain) + D28 (decision).
type PhaseResult struct {
	Index             int          `json:"plan_step_index"` // the PLAN step it came from (regular* shares one)
	Kind              string       `json:"kind"`
	FinalizedSlot     uint64       `json:"finalized_slot"`
	SignaturePeriod   uint64       `json:"signature_period"`
	SkippedRegulars   int          `json:"skipped_regulars"` // regulars skipped while waiting (StepBoundary only)
	PollDetectSeconds float64      `json:"poll_detect_seconds"`
	ProveSeconds      float64      `json:"prove_seconds"`
	SubmitSeconds     float64      `json:"submit_seconds"`
	TotalSeconds      float64      `json:"total_seconds"`
	CompletedUnix     int64        `json:"completed_unix"` // absolute wall-clock the record was built (the lab-log timestamp)
	CachePeriodAfter  uint64       `json:"cache_period_after"`
	Spend             *SpendResult `json:"spend"`
	// boundary only (omitempty → absent on regular phases), captured BEFORE Cache.Rotate mutates the
	// cache: rotated_promoted_current = the pre-rotation next (becomes output.current); rotated_new_next
	// = the proof-bound op-6 new next (becomes output.next).
	RotatedNewNext         string `json:"rotated_new_next,omitempty"`
	RotatedPromotedCurrent string `json:"rotated_promoted_current,omitempty"`
}

// PlanStep is one entry of the scripted plan (the scenario's COUNT/shape; each per-update DECISION is the
// relayer's live Discern). A step may confirm 1+ phases: StepRegularsUntilBoundary confirms N regulars +
// the boundary.
type PlanStep int

const (
	StepRegular               PlanStep = iota // one regular phase; HALT on an UNEXPECTED boundary
	StepBoundary                              // wait (SKIP advancing regulars) for the rollover, then one boundary
	StepRegularsUntilBoundary                 // "regular*": SPEND advancing regulars until the rollover, then SPEND it
)

func (s PlanStep) String() string {
	switch s {
	case StepRegular:
		return "regular"
	case StepBoundary:
		return "boundary"
	case StepRegularsUntilBoundary:
		return "regular*"
	default:
		return "?"
	}
}

// Loop is the relayer's main loop. Poller + Executor are injected (mocked in the gate, real on the VM).
// Stop is the self-stop hook (the cmd wires `sudo shutdown -h now`; nil = safe no-op, so the library
// never shuts a machine down by itself + the gate records the stop without shutting down).
type Loop struct {
	Poller               Poller
	Executor             Executor
	Cache                *Cache
	Plan                 []PlanStep
	OutDir               string
	BoundaryWaitDeadline time.Duration
	Log                  func(format string, args ...any) // heartbeat / progress
	Stop                 func(reason string)              // self-stop (VM: sudo shutdown; tests: record-only)
}

func (l *Loop) logf(format string, args ...any) {
	if l.Log != nil {
		l.Log(format, args...)
	}
}

func (l *Loop) stop(reason string) {
	if l.Stop != nil {
		l.Stop(reason)
		return
	}
	l.logf("STOP requested (%s) — no Stop handler wired; not self-stopping", reason)
}

// Run walks the plan; each step polls -> discerns -> (matches the step, HALTs, or waits) -> executes ->
// rotates/advances the cache -> records EACH confirmed phase live (STATUS + phase-N.json). A regular*
// step confirms multiple phases. On ANY failure: HALT, save the partial state, self-stop, return the
// error. On completion: SUMMARY + self-stop + nil. The operator returns to an N-phase SUMMARY or a
// STATUS.json with the exact halt cause — never a silently-spinning VM.
func (l *Loop) Run() error {
	var records []PhaseResult
	currentStep := ""
	confirm := func(r PhaseResult) {
		records = append(records, r)
		l.writeJSON(fmt.Sprintf("phase-%d.json", len(records)), r)
		l.writeStatus(len(records), currentStep, "confirmed", lastTx(records), "")
		l.logf("phase %d CONFIRMED: %s slot %d, prove %.1fs, tx %s",
			len(records), r.Kind, r.FinalizedSlot, r.ProveSeconds, spendTx(r.Spend))
	}
	proving := func() { l.writeStatus(len(records), currentStep, "proving", lastTx(records), "") }

	for i, step := range l.Plan {
		currentStep = step.String()
		l.writeStatus(len(records), currentStep, "polling", lastTx(records), "")
		if err := l.runStep(i, step, proving, confirm); err != nil {
			l.writeStatus(len(records), currentStep, "halted", lastTx(records), err.Error())
			l.logf("HALT at step %d/%d (%s): %v", i+1, len(l.Plan), step, err)
			l.stop(fmt.Sprintf("HALT at step %d/%d: %v", i+1, len(l.Plan), err))
			return err
		}
	}
	l.writeJSON("SUMMARY.json", summaryOf(records, len(l.Plan)))
	l.logf("SCENARIO COMPLETE: %d phases over %d plan steps", len(records), len(l.Plan))
	l.stop(fmt.Sprintf("scenario complete: %d phases / %d steps", len(records), len(l.Plan)))
	return nil
}

// runStep handles the three plan-step types. proving() marks the mid-phase STATUS; confirm() records a
// completed phase (a step may confirm MULTIPLE — regular* spends N regulars + the boundary). The plan is
// a GUARD (StepRegular HALTs on an unexpected boundary); the discernment is the live decision.
func (l *Loop) runStep(index int, step PlanStep, proving func(), confirm func(PhaseResult)) error {
	stepStart := time.Now()
	deadline := stepStart.Add(l.BoundaryWaitDeadline)
	phaseStart := time.Now()
	skipped := 0
	for {
		update, err := l.Poller.Next(l.Cache.LastFinalizedSlot)
		if err != nil {
			return fmt.Errorf("poll at step %d: %w", index, err)
		}
		decision := l.Cache.Discern(update.SignatureSlot, update.FinalizedSlot)
		if decision == Skip {
			continue // non-advancing — the poller should only yield advancing updates; guard + re-poll
		}
		if decision == Halt {
			return fmt.Errorf("step %d: discern HALT (signing period neither current nor current+1) at slot %d", index, update.FinalizedSlot)
		}

		switch step {
		case StepRegular:
			if decision == Boundary {
				return fmt.Errorf("step %d: BOUNDARY at a planned-regular step (slot %d) — unexpected rollover; reschedule with more lead", index, update.FinalizedSlot)
			}
			result, err := l.execute(index, Regular, update, 0, phaseStart, proving)
			if err != nil {
				return err
			}
			confirm(*result)
			return nil

		case StepBoundary:
			if decision == Regular {
				skipped++
				l.logf("step %d: waiting for boundary — skipped regular slot %d (skipped=%d, +%s)",
					index, update.FinalizedSlot, skipped, time.Since(stepStart).Round(time.Second))
				if time.Now().After(deadline) {
					return fmt.Errorf("step %d: boundary not seen within %s (skipped %d regulars)", index, l.BoundaryWaitDeadline, skipped)
				}
				continue
			}
			result, err := l.execute(index, Boundary, update, skipped, phaseStart, proving)
			if err != nil {
				return err
			}
			confirm(*result)
			return nil

		case StepRegularsUntilBoundary:
			// EXPECTED open-ended regular run; each regular is SPENT; the boundary is the step's exit.
			result, err := l.execute(index, decision, update, 0, phaseStart, proving)
			if err != nil {
				return err
			}
			confirm(*result)
			if decision == Boundary {
				return nil // the rollover: spent + rotated (in execute) → advance to the next plan step
			}
			phaseStart = time.Now() // the next regular times from its own start
			if time.Now().After(deadline) {
				return fmt.Errorf("step %d: boundary not seen within %s", index, l.BoundaryWaitDeadline)
			}
			continue

		default:
			return fmt.Errorf("step %d: unknown plan step %d", index, step)
		}
	}
}

func (l *Loop) execute(index int, kind Decision, update *Update, skipped int, phaseStart time.Time, proving func()) (*PhaseResult, error) {
	pollDetect := time.Since(phaseStart).Seconds()
	proving()
	exec, err := l.Executor.Execute(kind, update)
	if err != nil {
		return nil, fmt.Errorf("step %d execute (%s, slot %d): %w", index, kind, update.FinalizedSlot, err)
	}
	var rotatedNewNext, rotatedPromotedCurrent string
	if kind == Boundary {
		if update.NewNextCommitment == nil {
			return nil, fmt.Errorf("step %d: boundary update missing the new next committee commitment", index)
		}
		// capture the rotation values BEFORE Rotate mutates the cache: the promoted-current is the
		// pre-rotation NEXT commitment (→ output.current); the new next is the proof-bound op-6 value.
		rotatedPromotedCurrent = CommitmentHex(l.Cache.NextCommitteeCommitment)
		rotatedNewNext = CommitmentHex(*update.NewNextCommitment)
		l.Cache.Rotate(update.FinalizedSlot, *update.NewNextCommitment)
	} else {
		l.Cache.AdvanceRegular(update.FinalizedSlot)
	}
	return &PhaseResult{
		Index: index, Kind: kind.String(), FinalizedSlot: update.FinalizedSlot,
		SignaturePeriod: PeriodOf(update.SignatureSlot), SkippedRegulars: skipped,
		PollDetectSeconds: pollDetect, ProveSeconds: exec.ProveSeconds, SubmitSeconds: exec.SubmitSeconds,
		TotalSeconds: time.Since(phaseStart).Seconds(), CachePeriodAfter: l.Cache.CurrentPeriod,
		CompletedUnix:  time.Now().Unix(),
		RotatedNewNext: rotatedNewNext, RotatedPromotedCurrent: rotatedPromotedCurrent,
		Spend: exec.Spend,
	}, nil
}

// ── status / records (the unattended-run surface) ──

type statusFile struct {
	Completed   int    `json:"completed"`   // phases confirmed so far
	TotalSteps  int    `json:"total_steps"` // len(Plan) — note a regular* step yields a VARIABLE phase count
	PlanStep    string `json:"plan_step"`   // the current plan step (regular* / regular / boundary)
	State       string `json:"state"`       // polling | proving | confirmed | halted
	LastTx      string `json:"last_tx,omitempty"`
	Error       string `json:"error,omitempty"`
	UpdatedUnix int64  `json:"updated_unix"`
}

func (l *Loop) writeStatus(completed int, planStep, state, lastTx, errMsg string) {
	l.writeJSON("STATUS.json", statusFile{
		Completed: completed, TotalSteps: len(l.Plan), PlanStep: planStep,
		State: state, LastTx: lastTx, Error: errMsg, UpdatedUnix: time.Now().Unix(),
	})
}

func lastTx(records []PhaseResult) string {
	if n := len(records); n > 0 && records[n-1].Spend != nil {
		return records[n-1].Spend.TxHash
	}
	return ""
}

type summaryFile struct {
	Completed int           `json:"completed"`
	Planned   int           `json:"plan_steps"`
	Phases    []PhaseResult `json:"phases"`
}

func summaryOf(records []PhaseResult, planSteps int) summaryFile {
	return summaryFile{Completed: len(records), Planned: planSteps, Phases: records}
}

func (l *Loop) writeJSON(name string, v any) {
	if l.OutDir == "" {
		return
	}
	encoded, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		l.logf("marshal %s: %v", name, err)
		return
	}
	if err := os.WriteFile(filepath.Join(l.OutDir, name), append(encoded, '\n'), 0o644); err != nil {
		l.logf("write %s: %v", name, err)
	}
}

func spendTx(s *SpendResult) string {
	if s == nil {
		return "(none)"
	}
	return s.TxHash
}
