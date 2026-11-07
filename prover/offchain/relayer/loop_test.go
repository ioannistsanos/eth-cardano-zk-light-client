package relayer

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

// ── mocks (the loop's two seams) ──

// mockPoller replays a scripted sequence; Next yields the next update whose finalizedSlot advances.
type mockPoller struct {
	updates []*Update
	index   int
}

func (m *mockPoller) Next(since uint64) (*Update, error) {
	for m.index < len(m.updates) {
		u := m.updates[m.index]
		m.index++
		if u.FinalizedSlot > since {
			return u, nil
		}
	}
	return nil, ErrSourceExhausted
}

type execCall struct {
	kind Decision
	slot uint64
}

// mockExecutor returns canned results; failAtSlot != 0 makes it error at that finalized slot.
type mockExecutor struct {
	failAtSlot uint64
	calls      []execCall
}

func (m *mockExecutor) Execute(kind Decision, u *Update) (*ExecResult, error) {
	m.calls = append(m.calls, execCall{kind, u.FinalizedSlot})
	if m.failAtSlot != 0 && u.FinalizedSlot == m.failAtSlot {
		return nil, &mockExecError{slot: u.FinalizedSlot}
	}
	return &ExecResult{
		ProveSeconds: 14.5, SubmitSeconds: 30,
		Spend: &SpendResult{TxHash: "tx_" + strconv.FormatUint(u.FinalizedSlot, 10), ExUnitsSteps: 7_094_172_930, ExUnitsMem: 611_176, FeeLovelace: 995_880, TxSizeBytes: 6676},
	}, nil
}

type mockExecError struct{ slot uint64 }

func (e *mockExecError) Error() string {
	return "mock executor failure at slot " + strconv.FormatUint(e.slot, 10)
}

// the scenario updates: 2 regular (period 1600) → a skipped regular → boundary (period 1601) → 2 regular
// (period 1601). The rollover is placed AFTER reg#2 (the live-scheduling constraint, here deterministic).
func scenarioUpdates() []*Update {
	base := lastFinalizedSlot
	newNext := committee1602
	return []*Update{
		{SignatureSlot: sigSlotIn(currentPeriod), FinalizedSlot: base + 32},                                                   // reg#1
		{SignatureSlot: sigSlotIn(currentPeriod), FinalizedSlot: base + 64},                                                   // reg#2
		{SignatureSlot: sigSlotIn(currentPeriod), FinalizedSlot: base + 96},                                                   // (boundary step) regular → SKIPPED
		{SignatureSlot: sigSlotIn(currentPeriod + 1), FinalizedSlot: base + SlotsPerPeriod + 32, NewNextCommitment: &newNext}, // BOUNDARY (period+1 signs)
		{SignatureSlot: sigSlotIn(currentPeriod + 1), FinalizedSlot: base + SlotsPerPeriod + 64},                              // reg#3 (post-boundary, new current signs)
		{SignatureSlot: sigSlotIn(currentPeriod + 1), FinalizedSlot: base + SlotsPerPeriod + 96},                              // reg#4
	}
}

func newLoop(poller Poller, exec Executor, outDir string, stop func(string)) *Loop {
	return &Loop{
		Poller: poller, Executor: exec,
		Cache:                baseCache(),
		Plan:                 []PlanStep{StepRegular, StepRegular, StepBoundary, StepRegular, StepRegular},
		OutDir:               outDir,
		BoundaryWaitDeadline: time.Hour,
		Stop:                 stop,
	}
}

// GATE 1 — the full 2+1+2 scenario: live discernment, the boundary skips one regular then fires +
// rotates the cache, 2 post-boundary regulars, STATUS confirmed, self-stop once.
func TestLoop_FullScenario(t *testing.T) {
	exec := &mockExecutor{}
	stops := 0
	loop := newLoop(&mockPoller{updates: scenarioUpdates()}, exec, t.TempDir(), func(string) { stops++ })

	if err := loop.Run(); err != nil {
		t.Fatalf("Run: %v", err)
	}

	// the executor saw exactly 5 phases, kinds reg,reg,boundary,reg,reg (the skipped regular NOT executed).
	wantKinds := []Decision{Regular, Regular, Boundary, Regular, Regular}
	if len(exec.calls) != len(wantKinds) {
		t.Fatalf("executor calls: got %d, want %d (%v)", len(exec.calls), len(wantKinds), exec.calls)
	}
	for i, want := range wantKinds {
		if exec.calls[i].kind != want {
			t.Fatalf("phase %d kind: got %s want %s", i, exec.calls[i].kind, want)
		}
	}
	// the skipped regular (slot base+96) was never executed.
	for _, c := range exec.calls {
		if c.slot == lastFinalizedSlot+96 {
			t.Fatalf("the boundary-step regular (slot %d) should have been SKIPPED, not executed", c.slot)
		}
	}
	// the cache rotated on the boundary (current<-next, next<-new, period++).
	if loop.Cache.CurrentPeriod != currentPeriod+1 {
		t.Fatalf("cache period after boundary: got %d want %d", loop.Cache.CurrentPeriod, currentPeriod+1)
	}
	if loop.Cache.CurrentCommitteeCommitment != committee1601 {
		t.Fatalf("cache current after rotation != old next (committee1601)")
	}
	if loop.Cache.NextCommitteeCommitment != committee1602 {
		t.Fatalf("cache next after rotation != installed new next (committee1602)")
	}
	if stops != 1 {
		t.Fatalf("self-stop called %d times, want 1 (scenario complete)", stops)
	}

	// SUMMARY.json: 5 phases, the boundary phase recorded 1 skipped regular.
	var summary summaryFile
	readJSON(t, filepath.Join(loop.OutDir, "SUMMARY.json"), &summary)
	if summary.Completed != 5 || summary.Planned != 5 {
		t.Fatalf("summary: completed %d planned %d, want 5/5", summary.Completed, summary.Planned)
	}
	if summary.Phases[2].Kind != "BOUNDARY" || summary.Phases[2].SkippedRegulars != 1 {
		t.Fatalf("boundary phase record: kind %s skipped %d, want BOUNDARY/1", summary.Phases[2].Kind, summary.Phases[2].SkippedRegulars)
	}
	// STATUS.json: confirmed, 5 completed.
	var status statusFile
	readJSON(t, filepath.Join(loop.OutDir, "STATUS.json"), &status)
	if status.State != "confirmed" || status.Completed != 5 {
		t.Fatalf("status: state %s completed %d, want confirmed/5", status.State, status.Completed)
	}
	t.Logf("FULL SCENARIO GREEN — reg,reg,[skip 1]boundary+rotate(%d→%d),reg,reg; STATUS confirmed 5/5; self-stop once",
		currentPeriod, loop.Cache.CurrentPeriod)
}

// GATE 2 — schedule mismatch: a BOUNDARY at a planned-regular step HALTs (does NOT improvise the count).
func TestLoop_HaltBoundaryAtRegularStep(t *testing.T) {
	base := lastFinalizedSlot
	newNext := committee1602
	updates := []*Update{
		{SignatureSlot: sigSlotIn(currentPeriod), FinalizedSlot: base + 32},                                                   // reg#1 (ok)
		{SignatureSlot: sigSlotIn(currentPeriod + 1), FinalizedSlot: base + SlotsPerPeriod + 32, NewNextCommitment: &newNext}, // boundary at planned-regular phase 2 → HALT
	}
	stopReason := ""
	loop := newLoop(&mockPoller{updates: updates}, &mockExecutor{}, t.TempDir(), func(r string) { stopReason = r })

	err := loop.Run()
	if err == nil {
		t.Fatal("want HALT (boundary at a planned-regular step), got nil")
	}
	if stopReason == "" {
		t.Fatal("self-stop not called on the schedule-mismatch HALT")
	}
	var status statusFile
	readJSON(t, filepath.Join(loop.OutDir, "STATUS.json"), &status)
	if status.State != "halted" || status.Error == "" {
		t.Fatalf("status after HALT: state %s error %q, want halted + an error", status.State, status.Error)
	}
	t.Logf("SCHEDULE-MISMATCH HALT GREEN — boundary at planned-regular step → halted + self-stop, error recorded")
}

// GATE 3 — auto-HALT on a phase failure: the executor errors → the loop halts, saves STATUS, self-stops.
func TestLoop_HaltOnExecutorFailureAndStops(t *testing.T) {
	exec := &mockExecutor{failAtSlot: lastFinalizedSlot + 64} // fail reg#2
	stopReason := ""
	loop := newLoop(&mockPoller{updates: scenarioUpdates()}, exec, t.TempDir(), func(r string) { stopReason = r })

	err := loop.Run()
	if err == nil {
		t.Fatal("want HALT (executor failure), got nil")
	}
	if stopReason == "" {
		t.Fatal("self-stop not called on the executor-failure HALT — a hung VM would result")
	}
	var status statusFile
	readJSON(t, filepath.Join(loop.OutDir, "STATUS.json"), &status)
	if status.State != "halted" || status.Completed != 1 {
		t.Fatalf("status after failure at reg#2: state %s completed %d, want halted/1", status.State, status.Completed)
	}
	t.Logf("AUTO-HALT GREEN — executor failure at reg#2 → halted (1/5 done) + self-stop + error in STATUS")
}

// the regular* updates: 3 regulars (period 1600, ALL spent — a VARIABLE count) → boundary (period 1601)
// → 2 trailing regulars (period 1601). No skip: the regular* step spends each pre-boundary regular.
func regularStarUpdates() []*Update {
	base := lastFinalizedSlot
	newNext := committee1602
	return []*Update{
		{SignatureSlot: sigSlotIn(currentPeriod), FinalizedSlot: base + 32},                                                   // reg#1 (regular* — SPENT)
		{SignatureSlot: sigSlotIn(currentPeriod), FinalizedSlot: base + 64},                                                   // reg#2 (SPENT)
		{SignatureSlot: sigSlotIn(currentPeriod), FinalizedSlot: base + 96},                                                   // reg#3 (SPENT — variable count)
		{SignatureSlot: sigSlotIn(currentPeriod + 1), FinalizedSlot: base + SlotsPerPeriod + 32, NewNextCommitment: &newNext}, // BOUNDARY (the step's exit)
		{SignatureSlot: sigSlotIn(currentPeriod + 1), FinalizedSlot: base + SlotsPerPeriod + 64},                              // reg#4 (trailing)
		{SignatureSlot: sigSlotIn(currentPeriod + 1), FinalizedSlot: base + SlotsPerPeriod + 96},                              // reg#5 (trailing)
	}
}

// GATE 4 — the regular* VARIABLE pre-boundary count: SPEND N regulars (here 3) until the rollover, SPEND
// the boundary (+ rotate the cache byte-for-byte), then the 2 trailing regulars. This is the (C) scenario
// shape "regular*,regular,regular" — the pre-boundary count adapts (not the fixed 2), and the boundary
// stays a distinct watchable phase. The trailing StepRegular guards are unchanged (HALT on a 2nd boundary).
func TestLoop_RegularsUntilBoundary(t *testing.T) {
	exec := &mockExecutor{}
	stops := 0
	loop := &Loop{
		Poller: &mockPoller{updates: regularStarUpdates()}, Executor: exec,
		Cache:                baseCache(),
		Plan:                 []PlanStep{StepRegularsUntilBoundary, StepRegular, StepRegular},
		OutDir:               t.TempDir(),
		BoundaryWaitDeadline: time.Hour,
		Stop:                 func(string) { stops++ },
	}
	if err := loop.Run(); err != nil {
		t.Fatalf("Run: %v", err)
	}

	// 6 phases: 3 regulars SPENT in the regular* step, then the boundary, then 2 trailing regulars.
	wantKinds := []Decision{Regular, Regular, Regular, Boundary, Regular, Regular}
	if len(exec.calls) != len(wantKinds) {
		t.Fatalf("executor calls: got %d, want %d (%v)", len(exec.calls), len(wantKinds), exec.calls)
	}
	for i, want := range wantKinds {
		if exec.calls[i].kind != want {
			t.Fatalf("call %d kind: got %s want %s", i, exec.calls[i].kind, want)
		}
	}
	// the VARIABLE pre-boundary count: 3 regulars SPENT before the boundary (not skipped, not fixed at 2).
	preBoundary := 0
	for _, c := range exec.calls {
		if c.kind == Boundary {
			break
		}
		preBoundary++
	}
	if preBoundary != 3 {
		t.Fatalf("pre-boundary regular count: got %d, want 3 (variable, all SPENT)", preBoundary)
	}
	// cache rotated BYTE-FOR-BYTE (same rigor as the boundary case): current<-old next, next<-new, period++.
	if loop.Cache.CurrentPeriod != currentPeriod+1 {
		t.Fatalf("cache period after boundary: got %d want %d", loop.Cache.CurrentPeriod, currentPeriod+1)
	}
	if loop.Cache.CurrentCommitteeCommitment != committee1601 {
		t.Fatalf("rotation: new current %x != old next %x", loop.Cache.CurrentCommitteeCommitment, committee1601)
	}
	if loop.Cache.NextCommitteeCommitment != committee1602 {
		t.Fatalf("rotation: new next %x != installed %x", loop.Cache.NextCommitteeCommitment, committee1602)
	}
	if stops != 1 {
		t.Fatalf("self-stop called %d times, want 1", stops)
	}

	// SUMMARY: 6 phases; the boundary is the 4th (index 3) — a distinct, watchable Boundary phase.
	var summary summaryFile
	readJSON(t, filepath.Join(loop.OutDir, "SUMMARY.json"), &summary)
	if summary.Completed != 6 {
		t.Fatalf("summary completed: got %d, want 6", summary.Completed)
	}
	for i := 0; i < 3; i++ {
		if summary.Phases[i].Kind != "REGULAR" {
			t.Fatalf("phase %d kind: got %s, want REGULAR", i+1, summary.Phases[i].Kind)
		}
	}
	if summary.Phases[3].Kind != "BOUNDARY" {
		t.Fatalf("phase 4 kind: got %s, want BOUNDARY (the boundary stays a distinct watchable phase)", summary.Phases[3].Kind)
	}
	var status statusFile
	readJSON(t, filepath.Join(loop.OutDir, "STATUS.json"), &status)
	if status.State != "confirmed" || status.Completed != 6 {
		t.Fatalf("status: state %s completed %d, want confirmed/6", status.State, status.Completed)
	}
	t.Logf("REGULAR* GATE GREEN — 3 regulars SPENT (variable) → boundary+rotate(%d→%d) → 2 regulars; 6 phases; STATUS confirmed; self-stop once",
		currentPeriod, loop.Cache.CurrentPeriod)
}

func readJSON(t *testing.T, path string, v any) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if err := json.Unmarshal(raw, v); err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}
}
