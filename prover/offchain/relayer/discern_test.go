package relayer

import "testing"

// The offline decision-gate — the load-bearing core of the live scenario, proven for $0 before any VM
// time. The relayer is told NOTHING; Discern derives regular/boundary/halt/skip from finality progress
// + the signing period vs the cached current period. 5 cases: the two happy paths + the three edges
// (HALT, NO-PROGRESS, POST-BOUNDARY-REGULAR — the last proves the cache rotation actually took effect).

const (
	currentPeriod     = uint64(1600)       // period-1600 (the fixtures' period)
	lastFinalizedSlot = uint64(13_107_200) // period-1600 start (1600 * 8192)
)

// stand-in committee commitments (the discernment is value-independent; the rotation asserts equality).
var (
	committee1600 = [32]byte{0x10, 0x04, 0x1e, 0x8c} // current (period 1600)
	committee1601 = [32]byte{0x48, 0x3e, 0x20, 0xc9} // next (period 1601)
	committee1602 = [32]byte{0xaa, 0xbb, 0xcc, 0xdd} // the op-6 successor installed at the boundary
)

func baseCache() *Cache {
	return &Cache{
		CurrentPeriod:              currentPeriod,
		CurrentCommitteeCommitment: committee1600,
		NextCommitteeCommitment:    committee1601,
		LastFinalizedSlot:          lastFinalizedSlot,
	}
}

// a signature slot inside a given period.
func sigSlotIn(period uint64) uint64 { return period*SlotsPerPeriod + 100 }

// CASE 1 — REGULAR: period-1600 data, current committee signs, finality advances.
func TestDiscern_Regular(t *testing.T) {
	cache := baseCache()
	if got := cache.Discern(sigSlotIn(currentPeriod), lastFinalizedSlot+32); got != Regular {
		t.Fatalf("period-1600 current-signed advance: want REGULAR, got %s", got)
	}
}

// CASE 2 — BOUNDARY + byte-for-byte rotation assert (same rigor as datum.py's boundary gate).
func TestDiscern_BoundaryAndRotation(t *testing.T) {
	cache := baseCache()
	oldNext := cache.NextCommitteeCommitment
	if got := cache.Discern(sigSlotIn(currentPeriod+1), lastFinalizedSlot+32); got != Boundary {
		t.Fatalf("next-committee-signed (period+1): want BOUNDARY, got %s", got)
	}
	cache.Rotate(lastFinalizedSlot+32, committee1602)
	if cache.CurrentCommitteeCommitment != oldNext {
		t.Fatalf("rotation: new current %x != old next %x (current<-next violated)", cache.CurrentCommitteeCommitment, oldNext)
	}
	if cache.NextCommitteeCommitment != committee1602 {
		t.Fatalf("rotation: new next %x != supplied %x", cache.NextCommitteeCommitment, committee1602)
	}
	if cache.CurrentPeriod != currentPeriod+1 {
		t.Fatalf("rotation: period not incremented (got %d, want %d)", cache.CurrentPeriod, currentPeriod+1)
	}
	if cache.LastFinalizedSlot != lastFinalizedSlot+32 {
		t.Fatalf("rotation: finalized slot not advanced (got %d)", cache.LastFinalizedSlot)
	}
}

// CASE 3 — HALT: bridge >1 period behind (multi-boundary, out of scope) — NOT silently a boundary.
func TestDiscern_HaltMultiBoundary(t *testing.T) {
	cache := baseCache()
	if got := cache.Discern(sigSlotIn(currentPeriod+2), lastFinalizedSlot+32); got != Halt {
		t.Fatalf("signing period current+2: want HALT, got %s", got)
	}
}

// CASE 4 — NO-PROGRESS: a stale (==last) or rolled-back (<last) finalized slot → SKIP, no decision/no spend.
func TestDiscern_NoProgressSkips(t *testing.T) {
	cache := baseCache()
	if got := cache.Discern(sigSlotIn(currentPeriod), lastFinalizedSlot); got != Skip {
		t.Fatalf("finalized == last: want SKIP, got %s", got)
	}
	if got := cache.Discern(sigSlotIn(currentPeriod), lastFinalizedSlot-32); got != Skip {
		t.Fatalf("finalized < last (replay/rollback): want SKIP, got %s", got)
	}
}

// CASE 5 — POST-BOUNDARY REGULAR (the sharp one): after a boundary+rotation, an update signed by the
// NEW current (the rotated-in committee, period+1) is REGULAR, not boundary again. This proves the
// cache rotation took effect — a datum-mutated-but-cache-stale bug is caught HERE, offline, for $0.
func TestDiscern_PostBoundaryRegular(t *testing.T) {
	cache := baseCache()
	if got := cache.Discern(sigSlotIn(currentPeriod+1), lastFinalizedSlot+32); got != Boundary {
		t.Fatalf("setup: want BOUNDARY, got %s", got)
	}
	cache.Rotate(lastFinalizedSlot+32, committee1602)
	// the NEW current is the period-(1600+1) committee; an update it signs must read as REGULAR now.
	if got := cache.Discern(sigSlotIn(currentPeriod+1), lastFinalizedSlot+64); got != Regular {
		t.Fatalf("post-boundary: want REGULAR (new current signs), got %s — cache rotation did NOT take effect", got)
	}
	// and a further period+2 update would now be the NEXT boundary (current+1 relative to the rotated cache).
	if got := cache.Discern(sigSlotIn(currentPeriod+2), lastFinalizedSlot+96); got != Boundary {
		t.Fatalf("post-boundary: a period+2 update should now read BOUNDARY (current+1), got %s", got)
	}
}
