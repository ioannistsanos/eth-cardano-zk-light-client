package relayer

import "testing"

// THE SEEDING GATE — the load-bearing offline validation of the live wiring. The relayer's cache
// seeding (bootstrap.Verify -> committee commitments) must reproduce the KNOWN-GOOD period-1600
// commitments BYTE-FOR-BYTE: 10041e8c… (current) / 483e20c9… (next) — the exact values the rehearsal
// bridge carried and gate-1 / D27 accepted on-chain. If the seeding produced different commitments, the
// FIRST live spend (reg#1) would reject after the ~4 h fresh setup — so this is nailed offline here,
// tying the live seeding to the same proven-on-chain instance (the way the BLS helper is tied to
// bls_regular_period1600.json).
func TestSeedCache_Period1600KnownGood(t *testing.T) {
	cache, err := SeedCacheFromFixtures(period1600Bootstrap, period1600Update)
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	const (
		wantCurrent = "10041e8ce930617c420c43546f39dc8d123cec24e199f3f51dfadcb448529e1e"
		wantNext    = "483e20c94d6075d0dd670d9b6fe7144456eecc96fadb501ac719e4473625510f"
		wantPeriod  = uint64(1600)
		wantSlot    = uint64(13_107_200)
	)
	if got := CommitmentHex(cache.CurrentCommitteeCommitment); got != wantCurrent {
		t.Fatalf("current committee commitment: got %s want %s (the known-good gate-1/D27 value)", got, wantCurrent)
	}
	if got := CommitmentHex(cache.NextCommitteeCommitment); got != wantNext {
		t.Fatalf("next committee commitment: got %s want %s", got, wantNext)
	}
	if cache.CurrentPeriod != wantPeriod {
		t.Fatalf("current period: got %d want %d", cache.CurrentPeriod, wantPeriod)
	}
	if cache.LastFinalizedSlot != wantSlot {
		t.Fatalf("finalized slot: got %d want %d", cache.LastFinalizedSlot, wantSlot)
	}
	t.Logf("SEEDING GATE GREEN — seeded current %s… / next %s… (period %d, slot %d) == known-good gate-1/D27 values",
		wantCurrent[:12], wantNext[:12], cache.CurrentPeriod, cache.LastFinalizedSlot)
}
