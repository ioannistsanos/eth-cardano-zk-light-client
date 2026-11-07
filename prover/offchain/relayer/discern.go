// Package relayer is the live ZK-bridge relayer daemon: poll Ethereum finality -> discern regular vs
// boundary ON ITS OWN (period arithmetic) -> prove in-process -> submit on Cardano. This file is the
// LOAD-BEARING core — the live regular/boundary DECISION + the committee cache. The relayer is told
// NOTHING about which kind an update is; it derives the verdict from finality progress + the signing
// committee's period vs the bridge's current committee period. (The on-chain validator does no period
// arithmetic, D21 — that decision lives HERE, off-chain.)
package relayer

// SlotsPerPeriod mirrors beacon.SlotsPerPeriod (256 epochs x 32 slots). Kept local so the decision
// logic has no beacon/network import and stays a pure, offline-unit-testable function.
const SlotsPerPeriod = 8192

// PeriodOf is the sync-committee period of a slot.
func PeriodOf(slot uint64) uint64 { return slot / SlotsPerPeriod }

// Decision is the relayer's per-update verdict.
type Decision int

const (
	Skip     Decision = iota // no finality progress (stale / replayed update) — do nothing
	Regular                  // the CURRENT committee signs — a regular update within the period
	Boundary                 // the NEXT committee signs (period rolled over) — rotate + install new next
	Halt                     // signing period is neither current nor current+1 (multi-boundary / anomaly)
)

func (d Decision) String() string {
	switch d {
	case Skip:
		return "SKIP"
	case Regular:
		return "REGULAR"
	case Boundary:
		return "BOUNDARY"
	case Halt:
		return "HALT"
	default:
		return "?"
	}
}

// Cache is the relayer's view of the bridge's committee state — seeded from the LightClientBootstrap +
// the first LightClientUpdate, advanced on every spend. The committee identities are the 32-byte
// Poseidon COMMITMENTS the datum stores + the proof binds, so a Rotate's post-state mirrors the datum's
// (current <- next, next <- new) bit-for-bit.
type Cache struct {
	CurrentPeriod              uint64
	CurrentCommitteeCommitment [32]byte
	NextCommitteeCommitment    [32]byte
	LastFinalizedSlot          uint64
}

// Discern is the live regular/boundary decision — the whole point of the relayer. It is told nothing;
// it derives the verdict from (a) finality progress and (b) the signing committee's period vs the
// bridge's current committee period.
//
//	signatureSlot : the update's signature_slot — the committee that signed is PeriodOf(signatureSlot)
//	finalizedSlot : the update's finalized header slot — must STRICTLY advance, else the update is stale
func (c *Cache) Discern(signatureSlot, finalizedSlot uint64) Decision {
	if finalizedSlot <= c.LastFinalizedSlot {
		return Skip // no progress: a re-fetch of the same latest, or a rollback/replay — never act
	}
	signaturePeriod := PeriodOf(signatureSlot)
	switch {
	case signaturePeriod == c.CurrentPeriod:
		return Regular // current committee signs (proof binds current_committee_commitment)
	case signaturePeriod == c.CurrentPeriod+1:
		return Boundary // the next committee now signs — period rolled over (proof binds next; rotate)
	default:
		// signaturePeriod > current+1 (bridge >1 period behind — multi-boundary, out of scope) OR
		// signaturePeriod < current (an update signed by an already-rotated-out committee). Both anomalies.
		return Halt
	}
}

// AdvanceRegular records a confirmed regular spend: only the finalized slot moves (committees frozen,
// per validation.ak committees_frozen).
func (c *Cache) AdvanceRegular(finalizedSlot uint64) {
	c.LastFinalizedSlot = finalizedSlot
}

// Rotate records a confirmed boundary spend: current <- next (the promotion, validation.ak
// committee_rotated), next <- the new committee (op-6), period++, finalized slot advances. The relayer
// cache's post-rotation state MUST match the on-chain datum's — this is what the post-boundary-regular
// gate verifies (the daemon then sees the rotated-in committee as "current" and resumes regular phases).
func (c *Cache) Rotate(finalizedSlot uint64, newNextCommitteeCommitment [32]byte) {
	c.CurrentCommitteeCommitment = c.NextCommitteeCommitment // promotion: current <- input.next
	c.NextCommitteeCommitment = newNextCommitteeCommitment   // install the new next (proof-bound op-6)
	c.CurrentPeriod++
	c.LastFinalizedSlot = finalizedSlot
}
