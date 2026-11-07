// Package bootstrap is the off-chain genesis establishment for the Phase-A bridge (§2.1.6):
// a trusted weak-subjectivity checkpoint the deployer verifies once and turns into the initial
// datum (the two committee commitments + finalized header root/slot). It is plain Go, NOT a
// circuit and NOT a Groth16 proof — the genesis is trusted, so nothing re-verifies it on-chain;
// the off-chain rigor here (the canonicity of condition (e) and the Poseidon-match) IS the
// soundness.
//
// The five conditions (corrected against §2.1.6) span TWO headers / TWO state roots:
//
//	(a) current_sync_committee (gindex 86) → the BOOTSTRAP header's state_root, AND the
//	    bootstrap header reconstructs to the trusted block_root (the genesis anchor).
//	(b) next_sync_committee (gindex 87)    → the ATTESTED header's state_root.
//	(c) finalized_header (gindex 169)      → the ATTESTED header's state_root.
//	(d) the attested header is signed by the current committee (2/3 threshold, count ≥ 342).
//	(e) the committee identifiers = the per-key Poseidon commitments over CANONICAL keys.
//
// The current committee from (a) signs the update in (d), linking the two headers.
//
// Pre-condition P5 (§3.1.6): compute_sync_committee_period_at_slot(finalized_header.slot) ==
// compute_sync_committee_period_at_slot(signature_slot) — enforced here, before (e), so the
// finalized header persisted in the datum is consistent with the committee that signed it.
//
// (e) DIVERGENCE — intentional, recorded: §2.1.6 as written computes committee_id = Σ pubkeys
// (a G₁ sum). This implementation computes pubkeys_commitment = Poseidon(canonical (x,y)) with
// X canonicity instead — the SEC-01 follow-up-#4 divergence (the G₁ sum lost its consumer when
// SEC-01 dropped op-1; the Poseidon commitment is the committee identity). It is the off-chain
// twin of the in-circuit committeeBindAggregateCount (shared via offchain/commitment), so the
// genesis datum validates against the first regular update (the Poseidon-match).
package bootstrap

import (
	"errors"
	"fmt"
	"math/big"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fp"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"

	"eth-cardano-zk-light-client/prover/offchain/bls"
	"eth-cardano-zk-light-client/prover/offchain/commitment"
	"eth-cardano-zk-light-client/prover/offchain/ssz"
)

// Per-condition rejection sentinels (errors.Is-checkable).
var (
	ErrCurrentCommitteeBranch = errors.New("condition (a): current_sync_committee_branch (gindex 86) does not reach the bootstrap state_root")
	ErrCheckpoint             = errors.New("condition (a): bootstrap header does not reconstruct to the trusted block_root")
	ErrNextCommitteeBranch    = errors.New("condition (b): next_sync_committee_branch (gindex 87) does not reach the attested state_root")
	ErrFinalityBranch         = errors.New("condition (c): finality_branch (gindex 169) does not reach the attested state_root")
	ErrSyncAggregate          = errors.New("condition (d): sync aggregate does not verify or is below the 2/3 threshold")
	ErrNonCanonicalKey        = errors.New("condition (e): non-canonical pubkey coordinate (x ≥ p)")
	ErrPeriodMismatch         = errors.New("pre-condition P5: finalized_header.slot and signature_slot lie in different sync-committee periods")
)

// slotsPerPeriod is SLOTS_PER_EPOCH × EPOCHS_PER_SYNC_COMMITTEE_PERIOD = 32 × 256. Kept local:
// beacon.SlotsPerPeriod is the same constant, but beacon imports this package (capture.go).
const slotsPerPeriod = 8192

// blsBaseFieldModulusMinusOne is p−1 (the BLS12-381 base field), the canonical coordinate
// upper bound — the off-circuit twin of the in-circuit pMinus1 in decompresspubkey.go.
var blsBaseFieldModulusMinusOne = new(big.Int).Sub(fp.Modulus(), big.NewInt(1))

// SyncCommittee is a committee's compressed pubkeys (Vector[Bytes48, 512]) and aggregate_pubkey.
type SyncCommittee struct {
	Pubkeys         [][48]byte
	AggregatePubkey [48]byte
}

// Bootstrap is the genesis witness: the trusted bootstrap header + current committee (a), the
// signed attested header carrying the next committee (b) + finality (c) + the sync aggregate (d).
type Bootstrap struct {
	BootstrapHeader        ssz.Header
	TrustedBlockRoot       [32]byte
	CurrentCommittee       SyncCommittee
	CurrentCommitteeBranch [6][32]byte // gindex 86 → BootstrapHeader.StateRoot

	AttestedHeader      ssz.Header
	NextCommittee       SyncCommittee
	NextCommitteeBranch [6][32]byte // gindex 87 → AttestedHeader.StateRoot

	FinalizedHeader ssz.Header
	FinalityBranch  [7][32]byte // gindex 169 → AttestedHeader.StateRoot

	ParticipationBits     []bool   // sync_committee_bits (current committee signed (d))
	Signature             [96]byte // sync_aggregate signature (compressed G2)
	ForkVersion           [4]byte
	GenesisValidatorsRoot [32]byte
	SignatureSlot         uint64 // update.signature_slot — pre-condition P5 against FinalizedHeader.Slot
}

// Result is the genesis datum the deployer mints on-chain (Phase-3 Aiken): the two committee
// commitments + the initial finalized header root/slot.
type Result struct {
	CurrentPubkeysCommitment fr.Element
	NextPubkeysCommitment    fr.Element
	FinalizedHeaderRoot      [32]byte
	FinalizedSlot            uint64
}

// Verify checks pre-condition P5 and the five §2.1.6 conditions against the witness and returns
// the genesis datum. It returns a per-condition sentinel on the first failure; the datum only on
// full success.
func Verify(input *Bootstrap) (*Result, error) {
	// P5: the finalized header and the signature must share a sync-committee period.
	finalizedPeriod, signaturePeriod := input.FinalizedHeader.Slot/slotsPerPeriod, input.SignatureSlot/slotsPerPeriod
	if finalizedPeriod != signaturePeriod {
		return nil, fmt.Errorf("%w: finalized_header.slot %d (period %d) vs signature_slot %d (period %d)",
			ErrPeriodMismatch, input.FinalizedHeader.Slot, finalizedPeriod, input.SignatureSlot, signaturePeriod)
	}

	// (e) canonicity first: decompress every current + next key, rejecting a non-canonical
	// coordinate (the load-bearing check — a rotten commitment would grief the regular path).
	currentKeys, err := decompressAllCanonical(input.CurrentCommittee.Pubkeys)
	if err != nil {
		return nil, err
	}
	nextKeys, err := decompressAllCanonical(input.NextCommittee.Pubkeys)
	if err != nil {
		return nil, err
	}

	// (a) current committee ∈ the BOOTSTRAP state (gindex 86), and the bootstrap header is the
	// trusted checkpoint.
	currentCommitteeRoot := ssz.SyncCommitteeRoot(
		ssz.PubkeysRoot(input.CurrentCommittee.Pubkeys),
		ssz.Bytes48Root(input.CurrentCommittee.AggregatePubkey),
	)
	if ssz.Gindex86Walk(currentCommitteeRoot, input.CurrentCommitteeBranch) != input.BootstrapHeader.StateRoot {
		return nil, ErrCurrentCommitteeBranch
	}
	if input.BootstrapHeader.HashTreeRoot() != input.TrustedBlockRoot {
		return nil, ErrCheckpoint
	}

	// (b) next committee ∈ the ATTESTED state (gindex 87).
	nextCommitteeRoot := ssz.SyncCommitteeRoot(
		ssz.PubkeysRoot(input.NextCommittee.Pubkeys),
		ssz.Bytes48Root(input.NextCommittee.AggregatePubkey),
	)
	if ssz.Gindex87Walk(nextCommitteeRoot, input.NextCommitteeBranch) != input.AttestedHeader.StateRoot {
		return nil, ErrNextCommitteeBranch
	}

	// (c) finalized header ∈ the ATTESTED state (gindex 169).
	finalizedHeaderRoot := input.FinalizedHeader.HashTreeRoot()
	if ssz.Gindex169Walk(finalizedHeaderRoot, input.FinalityBranch) != input.AttestedHeader.StateRoot {
		return nil, ErrFinalityBranch
	}

	// (d) the current committee signed the attested header (compute_domain → compute_signing_root),
	// with 2/3 participation.
	attestedHeaderRoot := input.AttestedHeader.HashTreeRoot()
	domain := bls.ComputeDomain(bls.DomainSyncCommittee, input.ForkVersion, input.GenesisValidatorsRoot)
	signingRoot := bls.ComputeSigningRoot(attestedHeaderRoot, domain)
	var signature bls12381.G2Affine
	if _, err := signature.SetBytes(input.Signature[:]); err != nil {
		return nil, fmt.Errorf("%w: signature decode: %v", ErrSyncAggregate, err)
	}
	verified, _, err := bls.VerifySyncAggregate(currentKeys, input.ParticipationBits, signingRoot, signature)
	if err != nil || !verified {
		return nil, ErrSyncAggregate
	}

	// (e) the committee commitments over the canonical keys (the Poseidon twin).
	return &Result{
		CurrentPubkeysCommitment: commitment.Commit(currentKeys),
		NextPubkeysCommitment:    commitment.Commit(nextKeys),
		FinalizedHeaderRoot:      finalizedHeaderRoot,
		FinalizedSlot:            input.FinalizedHeader.Slot,
	}, nil
}

// decompressCanonicalPubkey decompresses a compressed G1 pubkey, enforcing X-coordinate
// canonicity (x ≤ p−1) — the off-circuit analogue of op-6's in-circuit
// field.AssertIsLessOrEqual(x, p−1) (SEC-01 F6). The compressed encoding carries x in the low
// 381 bits (the top 3 bits are the compression / infinity / sign flags). The off-chain bootstrap
// never receives y as input (SetBytes recomputes the canonical y), so unlike the in-circuit
// prover it cannot supply a non-canonical y — the F6 y-check has no off-chain analogue.
func decompressCanonicalPubkey(compressed [48]byte) (bls12381.G1Affine, error) {
	var xField [48]byte
	copy(xField[:], compressed[:])
	xField[0] &= 0x1f // clear the 3 flag bits, leaving the 381-bit x-coordinate
	if x := new(big.Int).SetBytes(xField[:]); x.Cmp(blsBaseFieldModulusMinusOne) > 0 {
		return bls12381.G1Affine{}, ErrNonCanonicalKey
	}
	var point bls12381.G1Affine
	if _, err := point.SetBytes(compressed[:]); err != nil {
		return point, fmt.Errorf("%w: decompress: %v", ErrNonCanonicalKey, err)
	}
	return point, nil
}

// DecompressCommittee decompresses a committee's compressed pubkeys with the condition-(e)
// X-canonicity enforcement — EXACTLY the decompression path Verify's prelude runs (it wraps the
// same internal). Exported so cmd/measure_bootstrap times the production path (not a copy) and
// future deployer tooling can reuse it; Verify itself is unchanged.
func DecompressCommittee(compressed [][48]byte) ([]bls12381.G1Affine, error) {
	return decompressAllCanonical(compressed)
}

func decompressAllCanonical(compressed [][48]byte) ([]bls12381.G1Affine, error) {
	keys := make([]bls12381.G1Affine, len(compressed))
	for i := range compressed {
		key, err := decompressCanonicalPubkey(compressed[i])
		if err != nil {
			return nil, fmt.Errorf("%w (key %d)", err, i)
		}
		keys[i] = key
	}
	return keys, nil
}
