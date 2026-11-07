package relayer

import (
	"encoding/hex"
	"fmt"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"

	"eth-cardano-zk-light-client/prover/offchain/bls"
	"eth-cardano-zk-light-client/prover/offchain/bootstrap"
)

// BLSRedeemerFields are the per-phase BLS inputs the on-chain redeemer + spend.py need: the
// participating-committee aggregate pubkey (apk, 96 B uncompressed X‖Y), the sync-aggregate signature,
// the participation count, the attested header root, plus the fork/gvr datum anchors. This is the LIVE
// analog of the committed bls_regular_period1600.json — produced from the beacon update + the signing
// committee per phase, and gated byte-identical to that fixture (cmd/export_bls_fixture is the same
// computation; this is its kind-aware, daemon-callable form).
type BLSRedeemerFields struct {
	ApkUncompressed       string // 96 B X‖Y — Σ pubkeys[i] over bits[i]=1 (the SIGNING committee)
	Signature             string // 96 B compressed G2 (sync_aggregate.signature) — passthrough
	Count                 int    // popcount(sync_committee_bits)
	AttestedHeaderRoot    string // 32 B
	ForkVersion           string // 4 B  (datum anchor)
	GenesisValidatorsRoot string // 32 B (datum anchor)
}

// BuildBLSFields aggregates the SIGNING committee's participating pubkeys into the apk + counts them,
// computes the attested root, and HALTs unless the real σ verifies off-chain under that apk AND the
// count meets the 2/3 threshold (so a malformed / under-participated update never reaches a spend). The
// signing committee is input.CurrentCommittee for BOTH kinds: a regular's signer is the current committee;
// a boundary's is the bridge's NEXT (the incoming committee that signed the rollover update) — the live
// buildWitness routes that into CurrentCommittee, and the on-chain verify_boundary binds it as datum.next.
// Mirrors cmd/export_bls_fixture — gated byte-identical to bls_regular_period1600.json.
func BuildBLSFields(input *bootstrap.Bootstrap, kind Decision) (*BLSRedeemerFields, error) {
	// the signing committee is input.CurrentCommittee for both kinds — buildWitness routes the boundary's
	// incoming next here; a regular's is the current. kind stays for the σ-HALT message below.
	keys, err := bootstrap.DecompressCommittee(input.CurrentCommittee.Pubkeys)
	if err != nil {
		return nil, fmt.Errorf("decompress signing committee: %w", err)
	}

	// the participating aggregate (the apk the real sync_aggregate signature verifies under) + count.
	var aggregateJacobian bls12381.G1Jac
	participants := make([]bls12381.G1Affine, 0, len(keys))
	for i := range keys {
		if i < len(input.ParticipationBits) && input.ParticipationBits[i] {
			var keyJacobian bls12381.G1Jac
			keyJacobian.FromAffine(&keys[i])
			aggregateJacobian.AddAssign(&keyJacobian)
			participants = append(participants, keys[i])
		}
	}
	var aggregatePublicKey bls12381.G1Affine
	aggregatePublicKey.FromJacobian(&aggregateJacobian)
	count := len(participants)

	attestedHeaderRoot := input.AttestedHeader.HashTreeRoot()
	domain := bls.ComputeDomain(bls.DomainSyncCommittee, input.ForkVersion, input.GenesisValidatorsRoot)
	signingRoot := bls.ComputeSigningRoot(attestedHeaderRoot, domain)

	var signature bls12381.G2Affine
	if _, err := signature.SetBytes(input.Signature[:]); err != nil {
		return nil, fmt.Errorf("signature decode: %w", err)
	}
	verified, err := bls.FastAggregateVerify(participants, signingRoot, signature)
	if err != nil {
		return nil, fmt.Errorf("FastAggregateVerify: %w", err)
	}
	if !verified {
		return nil, fmt.Errorf("HALT: the σ does not verify off-chain under the aggregated apk (kind=%s)", kind)
	}
	if count < bls.ParticipationThreshold {
		return nil, fmt.Errorf("HALT: participation count %d < threshold %d", count, bls.ParticipationThreshold)
	}

	apkUncompressed := aggregatePublicKey.RawBytes() // 96 B clean X‖Y — the redeemer + fixture form
	return &BLSRedeemerFields{
		ApkUncompressed:       hex.EncodeToString(apkUncompressed[:]),
		Signature:             hex.EncodeToString(input.Signature[:]),
		Count:                 count,
		AttestedHeaderRoot:    hex.EncodeToString(attestedHeaderRoot[:]),
		ForkVersion:           hex.EncodeToString(input.ForkVersion[:]),
		GenesisValidatorsRoot: hex.EncodeToString(input.GenesisValidatorsRoot[:]),
	}, nil
}
