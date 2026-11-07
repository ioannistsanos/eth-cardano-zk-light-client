package bls

import (
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
)

// EthereumDST is the sync-committee signature ciphersuite domain-separation tag (RFC 9380:
// SSWU map + random-oracle + proof-of-possession). Reused verbatim from poc_rogue_key — a DST
// mismatch fails silently on real Ethereum signatures, so this string is load-bearing.
var EthereumDST = []byte("BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_")

const (
	// SyncCommitteeSize is the Ethereum sync committee size.
	SyncCommitteeSize = 512
	// ParticipationThreshold is the 2/3 supermajority: ceil(512 * 2/3) = 342.
	ParticipationThreshold = 342
)

// FastAggregateVerify reports whether `signature` is the aggregate BLS signature of the
// 32-byte `message` (a signing root) under the aggregate of `pubkeys` — the Ethereum
// minimal-pubkey convention (pubkeys in G1, signature in G2), message hashed to G2 with
// EthereumDST. The verdict is the CIP-381 finalVerify form e(g1, σ)·e(−apk, H(m)) == 1
// (the same pairing the on-chain Aiken verifier performs). Returns false (nil error) on a
// normal verification failure; a non-nil error only on a malformed hash-to-curve input.
// Performs NO eth2 KeyValidate (an infinity pubkey is admitted) — a recorded, accepted
// divergence; see docs/security/known-divergences.md KD-1.
func FastAggregateVerify(pubkeys []bls12381.G1Affine, message [32]byte, signature bls12381.G2Affine) (bool, error) {
	if len(pubkeys) == 0 {
		return false, nil
	}
	_, _, g1Generator, _ := bls12381.Generators()
	aggregatePublicKey := sumG1(pubkeys)
	hashedMessage, err := bls12381.HashToG2(message[:], EthereumDST)
	if err != nil {
		return false, err
	}
	var negatedApk bls12381.G1Affine
	negatedApk.Neg(&aggregatePublicKey)
	return bls12381.PairingCheck(
		[]bls12381.G1Affine{g1Generator, negatedApk},
		[]bls12381.G2Affine{signature, hashedMessage},
	)
}

// VerifySyncAggregate is the bootstrap's condition (d): select the committee members whose
// participationBits is set, enforce the 2/3 supermajority (count ≥ ParticipationThreshold),
// and FastAggregateVerify the aggregate `signature` over `signingRoot`. Returns (verdict,
// participationCount, error); the verdict is false if the threshold is unmet OR the signature
// does not verify. participationBits is indexed parallel to committee.
func VerifySyncAggregate(committee []bls12381.G1Affine, participationBits []bool, signingRoot [32]byte, signature bls12381.G2Affine) (bool, int, error) {
	participants := make([]bls12381.G1Affine, 0, len(committee))
	for i := range committee {
		if i < len(participationBits) && participationBits[i] {
			participants = append(participants, committee[i])
		}
	}
	count := len(participants)
	if count < ParticipationThreshold {
		return false, count, nil
	}
	verified, err := FastAggregateVerify(participants, signingRoot, signature)
	return verified, count, err
}

// sumG1 aggregates G1 points (the aggregate public key). The zero G1Jac is the point at
// infinity, so an empty sum is the identity.
func sumG1(points []bls12381.G1Affine) bls12381.G1Affine {
	var accumulator bls12381.G1Jac
	for i := range points {
		var pointJacobian bls12381.G1Jac
		pointJacobian.FromAffine(&points[i])
		accumulator.AddAssign(&pointJacobian)
	}
	var result bls12381.G1Affine
	result.FromJacobian(&accumulator)
	return result
}
