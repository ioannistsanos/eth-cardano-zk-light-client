// Package witness builds the FULL-SIZE (N=512) REAL Groth16 witnesses for the assembled
// Phase-A circuits from the curated period-1600 fixtures — the stage-3 (AWS proving)
// prerequisite. Pure data transformation: a loaded bootstrap.Bootstrap (the one struct that
// already carries every needed field — bootstrap.LoadFromFixtures) → a circuit assignment,
// through the SAME production primitives the bootstrap pipeline validated
// (bootstrap.DecompressCommittee, commitment.Commit/FoldFp, the offchain/ssz twins).
//
// CURRENT vs NEXT — do not conflate (the role-semantics honesty boundary):
//   - The REGULAR witness's signers are the CURRENT committee (β's gindex-86 committee) with
//     the update's REAL sync_committee_bits — the keys that actually signed the attested
//     header (the σ-under-apk check in witness_test proves it cryptographically).
//   - The BOUNDARY witness built from the period-1600 fixtures is the period-1600 update
//     AS-IS: signers = current@1600 (the actual signers of THIS attested header), op-6
//     installs next@1601 from the SAME attested state. That is structurally a complete,
//     fully-real BoundaryCircuit instance — VALID for the stage-2/3 measurements (constraint
//     count, setup, proving time/memory are role-independent). It is NOT a rotation-shaped
//     transaction for a period-1600-bootstrapped datum: its pubkeys_commitment equals
//     datum.CURRENT, not datum.next (finding-2/#7 lives in the on-chain validator, not in
//     the circuit). A true rotation demo needs a period-1601-SIGNED update (attested@1601,
//     signed by 1601 = datum.next, carrying next@1602) — an optional future data-acquisition
//     follow-up if Phase-3 wants the on-chain rotation demonstrated.
//
// numberOfKeys: BuildRegular is N-parameterized — n < 512 subsets the committee side
// (commitment/apk/count recomputed for the subset; the finality side is N-independent) so the
// SAME code path is in-circuit-solvable locally at small N; 512 is the real witness.
// BuildBoundary is FULL-SIZE ONLY: op-6 merkleizes all N keys, so with the REAL gindex-87
// branch a truncated next-committee root can never reach the real state_root.
package witness

import (
	"fmt"
	"math/big"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bls12381"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"

	"eth-cardano-zk-light-client/prover/circuits/common"
	"eth-cardano-zk-light-client/prover/offchain/bootstrap"
	"eth-cardano-zk-light-client/prover/offchain/commitment"
	"eth-cardano-zk-light-client/prover/offchain/ssz"
)

// BuildRegular assembles the RegularCircuit witness: the first numberOfKeys CURRENT-committee
// keys (decompressed via the production path) with the REAL participation bits, the full real
// finality side, and the Option-P publics (commitment / packed apk / count / packed roots /
// slot). Internally HALTs (errors) if the N-independent finality anchor fails — the gindex-169
// fold of the finalized header must reach the attested state_root, exactly what the circuit's
// shared StateRoot wire will enforce.
func BuildRegular(input *bootstrap.Bootstrap, numberOfKeys int) (*common.RegularCircuit, error) {
	if numberOfKeys < 1 || numberOfKeys > len(input.CurrentCommittee.Pubkeys) {
		return nil, fmt.Errorf("numberOfKeys %d out of range (current committee has %d keys)", numberOfKeys, len(input.CurrentCommittee.Pubkeys))
	}
	if len(input.ParticipationBits) < numberOfKeys {
		return nil, fmt.Errorf("participation bits %d < numberOfKeys %d", len(input.ParticipationBits), numberOfKeys)
	}

	// the finality anchor (N-independent): the circuit will fold finalized_header_root up the
	// gindex-169 branch to op-3a's state_root — verify off-circuit NOW, not at AWS solve time.
	finalizedHeaderRoot := input.FinalizedHeader.HashTreeRoot()
	if ssz.Gindex169Walk(finalizedHeaderRoot, input.FinalityBranch) != input.AttestedHeader.StateRoot {
		return nil, fmt.Errorf("finality anchor: the gindex-169 walk does not reach the attested state_root")
	}

	currentKeys, err := bootstrap.DecompressCommittee(input.CurrentCommittee.Pubkeys[:numberOfKeys])
	if err != nil {
		return nil, fmt.Errorf("decompress current committee: %w", err)
	}
	participationBits := input.ParticipationBits[:numberOfKeys]
	aggregatePublicKey, participationCount := aggregateParticipants(currentKeys, participationBits)

	assignment := common.NewRegularCircuit(numberOfKeys)
	for i := range currentKeys {
		assignment.Pubkeys[i] = sw_bls12381.NewG1Affine(currentKeys[i])
		if participationBits[i] {
			assignment.Bits[i] = 1
		} else {
			assignment.Bits[i] = 0
		}
	}
	assignment.Slot = input.AttestedHeader.Slot
	assignment.ProposerIndex = input.AttestedHeader.ProposerIndex
	assignment.ParentRoot = toCircuitBytes32(input.AttestedHeader.ParentRoot)
	assignment.StateRoot = toCircuitBytes32(input.AttestedHeader.StateRoot)
	assignment.BodyRoot = toCircuitBytes32(input.AttestedHeader.BodyRoot)
	assignment.FinalizedHeaderRoot = toCircuitBytes32(finalizedHeaderRoot)
	for i := range input.FinalityBranch {
		assignment.FinalityBranch[i] = toCircuitBytes32(input.FinalityBranch[i])
	}
	slotBranch := input.FinalizedHeader.SlotBranch()
	for i := range slotBranch {
		assignment.SlotBranch[i] = toCircuitBytes32(slotBranch[i])
	}

	assignment.PubkeysCommitment = frToVariable(commitment.Commit(currentKeys))
	assignment.ApkPacked = packPoint(aggregatePublicKey)
	assignment.Count = participationCount
	assignment.AttestedHeaderRootPacked = packRootHalves(input.AttestedHeader.HashTreeRoot())
	assignment.FinalizedHeaderRootPacked = packRootHalves(finalizedHeaderRoot)
	assignment.FinalizedSlot = input.FinalizedHeader.Slot
	return assignment, nil
}

// BuildBoundary assembles the BoundaryCircuit witness: the regular core (BuildRegular) PLUS
// op-6's next-committee path (compressed bytes + Y hints + aggregate root + the gindex-87
// branch + the next Poseidon commitment). FULL-SIZE ONLY (see the package doc); internally
// HALTs (errors) if the gindex-87 anchor fails — the next-committee container root must walk
// to the SAME attested state_root the regular core binds.
func BuildBoundary(input *bootstrap.Bootstrap, numberOfKeys int) (*common.BoundaryCircuit, error) {
	if numberOfKeys != len(input.NextCommittee.Pubkeys) || numberOfKeys != len(input.CurrentCommittee.Pubkeys) {
		return nil, fmt.Errorf("boundary witness is full-size only (numberOfKeys %d, committees %d current / %d next): with the real gindex-87 branch a truncated next-committee root cannot reach the real state_root",
			numberOfKeys, len(input.CurrentCommittee.Pubkeys), len(input.NextCommittee.Pubkeys))
	}

	// the next-committee anchor: the circuit's op-6 walk terminal is the shared state_root —
	// verify off-circuit NOW (the off-circuit equivalent of what the AWS solve will enforce).
	nextCommitteeRoot := ssz.SyncCommitteeRoot(
		ssz.PubkeysRoot(input.NextCommittee.Pubkeys),
		ssz.Bytes48Root(input.NextCommittee.AggregatePubkey),
	)
	if ssz.Gindex87Walk(nextCommitteeRoot, input.NextCommitteeBranch) != input.AttestedHeader.StateRoot {
		return nil, fmt.Errorf("next-committee anchor: the gindex-87 walk does not reach the attested state_root")
	}

	base, err := BuildRegular(input, numberOfKeys)
	if err != nil {
		return nil, err
	}
	nextKeys, err := bootstrap.DecompressCommittee(input.NextCommittee.Pubkeys)
	if err != nil {
		return nil, fmt.Errorf("decompress next committee: %w", err)
	}

	assignment := common.NewBoundaryCircuit(numberOfKeys)
	assignment.RegularCircuit = *base
	for i := range nextKeys {
		assignment.Compressed[i] = toCircuitBytes48(input.NextCommittee.Pubkeys[i])
		assignment.YHint[i] = yHintOf(nextKeys[i])
	}
	assignment.AggRoot = toCircuitBytes32(ssz.Bytes48Root(input.NextCommittee.AggregatePubkey))
	for i := range input.NextCommitteeBranch {
		assignment.NextSyncCommitteeBranch[i] = toCircuitBytes32(input.NextCommitteeBranch[i])
	}
	assignment.NextPubkeysCommitment = frToVariable(commitment.Commit(nextKeys))
	return assignment, nil
}

// aggregateParticipants sums the bits-selected keys (the participating aggregate — the apk the
// real sync_aggregate signature verifies under) and counts the participants. The zero-value
// G1Jac is the point at infinity, so an empty selection yields the identity, matching the
// circuit's identity-start AddUnified accumulation.
func aggregateParticipants(keys []bls12381.G1Affine, participationBits []bool) (bls12381.G1Affine, int) {
	var accumulator bls12381.G1Jac
	count := 0
	for i := range keys {
		if participationBits[i] {
			var keyJacobian bls12381.G1Jac
			keyJacobian.FromAffine(&keys[i])
			accumulator.AddAssign(&keyJacobian)
			count++
		}
	}
	var aggregate bls12381.G1Affine
	aggregate.FromJacobian(&accumulator)
	return aggregate, count
}

// packPoint is the off-circuit twin of the in-circuit Reduce-then-packCoordinate over the apk:
// [X_lo, X_hi, Y_lo, Y_hi] via the mod-2^192 fold of the CANONICAL coordinates (gnark-crypto
// affine output is canonical, matching the in-circuit field.Reduce).
func packPoint(point bls12381.G1Affine) [4]frontend.Variable {
	xLo, xHi := commitment.FoldFp(point.X)
	yLo, yHi := commitment.FoldFp(point.Y)
	return [4]frontend.Variable{frToVariable(xLo), frToVariable(xHi), frToVariable(yLo), frToVariable(yHi)}
}

// packRootHalves is the off-circuit twin of the in-circuit packRoot: big-endian 16-byte halves
// (the LOCKED Option-P public-input encoding).
func packRootHalves(root [32]byte) [2]frontend.Variable {
	return [2]frontend.Variable{
		new(big.Int).SetBytes(root[0:16]),
		new(big.Int).SetBytes(root[16:32]),
	}
}

func toCircuitBytes32(bytes [32]byte) (out [32]uints.U8) {
	for i := range bytes {
		out[i] = uints.NewU8(bytes[i])
	}
	return
}

func toCircuitBytes48(bytes [48]byte) (out [48]uints.U8) {
	for i := range bytes {
		out[i] = uints.NewU8(bytes[i])
	}
	return
}

func frToVariable(element fr.Element) frontend.Variable {
	asBig := new(big.Int)
	element.BigInt(asBig)
	return asBig
}

// yHintOf converts a decompressed key's canonical Y coordinate to the op-6 emulated hint.
func yHintOf(key bls12381.G1Affine) emulated.Element[sw_bls12381.BaseField] {
	asBig := new(big.Int)
	key.Y.BigInt(asBig)
	return emulated.ValueOf[sw_bls12381.BaseField](asBig)
}
