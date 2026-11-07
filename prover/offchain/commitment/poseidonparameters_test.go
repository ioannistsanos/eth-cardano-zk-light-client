// poseidonparameters_test.go — pins the surfaced Poseidon2 parameter constants to the
// canonical default instance Commit uses: rebuilding the hasher EXPLICITLY from
// (PoseidonWidth, PoseidonFullRounds, PoseidonPartialRounds) with the zero initial state
// must reproduce Commit byte-identically. If gnark-crypto's default ever drifted from
// 2/6/50 (or the parameter-string seed derivation changed), this fails loudly instead of
// silently splitting the off-chain twin from the deployed datum commitments.
package commitment

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	poseidon2 "github.com/consensys/gnark-crypto/ecc/bls12-381/fr/poseidon2"
	gnarkHash "github.com/consensys/gnark-crypto/hash"
)

// explicitParameterCommit is CommitElements rebuilt from the surfaced constants — the
// explicitly-parameterized twin of the canonical-default hasher inside CommitElements.
func explicitParameterCommit(elements []fr.Element) fr.Element {
	permutation := poseidon2.NewPermutation(PoseidonWidth, PoseidonFullRounds, PoseidonPartialRounds)
	hasher := gnarkHash.NewMerkleDamgardHasher(permutation, make([]byte, fr.Bytes))
	for i := range elements {
		elementBytes := elements[i].Bytes()
		hasher.Write(elementBytes[:])
	}
	var out fr.Element
	out.SetBytes(hasher.Sum(nil))
	return out
}

// TestCommit_ExplicitParametersEquivalent: the surfaced (2, 6, 50) constants, explicitly
// instantiated, reproduce the canonical-default Commit over several committee sizes.
func TestCommit_ExplicitParametersEquivalent(t *testing.T) {
	for _, n := range []int{1, 2, 5, 8, 16} {
		points := deterministicPoints(n)
		got, want := explicitParameterCommit(Pack(points)), Commit(points)
		if got != want {
			t.Fatalf("explicit (width=%d, full=%d, partial=%d) != canonical default at n=%d:\n got  %s\n want %s",
				PoseidonWidth, PoseidonFullRounds, PoseidonPartialRounds, n, frHex(got), frHex(want))
		}
	}
}
