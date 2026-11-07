package relayer

import (
	"encoding/hex"
	"fmt"

	"eth-cardano-zk-light-client/prover/offchain/bootstrap"
)

// SeedCacheFromFixtures seeds the relayer Cache from a bootstrap (β) + update (α) fixture pair: it runs
// the §2.1.6 gate (bootstrap.Verify) and takes the committee commitments + finalized slot from its
// Result — the SAME gate-derived values offchain/boot.BuildGenesisValues writes into the genesis datum.
// So the seeded cache's committee commitments match the bridge's ON-CHAIN datum bit-for-bit; a mismatch
// here would reject reg#1 on the VM (after the ~4 h fresh setup), which is why it is gated against the
// known-good period-1600 values offline. currentPeriod is the signing committee's period.
//
// The LIVE seed (cmd/relayer) is the same path: FetchBootstrap + FetchUpdate -> WriteBootstrapFixture +
// WriteUpdateFixture -> THIS function. Seeding from fixtures keeps the gate offline + deterministic.
func SeedCacheFromFixtures(bootstrapPath, updatePath string) (*Cache, error) {
	input, signatureSlot, err := bootstrap.LoadFromFixtures(bootstrapPath, updatePath)
	if err != nil {
		return nil, fmt.Errorf("load fixtures: %w", err)
	}
	result, err := bootstrap.Verify(input)
	if err != nil {
		return nil, fmt.Errorf("§2.1.6 gate rejected the bootstrap (no cache without a passing gate): %w", err)
	}
	current := result.CurrentPubkeysCommitment.Bytes()
	next := result.NextPubkeysCommitment.Bytes()
	return &Cache{
		CurrentPeriod:              signatureSlot / SlotsPerPeriod,
		CurrentCommitteeCommitment: current,
		NextCommitteeCommitment:    next,
		LastFinalizedSlot:          result.FinalizedSlot,
	}, nil
}

// CommitmentHex renders a 32-byte committee commitment for logging / assertions.
func CommitmentHex(c [32]byte) string { return hex.EncodeToString(c[:]) }
