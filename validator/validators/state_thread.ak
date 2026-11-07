//// One-shot state-thread NFT minting policy. Layer 1 enforces the mint side of obligation #8:
//// the seed UTxO is consumed AND exactly one token (`bridge_state_token_name`, quantity 1) is
//// minted under this policy. The seed's single on-chain existence makes the policy succeed at
//// most once — re-minting is impossible, so the NFT (and thus the bridge state thread) is
//// unique by construction.
////
//// Boot trust model (recorded): this policy does NOT re-verify the §2.1.6 bootstrap on-chain.
//// The bootstrap is the trusted weak-subjectivity checkpoint, verified OFF-CHAIN by the
//// plain-Go verifier (prover/offchain/bootstrap); the operator publishes the off-chain-verified
//// genesis datum, and the one-shot NFT guarantees the thread starts exactly once from it.

use cardano/assets.{PolicyId}
use cardano/transaction.{OutputReference, Transaction}
use zkbridge/types.{bridge_state_token_name}
use zkbridge/validation.{is_one_shot_mint}

validator state_thread_nft(seed: OutputReference) {
  mint(_redeemer: Data, policy_id: PolicyId, self: Transaction) {
    is_one_shot_mint(self, seed, policy_id, bridge_state_token_name)
  }

  // Mint-only policy: any other script purpose is rejected.
  else(_) {
    fail
  }
}
