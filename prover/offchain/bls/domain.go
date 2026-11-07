// Package bls provides the off-circuit BLS sync-committee signature verification for the
// bootstrap's condition (d): the Ethereum minimal-pubkey ciphersuite (pubkeys in G1,
// signatures in G2, RFC-9380 hash-to-G2 with the sync-committee DST), the 2/3 participation
// threshold, and the compute_domain / compute_signing_root glue that turns an attested
// BeaconBlockHeader into the 32-byte message the committee signs. Pure Go (gnark-crypto
// BLS12-381 + crypto/sha256); the ciphersuite/DST is reused verbatim from the verified
// poc_rogue_key proof-of-concept. NOT a circuit — the bootstrap is a trusted off-chain
// genesis computation (see package bootstrap).
package bls

import "crypto/sha256"

// DomainSyncCommittee is DOMAIN_SYNC_COMMITTEE — the 4-byte domain type prefixing every
// sync-committee signature's domain (Ethereum consensus constant 0x07000000).
var DomainSyncCommittee = [4]byte{0x07, 0x00, 0x00, 0x00}

// ComputeForkDataRoot is hash_tree_root(ForkData{current_version, genesis_validators_root}),
// the 2-leaf SSZ container: SHA256( chunk(current_version) ‖ genesis_validators_root ), where
// chunk(current_version) is the 4-byte Version right-padded to a 32-byte chunk. Pinned by the
// consensus-spec-tests ssz_static/ForkData vector (domain_test.go).
func ComputeForkDataRoot(currentVersion [4]byte, genesisValidatorsRoot [32]byte) [32]byte {
	var buffer [64]byte
	copy(buffer[0:4], currentVersion[:]) // Version (Bytes4) right-padded in [0:32]
	copy(buffer[32:64], genesisValidatorsRoot[:])
	return sha256.Sum256(buffer[:])
}

// ComputeDomain is compute_domain(domain_type, fork_version, genesis_validators_root) =
// domain_type ‖ fork_data_root[0:28] (a 32-byte Domain). The 4-byte type prefixes the first
// 28 bytes of the fork-data root.
func ComputeDomain(domainType [4]byte, forkVersion [4]byte, genesisValidatorsRoot [32]byte) [32]byte {
	forkDataRoot := ComputeForkDataRoot(forkVersion, genesisValidatorsRoot)
	var domain [32]byte
	copy(domain[0:4], domainType[:])
	copy(domain[4:32], forkDataRoot[0:28])
	return domain
}

// ComputeSigningRoot is hash_tree_root(SigningData{object_root, domain}) =
// SHA256( object_root ‖ domain ) — the 32-byte message hashed to G2 and signed. object_root is
// hash_tree_root(attested_header). Pinned by the consensus-spec-tests ssz_static/SigningData
// vector (domain_test.go).
func ComputeSigningRoot(objectRoot [32]byte, domain [32]byte) [32]byte {
	var buffer [64]byte
	copy(buffer[0:32], objectRoot[:])
	copy(buffer[32:64], domain[:])
	return sha256.Sum256(buffer[:])
}
