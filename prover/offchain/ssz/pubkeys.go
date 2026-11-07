package ssz

// Bytes48Root is hash_tree_root(Bytes48) = SHA-256(b[0:32] ‖ (b[32:48] ‖ 16 zero bytes)).
func Bytes48Root(b [48]byte) [32]byte {
	var chunk1 [32]byte
	copy(chunk1[:16], b[32:48])
	return hashPair(b[0:32], chunk1[:])
}

// PubkeysRoot is hash_tree_root(Vector[Bytes48, N]) for N a power of two: N leaf roots
// merkleized through a perfect balanced tree (no padding, no length mixing — Vector).
func PubkeysRoot(pubkeys [][48]byte) [32]byte {
	level := make([][32]byte, len(pubkeys))
	for i, pk := range pubkeys {
		level[i] = Bytes48Root(pk)
	}
	for len(level) > 1 {
		next := make([][32]byte, len(level)/2)
		for i := range next {
			next[i] = hashPair(level[2*i][:], level[2*i+1][:])
		}
		level = next
	}
	return level[0]
}
