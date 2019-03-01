package beacon_challenge

func merkle_root(input interface{}) Root {
	// TODO SSZ merkle root hashing
	return ZERO_HASH
}

func signed_root(input interface{}, signType string) Root {
	// TODO SSZ signed root
	return ZERO_HASH
}

func bls_verify(pubkey BLSPubkey, message_hash Root, signature BLSSignature, domain BlsDomain) bool {
	// TODO BLS verify single
	return false
}

func ssz_encode(input interface{}) []byte {
	// TODO SSZ encode to bytes
	return []byte{}
}

func hash_tree_root(input interface{}) Root {
	// TODO SSZ hash tree root
	return ZERO_HASH
}

func hash(input []byte) Bytes32 {
	// TODO just hash, SHA 256 for now?
	return Bytes32{}
}

func xorBytes32(a Bytes32, b Bytes32) (out Bytes32) {
	for i := 0; i < 32; i++ {
		out[i] = a[i] ^ b[i]
	}
	return out
}

func bls_aggregate_pubkeys(pubkeys []BLSPubkey) BLSPubkey {
	// TODO aggregate pubkeys with BLS
	return BLSPubkey{}
}

func bls_verify_multiple(pubkeys []BLSPubkey, message_hashes []Root, signature BLSSignature, domain BlsDomain) bool {
	// TODO BLS verify multiple
	return false
}

// Verify that the given leaf is on the merkle branch.
func verify_merkle_branch(leaf Bytes32, branch []Root, depth uint64, index uint64, root Root) bool {
	value := leaf
	buf := make([]byte, 64, 64)
	for i := uint64(0); i < depth; i++ {
		if (index>>i)&1 == 1 {
			copy(buf[:32], branch[i][:])
			copy(buf[32:], value[:])
		} else {
			// reverse order in buffer, compared to above
			copy(buf[32:], branch[i][:])
			copy(buf[:32], value[:])
		}
		value = hash(buf)
	}
	return Root(value) == root
}
