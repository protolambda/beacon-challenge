package beacon_challenge

func merkle_root(input interface{}) Root {
	// TODO SSZ + hashing
	return ZERO_HASH
}

func signed_root(input interface{}, signType string) Root {
	// TODO SSZ signed root
	return ZERO_HASH
}

func bls_verify(pubkey BLSPubkey, message_hash Root, signature BLSSignature, domain BlsDomain) bool {
	return false
}

func hash_tree_root(input interface{}) Root {
	return ZERO_HASH
}

func hash(input interface{}) Bytes32 {
	return Bytes32{}
}

func xorBytes32(a Bytes32, b Bytes32) Bytes32 {
	out := Bytes32{}
	for i := 0; i < 32; i++ {
		out[i] = a[i] ^ b[i]
	}
	return out
}
