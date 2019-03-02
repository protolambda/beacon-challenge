package challenge

func bls_verify(pubkey BLSPubkey, message_hash Root, signature BLSSignature, domain BLSDomain) bool {
	// TODO BLS verify single
	return false
}

func bls_aggregate_pubkeys(pubkeys []BLSPubkey) BLSPubkey {
	// TODO aggregate pubkeys with BLS
	return BLSPubkey{}
}

func bls_verify_multiple(pubkeys []BLSPubkey, message_hashes []Root, signature BLSSignature, domain BLSDomain) bool {
	// TODO BLS verify multiple
	return false
}
