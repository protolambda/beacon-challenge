package beacon_challenge

import "crypto/sha256"

// Merkleize values (where len(values) is a power of two) and return the Merkle root.
// Note that the leaves are not hashed.
func merkle_root(values []Bytes32) Root {
	o := make([]Bytes32, len(values)*2)
	copy(o[len(values):], values)
	for i := len(values) - 1; i >= 0; i-- {
		o[i] = hash(append(o[i*2][:], o[i*2+1][:]...)
	}
	return Root(o[1])
}

func hash(input []byte) (out Bytes32) {
	// TODO this could be optimized,
	//  in reality you don't want to re-init the hashing function every time you call this
	hash := sha256.New()
	hash.Write(input)
	copy(out[:], hash.Sum(nil))
	return out
}

func xorBytes32(a Bytes32, b Bytes32) (out Bytes32) {
	for i := 0; i < 32; i++ {
		out[i] = a[i] ^ b[i]
	}
	return out
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
