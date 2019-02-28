package beacon_challenge

type Slot uint64
type Epoch uint64
type Shard uint64
type ValidatorIndex uint64
type Gwei uint64
type Root [32]byte
type Bytes32 [32]byte
type BLSPubkey [48]byte
type BLSSignature [96]byte
type BlsDomain uint64

type DepositIndex uint64

type Timestamp uint64
type Seconds uint64

type ValueFunction func(index ValidatorIndex) Gwei

type ValidatorIndexSet []ValidatorIndex

// returns a copy without the given indices
func (vs ValidatorIndexSet) Minus(removed ValidatorIndexSet) ValidatorIndexSet {
	res := vs.Copy()
	res.RemoveAll(removed)
	return res
}

func (vs ValidatorIndexSet) RemoveAll(removed ValidatorIndexSet) {
	for i, a := range vs {
		for _, b := range removed {
			if a == b {
				vs[i] = ValidatorIndex(0xffFFffFF)
				break
			}
		}
	}
	// remove all marked indices
	for i := 0; i < len(vs); {
		if vs[i] == 0xffFFffFF {
			// replace with last, and cut out last
			last := len(vs) - 1
			vs[i] = vs[last]
			vs = vs[:last]
		} else {
			i++
		}
	}
}

func (vs ValidatorIndexSet) Copy() ValidatorIndexSet {
	res := make([]ValidatorIndex, len(vs), len(vs))
	copy(res, vs)
	return res
}

func (s Slot) ToEpoch() Epoch {
	return Epoch(s / SLOTS_PER_EPOCH)
}

func (e Epoch) GetStartSlot() Slot {
	return Slot(e) * SLOTS_PER_EPOCH
}

// bits are indexed from right to left of internal byte array. Inside byte: also from right to left.
type Bitfield struct {
	Bytes []byte
	Length uint64
}

func (b Bitfield) GetBit(i uint64) byte {
	if b.Length > i {
		return b.Bytes[i >> 3] >> (i & 7)
	} else {
		panic("invalid bitfield access")
	}
}

func (b Bitfield) SetLen(length uint64) {
	lengthBytes := length >> 3
	if length & 7 == 0 {
		lengthBytes++
	}
	if b.Length <= length {
		// fit in old capacity?
		if uint64(cap(b.Bytes)) >= lengthBytes {
			b.Bytes = b.Bytes[:lengthBytes]
			// overwrite with zeros, old capacity may have content
			for i := b.Length; i <= lengthBytes; i++ {
				b.Bytes[i] = 0
			}
		} else {
			// TODO: we could allocate extra in advance
			newBytes := make([]byte, lengthBytes, lengthBytes)
			copy(newBytes, b.Bytes)
			b.Bytes = newBytes
		}
	}
	b.Length = length
}

func (b Bitfield) SetBit(i uint64, bit byte) {
	if bit != 1 && bit != 0 {
		panic("invalid bit supplied to bitfield SetBit")
	}
	// extend bitfield if necessary
	if b.Length <= i {
		b.SetLen(i + 1)
	}
	b.Bytes[i >> 3] |= bit << (i & 7)
}

func (b Bitfield) IsZero() bool {
	lengthBytes := b.Length >> 3
	if b.Length & 7 == 0 {
		lengthBytes++
	}
	for i := uint64(0); i < lengthBytes; i++ {
		if b.Bytes[i] != 0 {
			return false
		}
	}
	return true
}

func Max(a Gwei, b Gwei) Gwei {
	if a > b {
		return a
	} else {
		return b
	}
}
func Min(a Gwei, b Gwei) Gwei {
	if a < b {
		return a
	} else {
		return b
	}
}
