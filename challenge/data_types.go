package challenge

type Slot uint64
type Epoch uint64
type Shard uint64
type Gwei uint64
type Timestamp uint64
type ValidatorIndex uint64
type DepositIndex uint64
type BLSDomain uint64

// byte arrays
type Root [32]byte
type Bytes32 [32]byte
type BLSPubkey [48]byte
type BLSSignature [96]byte

type ValueFunction func(index ValidatorIndex) Gwei

type ValidatorIndexSet []ValidatorIndex

// returns a copy without the given indices
func (vs *ValidatorIndexSet) Minus(removed ValidatorIndexSet) ValidatorIndexSet {
	res := vs.Copy()
	res.RemoveAll(removed)
	return res
}

func (vs *ValidatorIndexSet) RemoveAll(removed ValidatorIndexSet) {
	for i, a := range *vs {
		for _, b := range removed {
			if a == b {
				(*vs)[i] = ValidatorIndexMarker
				break
			}
		}
	}
	// remove all marked indices
	for i := 0; i < len(*vs); {
		if (*vs)[i] == ValidatorIndexMarker {
			// replace with last, and cut out last
			last := len(*vs) - 1
			(*vs)[i] = (*vs)[last]
			*vs = (*vs)[:last]
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

// bits are indexed from left to right of internal byte array (like a little endian integer).
// But inside byte it is from right to left. //TODO: correct?
type Bitfield []byte

func (b Bitfield) GetBit(i uint64) byte {
	if uint64(len(b)<<3) > i {
		return (b[i>>3] >> (i & 7)) & 1
	}
	panic("invalid bitfield access")
}

// Verify bitfield against the size:
//  - the bitfield must have the correct amount of bytes
//  - bits after this size (in bits) must be 0.
func (b Bitfield) verifySize(size uint64) bool {
	// check byte count
	if uint64(len(b)) != (size+7)>>3 {
		return false
	}
	// check if bitfield is padded with zero bits only
	end := uint64(len(b)) << 3
	for i := size; i < end; i++ {
		if b.GetBit(i) == 1 {
			return false
		}
	}
	return true
}

func (b Bitfield) IsZero() bool {
	for i := 0; i < len(b); i++ {
		if b[i] != 0 {
			return false
		}
	}
	return true
}
