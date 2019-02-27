package beacon_challenge

import "math/big"

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
type Bitfield big.Int

type DepositIndex uint64

type Timestamp uint64
type Seconds uint64
