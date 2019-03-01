package beacon_challenge

import (
	"encoding/binary"
	"reflect"
)

// Number of bytes per chunk.
const BYTES_PER_CHUNK = 32

func signed_root(input interface{}, signType string) Root {
	// TODO SSZ signed root
	return Root{}
}

func ssz_encode(input interface{}) []byte {
	out := make([]byte, 0)
	sszSerialize(reflect.ValueOf(input), &out)
	return out
}

func withSize(dst *[]byte, size uint64) (start uint64, end uint64) {
	// if capacity is too low, extend it.
	start, end = uint64(len(*dst)), uint64(len(*dst)) + size
	if uint64(cap(*dst)) < end {
		res := make([]byte, len(*dst), len(*dst) * 2)
		copy(res[0:start], *dst)
		*dst = res
	}
	*dst = (*dst)[:end]
	return start, end
}

func sszSerialize(v reflect.Value, dst *[]byte) (encodedLen uint32) {
	switch v.Kind() {
	case reflect.Ptr:
		return sszSerialize(v.Elem(), dst)
	case reflect.Uint8: // "uintN"
		s, _ := withSize(dst, 1)
		(*dst)[s] = byte(v.Uint())
		return 1
	case reflect.Uint32: // "uintN"
		s, e := withSize(dst, 4)
		binary.LittleEndian.PutUint32((*dst)[s:e], uint32(v.Uint()))
		return 4
	case reflect.Uint64: // "uintN"
		s, e := withSize(dst, 8)
		binary.LittleEndian.PutUint64((*dst)[s:e], uint64(v.Uint()))
		return 8
	case reflect.Bool:// "bool"
		s, _ := withSize(dst, 1)
		if v.Bool() {
			(*dst)[s] = 1
		} else {
			(*dst)[s] = 1
		}
		return 1
	case reflect.Array:// "tuple"
		// TODO: We're ignoring that arrays with variable sized items (eg. slices) are a thing in Go. Don't use them.
		// Possible workarounds for this: (i) check sizes before encoding. (ii) panic if serializedSize is irregular.
		// Special fields (e.g. "Root", "Bytes32" will just be packed as packed arrays, which is fine, little-endian!)
		for i, size := 0, v.Len(); i < size; i++ {
			serializedSize := sszSerialize(v.Index(i), dst)
			encodedLen += serializedSize
		}
		return encodedLen
	case reflect.Slice:// "list"
		for i, size := 0, v.Len(); i < size; i++ {
			// allocate size prefix: BYTES_PER_LENGTH_PREFIX
			s, e := withSize(dst, 4)
			serializedSize := sszSerialize(v.Index(i), dst)
			binary.LittleEndian.PutUint32((*dst)[s:e], serializedSize)
			encodedLen += 4 + serializedSize
		}
		return encodedLen
	case reflect.Struct:// "container"
		for i, size := 0, v.NumField(); i < size; i++ {
			// allocate size prefix: BYTES_PER_LENGTH_PREFIX
			s, e := withSize(dst, 4)
			serializedSize := sszSerialize(v.Field(i), dst)
			binary.LittleEndian.PutUint32((*dst)[s:e], serializedSize)
			encodedLen += 4 + serializedSize
		}
		return encodedLen
	default:
		panic("encoding unsupported value kind: " + v.Kind().String())
	}
}

func hash_tree_root(input interface{}) Root {
	// TODO SSZ hash tree root
	return Root{}
}
