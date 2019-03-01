package beacon_challenge

func Max(a Gwei, b Gwei) Gwei {
	return Gwei(MaxU64(uint64(a), uint64(b)))
}
func Min(a Gwei, b Gwei) Gwei {
	return Gwei(MinU64(uint64(a), uint64(b)))
}

func MaxU64(a uint64, b uint64) uint64 {
	if a > b {
		return a
	} else {
		return b
	}
}

func MinU64(a uint64, b uint64) uint64 {
	if a < b {
		return a
	} else {
		return b
	}
}

// The largest integer x such that x**2 is less than or equal to n.
func integer_squareroot(n uint64) uint64 {
	x := n
	y := (x + 1) >> 1
	for y < x {
		x = y
		y = (x + n/x) >> 1
	}
	return x
}

func is_power_of_two(n uint64) bool {
	return (n > 0) && (n&(n-1) == 0)
}
