package beacon_challenge

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

// The largest integer x such that x**2 is less than or equal to n.
func integer_squareroot(n uint64) uint64 {
	x := n
	y := (x + 1) >> 1
	for y < x {
		x = y
		y = (x + n / x) >> 1
	}
	return x
}
