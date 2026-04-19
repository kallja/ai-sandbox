package crypto

// Zero overwrites a byte slice with zeroes to limit secret exposure in memory.
func Zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
