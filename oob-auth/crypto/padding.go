package crypto

import "fmt"

// Pad appends ISO 7816-4 padding to msg: a 0x01 marker byte followed by
// zero or more 0x00 bytes, bringing the total length to exactly size.
// Returns an error if msg is too large to fit (needs at least 1 byte for the marker).
func Pad(msg []byte, size int) ([]byte, error) {
	if len(msg) >= size {
		return nil, fmt.Errorf("message too large for padding: %d bytes (max %d)", len(msg), size-1)
	}
	padded := make([]byte, size)
	copy(padded, msg)
	padded[len(msg)] = 0x01
	// Remaining bytes are already 0x00 from make().
	return padded, nil
}

// Unpad strips ISO 7816-4 padding: scans backwards past 0x00 bytes,
// expects a 0x01 marker, and returns everything before it.
func Unpad(padded []byte) ([]byte, error) {
	for i := len(padded) - 1; i >= 0; i-- {
		switch padded[i] {
		case 0x00:
			continue
		case 0x01:
			return padded[:i], nil
		default:
			return nil, fmt.Errorf("invalid padding byte at offset %d: 0x%02x", i, padded[i])
		}
	}
	return nil, fmt.Errorf("no padding marker found")
}
