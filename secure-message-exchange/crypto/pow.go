package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// ComputePoW finds a nonce such that SHA-256(nonce || body) has at least
// difficulty leading zero bits. Returns the hex-encoded nonce.
func ComputePoW(body []byte, difficulty int) (string, error) {
	nonce := make([]byte, 16)
	buf := make([]byte, 16+len(body))
	copy(buf[16:], body)

	for {
		if _, err := rand.Read(nonce); err != nil {
			return "", fmt.Errorf("generate nonce: %w", err)
		}
		copy(buf[:16], nonce)
		hash := sha256.Sum256(buf)
		if hasLeadingZeroBits(hash, difficulty) {
			return hex.EncodeToString(nonce), nil
		}
	}
}

// VerifyPoW checks that SHA-256(nonce || body) has at least difficulty
// leading zero bits. The nonce is hex-encoded.
func VerifyPoW(nonceHex string, body []byte, difficulty int) bool {
	nonce, err := hex.DecodeString(nonceHex)
	if err != nil {
		return false
	}
	buf := make([]byte, len(nonce)+len(body))
	copy(buf, nonce)
	copy(buf[len(nonce):], body)
	hash := sha256.Sum256(buf)
	return hasLeadingZeroBits(hash, difficulty)
}

// hasLeadingZeroBits checks if the hash has at least n leading zero bits.
func hasLeadingZeroBits(hash [32]byte, n int) bool {
	for i := 0; i < n; i++ {
		byteIdx := i / 8
		bitIdx := 7 - (i % 8)
		if hash[byteIdx]&(1<<bitIdx) != 0 {
			return false
		}
	}
	return true
}
