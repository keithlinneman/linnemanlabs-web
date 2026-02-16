package cryptoutil

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
)

// HashEqual performs constant-time comparison of two hex-encoded hashes
// to prevent timing attacks. It returns true if the hashes are equal.
func HashEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// SHA256Hex computes the SHA-256 hash of the input data and returns it as a hex string
func SHA256Hex(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}
