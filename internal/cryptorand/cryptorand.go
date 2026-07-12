// Package cryptorand provides helpers for generating cryptographically secure
// random tokens and their hashes.
package cryptorand

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
)

// Token generates a URL-safe, base64-encoded random token with the given number
// of random bytes (before encoding). 32 bytes yields 256 bits of entropy.
func Token(nbytes int) (string, error) {
	b := make([]byte, nbytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// Bytes returns n cryptographically random bytes.
func Bytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}

// HashToken returns the SHA-256 digest of a token. Opaque tokens (refresh,
// email-verification, password-reset) are stored as this digest so that a
// database leak does not expose usable secrets.
func HashToken(token string) []byte {
	sum := sha256.Sum256([]byte(token))
	return sum[:]
}
