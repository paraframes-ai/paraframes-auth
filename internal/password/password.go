// Package password implements Argon2id password hashing and verification using
// the PHC string format, plus a lightweight strength policy.
package password

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"unicode"

	"golang.org/x/crypto/argon2"
)

// Params configures the Argon2id KDF.
type Params struct {
	Memory      uint32 // in KiB
	Iterations  uint32
	Parallelism uint8
	SaltLength  uint32
	KeyLength   uint32
}

// DefaultParams returns OWASP-aligned defaults for Argon2id.
func DefaultParams() Params {
	return Params{
		Memory:      64 * 1024,
		Iterations:  3,
		Parallelism: 2,
		SaltLength:  16,
		KeyLength:   32,
	}
}

// ErrMismatch is returned when a password does not match the stored hash.
var ErrMismatch = errors.New("password does not match")

// Hash derives an Argon2id hash of the password and returns it in PHC string
// format: $argon2id$v=19$m=65536,t=3,p=2$<salt>$<hash>.
func Hash(pw string, p Params) (string, error) {
	salt := make([]byte, p.SaltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(pw), salt, p.Iterations, p.Memory, p.Parallelism, p.KeyLength)

	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Key := base64.RawStdEncoding.EncodeToString(key)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, p.Memory, p.Iterations, p.Parallelism, b64Salt, b64Key), nil
}

// Verify checks pw against a PHC-format Argon2id hash in constant time.
func Verify(pw, encoded string) error {
	p, salt, key, err := decode(encoded)
	if err != nil {
		return err
	}
	other := argon2.IDKey([]byte(pw), salt, p.Iterations, p.Memory, p.Parallelism, uint32(len(key)))
	if subtle.ConstantTimeCompare(key, other) != 1 {
		return ErrMismatch
	}
	return nil
}

func decode(encoded string) (Params, []byte, []byte, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return Params{}, nil, nil, errors.New("invalid argon2 hash format")
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
		return Params{}, nil, nil, err
	}
	if version != argon2.Version {
		return Params{}, nil, nil, fmt.Errorf("incompatible argon2 version %d", version)
	}
	var p Params
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &p.Memory, &p.Iterations, &p.Parallelism); err != nil {
		return Params{}, nil, nil, err
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return Params{}, nil, nil, err
	}
	key, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return Params{}, nil, nil, err
	}
	return p, salt, key, nil
}

// Policy validates password strength. Returns a human-readable reason if the
// password is unacceptable.
func Policy(pw string) error {
	if len(pw) < 10 {
		return errors.New("password must be at least 10 characters")
	}
	if len(pw) > 4096 {
		return errors.New("password is too long")
	}
	var hasLetter, hasNumber bool
	for _, r := range pw {
		switch {
		case unicode.IsLetter(r):
			hasLetter = true
		case unicode.IsNumber(r):
			hasNumber = true
		}
	}
	if !hasLetter || !hasNumber {
		return errors.New("password must contain at least one letter and one number")
	}
	return nil
}
