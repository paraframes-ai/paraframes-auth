// Package token issues and verifies ES256-signed access tokens (JWTs) and
// publishes the corresponding public keys as a JWKS document.
package token

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Claims is the set of claims carried by an access token.
type Claims struct {
	Email         string `json:"email,omitempty"`
	EmailVerified bool   `json:"email_verified"`
	BetaTester    bool   `json:"beta"`
	SessionID     string `json:"sid"`
	jwt.RegisteredClaims
}

// Issuer issues and verifies access tokens with a single active ES256 key.
type Issuer struct {
	priv     *ecdsa.PrivateKey
	kid      string
	issuer   string
	audience string
	ttl      time.Duration
}

// NewIssuer constructs an Issuer from a PEM-encoded EC private key. If pemKey is
// empty, a throwaway key is generated (development only).
func NewIssuer(pemKey, kid, issuer, audience string, ttl time.Duration) (*Issuer, error) {
	var priv *ecdsa.PrivateKey
	var err error
	if pemKey == "" {
		priv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
	} else {
		priv, err = parseECPrivateKey(pemKey)
		if err != nil {
			return nil, err
		}
	}
	return &Issuer{priv: priv, kid: kid, issuer: issuer, audience: audience, ttl: ttl}, nil
}

// Generated reports whether the signing key was randomly generated (no PEM
// supplied). Callers should warn loudly if this is true outside development.
func (i *Issuer) Generated() bool { return i.priv != nil }

// TTL returns the configured access-token lifetime.
func (i *Issuer) TTL() time.Duration { return i.ttl }

// Subject describes the token subject for an issued access token.
type Subject struct {
	UserID        string
	Email         string
	EmailVerified bool
	BetaTester    bool
	SessionID     string
}

// Issue signs and returns an access token for the subject.
func (i *Issuer) Issue(s Subject, now time.Time) (string, error) {
	claims := Claims{
		Email:         s.Email,
		EmailVerified: s.EmailVerified,
		BetaTester:    s.BetaTester,
		SessionID:     s.SessionID,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    i.issuer,
			Subject:   s.UserID,
			Audience:  jwt.ClaimStrings{i.audience},
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(i.ttl)),
			ID:        randID(),
		},
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	tok.Header["kid"] = i.kid
	return tok.SignedString(i.priv)
}

// Verify parses and validates an access token, returning its claims.
func (i *Issuer) Verify(tokenStr string) (*Claims, error) {
	claims := &Claims{}
	_, err := jwt.ParseWithClaims(tokenStr, claims, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodECDSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return &i.priv.PublicKey, nil
	}, jwt.WithIssuer(i.issuer), jwt.WithAudience(i.audience), jwt.WithValidMethods([]string{"ES256"}))
	if err != nil {
		return nil, err
	}
	return claims, nil
}

// JWK is a single JSON Web Key (public, EC P-256).
type JWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

// JWKS is a JSON Web Key Set.
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// JWKS returns the public key set used to verify issued access tokens.
func (i *Issuer) JWKS() JWKS {
	pub := i.priv.PublicKey
	byteLen := (pub.Curve.Params().BitSize + 7) / 8
	return JWKS{Keys: []JWK{{
		Kty: "EC",
		Crv: "P-256",
		Kid: i.kid,
		Use: "sig",
		Alg: "ES256",
		X:   base64.RawURLEncoding.EncodeToString(leftPad(pub.X.Bytes(), byteLen)),
		Y:   base64.RawURLEncoding.EncodeToString(leftPad(pub.Y.Bytes(), byteLen)),
	}}}
}

func leftPad(b []byte, size int) []byte {
	if len(b) >= size {
		return b
	}
	out := make([]byte, size)
	copy(out[size-len(b):], b)
	return out
}

func parseECPrivateKey(pemStr string) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}
	switch block.Type {
	case "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(block.Bytes)
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		ec, ok := key.(*ecdsa.PrivateKey)
		if !ok {
			return nil, errors.New("PKCS8 key is not an EC private key")
		}
		return ec, nil
	default:
		return nil, fmt.Errorf("unsupported PEM type %q", block.Type)
	}
}

// randID returns a short random JWT ID (jti).
func randID() string {
	n, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	return base64.RawURLEncoding.EncodeToString(n.Bytes())
}
