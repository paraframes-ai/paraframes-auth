package oauth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// newMockProvider spins up an httptest server serving a JWKS for a generated
// RSA key and returns a verifier wired to it.
func newMockProvider(t *testing.T, issuer, audience string) (*Verifier, *rsa.PrivateKey, func()) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	const kid = "mock-key-1"
	jwks := map[string]any{
		"keys": []map[string]string{{
			"kty": "RSA",
			"kid": kid,
			"use": "sig",
			"alg": "RS256",
			"n":   base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
			"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
		}},
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(jwks)
	}))
	vf := &Verifier{
		provider:  ProviderGoogle,
		issuers:   []string{issuer},
		audiences: map[string]bool{audience: true},
		jwks:      newJWKSCache(srv.URL, srv.Client()),
		timeNow:   time.Now,
	}
	return vf, key, srv.Close
}

func signToken(t *testing.T, key *rsa.PrivateKey, claims jwt.MapClaims) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = "mock-key-1"
	s, err := tok.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestVerifyValidToken(t *testing.T) {
	vf, key, done := newMockProvider(t, "https://accounts.google.com", "client-abc")
	defer done()

	tok := signToken(t, key, jwt.MapClaims{
		"iss":            "https://accounts.google.com",
		"aud":            "client-abc",
		"sub":            "google-sub-1",
		"email":          "user@example.com",
		"email_verified": true,
		"name":           "Test User",
		"exp":            time.Now().Add(time.Hour).Unix(),
		"iat":            time.Now().Unix(),
	})

	claims, err := vf.Verify(context.Background(), tok)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if claims.Subject != "google-sub-1" || claims.Email != "user@example.com" || !claims.EmailVerified {
		t.Errorf("unexpected claims: %+v", claims)
	}
}

func TestVerifyRejectsBadAudience(t *testing.T) {
	vf, key, done := newMockProvider(t, "https://accounts.google.com", "client-abc")
	defer done()
	tok := signToken(t, key, jwt.MapClaims{
		"iss": "https://accounts.google.com",
		"aud": "someone-else",
		"sub": "x",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	if _, err := vf.Verify(context.Background(), tok); err == nil {
		t.Fatal("expected audience mismatch to fail")
	}
}

func TestVerifyRejectsWrongSigner(t *testing.T) {
	vf, _, done := newMockProvider(t, "https://accounts.google.com", "client-abc")
	defer done()
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	tok := signToken(t, other, jwt.MapClaims{
		"iss": "https://accounts.google.com",
		"aud": "client-abc",
		"sub": "x",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	if _, err := vf.Verify(context.Background(), tok); err == nil {
		t.Fatal("expected token signed by unknown key to fail")
	}
}
