// Package oauth verifies OpenID Connect identity tokens from Google and Apple
// by fetching and caching each provider's JWKS and validating the standard
// claims (iss, aud, exp).
package oauth

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// ErrInvalidToken indicates the ID token failed verification.
var ErrInvalidToken = errors.New("invalid id token")

// Provider identifies a social login provider.
type Provider string

const (
	ProviderGoogle Provider = "google"
	ProviderApple  Provider = "apple"

	googleIssuer   = "https://accounts.google.com"
	googleIssuerNP = "accounts.google.com"
	googleJWKSURL  = "https://www.googleapis.com/oauth2/v3/certs"

	appleIssuer  = "https://appleid.apple.com"
	appleJWKSURL = "https://appleid.apple.com/auth/keys"
)

// IDTokenClaims is the subset of OIDC claims the platform consumes.
type IDTokenClaims struct {
	Subject       string
	Email         string
	EmailVerified bool
	Name          string
	Provider      Provider
}

// Verifier verifies ID tokens for a single provider.
type Verifier struct {
	provider  Provider
	issuers   []string
	audiences map[string]bool
	jwks      *jwksCache
	timeNow   func() time.Time
}

// Config configures the set of verifiers.
type Config struct {
	GoogleClientIDs []string
	AppleClientIDs  []string
	HTTPClient      *http.Client
}

// Verifiers holds per-provider verifiers.
type Verifiers struct {
	google *Verifier
	apple  *Verifier
}

// NewVerifiers constructs verifiers for the configured providers. A provider
// with no client IDs is left nil and rejected at request time.
func NewVerifiers(cfg Config) *Verifiers {
	hc := cfg.HTTPClient
	if hc == nil {
		hc = &http.Client{Timeout: 10 * time.Second}
	}
	v := &Verifiers{}
	if len(cfg.GoogleClientIDs) > 0 {
		v.google = &Verifier{
			provider:  ProviderGoogle,
			issuers:   []string{googleIssuer, googleIssuerNP},
			audiences: toSet(cfg.GoogleClientIDs),
			jwks:      newJWKSCache(googleJWKSURL, hc),
			timeNow:   time.Now,
		}
	}
	if len(cfg.AppleClientIDs) > 0 {
		v.apple = &Verifier{
			provider:  ProviderApple,
			issuers:   []string{appleIssuer},
			audiences: toSet(cfg.AppleClientIDs),
			jwks:      newJWKSCache(appleJWKSURL, hc),
			timeNow:   time.Now,
		}
	}
	return v
}

// For returns the verifier for a provider, or nil if not configured.
func (v *Verifiers) For(p Provider) *Verifier {
	switch p {
	case ProviderGoogle:
		return v.google
	case ProviderApple:
		return v.apple
	}
	return nil
}

// Verify validates an ID token string and returns the extracted claims.
func (vf *Verifier) Verify(ctx context.Context, idToken string) (*IDTokenClaims, error) {
	claims := jwt.MapClaims{}
	_, err := jwt.ParseWithClaims(idToken, claims, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method %v", t.Header["alg"])
		}
		kid, _ := t.Header["kid"].(string)
		if kid == "" {
			return nil, errors.New("missing kid")
		}
		return vf.jwks.key(ctx, kid)
	}, jwt.WithValidMethods([]string{"RS256"}), jwt.WithTimeFunc(vf.timeNow))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}

	iss, _ := claims["iss"].(string)
	if !contains(vf.issuers, iss) {
		return nil, fmt.Errorf("%w: unexpected issuer %q", ErrInvalidToken, iss)
	}
	if !vf.audienceOK(claims["aud"]) {
		return nil, fmt.Errorf("%w: audience mismatch", ErrInvalidToken)
	}

	sub, _ := claims["sub"].(string)
	if sub == "" {
		return nil, fmt.Errorf("%w: missing subject", ErrInvalidToken)
	}
	email, _ := claims["email"].(string)
	name, _ := claims["name"].(string)

	// email_verified may arrive as bool or the string "true".
	emailVerified := false
	switch ev := claims["email_verified"].(type) {
	case bool:
		emailVerified = ev
	case string:
		emailVerified = ev == "true"
	}

	return &IDTokenClaims{
		Subject:       sub,
		Email:         email,
		EmailVerified: emailVerified,
		Name:          name,
		Provider:      vf.provider,
	}, nil
}

func (vf *Verifier) audienceOK(aud any) bool {
	switch a := aud.(type) {
	case string:
		return vf.audiences[a]
	case []any:
		for _, x := range a {
			if s, ok := x.(string); ok && vf.audiences[s] {
				return true
			}
		}
	}
	return false
}

// --- JWKS cache ---

type jwksCache struct {
	url    string
	client *http.Client

	mu        sync.RWMutex
	keys      map[string]*rsa.PublicKey
	fetchedAt time.Time
	ttl       time.Duration
}

func newJWKSCache(url string, client *http.Client) *jwksCache {
	return &jwksCache{url: url, client: client, keys: map[string]*rsa.PublicKey{}, ttl: time.Hour}
}

func (c *jwksCache) key(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	c.mu.RLock()
	k, ok := c.keys[kid]
	fresh := time.Since(c.fetchedAt) < c.ttl
	c.mu.RUnlock()
	if ok && fresh {
		return k, nil
	}
	if err := c.refresh(ctx); err != nil {
		// Fall back to a stale cached key if we have one.
		if ok {
			return k, nil
		}
		return nil, err
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	if k, ok := c.keys[kid]; ok {
		return k, nil
	}
	return nil, fmt.Errorf("no key for kid %q", kid)
}

type jwkSet struct {
	Keys []struct {
		Kty string `json:"kty"`
		Kid string `json:"kid"`
		Use string `json:"use"`
		Alg string `json:"alg"`
		N   string `json:"n"`
		E   string `json:"e"`
	} `json:"keys"`
}

func (c *jwksCache) refresh(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.url, nil)
	if err != nil {
		return err
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("jwks fetch status %d", resp.StatusCode)
	}
	var set jwkSet
	if err := decodeJSON(resp.Body, &set); err != nil {
		return err
	}
	keys := make(map[string]*rsa.PublicKey, len(set.Keys))
	for _, k := range set.Keys {
		if k.Kty != "RSA" {
			continue
		}
		pub, err := rsaPublicKey(k.N, k.E)
		if err != nil {
			continue
		}
		keys[k.Kid] = pub
	}
	c.mu.Lock()
	c.keys = keys
	c.fetchedAt = time.Now()
	c.mu.Unlock()
	return nil
}

func rsaPublicKey(nB64, eB64 string) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(nB64)
	if err != nil {
		return nil, err
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(eB64)
	if err != nil {
		return nil, err
	}
	n := new(big.Int).SetBytes(nBytes)
	e := new(big.Int).SetBytes(eBytes)
	if !e.IsInt64() {
		return nil, errors.New("exponent too large")
	}
	return &rsa.PublicKey{N: n, E: int(e.Int64())}, nil
}

func toSet(xs []string) map[string]bool {
	m := make(map[string]bool, len(xs))
	for _, x := range xs {
		m[x] = true
	}
	return m
}

func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}
