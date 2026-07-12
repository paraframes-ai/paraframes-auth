package token

import (
	"testing"
	"time"
)

func newTestIssuer(t *testing.T) *Issuer {
	t.Helper()
	iss, err := NewIssuer("", "test-kid", "https://issuer.test", "test-aud", 15*time.Minute)
	if err != nil {
		t.Fatalf("new issuer: %v", err)
	}
	return iss
}

func TestIssueAndVerify(t *testing.T) {
	iss := newTestIssuer(t)
	now := time.Now()
	tok, err := iss.Issue(Subject{
		UserID:        "user-123",
		Email:         "a@b.com",
		EmailVerified: true,
		BetaTester:    true,
		SessionID:     "sess-1",
	}, now)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	claims, err := iss.Verify(tok)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if claims.Subject != "user-123" {
		t.Errorf("subject = %q", claims.Subject)
	}
	if claims.SessionID != "sess-1" {
		t.Errorf("sid = %q", claims.SessionID)
	}
	if !claims.BetaTester || !claims.EmailVerified {
		t.Errorf("flags not preserved: beta=%v verified=%v", claims.BetaTester, claims.EmailVerified)
	}
}

func TestVerifyRejectsExpired(t *testing.T) {
	iss := newTestIssuer(t)
	past := time.Now().Add(-time.Hour)
	tok, err := iss.Issue(Subject{UserID: "u", SessionID: "s"}, past)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if _, err := iss.Verify(tok); err == nil {
		t.Fatal("expected expired token to fail verification")
	}
}

func TestVerifyRejectsWrongIssuerKey(t *testing.T) {
	a := newTestIssuer(t)
	b := newTestIssuer(t)
	tok, _ := a.Issue(Subject{UserID: "u", SessionID: "s"}, time.Now())
	if _, err := b.Verify(tok); err == nil {
		t.Fatal("expected verification with a different key to fail")
	}
}

func TestJWKS(t *testing.T) {
	iss := newTestIssuer(t)
	jwks := iss.JWKS()
	if len(jwks.Keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(jwks.Keys))
	}
	k := jwks.Keys[0]
	if k.Kty != "EC" || k.Crv != "P-256" || k.Alg != "ES256" {
		t.Errorf("unexpected JWK: %+v", k)
	}
	if k.Kid != "test-kid" {
		t.Errorf("kid = %q", k.Kid)
	}
	if k.X == "" || k.Y == "" {
		t.Error("JWK missing coordinates")
	}
}
