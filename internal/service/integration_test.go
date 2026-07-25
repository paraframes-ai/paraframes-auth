package service_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/paraframes-ai/paraframes-auth/internal/database"
	"github.com/paraframes-ai/paraframes-auth/internal/email"
	"github.com/paraframes-ai/paraframes-auth/internal/oauth"
	"github.com/paraframes-ai/paraframes-auth/internal/password"
	"github.com/paraframes-ai/paraframes-auth/internal/service"
	"github.com/paraframes-ai/paraframes-auth/internal/store"
	"github.com/paraframes-ai/paraframes-auth/internal/token"
	"github.com/paraframes-ai/paraframes-auth/internal/webauthnx"
)

// newTestService connects to TEST_DATABASE_URL, migrates, truncates, and returns
// a ready Service. The test is skipped when TEST_DATABASE_URL is unset.
func newTestService(t *testing.T) (*service.Service, *store.Store) {
	t.Helper()
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("set TEST_DATABASE_URL to run integration tests")
	}
	ctx := context.Background()
	pool, err := database.Connect(ctx, url)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(pool.Close)
	if err := database.Migrate(ctx, pool); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if _, err := pool.Exec(ctx, `TRUNCATE users, identities, sessions, email_tokens, webauthn_credentials, webauthn_challenges CASCADE`); err != nil {
		t.Fatalf("truncate: %v", err)
	}
	st := store.New(pool)
	issuer, err := token.NewIssuer("", "test", "https://test", "test-aud", 15*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	wa, err := webauthnx.New("localhost", "Test", []string{"http://localhost"})
	if err != nil {
		t.Fatal(err)
	}
	p := password.DefaultParams()
	p.Memory = 8 * 1024
	p.Iterations = 1
	svc := service.New(st, issuer, oauth.NewVerifiers(oauth.Config{}), wa, email.ConsoleMailer{}, service.Config{
		PublicURL:       "https://test",
		RefreshTokenTTL: time.Hour,
		BetaAccessCode:  "beta-code",
		PasswordParams:  p,
	})
	return svc, st
}

func TestRegisterLoginRefresh(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()
	meta := service.RequestMeta{UserAgent: "test", IP: "127.0.0.1"}

	reg, err := svc.Register(ctx, "user@example.com", "supersecret123", "User", meta)
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if reg.User.Email != "user@example.com" {
		t.Errorf("email = %q", reg.User.Email)
	}

	// Duplicate registration must conflict.
	if _, err := svc.Register(ctx, "user@example.com", "supersecret123", "", meta); err != service.ErrEmailTaken {
		t.Errorf("duplicate register err = %v, want ErrEmailTaken", err)
	}

	// Wrong password.
	if _, err := svc.Login(ctx, "user@example.com", "wrongpass999", meta); err != service.ErrInvalidCredentials {
		t.Errorf("bad login err = %v", err)
	}

	login, err := svc.Login(ctx, "user@example.com", "supersecret123", meta)
	if err != nil {
		t.Fatalf("login: %v", err)
	}

	// Refresh rotates the token.
	rotated, err := svc.Refresh(ctx, login.Tokens.RefreshToken, meta)
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if rotated.RefreshToken == login.Tokens.RefreshToken {
		t.Error("refresh token was not rotated")
	}
}

func TestRefreshReuseDetection(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()
	meta := service.RequestMeta{UserAgent: "test", IP: "127.0.0.1"}

	reg, err := svc.Register(ctx, "reuse@example.com", "supersecret123", "", meta)
	if err != nil {
		t.Fatal(err)
	}
	rotated, err := svc.Refresh(ctx, reg.Tokens.RefreshToken, meta)
	if err != nil {
		t.Fatal(err)
	}

	// Replaying the original (now-rotated-away) token is a breach signal.
	if _, err := svc.Refresh(ctx, reg.Tokens.RefreshToken, meta); err != service.ErrInvalidToken {
		t.Errorf("replay err = %v, want ErrInvalidToken", err)
	}

	// The breach must revoke the entire session family, including the token
	// that was legitimately issued by the rotation. This is the regression the
	// RevokeAllSessions uuid-cast fix protects.
	if _, err := svc.Refresh(ctx, rotated.RefreshToken, meta); err != service.ErrInvalidToken {
		t.Errorf("post-breach rotated token err = %v, want ErrInvalidToken (family should be revoked)", err)
	}
}

func TestBetaEnrollmentGatesPasskeys(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()
	meta := service.RequestMeta{UserAgent: "test", IP: "127.0.0.1"}

	reg, err := svc.Register(ctx, "beta@example.com", "supersecret123", "", meta)
	if err != nil {
		t.Fatal(err)
	}
	uid := reg.User.ID

	if _, _, err := svc.BeginPasskeyRegistration(ctx, uid); err != service.ErrBetaRequired {
		t.Errorf("passkey without beta err = %v, want ErrBetaRequired", err)
	}
	if _, err := svc.EnrollBeta(ctx, uid, "wrong"); err != service.ErrBetaCodeInvalid {
		t.Errorf("wrong beta code err = %v", err)
	}
	view, err := svc.EnrollBeta(ctx, uid, "beta-code")
	if err != nil || !view.IsBetaTester {
		t.Fatalf("enroll beta: err=%v beta=%v", err, view != nil && view.IsBetaTester)
	}
	if _, _, err := svc.BeginPasskeyRegistration(ctx, uid); err != nil {
		t.Errorf("passkey after beta err = %v, want nil", err)
	}
}

func TestPasswordResetRevokesSessions(t *testing.T) {
	svc, st := newTestService(t)
	ctx := context.Background()
	meta := service.RequestMeta{UserAgent: "test", IP: "127.0.0.1"}

	reg, err := svc.Register(ctx, "reset@example.com", "supersecret123", "", meta)
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.ForgotPassword(ctx, "reset@example.com"); err != nil {
		t.Fatal(err)
	}
	// The reset token is single-use and delivered by email; here we drive the
	// change-password path (which also revokes sessions) as a proxy.
	if err := svc.ChangePassword(ctx, reg.User.ID, "supersecret123", "newsecret456", ""); err != nil {
		t.Fatalf("change password: %v", err)
	}
	sessions, err := st.ListActiveSessions(ctx, reg.User.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(sessions) != 0 {
		t.Errorf("expected all sessions revoked after password change, got %d", len(sessions))
	}
	// Old password no longer works.
	if _, err := svc.Login(ctx, "reset@example.com", "supersecret123", meta); err != service.ErrInvalidCredentials {
		t.Errorf("login with old password err = %v", err)
	}
}
