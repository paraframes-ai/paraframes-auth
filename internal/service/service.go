// Package service implements the platform's authentication and identity
// business logic, independent of transport (HTTP).
package service

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/paraframes-ai/paraframes-auth/internal/cryptorand"
	"github.com/paraframes-ai/paraframes-auth/internal/email"
	"github.com/paraframes-ai/paraframes-auth/internal/oauth"
	"github.com/paraframes-ai/paraframes-auth/internal/password"
	"github.com/paraframes-ai/paraframes-auth/internal/store"
	"github.com/paraframes-ai/paraframes-auth/internal/token"
	"github.com/paraframes-ai/paraframes-auth/internal/webauthnx"
)

// Error is a domain error with a stable code that the HTTP layer maps to a
// status and client-facing message.
type Error struct {
	Code    string
	Message string
}

func (e *Error) Error() string { return e.Code + ": " + e.Message }

func newErr(code, msg string) *Error { return &Error{Code: code, Message: msg} }

// Domain errors.
var (
	ErrEmailTaken         = newErr("email_taken", "an account with this email already exists")
	ErrInvalidCredentials = newErr("invalid_credentials", "invalid email or password")
	ErrInvalidToken       = newErr("invalid_token", "the token is invalid or has expired")
	ErrAccountDisabled    = newErr("account_disabled", "this account has been disabled")
	ErrEmailNotVerified   = newErr("email_not_verified", "email address is not verified")
	ErrWeakPassword       = newErr("weak_password", "password does not meet requirements")
	ErrValidation         = newErr("validation_error", "the request is invalid")
	ErrNotFound           = newErr("not_found", "resource not found")
	ErrBetaRequired       = newErr("beta_required", "this feature is limited to beta testers")
	ErrBetaCodeInvalid    = newErr("beta_code_invalid", "invalid beta access code")
	ErrProviderNotEnabled = newErr("provider_not_enabled", "this login provider is not enabled")
	ErrNoPassword         = newErr("no_password", "this account has no password set")
)

// Config carries the service's tunable settings.
type Config struct {
	PublicURL       string
	RefreshTokenTTL time.Duration
	BetaAccessCode  string
	PasswordParams  password.Params
}

// Service is the application core.
type Service struct {
	store     *store.Store
	issuer    *token.Issuer
	verifiers *oauth.Verifiers
	webauthn  *webauthnx.Manager
	mailer    email.Mailer
	cfg       Config

	now func() time.Time
}

// New constructs a Service.
func New(
	st *store.Store,
	issuer *token.Issuer,
	verifiers *oauth.Verifiers,
	wa *webauthnx.Manager,
	mailer email.Mailer,
	cfg Config,
) *Service {
	return &Service{
		store:     st,
		issuer:    issuer,
		verifiers: verifiers,
		webauthn:  wa,
		mailer:    mailer,
		cfg:       cfg,
		now:       time.Now,
	}
}

// SetClock overrides the time source (for tests).
func (s *Service) SetClock(now func() time.Time) { s.now = now }

// RequestMeta carries device/network context for a session-creating action.
type RequestMeta struct {
	UserAgent string
	IP        string
}

// TokenPair is returned on any successful authentication.
type TokenPair struct {
	AccessToken  string    `json:"access_token"`
	TokenType    string    `json:"token_type"`
	ExpiresIn    int       `json:"expires_in"` // access token lifetime in seconds
	RefreshToken string    `json:"refresh_token"`
	ExpiresAt    time.Time `json:"-"`
}

// UserView is a client-safe representation of a user.
type UserView struct {
	ID            string    `json:"id"`
	Email         string    `json:"email,omitempty"`
	EmailVerified bool      `json:"email_verified"`
	DisplayName   string    `json:"display_name"`
	IsBetaTester  bool      `json:"is_beta_tester"`
	CreatedAt     time.Time `json:"created_at"`
}

// AuthResult bundles the tokens and user returned by a login/registration.
type AuthResult struct {
	User   UserView  `json:"user"`
	Tokens TokenPair `json:"tokens"`
}

func toUserView(u *store.User) UserView {
	return UserView{
		ID:            u.ID,
		Email:         u.Email,
		EmailVerified: u.EmailVerified,
		DisplayName:   u.DisplayName,
		IsBetaTester:  u.IsBetaTester,
		CreatedAt:     u.CreatedAt,
	}
}

// normalizeEmail lowercases and trims an email address.
func normalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

// issueTokens creates a new session and returns an access+refresh token pair.
func (s *Service) issueTokens(ctx context.Context, u *store.User, meta RequestMeta, parentID *string) (*TokenPair, error) {
	refresh, err := cryptorand.Token(32)
	if err != nil {
		return nil, err
	}
	now := s.now()
	sess, err := s.store.CreateSession(ctx, &store.Session{
		UserID:    u.ID,
		TokenHash: cryptorand.HashToken(refresh),
		ParentID:  parentID,
		UserAgent: meta.UserAgent,
		IP:        meta.IP,
		ExpiresAt: now.Add(s.cfg.RefreshTokenTTL),
	})
	if err != nil {
		return nil, err
	}
	return s.accessTokenForSession(u, sess.ID, refresh)
}

func (s *Service) accessTokenForSession(u *store.User, sessionID, refresh string) (*TokenPair, error) {
	now := s.now()
	access, err := s.issuer.Issue(token.Subject{
		UserID:        u.ID,
		Email:         u.Email,
		EmailVerified: u.EmailVerified,
		BetaTester:    u.IsBetaTester,
		SessionID:     sessionID,
	}, now)
	if err != nil {
		return nil, err
	}
	return &TokenPair{
		AccessToken:  access,
		TokenType:    "Bearer",
		ExpiresIn:    int(s.issuer.TTL().Seconds()),
		RefreshToken: refresh,
		ExpiresAt:    now.Add(s.issuer.TTL()),
	}, nil
}

// asStoreErr maps store errors to domain errors where useful.
func asStoreErr(err error) error {
	switch {
	case errors.Is(err, store.ErrNotFound):
		return ErrNotFound
	case errors.Is(err, store.ErrConflict):
		return ErrEmailTaken
	default:
		return err
	}
}
