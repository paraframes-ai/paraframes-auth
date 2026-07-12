package store

import "time"

// User is an identity in the platform.
type User struct {
	ID            string
	Email         string // may be empty for provider-relayed private emails
	EmailVerified bool
	PasswordHash  *string // nil for social-only or passkey-only accounts
	DisplayName   string
	IsBetaTester  bool
	Disabled      bool
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

// Identity links a user to an external OIDC provider (google, apple).
type Identity struct {
	ID        string
	UserID    string
	Provider  string
	Subject   string
	Email     string
	CreatedAt time.Time
}

// Session represents a refresh-token-backed session (one per device/login).
type Session struct {
	ID         string
	UserID     string
	TokenHash  []byte
	ParentID   *string
	UserAgent  string
	IP         string
	ExpiresAt  time.Time
	RevokedAt  *time.Time
	CreatedAt  time.Time
	LastUsedAt time.Time
}

// IsActive reports whether the session can still be used to refresh.
func (s *Session) IsActive(now time.Time) bool {
	return s.RevokedAt == nil && now.Before(s.ExpiresAt)
}

// EmailTokenPurpose enumerates the purposes of a one-time email token.
type EmailTokenPurpose string

const (
	PurposeVerifyEmail   EmailTokenPurpose = "verify_email"
	PurposeResetPassword EmailTokenPurpose = "reset_password"
)

// EmailToken is a single-use token delivered by email.
type EmailToken struct {
	ID         string
	UserID     string
	TokenHash  []byte
	Purpose    EmailTokenPurpose
	ExpiresAt  time.Time
	ConsumedAt *time.Time
	CreatedAt  time.Time
}

// WebAuthnCredential is a registered passkey.
type WebAuthnCredential struct {
	ID              string
	UserID          string
	CredentialID    []byte
	PublicKey       []byte
	AttestationType string
	AAGUID          []byte
	SignCount       uint32
	CloneWarning    bool
	Transports      []string
	Name            string
	CreatedAt       time.Time
	LastUsedAt      time.Time
}

// WebAuthnChallenge stores in-flight ceremony session data between begin/finish.
type WebAuthnChallenge struct {
	ID        string
	UserID    *string
	Data      []byte // serialized webauthn.SessionData
	ExpiresAt time.Time
	CreatedAt time.Time
}
