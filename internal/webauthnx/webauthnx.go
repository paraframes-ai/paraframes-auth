// Package webauthnx wraps go-webauthn, adapting the platform's user and
// credential models to the library's interfaces.
package webauthnx

import (
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/paraframes-ai/paraframes-auth/internal/store"
)

// Manager owns the configured WebAuthn relying party.
type Manager struct {
	wa *webauthn.WebAuthn
}

// New constructs a Manager for the given relying party settings.
func New(rpID, rpDisplayName string, origins []string) (*Manager, error) {
	wa, err := webauthn.New(&webauthn.Config{
		RPID:          rpID,
		RPDisplayName: rpDisplayName,
		RPOrigins:     origins,
	})
	if err != nil {
		return nil, err
	}
	return &Manager{wa: wa}, nil
}

// WebAuthn exposes the underlying relying party.
func (m *Manager) WebAuthn() *webauthn.WebAuthn { return m.wa }

// User adapts a store.User plus its passkeys to the webauthn.User interface.
type User struct {
	Model       *store.User
	Credentials []store.WebAuthnCredential
}

var _ webauthn.User = (*User)(nil)

// WebAuthnID returns the raw user handle (the user UUID bytes).
func (u *User) WebAuthnID() []byte { return []byte(u.Model.ID) }

// WebAuthnName returns the username (email, falling back to the user ID).
func (u *User) WebAuthnName() string {
	if u.Model.Email != "" {
		return u.Model.Email
	}
	return u.Model.ID
}

// WebAuthnDisplayName returns the human-friendly display name.
func (u *User) WebAuthnDisplayName() string {
	if u.Model.DisplayName != "" {
		return u.Model.DisplayName
	}
	return u.WebAuthnName()
}

// WebAuthnCredentials returns the user's registered credentials.
func (u *User) WebAuthnCredentials() []webauthn.Credential {
	out := make([]webauthn.Credential, 0, len(u.Credentials))
	for i := range u.Credentials {
		out = append(out, ToLibCredential(&u.Credentials[i]))
	}
	return out
}

// ToLibCredential converts a stored credential to the library type.
func ToLibCredential(c *store.WebAuthnCredential) webauthn.Credential {
	transports := make([]protocol.AuthenticatorTransport, 0, len(c.Transports))
	for _, t := range c.Transports {
		transports = append(transports, protocol.AuthenticatorTransport(t))
	}
	return webauthn.Credential{
		ID:              c.CredentialID,
		PublicKey:       c.PublicKey,
		AttestationType: c.AttestationType,
		Transport:       transports,
		Authenticator: webauthn.Authenticator{
			AAGUID:       c.AAGUID,
			SignCount:    c.SignCount,
			CloneWarning: c.CloneWarning,
		},
	}
}

// FromLibCredential converts a freshly created library credential into a
// storable model for the given user.
func FromLibCredential(userID string, c *webauthn.Credential) *store.WebAuthnCredential {
	transports := make([]string, 0, len(c.Transport))
	for _, t := range c.Transport {
		transports = append(transports, string(t))
	}
	return &store.WebAuthnCredential{
		UserID:          userID,
		CredentialID:    c.ID,
		PublicKey:       c.PublicKey,
		AttestationType: c.AttestationType,
		AAGUID:          c.Authenticator.AAGUID,
		SignCount:       c.Authenticator.SignCount,
		CloneWarning:    c.Authenticator.CloneWarning,
		Transports:      transports,
	}
}
