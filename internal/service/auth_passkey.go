package service

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/paraframes-ai/paraframes-auth/internal/store"
	"github.com/paraframes-ai/paraframes-auth/internal/webauthnx"
)

const passkeyChallengeTTL = 5 * time.Minute

// PasskeyView is a client-safe representation of a registered passkey.
type PasskeyView struct {
	ID         string    `json:"id"`
	Name       string    `json:"name"`
	Transports []string  `json:"transports"`
	CreatedAt  time.Time `json:"created_at"`
	LastUsedAt time.Time `json:"last_used_at"`
}

// BeginPasskeyRegistration starts a passkey registration ceremony for a beta
// tester, returning WebAuthn creation options and a challenge ID to echo back.
func (s *Service) BeginPasskeyRegistration(ctx context.Context, userID string) (json.RawMessage, string, error) {
	if s.webauthn == nil {
		return nil, "", ErrProviderNotEnabled
	}
	u, err := s.loadUser(ctx, userID)
	if err != nil {
		return nil, "", err
	}
	if !u.IsBetaTester {
		return nil, "", ErrBetaRequired
	}
	creds, err := s.store.ListWebAuthnCredentials(ctx, userID)
	if err != nil {
		return nil, "", err
	}
	waUser := &webauthnx.User{Model: u, Credentials: creds}

	exclusions := make([]protocol.CredentialDescriptor, 0, len(creds))
	for _, c := range waUser.WebAuthnCredentials() {
		exclusions = append(exclusions, c.Descriptor())
	}

	options, sessionData, err := s.webauthn.WebAuthn().BeginRegistration(
		waUser,
		webauthn.WithExclusions(exclusions),
		webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
			ResidentKey:      protocol.ResidentKeyRequirementPreferred,
			UserVerification: protocol.VerificationPreferred,
		}),
		webauthn.WithConveyancePreference(protocol.PreferNoAttestation),
	)
	if err != nil {
		return nil, "", err
	}

	challengeID, err := s.storeChallenge(ctx, &userID, sessionData)
	if err != nil {
		return nil, "", err
	}
	raw, err := json.Marshal(options)
	if err != nil {
		return nil, "", err
	}
	return raw, challengeID, nil
}

// FinishPasskeyRegistration completes a registration ceremony and stores the
// new credential.
func (s *Service) FinishPasskeyRegistration(ctx context.Context, userID, challengeID string, responseBody []byte, name string) (*PasskeyView, error) {
	if s.webauthn == nil {
		return nil, ErrProviderNotEnabled
	}
	u, err := s.loadUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	if !u.IsBetaTester {
		return nil, ErrBetaRequired
	}
	sessionData, err := s.consumeChallenge(ctx, challengeID)
	if err != nil {
		return nil, err
	}
	creds, err := s.store.ListWebAuthnCredentials(ctx, userID)
	if err != nil {
		return nil, err
	}
	waUser := &webauthnx.User{Model: u, Credentials: creds}

	parsed, err := protocol.ParseCredentialCreationResponseBody(bytes.NewReader(responseBody))
	if err != nil {
		return nil, ErrValidation
	}
	cred, err := s.webauthn.WebAuthn().CreateCredential(waUser, *sessionData, parsed)
	if err != nil {
		return nil, ErrValidation
	}

	model := webauthnx.FromLibCredential(userID, cred)
	model.Name = name
	if err := s.store.CreateWebAuthnCredential(ctx, model); err != nil {
		if errors.Is(err, store.ErrConflict) {
			return nil, newErr("passkey_exists", "this passkey is already registered")
		}
		return nil, err
	}
	return &PasskeyView{
		ID:         model.ID,
		Name:       model.Name,
		Transports: model.Transports,
		CreatedAt:  model.CreatedAt,
		LastUsedAt: model.LastUsedAt,
	}, nil
}

// BeginPasskeyLogin starts an assertion ceremony. If emailAddr is provided the
// ceremony targets that user's credentials; otherwise a discoverable
// (usernameless) login is started.
func (s *Service) BeginPasskeyLogin(ctx context.Context, emailAddr string) (json.RawMessage, string, error) {
	if s.webauthn == nil {
		return nil, "", ErrProviderNotEnabled
	}
	emailAddr = normalizeEmail(emailAddr)

	var (
		options     *protocol.CredentialAssertion
		sessionData *webauthn.SessionData
		challUser   *string
		err         error
	)

	if emailAddr != "" {
		u, gerr := s.store.GetUserByEmail(ctx, emailAddr)
		if gerr != nil {
			// Avoid leaking existence: start a discoverable ceremony instead.
			options, sessionData, err = s.webauthn.WebAuthn().BeginDiscoverableLogin()
		} else {
			creds, lerr := s.store.ListWebAuthnCredentials(ctx, u.ID)
			if lerr != nil {
				return nil, "", lerr
			}
			if !u.IsBetaTester || len(creds) == 0 {
				options, sessionData, err = s.webauthn.WebAuthn().BeginDiscoverableLogin()
			} else {
				waUser := &webauthnx.User{Model: u, Credentials: creds}
				options, sessionData, err = s.webauthn.WebAuthn().BeginLogin(waUser)
				uid := u.ID
				challUser = &uid
			}
		}
	} else {
		options, sessionData, err = s.webauthn.WebAuthn().BeginDiscoverableLogin()
	}
	if err != nil {
		return nil, "", err
	}

	challengeID, err := s.storeChallenge(ctx, challUser, sessionData)
	if err != nil {
		return nil, "", err
	}
	raw, err := json.Marshal(options)
	if err != nil {
		return nil, "", err
	}
	return raw, challengeID, nil
}

// FinishPasskeyLogin completes an assertion ceremony and issues tokens.
func (s *Service) FinishPasskeyLogin(ctx context.Context, challengeID string, responseBody []byte, meta RequestMeta) (*AuthResult, error) {
	if s.webauthn == nil {
		return nil, ErrProviderNotEnabled
	}
	challenge, err := s.consumeChallengeRaw(ctx, challengeID)
	if err != nil {
		return nil, err
	}
	var sessionData webauthn.SessionData
	if err := json.Unmarshal(challenge.Data, &sessionData); err != nil {
		return nil, ErrInvalidToken
	}

	parsed, err := protocol.ParseCredentialRequestResponseBody(bytes.NewReader(responseBody))
	if err != nil {
		return nil, ErrValidation
	}

	var u *store.User

	if challenge.UserID != nil {
		// Non-discoverable: we know the user.
		u, err = s.loadUser(ctx, *challenge.UserID)
		if err != nil {
			return nil, err
		}
		creds, err := s.store.ListWebAuthnCredentials(ctx, u.ID)
		if err != nil {
			return nil, err
		}
		waUser := &webauthnx.User{Model: u, Credentials: creds}
		cred, err := s.webauthn.WebAuthn().ValidateLogin(waUser, sessionData, parsed)
		if err != nil {
			return nil, ErrInvalidCredentials
		}
		s.updateSignCount(ctx, cred)
	} else {
		// Discoverable: resolve the user from the credential's user handle.
		cred, err := s.webauthn.WebAuthn().ValidateDiscoverableLogin(
			func(_, userHandle []byte) (webauthn.User, error) {
				loaded, err := s.loadUser(ctx, string(userHandle))
				if err != nil {
					return nil, err
				}
				if !loaded.IsBetaTester {
					return nil, ErrBetaRequired
				}
				creds, err := s.store.ListWebAuthnCredentials(ctx, loaded.ID)
				if err != nil {
					return nil, err
				}
				u = loaded
				return &webauthnx.User{Model: loaded, Credentials: creds}, nil
			}, sessionData, parsed)
		if err != nil || u == nil {
			return nil, ErrInvalidCredentials
		}
		s.updateSignCount(ctx, cred)
	}

	if u.Disabled {
		return nil, ErrAccountDisabled
	}
	tokens, err := s.issueTokens(ctx, u, meta, nil)
	if err != nil {
		return nil, err
	}
	return &AuthResult{User: toUserView(u), Tokens: *tokens}, nil
}

// ListPasskeys returns the user's registered passkeys.
func (s *Service) ListPasskeys(ctx context.Context, userID string) ([]PasskeyView, error) {
	creds, err := s.store.ListWebAuthnCredentials(ctx, userID)
	if err != nil {
		return nil, err
	}
	out := make([]PasskeyView, 0, len(creds))
	for _, c := range creds {
		out = append(out, PasskeyView{
			ID:         c.ID,
			Name:       c.Name,
			Transports: c.Transports,
			CreatedAt:  c.CreatedAt,
			LastUsedAt: c.LastUsedAt,
		})
	}
	return out, nil
}

// DeletePasskey removes one of the user's passkeys.
func (s *Service) DeletePasskey(ctx context.Context, userID, id string) error {
	if err := s.store.DeleteWebAuthnCredential(ctx, userID, id); err != nil {
		return asStoreErr(err)
	}
	return nil
}

func (s *Service) updateSignCount(ctx context.Context, cred *webauthn.Credential) {
	_ = s.store.UpdateWebAuthnSignCount(ctx, cred.ID, cred.Authenticator.SignCount, cred.Authenticator.CloneWarning)
}

func (s *Service) storeChallenge(ctx context.Context, userID *string, sessionData *webauthn.SessionData) (string, error) {
	data, err := json.Marshal(sessionData)
	if err != nil {
		return "", err
	}
	ch := &store.WebAuthnChallenge{
		UserID:    userID,
		Data:      data,
		ExpiresAt: s.now().Add(passkeyChallengeTTL),
	}
	if err := s.store.CreateWebAuthnChallenge(ctx, ch); err != nil {
		return "", err
	}
	return ch.ID, nil
}

func (s *Service) consumeChallenge(ctx context.Context, id string) (*webauthn.SessionData, error) {
	ch, err := s.consumeChallengeRaw(ctx, id)
	if err != nil {
		return nil, err
	}
	var sd webauthn.SessionData
	if err := json.Unmarshal(ch.Data, &sd); err != nil {
		return nil, ErrInvalidToken
	}
	return &sd, nil
}

func (s *Service) consumeChallengeRaw(ctx context.Context, id string) (*store.WebAuthnChallenge, error) {
	if id == "" {
		return nil, ErrInvalidToken
	}
	ch, err := s.store.ConsumeWebAuthnChallenge(ctx, id)
	if err != nil {
		return nil, ErrInvalidToken
	}
	return ch, nil
}
