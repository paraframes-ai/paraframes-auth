package service

import (
	"context"
	"errors"

	"github.com/paraframes-ai/paraframes-auth/internal/oauth"
	"github.com/paraframes-ai/paraframes-auth/internal/store"
)

// SocialLogin verifies an OIDC ID token from a provider (google/apple), then
// finds or provisions the corresponding user and issues tokens.
//
// Account resolution order:
//  1. Existing identity (provider, subject) -> that user.
//  2. Verified email matching an existing user -> link identity to it.
//  3. Otherwise create a new user.
//
// displayName is an optional override supplied by the client (Apple only sends
// the name on the very first authorization).
func (s *Service) SocialLogin(ctx context.Context, provider oauth.Provider, idToken, displayName string, meta RequestMeta) (*AuthResult, error) {
	vf := s.verifiers.For(provider)
	if vf == nil {
		return nil, ErrProviderNotEnabled
	}
	claims, err := vf.Verify(ctx, idToken)
	if err != nil {
		if errors.Is(err, oauth.ErrInvalidToken) {
			return nil, ErrInvalidToken
		}
		return nil, err
	}

	// 1. Existing linked identity.
	identity, err := s.store.GetIdentity(ctx, string(provider), claims.Subject)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return nil, err
	}
	if identity != nil {
		u, err := s.store.GetUserByID(ctx, identity.UserID)
		if err != nil {
			return nil, err
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

	// 2. Link by verified email to an existing account.
	emailAddr := normalizeEmail(claims.Email)
	var u *store.User
	if emailAddr != "" && claims.EmailVerified {
		existing, err := s.store.GetUserByEmail(ctx, emailAddr)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			return nil, err
		}
		if existing != nil {
			u = existing
		}
	}

	// 3. Create a new user.
	if u == nil {
		name := displayName
		if name == "" {
			name = claims.Name
		}
		created, err := s.store.CreateUser(ctx, &store.User{
			Email:         emailAddr,
			EmailVerified: claims.EmailVerified,
			DisplayName:   name,
		})
		if err != nil {
			return nil, asStoreErr(err)
		}
		u = created
	} else if !u.EmailVerified && claims.EmailVerified {
		// Provider vouches for the email; mark it verified.
		if err := s.store.SetEmailVerified(ctx, u.ID, true); err != nil {
			return nil, err
		}
		u.EmailVerified = true
	}

	if u.Disabled {
		return nil, ErrAccountDisabled
	}

	// Link the identity.
	if err := s.store.CreateIdentity(ctx, &store.Identity{
		UserID:   u.ID,
		Provider: string(provider),
		Subject:  claims.Subject,
		Email:    emailAddr,
	}); err != nil && !errors.Is(err, store.ErrConflict) {
		return nil, err
	}

	tokens, err := s.issueTokens(ctx, u, meta, nil)
	if err != nil {
		return nil, err
	}
	return &AuthResult{User: toUserView(u), Tokens: *tokens}, nil
}
