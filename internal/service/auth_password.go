package service

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/paraframes-ai/paraframes-auth/internal/cryptorand"
	"github.com/paraframes-ai/paraframes-auth/internal/email"
	"github.com/paraframes-ai/paraframes-auth/internal/password"
	"github.com/paraframes-ai/paraframes-auth/internal/store"
)

const (
	emailVerifyTTL   = 24 * time.Hour
	passwordResetTTL = time.Hour
)

// Register creates a new email/password account and sends a verification email.
func (s *Service) Register(ctx context.Context, emailAddr, pw, displayName string, meta RequestMeta) (*AuthResult, error) {
	emailAddr = normalizeEmail(emailAddr)
	if emailAddr == "" || !looksLikeEmail(emailAddr) {
		return nil, ErrValidation
	}
	if err := password.Policy(pw); err != nil {
		return nil, &Error{Code: ErrWeakPassword.Code, Message: err.Error()}
	}
	hash, err := password.Hash(pw, s.cfg.PasswordParams)
	if err != nil {
		return nil, err
	}
	u, err := s.store.CreateUser(ctx, &store.User{
		Email:        emailAddr,
		PasswordHash: &hash,
		DisplayName:  displayName,
	})
	if err != nil {
		if errors.Is(err, store.ErrConflict) {
			return nil, ErrEmailTaken
		}
		return nil, err
	}

	if err := s.sendEmailVerification(ctx, u); err != nil {
		// Non-fatal: account is created; the user can request another email.
		// The error is logged by the caller if needed.
		_ = err
	}

	tokens, err := s.issueTokens(ctx, u, meta, nil)
	if err != nil {
		return nil, err
	}
	return &AuthResult{User: toUserView(u), Tokens: *tokens}, nil
}

// Login authenticates an email/password user.
func (s *Service) Login(ctx context.Context, emailAddr, pw string, meta RequestMeta) (*AuthResult, error) {
	emailAddr = normalizeEmail(emailAddr)
	u, err := s.store.GetUserByEmail(ctx, emailAddr)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			// Perform a dummy verify to reduce timing side-channels.
			_ = password.Verify(pw, dummyHash)
			return nil, ErrInvalidCredentials
		}
		return nil, err
	}
	if u.PasswordHash == nil {
		return nil, ErrInvalidCredentials
	}
	if err := password.Verify(pw, *u.PasswordHash); err != nil {
		return nil, ErrInvalidCredentials
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

// Refresh rotates a refresh token: the presented token is revoked and a new
// session (child) is issued. Presenting an already-revoked token is treated as
// theft and revokes the user's entire session tree.
func (s *Service) Refresh(ctx context.Context, refreshToken string, meta RequestMeta) (*TokenPair, error) {
	if refreshToken == "" {
		return nil, ErrInvalidToken
	}
	hash := cryptorand.HashToken(refreshToken)
	sess, err := s.store.GetSessionByTokenHash(ctx, hash)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, ErrInvalidToken
		}
		return nil, err
	}
	now := s.now()

	// Reuse detection: a token that was already rotated away (revoked) is being
	// replayed. Revoke all of the user's sessions defensively.
	if sess.RevokedAt != nil {
		_ = s.store.RevokeAllSessions(ctx, sess.UserID, "")
		return nil, ErrInvalidToken
	}
	if now.After(sess.ExpiresAt) {
		return nil, ErrInvalidToken
	}

	u, err := s.store.GetUserByID(ctx, sess.UserID)
	if err != nil {
		return nil, err
	}
	if u.Disabled {
		_ = s.store.RevokeAllSessions(ctx, u.ID, "")
		return nil, ErrAccountDisabled
	}

	// Rotate: revoke the current session and mint a child.
	if err := s.store.RevokeSession(ctx, sess.ID); err != nil {
		return nil, err
	}
	return s.issueTokens(ctx, u, meta, &sess.ID)
}

// Logout revokes the session associated with a refresh token.
func (s *Service) Logout(ctx context.Context, refreshToken string) error {
	if refreshToken == "" {
		return nil
	}
	sess, err := s.store.GetSessionByTokenHash(ctx, cryptorand.HashToken(refreshToken))
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil // already gone
		}
		return err
	}
	return s.store.RevokeSession(ctx, sess.ID)
}

// VerifyEmail consumes an email-verification token and marks the email verified.
func (s *Service) VerifyEmail(ctx context.Context, tokenStr string) error {
	tok, err := s.store.ConsumeEmailToken(ctx, cryptorand.HashToken(tokenStr), store.PurposeVerifyEmail)
	if err != nil {
		return ErrInvalidToken
	}
	return s.store.SetEmailVerified(ctx, tok.UserID, true)
}

// ResendVerification re-sends a verification email if the account exists and is
// unverified. It never reveals whether the email is registered.
func (s *Service) ResendVerification(ctx context.Context, emailAddr string) error {
	u, err := s.store.GetUserByEmail(ctx, normalizeEmail(emailAddr))
	if err != nil {
		return nil // do not leak existence
	}
	if u.EmailVerified {
		return nil
	}
	return s.sendEmailVerification(ctx, u)
}

// ForgotPassword issues a password-reset email if the account exists. It never
// reveals whether the email is registered.
func (s *Service) ForgotPassword(ctx context.Context, emailAddr string) error {
	u, err := s.store.GetUserByEmail(ctx, normalizeEmail(emailAddr))
	if err != nil {
		return nil
	}
	if err := s.store.InvalidateEmailTokens(ctx, u.ID, store.PurposeResetPassword); err != nil {
		return err
	}
	raw, err := cryptorand.Token(32)
	if err != nil {
		return err
	}
	if err := s.store.CreateEmailToken(ctx, &store.EmailToken{
		UserID:    u.ID,
		TokenHash: cryptorand.HashToken(raw),
		Purpose:   store.PurposeResetPassword,
		ExpiresAt: s.now().Add(passwordResetTTL),
	}); err != nil {
		return err
	}
	link := fmt.Sprintf("%s/reset-password?token=%s", s.cfg.PublicURL, raw)
	return s.mailer.Send(ctx, email.Message{
		To:      u.Email,
		Subject: "Reset your password",
		Text:    fmt.Sprintf("Use the link below to reset your password. It expires in 1 hour.\n\n%s\n\nIf you did not request this, you can ignore this email.", link),
	})
}

// ResetPassword consumes a reset token, sets a new password, and revokes all
// existing sessions.
func (s *Service) ResetPassword(ctx context.Context, tokenStr, newPassword string) error {
	if err := password.Policy(newPassword); err != nil {
		return &Error{Code: ErrWeakPassword.Code, Message: err.Error()}
	}
	tok, err := s.store.ConsumeEmailToken(ctx, cryptorand.HashToken(tokenStr), store.PurposeResetPassword)
	if err != nil {
		return ErrInvalidToken
	}
	hash, err := password.Hash(newPassword, s.cfg.PasswordParams)
	if err != nil {
		return err
	}
	if err := s.store.SetPasswordHash(ctx, tok.UserID, hash); err != nil {
		return err
	}
	// Password changed: invalidate every session.
	return s.store.RevokeAllSessions(ctx, tok.UserID, "")
}

// ChangePassword updates a logged-in user's password after verifying the
// current one, then revokes all other sessions.
func (s *Service) ChangePassword(ctx context.Context, userID, currentPassword, newPassword, keepSessionID string) error {
	if err := password.Policy(newPassword); err != nil {
		return &Error{Code: ErrWeakPassword.Code, Message: err.Error()}
	}
	u, err := s.store.GetUserByID(ctx, userID)
	if err != nil {
		return asStoreErr(err)
	}
	if u.PasswordHash == nil {
		return ErrNoPassword
	}
	if err := password.Verify(currentPassword, *u.PasswordHash); err != nil {
		return ErrInvalidCredentials
	}
	hash, err := password.Hash(newPassword, s.cfg.PasswordParams)
	if err != nil {
		return err
	}
	if err := s.store.SetPasswordHash(ctx, userID, hash); err != nil {
		return err
	}
	return s.store.RevokeAllSessions(ctx, userID, keepSessionID)
}

func (s *Service) sendEmailVerification(ctx context.Context, u *store.User) error {
	if u.Email == "" {
		return nil
	}
	if err := s.store.InvalidateEmailTokens(ctx, u.ID, store.PurposeVerifyEmail); err != nil {
		return err
	}
	raw, err := cryptorand.Token(32)
	if err != nil {
		return err
	}
	if err := s.store.CreateEmailToken(ctx, &store.EmailToken{
		UserID:    u.ID,
		TokenHash: cryptorand.HashToken(raw),
		Purpose:   store.PurposeVerifyEmail,
		ExpiresAt: s.now().Add(emailVerifyTTL),
	}); err != nil {
		return err
	}
	link := fmt.Sprintf("%s/verify-email?token=%s", s.cfg.PublicURL, raw)
	return s.mailer.Send(ctx, email.Message{
		To:      u.Email,
		Subject: "Verify your email address",
		Text:    fmt.Sprintf("Welcome! Confirm your email using the link below (valid for 24 hours).\n\n%s", link),
	})
}

// dummyHash is a precomputed Argon2id hash used to equalize timing on
// login attempts for non-existent accounts.
var dummyHash = "$argon2id$v=19$m=65536,t=3,p=2$AAAAAAAAAAAAAAAAAAAAAA$RdescudvJCsgt3ub+b+dWRWJTmaaJObG3G+wLKw2Fjo"

func looksLikeEmail(s string) bool {
	at := -1
	for i, r := range s {
		if r == '@' {
			if at != -1 {
				return false
			}
			at = i
		}
	}
	return at > 0 && at < len(s)-1
}
