package service

import (
	"context"
	"crypto/subtle"
	"time"

	"github.com/paraframes-ai/paraframes-auth/internal/store"
)

// Me returns the current user's profile.
func (s *Service) Me(ctx context.Context, userID string) (*UserView, error) {
	u, err := s.store.GetUserByID(ctx, userID)
	if err != nil {
		return nil, asStoreErr(err)
	}
	v := toUserView(u)
	return &v, nil
}

// UpdateProfile updates mutable profile fields.
func (s *Service) UpdateProfile(ctx context.Context, userID, displayName string) (*UserView, error) {
	if err := s.store.SetDisplayName(ctx, userID, displayName); err != nil {
		return nil, err
	}
	return s.Me(ctx, userID)
}

// SessionView is a client-safe representation of a session.
type SessionView struct {
	ID         string    `json:"id"`
	UserAgent  string    `json:"user_agent"`
	IP         string    `json:"ip"`
	Current    bool      `json:"current"`
	CreatedAt  time.Time `json:"created_at"`
	LastUsedAt time.Time `json:"last_used_at"`
	ExpiresAt  time.Time `json:"expires_at"`
}

// ListSessions returns the user's active sessions, flagging the current one.
func (s *Service) ListSessions(ctx context.Context, userID, currentSessionID string) ([]SessionView, error) {
	sessions, err := s.store.ListActiveSessions(ctx, userID)
	if err != nil {
		return nil, err
	}
	out := make([]SessionView, 0, len(sessions))
	for _, sess := range sessions {
		out = append(out, SessionView{
			ID:         sess.ID,
			UserAgent:  sess.UserAgent,
			IP:         sess.IP,
			Current:    sess.ID == currentSessionID,
			CreatedAt:  sess.CreatedAt,
			LastUsedAt: sess.LastUsedAt,
			ExpiresAt:  sess.ExpiresAt,
		})
	}
	return out, nil
}

// RevokeSession revokes one of the user's sessions by ID.
func (s *Service) RevokeSession(ctx context.Context, userID, sessionID string) error {
	sess, err := s.store.GetSessionByID(ctx, sessionID)
	if err != nil {
		return asStoreErr(err)
	}
	if sess.UserID != userID {
		return ErrNotFound // do not reveal other users' sessions
	}
	return s.store.RevokeSession(ctx, sessionID)
}

// RevokeOtherSessions revokes all of the user's sessions except the current one.
func (s *Service) RevokeOtherSessions(ctx context.Context, userID, keepSessionID string) error {
	return s.store.RevokeAllSessions(ctx, userID, keepSessionID)
}

// EnrollBeta grants beta-tester access if the provided code matches the
// configured beta access code. This is what unlocks passkey enrollment.
func (s *Service) EnrollBeta(ctx context.Context, userID, code string) (*UserView, error) {
	if s.cfg.BetaAccessCode == "" {
		return nil, ErrBetaCodeInvalid
	}
	if subtle.ConstantTimeCompare([]byte(code), []byte(s.cfg.BetaAccessCode)) != 1 {
		return nil, ErrBetaCodeInvalid
	}
	if err := s.store.SetBetaTester(ctx, userID, true); err != nil {
		return nil, err
	}
	return s.Me(ctx, userID)
}

// loadUser is a small helper used by passkey flows.
func (s *Service) loadUser(ctx context.Context, userID string) (*store.User, error) {
	u, err := s.store.GetUserByID(ctx, userID)
	if err != nil {
		return nil, asStoreErr(err)
	}
	return u, nil
}
