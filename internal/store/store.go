// Package store provides typed repository access to the Postgres-backed data
// model used by the auth service.
package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrNotFound is returned when a queried row does not exist.
var ErrNotFound = errors.New("not found")

// ErrConflict is returned on a unique-constraint violation.
var ErrConflict = errors.New("conflict")

// Store is the repository root, wrapping a pgx pool.
type Store struct {
	pool *pgxpool.Pool
}

// New constructs a Store.
func New(pool *pgxpool.Pool) *Store { return &Store{pool: pool} }

// Pool exposes the underlying pool (for health checks).
func (s *Store) Pool() *pgxpool.Pool { return s.pool }

func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code == "23505"
	}
	return false
}

// --- Users ---

const userCols = `id, email, email_verified, password_hash, display_name, is_beta_tester, disabled, created_at, updated_at`

func scanUser(row pgx.Row) (*User, error) {
	var u User
	var email *string
	err := row.Scan(&u.ID, &email, &u.EmailVerified, &u.PasswordHash, &u.DisplayName, &u.IsBetaTester, &u.Disabled, &u.CreatedAt, &u.UpdatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	if email != nil {
		u.Email = *email
	}
	return &u, nil
}

// CreateUser inserts a new user. A nil/empty email is stored as SQL NULL.
func (s *Store) CreateUser(ctx context.Context, u *User) (*User, error) {
	var email *string
	if u.Email != "" {
		email = &u.Email
	}
	row := s.pool.QueryRow(ctx,
		`INSERT INTO users (email, email_verified, password_hash, display_name, is_beta_tester)
		 VALUES ($1,$2,$3,$4,$5) RETURNING `+userCols,
		email, u.EmailVerified, u.PasswordHash, u.DisplayName, u.IsBetaTester)
	created, err := scanUser(row)
	if err != nil {
		if isUniqueViolation(err) {
			return nil, ErrConflict
		}
		return nil, err
	}
	return created, nil
}

// GetUserByID looks up a user by ID.
func (s *Store) GetUserByID(ctx context.Context, id string) (*User, error) {
	return scanUser(s.pool.QueryRow(ctx, `SELECT `+userCols+` FROM users WHERE id=$1`, id))
}

// GetUserByEmail looks up a user by email (case-insensitive).
func (s *Store) GetUserByEmail(ctx context.Context, email string) (*User, error) {
	return scanUser(s.pool.QueryRow(ctx, `SELECT `+userCols+` FROM users WHERE email=$1`, email))
}

// SetPasswordHash updates a user's password hash.
func (s *Store) SetPasswordHash(ctx context.Context, userID string, hash string) error {
	_, err := s.pool.Exec(ctx, `UPDATE users SET password_hash=$1, updated_at=now() WHERE id=$2`, hash, userID)
	return err
}

// SetEmailVerified marks a user's email as verified.
func (s *Store) SetEmailVerified(ctx context.Context, userID string, verified bool) error {
	_, err := s.pool.Exec(ctx, `UPDATE users SET email_verified=$1, updated_at=now() WHERE id=$2`, verified, userID)
	return err
}

// SetDisplayName updates a user's display name.
func (s *Store) SetDisplayName(ctx context.Context, userID, name string) error {
	_, err := s.pool.Exec(ctx, `UPDATE users SET display_name=$1, updated_at=now() WHERE id=$2`, name, userID)
	return err
}

// SetBetaTester toggles a user's beta-tester flag.
func (s *Store) SetBetaTester(ctx context.Context, userID string, beta bool) error {
	_, err := s.pool.Exec(ctx, `UPDATE users SET is_beta_tester=$1, updated_at=now() WHERE id=$2`, beta, userID)
	return err
}

// --- Identities ---

// GetIdentity looks up an external identity by provider and subject.
func (s *Store) GetIdentity(ctx context.Context, provider, subject string) (*Identity, error) {
	var id Identity
	err := s.pool.QueryRow(ctx,
		`SELECT id, user_id, provider, subject, email, created_at FROM identities WHERE provider=$1 AND subject=$2`,
		provider, subject).Scan(&id.ID, &id.UserID, &id.Provider, &id.Subject, &id.Email, &id.CreatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &id, nil
}

// CreateIdentity links a user to an external provider identity.
func (s *Store) CreateIdentity(ctx context.Context, id *Identity) error {
	err := s.pool.QueryRow(ctx,
		`INSERT INTO identities (user_id, provider, subject, email) VALUES ($1,$2,$3,$4) RETURNING id, created_at`,
		id.UserID, id.Provider, id.Subject, id.Email).Scan(&id.ID, &id.CreatedAt)
	if err != nil {
		if isUniqueViolation(err) {
			return ErrConflict
		}
		return err
	}
	return nil
}

// ListIdentities returns all external identities linked to a user.
func (s *Store) ListIdentities(ctx context.Context, userID string) ([]Identity, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, user_id, provider, subject, email, created_at FROM identities WHERE user_id=$1 ORDER BY created_at`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Identity
	for rows.Next() {
		var id Identity
		if err := rows.Scan(&id.ID, &id.UserID, &id.Provider, &id.Subject, &id.Email, &id.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// --- Sessions ---

const sessionCols = `id, user_id, token_hash, parent_id, user_agent, ip, expires_at, revoked_at, created_at, last_used_at`

func scanSession(row pgx.Row) (*Session, error) {
	var s Session
	err := row.Scan(&s.ID, &s.UserID, &s.TokenHash, &s.ParentID, &s.UserAgent, &s.IP, &s.ExpiresAt, &s.RevokedAt, &s.CreatedAt, &s.LastUsedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &s, nil
}

// CreateSession inserts a new session row.
func (s *Store) CreateSession(ctx context.Context, sess *Session) (*Session, error) {
	row := s.pool.QueryRow(ctx,
		`INSERT INTO sessions (user_id, token_hash, parent_id, user_agent, ip, expires_at)
		 VALUES ($1,$2,$3,$4,$5,$6) RETURNING `+sessionCols,
		sess.UserID, sess.TokenHash, sess.ParentID, sess.UserAgent, sess.IP, sess.ExpiresAt)
	return scanSession(row)
}

// GetSessionByTokenHash looks up a session by the refresh token hash.
func (s *Store) GetSessionByTokenHash(ctx context.Context, hash []byte) (*Session, error) {
	return scanSession(s.pool.QueryRow(ctx, `SELECT `+sessionCols+` FROM sessions WHERE token_hash=$1`, hash))
}

// GetSessionByID looks up a session by ID.
func (s *Store) GetSessionByID(ctx context.Context, id string) (*Session, error) {
	return scanSession(s.pool.QueryRow(ctx, `SELECT `+sessionCols+` FROM sessions WHERE id=$1`, id))
}

// TouchSession updates a session's last-used timestamp.
func (s *Store) TouchSession(ctx context.Context, id string) error {
	_, err := s.pool.Exec(ctx, `UPDATE sessions SET last_used_at=now() WHERE id=$1`, id)
	return err
}

// RevokeSession revokes a single session.
func (s *Store) RevokeSession(ctx context.Context, id string) error {
	_, err := s.pool.Exec(ctx, `UPDATE sessions SET revoked_at=now() WHERE id=$1 AND revoked_at IS NULL`, id)
	return err
}

// RevokeAllSessions revokes every session for a user. If exceptID is non-empty,
// that session is left active (e.g. "log out everywhere else").
func (s *Store) RevokeAllSessions(ctx context.Context, userID, exceptID string) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE sessions SET revoked_at=now() WHERE user_id=$1 AND revoked_at IS NULL AND ($2='' OR id::text <> $2)`,
		userID, exceptID)
	return err
}

// ListActiveSessions returns non-revoked, unexpired sessions for a user.
func (s *Store) ListActiveSessions(ctx context.Context, userID string) ([]Session, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT `+sessionCols+` FROM sessions WHERE user_id=$1 AND revoked_at IS NULL AND expires_at > now() ORDER BY last_used_at DESC`,
		userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Session
	for rows.Next() {
		sess, err := scanSession(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *sess)
	}
	return out, rows.Err()
}

// --- Email tokens ---

// CreateEmailToken inserts a single-use email token.
func (s *Store) CreateEmailToken(ctx context.Context, t *EmailToken) error {
	return s.pool.QueryRow(ctx,
		`INSERT INTO email_tokens (user_id, token_hash, purpose, expires_at) VALUES ($1,$2,$3,$4) RETURNING id, created_at`,
		t.UserID, t.TokenHash, string(t.Purpose), t.ExpiresAt).Scan(&t.ID, &t.CreatedAt)
}

// ConsumeEmailToken atomically fetches and marks an email token as consumed,
// returning it only if it is valid (unconsumed, unexpired, right purpose).
func (s *Store) ConsumeEmailToken(ctx context.Context, hash []byte, purpose EmailTokenPurpose) (*EmailToken, error) {
	var t EmailToken
	var purposeStr string
	err := s.pool.QueryRow(ctx,
		`UPDATE email_tokens SET consumed_at=now()
		 WHERE token_hash=$1 AND purpose=$2 AND consumed_at IS NULL AND expires_at > now()
		 RETURNING id, user_id, token_hash, purpose, expires_at, consumed_at, created_at`,
		hash, string(purpose)).
		Scan(&t.ID, &t.UserID, &t.TokenHash, &purposeStr, &t.ExpiresAt, &t.ConsumedAt, &t.CreatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	t.Purpose = EmailTokenPurpose(purposeStr)
	return &t, nil
}

// InvalidateEmailTokens consumes all outstanding tokens of a purpose for a user
// (e.g. before issuing a fresh one).
func (s *Store) InvalidateEmailTokens(ctx context.Context, userID string, purpose EmailTokenPurpose) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE email_tokens SET consumed_at=now() WHERE user_id=$1 AND purpose=$2 AND consumed_at IS NULL`,
		userID, string(purpose))
	return err
}

// --- WebAuthn credentials ---

// CreateWebAuthnCredential stores a registered passkey.
func (s *Store) CreateWebAuthnCredential(ctx context.Context, c *WebAuthnCredential) error {
	err := s.pool.QueryRow(ctx,
		`INSERT INTO webauthn_credentials (user_id, credential_id, public_key, attestation_type, aaguid, sign_count, clone_warning, transports, name)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING id, created_at, last_used_at`,
		c.UserID, c.CredentialID, c.PublicKey, c.AttestationType, c.AAGUID, int64(c.SignCount), c.CloneWarning, c.Transports, c.Name).
		Scan(&c.ID, &c.CreatedAt, &c.LastUsedAt)
	if err != nil {
		if isUniqueViolation(err) {
			return ErrConflict
		}
		return err
	}
	return nil
}

// ListWebAuthnCredentials returns all passkeys for a user.
func (s *Store) ListWebAuthnCredentials(ctx context.Context, userID string) ([]WebAuthnCredential, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, user_id, credential_id, public_key, attestation_type, aaguid, sign_count, clone_warning, transports, name, created_at, last_used_at
		 FROM webauthn_credentials WHERE user_id=$1 ORDER BY created_at`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanCredentials(rows)
}

// GetWebAuthnCredentialByCredID looks up a passkey by its raw credential ID.
func (s *Store) GetWebAuthnCredentialByCredID(ctx context.Context, credID []byte) (*WebAuthnCredential, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, user_id, credential_id, public_key, attestation_type, aaguid, sign_count, clone_warning, transports, name, created_at, last_used_at
		 FROM webauthn_credentials WHERE credential_id=$1`, credID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	creds, err := scanCredentials(rows)
	if err != nil {
		return nil, err
	}
	if len(creds) == 0 {
		return nil, ErrNotFound
	}
	return &creds[0], nil
}

func scanCredentials(rows pgx.Rows) ([]WebAuthnCredential, error) {
	var out []WebAuthnCredential
	for rows.Next() {
		var c WebAuthnCredential
		var signCount int64
		if err := rows.Scan(&c.ID, &c.UserID, &c.CredentialID, &c.PublicKey, &c.AttestationType, &c.AAGUID,
			&signCount, &c.CloneWarning, &c.Transports, &c.Name, &c.CreatedAt, &c.LastUsedAt); err != nil {
			return nil, err
		}
		c.SignCount = uint32(signCount)
		out = append(out, c)
	}
	return out, rows.Err()
}

// UpdateWebAuthnSignCount updates the authenticator sign counter after a login.
func (s *Store) UpdateWebAuthnSignCount(ctx context.Context, credID []byte, signCount uint32, cloneWarning bool) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE webauthn_credentials SET sign_count=$1, clone_warning=$2, last_used_at=now() WHERE credential_id=$3`,
		int64(signCount), cloneWarning, credID)
	return err
}

// DeleteWebAuthnCredential removes a passkey belonging to a user.
func (s *Store) DeleteWebAuthnCredential(ctx context.Context, userID, id string) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM webauthn_credentials WHERE id=$1 AND user_id=$2`, id, userID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// --- WebAuthn challenges ---

// CreateWebAuthnChallenge stores in-flight ceremony session data.
func (s *Store) CreateWebAuthnChallenge(ctx context.Context, c *WebAuthnChallenge) error {
	return s.pool.QueryRow(ctx,
		`INSERT INTO webauthn_challenges (user_id, data, expires_at) VALUES ($1,$2,$3) RETURNING id, created_at`,
		c.UserID, c.Data, c.ExpiresAt).Scan(&c.ID, &c.CreatedAt)
}

// ConsumeWebAuthnChallenge fetches and deletes a challenge by ID if unexpired.
func (s *Store) ConsumeWebAuthnChallenge(ctx context.Context, id string) (*WebAuthnChallenge, error) {
	var c WebAuthnChallenge
	err := s.pool.QueryRow(ctx,
		`DELETE FROM webauthn_challenges WHERE id=$1 AND expires_at > now()
		 RETURNING id, user_id, data, expires_at, created_at`, id).
		Scan(&c.ID, &c.UserID, &c.Data, &c.ExpiresAt, &c.CreatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &c, nil
}

// DeleteExpired purges expired sessions, tokens, and challenges. Intended to be
// run periodically.
func (s *Store) DeleteExpired(ctx context.Context, now time.Time) error {
	batch := []string{
		`DELETE FROM webauthn_challenges WHERE expires_at < now()`,
		`DELETE FROM email_tokens WHERE expires_at < now() - interval '7 days'`,
		`DELETE FROM sessions WHERE expires_at < now() - interval '30 days'`,
	}
	for _, q := range batch {
		if _, err := s.pool.Exec(ctx, q); err != nil {
			return err
		}
	}
	return nil
}
