package auth

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
)

// PasswordSnapshot binds verification to the credential and Auth instance
// observed through a live session. It is not a grant to mutate account data.
type PasswordSnapshot struct {
	accountID int64
	version   int64
	verify    func(string) (bool, error)
}

func (p PasswordSnapshot) AccountID() int64       { return p.accountID }
func (p PasswordSnapshot) PasswordVersion() int64 { return p.version }

func (p PasswordSnapshot) Verify(password string) (bool, error) {
	if p.verify == nil {
		return false, unauthorized
	}
	return p.verify(password)
}

// PasswordSnapshot reads the credential version and captures the hash only
// inside Auth. The verifier uses this server's existing hash semaphore.
func (s *Server) PasswordSnapshot(ctx context.Context, proof AccessProof) (PasswordSnapshot, error) {
	if err := proof.Validate(); err != nil {
		return PasswordSnapshot{}, err
	}
	var id, version int64
	var hash string
	err := s.db.QueryRow(ctx, `SELECT u.id,u.password_version,u.password_hash FROM auth_users u JOIN auth_sessions s ON s.user_id=u.id
 WHERE s.access_digest=$1 AND s.revoked_at IS NULL AND s.access_expires_at>now() AND s.expires_at>now()`, proof.digest).Scan(&id, &version, &hash)
	if errors.Is(err, pgx.ErrNoRows) {
		return PasswordSnapshot{}, unauthorized
	}
	if err != nil {
		return PasswordSnapshot{}, err
	}
	return PasswordSnapshot{accountID: id, version: version, verify: func(password string) (bool, error) {
		if err := s.acquireHash(); err != nil {
			return false, err
		}
		defer func() { <-s.hashSlots }()
		return s.passwords.verify(hash, password), nil
	}}, nil
}

// ProfileEditTarget contains the account fields used by the PATCH rules.
type ProfileEditTarget struct {
	ID            int64
	Email         string
	EmailVerified bool
}

// LockProfileAccount preserves PATCH's live-session predicate on the account
// lock. The final write must still revalidate the session.
func (p AccessProof) LockProfileAccount(ctx context.Context, tx pgx.Tx) (ProfileEditTarget, error) {
	if err := p.Validate(); err != nil {
		return ProfileEditTarget{}, err
	}
	var target ProfileEditTarget
	err := tx.QueryRow(ctx, `SELECT u.id,u.email,u.email_verified_at IS NOT NULL FROM auth_users u JOIN auth_sessions s ON s.user_id=u.id
 WHERE s.access_digest=$1 AND s.revoked_at IS NULL AND s.access_expires_at>clock_timestamp()
 AND s.expires_at>clock_timestamp() FOR UPDATE OF u`, p.digest).Scan(&target.ID, &target.Email, &target.EmailVerified)
	if errors.Is(err, pgx.ErrNoRows) {
		return ProfileEditTarget{}, unauthorized
	}
	return target, err
}

// WriteLockedProfile uses the same proof and transaction after Account applies
// its rules. The UPDATE itself revalidates and locks the active session.
func (p AccessProof) WriteLockedProfile(ctx context.Context, tx pgx.Tx, id int64, name, email *string) (Profile, error) {
	if err := p.Validate(); err != nil {
		return Profile{}, err
	}
	return ScanProfile(tx.QueryRow(ctx, `UPDATE auth_users u SET name=COALESCE($3,u.name),email=COALESCE($4,u.email)
 WHERE u.id=$2 AND EXISTS (SELECT 1 FROM auth_sessions s WHERE s.user_id=u.id AND s.access_digest=$1
 AND s.revoked_at IS NULL AND s.access_expires_at>clock_timestamp() AND s.expires_at>clock_timestamp() FOR SHARE OF s)
 RETURNING `+ProfileColumns, p.digest, id, name, email))
}

func NewEmailCode() (string, []byte, error) {
	code, err := newToken("em_")
	if err != nil {
		return "", nil, err
	}
	return code, EmailCodeDigest(code), nil
}

func EmailCodeDigest(code string) []byte { return tokenDigest(code, "em_") }
