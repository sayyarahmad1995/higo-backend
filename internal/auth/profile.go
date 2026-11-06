package auth

import (
	"context"
	"errors"
	"net/mail"
	"strings"

	"github.com/jackc/pgx/v5"
)

type profilePatch struct {
	Name  *string `json:"name"`
	Email *string `json:"email"`
}

func validProfileName(name string) bool {
	return len(name) > 0 && len(name) <= 150 && !strings.ContainsRune(name, 0)
}

func validProfileEmail(email string) bool {
	if email == "" {
		return true
	}
	if len(email) > 254 {
		return false
	}
	address, err := mail.ParseAddress(email)
	return err == nil && address.Address == email
}

func (s *Server) updateProfile(ctx context.Context, body input, bearer string) (int, any, error) {
	digest := tokenDigest(bearer, "at_")
	if digest == nil {
		return 0, nil, unauthorized
	}
	patch := body.Profile
	if patch.Name == nil && patch.Email == nil {
		return 0, nil, invalid
	}
	if patch.Name != nil {
		*patch.Name = strings.TrimSpace(*patch.Name)
		if !validProfileName(*patch.Name) {
			return 0, nil, invalid
		}
	}
	if patch.Email != nil {
		*patch.Email = strings.TrimSpace(*patch.Email)
		if !validProfileEmail(*patch.Email) {
			return 0, nil, invalid
		}
	}
	var result currentUser
	err := pgx.BeginFunc(ctx, s.db, func(tx pgx.Tx) error {
		// Match password reset's account-then-session lock order.
		var userID int64
		err := tx.QueryRow(ctx, `SELECT u.id FROM auth_users u JOIN auth_sessions s ON s.user_id=u.id
 WHERE s.access_digest=$1 AND s.revoked_at IS NULL AND s.access_expires_at>clock_timestamp()
 AND s.expires_at>clock_timestamp() FOR UPDATE OF u`, digest).Scan(&userID)
		if errors.Is(err, pgx.ErrNoRows) {
			return unauthorized
		}
		if err != nil {
			return err
		}
		result, err = scanCurrentUser(tx.QueryRow(ctx, `UPDATE auth_users u SET name=COALESCE($3,u.name),email=COALESCE($4,u.email)
 WHERE u.id=$2 AND EXISTS (SELECT 1 FROM auth_sessions s WHERE s.user_id=u.id AND s.access_digest=$1
 AND s.revoked_at IS NULL AND s.access_expires_at>clock_timestamp() AND s.expires_at>clock_timestamp() FOR SHARE OF s)
 RETURNING u.id,u.phone,u.name,u.email`, digest, userID, patch.Name, patch.Email))
		return err
	})
	return 200, result, err
}
