package auth

import (
	"context"
	"net/mail"
	"strings"

	"github.com/jackc/pgx/v5"
)

type profilePatch struct {
	Name  *string `json:"name"`
	Email *string `json:"email"`
}

func ValidProfileName(name string) bool {
	return len(name) > 0 && len(name) <= 150 && !strings.ContainsRune(name, 0)
}

func ValidProfileEmail(email string) bool {
	if email == "" {
		return true
	}
	if len(email) > 254 {
		return false
	}
	address, err := mail.ParseAddress(email)
	return err == nil && address.Address == email
}

func (s *Server) UpdateProfile(ctx context.Context, body Input, bearer string) (any, error) {
	proof := NewAccessProof(bearer)
	if err := proof.Validate(); err != nil {
		return nil, err
	}
	patch := body.Profile
	if patch.Name == nil && patch.Email == nil {
		return nil, invalid
	}
	if patch.Name != nil {
		*patch.Name = strings.TrimSpace(*patch.Name)
		if !ValidProfileName(*patch.Name) {
			return nil, invalid
		}
	}
	if patch.Email != nil {
		*patch.Email = strings.TrimSpace(*patch.Email)
		if !ValidProfileEmail(*patch.Email) {
			return nil, invalid
		}
	}
	var result Profile
	err := pgx.BeginFunc(ctx, s.db, func(tx pgx.Tx) error {
		// Match password reset's account-then-session lock order.
		target, err := proof.LockProfileAccount(ctx, tx)
		if err != nil {
			return err
		}
		if patch.Email != nil && *patch.Email != target.Email {
			if target.EmailVerified {
				return invalid
			}
			if _, err := tx.Exec(ctx, `DELETE FROM auth_email_challenges WHERE user_id=$1`, target.ID); err != nil {
				return err
			}
		}
		result, err = proof.WriteLockedProfile(ctx, tx, target.ID, patch.Name, patch.Email)
		return err
	})
	return result, err
}
