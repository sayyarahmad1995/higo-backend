package account

import (
	"context"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/sayyarahmad1995/higo-backend/internal/auth"
)

type ProfilePatch struct {
	Name  *string `json:"name"`
	Email *string `json:"email"`
}

func (s *Service) UpdateProfile(ctx context.Context, proof auth.AccessProof, patch ProfilePatch) (auth.Profile, error) {
	if err := proof.Validate(); err != nil {
		return auth.Profile{}, err
	}
	if patch.Name == nil && patch.Email == nil {
		return auth.Profile{}, invalid
	}
	if patch.Name != nil {
		*patch.Name = strings.TrimSpace(*patch.Name)
		if !auth.ValidProfileName(*patch.Name) {
			return auth.Profile{}, invalid
		}
	}
	if patch.Email != nil {
		*patch.Email = strings.TrimSpace(*patch.Email)
		if !auth.ValidProfileEmail(*patch.Email) {
			return auth.Profile{}, invalid
		}
	}
	var result auth.Profile
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

func (s *Service) Profile(ctx context.Context, proof auth.AccessProof) (auth.Profile, error) {
	return s.auth.CurrentProfile(ctx, proof)
}
