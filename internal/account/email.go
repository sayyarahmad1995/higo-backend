package account

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/sayyarahmad1995/higo-backend/internal/auth"
	"github.com/sayyarahmad1995/higo-backend/internal/ratelimit"
)

type EmailSender interface {
	Send(ctx context.Context, address, code string) error
}

func (s *Service) RequestEmailVerification(ctx context.Context, access auth.AccessProof, address, password string) (auth.Profile, error) {
	if err := access.Validate(); err != nil {
		return auth.Profile{}, err
	}
	address = strings.TrimSpace(address)
	if address == "" || !auth.ValidProfileEmail(address) || !auth.ValidPassword(password) {
		return auth.Profile{}, invalid
	}
	snapshot, err := s.auth.PasswordSnapshot(ctx, access)
	if err != nil {
		return auth.Profile{}, err
	}
	id, version := snapshot.AccountID(), snapshot.PasswordVersion()
	if s.emailSender == nil {
		return auth.Profile{}, busy
	}
	account := strconv.FormatInt(id, 10)
	if err := ratelimit.Allow(ctx, s.db, "email/password/"+account, 15*time.Minute, 10); err != nil {
		return auth.Profile{}, err
	}
	verified, err := snapshot.Verify(password)
	if err != nil {
		return auth.Profile{}, err
	}
	if !verified {
		return auth.Profile{}, invalid
	}
	code, proof, err := auth.NewEmailCode()
	if err != nil {
		return auth.Profile{}, err
	}
	err = pgx.BeginFunc(ctx, s.db, func(tx pgx.Tx) error {
		owner, err := access.LockAccount(ctx, tx)
		if err != nil {
			return err
		}
		if owner != id {
			return unauthorized
		}
		tag, err := tx.Exec(ctx, `INSERT INTO auth_rate_limits (key,bucket,attempts,expires_at)
 VALUES ($1,0,1,clock_timestamp()+interval '60 seconds')
 ON CONFLICT (key,bucket) DO UPDATE SET expires_at=clock_timestamp()+interval '60 seconds'
 WHERE auth_rate_limits.expires_at<=clock_timestamp()`, ratelimit.Key("email/account/"+account))
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return ratelimit.ErrLimited
		}
		for _, budget := range []struct {
			key    string
			window time.Duration
			limit  int
		}{
			{"email/recipient/" + strings.ToLower(address), time.Hour, 5},
			{"email/global", time.Minute, 60},
		} {
			if err := ratelimit.Allow(ctx, tx, budget.key, budget.window, budget.limit); err != nil {
				return err
			}
		}
		tag, err = tx.Exec(ctx, `INSERT INTO auth_email_challenges (user_id,target_email,original_email,password_version,digest,expires_at)
 SELECT id,$2,email,password_version,$3,clock_timestamp()+interval '15 minutes' FROM auth_users WHERE id=$1 AND password_version=$4
 ON CONFLICT (user_id) DO UPDATE SET target_email=excluded.target_email,original_email=excluded.original_email,
 password_version=excluded.password_version,digest=excluded.digest,expires_at=excluded.expires_at,delivered=false`, id, address, proof, version)
		if err == nil && tag.RowsAffected() != 1 {
			return unauthorized
		}
		return err
	})
	if err != nil {
		return auth.Profile{}, err
	}
	if err := s.emailSender.Send(ctx, address, code); err != nil {
		return auth.Profile{}, busy
	}
	var profile auth.Profile
	err = pgx.BeginFunc(ctx, s.db, func(tx pgx.Tx) error {
		owner, err := access.LockAccount(ctx, tx)
		if err != nil {
			return err
		}
		if owner != id {
			return unauthorized
		}
		tag, err := tx.Exec(ctx, `UPDATE auth_email_challenges SET delivered=true WHERE user_id=$1 AND digest=$2`, id, proof)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return invalid
		}
		profile, err = auth.ScanProfile(tx.QueryRow(ctx, `SELECT `+auth.ProfileColumns+` FROM auth_users u WHERE u.id=$1`, id))
		return err
	})
	return profile, err
}

func (s *Service) VerifyEmail(ctx context.Context, access auth.AccessProof, code string) (auth.Profile, error) {
	if err := access.Validate(); err != nil {
		return auth.Profile{}, err
	}
	proof := auth.EmailCodeDigest(strings.TrimSpace(code))
	if proof == nil {
		return auth.Profile{}, invalidCode
	}
	var profile auth.Profile
	err := pgx.BeginFunc(ctx, s.db, func(tx pgx.Tx) error {
		id, err := access.LockAccount(ctx, tx)
		if err != nil {
			return err
		}
		var address string
		err = tx.QueryRow(ctx, `DELETE FROM auth_email_challenges c USING auth_users u
 WHERE c.user_id=u.id AND u.id=$1 AND c.digest=$2 AND c.delivered AND c.expires_at>clock_timestamp()
 AND c.original_email=u.email AND c.password_version=u.password_version RETURNING c.target_email`, id, proof).Scan(&address)
		if errors.Is(err, pgx.ErrNoRows) {
			return invalidCode
		}
		if err != nil {
			return err
		}
		profile, err = auth.ScanProfile(tx.QueryRow(ctx, `UPDATE auth_users u SET email=$2,email_verified_at=clock_timestamp() WHERE id=$1 RETURNING `+auth.ProfileColumns, id, address))
		return err
	})
	return profile, err
}
