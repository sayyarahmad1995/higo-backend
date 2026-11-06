package auth

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

type EmailSender interface {
	Send(ctx context.Context, address, code string) error
}

func (s *Server) requestEmailVerification(ctx context.Context, body input, bearer string) (int, any, error) {
	digest := tokenDigest(bearer, "at_")
	if digest == nil {
		return 0, nil, unauthorized
	}
	address := strings.TrimSpace(body.Email)
	if address == "" || !validProfileEmail(address) || !validPassword(body.Password) {
		return 0, nil, invalid
	}
	var id, version int64
	var hash string
	err := s.db.QueryRow(ctx, `SELECT u.id,u.password_version,u.password_hash FROM auth_users u JOIN auth_sessions s ON s.user_id=u.id
 WHERE s.access_digest=$1 AND s.revoked_at IS NULL AND s.access_expires_at>now() AND s.expires_at>now()`, digest).Scan(&id, &version, &hash)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, nil, unauthorized
	}
	if err != nil {
		return 0, nil, err
	}
	if s.emailSender == nil {
		return 0, nil, busy
	}
	account := strconv.FormatInt(id, 10)
	if err := allow(ctx, s.db, "email/password/"+account, 15*time.Minute, 10); err != nil {
		return 0, nil, err
	}
	if err := s.acquireHash(); err != nil {
		return 0, nil, err
	}
	verified := s.passwords.verify(hash, body.Password)
	<-s.hashSlots
	if !verified {
		return 0, nil, invalid
	}
	code, err := newToken("em_")
	if err != nil {
		return 0, nil, err
	}
	proof := tokenDigest(code, "em_")
	err = pgx.BeginFunc(ctx, s.db, func(tx pgx.Tx) error {
		owner, err := lockEmailAccount(ctx, tx, digest)
		if err != nil {
			return err
		}
		if owner != id {
			return unauthorized
		}
		tag, err := tx.Exec(ctx, `INSERT INTO auth_rate_limits (key,bucket,attempts,expires_at)
 VALUES ($1,0,1,clock_timestamp()+interval '60 seconds')
 ON CONFLICT (key,bucket) DO UPDATE SET expires_at=clock_timestamp()+interval '60 seconds'
 WHERE auth_rate_limits.expires_at<=clock_timestamp()`, hexDigest("email/account/"+account))
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return limited
		}
		for _, budget := range []struct {
			key    string
			window time.Duration
			limit  int
		}{
			{"email/recipient/" + strings.ToLower(address), time.Hour, 5},
			{"email/global", time.Minute, 60},
		} {
			if err := allow(ctx, tx, budget.key, budget.window, budget.limit); err != nil {
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
		return 0, nil, err
	}
	if err := s.emailSender.Send(ctx, address, code); err != nil {
		return 0, nil, busy
	}
	var profile currentUser
	err = pgx.BeginFunc(ctx, s.db, func(tx pgx.Tx) error {
		owner, err := lockEmailAccount(ctx, tx, digest)
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
		profile, err = scanCurrentUser(tx.QueryRow(ctx, `SELECT `+currentUserColumns+` FROM auth_users u WHERE u.id=$1`, id))
		return err
	})
	return 202, profile, err
}

func lockEmailAccount(ctx context.Context, tx pgx.Tx, digest []byte) (int64, error) {
	var id int64
	err := tx.QueryRow(ctx, `SELECT u.id FROM auth_users u JOIN auth_sessions s ON s.user_id=u.id
 WHERE s.access_digest=$1 FOR UPDATE OF u`, digest).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, unauthorized
	}
	if err != nil {
		return 0, err
	}
	err = tx.QueryRow(ctx, `SELECT user_id FROM auth_sessions WHERE user_id=$1 AND access_digest=$2
 AND revoked_at IS NULL AND access_expires_at>clock_timestamp() AND expires_at>clock_timestamp() FOR SHARE`, id, digest).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, unauthorized
	}
	return id, err
}

func (s *Server) verifyEmail(ctx context.Context, body input, bearer string) (int, any, error) {
	digest := tokenDigest(bearer, "at_")
	if digest == nil {
		return 0, nil, unauthorized
	}
	proof := tokenDigest(strings.TrimSpace(body.Code), "em_")
	if proof == nil {
		return 0, nil, invalidCode
	}
	var profile currentUser
	err := pgx.BeginFunc(ctx, s.db, func(tx pgx.Tx) error {
		id, err := lockEmailAccount(ctx, tx, digest)
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
		profile, err = scanCurrentUser(tx.QueryRow(ctx, `UPDATE auth_users u SET email=$2,email_verified_at=clock_timestamp() WHERE id=$1 RETURNING `+currentUserColumns, id, address))
		return err
	})
	return 200, profile, err
}
