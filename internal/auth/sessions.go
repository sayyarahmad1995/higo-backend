package auth

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/sayyarahmad1995/higo-backend/internal/ratelimit"
)

type sessionTokens struct {
	Access    string `json:"access_token"`
	Refresh   string `json:"refresh_token"`
	ExpiresIn int    `json:"expires_in"`
}

func makeSessionTokens() (sessionTokens, error) {
	access, err := newToken("at_")
	if err != nil {
		return sessionTokens{}, err
	}
	refresh, err := newToken("rt_")
	return sessionTokens{access, refresh, 900}, err
}

func insertRefresh(ctx context.Context, tx pgx.Tx, session int64, token string) error {
	_, err := tx.Exec(ctx, `INSERT INTO auth_refresh(digest,session_id) VALUES ($1,$2)`, tokenDigest(token, "rt_"), session)
	return err
}

func issueSession(ctx context.Context, tx pgx.Tx, user int64) (sessionTokens, error) {
	tokens, err := makeSessionTokens()
	if err != nil {
		return tokens, err
	}
	var id int64
	err = tx.QueryRow(ctx, `INSERT INTO auth_sessions (user_id,access_digest,access_expires_at,expires_at)
 VALUES($1,$2,now()+interval '15 minutes',now()+interval '30 days') RETURNING id`, user, tokenDigest(tokens.Access, "at_")).Scan(&id)
	if err != nil {
		return tokens, err
	}
	return tokens, insertRefresh(ctx, tx, id, tokens.Refresh)
}

func (s *Server) Login(ctx context.Context, body Input, _ string) (any, error) {
	phone := phoneNumber(body.Phone)
	if phone == "" || !validPassword(body.Password) {
		return nil, denied
	}
	if err := ratelimit.Allow(ctx, s.db, "login/phone/"+phone, 15*time.Minute, 10); err != nil {
		return nil, err
	}
	var user, version int64
	hash := s.dummyHash
	err := s.db.QueryRow(ctx, `SELECT id,password_version,password_hash FROM auth_users WHERE phone=$1`, phone).Scan(&user, &version, &hash)
	exists := err == nil
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, err
	}
	if err := s.acquireHash(); err != nil {
		return nil, err
	}
	verified := s.passwords.verify(hash, body.Password)
	<-s.hashSlots
	if !exists || !verified {
		return nil, denied
	}
	var tokens sessionTokens
	err = pgx.BeginFunc(ctx, s.db, func(tx pgx.Tx) error {
		var current int64
		err := tx.QueryRow(ctx, `SELECT password_version FROM auth_users WHERE id=$1 FOR UPDATE`, user).Scan(&current)
		if errors.Is(err, pgx.ErrNoRows) || (err == nil && current != version) {
			return denied
		}
		if err != nil {
			return err
		}
		tokens, err = issueSession(ctx, tx, user)
		return err
	})
	return tokens, err
}

func (s *Server) Refresh(ctx context.Context, body Input, _ string) (any, error) {
	digest := tokenDigest(body.Refresh, "rt_")
	if digest == nil {
		return nil, unauthorized
	}
	var replay bool
	var tokens sessionTokens
	err := pgx.BeginFunc(ctx, s.db, func(tx pgx.Tx) error {
		var id int64
		err := tx.QueryRow(ctx, `SELECT session_id FROM auth_refresh WHERE digest=$1`, digest).Scan(&id)
		if errors.Is(err, pgx.ErrNoRows) {
			return unauthorized
		}
		if err != nil {
			return err
		}
		err = tx.QueryRow(ctx, `SELECT id FROM auth_sessions WHERE id=$1 AND expires_at>now() AND revoked_at IS NULL FOR UPDATE`, id).Scan(&id)
		if errors.Is(err, pgx.ErrNoRows) {
			return unauthorized
		}
		if err != nil {
			return err
		}
		tag, err := tx.Exec(ctx, `UPDATE auth_refresh SET consumed=true WHERE digest=$1 AND NOT consumed`, digest)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			replay = true
			_, err = tx.Exec(ctx, `UPDATE auth_sessions SET revoked_at=now() WHERE id=$1`, id)
			return err
		}
		tokens, err = makeSessionTokens()
		if err != nil {
			return err
		}
		err = tx.QueryRow(ctx, `UPDATE auth_sessions SET access_digest=$2,access_expires_at=LEAST(expires_at,now()+interval '15 minutes') WHERE id=$1
 RETURNING floor(extract(epoch FROM access_expires_at-now()))::integer`,
			id, tokenDigest(tokens.Access, "at_")).Scan(&tokens.ExpiresIn)
		if err != nil {
			return err
		}
		return insertRefresh(ctx, tx, id, tokens.Refresh)
	})
	if err == nil && replay {
		slog.Warn("auth_refresh_replay_session_revoked")
		return nil, unauthorized
	}
	return tokens, err
}

func (s *Server) Logout(ctx context.Context, _ Input, bearer string) (any, error) {
	digest := tokenDigest(bearer, "at_")
	if digest == nil {
		return nil, unauthorized
	}
	tag, err := s.db.Exec(ctx, `UPDATE auth_sessions SET revoked_at=now()
 WHERE access_digest=$1 AND revoked_at IS NULL AND access_expires_at>now() AND expires_at>now()`, digest)
	if err == nil && tag.RowsAffected() == 0 {
		return nil, unauthorized
	}
	return nil, err
}

type currentUser struct {
	ID            int64    `json:"id"`
	Phone         string   `json:"phone"`
	Name          string   `json:"name"`
	Email         string   `json:"email"`
	EmailVerified bool     `json:"email_verified"`
	PendingEmail  string   `json:"pending_email"`
	Capabilities  []string `json:"capabilities"`
}

func (s *Server) Me(ctx context.Context, _ Input, bearer string) (any, error) {
	return s.currentAccount(ctx, bearer)
}

func (s *Server) currentAccount(ctx context.Context, bearer string) (currentUser, error) {
	return s.accountForProof(ctx, NewAccessProof(bearer))
}

func (s *Server) accountForProof(ctx context.Context, proof AccessProof) (currentUser, error) {
	if err := proof.Validate(); err != nil {
		return currentUser{}, err
	}
	return scanCurrentUser(s.db.QueryRow(ctx, `SELECT `+currentUserColumns+` FROM auth_sessions s
 JOIN auth_users u ON u.id=s.user_id WHERE s.access_digest=$1 AND s.revoked_at IS NULL
 AND s.access_expires_at>now() AND s.expires_at>now()`, proof.digest))
}

const currentUserColumns = `u.id,u.phone,u.name,u.email,u.has_driver_capability,u.email_verified_at IS NOT NULL,
 COALESCE((SELECT c.target_email FROM auth_email_challenges c WHERE c.user_id=u.id
 AND c.original_email=u.email AND c.password_version=u.password_version AND c.delivered AND c.expires_at>clock_timestamp()),'')`

func scanCurrentUser(row pgx.Row) (currentUser, error) {
	user := currentUser{Capabilities: []string{"rider"}}
	var driver bool
	err := row.Scan(&user.ID, &user.Phone, &user.Name, &user.Email, &driver, &user.EmailVerified, &user.PendingEmail)
	if driver {
		user.Capabilities = append(user.Capabilities, "driver")
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return currentUser{}, unauthorized
	}
	return user, err
}
