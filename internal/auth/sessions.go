package auth

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"
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

func (s *Server) login(ctx context.Context, body input, _ string) (int, any, error) {
	phone := phoneNumber(body.Phone)
	if phone == "" || !validPassword(body.Password) {
		return 0, nil, denied
	}
	if err := allow(ctx, s.db, "login/phone/"+phone, 15*time.Minute, 10); err != nil {
		return 0, nil, err
	}
	var user, version int64
	hash := s.dummyHash
	err := s.db.QueryRow(ctx, `SELECT id,password_version,password_hash FROM auth_users WHERE phone=$1`, phone).Scan(&user, &version, &hash)
	exists := err == nil
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return 0, nil, err
	}
	if err := s.acquireHash(); err != nil {
		return 0, nil, err
	}
	verified := s.passwords.verify(hash, body.Password)
	<-s.hashSlots
	if !exists || !verified {
		return 0, nil, denied
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
	return 200, tokens, err
}

func (s *Server) refresh(ctx context.Context, body input, _ string) (int, any, error) {
	digest := tokenDigest(body.Refresh, "rt_")
	if digest == nil {
		return 0, nil, unauthorized
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
		return 0, nil, unauthorized
	}
	return 200, tokens, err
}

func (s *Server) logout(ctx context.Context, _ input, bearer string) (int, any, error) {
	digest := tokenDigest(bearer, "at_")
	if digest == nil {
		return 0, nil, unauthorized
	}
	tag, err := s.db.Exec(ctx, `UPDATE auth_sessions SET revoked_at=now()
 WHERE access_digest=$1 AND revoked_at IS NULL AND access_expires_at>now() AND expires_at>now()`, digest)
	if err == nil && tag.RowsAffected() == 0 {
		return 0, nil, unauthorized
	}
	return 204, nil, err
}

type currentUser struct {
	ID           int64    `json:"id"`
	Phone        string   `json:"phone"`
	Name         string   `json:"name"`
	Email        string   `json:"email"`
	Capabilities []string `json:"capabilities"`
}

func (s *Server) me(ctx context.Context, _ input, bearer string) (int, any, error) {
	digest := tokenDigest(bearer, "at_")
	if digest == nil {
		return 0, nil, unauthorized
	}
	user, err := scanCurrentUser(s.db.QueryRow(ctx, `SELECT u.id,u.phone,u.name,u.email FROM auth_sessions s
 JOIN auth_users u ON u.id=s.user_id WHERE s.access_digest=$1 AND s.revoked_at IS NULL
 AND s.access_expires_at>now() AND s.expires_at>now()`, digest))
	return 200, user, err
}

func scanCurrentUser(row pgx.Row) (currentUser, error) {
	user := currentUser{Capabilities: []string{"rider"}}
	err := row.Scan(&user.ID, &user.Phone, &user.Name, &user.Email)
	if errors.Is(err, pgx.ErrNoRows) {
		return currentUser{}, unauthorized
	}
	return user, err
}
