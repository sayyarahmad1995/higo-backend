package auth

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"net/mail"
	"strings"

	"github.com/jackc/pgx/v5"
)

const registration = "registration"
const recovery = "recovery"

func (s *Server) otpDigest(purpose, challenge, code string) []byte {
	mac := hmac.New(sha256.New, s.otpKey)
	mac.Write([]byte(purpose + ":" + challenge + ":" + code))
	return mac.Sum(nil)
}

func (s *Server) register(ctx context.Context, body input, _ string) (int, any, error) {
	phone := phoneNumber(body.Phone)
	name := strings.TrimSpace(body.Name)
	email := strings.TrimSpace(body.Email)
	if phone == "" || !validPassword(body.Password) || len(name) == 0 || len(name) > 150 || len(email) > 254 {
		return 0, nil, invalid
	}
	if email != "" {
		address, err := mail.ParseAddress(email)
		if err != nil || address.Address != email {
			return 0, nil, invalid
		}
	}
	return s.issue(ctx, registration, phone, body.Password, name, email)
}

func (s *Server) requestRecovery(ctx context.Context, body input, _ string) (int, any, error) {
	phone := phoneNumber(body.Phone)
	if phone == "" {
		return 0, nil, invalid
	}
	return s.issue(ctx, recovery, phone, "", "", "")
}

func (s *Server) issue(ctx context.Context, purpose, phone, password, name, email string) (int, any, error) {
	select {
	case s.smsSlots <- struct{}{}:
	default:
		return 0, nil, busy
	}
	queued := false
	defer func() {
		if !queued {
			<-s.smsSlots
		}
	}()
	if err := s.reserveSMS(ctx, purpose, phone); err != nil {
		return 0, nil, err
	}
	var passwordHash *string
	if purpose == registration {
		hash, err := s.hash(password)
		if err != nil {
			return 0, nil, err
		}
		passwordHash = &hash
	}
	challenge, err := newToken("oc_")
	if err != nil {
		return 0, nil, err
	}
	code, err := newOTP()
	if err != nil {
		return 0, nil, err
	}
	id := tokenDigest(challenge, "oc_")
	var send bool
	err = s.db.QueryRow(ctx, `WITH account AS (SELECT id,password_version FROM auth_users WHERE phone=$3)
 INSERT INTO auth_challenges (id,purpose,phone,user_id,password_version,password_hash,name,email,otp_digest,expires_at)
 SELECT $1,$2,$3,CASE WHEN $2='recovery' THEN account.id END,
 CASE WHEN $2='recovery' THEN account.password_version END,$4,$5,$6,$7,now()+interval '5 minutes'
 FROM (SELECT 1) AS seed LEFT JOIN account ON true
 RETURNING CASE WHEN purpose='recovery' THEN user_id IS NOT NULL ELSE NOT EXISTS(SELECT 1 FROM account) END`,
		id, purpose, phone, passwordHash, name, email, s.otpDigest(purpose, challenge, code)).Scan(&send)
	if err != nil {
		return 0, nil, err
	}
	s.dispatchSMS(delivery{id, phone, code, send})
	queued = true
	return 202, map[string]any{"challenge": challenge, "expires_in": 300, "resend_after": 60}, nil
}

type challengeRecord struct {
	phone, name, email string
	hash               *string
	user, version      *int64
}

func (s *Server) verifyChallenge(ctx context.Context, body input, purpose string, finish func(pgx.Tx, challengeRecord) (int, any, error)) (int, any, error) {
	id := tokenDigest(body.Challenge, "oc_")
	if id == nil || !otpPattern.MatchString(body.Code) {
		return 0, nil, invalidCode
	}
	var result any
	var status int
	var rejected error
	err := pgx.BeginFunc(ctx, s.db, func(tx pgx.Tx) error {
		var record challengeRecord
		var match bool
		err := tx.QueryRow(ctx, `UPDATE auth_challenges SET attempts=attempts+1, consumed=(delivered AND otp_digest=$3)
    WHERE id=$1 AND purpose=$2 AND NOT consumed AND attempts<5 AND expires_at>clock_timestamp()
    RETURNING consumed,phone,password_hash,name,email,user_id,password_version`,
			id, purpose, s.otpDigest(purpose, body.Challenge, body.Code)).Scan(&match, &record.phone, &record.hash, &record.name, &record.email, &record.user, &record.version)
		if errors.Is(err, pgx.ErrNoRows) || (err == nil && !match) {
			rejected = invalidCode
			return nil
		}
		if err != nil {
			return err
		}
		status, result, err = finish(tx, record)
		if err == invalidCode {
			rejected = err
			return nil
		}
		return err
	})
	if err != nil {
		return 0, nil, err
	}
	return status, result, rejected
}

func (s *Server) verifyRegistration(ctx context.Context, body input, _ string) (int, any, error) {
	return s.verifyChallenge(ctx, body, registration, func(tx pgx.Tx, record challengeRecord) (int, any, error) {
		var user int64
		err := tx.QueryRow(ctx, `INSERT INTO auth_users (phone,password_hash,name,email) VALUES ($1,$2,$3,$4)
   ON CONFLICT (phone) DO NOTHING RETURNING id`, record.phone, *record.hash, record.name, record.email).Scan(&user)
		if errors.Is(err, pgx.ErrNoRows) {
			return 0, nil, invalidCode
		}
		if err != nil {
			return 0, nil, err
		}
		session, err := issueSession(ctx, tx, user)
		return 201, session, err
	})
}

func (s *Server) verifyRecovery(ctx context.Context, body input, _ string) (int, any, error) {
	return s.verifyChallenge(ctx, body, recovery, func(tx pgx.Tx, record challengeRecord) (int, any, error) {
		if record.user == nil {
			return 0, nil, invalidCode
		}
		var version int64
		err := tx.QueryRow(ctx, `SELECT password_version FROM auth_users WHERE id=$1 FOR UPDATE`, *record.user).Scan(&version)
		if errors.Is(err, pgx.ErrNoRows) || (err == nil && version != *record.version) {
			return 0, nil, invalidCode
		}
		if err != nil {
			return 0, nil, err
		}
		token, err := newToken("rc_")
		if err != nil {
			return 0, nil, err
		}
		_, err = tx.Exec(ctx, `INSERT INTO auth_recovery VALUES($1,$2,$3,now()+interval '10 minutes')`,
			tokenDigest(token, "rc_"), *record.user, version)
		return 200, map[string]any{"recovery_token": token, "expires_in": 600}, err
	})
}

func (s *Server) reset(ctx context.Context, body input, _ string) (int, any, error) {
	digest := tokenDigest(body.Recovery, "rc_")
	if digest == nil {
		return 0, nil, invalidRecovery
	}
	if !validPassword(body.Password) {
		return 0, nil, invalid
	}
	var user, version int64
	err := s.db.QueryRow(ctx, `SELECT user_id,password_version FROM auth_recovery WHERE digest=$1 AND expires_at>now()`, digest).Scan(&user, &version)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, nil, invalidRecovery
	}
	if err != nil {
		return 0, nil, err
	}
	hash, err := s.hash(body.Password)
	if err != nil {
		return 0, nil, err
	}
	err = pgx.BeginFunc(ctx, s.db, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE auth_users SET password_hash=$3,password_version=password_version+1 WHERE id=$1 AND password_version=$2`, user, version, hash)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return invalidRecovery
		}
		tag, err = tx.Exec(ctx, `DELETE FROM auth_recovery WHERE digest=$1 AND expires_at>now()`, digest)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return invalidRecovery
		}
		if _, err := tx.Exec(ctx, `DELETE FROM auth_recovery WHERE user_id=$1`, user); err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `UPDATE auth_sessions SET revoked_at=now() WHERE user_id=$1 AND revoked_at IS NULL`, user)
		return err
	})
	return 204, nil, err
}
