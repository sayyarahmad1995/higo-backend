package account

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/sayyarahmad1995/higo-backend/internal/auth"
	"github.com/sayyarahmad1995/higo-backend/internal/ratelimit"
)

var (
	invalid      = errors.New("invalid_request")
	invalidCode  = errors.New("invalid_or_expired_code")
	unauthorized = errors.New("unauthorized")
	busy         = errors.New("temporarily_unavailable")
)

type Service struct {
	db          *pgxpool.Pool
	auth        *auth.Server
	emailSender EmailSender
}

func New(db *pgxpool.Pool, authService *auth.Server, sender EmailSender) *Service {
	return &Service{db: db, auth: authService, emailSender: sender}
}

// AllowRequest applies the existing Account route budget. GET and PATCH /me
// share the same key.
func (s *Service) AllowRequest(ctx context.Context, operation, peer string) error {
	return ratelimit.Allow(ctx, s.db, operation+"/ip/"+peer, time.Minute, 60)
}

// ErrorCode identifies Account errors safe to expose in an API response.
func ErrorCode(err error) string {
	switch err {
	case invalid, invalidCode, unauthorized, busy:
		return err.Error()
	default:
		return ""
	}
}
