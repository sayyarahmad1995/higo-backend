package auth

import (
	"context"
	"github.com/sayyarahmad1995/higo-backend/internal/ratelimit"
	"time"
)

// AllowRequest applies the existing per-peer budget for the operation.
func (s *Server) AllowRequest(ctx context.Context, operation, peer string) error {
	limit := 60
	if operation == "auth/register" || operation == "auth/recovery/request" {
		limit = 10
	}
	return ratelimit.Allow(ctx, s.db, operation+"/ip/"+peer, time.Minute, limit)
}
