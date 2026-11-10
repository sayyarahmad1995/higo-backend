package ratelimit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

var ErrLimited = errors.New("rate_limited")

type executor interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
}

// Key preserves the existing on-disk hash of a budget key.
func Key(value string) string {
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:])
}

// Allow increments a fixed-window counter in the caller's pool or transaction.
func Allow(ctx context.Context, db executor, key string, window time.Duration, limit int) error {
	seconds := int64(window / time.Second)
	tag, err := db.Exec(ctx, `INSERT INTO auth_rate_limits (key,bucket,attempts,expires_at)
 SELECT $1, floor(extract(epoch FROM now())/$2::bigint)::bigint, 1, now()+$2::bigint*interval '2 seconds'
 ON CONFLICT (key,bucket) DO UPDATE SET attempts=auth_rate_limits.attempts+1 WHERE auth_rate_limits.attempts<$3`,
		Key(key), seconds, limit)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrLimited
	}
	return err
}
