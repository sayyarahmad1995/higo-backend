package account

import (
	"context"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// PurgeExpiredEmailChallenges runs the Account statement on the shared worker.
func PurgeExpiredEmailChallenges(ctx context.Context, db *pgxpool.Pool) {
	deadline, cancel := context.WithTimeout(ctx, 10*time.Second)
	_, err := db.Exec(deadline, `DELETE FROM auth_email_challenges WHERE expires_at<=now()`)
	cancel()
	if err != nil && ctx.Err() == nil {
		slog.Warn("auth_cleanup_failed")
	}
}
