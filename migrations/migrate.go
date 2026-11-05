package migrations

import (
	"context"
	_ "embed"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed 001_auth.sql
var authSchema string

// Apply serializes migration runners and commits each schema change with its version.
func Apply(ctx context.Context, db *pgxpool.Pool) error {
	return pgx.BeginFunc(ctx, db, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(62124418001)`); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (version integer PRIMARY KEY)`); err != nil {
			return err
		}
		var applied bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM schema_migrations WHERE version=1)`).Scan(&applied); err != nil || applied {
			return err
		}
		if _, err := tx.Exec(ctx, authSchema, pgx.QueryExecModeSimpleProtocol); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO schema_migrations VALUES (1)`)
		return err
	})
}
