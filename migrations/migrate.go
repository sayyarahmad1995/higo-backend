package migrations

import (
	"context"
	_ "embed"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed 001_auth.sql
var authSchema string

//go:embed 002_account_capabilities.sql
var accountCapabilities string

//go:embed 003_email_verification.sql
var emailVerification string

// Apply serializes migration runners and commits each schema change with its version.
func Apply(ctx context.Context, db *pgxpool.Pool) error {
	return pgx.BeginFunc(ctx, db, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(62124418001)`); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (version integer PRIMARY KEY)`); err != nil {
			return err
		}
		for i, schema := range []string{authSchema, accountCapabilities, emailVerification} {
			version := i + 1
			var applied bool
			if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM schema_migrations WHERE version=$1)`, version).Scan(&applied); err != nil {
				return err
			}
			if applied {
				continue
			}
			if _, err := tx.Exec(ctx, schema, pgx.QueryExecModeSimpleProtocol); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `INSERT INTO schema_migrations VALUES ($1)`, version); err != nil {
				return err
			}
		}
		return nil
	})
}
