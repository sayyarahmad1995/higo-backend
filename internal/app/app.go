package app

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/sayyarahmad1995/higo-backend/internal/auth"
	"github.com/sayyarahmad1995/higo-backend/internal/httpapi"
	"github.com/sayyarahmad1995/higo-backend/internal/httpserver"
	"github.com/sayyarahmad1995/higo-backend/migrations"
)

// Run starts Core and shuts it down on an interrupt or termination signal.
func Run() error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	startup, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	poolConfig, err := pgxpool.ParseConfig(cfg.databaseURL)
	if err != nil {
		return errors.New("invalid DATABASE_URL")
	}
	poolConfig.MaxConns = 12
	db, err := pgxpool.NewWithConfig(startup, poolConfig)
	if err != nil {
		return errors.New("database pool initialization failed")
	}
	defer db.Close()
	if err := migrations.Apply(startup, db); err != nil {
		return fmt.Errorf("migration failed: %w", err)
	}
	api, err := auth.New(ctx, db, cfg.sms, cfg.auth)
	if err != nil {
		return err
	}
	defer api.Close()
	return httpserver.Run(ctx, cfg.address, httpapi.Handler(api))
}
