package httpserver

import (
	"context"
	"log/slog"
	"net/http"
	"time"
)

// Run serves handler until the context is canceled or the listener fails.
func Run(ctx context.Context, address string, handler http.Handler) error {
	return serve(ctx, &http.Server{
		Addr:              address,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    8192,
	})
}

func serve(ctx context.Context, server *http.Server) error {
	done := make(chan error, 1)
	go func() { done <- server.ListenAndServe() }()
	slog.Info("api_listening", "address", server.Addr)
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		return server.Shutdown(shutdown)
	}
}
