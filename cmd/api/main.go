package main

import (
	"log/slog"
	"os"

	"github.com/sayyarahmad1995/higo-backend/internal/app"
)

func main() {
	if err := app.Run(); err != nil {
		slog.Error("api_stopped", "error", err)
		os.Exit(1)
	}
}
