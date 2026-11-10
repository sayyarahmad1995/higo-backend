package httpapi

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/sayyarahmad1995/higo-backend/internal/auth"
	"github.com/sayyarahmad1995/higo-backend/internal/driver"
)

type operation func(context.Context, auth.Input, string) (any, error)

type api struct {
	auth   *auth.Server
	driver *driver.Service
}

// Handler registers the Core HTTP API against the Auth and Driver features.
func Handler(service *auth.Server, driverService *driver.Service) http.Handler {
	api := api{auth: service, driver: driverService}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	api.authRoute(mux, http.MethodPost, "auth/register", http.StatusAccepted, service.Register)
	api.authRoute(mux, http.MethodPost, "auth/register/verify", http.StatusCreated, service.VerifyRegistration)
	api.authRoute(mux, http.MethodPost, "auth/login", http.StatusOK, service.Login)
	api.authRoute(mux, http.MethodPost, "auth/refresh", http.StatusOK, service.Refresh)
	api.authRoute(mux, http.MethodPost, "auth/logout", http.StatusNoContent, service.Logout)
	api.authRoute(mux, http.MethodPost, "auth/recovery/request", http.StatusAccepted, service.RequestRecovery)
	api.authRoute(mux, http.MethodPost, "auth/recovery/verify", http.StatusOK, service.VerifyRecovery)
	api.authRoute(mux, http.MethodPost, "auth/recovery/reset", http.StatusNoContent, service.Reset)
	api.authRoute(mux, http.MethodGet, "me", http.StatusOK, service.Me)
	api.authRoute(mux, http.MethodPatch, "me", http.StatusOK, service.UpdateProfile)
	api.authRoute(mux, http.MethodPost, "me/email/request", http.StatusAccepted, service.RequestEmailVerification)
	api.authRoute(mux, http.MethodPost, "me/email/verify", http.StatusOK, service.VerifyEmail)
	api.registerDriverRoutes(mux)
	return mux
}

func (a api) authRoute(mux *http.ServeMux, method, path string, status int, run operation) {
	a.route(mux, method, path, a.auth.AllowRequest, func(ctx context.Context, w http.ResponseWriter, r *http.Request, bearer string) {
		var body auth.Input
		if method == http.MethodPatch || (method == http.MethodPost && path != "auth/logout") {
			var target any = &body
			if method == http.MethodPatch {
				target = &body.Profile
			}
			if err := decodeJSON(w, r, 4096, target); err != nil {
				respond(w, 0, nil, invalidRequest)
				return
			}
		}
		result, err := run(ctx, body, bearer)
		finish(w, path, status, result, err)
	})
}

func (a api) route(mux *http.ServeMux, method, path string, allow func(context.Context, string, string) error, handle func(context.Context, http.ResponseWriter, *http.Request, string)) {
	mux.HandleFunc(method+" /api/v1/"+path, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "application/json")

		requestTimeout := 10 * time.Second
		ratePath := path
		if method == http.MethodPost && path == onboardingPath+"/document" {
			requestTimeout = 25 * time.Second
			ratePath = method + "/" + path
			_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(30 * time.Second))
		}
		ctx, cancel := context.WithTimeout(r.Context(), requestTimeout)
		defer cancel()

		peer, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			peer = r.RemoteAddr
		}
		if err := allow(ctx, ratePath, peer); err != nil {
			respond(w, 0, nil, err)
			return
		}
		bearer, _ := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		handle(ctx, w, r, bearer)
	})
}

func finish(w http.ResponseWriter, path string, status int, result any, err error) {
	if path != "me" {
		slog.Info("auth_request", "operation", path, "outcome", outcome(err))
	}
	respond(w, status, result, err)
}
