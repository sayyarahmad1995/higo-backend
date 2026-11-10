package httpapi

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/sayyarahmad1995/higo-backend/internal/auth"
)

const onboardingPath = "me/driver-application"

type operation func(context.Context, auth.Input, string) (any, error)

type api struct {
	auth *auth.Server
}

// Handler registers the Core HTTP API against the Auth feature.
func Handler(service *auth.Server) http.Handler {
	api := api{auth: service}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	api.route(mux, http.MethodPost, "auth/register", http.StatusAccepted, service.Register)
	api.route(mux, http.MethodPost, "auth/register/verify", http.StatusCreated, service.VerifyRegistration)
	api.route(mux, http.MethodPost, "auth/login", http.StatusOK, service.Login)
	api.route(mux, http.MethodPost, "auth/refresh", http.StatusOK, service.Refresh)
	api.route(mux, http.MethodPost, "auth/logout", http.StatusNoContent, service.Logout)
	api.route(mux, http.MethodPost, "auth/recovery/request", http.StatusAccepted, service.RequestRecovery)
	api.route(mux, http.MethodPost, "auth/recovery/verify", http.StatusOK, service.VerifyRecovery)
	api.route(mux, http.MethodPost, "auth/recovery/reset", http.StatusNoContent, service.Reset)
	api.route(mux, http.MethodGet, "me", http.StatusOK, service.Me)
	api.route(mux, http.MethodPatch, "me", http.StatusOK, service.UpdateProfile)
	api.route(mux, http.MethodPost, "me/email/request", http.StatusAccepted, service.RequestEmailVerification)
	api.route(mux, http.MethodPost, "me/email/verify", http.StatusOK, service.VerifyEmail)
	api.route(mux, http.MethodGet, onboardingPath, http.StatusOK, service.GetOnboarding)
	api.route(mux, http.MethodPatch, onboardingPath, http.StatusOK, service.SaveOnboarding)
	api.route(mux, http.MethodPost, onboardingPath, http.StatusOK, service.SubmitOnboarding)
	api.route(mux, http.MethodPost, onboardingPath+"/document", http.StatusOK, service.SaveOnboardingDocument)
	api.route(mux, http.MethodDelete, onboardingPath+"/document", http.StatusOK, service.RemoveOnboardingDocument)
	api.route(mux, http.MethodGet, onboardingPath+"/preview", http.StatusOK, service.PreviewOnboardingDocument)
	return mux
}

func (a api) route(mux *http.ServeMux, method, path string, status int, run operation) {
	mux.HandleFunc(method+" /api/v1/"+path, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "application/json")

		documentUpload := method == http.MethodPost && path == onboardingPath+"/document"
		requestTimeout := 10 * time.Second
		ratePath := path
		if documentUpload {
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
		if err := a.auth.AllowRequest(ctx, ratePath, peer); err != nil {
			respond(w, 0, nil, err)
			return
		}

		var body auth.Input
		bearer, _ := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		switch {
		case path == onboardingPath+"/preview":
			body.OnboardingPreview = r.URL.Query().Get("kind")
			release, err := a.auth.ReservePreview(ctx, bearer)
			if err != nil {
				respond(w, 0, nil, err)
				return
			}
			defer release()
		case method == http.MethodDelete && path == onboardingPath+"/document":
			body.OnboardingDocument.Kind = r.URL.Query().Get("kind")
			body.OnboardingDocument.Revision = r.URL.Query().Get("draft_revision")
		case documentUpload:
			id, err := a.auth.CheckUpload(ctx, bearer)
			if err != nil {
				respond(w, 0, nil, err)
				return
			}
			if r.ContentLength > maxUploadBytes {
				respond(w, 0, nil, documentTooLarge)
				return
			}
			releaseAccount, releaseSlot, err := a.auth.ReserveUpload(id)
			if err != nil {
				respond(w, 0, nil, err)
				return
			}
			defer releaseSlot()
			if err := a.decodeUpload(ctx, w, r, id, &body.OnboardingDocument, releaseAccount); err != nil {
				respond(w, 0, nil, err)
				return
			}
		case method == http.MethodPatch || (method == http.MethodPost && path != "auth/logout"):
			if err := decodeJSON(w, r, 4096, jsonTarget(&body, method, path)); err != nil {
				respond(w, 0, nil, invalidRequest)
				return
			}
		}

		result, err := run(ctx, body, bearer)
		if path != "me" {
			slog.Info("auth_request", "operation", path, "outcome", outcome(err))
		}
		respond(w, status, result, err)
	})
}

func jsonTarget(body *auth.Input, method, path string) any {
	if path == onboardingPath {
		if method == http.MethodPatch {
			return &body.OnboardingDraft
		}
		return &body.OnboardingSubmit
	}
	if method == http.MethodPatch {
		return &body.Profile
	}
	return body
}
