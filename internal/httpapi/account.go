package httpapi

import (
	"context"
	"net/http"

	"github.com/sayyarahmad1995/higo-backend/internal/account"
	"github.com/sayyarahmad1995/higo-backend/internal/auth"
)

func (a api) registerAccountRoutes(mux *http.ServeMux) {
	register := func(method, path string, handle func(context.Context, http.ResponseWriter, *http.Request, auth.AccessProof)) {
		a.route(mux, method, path, a.account.AllowRequest, func(ctx context.Context, w http.ResponseWriter, r *http.Request, bearer string) {
			handle(ctx, w, r, auth.NewAccessProof(bearer))
		})
	}
	register(http.MethodGet, "me", a.getProfile)
	register(http.MethodPatch, "me", a.updateProfile)
	register(http.MethodPost, "me/email/request", a.requestEmailVerification)
	register(http.MethodPost, "me/email/verify", a.verifyEmail)
}

func (a api) getProfile(ctx context.Context, w http.ResponseWriter, _ *http.Request, proof auth.AccessProof) {
	profile, err := a.account.Profile(ctx, proof)
	finish(w, "me", http.StatusOK, profile, err)
}

func (a api) updateProfile(ctx context.Context, w http.ResponseWriter, r *http.Request, proof auth.AccessProof) {
	var patch account.ProfilePatch
	if err := decodeJSON(w, r, 4096, &patch); err != nil {
		respond(w, 0, nil, invalidRequest)
		return
	}
	profile, err := a.account.UpdateProfile(ctx, proof, patch)
	finish(w, "me", http.StatusOK, profile, err)
}

func (a api) requestEmailVerification(ctx context.Context, w http.ResponseWriter, r *http.Request, proof auth.AccessProof) {
	// Email POSTs retain the historically accepted Auth fields.
	var input auth.Input
	if err := decodeJSON(w, r, 4096, &input); err != nil {
		respond(w, 0, nil, invalidRequest)
		return
	}
	profile, err := a.account.RequestEmailVerification(ctx, proof, input.Email, input.Password)
	finish(w, "me/email/request", http.StatusAccepted, profile, err)
}

func (a api) verifyEmail(ctx context.Context, w http.ResponseWriter, r *http.Request, proof auth.AccessProof) {
	var input auth.Input
	if err := decodeJSON(w, r, 4096, &input); err != nil {
		respond(w, 0, nil, invalidRequest)
		return
	}
	profile, err := a.account.VerifyEmail(ctx, proof, input.Code)
	finish(w, "me/email/verify", http.StatusOK, profile, err)
}
