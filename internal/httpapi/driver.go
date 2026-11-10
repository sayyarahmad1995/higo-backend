package httpapi

import (
	"context"
	"net/http"

	"github.com/sayyarahmad1995/higo-backend/internal/auth"
	"github.com/sayyarahmad1995/higo-backend/internal/driver"
)

const onboardingPath = "me/driver-application"

func (a api) registerDriverRoutes(mux *http.ServeMux) {
	register := func(method, path string, handle func(context.Context, http.ResponseWriter, *http.Request, auth.AccessProof)) {
		a.route(mux, method, path, a.driver.AllowRequest, func(ctx context.Context, w http.ResponseWriter, r *http.Request, bearer string) {
			handle(ctx, w, r, auth.NewAccessProof(bearer))
		})
	}
	register(http.MethodGet, onboardingPath, a.getOnboarding)
	register(http.MethodPatch, onboardingPath, a.saveOnboarding)
	register(http.MethodPost, onboardingPath, a.submitOnboarding)
	register(http.MethodPost, onboardingPath+"/document", a.uploadDocument)
	register(http.MethodDelete, onboardingPath+"/document", a.removeDocument)
	register(http.MethodGet, onboardingPath+"/preview", a.previewDocument)
}

func (a api) getOnboarding(ctx context.Context, w http.ResponseWriter, _ *http.Request, proof auth.AccessProof) {
	result, err := a.driver.GetOnboarding(ctx, proof)
	finish(w, onboardingPath, http.StatusOK, result, err)
}

func (a api) saveOnboarding(ctx context.Context, w http.ResponseWriter, r *http.Request, proof auth.AccessProof) {
	var draft map[string]string
	if err := decodeJSON(w, r, 4096, &draft); err != nil {
		respond(w, 0, nil, invalidRequest)
		return
	}
	result, err := a.driver.SaveOnboarding(ctx, proof, draft)
	finish(w, onboardingPath, http.StatusOK, result, err)
}

func (a api) submitOnboarding(ctx context.Context, w http.ResponseWriter, r *http.Request, proof auth.AccessProof) {
	var submission driver.Submission
	if err := decodeJSON(w, r, 4096, &submission); err != nil {
		respond(w, 0, nil, invalidRequest)
		return
	}
	result, err := a.driver.SubmitOnboarding(ctx, proof, submission)
	finish(w, onboardingPath, http.StatusOK, result, err)
}

func (a api) uploadDocument(ctx context.Context, w http.ResponseWriter, r *http.Request, proof auth.AccessProof) {
	id, err := a.auth.ResolveAccount(ctx, proof)
	if err != nil {
		respond(w, 0, nil, err)
		return
	}
	if err := a.driver.CheckUploadCooldown(ctx, id); err != nil {
		respond(w, 0, nil, err)
		return
	}
	if r.ContentLength > maxUploadBytes {
		respond(w, 0, nil, documentTooLarge)
		return
	}
	releaseAccount, releaseSlot, err := a.driver.ReserveUpload(id)
	if err != nil {
		respond(w, 0, nil, err)
		return
	}
	defer releaseSlot()

	var document driver.Document
	if err := a.decodeUpload(ctx, w, r, id, &document, releaseAccount); err != nil {
		respond(w, 0, nil, err)
		return
	}
	result, err := a.driver.SaveOnboardingDocument(ctx, proof, document)
	finish(w, onboardingPath+"/document", http.StatusOK, result, err)
}

func (a api) removeDocument(ctx context.Context, w http.ResponseWriter, r *http.Request, proof auth.AccessProof) {
	query := r.URL.Query()
	result, err := a.driver.RemoveOnboardingDocument(ctx, proof, query.Get("kind"), query.Get("draft_revision"))
	finish(w, onboardingPath+"/document", http.StatusOK, result, err)
}

func (a api) previewDocument(ctx context.Context, w http.ResponseWriter, r *http.Request, proof auth.AccessProof) {
	kind := r.URL.Query().Get("kind")
	if _, err := a.auth.ResolveAccount(ctx, proof); err != nil {
		respond(w, 0, nil, err)
		return
	}
	release, err := a.driver.ReservePreview()
	if err != nil {
		respond(w, 0, nil, err)
		return
	}
	defer release()
	result, err := a.driver.PreviewOnboardingDocument(ctx, proof, kind)
	finish(w, onboardingPath+"/preview", http.StatusOK, result, err)
}
