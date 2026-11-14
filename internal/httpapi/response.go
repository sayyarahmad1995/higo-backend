package httpapi

import (
	"encoding/json"
	"net/http"

	"github.com/sayyarahmad1995/higo-backend/internal/account"
	"github.com/sayyarahmad1995/higo-backend/internal/auth"
	"github.com/sayyarahmad1995/higo-backend/internal/driver"
)

type requestError string

func (e requestError) Error() string { return string(e) }

const (
	invalidRequest   requestError = "invalid_request"
	documentTooLarge requestError = "document_too_large"
	uploadTimeout    requestError = "upload_timeout"
)

func outcome(err error) string {
	if err == nil {
		return "success"
	}
	if requestErr, ok := err.(requestError); ok {
		return requestErr.Error()
	}
	if code := auth.ErrorCode(err); code != "" {
		return code
	}
	if code := account.ErrorCode(err); code != "" {
		return code
	}
	if code := driver.ErrorCode(err); code != "" {
		return code
	}
	return "internal_error"
}

func respond(w http.ResponseWriter, status int, result any, err error) {
	if err != nil {
		code := outcome(err)
		switch code {
		case "invalid_request", "invalid_or_expired_code", "invalid_or_expired_recovery_token", "invalid_document":
			status = http.StatusBadRequest
		case "document_too_large":
			status = http.StatusRequestEntityTooLarge
		case "onboarding_conflict", "onboarding_incomplete":
			status = http.StatusConflict
		case "upload_timeout":
			status = http.StatusRequestTimeout
		case "invalid_credentials", "unauthorized":
			status = http.StatusUnauthorized
		case "rate_limited":
			status = http.StatusTooManyRequests
		case "temporarily_unavailable":
			status = http.StatusServiceUnavailable
		default:
			status = http.StatusInternalServerError
		}
		result = map[string]string{"error": code}
	}
	w.WriteHeader(status)
	if result != nil {
		_ = json.NewEncoder(w).Encode(result)
	}
}
