package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"time"
)

func decodeJSON(w http.ResponseWriter, r *http.Request, maxBytes int64, target any) error {
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	switch err := decoder.Decode(new(any)); err {
	case io.EOF:
		return nil
	case nil:
		return invalidRequest
	default:
		return err
	}
}

const maxUploadBytes = 3 * 1024 * 1024

func (a api) decodeUpload(ctx context.Context, w http.ResponseWriter, r *http.Request, id int64, target any, releaseAccount func()) error {
	// Limit how long a stalled client can hold an upload slot.
	_ = http.NewResponseController(w).SetReadDeadline(time.Now().Add(20 * time.Second))
	started := time.Now()
	err := decodeJSON(w, r, maxUploadBytes, target)
	if time.Since(started) >= 5*time.Second {
		a.auth.RecordSlowUpload(ctx, id)
	}

	releaseAccount()

	var networkError net.Error
	var oversized *http.MaxBytesError
	switch {
	case err == nil:
		return nil
	case errors.As(err, &networkError) && networkError.Timeout():
		return uploadTimeout
	case errors.As(err, &oversized):
		return documentTooLarge
	default:
		return invalidRequest
	}
}
