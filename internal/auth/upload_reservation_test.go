package auth_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"image"
	"image/png"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"testing/iotest"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/sayyarahmad1995/higo-backend/internal/auth"
)

type uploadReaderFunc func([]byte) (int, error)

func (read uploadReaderFunc) Read(p []byte) (int, error) { return read(p) }

func testUploadReservations(t *testing.T, handler http.Handler, server *auth.Server, db *pgxpool.Pool, access string, accountID int64) {
	t.Helper()

	var picture bytes.Buffer
	if err := png.Encode(&picture, image.NewRGBA(image.Rect(0, 0, 2, 2))); err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(map[string]any{"kind": "selfie", "image": picture.Bytes()})
	if err != nil {
		t.Fatal(err)
	}
	upload := func(ctx context.Context, body io.Reader) *httptest.ResponseRecorder {
		req := httptest.NewRequestWithContext(ctx, http.MethodPost, "/api/v1/me/driver-application/document", body)
		req.RemoteAddr = "192.0.2.12:12345"
		req.Header.Set("Authorization", "Bearer "+access)
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, req)
		return recorder
	}
	expectError := func(t *testing.T, response *httptest.ResponseRecorder, status int, code string) {
		t.Helper()
		if response.Code != status || response.Body.String() != fmt.Sprintf("{\"error\":%q}\n", code) {
			t.Fatalf("response = %d %s, want %d %s", response.Code, response.Body, status, code)
		}
	}
	expectAvailable := func(t *testing.T) {
		t.Helper()
		// There is no draft yet. This response shows that the retry reached the business operation.
		expectError(t, upload(t.Context(), bytes.NewReader(payload)), http.StatusConflict, "onboarding_incomplete")

		// A successful retry alone would miss a leak of one of the two global slots.
		for _, id := range []int64{accountID, -1} {
			releaseAccount, releaseSlot, err := server.ReserveUpload(id)
			if err != nil {
				t.Fatalf("upload capacity was not released: %v", err)
			}
			defer releaseSlot()
			defer releaseAccount()
		}
	}

	t.Run("simultaneous upload for the same account is rejected", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
		defer cancel()
		reading, resume := make(chan struct{}), make(chan struct{})
		body := io.MultiReader(uploadReaderFunc(func([]byte) (int, error) {
			close(reading)
			select {
			case <-resume:
				return 0, io.EOF
			case <-ctx.Done():
				return 0, ctx.Err()
			}
		}), bytes.NewReader(payload))
		var first *httptest.ResponseRecorder
		done := make(chan struct{})
		go func() {
			defer close(done)
			first = upload(ctx, body)
		}()
		defer func() {
			cancel()
			// Join the handler before the parent test can close Auth or the database.
			<-done
		}()

		select {
		case <-reading:
		case <-ctx.Done():
			t.Fatal("first upload did not reach body decoding")
		}
		expectError(t, upload(ctx, bytes.NewReader(payload)), http.StatusServiceUnavailable, "temporarily_unavailable")
		close(resume)
		select {
		case <-done:
		case <-ctx.Done():
			t.Fatal("first upload did not complete")
		}
		expectError(t, first, http.StatusConflict, "onboarding_incomplete")
		expectAvailable(t)
	})

	t.Run("failed uploads release account and global reservations", func(t *testing.T) {
		for _, tc := range []struct {
			name   string
			body   func(context.Context, context.CancelFunc) io.Reader
			status int
			code   string
		}{
			{"malformed", func(context.Context, context.CancelFunc) io.Reader {
				return strings.NewReader("{")
			}, http.StatusBadRequest, "invalid_request"},
			{"streamed oversized", func(context.Context, context.CancelFunc) io.Reader {
				// MultiReader leaves the content length unknown, so the limit is hit after reservation.
				return io.MultiReader(strings.NewReader(`{"image":"`), strings.NewReader(strings.Repeat("A", 3*1024*1024)), strings.NewReader(`"}`))
			}, http.StatusRequestEntityTooLarge, "document_too_large"},
			{"canceled during read", func(ctx context.Context, cancel context.CancelFunc) io.Reader {
				return uploadReaderFunc(func([]byte) (int, error) {
					cancel()
					return 0, ctx.Err()
				})
			}, http.StatusBadRequest, "invalid_request"},
			{"read timed out", func(context.Context, context.CancelFunc) io.Reader {
				return iotest.ErrReader(os.ErrDeadlineExceeded)
			}, http.StatusRequestTimeout, "upload_timeout"},
		} {
			t.Run(tc.name, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
				defer cancel()
				expectError(t, upload(ctx, tc.body(ctx, cancel)), tc.status, tc.code)
				expectAvailable(t)
			})
		}
	})

	t.Run("slow upload persists an account cooldown", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
		defer cancel()
		key := auth.HexDigestForTest(fmt.Sprintf("document/slow-upload/%d", accountID))
		t.Cleanup(func() {
			cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if _, err := db.Exec(cleanup, "DELETE FROM auth_rate_limits WHERE key=$1 AND bucket=0", key); err != nil {
				t.Error(err)
			}
		})

		body := io.MultiReader(uploadReaderFunc(func([]byte) (int, error) {
			timer := time.NewTimer(5100 * time.Millisecond)
			defer timer.Stop()
			select {
			case <-timer.C:
				return 0, io.EOF
			case <-ctx.Done():
				return 0, ctx.Err()
			}
		}), bytes.NewReader(payload))
		expectError(t, upload(ctx, body), http.StatusConflict, "onboarding_incomplete")

		var active bool
		err := db.QueryRow(ctx, "SELECT expires_at > now() FROM auth_rate_limits WHERE key=$1 AND bucket=0", key).Scan(&active)
		if err != nil || !active {
			t.Fatalf("expected an active cooldown in PostgreSQL, got active=%t, err=%v", active, err)
		}
		expectError(t, upload(ctx, bytes.NewReader(payload)), http.StatusTooManyRequests, "rate_limited")

		if _, err := db.Exec(ctx, "UPDATE auth_rate_limits SET expires_at=now() WHERE key=$1 AND bucket=0", key); err != nil {
			t.Fatal(err)
		}
		expectAvailable(t)
	})
}
