package auth_test

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/json"
	"fmt"
	"image"
	"image/png"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"crypto/rand"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/sayyarahmad1995/higo-backend/internal/auth"
	"github.com/sayyarahmad1995/higo-backend/internal/driver"
)

const driverPath = "/api/v1/me/driver-application"

type heldPreviewResponse struct {
	*httptest.ResponseRecorder
	onHeader func()
}

func (w *heldPreviewResponse) WriteHeader(status int) {
	w.onHeader()
	w.ResponseRecorder.WriteHeader(status)
}

func testDriverTransactions(t *testing.T, db *pgxpool.Pool, handler http.Handler, service *driver.Service, sourceID int64, sourceAccess, password string) {
	t.Helper()
	ctx := t.Context()
	var id int64
	if err := db.QueryRow(ctx, `INSERT INTO auth_users(phone,name,password_hash)
 SELECT '+923111234567','Driver fixture',password_hash FROM auth_users WHERE id=$1 RETURNING id`, sourceID).Scan(&id); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := db.Exec(context.Background(), "DELETE FROM auth_users WHERE id=$1", id); err != nil {
			t.Error(err)
		}
	})
	newRequest := func(ctx context.Context, method, path, bearer string, body io.Reader) *http.Request {
		req := httptest.NewRequestWithContext(ctx, method, path, body)
		req.RemoteAddr = "192.0.2.50:12345"
		req.Header.Set("Authorization", "Bearer "+bearer)
		return req
	}
	request := func(method, path, bearer string, body io.Reader) *httptest.ResponseRecorder {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, newRequest(ctx, method, path, bearer, body))
		return recorder
	}
	expect := func(t *testing.T, response *httptest.ResponseRecorder, status int, code string) {
		t.Helper()
		if response.Code != status || (code != "" && response.Body.String() != fmt.Sprintf("{\"error\":%q}\n", code)) {
			t.Fatalf("response = %d %s, want %d %s", response.Code, response.Body, status, code)
		}
	}
	login := func(t *testing.T) string {
		t.Helper()
		credentials, err := json.Marshal(map[string]string{"phone": "+923111234567", "password": password})
		if err != nil {
			t.Fatal(err)
		}
		response := request(http.MethodPost, "/api/v1/auth/login", "", bytes.NewReader(credentials))
		expect(t, response, http.StatusOK, "")
		var tokens struct {
			Access string `json:"access_token"`
		}
		if err := json.Unmarshal(response.Body.Bytes(), &tokens); err != nil || tokens.Access == "" {
			t.Fatalf("login did not return an access token: %v", err)
		}
		return tokens.Access
	}
	access := login(t)
	expect(t, request(http.MethodPatch, driverPath, access, strings.NewReader(`{"revision":"0","step":"0"}`)), http.StatusOK, "")

	makeImage := func(red byte) []byte {
		t.Helper()
		picture := image.NewRGBA(image.Rect(0, 0, 2, 2))
		picture.Pix[0], picture.Pix[3] = red, 255
		var encoded bytes.Buffer
		if err := png.Encode(&encoded, picture); err != nil {
			t.Fatal(err)
		}
		return encoded.Bytes()
	}
	imageData := makeImage(20)
	uploadBody := func(data []byte, revision string) io.Reader {
		t.Helper()
		payload, err := json.Marshal(map[string]any{"kind": "selfie", "image": data, "draft_revision": revision})
		if err != nil {
			t.Fatal(err)
		}
		return bytes.NewReader(payload)
	}
	quotaKey := auth.HexDigestForTest(fmt.Sprintf("onboarding/document-changes/%d", id))
	assertDraft := func(t *testing.T, revision, evidence int, submitted bool) {
		t.Helper()
		var gotRevision, gotEvidence int
		var gotSubmitted bool
		err := db.QueryRow(ctx, `SELECT draft_revision, submitted_at IS NOT NULL,
 (SELECT count(*) FROM driver_onboarding_documents d WHERE (d.user_id,d.application_version)=(a.user_id,a.application_version))
 FROM driver_onboarding_applications a WHERE user_id=$1 AND application_version=1`, id).
			Scan(&gotRevision, &gotSubmitted, &gotEvidence)
		if err != nil || gotRevision != revision || gotEvidence != evidence || gotSubmitted != submitted {
			t.Fatalf("draft revision=%d evidence=%d submitted=%t err=%v", gotRevision, gotEvidence, gotSubmitted, err)
		}
	}
	t.Run("logout during body decoding invalidates Driver transaction", func(t *testing.T) {
		body := io.MultiReader(uploadReaderFunc(func([]byte) (int, error) {
			// Reaching Read proves preflight and reservation succeeded before logout.
			expect(t, request(http.MethodPost, "/api/v1/auth/logout", access, nil), http.StatusNoContent, "")
			return 0, io.EOF
		}), uploadBody(imageData, "1"))
		expect(t, request(http.MethodPost, driverPath+"/document", access, body), http.StatusUnauthorized, "unauthorized")
		assertDraft(t, 1, 0, false)
		access = login(t)
	})

	t.Run("canceled Driver request waiting on the account lock leaves draft unchanged", func(t *testing.T) {
		tx, err := db.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(ctx)
		if _, err := tx.Exec(ctx, "SELECT id FROM auth_users WHERE id=$1 FOR UPDATE", id); err != nil {
			t.Fatal(err)
		}
		var blocker int32
		if err := tx.QueryRow(ctx, "SELECT pg_backend_pid()").Scan(&blocker); err != nil {
			t.Fatal(err)
		}
		wait, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		var result *httptest.ResponseRecorder
		done := make(chan struct{})
		go func() {
			defer close(done)
			result = httptest.NewRecorder()
			handler.ServeHTTP(result, newRequest(wait, http.MethodPatch, driverPath, access, strings.NewReader(`{"revision":"1","step":"0"}`)))
		}()
		defer func() {
			cancel()
			_ = tx.Rollback(ctx)
			<-done
		}()
		for {
			var blocked bool
			err := db.QueryRow(wait, `SELECT EXISTS (
 SELECT 1 FROM pg_stat_activity WHERE $1=ANY(pg_blocking_pids(pid)))`, blocker).Scan(&blocked)
			if err != nil {
				t.Fatal("Driver request never waited for the account lock: ", err)
			}
			if blocked {
				break
			}
			time.Sleep(5 * time.Millisecond)
		}
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("Driver request did not exit after cancellation")
		}
		expect(t, result, http.StatusInternalServerError, "internal_error")
		assertDraft(t, 1, 0, false)
	})

	t.Run("preview responses from two accounts occupy both processing slots", func(t *testing.T) {
		// Writing a preview response happens before its processing slot is released.
		// Nest the requests at that point to keep both slots held deterministically.
		preview := func(token string, onHeader func()) {
			response := &heldPreviewResponse{ResponseRecorder: httptest.NewRecorder(), onHeader: onHeader}
			handler.ServeHTTP(response, newRequest(ctx, http.MethodGet, driverPath+"/preview?kind=selfie", token, nil))
			expect(t, response.ResponseRecorder, http.StatusBadRequest, "invalid_request")
		}
		preview(sourceAccess, func() {
			preview(access, func() {
				expect(t, request(http.MethodPost, driverPath+"/document", access, uploadBody(imageData, "1")), http.StatusServiceUnavailable, "temporarily_unavailable")
			})
		})
		assertDraft(t, 1, 0, false)
	})

	exec := func(t *testing.T, sql string, args ...any) {
		t.Helper()
		if _, err := db.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	t.Run("failed revision update rolls back evidence and quota", func(t *testing.T) {
		exec(t, "ALTER TABLE driver_onboarding_applications ADD CONSTRAINT test_revision_failure CHECK (draft_revision <> 2) NOT VALID")
		response := request(http.MethodPost, driverPath+"/document", access, uploadBody(imageData, "1"))
		exec(t, "ALTER TABLE driver_onboarding_applications DROP CONSTRAINT test_revision_failure")
		expect(t, response, http.StatusInternalServerError, "internal_error")
		assertDraft(t, 1, 0, false)
		var rows int
		if err := db.QueryRow(ctx, "SELECT count(*) FROM auth_rate_limits WHERE key=$1", quotaKey).Scan(&rows); err != nil || rows != 0 {
			t.Fatalf("failed transaction left %d quota rows, err=%v", rows, err)
		}
	})
	expect(t, request(http.MethodPost, driverPath+"/document", access, uploadBody(imageData, "1")), http.StatusOK, "")
	assertDraft(t, 2, 1, false)

	t.Run("identical retry bypasses exhausted change budget", func(t *testing.T) {
		exec(t, `INSERT INTO auth_rate_limits(key,bucket,attempts,expires_at)
 SELECT $1, floor(extract(epoch FROM now())/900)::bigint + bucket_offset, 40, now()+interval '30 minutes'
 FROM generate_series(0,1) AS bucket_offset ON CONFLICT (key,bucket) DO UPDATE SET attempts=40,expires_at=excluded.expires_at`, quotaKey)
		expect(t, request(http.MethodPost, driverPath+"/document", access, uploadBody(imageData, "1")), http.StatusOK, "")
		expect(t, request(http.MethodPost, driverPath+"/document", access, uploadBody(makeImage(100), "2")), http.StatusTooManyRequests, "rate_limited")
		assertDraft(t, 2, 1, false)
	})

	t.Run("legacy ciphertext opens only for its original evidence context", func(t *testing.T) {
		for kind, alias := range map[string]string{
			"cnic_front": "identity:front", "cnic_back": "identity:back",
			"registration": "vehicle:registration", "additional": "vehicle:insurance",
		} {
			encrypted := sealBaselineEvidence(t, id, 1, alias, imageData)
			exec(t, `INSERT INTO driver_onboarding_documents VALUES ($1,1,$2,$3)`, id, kind, encrypted)
			response := request(http.MethodGet, driverPath+"/preview?kind="+kind, access, nil)
			expect(t, response, http.StatusOK, "")
			var result struct {
				Image []byte `json:"image"`
			}
			if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil || !bytes.Equal(result.Image, imageData) {
				t.Fatalf("legacy %s evidence was not recovered: %v", kind, err)
			}

			wrongContext := sealBaselineEvidence(t, id, 2, alias, imageData)
			exec(t, "UPDATE driver_onboarding_documents SET image=$3 WHERE user_id=$1 AND kind=$2", id, kind, wrongContext)
			expect(t, request(http.MethodGet, driverPath+"/preview?kind="+kind, access, nil), http.StatusInternalServerError, "internal_error")
			exec(t, "UPDATE driver_onboarding_documents SET image=$3 WHERE user_id=$1 AND kind=$2", id, kind, encrypted)
		}
	})

	t.Run("evidence operations are scoped to the authenticated account", func(t *testing.T) {
		expect(t, request(http.MethodGet, driverPath+"/preview?kind=selfie", sourceAccess, nil), http.StatusBadRequest, "invalid_request")
		expect(t, request(http.MethodPost, driverPath+"/document", sourceAccess, uploadBody(imageData, "2")), http.StatusConflict, "onboarding_incomplete")
		expect(t, request(http.MethodDelete, driverPath+"/document?kind=additional&draft_revision=2", sourceAccess, nil), http.StatusConflict, "onboarding_conflict")
		assertDraft(t, 2, 5, false)
	})

	t.Run("failed submission keeps the draft and evidence available", func(t *testing.T) {
		exec(t, `UPDATE driver_onboarding_applications SET details='{"step":"3","legal_name":"Driver Fixture",
 "date_of_birth":"1990-01-01","cnic_number":"1234567890123","make":"Test","model":"Car","color":"Black",
 "manufacture_year":"2020","registration_number":"ABC-123","cnic_validity":"lifetime",
 "license_expiry":"2099-01-01","registration_validity":"no_expiry","additional_validity":"no_expiry"}'
 WHERE user_id=$1`, id)
		for _, kind := range []string{"license_front", "license_back", "exterior_front", "exterior_rear", "exterior_right", "exterior_left", "interior_front", "interior_rear"} {
			exec(t, "INSERT INTO driver_onboarding_documents VALUES ($1,1,$2,$3)", id, kind, sealBaselineEvidence(t, id, 1, kind, imageData))
		}
		submit := func() *httptest.ResponseRecorder {
			return request(http.MethodPost, driverPath, access, strings.NewReader(`{"draft_revision":"2","confirmed":true}`))
		}
		exec(t, "ALTER TABLE driver_onboarding_applications ADD CONSTRAINT test_submission_failure CHECK (submitted_at IS NULL) NOT VALID")
		response := submit()
		exec(t, "ALTER TABLE driver_onboarding_applications DROP CONSTRAINT test_submission_failure")
		expect(t, response, http.StatusInternalServerError, "internal_error")
		assertDraft(t, 2, 13, false)
		expect(t, submit(), http.StatusOK, "")
		assertDraft(t, 2, 13, true)
		expect(t, request(http.MethodDelete, driverPath+"/document?kind=additional&draft_revision=2", access, nil), http.StatusConflict, "onboarding_conflict")
		assertDraft(t, 2, 13, true)
	})

	t.Run("retention purges only eligible Driver rows", func(t *testing.T) {
		ciphertext := sealBaselineEvidence(t, id, 2, "selfie", imageData)
		exec(t, `INSERT INTO driver_onboarding_applications(user_id,application_version,details,updated_at)
 VALUES($1,2,'{"step":"2","legal_name":"Saved Draft"}',now()-interval '31 days')`, id)
		exec(t, "INSERT INTO driver_onboarding_documents VALUES ($1,2,'selfie',$2)", id, ciphertext)
		exec(t, `INSERT INTO driver_identity_submissions(user_id,version,legal_name,cnic_front,cnic_back,submitted_at)
 VALUES($1,1,'Driver Fixture',$2,$2,now()-interval '31 days'),($1,2,'Driver Fixture',$2,$2,now())`, id, ciphertext)
		exec(t, `INSERT INTO driver_vehicle_submissions(user_id,vehicle_id,version,make,model,manufacture_year,color,registration_number,registration_image,insurance_image,submitted_at)
 VALUES($1,1,1,'Test','Car',2020,'Black','ABC-123',$2,$2,now()-interval '31 days'),
 ($1,1,2,'Test','Car',2020,'Black','ABC-123',$2,$2,now())`, id, ciphertext)
		exec(t, "UPDATE driver_onboarding_applications SET updated_at=now()-interval '31 days' WHERE user_id=$1 AND application_version=1", id)
		service.PurgeDocuments(ctx)
		assertDraft(t, 2, 13, true)
		var purged bool
		err := db.QueryRow(ctx, `SELECT
 (SELECT details->>'step'='0' AND details->>'legal_name'='Saved Draft' AND draft_revision=2
 FROM driver_onboarding_applications WHERE user_id=$1 AND application_version=2)
 AND NOT EXISTS (SELECT 1 FROM driver_onboarding_documents WHERE user_id=$1 AND application_version=2)
 AND (SELECT bool_and((cnic_front IS NULL)=(version=1)) FROM driver_identity_submissions WHERE user_id=$1)
 AND (SELECT bool_and((registration_image IS NULL)=(version=1)) FROM driver_vehicle_submissions WHERE user_id=$1)`, id).Scan(&purged)
		if err != nil || !purged {
			t.Fatalf("unexpected retention state: purged=%t, err=%v", purged, err)
		}
	})
}

var requiredDriverKinds = []string{
	"selfie", "cnic_front", "cnic_back", "license_front", "license_back", "registration",
	"exterior_front", "exterior_rear", "exterior_right", "exterior_left", "interior_front", "interior_rear",
}

// Baseline storage prepends the 12-byte nonce to standard AES-GCM ciphertext.
func baselineEvidenceCipher(t *testing.T) cipher.AEAD {
	t.Helper()
	block, err := aes.NewCipher(bytes.Repeat([]byte{8}, 32))
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	return gcm
}

func baselineEvidenceAAD(id int64, version int, alias string) []byte {
	return []byte(fmt.Sprintf("driver-onboarding:%d:%d:%s", id, version, alias))
}

func sealBaselineEvidence(t *testing.T, id int64, version int, alias string, image []byte) []byte {
	t.Helper()
	gcm := baselineEvidenceCipher(t)
	aad := baselineEvidenceAAD(id, version, alias)
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	return gcm.Seal(bytes.Clone(nonce), nonce, image, aad)
}

func openBaselineEvidence(t *testing.T, id int64, version int, kind string, encrypted []byte) ([]byte, error) {
	t.Helper()
	alias := kind
	switch kind {
	case "cnic_front":
		alias = "identity:front"
	case "cnic_back":
		alias = "identity:back"
	case "registration":
		alias = "vehicle:registration"
	case "additional":
		alias = "vehicle:insurance"
	}
	gcm := baselineEvidenceCipher(t)
	size := gcm.NonceSize()
	if len(encrypted) < size {
		return nil, fmt.Errorf("truncated evidence")
	}
	return gcm.Open(nil, encrypted[:size], encrypted[size:], baselineEvidenceAAD(id, version, alias))
}
