package auth_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"image"
	"image/png"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/sayyarahmad1995/higo-backend/internal/auth"
	"github.com/sayyarahmad1995/higo-backend/internal/driver"
	"github.com/sayyarahmad1995/higo-backend/internal/httpapi"
	"github.com/sayyarahmad1995/higo-backend/migrations"
)

type testSMS struct {
	codes   chan string
	stall   atomic.Bool
	started chan struct{}
}

type testEmail chan string

func (s testEmail) Send(_ context.Context, address, code string) error {
	s <- code
	if address == "failed@example.test" {
		return errors.New("test provider unavailable")
	}
	return nil
}

func (s *testSMS) Send(ctx context.Context, phone, code string) error {
	if phone == "+923001234567" && s.stall.Load() {
		close(s.started)
		<-ctx.Done()
		return ctx.Err()
	}
	s.codes <- code
	return nil
}

func TestAuthenticationFlow(t *testing.T) {
	url := os.Getenv("HIGO_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("HIGO_TEST_DATABASE_URL is required for PostgreSQL tests")
	}
	ctx := context.Background()
	db, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	schema, err := auth.NewTokenForTest("")
	if err != nil {
		t.Fatal(err)
	}
	schema = "test_" + auth.HexDigestForTest(schema)[:16]
	if _, err := db.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatal(err)
	}
	defer db.Exec(ctx, "DROP SCHEMA "+schema+" CASCADE")
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	isolated, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer isolated.Close()
	if err := migrations.Apply(ctx, isolated); err != nil {
		t.Fatal(err)
	}
	sms := &testSMS{codes: make(chan string, 4), started: make(chan struct{})}
	emails := make(testEmail, 4)
	driverService, err := driver.New(isolated, bytes.Repeat([]byte{8}, 32))
	if err != nil {
		t.Fatal(err)
	}
	server, err := auth.New(ctx, isolated, sms, auth.Config{PurgeDriverDocuments: driverService.PurgeDocuments, EmailSender: emails, OTPKey: bytes.Repeat([]byte{7}, 32), PasswordMemory: 19456, PasswordPasses: 2})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	handler := httpapi.Handler(server, driverService)
	peer := "192.0.2.1:12345"
	call := func(method, path, bearer string, body any) (int, map[string]any) {
		data, _ := json.Marshal(body)
		req := httptest.NewRequest(method, "/api/v1/"+path, bytes.NewReader(data))
		req.RemoteAddr = peer
		if bearer != "" {
			req.Header.Set("Authorization", "Bearer "+bearer)
		}
		resp := httptest.NewRecorder()
		handler.ServeHTTP(resp, req)
		var result map[string]any
		json.Unmarshal(resp.Body.Bytes(), &result)
		return resp.Code, result
	}
	post := func(path string, body any) (int, map[string]any) {
		return call(http.MethodPost, "auth/"+path, "", body)
	}
	expect := func(t *testing.T, got, want int, result map[string]any) {
		t.Helper()
		if got != want {
			t.Fatalf("status = %d, want %d (%v)", got, want, result)
		}
	}
	receiveCode := func(t *testing.T, challenge string) string {
		t.Helper()
		select {
		case code := <-sms.codes:
			deadline := time.Now().Add(3 * time.Second)
			for time.Now().Before(deadline) {
				var delivered bool
				err := isolated.QueryRow(ctx, "SELECT delivered FROM auth_challenges WHERE id=$1", auth.TokenDigestForTest(challenge, "oc_")).Scan(&delivered)
				if err != nil {
					t.Fatal(err)
				}
				if delivered {
					return code
				}
				time.Sleep(10 * time.Millisecond)
			}
			t.Fatal("SMS was not marked delivered")
		case <-time.After(5 * time.Second):
			t.Fatal("SMS missing")
		}
		return ""
	}
	t.Run("malformed request bodies keep the HTTP error contract", func(t *testing.T) {
		for _, tc := range []struct {
			name string
			body string
		}{
			{"malformed JSON", `{"phone":`},
			{"unknown field", `{"unknown":true}`},
			{"trailing value", `{} {}`},
			{"oversized body", `{"phone":"` + strings.Repeat("0", 4096) + `"}`},
		} {
			t.Run(tc.name, func(t *testing.T) {
				req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", strings.NewReader(tc.body))
				req.RemoteAddr = "192.0.2.11:12345"
				recorder := httptest.NewRecorder()
				handler.ServeHTTP(recorder, req)
				if recorder.Code != http.StatusBadRequest || recorder.Body.String() != "{\"error\":\"invalid_request\"}\n" ||
					recorder.Header().Get("Content-Type") != "application/json" || recorder.Header().Get("Cache-Control") != "no-store" {
					t.Fatalf("unexpected response: %d %v %s", recorder.Code, recorder.Header(), recorder.Body)
				}
			})
		}
	})
	t.Run("canceled request stops before decoding", func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		req := httptest.NewRequestWithContext(ctx, http.MethodPost, "/api/v1/auth/login", strings.NewReader("{"))
		req.RemoteAddr = "192.0.2.11:12345"
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, req)
		if recorder.Code != http.StatusInternalServerError || recorder.Body.String() != "{\"error\":\"internal_error\"}\n" {
			t.Fatalf("unexpected response: %d %s", recorder.Code, recorder.Body)
		}
	})
	const phone = "+923001234567"
	const oldPassword = "the original password"
	const newPassword = "the replacement password"
	credentials := map[string]string{"phone": phone, "password": oldPassword, "name": "Test Rider", "email": "signup@example.test"}
	status, unknown := post("login", credentials)
	expect(t, status, 401, unknown)
	status, body := post("register", credentials)
	expect(t, status, 202, body)
	challenge := body["challenge"].(string)
	code := receiveCode(t, challenge)
	proof := map[string]string{"challenge": challenge, "code": code}
	status, body = post("recovery/verify", proof)
	expect(t, status, 400, body)
	type response struct {
		status int
		body   map[string]any
	}
	verification := make(chan response, 2)
	for range 2 {
		go func() {
			status, body := post("register/verify", proof)
			verification <- response{status, body}
		}()
	}
	first, second := <-verification, <-verification
	if first.status != 201 {
		first, second = second, first
	}
	expect(t, first.status, 201, first.body)
	expect(t, second.status, 400, second.body)
	body = first.body
	access := body["access_token"].(string)
	refresh := body["refresh_token"].(string)
	status, body = post("register/verify", proof)
	expect(t, status, 400, body)
	status, body = call(http.MethodGet, "me", access, nil)
	expect(t, status, 200, body)
	if body["phone"] != phone {
		t.Fatal("wrong current user")
	}
	t.Run("upload reservation boundary", func(t *testing.T) {
		testUploadReservations(t, handler, driverService, isolated, access, int64(body["id"].(float64)))
	})
	t.Run("Driver transaction boundaries", func(t *testing.T) {
		testDriverTransactions(t, isolated, handler, driverService, int64(body["id"].(float64)), access, oldPassword)
	})
	t.Run("redesigned onboarding is resumable, bounded and immutable", func(t *testing.T) {
		const path = "me/driver-application"
		var picture bytes.Buffer
		if err := png.Encode(&picture, image.NewRGBA(image.Rect(0, 0, 2, 2))); err != nil {
			t.Fatal(err)
		}
		draft := map[string]string{"revision": "0", "step": "0", "legal_name": "Example Driver", "date_of_birth": "1990-01-01", "cnic_number": "1234567890123"}
		update := func(method, route string, data any, want int) map[string]any {
			t.Helper()
			status, body := call(method, route, access, data)
			expect(t, status, want, body)
			return body
		}
		apply := func(body map[string]any) { draft["revision"] = body["draft"].(map[string]any)["revision"].(string) }
		upload := func(kind string, image []byte, want int) map[string]any {
			return update(http.MethodPost, path+"/document", map[string]any{"draft_revision": draft["revision"], "kind": kind, "image": image}, want)
		}
		apply(update(http.MethodPatch, path, draft, 200))
		draft["step"] = "1"
		update(http.MethodPatch, path, draft, 409)
		upload("selfie", []byte("bad image"), 400)
		upload("selfie", make([]byte, (2*1024*1024)+1), 413)
		upload("selfie", make([]byte, 3*(2*1024*1024)), 413)
		apply(upload("selfie", picture.Bytes(), 200))
		savedRevision := draft["revision"]
		retry := update(http.MethodPost, path+"/document", map[string]any{
			"draft_revision": "1", "kind": "selfie", "image": picture.Bytes(),
		}, 200)
		if retry["draft"].(map[string]any)["revision"] != savedRevision {
			t.Fatal("an identical retry changed the draft revision")
		}
		for i := 1; i <= 6; i++ {
			imageData := image.NewRGBA(image.Rect(0, 0, 2, 2))
			imageData.Pix[0], imageData.Pix[3] = byte(i), 255
			var replacement bytes.Buffer
			if err := png.Encode(&replacement, imageData); err != nil {
				t.Fatal(err)
			}
			apply(upload("selfie", replacement.Bytes(), 200))
		}
		status, body := post("login", credentials)
		expect(t, status, 200, body)
		restored := body["access_token"].(string)
		status, body = call(http.MethodGet, path, restored, nil)
		expect(t, status, 200, body)
		if body["draft"].(map[string]any)["revision"] != draft["revision"] || len(body["documents"].([]any)) != 1 {
			t.Fatal(body)
		}
		update(http.MethodGet, path+"/preview?kind=selfie", nil, 200)
		apply(update(http.MethodPatch, path, draft, 200))
		draft["step"], draft["make"], draft["model"], draft["manufacture_year"], draft["color"], draft["registration_number"] = "2", "Test", "Car", "2020", "Black", "ABC-123"
		results := make(chan response, 2)
		for range 2 {
			go func() {
				status, body := call(http.MethodPatch, path, restored, draft)
				results <- response{status, body}
			}()
		}
		a, b := <-results, <-results
		if a.status == 409 {
			a, b = b, a
		}
		expect(t, a.status, 200, a.body)
		expect(t, b.status, 409, b.body)
		apply(a.body)
		upload("cnic_front", make([]byte, (1024*1024)+1), 413)
		for _, kind := range requiredDriverKinds[1:] {
			apply(upload(kind, picture.Bytes(), 200))
		}
		apply(upload("additional", picture.Bytes(), 200))
		apply(update(http.MethodDelete, path+"/document?kind=additional&draft_revision="+draft["revision"], nil, 200))
		draft["step"], draft["cnic_validity"], draft["registration_validity"], draft["license_expiry"] = "3", "lifetime", "no_expiry", "2000-01-01"
		update(http.MethodPatch, path, draft, 409)
		draft["license_expiry"] = "2099-01-01"
		apply(update(http.MethodPatch, path, draft, 200))
		final := map[string]any{"draft_revision": draft["revision"], "confirmed": false}
		update(http.MethodPost, path, final, 409)
		final["confirmed"] = true
		for range 2 {
			go func() {
				status, body := call(http.MethodPost, path, restored, final)
				results <- response{status, body}
			}()
		}
		for range 2 {
			result := <-results
			expect(t, result.status, 200, result.body)
			if result.body["status"] != "pending_review" || result.body["application_version"] != float64(1) || result.body["submitted_at"] == nil {
				t.Fatal(result.body)
			}
		}
		draft["legal_name"] = "Attempted Rewrite"
		update(http.MethodPatch, path, draft, 409)
		upload("selfie", picture.Bytes(), 409)
		update(http.MethodGet, path+"/preview?kind=selfie", nil, 409)
		rows, err := isolated.Query(ctx, `SELECT user_id,kind,image FROM driver_onboarding_documents`)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		count := 0
		for rows.Next() {
			var id int64
			var kind string
			var encrypted []byte
			if err := rows.Scan(&id, &kind, &encrypted); err != nil {
				t.Fatal(err)
			}
			data, err := openBaselineEvidence(t, id, 1, kind, encrypted)
			if err != nil || !bytes.HasPrefix(data, picture.Bytes()[:8]) || bytes.HasPrefix(encrypted, picture.Bytes()[:8]) {
				t.Fatalf("encryption of %s: %v", kind, err)
			}
			count++
		}
		if err := rows.Err(); err != nil || count != len(requiredDriverKinds) {
			t.Fatalf("evidence count %d: %v", count, err)
		}
		status, body = call(http.MethodGet, "me", restored, nil)
		expect(t, status, 200, body)
		if caps := body["capabilities"].([]any); len(caps) != 1 || caps[0] != "rider" {
			t.Fatal(body)
		}
	})

	t.Run("driver membership comes from storage across sessions", func(t *testing.T) {
		status, body := call(http.MethodGet, "me", access, nil)
		expect(t, status, 200, body)
		if got := body["capabilities"].([]any); len(got) != 1 || got[0] != "rider" {
			t.Fatalf("default capabilities = %v", got)
		}
		if _, err := isolated.Exec(ctx, "UPDATE auth_users SET has_driver_capability=true WHERE phone=$1", phone); err != nil {
			t.Fatal(err)
		}
		status, body = post("login", credentials)
		expect(t, status, 200, body)
		status, body = call(http.MethodGet, "me", body["access_token"].(string), nil)
		expect(t, status, 200, body)
		if got := body["capabilities"].([]any); len(got) != 2 || got[0] != "rider" || got[1] != "driver" {
			t.Fatalf("persisted capabilities = %v", got)
		}
	})
	t.Run("profile updates belong to the bearer and persist across sessions", func(t *testing.T) {
		patch := func(bearer string, fields map[string]any) (int, map[string]any) {
			return call(http.MethodPatch, "me", bearer, fields)
		}
		status, body := patch("", map[string]any{"name": "Other"})
		expect(t, status, 401, body)
		for _, invalid := range []map[string]any{
			{}, {"name": "   "}, {"email": "not an email"}, {"name": "Other", "phone": "+923011234567"},
			{"name": "Other", "id": 2}, {"capabilities": []string{"driver"}},
		} {
			status, body = patch(access, invalid)
			expect(t, status, 400, body)
		}
		status, body = patch(access, map[string]any{"name": "  Updated Rider  ", "email": "rider@example.test"})
		expect(t, status, 200, body)
		if body["name"] != "Updated Rider" || body["email"] != "rider@example.test" || body["phone"] != phone {
			t.Fatalf("unexpected profile: %v", body)
		}
		status, body = post("login", credentials)
		expect(t, status, 200, body)
		secondAccess := body["access_token"].(string)
		status, body = call(http.MethodGet, "me", secondAccess, nil)
		expect(t, status, 200, body)
		if body["name"] != "Updated Rider" || body["email"] != "rider@example.test" {
			t.Fatalf("profile not visible from new session: %v", body)
		}
		status, body = patch(secondAccess, map[string]any{"email": ""})
		expect(t, status, 200, body)
		if body["name"] != "Updated Rider" || body["email"] != "" {
			t.Fatalf("clearing email changed other profile data: %v", body)
		}
		lock, err := isolated.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer lock.Rollback(ctx)
		if _, err := lock.Exec(ctx, "SELECT id FROM auth_users WHERE phone=$1 FOR UPDATE", phone); err != nil {
			t.Fatal(err)
		}
		var lockPID int32
		if err := lock.QueryRow(ctx, "SELECT pg_backend_pid()").Scan(&lockPID); err != nil {
			t.Fatal(err)
		}
		pending := make(chan response, 1)
		go func() {
			status, body := patch(secondAccess, map[string]any{"name": "Late write"})
			pending <- response{status, body}
		}()
		wait, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		for {
			var blocked bool
			if err := isolated.QueryRow(wait, `SELECT EXISTS (
 SELECT 1 FROM pg_stat_activity WHERE $1=ANY(pg_blocking_pids(pid)))`, lockPID).Scan(&blocked); err != nil {
				t.Fatal("profile update never waited for the account lock: ", err)
			}
			if blocked {
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		status, body = call(http.MethodPost, "auth/logout", secondAccess, nil)
		expect(t, status, 204, body)
		if err := lock.Rollback(ctx); err != nil {
			t.Fatal(err)
		}
		late := <-pending
		expect(t, late.status, 401, late.body)
		status, body = patch(secondAccess, map[string]any{"name": "Other"})
		expect(t, status, 401, body)
	})
	t.Run("email replacement stays pending and proof is account-bound and single-use", func(t *testing.T) {
		if len(emails) != 0 {
			t.Fatal("registration sent verification email")
		}
		var id int64
		if err := isolated.QueryRow(ctx, `SELECT id FROM auth_users WHERE phone=$1`, phone).Scan(&id); err != nil {
			t.Fatal(err)
		}
		resetCooldown := func() {
			if _, err := isolated.Exec(ctx, `DELETE FROM auth_rate_limits WHERE key=$1`, auth.HexDigestForTest("email/account/"+strconv.FormatInt(id, 10))); err != nil {
				t.Fatal(err)
			}
		}
		request := func(address, password string) (int, map[string]any) {
			return call(http.MethodPost, "me/email/request", access, map[string]string{"email": address, "password": password})
		}
		verify := func(token, code string) (int, map[string]any) {
			return call(http.MethodPost, "me/email/verify", token, map[string]string{"code": code})
		}
		status, body := request("first@example.test", "an incorrect password")
		expect(t, status, 400, body)
		status, body = request("first@example.test", credentials["password"])
		expect(t, status, 202, body)
		status, body = request("first@example.test", credentials["password"])
		expect(t, status, 429, body)
		status, body = verify(access, <-emails)
		expect(t, status, 200, body)
		if body["email_verified"] != true || body["email"] != "first@example.test" {
			t.Fatal("verification response missing profile", body)
		}
		status, body = call(http.MethodPatch, "me", access, map[string]string{"email": "bypass@example.test"})
		expect(t, status, 400, body)
		resetCooldown()
		status, body = request("next@example.test", credentials["password"])
		expect(t, status, 202, body)
		code := <-emails
		status, body = call(http.MethodGet, "me", access, nil)
		expect(t, status, 200, body)
		if body["email"] != "first@example.test" || body["pending_email"] != "next@example.test" || body["email_verified"] != true {
			t.Fatal("incorrect replacement state", body)
		}
		if _, err := isolated.Exec(ctx, `INSERT INTO auth_users (phone,name,password_hash) SELECT '+923081234567','Other',password_hash FROM auth_users WHERE id=$1`, id); err != nil {
			t.Fatal(err)
		}
		status, body = post("login", map[string]string{"phone": "+923081234567", "password": credentials["password"]})
		expect(t, status, 200, body)
		otherAccess := body["access_token"].(string)
		status, body = call(http.MethodGet, "me/driver-application", otherAccess, nil)
		expect(t, status, 200, body)
		if body["status"] != "draft" || body["draft"].(map[string]any)["revision"] != "0" {
			t.Fatal("another account's application was exposed", body)
		}
		status, body = call(http.MethodPost, "me/driver-application", otherAccess, map[string]string{"draft_revision": "5"})
		expect(t, status, 409, body)
		if _, err := isolated.Exec(ctx, `WITH draft AS (INSERT INTO driver_onboarding_applications(user_id,details,updated_at)
 SELECT id,'{"step":"2","legal_name":"Other Applicant"}',now()-interval '31 days'
 FROM auth_users WHERE phone='+923081234567' RETURNING user_id,application_version)
 INSERT INTO driver_onboarding_documents SELECT user_id,application_version,'selfie',decode(repeat('01',29),'hex') FROM draft`); err != nil {
			t.Fatal(err)
		}
		driverService.PurgeDocuments(ctx)
		status, body = call(http.MethodGet, "me/driver-application", otherAccess, nil)
		expect(t, status, 200, body)
		if draft := body["draft"].(map[string]any); len(body["documents"].([]any)) != 0 || draft["legal_name"] != "Other Applicant" || draft["revision"] != "2" {
			t.Fatal("cleanup failed to expire evidence without deleting draft details", body)
		}
		status, body = verify(otherAccess, code)
		expect(t, status, 400, body)
		if _, err := isolated.Exec(ctx, `UPDATE auth_email_challenges SET expires_at=now()-interval '1 second' WHERE user_id=$1`, id); err != nil {
			t.Fatal(err)
		}
		status, body = verify(access, code)
		expect(t, status, 400, body)
		resetCooldown()
		status, body = request("next@example.test", credentials["password"])
		expect(t, status, 202, body)
		code = <-emails
		results := make(chan int, 2)
		for range 2 {
			go func() { status, _ := verify(access, code); results <- status }()
		}
		a, b := <-results, <-results
		if !((a == 200 && b == 400) || (a == 400 && b == 200)) {
			t.Fatalf("concurrent verification statuses %d, %d", a, b)
		}
		status, body = verify(access, code)
		expect(t, status, 400, body)
		status, body = call(http.MethodGet, "me", access, nil)
		expect(t, status, 200, body)
		if body["email"] != "next@example.test" || body["pending_email"] != "" || body["email_verified"] != true {
			t.Fatal("replacement not applied", body)
		}
		resetCooldown()
		status, body = request("failed@example.test", credentials["password"])
		expect(t, status, 503, body)
		status, body = verify(access, <-emails)
		expect(t, status, 400, body)
		status, body = call(http.MethodGet, "me", access, nil)
		expect(t, status, 200, body)
		if body["email"] != "next@example.test" || body["pending_email"] != "" || body["email_verified"] != true {
			t.Fatal("failed delivery changed the trusted address or exposed a pending address", body)
		}
	})
	status, body = post("login", map[string]string{"phone": phone, "password": "an incorrect password"})
	expect(t, status, 401, body)
	if body["error"] != unknown["error"] {
		t.Fatal("login discloses account existence")
	}
	var group sync.WaitGroup
	results := make(chan response, 2)
	for range 2 {
		group.Add(1)
		go func() {
			defer group.Done()
			status, body := post("refresh", map[string]string{"refresh_token": refresh})
			results <- response{status, body}
		}()
	}
	group.Wait()
	rotated, replay := <-results, <-results
	if rotated.status != 200 {
		rotated, replay = replay, rotated
	}
	expect(t, rotated.status, 200, rotated.body)
	expect(t, replay.status, 401, replay.body)
	status, body = call(http.MethodGet, "me", rotated.body["access_token"].(string), nil)
	expect(t, status, 401, body)
	status, body = post("login", credentials)
	expect(t, status, 200, body)
	access = body["access_token"].(string)
	if _, err := isolated.Exec(ctx, "DELETE FROM auth_rate_limits WHERE key=$1", auth.HexDigestForTest("sms/phone/"+phone)); err != nil {
		t.Fatal(err)
	}
	status, body = post("recovery/request", map[string]string{"phone": phone})
	expect(t, status, 202, body)
	proof = map[string]string{"challenge": body["challenge"].(string), "code": receiveCode(t, body["challenge"].(string))}
	status, body = post("register/verify", proof)
	expect(t, status, 400, body)
	status, body = post("recovery/verify", proof)
	expect(t, status, 200, body)
	recovery := body["recovery_token"].(string)
	status, body = call(http.MethodGet, "me", recovery, nil)
	expect(t, status, 401, body)
	status, body = call(http.MethodPatch, "me", recovery, map[string]string{"name": "Other"})
	expect(t, status, 401, body)
	status, body = post("recovery/reset", map[string]string{"recovery_token": recovery, "password": newPassword})
	expect(t, status, 204, body)
	status, body = post("recovery/reset", map[string]string{"recovery_token": recovery, "password": oldPassword})
	expect(t, status, 400, body)
	status, body = call(http.MethodGet, "me", access, nil)
	expect(t, status, 401, body)
	credentials["password"] = newPassword
	status, body = post("login", credentials)
	expect(t, status, 200, body)
	access = body["access_token"].(string)
	status, body = call(http.MethodPost, "auth/logout", access, nil)
	expect(t, status, 204, body)
	status, body = call(http.MethodGet, "me", access, nil)
	expect(t, status, 401, body)
	t.Run("expired and exhausted challenges", func(t *testing.T) {
		cases := []struct {
			phone  string
			expire bool
		}{{"+923011234567", true}, {"+923021234567", false}}
		for _, scenario := range cases {
			status, body := post("register", map[string]string{"phone": scenario.phone, "password": oldPassword, "name": "Other Rider"})
			expect(t, status, 202, body)
			challenge := body["challenge"].(string)
			code := receiveCode(t, challenge)
			if scenario.expire {
				if _, err := isolated.Exec(ctx, "UPDATE auth_challenges SET expires_at=now()-interval '1 second' WHERE id=$1", auth.TokenDigestForTest(challenge, "oc_")); err != nil {
					t.Fatal(err)
				}
			} else {
				wrong := "000000"
				if code == wrong {
					wrong = "000001"
				}
				for range 5 {
					status, body = post("register/verify", map[string]string{"challenge": challenge, "code": wrong})
					expect(t, status, 400, body)
				}
			}
			status, body = post("register/verify", map[string]string{"challenge": challenge, "code": code})
			expect(t, status, 400, body)
			status, body = post("login", map[string]string{"phone": scenario.phone, "password": oldPassword})
			expect(t, status, 401, body)
		}
	})

	t.Run("login throttle and access expiry", func(t *testing.T) {
		status, body := post("login", credentials)
		expect(t, status, 200, body)
		access := body["access_token"].(string)
		if _, err := isolated.Exec(ctx, "UPDATE auth_sessions SET access_expires_at=now()-interval '1 second' WHERE access_digest=$1", auth.TokenDigestForTest(access, "at_")); err != nil {
			t.Fatal(err)
		}
		status, body = call(http.MethodGet, "me", access, nil)
		expect(t, status, 401, body)
		status, body = call(http.MethodPatch, "me", access, map[string]string{"name": "Other"})
		expect(t, status, 401, body)
		for range 10 {
			status, body = post("login", map[string]string{"phone": "+923091234567", "password": oldPassword})
			expect(t, status, 401, body)
		}
		status, body = post("login", map[string]string{"phone": "+923091234567", "password": oldPassword})
		expect(t, status, 429, body)
	})
	t.Run("cooldown denials preserve the issuance budget", func(t *testing.T) {
		number := "+923051234567"
		credentials := map[string]string{"phone": number, "password": oldPassword, "name": "Other Rider"}
		status, body := post("register", credentials)
		expect(t, status, 202, body)
		receiveCode(t, body["challenge"].(string))
		for range 5 {
			status, body = post("register", credentials)
			expect(t, status, 429, body)
		}
		if _, err := isolated.Exec(ctx, "DELETE FROM auth_rate_limits WHERE key=$1", auth.HexDigestForTest("sms/phone/"+number)); err != nil {
			t.Fatal(err)
		}
		status, body = post("register", credentials)
		expect(t, status, 202, body)
		receiveCode(t, body["challenge"].(string))
	})
	t.Run("refresh advertises the remaining access lifetime", func(t *testing.T) {
		status, body := post("login", credentials)
		expect(t, status, 200, body)
		if _, err := isolated.Exec(ctx, "UPDATE auth_sessions SET expires_at=now()+interval '30 seconds' WHERE access_digest=$1", auth.TokenDigestForTest(body["access_token"].(string), "at_")); err != nil {
			t.Fatal(err)
		}
		status, body = post("refresh", map[string]string{"refresh_token": body["refresh_token"].(string)})
		expect(t, status, 200, body)
		if expires := body["expires_in"].(float64); expires < 25 || expires > 30 {
			t.Fatalf("expires_in = %v", expires)
		}
	})
	t.Run("registration rolls back if session persistence fails", func(t *testing.T) {
		peer = "192.0.2.2:12345"
		number := "+923061234567"
		status, body := post("register", map[string]string{"phone": number, "password": oldPassword, "name": "Rollback Rider"})
		expect(t, status, 202, body)
		challenge := body["challenge"].(string)
		code := receiveCode(t, challenge)
		if _, err := isolated.Exec(ctx, "ALTER TABLE auth_sessions ADD CHECK (id < 0) NOT VALID"); err != nil {
			t.Fatal(err)
		}
		status, body = post("register/verify", map[string]string{"challenge": challenge, "code": code})
		expect(t, status, 500, body)
		if _, err := isolated.Exec(ctx, "ALTER TABLE auth_sessions DROP CONSTRAINT auth_sessions_id_check"); err != nil {
			t.Fatal(err)
		}
		status, body = post("login", map[string]string{"phone": number, "password": oldPassword})
		expect(t, status, 401, body)
		status, body = post("register/verify", map[string]string{"challenge": challenge, "code": code})
		expect(t, status, 201, body)
		status, body = call(http.MethodPatch, "me", body["access_token"].(string), map[string]string{"name": "Second Rider"})
		expect(t, status, 200, body)
		if body["name"] != "Second Rider" || body["phone"] != number {
			t.Fatalf("unexpected second account profile: %v", body)
		}
		var firstName string
		if err := isolated.QueryRow(ctx, "SELECT name FROM auth_users WHERE phone=$1", phone).Scan(&firstName); err != nil || firstName != "Updated Rider" {
			t.Fatalf("first account changed: %q (%v)", firstName, err)
		}
	})

	t.Run("a stalled SMS does not delay another recipient", func(t *testing.T) {
		const other = "+923061234567"
		if _, err := isolated.Exec(ctx, "DELETE FROM auth_rate_limits WHERE key IN ($1,$2)", auth.HexDigestForTest("sms/phone/"+phone), auth.HexDigestForTest("sms/phone/"+other)); err != nil {
			t.Fatal(err)
		}
		sms.stall.Store(true)
		status, body := post("recovery/request", map[string]string{"phone": phone})
		expect(t, status, 202, body)
		select {
		case <-sms.started:
		case <-time.After(3 * time.Second):
			t.Fatal("first delivery never started")
		}
		status, body = post("recovery/request", map[string]string{"phone": other})
		expect(t, status, 202, body)
		receiveCode(t, body["challenge"].(string))
	})

	t.Run("SMS overload preserves the phone cooldown", func(t *testing.T) {
		phone := map[string]string{"phone": "+923071234567"}
		release := server.SaturateSMSForTest()
		status, body := post("recovery/request", phone)
		release()
		expect(t, status, 503, body)
		status, body = post("recovery/request", phone)
		expect(t, status, 202, body)
	})
}

func TestOnboardingHasNoAdministrativeOrLegacyRoutes(t *testing.T) {
	handler := httpapi.Handler(&auth.Server{}, &driver.Service{})
	for _, path := range []string{"/admin/", "/admin/app.mjs", "/api/v1/admin/onboarding", "/api/v1/admin/onboarding/document",
		"/api/v1/admin/onboarding/decision", "/api/v1/admin/auth/login", "/api/v1/admin/audit", "/api/v1/me/driver-submission", "/api/v1/me/vehicles"} {
		for _, method := range []string{http.MethodGet, http.MethodPost, http.MethodPatch} {
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, httptest.NewRequest(method, path, nil))
			if recorder.Code != 404 {
				t.Errorf("%s %s: %d", method, path, recorder.Code)
			}
		}
	}
}

func TestHTTPMethods(t *testing.T) {
	handler := httpapi.Handler(&auth.Server{}, &driver.Service{})
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/auth/login", nil))
	if recorder.Code != http.StatusMethodNotAllowed || recorder.Header().Get("Allow") != http.MethodPost {
		t.Fatalf("wrong-method response = %d, Allow = %q", recorder.Code, recorder.Header().Get("Allow"))
	}

	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodHead, "/healthz", nil))
	if recorder.Code != http.StatusNoContent || recorder.Body.Len() != 0 {
		t.Fatalf("HEAD /healthz = %d %s", recorder.Code, recorder.Body)
	}
}
