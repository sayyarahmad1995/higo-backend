package auth

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
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
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
	schema, err := newToken("")
	if err != nil {
		t.Fatal(err)
	}
	schema = "test_" + hexDigest(schema)[:16]
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
	server, err := New(ctx, isolated, sms, Config{DriverDocumentKey: bytes.Repeat([]byte{8}, 32), EmailSender: emails, OTPKey: bytes.Repeat([]byte{7}, 32), PasswordMemory: 19456, PasswordPasses: 2})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	handler := server.Handler()
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
				err := isolated.QueryRow(ctx, "SELECT delivered FROM auth_challenges WHERE id=$1", tokenDigest(challenge, "oc_")).Scan(&delivered)
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
	t.Run("unified onboarding is resumable, bounded and immutable on submission", func(t *testing.T) {
		const path = "me/driver-application"
		identityPath, vehiclePath := path+"/identity-documents", path+"/vehicle-documents"
		get := func(token string) map[string]any {
			t.Helper()
			status, body := call(http.MethodGet, path, token, nil)
			expect(t, status, 200, body)
			return body
		}
		draftOf := func(body map[string]any) map[string]any { return body["draft"].(map[string]any) }
		status, body := call(http.MethodGet, path, "", nil)
		expect(t, status, 401, body)
		if draftOf(get(access))["revision"] != "0" {
			t.Fatal("unexpected draft")
		}
		fields := map[string]string{"step": "1", "revision": "0"}
		status, body = call(http.MethodPatch, path, access, fields)
		expect(t, status, 409, body)
		fields["legal_name"] = "Example Driver"
		status, body = call(http.MethodPatch, path, access, fields)
		expect(t, status, 200, body)
		fields["revision"] = "1"
		fields["step"] = "2"
		status, body = call(http.MethodPatch, path, access, fields)
		expect(t, status, 409, body)
		fields["make"], fields["model"], fields["manufacture_year"], fields["color"], fields["registration_number"] = "Test", "Car", "2020", "Black", "abc-123"
		results := make(chan response, 2)
		for range 2 {
			go func() {
				status, body := call(http.MethodPatch, path, access, fields)
				results <- response{status, body}
			}()
		}
		a, b := <-results, <-results
		if !((a.status == 200 && b.status == 409) || (a.status == 409 && b.status == 200)) {
			t.Fatalf("draft race %v %v", a, b)
		}
		var picture bytes.Buffer
		if err := png.Encode(&picture, image.NewRGBA(image.Rect(0, 0, 2, 2))); err != nil {
			t.Fatal(err)
		}
		identity := map[string]any{"draft_revision": "2", "cnic_front": picture.Bytes(), "cnic_back": picture.Bytes()}
		status, body = call(http.MethodPost, identityPath, "", identity)
		expect(t, status, 401, body)
		identity["cnic_front"] = []byte("bad image")
		status, body = call(http.MethodPost, identityPath, access, identity)
		expect(t, status, 400, body)
		identity["cnic_front"] = make([]byte, maxDriverImage+1)
		status, body = call(http.MethodPost, identityPath, access, identity)
		expect(t, status, 413, body)
		identity["cnic_back"] = make([]byte, 2*maxDriverImage)
		status, body = call(http.MethodPost, identityPath, access, identity)
		expect(t, status, 413, body)
		identity["cnic_front"], identity["cnic_back"] = picture.Bytes(), picture.Bytes()
		status, body = call(http.MethodPost, identityPath, access, identity)
		expect(t, status, 200, body)
		if draft := draftOf(body); draft["identity_saved"] != "true" || draft["revision"] != "3" {
			t.Fatal(body)
		}
		status, body = call(http.MethodPost, path, access, map[string]string{"draft_revision": "3"})
		expect(t, status, 409, body)
		status, body = post("login", credentials)
		expect(t, status, 200, body)
		restored := body["access_token"].(string)
		if draft := draftOf(get(restored)); draft["identity_saved"] != "true" || draft["registration_number"] != "ABC-123" {
			t.Fatal(draft)
		}
		vehicle := map[string]any{"draft_revision": "3", "registration_image": picture.Bytes(), "insurance_image": picture.Bytes()}
		for range cap(server.vehicleUploadSlots) {
			server.vehicleUploadSlots <- struct{}{}
		}
		status, body = call(http.MethodPost, vehiclePath, restored, vehicle)
		for range cap(server.vehicleUploadSlots) {
			<-server.vehicleUploadSlots
		}
		expect(t, status, 503, body)
		vehicle["insurance_image"] = make([]byte, maxVehicleDocument+1)
		status, body = call(http.MethodPost, vehiclePath, restored, vehicle)
		expect(t, status, 413, body)
		vehicle["insurance_image"] = picture.Bytes()
		status, body = call(http.MethodPost, vehiclePath, restored, vehicle)
		expect(t, status, 200, body)
		fields["step"], fields["revision"], fields["registration_number"] = "3", "4", "ABC-123"
		status, body = call(http.MethodPatch, path, restored, fields)
		expect(t, status, 200, body)
		final := map[string]string{"draft_revision": "5"}
		for range 2 {
			go func() {
				status, body := call(http.MethodPost, path, restored, final)
				results <- response{status, body}
			}()
		}
		for range 2 {
			result := <-results
			expect(t, result.status, 200, result.body)
			if result.body["status"] != "under_review" || result.body["application_version"] != float64(1) || result.body["submitted_at"] == nil {
				t.Fatal(result.body)
			}
		}
		fields["revision"], fields["legal_name"] = "5", "Attempted Rewrite"
		status, body = call(http.MethodPatch, path, restored, fields)
		expect(t, status, 409, body)
		identity["draft_revision"] = "5"
		status, body = call(http.MethodPost, identityPath, restored, identity)
		expect(t, status, 409, body)
		if result := get(restored); result["status"] != "under_review" || draftOf(result)["legal_name"] != "Example Driver" {
			t.Fatal(result)
		}
		var encrypted []byte
		var applications int
		if err := isolated.QueryRow(ctx, `SELECT count(*) FROM driver_onboarding_applications`).Scan(&applications); err != nil || applications != 1 {
			t.Fatalf("application count %d: %v", applications, err)
		}
		if err := isolated.QueryRow(ctx, `SELECT cnic_front FROM driver_onboarding_applications`).Scan(&encrypted); err != nil || len(encrypted) == 0 || bytes.HasPrefix(encrypted, picture.Bytes()[:8]) {
			t.Fatalf("invalid encrypted image: %v", err)
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
			if _, err := isolated.Exec(ctx, `DELETE FROM auth_rate_limits WHERE key=$1`, hexDigest("email/account/"+strconv.FormatInt(id, 10))); err != nil {
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
		if _, err := isolated.Exec(ctx, `INSERT INTO driver_onboarding_applications(user_id,details,cnic_front,cnic_back,updated_at)
 SELECT id,'{"step":"2","legal_name":"Other Applicant"}',decode('01','hex'),decode('01','hex'),now()-interval '31 days'
 FROM auth_users WHERE phone='+923081234567'`); err != nil {
			t.Fatal(err)
		}
		if _, err := isolated.Exec(ctx, purgeAbandonedOnboardingDocuments); err != nil {
			t.Fatal(err)
		}
		status, body = call(http.MethodGet, "me/driver-application", otherAccess, nil)
		expect(t, status, 200, body)
		if draft := body["draft"].(map[string]any); draft["identity_saved"] != nil || draft["legal_name"] != "Other Applicant" || draft["revision"] != "2" {
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
	if _, err := isolated.Exec(ctx, "DELETE FROM auth_rate_limits WHERE key=$1", hexDigest("sms/phone/"+phone)); err != nil {
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
				if _, err := isolated.Exec(ctx, "UPDATE auth_challenges SET expires_at=now()-interval '1 second' WHERE id=$1", tokenDigest(challenge, "oc_")); err != nil {
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
		if _, err := isolated.Exec(ctx, "UPDATE auth_sessions SET access_expires_at=now()-interval '1 second' WHERE access_digest=$1", tokenDigest(access, "at_")); err != nil {
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
		if _, err := isolated.Exec(ctx, "DELETE FROM auth_rate_limits WHERE key=$1", hexDigest("sms/phone/"+number)); err != nil {
			t.Fatal(err)
		}
		status, body = post("register", credentials)
		expect(t, status, 202, body)
		receiveCode(t, body["challenge"].(string))
	})
	t.Run("refresh advertises the remaining access lifetime", func(t *testing.T) {
		status, body := post("login", credentials)
		expect(t, status, 200, body)
		if _, err := isolated.Exec(ctx, "UPDATE auth_sessions SET expires_at=now()+interval '30 seconds' WHERE access_digest=$1", tokenDigest(body["access_token"].(string), "at_")); err != nil {
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
		if _, err := isolated.Exec(ctx, "DELETE FROM auth_rate_limits WHERE key IN ($1,$2)", hexDigest("sms/phone/"+phone), hexDigest("sms/phone/"+other)); err != nil {
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
		added := cap(server.smsSlots) - len(server.smsSlots)
		for range added {
			server.smsSlots <- struct{}{}
		}
		status, body := post("recovery/request", phone)
		for range added {
			<-server.smsSlots
		}
		expect(t, status, 503, body)
		status, body = post("recovery/request", phone)
		expect(t, status, 202, body)
	})
}

func TestOnboardingHasNoAdministrativeOrLegacyRoutes(t *testing.T) {
	handler := (&Server{}).Handler()
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
