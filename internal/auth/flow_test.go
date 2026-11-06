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
	t.Run("driver identity submissions are authenticated and versioned", func(t *testing.T) {
		var imageBytes bytes.Buffer
		if err := png.Encode(&imageBytes, image.NewRGBA(image.Rect(0, 0, 2, 2))); err != nil {
			t.Fatal(err)
		}
		payload := map[string]any{"legal_name": "Example Driver", "cnic_front": imageBytes.Bytes(), "cnic_back": imageBytes.Bytes()}
		status, body := call(http.MethodPost, "me/driver-submission", "", payload)
		expect(t, status, 401, body)
		status, body = call(http.MethodGet, "me/driver-submission", access, nil)
		expect(t, status, 200, body)
		if body["status"] != "not_submitted" {
			t.Fatal(body)
		}
		payload["cnic_back"] = []byte("not an image")
		status, body = call(http.MethodPost, "me/driver-submission", access, payload)
		expect(t, status, 400, body)
		payload["cnic_back"] = imageBytes.Bytes()
		payload["approved"] = true
		status, body = call(http.MethodPost, "me/driver-submission", access, payload)
		expect(t, status, 400, body)
		delete(payload, "approved")
		for version := 1; version <= 2; version++ {
			status, body = call(http.MethodPost, "me/driver-submission", access, payload)
			expect(t, status, 201, body)
			if body["status"] != "submitted" || body["version"] != float64(version) || body["cnic_front"] != nil {
				t.Fatal(body)
			}
		}
		status, body = call(http.MethodGet, "me/driver-submission", access, nil)
		expect(t, status, 200, body)
		if body["version"] != float64(2) {
			t.Fatal(body)
		}
		versions := make(chan response, 2)
		for range 2 {
			go func() {
				status, body := call(http.MethodPost, "me/driver-submission", access, payload)
				versions <- response{status, body}
			}()
		}
		first, second := <-versions, <-versions
		if first.status == 503 {
			first.status, first.body = call(http.MethodPost, "me/driver-submission", access, payload)
		}
		if second.status == 503 {
			second.status, second.body = call(http.MethodPost, "me/driver-submission", access, payload)
		}
		expect(t, first.status, 201, first.body)
		expect(t, second.status, 201, second.body)
		if first.body["version"] == second.body["version"] {
			t.Fatal("concurrent submissions reused a version")
		}
		var encrypted []byte
		if err := isolated.QueryRow(ctx, `SELECT d.cnic_front FROM driver_identity_submissions d JOIN auth_users u ON u.id=d.user_id WHERE u.phone=$1 AND d.version=1`, phone).Scan(&encrypted); err != nil {
			t.Fatal(err)
		}
		if bytes.HasPrefix(encrypted, imageBytes.Bytes()[:8]) {
			t.Fatal("document stored as plaintext")
		}
		status, body = call(http.MethodGet, "me", access, nil)
		expect(t, status, 200, body)
		if capabilities := body["capabilities"].([]any); len(capabilities) != 1 || capabilities[0] != "rider" {
			t.Fatal("submission changed membership", body)
		}
		previousPeer := peer
		peer = "192.0.2.99:12345"
		defer func() { peer = previousPeer }()
		payload["cnic_front"] = make([]byte, maxDriverImage+1)
		status, body = call(http.MethodPost, "me/driver-submission", access, payload)
		expect(t, status, 413, body)
		if body["error"] != "document_too_large" {
			t.Fatal(body)
		}
		if _, err := isolated.Exec(ctx, `UPDATE driver_identity_submissions SET submitted_at=now()-interval '31 days'`); err != nil {
			t.Fatal(err)
		}
		if _, err := isolated.Exec(ctx, purgeSupersededDriverDocuments); err != nil {
			t.Fatal(err)
		}
		var versionsLeft, imagesLeft int
		if err := isolated.QueryRow(ctx, `SELECT count(*),count(cnic_front) FROM driver_identity_submissions`).Scan(&versionsLeft, &imagesLeft); err != nil {
			t.Fatal(err)
		}
		if versionsLeft != 4 || imagesLeft != 1 {
			t.Fatalf("cleanup kept %d versions and %d document pairs", versionsLeft, imagesLeft)
		}
		payload["cnic_back"] = make([]byte, 2*maxDriverImage)
		status, body = call(http.MethodPost, "me/driver-submission", access, payload)
		expect(t, status, 413, body)
		if body["error"] != "document_too_large" {
			t.Fatal(body)
		}
	})
	if body["email"] != "signup@example.test" || body["email_verified"] != false || body["pending_email"] != "" || len(emails) != 0 {
		t.Fatal("registration must store email unverified without sending", body)
	}
	var vehicleID string
	var vehiclePayload map[string]any
	t.Run("vehicle submissions persist versions without granting approval", func(t *testing.T) {
		var picture bytes.Buffer
		if err := png.Encode(&picture, image.NewRGBA(image.Rect(0, 0, 2, 2))); err != nil {
			t.Fatal(err)
		}
		payload := map[string]any{"make": "Toyota", "model": "Corolla", "color": "White", "manufacture_year": "2022", "registration_number": "ABC-123", "registration_image": picture.Bytes(), "insurance_image": picture.Bytes()}
		status, body := call(http.MethodPost, "me/vehicles", "", payload)
		expect(t, status, 401, body)
		payload["registration_image"] = make([]byte, maxVehicleDocument+1)
		status, body = call(http.MethodPost, "me/vehicles", access, payload)
		expect(t, status, 413, body)
		payload["insurance_image"] = make([]byte, 3*maxVehicleDocument)
		status, body = call(http.MethodPost, "me/vehicles", access, payload)
		expect(t, status, 413, body)
		payload["registration_image"] = picture.Bytes()
		payload["insurance_image"] = picture.Bytes()
		status, body = call(http.MethodPost, "me/vehicles", access, payload)
		expect(t, status, 201, body)
		if body["status"] != "submitted" || body["version"] != float64(1) || body["registration_image"] != nil {
			t.Fatal(body)
		}
		vehicleID = strconv.FormatInt(int64(body["vehicle_id"].(float64)), 10)
		payload["vehicle_id"] = vehicleID
		payload["color"] = "Blue"
		vehiclePayload = payload
		versions := make(chan response, 2)
		for range 2 {
			go func() {
				status, body := call(http.MethodPost, "me/vehicles", access, payload)
				versions <- response{status, body}
			}()
		}
		a, b := <-versions, <-versions
		if a.status == 503 {
			a.status, a.body = call(http.MethodPost, "me/vehicles", access, payload)
		}
		if b.status == 503 {
			b.status, b.body = call(http.MethodPost, "me/vehicles", access, payload)
		}
		expect(t, a.status, 201, a.body)
		expect(t, b.status, 201, b.body)
		if a.body["version"] == b.body["version"] {
			t.Fatal("concurrent revisions reused a version")
		}
		status, body = call(http.MethodGet, "me/vehicles", access, nil)
		expect(t, status, 200, body)
		latest := body["vehicles"].([]any)
		if len(latest) != 1 || latest[0].(map[string]any)["version"] != float64(3) {
			t.Fatal(body)
		}
		for range cap(server.vehicleUploadSlots) {
			server.vehicleUploadSlots <- struct{}{}
		}
		status, body = call(http.MethodPost, "me/vehicles", access, payload)
		blocked := response{status, body}
		status, body = call(http.MethodPost, "me/driver-submission", access, map[string]any{"legal_name": "Driver"})
		for range cap(server.vehicleUploadSlots) {
			<-server.vehicleUploadSlots
		}
		expect(t, blocked.status, 503, blocked.body)
		expect(t, status, 400, body)
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
		status, body = call(http.MethodGet, "me/vehicles", otherAccess, nil)
		expect(t, status, 200, body)
		if vehicleID == "" || len(body["vehicles"].([]any)) != 0 {
			t.Fatal("another account's vehicle was exposed", body)
		}
		status, body = call(http.MethodGet, "me/driver-submission", otherAccess, nil)
		expect(t, status, 200, body)
		if body["status"] != "not_submitted" {
			t.Fatal("another account's submission was exposed", body)
		}
		status, body = call(http.MethodPost, "me/vehicles", otherAccess, vehiclePayload)
		expect(t, status, 409, body)
		if body["error"] != "driver_identity_required" {
			t.Fatal(body)
		}
		if _, err := isolated.Exec(ctx, `INSERT INTO driver_identity_submissions(user_id,version,legal_name)
 SELECT id,1,'Other Driver' FROM auth_users WHERE phone='+923081234567'`); err != nil {
			t.Fatal(err)
		}
		status, body = call(http.MethodPost, "me/vehicles", otherAccess, vehiclePayload)
		expect(t, status, 404, body)
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

	t.Run("application submission binds exact owned versions and reflects both checks", func(t *testing.T) {
		status, body := post("login", credentials)
		expect(t, status, 200, body)
		owner := body["access_token"].(string)
		otherPhone := "+923061234567"
		status, body = post("login", map[string]string{"phone": otherPhone, "password": oldPassword})
		expect(t, status, 200, body)
		other := body["access_token"].(string)
		const path = "me/driver-application"
		status, body = call(http.MethodPatch, path, owner, map[string]string{"legal_name": "Draft Driver", "step": "1"})
		expect(t, status, 200, body)
		status, body = call(http.MethodGet, path, owner, nil)
		expect(t, status, 200, body)
		if body["status"] != "draft" || body["draft"].(map[string]any)["legal_name"] != "Draft Driver" {
			t.Fatal(body)
		}
		status, body = call(http.MethodGet, path, other, nil)
		expect(t, status, 200, body)
		if len(body["draft"].(map[string]any)) != 0 {
			t.Fatal("another account's draft leaked", body)
		}
		var applications int
		if err := isolated.QueryRow(ctx, `SELECT count(*) FROM driver_applications`).Scan(&applications); err != nil || applications != 0 {
			t.Fatalf("upload entered review: %d %v", applications, err)
		}
		binding := map[string]any{"identity_version": 4, "vehicle_id": vehicleID, "vehicle_version": 3}
		status, body = call(http.MethodPost, path, other, binding)
		expect(t, status, 409, body)
		binding["identity_version"] = 3
		status, body = call(http.MethodPost, path, owner, binding)
		expect(t, status, 409, body)
		binding["identity_version"] = 4
		results := make(chan response, 2)
		for range 2 {
			go func() {
				status, body := call(http.MethodPost, path, owner, binding)
				results <- response{status, body}
			}()
		}
		for range 2 {
			result := <-results
			expect(t, result.status, 200, result.body)
			if result.body["status"] != "under_review" || result.body["draft"].(map[string]any)["step"] != nil {
				t.Fatal(result.body)
			}
		}
		var id int64
		if err := isolated.QueryRow(ctx, `SELECT id FROM driver_applications`).Scan(&id); err != nil {
			t.Fatal(err)
		}
		if err := isolated.QueryRow(ctx, `SELECT count(*) FROM driver_applications`).Scan(&applications); err != nil || applications != 1 {
			t.Fatalf("final submission duplicated: %d %v", applications, err)
		}
		check := func(kind, decision, reason string) {
			t.Helper()
			if _, err := isolated.Exec(ctx, `INSERT INTO driver_application_checks(application_id,kind,decision,reason,reviewer_id)
 SELECT $1,$2,$3,$4,id FROM auth_users WHERE phone=$5`, id, kind, decision, reason, otherPhone); err != nil {
				t.Fatal(err)
			}
		}
		check("identity", "approved", "")
		status, body = call(http.MethodGet, path, owner, nil)
		expect(t, status, 200, body)
		if body["status"] != "under_review" {
			t.Fatal(body)
		}
		check("vehicle", "rejected", "Replace the vehicle image")
		status, body = call(http.MethodGet, path, owner, nil)
		expect(t, status, 200, body)
		if body["status"] != "rejected" || body["reason"] != "Replace the vehicle image" {
			t.Fatal(body)
		}
		var picture bytes.Buffer
		if err := png.Encode(&picture, image.NewRGBA(image.Rect(0, 0, 2, 2))); err != nil {
			t.Fatal(err)
		}
		status, body = call(http.MethodPost, "me/driver-submission", owner, map[string]any{"legal_name": "Revised Driver", "cnic_front": picture.Bytes(), "cnic_back": picture.Bytes()})
		expect(t, status, 201, body)
		binding["identity_version"] = 5
		status, body = call(http.MethodPost, path, owner, binding)
		expect(t, status, 409, body) // Revising identity cannot requeue a rejected vehicle version.
		status, body = call(http.MethodPost, "me/vehicles", owner, map[string]any{"vehicle_id": vehicleID, "make": "Test", "model": "Car", "manufacture_year": "2020", "color": "Black", "registration_number": "ABC-123", "registration_image": picture.Bytes(), "insurance_image": picture.Bytes()})
		expect(t, status, 201, body)
		binding["vehicle_version"] = body["version"]
		status, body = call(http.MethodPost, path, owner, binding)
		expect(t, status, 200, body)
		if body["status"] != "under_review" {
			t.Fatal(body)
		}
		if err := isolated.QueryRow(ctx, `SELECT id FROM current_driver_applications`).Scan(&id); err != nil {
			t.Fatal(err)
		}
		check("vehicle", "approved", "")
		status, body = call(http.MethodGet, path, owner, nil)
		expect(t, status, 200, body)
		if body["status"] != "under_review" {
			t.Fatal("new application inherited old identity approval", body)
		}
		check("identity", "approved", "")
		status, body = call(http.MethodGet, path, owner, nil)
		expect(t, status, 200, body)
		if body["status"] != "approved" {
			t.Fatal(body)
		}
		status, body = call(http.MethodGet, "me", owner, nil)
		expect(t, status, 200, body)
		if caps := body["capabilities"].([]any); len(caps) != 1 || caps[0] != "rider" {
			t.Fatal("approval granted membership", body)
		}
	})
}

func TestCoreDoesNotServeAdminOperations(t *testing.T) {
	handler := (&Server{}).Handler()
	for _, path := range []string{"/admin/", "/admin/app.mjs", "/api/v1/admin/auth/login", "/api/v1/admin/onboarding",
		"/api/v1/admin/onboarding/document", "/api/v1/admin/onboarding/decision", "/api/v1/admin/audit"} {
		for _, method := range []string{http.MethodGet, http.MethodPost} {
			res := httptest.NewRecorder()
			handler.ServeHTTP(res, httptest.NewRequest(method, path, nil))
			if res.Code != http.StatusNotFound {
				t.Errorf("%s %s returned %d", method, path, res.Code)
			}
		}
	}
}
