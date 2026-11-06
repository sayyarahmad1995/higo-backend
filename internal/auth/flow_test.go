package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
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
	server, err := New(ctx, isolated, sms, Config{OTPKey: bytes.Repeat([]byte{7}, 32), PasswordMemory: 19456, PasswordPasses: 2})
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
	credentials := map[string]string{"phone": phone, "password": oldPassword, "name": "Test Rider"}
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
