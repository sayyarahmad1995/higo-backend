package auth_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/sayyarahmad1995/higo-backend/internal/auth"
)

type emailGate struct {
	address string
	code    chan string
	resume  chan struct{}
}

type gatedEmail struct {
	testEmail
	gate atomic.Pointer[emailGate]
}

func (s *gatedEmail) Send(ctx context.Context, address, code string) error {
	if gate := s.gate.Load(); gate != nil && gate.address == address {
		gate.code <- code
		select {
		case <-gate.resume:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return s.testEmail.Send(ctx, address, code)
}

func testAccountBoundaries(t *testing.T, db *pgxpool.Pool, handler http.Handler, server *auth.Server, sender *gatedEmail, sourcePhone, password string) {
	t.Helper()
	ctx := t.Context()
	const phone = "+923121234567"
	var id int64
	if err := db.QueryRow(ctx, `INSERT INTO auth_users(phone,name,password_hash)
 SELECT $1,'Account fixture',password_hash FROM auth_users WHERE phone=$2 RETURNING id`, phone, sourcePhone).Scan(&id); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := db.Exec(context.Background(), "DELETE FROM auth_users WHERE id=$1", id); err != nil {
			t.Error(err)
		}
	})
	send := func(ctx context.Context, method, path, bearer string, body map[string]any) *httptest.ResponseRecorder {
		payload, _ := json.Marshal(body)
		req := httptest.NewRequestWithContext(ctx, method, "/api/v1/"+path, bytes.NewReader(payload))
		req.RemoteAddr = "192.0.2.51:12345"
		req.Header.Set("Authorization", "Bearer "+bearer)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, req)
		return response
	}
	expect := func(t *testing.T, response *httptest.ResponseRecorder, status int, code string) {
		t.Helper()
		if response.Code != status || (code != "" && response.Body.String() != fmt.Sprintf("{\"error\":%q}\n", code)) {
			t.Fatalf("response = %d %s, want %d %s", response.Code, response.Body, status, code)
		}
	}
	login := func(t *testing.T, password string) string {
		t.Helper()
		response := send(ctx, http.MethodPost, "auth/login", "", map[string]any{"phone": phone, "password": password})
		expect(t, response, 200, "")
		var result struct {
			Access string `json:"access_token"`
		}
		if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil || result.Access == "" {
			t.Fatalf("missing access token: %v", err)
		}
		return result.Access
	}
	exec := func(t *testing.T, sql string, args ...any) {
		t.Helper()
		if _, err := db.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	cooldownKey := auth.HexDigestForTest("email/account/" + strconv.FormatInt(id, 10))
	resetCooldown := func(t *testing.T) {
		t.Helper()
		exec(t, "DELETE FROM auth_rate_limits WHERE key=$1", cooldownKey)
	}
	emailRequest := func(ctx context.Context, bearer, address string) *httptest.ResponseRecorder {
		// The current email decoder accepts other fields from the shared Auth input.
		return send(ctx, http.MethodPost, "me/email/request", bearer, map[string]any{
			"email": address, "password": password, "name": "Ignored",
		})
	}
	verify := func(bearer, code string) *httptest.ResponseRecorder {
		return send(ctx, http.MethodPost, "me/email/verify", bearer, map[string]any{"code": code, "email": "ignored@example.test"})
	}
	patchEmail := func(bearer, address string) *httptest.ResponseRecorder {
		return send(ctx, http.MethodPatch, "me", bearer, map[string]any{"email": address, "name": nil})
	}
	expectProfile := func(t *testing.T, bearer, email, pending string, verified bool) {
		t.Helper()
		response := send(ctx, http.MethodGet, "me", bearer, nil)
		expect(t, response, 200, "")
		var actual map[string]any
		if err := json.Unmarshal(response.Body.Bytes(), &actual); err != nil {
			t.Fatal(err)
		}
		if len(actual) != 7 || actual["id"] != float64(id) || actual["phone"] != phone ||
			actual["name"] != "Account fixture" || actual["email"] != email ||
			actual["pending_email"] != pending || actual["email_verified"] != verified ||
			fmt.Sprint(actual["capabilities"]) != "[rider]" {
			t.Fatalf("unexpected account projection: %s", response.Body)
		}
	}
	issue := func(t *testing.T, bearer, address string) string {
		t.Helper()
		resetCooldown(t)
		expect(t, emailRequest(ctx, bearer, address), 202, "")
		select {
		case code := <-sender.testEmail:
			return code
		case <-time.After(3 * time.Second):
			t.Fatal("provider did not receive an email code")
			return ""
		}
	}
	blockedDelivery := func(t *testing.T, bearer, address string, intervene func(string), status int, outcome string) {
		t.Helper()
		resetCooldown(t)
		requestCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
		gate := &emailGate{address: address, code: make(chan string, 1), resume: make(chan struct{})}
		sender.gate.Store(gate)
		done := make(chan struct{})
		var response *httptest.ResponseRecorder
		go func() {
			defer close(done)
			response = emailRequest(requestCtx, bearer, address)
		}()
		defer func() {
			cancel()
			<-done
			sender.gate.Store(nil)
		}()
		select {
		case code := <-gate.code:
			intervene(code)
		case <-requestCtx.Done():
			t.Fatal("email request did not reach provider")
		}
		close(gate.resume)
		<-done
		expect(t, response, status, outcome)
	}

	access := login(t, password)
	t.Run("profile response and bearer errors", func(t *testing.T) {
		for _, token := range []string{"", "at_malformed"} {
			expect(t, send(ctx, http.MethodGet, "me", token, nil), 401, "unauthorized")
		}
		expired := login(t, password)
		exec(t, "UPDATE auth_sessions SET access_expires_at=now()-interval '1 second' WHERE access_digest=$1", auth.TokenDigestForTest(expired, "at_"))
		expect(t, send(ctx, http.MethodGet, "me", expired, nil), 401, "unauthorized")
		expect(t, send(ctx, http.MethodPatch, "me", access, map[string]any{"name": nil, "email": nil}), 400, "invalid_request")
		expect(t, send(ctx, http.MethodPatch, "me", access, map[string]any{"name": string(bytes.Repeat([]byte("é"), 76))}), 400, "invalid_request")
		expectProfile(t, access, "", "", false)
	})

	t.Run("email and login share hash capacity", func(t *testing.T) {
		resetCooldown(t)
		release := server.SaturateHashForTest()
		defer release()
		expect(t, emailRequest(ctx, access, "capacity@example.test"), 503, "temporarily_unavailable")
		expect(t, send(ctx, http.MethodPost, "auth/login", "", map[string]any{"phone": phone, "password": password}), 503, "temporarily_unavailable")
		if len(sender.testEmail) != 0 {
			t.Fatal("provider was called while the hash pool was full")
		}
	})

	t.Run("logout while delivery is blocked prevents acknowledgement", func(t *testing.T) {
		var code string
		blockedDelivery(t, access, "revoked@example.test", func(value string) {
			code = value
			expect(t, send(ctx, http.MethodPost, "auth/logout", access, nil), 204, "")
		}, 401, "unauthorized")
		expect(t, send(ctx, http.MethodGet, "me", access, nil), 401, "unauthorized")
		access = login(t, password)
		expectProfile(t, access, "", "", false)
		expect(t, verify(access, code), 400, "invalid_or_expired_code")
	})

	t.Run("profile change invalidates challenge while delivery is blocked", func(t *testing.T) {
		blockedDelivery(t, access, "stale@example.test", func(code string) {
			expect(t, patchEmail(access, "  unverified@example.test  "), 200, "")
			expect(t, verify(access, code), 400, "invalid_or_expired_code")
		}, 400, "invalid_request")
		expectProfile(t, access, "unverified@example.test", "", false)
	})

	t.Run("resend wins over acknowledgement for the old digest", func(t *testing.T) {
		var oldCode string
		blockedDelivery(t, access, "old@example.test", func(code string) {
			oldCode = code
			issue(t, access, "pending@example.test")
		}, 400, "invalid_request")
		expect(t, verify(access, oldCode), 400, "invalid_or_expired_code")
		expectProfile(t, access, "unverified@example.test", "pending@example.test", false)
	})

	t.Run("failed profile write rolls back challenge deletion", func(t *testing.T) {
		exec(t, "ALTER TABLE auth_users ADD CONSTRAINT test_patch_failure CHECK (email <> 'blocked@example.test') NOT VALID")
		response := patchEmail(access, "blocked@example.test")
		exec(t, "ALTER TABLE auth_users DROP CONSTRAINT test_patch_failure")
		expect(t, response, 500, "internal_error")
		expectProfile(t, access, "unverified@example.test", "pending@example.test", false)
		expect(t, patchEmail(access, "unverified@example.test"), 200, "")
		expectProfile(t, access, "unverified@example.test", "pending@example.test", false)
	})

	t.Run("failed verification rolls back challenge consumption", func(t *testing.T) {
		code := issue(t, access, "verified@example.test")
		exec(t, "ALTER TABLE auth_users ADD CONSTRAINT test_email_failure CHECK (email <> 'verified@example.test') NOT VALID")
		response := verify(access, code)
		exec(t, "ALTER TABLE auth_users DROP CONSTRAINT test_email_failure")
		expect(t, response, 500, "internal_error")
		expectProfile(t, access, "unverified@example.test", "verified@example.test", false)
		results := make(chan *httptest.ResponseRecorder, 2)
		for range 2 {
			go func() { results <- verify(access, code) }()
		}
		a, b := <-results, <-results
		if b.Code == 200 {
			a, b = b, a
		}
		expect(t, a, 200, "")
		expect(t, b, 400, "invalid_or_expired_code")
		expectProfile(t, access, "verified@example.test", "", true)
		expect(t, patchEmail(access, ""), 400, "invalid_request")
	})

	t.Run("issuance limits keep recipient key and roll back later budget failures", func(t *testing.T) {
		resetCooldown(t)
		recipientKey := auth.HexDigestForTest("email/recipient/mixed@example.test")
		globalKey := auth.HexDigestForTest("email/global")
		seed := func(key string, seconds, attempts int) {
			exec(t, `INSERT INTO auth_rate_limits(key,bucket,attempts,expires_at)
 SELECT $1,floor(extract(epoch FROM now())/$2::bigint)::bigint+n,$3,now()+interval '2 hours'
 FROM generate_series(0,1) AS n
 ON CONFLICT(key,bucket) DO UPDATE SET attempts=excluded.attempts,expires_at=excluded.expires_at`, key, seconds, attempts)
		}
		seed(recipientKey, 3600, 5)
		expect(t, emailRequest(ctx, access, "MiXeD@example.test"), 429, "rate_limited")
		exec(t, "DELETE FROM auth_rate_limits WHERE key=$1", recipientKey)
		seed(globalKey, 60, 60)
		expect(t, emailRequest(ctx, access, "MiXeD@example.test"), 429, "rate_limited")
		exec(t, "DELETE FROM auth_rate_limits WHERE key=$1", globalKey)
		var rows int
		if err := db.QueryRow(ctx, "SELECT count(*) FROM auth_rate_limits WHERE key IN ($1,$2)", cooldownKey, recipientKey).Scan(&rows); err != nil || rows != 0 {
			t.Fatalf("failed issuance left %d budget rows: %v", rows, err)
		}
	})

	t.Run("password version change while issuance waits invalidates the verified snapshot", func(t *testing.T) {
		resetCooldown(t)
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
		var response *httptest.ResponseRecorder
		done := make(chan struct{})
		go func() {
			defer close(done)
			response = emailRequest(wait, access, "stale-version@example.test")
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
				t.Fatal("email request never waited for the account lock: ", err)
			}
			if blocked {
				break
			}
			time.Sleep(5 * time.Millisecond)
		}
		// Leave the session active to isolate the version predicate from revocation.
		if _, err := tx.Exec(ctx, "UPDATE auth_users SET password_version=password_version+1 WHERE id=$1", id); err != nil {
			t.Fatal(err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		<-done
		expect(t, response, 401, "unauthorized")
		expectProfile(t, access, "verified@example.test", "", true)
		if len(sender.testEmail) != 0 {
			t.Fatal("provider received a stale-password challenge")
		}
	})

	t.Run("password reset hides and invalidates an outstanding email code", func(t *testing.T) {
		code := issue(t, access, "old-version@example.test")
		grant, err := auth.NewTokenForTest("rc_")
		if err != nil {
			t.Fatal(err)
		}
		exec(t, `INSERT INTO auth_recovery(digest,user_id,password_version,expires_at)
 SELECT $1,id,password_version,now()+interval '10 minutes' FROM auth_users WHERE id=$2`, auth.TokenDigestForTest(grant, "rc_"), id)
		const replacement = "replacement fixture password"
		expect(t, send(ctx, http.MethodPost, "auth/recovery/reset", "", map[string]any{"recovery_token": grant, "password": replacement}), 204, "")
		expect(t, verify(access, code), 401, "unauthorized")
		access = login(t, replacement)
		expectProfile(t, access, "verified@example.test", "", true)
		expect(t, verify(access, code), 400, "invalid_or_expired_code")
	})
}
