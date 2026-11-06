package auth

import (
	"context"
	"crypto/cipher"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	invalid         = errors.New("invalid_request")
	invalidCode     = errors.New("invalid_or_expired_code")
	invalidRecovery = errors.New("invalid_or_expired_recovery_token")
	denied          = errors.New("invalid_credentials")
	unauthorized    = errors.New("unauthorized")
	limited         = errors.New("rate_limited")
	busy            = errors.New("temporarily_unavailable")
	uploadTimeout   = errors.New("upload_timeout")
)

type SMS interface {
	Send(ctx context.Context, phone, code string) error
}

type Config struct {
	DriverDocumentKey              []byte
	EmailSender                    EmailSender
	OTPKey                         []byte
	PasswordMemory, PasswordPasses uint32
}

type Server struct {
	driverDocumentCipher cipher.AEAD
	driverDocumentSlots  chan struct{}
	driverUploadSlots    chan struct{}
	vehicleUploadSlots   chan struct{}
	activeUploadAccounts sync.Map
	emailSender          EmailSender
	db                   *pgxpool.Pool
	sms                  SMS
	passwords            passwords
	otpKey               []byte
	dummyHash            string
	hashSlots            chan struct{}
	deliveryContext      context.Context
	smsSlots             chan struct{}
	cancel               context.CancelFunc
	worker               sync.WaitGroup
}

type delivery struct {
	id          []byte
	phone, code string
	send        bool
}

func New(ctx context.Context, db *pgxpool.Pool, sms SMS, cfg Config) (*Server, error) {
	if len(cfg.OTPKey) < 32 || !validCost(cfg.PasswordMemory, cfg.PasswordPasses) || db == nil || sms == nil {
		return nil, errors.New("invalid auth configuration")
	}
	p := passwords{cfg.PasswordMemory, cfg.PasswordPasses}
	dummy, err := p.hash("dummy credential for timing")
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(ctx)
	s := &Server{db: db, sms: sms, emailSender: cfg.EmailSender, passwords: p, otpKey: append([]byte(nil), cfg.OTPKey...), dummyHash: dummy,
		hashSlots: make(chan struct{}, 2), deliveryContext: ctx, smsSlots: make(chan struct{}, 32), cancel: cancel}
	s.driverDocumentCipher, err = newDriverDocumentCipher(cfg.DriverDocumentKey)
	if err != nil {
		cancel()
		return nil, err
	}
	s.driverDocumentSlots = make(chan struct{}, 2)
	s.driverUploadSlots = make(chan struct{}, 2)
	s.vehicleUploadSlots = make(chan struct{}, 2)
	s.worker.Go(func() { s.cleanup(ctx) })
	return s, nil
}

func (s *Server) Close() { s.cancel(); s.worker.Wait() }

func (s *Server) dispatchSMS(item delivery) {
	timeout, cancel := context.WithTimeout(s.deliveryContext, 10*time.Second)
	s.worker.Go(func() {
		defer cancel()
		if item.send {
			err := s.sms.Send(timeout, item.phone, item.code)
			if err == nil {
				_, err = s.db.Exec(timeout, `UPDATE auth_challenges SET delivered=true WHERE id=$1 AND expires_at>now()`, item.id)
			}
			if err != nil && s.deliveryContext.Err() == nil {
				slog.Warn("auth_sms_delivery_failed")
			}
		}
		// Keep capacity occupied equally for real and suppressed deliveries.
		<-timeout.Done()
		<-s.smsSlots
	})
}

func (s *Server) cleanup(ctx context.Context) {
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()
	for {
		for _, statement := range []string{
			`DELETE FROM auth_challenges WHERE expires_at<=now()`,
			`DELETE FROM auth_email_challenges WHERE expires_at<=now()`,
			purgeSupersededDriverDocuments,
			purgeSupersededVehicleDocuments,
			`DELETE FROM auth_recovery WHERE expires_at<=now()`,
			`DELETE FROM auth_sessions WHERE expires_at<=now()`,
			`DELETE FROM auth_rate_limits WHERE expires_at<=now()`,
		} {
			deadline, cancel := context.WithTimeout(ctx, 10*time.Second)
			_, err := s.db.Exec(deadline, statement)
			cancel()
			if err != nil && ctx.Err() == nil {
				slog.Warn("auth_cleanup_failed")
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

type input struct {
	Phone             string                 `json:"phone"`
	Password          string                 `json:"password"`
	Name              string                 `json:"name"`
	Email             string                 `json:"email"`
	Challenge         string                 `json:"challenge"`
	Code              string                 `json:"code"`
	Refresh           string                 `json:"refresh_token"`
	Recovery          string                 `json:"recovery_token"`
	Profile           profilePatch           `json:"-"`
	DriverSubmission  driverSubmissionInput  `json:"-"`
	VehicleSubmission vehicleSubmissionInput `json:"-"`
}

type operation func(context.Context, input, string) (int, any, error)

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	s.route(mux, "POST", "auth/register", s.register)
	s.route(mux, "POST", "auth/register/verify", s.verifyRegistration)
	s.route(mux, "POST", "auth/login", s.login)
	s.route(mux, "POST", "auth/refresh", s.refresh)
	s.route(mux, "POST", "auth/logout", s.logout)
	s.route(mux, "POST", "auth/recovery/request", s.requestRecovery)
	s.route(mux, "POST", "auth/recovery/verify", s.verifyRecovery)
	s.route(mux, "POST", "auth/recovery/reset", s.reset)
	s.route(mux, "GET", "me", s.me)
	s.route(mux, "PATCH", "me", s.updateProfile)
	s.route(mux, "POST", "me/email/request", s.requestEmailVerification)
	s.route(mux, "POST", "me/email/verify", s.verifyEmail)
	s.route(mux, "GET", "me/driver-submission", s.driverSubmission)
	s.route(mux, "POST", "me/driver-submission", s.submitDriverIdentity)
	s.route(mux, "GET", "me/vehicles", s.vehicles)
	s.route(mux, "POST", "me/vehicles", s.submitVehicle)
	return mux
}

func (s *Server) route(mux *http.ServeMux, method, path string, run operation) {
	mux.HandleFunc(method+" /api/v1/"+path, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "application/json")
		vehicleUpload := method == http.MethodPost && path == "me/vehicles"
		requestTimeout := 10 * time.Second
		if vehicleUpload {
			requestTimeout = 25 * time.Second
			_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(30 * time.Second))
		}
		ctx, cancel := context.WithTimeout(r.Context(), requestTimeout)
		defer cancel()
		peer, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			peer = r.RemoteAddr
		}
		limit := 60
		documentUpload := method == http.MethodPost && (path == "me/driver-submission" || path == "me/vehicles")
		if path == "auth/register" || path == "auth/recovery/request" || documentUpload {
			limit = 10
		}
		ratePath := path
		if path == "me/driver-submission" || path == "me/vehicles" {
			ratePath = method + "/" + path
		}
		if err := allow(ctx, s.db, ratePath+"/ip/"+peer, time.Minute, limit); err != nil {
			respond(w, 0, nil, err)
			return
		}
		var body input
		bearer, _ := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if method == http.MethodPatch || (method == http.MethodPost && path != "auth/logout") {
			var maxBytes int64 = 4096
			var releaseUpload func()
			var uploadStarted time.Time
			var cooldownKey string
			var target any = &body
			if method == http.MethodPatch {
				target = &body.Profile
			}
			if documentUpload {
				_, account, err := s.me(ctx, input{}, bearer)
				if err != nil {
					respond(w, 0, nil, err)
					return
				}
				id := account.(currentUser).ID
				cooldownKey = hexDigest(fmt.Sprintf("document/slow-upload/%d", id))
				var coolingDown bool
				if err := s.db.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM auth_rate_limits WHERE key=$1 AND bucket=0 AND expires_at>now())`, cooldownKey).Scan(&coolingDown); err != nil {
					respond(w, 0, nil, err)
					return
				}
				if coolingDown {
					respond(w, 0, nil, limited)
					return
				}
				maxBytes = 3 * 1024 * 1024
				target = &body.DriverSubmission
				if path == "me/vehicles" {
					maxBytes = 6 * 1024 * 1024
					target = &body.VehicleSubmission
				}
				if r.ContentLength > maxBytes {
					respond(w, 0, nil, documentTooLarge)
					return
				}
				if _, active := s.activeUploadAccounts.LoadOrStore(id, struct{}{}); active {
					respond(w, 0, nil, busy)
					return
				}
				slots := s.driverUploadSlots
				if vehicleUpload {
					slots = s.vehicleUploadSlots
				}
				select {
				case slots <- struct{}{}:
					defer func() { <-slots }()
					releaseUpload = func() { s.activeUploadAccounts.Delete(id) }
				default:
					s.activeUploadAccounts.Delete(id)
					respond(w, 0, nil, busy)
					return
				}
				// Limit how long a stalled client can hold an upload slot.
				readTimeout := 5 * time.Second
				if vehicleUpload {
					readTimeout = 20 * time.Second
				}
				_ = http.NewResponseController(w).SetReadDeadline(time.Now().Add(readTimeout))
				uploadStarted = time.Now()
			}
			decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBytes))
			decoder.DisallowUnknownFields()
			decodeErr := decoder.Decode(target)
			if decodeErr == nil {
				decodeErr = decoder.Decode(new(any))
				if decodeErr == io.EOF {
					decodeErr = nil
				} else if decodeErr == nil {
					decodeErr = invalid
				}
			}
			if documentUpload && time.Since(uploadStarted) >= 5*time.Second {
				penaltyCtx, stop := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
				_, _ = s.db.Exec(penaltyCtx, `INSERT INTO auth_rate_limits(key,bucket,attempts,expires_at) VALUES ($1,0,1,now()+interval '60 seconds')
 ON CONFLICT (key,bucket) DO UPDATE SET expires_at=excluded.expires_at`, cooldownKey)
				stop()
			}
			if decodeErr != nil {
				if releaseUpload != nil {
					releaseUpload()
				}
				var networkError net.Error
				if documentUpload && errors.As(decodeErr, &networkError) && networkError.Timeout() {
					respond(w, 0, nil, uploadTimeout)
					return
				}
				var oversized *http.MaxBytesError
				if errors.As(decodeErr, &oversized) && documentUpload {
					respond(w, 0, nil, documentTooLarge)
					return
				}
				respond(w, 0, nil, invalid)
				return
			}
			if releaseUpload != nil {
				releaseUpload()
			}
		}
		status, result, err := run(ctx, body, bearer)
		if path != "me" {
			slog.Info("auth_request", "operation", path, "outcome", outcome(err))
		}
		respond(w, status, result, err)
	})
}

func outcome(err error) string {
	switch err {
	case nil:
		return "success"
	case invalid, invalidCode, invalidRecovery, denied, unauthorized, limited, busy, documentTooLarge, invalidDocument, documentQuota, identityRequired, vehicleNotFound, uploadTimeout:
		return err.Error()
	default:
		return "internal_error"
	}
}

func respond(w http.ResponseWriter, status int, result any, err error) {
	if err != nil {
		switch err {
		case invalid, invalidCode, invalidRecovery, invalidDocument:
			status = 400
		case documentTooLarge:
			status = 413
		case documentQuota, identityRequired:
			status = 409
		case vehicleNotFound:
			status = 404
		case uploadTimeout:
			status = 408
		case denied, unauthorized:
			status = 401
		case limited:
			status = 429
		case busy:
			status = 503
		default:
			status = 500
		}
		result = map[string]string{"error": outcome(err)}
	}
	w.WriteHeader(status)
	if result != nil {
		_ = json.NewEncoder(w).Encode(result)
	}
}

type rateExecutor interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
}

func allow(ctx context.Context, db rateExecutor, key string, window time.Duration, limit int) error {
	seconds := int64(window / time.Second)
	tag, err := db.Exec(ctx, `INSERT INTO auth_rate_limits (key,bucket,attempts,expires_at)
 SELECT $1, floor(extract(epoch FROM now())/$2::bigint)::bigint, 1, now()+$2::bigint*interval '2 seconds'
 ON CONFLICT (key,bucket) DO UPDATE SET attempts=auth_rate_limits.attempts+1 WHERE auth_rate_limits.attempts<$3`,
		hexDigest(key), seconds, limit)
	if err == nil && tag.RowsAffected() == 0 {
		return limited
	}
	return err
}

func (s *Server) reserveSMS(ctx context.Context, purpose, phone string) error {
	return pgx.BeginFunc(ctx, s.db, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `INSERT INTO auth_rate_limits (key,bucket,attempts,expires_at)
 VALUES ($1,0,1,clock_timestamp()+interval '60 seconds')
 ON CONFLICT (key,bucket) DO UPDATE SET expires_at=clock_timestamp()+interval '60 seconds'
 WHERE auth_rate_limits.expires_at<=clock_timestamp()`, hexDigest("sms/phone/"+phone))
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return limited
		}
		if err := allow(ctx, tx, purpose+"/phone/"+phone, time.Hour, 5); err != nil {
			return err
		}
		return allow(ctx, tx, "sms/global", time.Minute, 60)
	})
}

func (s *Server) acquireHash() error {
	select {
	case s.hashSlots <- struct{}{}:
		return nil
	default:
		return busy
	}
}

func (s *Server) hash(password string) (string, error) {
	if err := s.acquireHash(); err != nil {
		return "", err
	}
	defer func() { <-s.hashSlots }()
	return s.passwords.hash(password)
}
