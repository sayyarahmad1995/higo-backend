package auth

import (
	"context"
	"crypto/cipher"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/sayyarahmad1995/higo-backend/internal/ratelimit"
)

var (
	invalid         = errors.New("invalid_request")
	invalidCode     = errors.New("invalid_or_expired_code")
	invalidRecovery = errors.New("invalid_or_expired_recovery_token")
	denied          = errors.New("invalid_credentials")
	unauthorized    = errors.New("unauthorized")
	limited         = ratelimit.ErrLimited
	busy            = errors.New("temporarily_unavailable")
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
	documentUploadSlots  chan struct{}
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
	s.documentUploadSlots = make(chan struct{}, 2)
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
			purgeAbandonedOnboardingDocuments,
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

// Input carries decoded values to the feature operations.
type Input struct {
	Phone              string               `json:"phone"`
	Password           string               `json:"password"`
	Name               string               `json:"name"`
	Email              string               `json:"email"`
	Challenge          string               `json:"challenge"`
	Code               string               `json:"code"`
	Refresh            string               `json:"refresh_token"`
	Recovery           string               `json:"recovery_token"`
	Profile            profilePatch         `json:"-"`
	OnboardingDraft    map[string]string    `json:"-"`
	OnboardingDocument onboardingDocument   `json:"-"`
	OnboardingPreview  string               `json:"-"`
	OnboardingSubmit   onboardingSubmission `json:"-"`
}

// ErrorCode identifies domain errors safe to expose in an API response.
func ErrorCode(err error) string {
	switch err {
	case invalid, invalidCode, invalidRecovery, denied, unauthorized, limited, busy, documentTooLarge, invalidDocument, onboardingConflict, onboardingIncomplete:
		return err.Error()
	default:
		return ""
	}
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
		if err := ratelimit.Allow(ctx, tx, purpose+"/phone/"+phone, time.Hour, 5); err != nil {
			return err
		}
		return ratelimit.Allow(ctx, tx, "sms/global", time.Minute, 60)
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
