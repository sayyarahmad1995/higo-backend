package app

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"

	"github.com/sayyarahmad1995/higo-backend/internal/auth"
	"github.com/sayyarahmad1995/higo-backend/internal/sms"
)

type config struct {
	auth                 auth.Config
	address, databaseURL string
	sms                  auth.SMS
}

type localSMS struct{}

func (localSMS) Send(_ context.Context, phone, code string) error {
	fmt.Fprintf(os.Stderr, "LOCAL SMS %s: %s\n", phone, code)
	return nil
}

func loadConfig() (config, error) {
	var cfg config
	cfg.databaseURL = os.Getenv("DATABASE_URL")
	if cfg.databaseURL == "" {
		return cfg, errors.New("DATABASE_URL is required")
	}
	key, err := base64.StdEncoding.DecodeString(os.Getenv("HIGO_OTP_KEY"))
	if err != nil || len(key) != 32 {
		return cfg, errors.New("HIGO_OTP_KEY must be 32 random bytes encoded as standard Base64")
	}
	memory, err := number("HIGO_ARGON2_MEMORY_KIB", 65536)
	if err != nil {
		return cfg, err
	}
	passes, err := number("HIGO_ARGON2_PASSES", 3)
	if err != nil {
		return cfg, err
	}
	cfg.auth = auth.Config{OTPKey: key, PasswordMemory: memory, PasswordPasses: passes}
	if encoded := os.Getenv("HIGO_DRIVER_DOCUMENT_KEY"); encoded != "" {
		cfg.auth.DriverDocumentKey, err = base64.StdEncoding.DecodeString(encoded)
		if err != nil || len(cfg.auth.DriverDocumentKey) != 32 {
			return cfg, errors.New("HIGO_DRIVER_DOCUMENT_KEY must be 32 random bytes encoded as standard Base64")
		}
	}
	cfg.address = os.Getenv("HIGO_LISTEN_ADDR")
	if cfg.address == "" {
		cfg.address = "127.0.0.1:8080"
	}
	switch os.Getenv("HIGO_ENV") {
	case "development":
		host, _, err := net.SplitHostPort(cfg.address)
		if err != nil || (host != "127.0.0.1" && host != "::1") {
			return cfg, errors.New("development SMS requires a loopback listener")
		}
		cfg.sms = localSMS{}
		cfg.auth.EmailSender = localEmail{}
	case "production":
		cfg.auth.EmailSender, err = productionEmail()
		if err != nil {
			return cfg, err
		}
		cfg.sms, err = sms.NewTwilio(os.Getenv("TWILIO_ACCOUNT_SID"), os.Getenv("TWILIO_AUTH_TOKEN"), os.Getenv("TWILIO_MESSAGING_SERVICE_SID"))
		if err != nil {
			return cfg, err
		}
	default:
		return cfg, errors.New("HIGO_ENV must be development or production")
	}
	return cfg, nil
}

func number(key string, fallback uint32) (uint32, error) {
	value := os.Getenv(key)
	if value == "" {
		return fallback, nil
	}
	parsed, err := strconv.ParseUint(value, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("%s must be an unsigned integer", key)
	}
	return uint32(parsed), nil
}
