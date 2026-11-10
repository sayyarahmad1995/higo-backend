package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/mail"
	"os"
	"time"

	"github.com/sayyarahmad1995/higo-backend/internal/auth"
)

type localEmail struct{}

func (localEmail) Send(_ context.Context, address, code string) error {
	fmt.Fprintf(os.Stderr, "LOCAL EMAIL %s: %s\n", address, code)
	return nil
}

type resendEmail struct {
	key, from string
	client    *http.Client
}

func productionEmail() (auth.EmailSender, error) {
	key, from := os.Getenv("RESEND_API_KEY"), os.Getenv("HIGO_EMAIL_FROM")
	if key == "" && from == "" {
		return nil, nil
	}
	if _, err := mail.ParseAddress(from); err != nil || key == "" {
		return nil, errors.New("email delivery requires RESEND_API_KEY and a valid HIGO_EMAIL_FROM")
	}
	return resendEmail{key, from, &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}

func (s resendEmail) Send(ctx context.Context, address, code string) error {
	data, err := json.Marshal(map[string]any{
		"from": s.from, "to": []string{address}, "subject": "Verify your HiGO email",
		"text": "Enter this code in HiGO within 15 minutes: " + code + "\nIf you did not request this, ignore this message.",
	})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.resend.com/emails", bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+s.key)
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("email provider returned HTTP %d", resp.StatusCode)
	}
	return nil
}
