package sms

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

var accountPattern = regexp.MustCompile(`^AC[0-9a-fA-F]{32}$`)
var servicePattern = regexp.MustCompile(`^MG[0-9a-fA-F]{32}$`)

type Twilio struct {
	account, secret, service string
	client                   *http.Client
}

func NewTwilio(account, secret, service string) (*Twilio, error) {
	if !accountPattern.MatchString(account) || !servicePattern.MatchString(service) || strings.TrimSpace(secret) == "" {
		return nil, errors.New("Twilio credentials or messaging service are invalid")
	}
	return &Twilio{account, secret, service, &http.Client{
		Timeout:       8 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}, nil
}

func (t *Twilio) Send(ctx context.Context, phone, code string) error {
	endpoint := "https://api.twilio.com/2010-04-01/Accounts/" + t.account + "/Messages.json"
	form := url.Values{"To": {phone}, "MessagingServiceSid": {t.service}, "Body": {"Your HiGO verification code is " + code}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(t.account, t.secret)
	resp, err := t.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("SMS gateway returned HTTP %d", resp.StatusCode)
	}
	return nil
}
