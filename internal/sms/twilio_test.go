package sms

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
)

type transportFunc func(*http.Request) (*http.Response, error)

func (f transportFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

func TestTwilioDelivery(t *testing.T) {
	account := "AC" + strings.Repeat("a", 32)
	service := "MG" + strings.Repeat("b", 32)
	adapter, err := NewTwilio(account, "test-secret", service)
	if err != nil {
		t.Fatal(err)
	}
	for _, status := range []int{201, 429, 500} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			adapter.client.Transport = transportFunc(func(req *http.Request) (*http.Response, error) {
				if req.Method != "POST" || req.URL.Host != "api.twilio.com" || req.URL.Path != "/2010-04-01/Accounts/"+account+"/Messages.json" {
					t.Fatalf("unexpected request %s %s", req.Method, req.URL)
				}
				user, secret, ok := req.BasicAuth()
				if !ok || user != account || secret != "test-secret" {
					t.Fatal("missing request credentials")
				}
				if err := req.ParseForm(); err != nil {
					t.Fatal(err)
				}
				if req.Form.Get("To") != "+923001234567" || req.Form.Get("MessagingServiceSid") != service || !strings.HasSuffix(req.Form.Get("Body"), "012345") {
					t.Fatal("unexpected Twilio form")
				}
				return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader("provider response"))}, nil
			})
			if err := adapter.Send(context.Background(), "+923001234567", "012345"); (err == nil) != (status == 201) {
				t.Fatalf("status %d: %v", status, err)
			}
		})
	}
}
