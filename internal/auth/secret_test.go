package auth

import (
	"strings"
	"testing"
)

func TestPasswords(t *testing.T) {
	p := passwords{memory: 19456, passes: 2}
	first, err := p.hash("a valid long password")
	if err != nil {
		t.Fatal(err)
	}
	second, err := p.hash("a valid long password")
	if err != nil || first == second {
		t.Fatal("expected unique salts")
	}
	if !p.verify(first, "a valid long password") || p.verify(first, "a wrong long password") {
		t.Fatal("password verification mismatch")
	}
	if p.verify(strings.Replace(first, "m=19456", "m=999999999", 1), "a valid long password") {
		t.Fatal("accepted unbounded cost")
	}
	if _, err := p.hash("short"); err == nil {
		t.Fatal("accepted short password")
	}
}

func TestPhoneAndTokens(t *testing.T) {
	if got := phoneNumber(" +92 300-1234567 "); got != "+923001234567" {
		t.Fatalf("phone = %q", got)
	}
	if phoneNumber("03001234567") != "" {
		t.Fatal("accepted ambiguous local number")
	}
	token, err := newToken("at_")
	if err != nil || tokenDigest(token, "at_") == nil || tokenDigest(token, "rt_") != nil {
		t.Fatal("token validation failed")
	}
	for range 20 {
		code, err := newOTP()
		if err != nil || !otpPattern.MatchString(code) {
			t.Fatal("invalid generated OTP")
		}
	}
}
