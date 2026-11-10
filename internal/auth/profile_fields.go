package auth

import (
	"net/mail"
	"strings"
)

func ValidProfileName(name string) bool {
	return len(name) > 0 && len(name) <= 150 && !strings.ContainsRune(name, 0)
}

func ValidProfileEmail(email string) bool {
	if email == "" {
		return true
	}
	if len(email) > 254 {
		return false
	}
	address, err := mail.ParseAddress(email)
	return err == nil && address.Address == email
}
