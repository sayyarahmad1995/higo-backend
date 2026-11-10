package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"regexp"
	"strconv"
	"strings"

	"github.com/nyaruka/phonenumbers"
	"golang.org/x/crypto/argon2"
)

var (
	e164Pattern = regexp.MustCompile(`^\+[1-9][0-9]{7,14}$`)
	otpPattern  = regexp.MustCompile(`^[0-9]{6}$`)
	hashPattern = regexp.MustCompile(`^\$argon2id\$v=19\$m=([0-9]{1,6}),t=([1-4]),p=1\$([A-Za-z0-9+/]{22})\$([A-Za-z0-9+/]{43})$`)
)

type passwords struct{ memory, passes uint32 }

func validCost(memory, passes uint32) bool {
	return memory >= 19456 && memory <= 131072 && passes >= 2 && passes <= 4
}

func ValidPassword(password string) bool { return len(password) >= 12 && len(password) <= 128 }

func (p passwords) hash(password string) (string, error) {
	if !ValidPassword(password) || !validCost(p.memory, p.passes) {
		return "", errors.New("invalid password or Argon2id parameters")
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	hash := argon2.IDKey([]byte(password), salt, p.passes, p.memory, 1, 32)
	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=1$%s$%s", p.memory, p.passes,
		base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(hash)), nil
}

func (p passwords) verify(encoded, password string) bool {
	parts := hashPattern.FindStringSubmatch(encoded)
	if parts == nil || len(password) > 128 {
		return false
	}
	memory, _ := strconv.ParseUint(parts[1], 10, 32)
	passes, _ := strconv.ParseUint(parts[2], 10, 32)
	if !validCost(uint32(memory), uint32(passes)) {
		return false
	}
	salt, saltErr := base64.RawStdEncoding.Strict().DecodeString(parts[3])
	expected, hashErr := base64.RawStdEncoding.Strict().DecodeString(parts[4])
	if saltErr != nil || hashErr != nil {
		return false
	}
	actual := argon2.IDKey([]byte(password), salt, uint32(passes), uint32(memory), 1, 32)
	return subtle.ConstantTimeCompare(actual, expected) == 1
}

func phoneNumber(raw string) string {
	canonical := strings.NewReplacer(" ", "", "-", "", "(", "", ")", "").Replace(strings.TrimSpace(raw))
	if !e164Pattern.MatchString(canonical) {
		return ""
	}
	number, err := phonenumbers.Parse(canonical, "")
	if err != nil || !phonenumbers.IsValidNumber(number) {
		return ""
	}
	return phonenumbers.Format(number, phonenumbers.E164)
}

func newToken(prefix string) (string, error) {
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return "", err
	}
	return prefix + base64.RawURLEncoding.EncodeToString(secret), nil
}

func tokenDigest(token, prefix string) []byte {
	encoded, ok := strings.CutPrefix(token, prefix)
	if !ok || len(encoded) != 43 {
		return nil
	}
	if _, err := base64.RawURLEncoding.Strict().DecodeString(encoded); err != nil {
		return nil
	}
	digest := sha256.Sum256([]byte(token))
	return digest[:]
}

func hexDigest(value string) string {
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:])
}

func newOTP() (string, error) {
	value, err := rand.Int(rand.Reader, big.NewInt(1_000_000))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%06d", value.Int64()), nil
}
