package driver

import (
	"crypto/cipher"
	"errors"
	"sync"

	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	invalid = errors.New("invalid_request")
	busy    = errors.New("temporarily_unavailable")
)

type Service struct {
	db                   *pgxpool.Pool
	driverDocumentCipher cipher.AEAD
	driverDocumentSlots  chan struct{}
	documentUploadSlots  chan struct{}
	activeUploadAccounts sync.Map
}

// New constructs the Driver feature. An absent key leaves evidence operations
// unavailable while preserving the other onboarding operations.
func New(db *pgxpool.Pool, key []byte) (*Service, error) {
	documentCipher, err := newDriverDocumentCipher(key)
	if err != nil {
		return nil, err
	}
	return &Service{
		db: db, driverDocumentCipher: documentCipher,
		driverDocumentSlots: make(chan struct{}, 2),
		documentUploadSlots: make(chan struct{}, 2),
	}, nil
}

// ErrorCode identifies Driver errors safe to expose in an API response.
func ErrorCode(err error) string {
	switch err {
	case invalid, busy, documentTooLarge, invalidDocument, onboardingConflict, onboardingIncomplete:
		return err.Error()
	default:
		return ""
	}
}
