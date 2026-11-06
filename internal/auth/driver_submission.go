package auth

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"fmt"
	"image"
	"image/jpeg"
	"image/png"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

const maxDriverImage = 1024 * 1024

const purgeSupersededDriverDocuments = `UPDATE driver_identity_submissions d SET cnic_front=NULL,cnic_back=NULL
 WHERE (d.user_id,d.version) IN (SELECT old.user_id,old.version FROM driver_identity_submissions old
 WHERE old.cnic_front IS NOT NULL AND old.submitted_at < now()-interval '30 days'
 AND EXISTS (SELECT 1 FROM driver_identity_submissions newer WHERE newer.user_id=old.user_id AND newer.version>old.version)
 ORDER BY old.submitted_at LIMIT 500)`

var (
	documentTooLarge = errors.New("document_too_large")
	invalidDocument  = errors.New("invalid_document")
	documentQuota    = errors.New("document_quota_exceeded")
)

type boundedDriverImage struct{ bytes.Buffer }

func (b *boundedDriverImage) Write(data []byte) (int, error) {
	if len(data) > maxDriverImage-b.Len() {
		return 0, documentTooLarge
	}
	return b.Buffer.Write(data)
}

type driverSubmissionInput struct {
	LegalName string `json:"legal_name"`
	Front     []byte `json:"cnic_front"`
	Back      []byte `json:"cnic_back"`
}

type driverSubmissionStatus struct {
	Status      string     `json:"status"`
	Version     int        `json:"version,omitempty"`
	LegalName   string     `json:"legal_name,omitempty"`
	SubmittedAt *time.Time `json:"submitted_at,omitempty"`
}

func newDriverDocumentCipher(key []byte) (cipher.AEAD, error) {
	if len(key) == 0 {
		return nil, nil
	}
	if len(key) != 32 {
		return nil, errors.New("Driver document key must be 32 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCMWithRandomNonce(block)
}

func normalizeDriverImage(data []byte) ([]byte, error) {
	if len(data) > maxDriverImage {
		return nil, documentTooLarge
	}
	if len(data) == 0 {
		return nil, invalidDocument
	}
	cfg, format, err := image.DecodeConfig(bytes.NewReader(data))
	if err != nil || (format != "png" && format != "jpeg") || cfg.Width < 1 || cfg.Height < 1 || cfg.Width > 4096 || cfg.Height > 4096 || cfg.Width*cfg.Height > 8_000_000 {
		return nil, invalidDocument
	}
	decoded, _, err := image.Decode(bytes.NewReader(data))
	if err != nil {
		return nil, invalidDocument
	}
	var output boundedDriverImage
	if format == "jpeg" {
		err = jpeg.Encode(&output, decoded, nil)
	} else {
		err = png.Encode(&output, decoded)
	}
	if err != nil {
		if errors.Is(err, documentTooLarge) {
			return nil, documentTooLarge
		}
		return nil, invalidDocument
	}
	return output.Bytes(), nil
}

func (s *Server) driverSubmission(ctx context.Context, _ input, bearer string) (int, any, error) {
	digest := tokenDigest(bearer, "at_")
	if digest == nil {
		return 0, nil, unauthorized
	}
	var result driverSubmissionStatus
	err := s.db.QueryRow(ctx, `SELECT COALESCE(d.status,'not_submitted'),COALESCE(d.version,0),COALESCE(d.legal_name,''),d.submitted_at
 FROM auth_sessions s LEFT JOIN LATERAL (SELECT status,version,legal_name,submitted_at FROM driver_identity_submissions
 WHERE user_id=s.user_id ORDER BY version DESC LIMIT 1) d ON true
 WHERE s.access_digest=$1 AND s.revoked_at IS NULL AND s.access_expires_at>now() AND s.expires_at>now()`, digest).Scan(&result.Status, &result.Version, &result.LegalName, &result.SubmittedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, nil, unauthorized
	}
	return 200, result, err
}

func (s *Server) submitDriverIdentity(ctx context.Context, body input, bearer string) (int, any, error) {
	if s.driverDocumentCipher == nil {
		return 0, nil, busy
	}
	digest := tokenDigest(bearer, "at_")
	if digest == nil {
		return 0, nil, unauthorized
	}
	submission := body.DriverSubmission
	select {
	case s.driverDocumentSlots <- struct{}{}:
		defer func() { <-s.driverDocumentSlots }()
	default:
		return 0, nil, busy
	}
	name := strings.TrimSpace(submission.LegalName)
	if !validProfileName(name) {
		return 0, nil, invalid
	}
	front, err := normalizeDriverImage(submission.Front)
	if err != nil {
		return 0, nil, err
	}
	back, err := normalizeDriverImage(submission.Back)
	if err != nil {
		return 0, nil, err
	}
	result := driverSubmissionStatus{Status: "submitted", LegalName: name}
	err = pgx.BeginFunc(ctx, s.db, func(tx pgx.Tx) error {
		id, err := lockSessionAccount(ctx, tx, digest)
		if err != nil {
			return err
		}
		if err := allow(ctx, tx, fmt.Sprintf("driver/submission/%d", id), 24*time.Hour, 5); err != nil {
			return err
		}
		var retained int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM driver_identity_submissions WHERE user_id=$1 AND cnic_front IS NOT NULL`, id).Scan(&retained); err != nil {
			return err
		}
		if retained >= 20 {
			return documentQuota
		}
		if err := tx.QueryRow(ctx, `SELECT COALESCE(MAX(version),0)+1 FROM driver_identity_submissions WHERE user_id=$1`, id).Scan(&result.Version); err != nil {
			return err
		}
		associated := fmt.Sprintf("driver-cnic:%d:%d:", id, result.Version)
		return tx.QueryRow(ctx, `INSERT INTO driver_identity_submissions (user_id,version,legal_name,cnic_front,cnic_back)
 VALUES ($1,$2,$3,$4,$5) RETURNING submitted_at`, id, result.Version, name,
			s.driverDocumentCipher.Seal(nil, nil, front, []byte(associated+"front")),
			s.driverDocumentCipher.Seal(nil, nil, back, []byte(associated+"back"))).Scan(&result.SubmittedAt)
	})
	return 201, result, err
}
