package auth

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"image"
	"image/jpeg"
	"image/png"
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
)

type boundedDriverImage struct {
	bytes.Buffer
	limit int
}

func (b *boundedDriverImage) Write(data []byte) (int, error) {
	if len(data) > b.limit-b.Len() {
		return 0, documentTooLarge
	}
	return b.Buffer.Write(data)
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
	return normalizeDocumentImage(data, maxDriverImage)
}

func normalizeDocumentImage(data []byte, limit int) ([]byte, error) {
	if len(data) > limit {
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
	output := boundedDriverImage{limit: limit}
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

const maxVehicleDocument = 2 * 1024 * 1024

const purgeSupersededVehicleDocuments = `UPDATE driver_vehicle_submissions v SET registration_image=NULL,insurance_image=NULL
 WHERE (v.user_id,v.vehicle_id,v.version) IN (SELECT old.user_id,old.vehicle_id,old.version FROM driver_vehicle_submissions old
 WHERE old.registration_image IS NOT NULL AND old.submitted_at<now()-interval '30 days'
 AND EXISTS(SELECT 1 FROM driver_vehicle_submissions newer WHERE newer.user_id=old.user_id AND newer.vehicle_id=old.vehicle_id AND newer.version>old.version)
 ORDER BY old.submitted_at LIMIT 500)`
