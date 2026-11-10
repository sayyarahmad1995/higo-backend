package driver

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"fmt"
	"image"
	"image/jpeg"
	"image/png"
)

const maxDriverImage = 1024 * 1024

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

func onboardingDocumentAAD(id int64, version int, kind string) []byte {
	switch kind {
	case "cnic_front":
		kind = "identity:front"
	case "cnic_back":
		kind = "identity:back"
	case "registration":
		kind = "vehicle:registration"
	case "additional":
		kind = "vehicle:insurance"
	}
	return []byte(fmt.Sprintf("driver-onboarding:%d:%d:%s", id, version, kind))
}
