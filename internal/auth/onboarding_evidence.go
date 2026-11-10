package auth

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"
)

var requiredOnboardingDocuments = []string{
	"selfie", "cnic_front", "cnic_back", "license_front", "license_back", "registration",
	"exterior_front", "exterior_rear", "exterior_right", "exterior_left", "interior_front", "interior_rear",
}
var onboardingCNIC = regexp.MustCompile(`^[0-9]{13}$`)

func onboardingToday() time.Time {
	now := time.Now().In(time.FixedZone("PKT", 5*60*60))
	return time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
}

func completeDriver(d map[string]string, today time.Time) bool {
	dob, err := time.Parse(time.DateOnly, d["date_of_birth"])
	return err == nil && dob.Year() > 0 && !dob.AddDate(18, 0, 0).After(today) &&
		validProfileName(d["legal_name"]) && onboardingCNIC.MatchString(d["cnic_number"])
}

func hasDocument(kinds []string, kind string) bool { return slices.Contains(kinds, kind) }

func staleOnboardingEvidence(previous, current map[string]string) []string {
	changed := func(fields ...string) bool {
		for _, field := range fields {
			if previous[field] != "" && previous[field] != current[field] {
				return true
			}
		}
		return false
	}
	var stale []string
	if changed("legal_name", "date_of_birth", "cnic_number") {
		stale = append(stale, "selfie", "cnic_front", "cnic_back", "license_front", "license_back")
	}
	if changed("make", "model", "manufacture_year", "color", "registration_number") {
		stale = append(stale, "registration", "additional", "exterior_front", "exterior_rear",
			"exterior_right", "exterior_left", "interior_front", "interior_rear")
	}
	return stale
}

func unexpired(value string, today time.Time) bool {
	expiry, err := time.Parse(time.DateOnly, value)
	return err == nil && !expiry.Before(today)
}

func validDraftExpiry(previous, details map[string]string, today time.Time) bool {
	for _, field := range []string{"cnic_expiry", "license_expiry", "registration_expiry", "additional_expiry"} {
		if value := details[field]; value != "" && value != previous[field] && !unexpired(value, today) {
			return false
		}
	}
	return true
}

func validDocumentDate(d map[string]string, prefix, noExpiry string, today time.Time) bool {
	switch d[prefix+"_validity"] {
	case "expires":
		return unexpired(d[prefix+"_expiry"], today)
	case noExpiry:
		return d[prefix+"_expiry"] == ""
	default:
		return false
	}
}

func completeEvidence(d map[string]string, kinds []string, today time.Time) bool {
	for _, kind := range requiredOnboardingDocuments {
		if !hasDocument(kinds, kind) {
			return false
		}
	}
	return validDocumentDate(d, "cnic", "lifetime", today) &&
		unexpired(d["license_expiry"], today) &&
		validDocumentDate(d, "registration", "no_expiry", today) &&
		(!hasDocument(kinds, "additional") || validDocumentDate(d, "additional", "no_expiry", today))
}

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

func (s *Server) SaveOnboardingDocument(ctx context.Context, body Input, bearer string) (any, error) {
	doc := body.OnboardingDocument
	if !hasDocument(requiredOnboardingDocuments, doc.Kind) && doc.Kind != "additional" {
		return nil, invalid
	}
	if s.driverDocumentCipher == nil {
		return nil, busy
	}
	select {
	case s.driverDocumentSlots <- struct{}{}:
		defer func() { <-s.driverDocumentSlots }()
	default:
		return nil, busy
	}
	limit := maxVehicleDocument
	if doc.Kind == "cnic_front" || doc.Kind == "cnic_back" {
		limit = maxDriverImage
	}
	normalized, err := normalizeDocumentImage(doc.Image, limit)
	if err != nil {
		return nil, err
	}
	return s.withOnboarding(ctx, bearer, func(tx pgx.Tx, id int64, current onboardingApplication) error {
		if current.SubmittedAt != nil {
			return onboardingConflict
		}
		if current.Version == 0 || (doc.Kind != "selfie" && current.Draft["step"] != "2" && current.Draft["step"] != "3") {
			return onboardingIncomplete
		}
		aad := onboardingDocumentAAD(id, current.Version, doc.Kind)
		if hasDocument(current.Documents, doc.Kind) {
			var saved []byte
			if err := tx.QueryRow(ctx, `SELECT image FROM driver_onboarding_documents
 WHERE user_id=$1 AND application_version=$2 AND kind=$3`, id, current.Version, doc.Kind).Scan(&saved); err != nil {
				return err
			}
			previous, err := s.driverDocumentCipher.Open(nil, nil, saved, aad)
			if err != nil {
				return err
			}
			if bytes.Equal(previous, normalized) {
				return nil
			}
		}
		if current.Draft["revision"] != doc.Revision {
			return onboardingConflict
		}
		if err := allow(ctx, tx, fmt.Sprintf("onboarding/document-changes/%d", id), 15*time.Minute, 40); err != nil {
			return err
		}
		encrypted := s.driverDocumentCipher.Seal(nil, nil, normalized, aad)
		if _, err := tx.Exec(ctx, `INSERT INTO driver_onboarding_documents(user_id,application_version,kind,image)
 VALUES($1,$2,$3,$4) ON CONFLICT (user_id,application_version,kind) DO UPDATE SET image=excluded.image`, id, current.Version, doc.Kind, encrypted); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `UPDATE driver_onboarding_applications SET draft_revision=draft_revision+1,updated_at=clock_timestamp()
 WHERE user_id=$1 AND application_version=$2`, id, current.Version)
		return err
	})
}

func (s *Server) PreviewOnboardingDocument(ctx context.Context, body Input, bearer string) (any, error) {
	if s.driverDocumentCipher == nil {
		return nil, busy
	}
	if !hasDocument(requiredOnboardingDocuments, body.OnboardingPreview) && body.OnboardingPreview != "additional" {
		return nil, invalid
	}
	var plain []byte
	_, err := s.withOnboarding(ctx, bearer, func(tx pgx.Tx, id int64, current onboardingApplication) error {
		if current.SubmittedAt != nil {
			return onboardingConflict
		}
		var data []byte
		err := tx.QueryRow(ctx, `SELECT image FROM driver_onboarding_documents WHERE user_id=$1 AND application_version=$2 AND kind=$3`, id, current.Version, body.OnboardingPreview).Scan(&data)
		if errors.Is(err, pgx.ErrNoRows) {
			return invalid
		}
		if err != nil {
			return err
		}
		plain, err = s.driverDocumentCipher.Open(nil, nil, data, onboardingDocumentAAD(id, current.Version, body.OnboardingPreview))
		return err
	})
	return map[string][]byte{"image": plain}, err
}

func (s *Server) RemoveOnboardingDocument(ctx context.Context, body Input, bearer string) (any, error) {
	doc := body.OnboardingDocument
	if doc.Kind != "additional" {
		return nil, invalid
	}
	return s.withOnboarding(ctx, bearer, func(tx pgx.Tx, id int64, current onboardingApplication) error {
		if current.SubmittedAt != nil || current.Draft["revision"] != doc.Revision {
			return onboardingConflict
		}
		if !hasDocument(current.Documents, doc.Kind) {
			return nil
		}
		if _, err := tx.Exec(ctx, `DELETE FROM driver_onboarding_documents
 WHERE user_id=$1 AND application_version=$2 AND kind='additional'`, id, current.Version); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `UPDATE driver_onboarding_applications SET
 details=details-'additional_expiry'-'additional_validity',draft_revision=draft_revision+1,updated_at=clock_timestamp()
 WHERE user_id=$1 AND application_version=$2`, id, current.Version)
		return err
	})
}
