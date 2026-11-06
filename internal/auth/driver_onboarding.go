package auth

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

var (
	onboardingConflict     = errors.New("onboarding_conflict")
	onboardingIncomplete   = errors.New("onboarding_incomplete")
	onboardingRegistration = regexp.MustCompile(`^[A-Z0-9][A-Z0-9 -]{1,23}$`)
)

const onboardingPath = "me/driver-application"

const purgeAbandonedOnboardingDocuments = `WITH expired AS (
 SELECT user_id,application_version FROM driver_onboarding_applications
 WHERE submitted_at IS NULL AND (cnic_front IS NOT NULL OR registration_image IS NOT NULL)
 AND updated_at < now()-interval '30 days' ORDER BY updated_at LIMIT 500 FOR UPDATE SKIP LOCKED
)
UPDATE driver_onboarding_applications a SET cnic_front=NULL,cnic_back=NULL,
 registration_image=NULL,insurance_image=NULL,draft_revision=draft_revision+1,
 details=CASE WHEN details->>'step'='3' THEN jsonb_set(details,'{step}','"2"') ELSE details END
 FROM expired e WHERE (a.user_id,a.application_version)=(e.user_id,e.application_version)`

type onboardingDocuments struct {
	Revision string `json:"draft_revision"`
	Front    []byte `json:"cnic_front"`
	Back     []byte `json:"cnic_back"`
}
type onboardingVehicleDocuments struct {
	Revision     string `json:"draft_revision"`
	Registration []byte `json:"registration_image"`
	Insurance    []byte `json:"insurance_image"`
}
type onboardingSubmission struct {
	Revision string `json:"draft_revision"`
}
type onboardingApplication struct {
	Status      string            `json:"status"`
	Version     int               `json:"application_version,omitempty"`
	SubmittedAt *time.Time        `json:"submitted_at,omitempty"`
	Draft       map[string]string `json:"draft"`
}

func readOnboarding(ctx context.Context, tx pgx.Tx, id int64) (onboardingApplication, error) {
	result := onboardingApplication{Status: "draft", Draft: map[string]string{}}
	var revision string
	var identity, vehicle bool
	err := tx.QueryRow(ctx, `SELECT application_version,draft_revision::text,details,
 cnic_front IS NOT NULL,registration_image IS NOT NULL,submitted_at
 FROM driver_onboarding_applications WHERE user_id=$1 ORDER BY application_version DESC LIMIT 1 FOR UPDATE`, id).
		Scan(&result.Version, &revision, &result.Draft, &identity, &vehicle, &result.SubmittedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		result.Draft["revision"] = "0"
		return result, nil
	}
	if err != nil {
		return result, err
	}
	if result.SubmittedAt != nil {
		result.Status = "pending_review"
	}
	result.Draft["revision"] = revision
	if identity {
		result.Draft["identity_saved"] = "true"
	}
	if vehicle {
		result.Draft["vehicle_saved"] = "true"
	}
	return result, nil
}

func (s *Server) withOnboarding(ctx context.Context, bearer string, change func(pgx.Tx, int64, onboardingApplication) error) (int, any, error) {
	digest := tokenDigest(bearer, "at_")
	if digest == nil {
		return 0, nil, unauthorized
	}
	var result onboardingApplication
	err := pgx.BeginFunc(ctx, s.db, func(tx pgx.Tx) error {
		id, err := lockSessionAccount(ctx, tx, digest)
		if err != nil {
			return err
		}
		result, err = readOnboarding(ctx, tx, id)
		if err != nil || change == nil {
			return err
		}
		if err := change(tx, id, result); err != nil {
			return err
		}
		result, err = readOnboarding(ctx, tx, id)
		return err
	})
	return 200, result, err
}

func (s *Server) getOnboarding(ctx context.Context, _ input, bearer string) (int, any, error) {
	return s.withOnboarding(ctx, bearer, nil)
}

var onboardingVehicleFields = []string{"make", "model", "manufacture_year", "color", "registration_number"}

func completeVehicle(details map[string]string) bool {
	year, err := strconv.Atoi(details["manufacture_year"])
	if err != nil || year < 1900 || year > time.Now().Year()+1 || !onboardingRegistration.MatchString(details["registration_number"]) {
		return false
	}
	for _, key := range []string{"make", "model", "color"} {
		if !validProfileName(details[key]) || len(details[key]) > 80 {
			return false
		}
	}
	return true
}

func (s *Server) saveOnboarding(ctx context.Context, body input, bearer string) (int, any, error) {
	return s.withOnboarding(ctx, bearer, func(tx pgx.Tx, id int64, current onboardingApplication) error {
		if body.OnboardingDraft == nil {
			return invalid
		}
		if current.SubmittedAt != nil || body.OnboardingDraft["revision"] != current.Draft["revision"] {
			return onboardingConflict
		}
		details := make(map[string]string)
		for key, value := range body.OnboardingDraft {
			switch key {
			case "revision", "identity_saved", "vehicle_saved":
				continue // Server-derived values.
			case "step", "legal_name", "make", "model", "manufacture_year", "color", "registration_number":
			default:
				return invalid
			}
			value = strings.TrimSpace(value)
			if len(value) > 150 || strings.ContainsRune(value, 0) {
				return invalid
			}
			if key == "registration_number" {
				value = strings.ToUpper(value)
			}
			details[key] = value
		}
		step, err := strconv.Atoi(details["step"])
		if err != nil || step < 0 || step > 3 {
			return invalid
		}
		priorStep, _ := strconv.Atoi(current.Draft["step"])
		if step > priorStep+1 ||
			(step >= 1 && !validProfileName(details["legal_name"])) ||
			(step >= 2 && !completeVehicle(details)) {
			return onboardingIncomplete
		}
		details["step"] = strconv.Itoa(step)
		changedIdentity := details["legal_name"] != current.Draft["legal_name"]
		changedVehicle := false
		for _, key := range onboardingVehicleFields {
			changedVehicle = changedVehicle || details[key] != current.Draft[key]
		}
		if step == 3 && (changedIdentity || changedVehicle || current.Draft["identity_saved"] != "true" || current.Draft["vehicle_saved"] != "true") {
			return onboardingIncomplete
		}
		if current.Version == 0 {
			_, err = tx.Exec(ctx, `INSERT INTO driver_onboarding_applications(user_id,details) VALUES($1,$2)`, id, details)
			return err
		}
		_, err = tx.Exec(ctx, `UPDATE driver_onboarding_applications SET details=$3,
 cnic_front=CASE WHEN $4 THEN NULL ELSE cnic_front END,cnic_back=CASE WHEN $4 THEN NULL ELSE cnic_back END,
 registration_image=CASE WHEN $5 THEN NULL ELSE registration_image END,insurance_image=CASE WHEN $5 THEN NULL ELSE insurance_image END,
 draft_revision=draft_revision+1,updated_at=clock_timestamp()
 WHERE user_id=$1 AND application_version=$2 AND submitted_at IS NULL`, id, current.Version, details, changedIdentity, changedVehicle)
		return err
	})
}

func (s *Server) saveOnboardingIdentity(ctx context.Context, body input, bearer string) (int, any, error) {
	doc := body.OnboardingIdentity
	return s.saveOnboardingDocuments(ctx, bearer, doc.Revision, false, doc.Front, doc.Back)
}

func (s *Server) saveOnboardingVehicle(ctx context.Context, body input, bearer string) (int, any, error) {
	doc := body.OnboardingVehicle
	return s.saveOnboardingDocuments(ctx, bearer, doc.Revision, true, doc.Registration, doc.Insurance)
}

func (s *Server) saveOnboardingDocuments(ctx context.Context, bearer, revision string, vehicle bool, first, second []byte) (int, any, error) {
	if s.driverDocumentCipher == nil {
		return 0, nil, busy
	}
	select {
	case s.driverDocumentSlots <- struct{}{}:
		defer func() { <-s.driverDocumentSlots }()
	default:
		return 0, nil, busy
	}
	limit, kind, firstSide, secondSide := maxDriverImage, "identity", "front", "back"
	query := `UPDATE driver_onboarding_applications SET cnic_front=$3,cnic_back=$4,
 draft_revision=draft_revision+1,updated_at=clock_timestamp() WHERE user_id=$1 AND application_version=$2 AND submitted_at IS NULL`
	if vehicle {
		limit, kind, firstSide, secondSide = maxVehicleDocument, "vehicle", "registration", "insurance"
		query = `UPDATE driver_onboarding_applications SET registration_image=$3,insurance_image=$4,
 draft_revision=draft_revision+1,updated_at=clock_timestamp() WHERE user_id=$1 AND application_version=$2 AND submitted_at IS NULL`
	}
	first, err := normalizeDocumentImage(first, limit)
	if err != nil {
		return 0, nil, err
	}
	second, err = normalizeDocumentImage(second, limit)
	if err != nil {
		return 0, nil, err
	}
	return s.withOnboarding(ctx, bearer, func(tx pgx.Tx, id int64, current onboardingApplication) error {
		if current.SubmittedAt != nil || revision != current.Draft["revision"] {
			return onboardingConflict
		}
		if (current.Draft["step"] != "2" && current.Draft["step"] != "3") ||
			!validProfileName(current.Draft["legal_name"]) || !completeVehicle(current.Draft) {
			return onboardingIncomplete
		}
		if err := allow(ctx, tx, fmt.Sprintf("onboarding/%s/%d", kind, id), 24*time.Hour, 5); err != nil {
			return err
		}
		associated := fmt.Sprintf("driver-onboarding:%d:%d:%s:", id, current.Version, kind)
		_, err := tx.Exec(ctx, query, id, current.Version,
			s.driverDocumentCipher.Seal(nil, nil, first, []byte(associated+firstSide)),
			s.driverDocumentCipher.Seal(nil, nil, second, []byte(associated+secondSide)))
		return err
	})
}

func (s *Server) submitOnboarding(ctx context.Context, body input, bearer string) (int, any, error) {
	return s.withOnboarding(ctx, bearer, func(tx pgx.Tx, id int64, current onboardingApplication) error {
		if body.OnboardingSubmit.Revision != current.Draft["revision"] {
			return onboardingConflict
		}
		if current.SubmittedAt != nil {
			return nil
		} // Retry after an uncertain response.
		if current.Draft["step"] != "3" || !validProfileName(current.Draft["legal_name"]) ||
			!completeVehicle(current.Draft) || current.Draft["identity_saved"] != "true" || current.Draft["vehicle_saved"] != "true" {
			return onboardingIncomplete
		}
		_, err := tx.Exec(ctx, `UPDATE driver_onboarding_applications SET submitted_at=clock_timestamp(),updated_at=clock_timestamp()
 WHERE user_id=$1 AND application_version=$2 AND submitted_at IS NULL`, id, current.Version)
		return err
	})
}
