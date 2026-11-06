package auth

import (
	"context"
	"errors"
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
 WHERE submitted_at IS NULL AND EXISTS (SELECT 1 FROM driver_onboarding_documents d WHERE (d.user_id,d.application_version)=(driver_onboarding_applications.user_id,driver_onboarding_applications.application_version))
 AND updated_at < now()-interval '30 days' ORDER BY updated_at LIMIT 500 FOR UPDATE SKIP LOCKED
), removed AS (
 DELETE FROM driver_onboarding_documents d USING expired e WHERE (d.user_id,d.application_version)=(e.user_id,e.application_version)
)
UPDATE driver_onboarding_applications a SET cnic_front=NULL,cnic_back=NULL,
 registration_image=NULL,insurance_image=NULL,draft_revision=draft_revision+1,
 details=jsonb_set(details,'{step}','"0"')
 FROM expired e WHERE (a.user_id,a.application_version)=(e.user_id,e.application_version)`

type onboardingDocument struct {
	Revision string `json:"draft_revision"`
	Kind     string `json:"kind"`
	Image    []byte `json:"image"`
}
type onboardingSubmission struct {
	Revision  string `json:"draft_revision"`
	Confirmed bool   `json:"confirmed"`
}
type onboardingApplication struct {
	Status      string            `json:"status"`
	Version     int               `json:"application_version,omitempty"`
	SubmittedAt *time.Time        `json:"submitted_at,omitempty"`
	Draft       map[string]string `json:"draft"`
	Documents   []string          `json:"documents"`
}

func readOnboarding(ctx context.Context, tx pgx.Tx, id int64) (onboardingApplication, error) {
	result := onboardingApplication{Status: "draft", Draft: map[string]string{}, Documents: []string{}}
	var revision string

	err := tx.QueryRow(ctx, `SELECT application_version,draft_revision::text,details,
 submitted_at, ARRAY(SELECT kind FROM driver_onboarding_documents d WHERE (d.user_id,d.application_version)=(a.user_id,a.application_version) ORDER BY kind)
 FROM driver_onboarding_applications a WHERE user_id=$1 ORDER BY application_version DESC LIMIT 1 FOR UPDATE`, id).
		Scan(&result.Version, &revision, &result.Draft, &result.SubmittedAt, &result.Documents)
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
			case "revision":
				continue // Server-derived values.
			case "step", "legal_name", "make", "model", "manufacture_year", "color", "registration_number", "date_of_birth", "cnic_number", "cnic_validity", "cnic_expiry", "license_expiry", "registration_validity", "registration_expiry", "additional_validity", "additional_expiry":
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
			(step >= 1 && (!completeDriver(details, onboardingToday()) || !hasDocument(current.Documents, "selfie"))) ||
			(step >= 2 && !completeVehicle(details)) {
			return onboardingIncomplete
		}
		details["step"] = strconv.Itoa(step)
		if step == 3 && !completeEvidence(details, current.Documents, onboardingToday()) {
			return onboardingIncomplete
		}
		if current.Version == 0 {
			_, err = tx.Exec(ctx, `INSERT INTO driver_onboarding_applications(user_id,details) VALUES($1,$2)`, id, details)
			return err
		}
		_, err = tx.Exec(ctx, `UPDATE driver_onboarding_applications SET details=$3,
 draft_revision=draft_revision+1,updated_at=clock_timestamp()
 WHERE user_id=$1 AND application_version=$2 AND submitted_at IS NULL`, id, current.Version, details)
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
		if !body.OnboardingSubmit.Confirmed || current.Draft["step"] != "3" || !completeDriver(current.Draft, onboardingToday()) ||
			!completeVehicle(current.Draft) || !completeEvidence(current.Draft, current.Documents, onboardingToday()) {
			return onboardingIncomplete
		}
		_, err := tx.Exec(ctx, `UPDATE driver_onboarding_applications SET submitted_at=clock_timestamp(),updated_at=clock_timestamp()
 WHERE user_id=$1 AND application_version=$2 AND submitted_at IS NULL`, id, current.Version)
		return err
	})
}
