package driver

import (
	"context"
	"errors"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/sayyarahmad1995/higo-backend/internal/auth"
)

var (
	onboardingConflict     = errors.New("onboarding_conflict")
	onboardingIncomplete   = errors.New("onboarding_incomplete")
	onboardingRegistration = regexp.MustCompile(`^[A-Z0-9][A-Z0-9 -]{1,23}$`)
)

type Document struct {
	Revision string `json:"draft_revision"`
	Kind     string `json:"kind"`
	Image    []byte `json:"image"`
}
type Submission struct {
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

func (s *Service) withOnboarding(ctx context.Context, proof auth.AccessProof, change func(pgx.Tx, int64, onboardingApplication) error) (any, error) {
	if err := proof.Validate(); err != nil {
		return nil, err
	}
	var result onboardingApplication
	err := pgx.BeginFunc(ctx, s.db, func(tx pgx.Tx) error {
		id, err := proof.LockAccount(ctx, tx)
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
	return result, err
}

func (s *Service) GetOnboarding(ctx context.Context, proof auth.AccessProof) (any, error) {
	return s.withOnboarding(ctx, proof, nil)
}

func completeVehicle(details map[string]string) bool {
	year, err := strconv.Atoi(details["manufacture_year"])
	if err != nil || year < 1900 || year > time.Now().Year()+1 || !onboardingRegistration.MatchString(details["registration_number"]) {
		return false
	}
	for _, key := range []string{"make", "model", "color"} {
		if !validDriverName(details[key]) || len(details[key]) > 80 {
			return false
		}
	}
	return true
}

func (s *Service) SaveOnboarding(ctx context.Context, proof auth.AccessProof, draft map[string]string) (any, error) {
	return s.withOnboarding(ctx, proof, func(tx pgx.Tx, id int64, current onboardingApplication) error {
		if draft == nil {
			return invalid
		}
		if current.SubmittedAt != nil || draft["revision"] != current.Draft["revision"] {
			return onboardingConflict
		}
		details := make(map[string]string)
		for key, value := range draft {
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
		today := onboardingToday()
		if step > priorStep+1 ||
			(step >= 1 && (!completeDriver(details, today) || !hasDocument(current.Documents, "selfie"))) ||
			(step >= 2 && !completeVehicle(details)) || !validDraftExpiry(current.Draft, details, today) {
			return onboardingIncomplete
		}
		details["step"] = strconv.Itoa(step)
		stale := staleOnboardingEvidence(current.Draft, details)
		if step == 3 && (len(stale) != 0 || !completeEvidence(details, current.Documents, today)) {
			return onboardingIncomplete
		}
		if hasDocument(stale, "selfie") {
			details["step"] = "0"
		}
		if current.Version == 0 {
			_, err = tx.Exec(ctx, `INSERT INTO driver_onboarding_applications(user_id,details) VALUES($1,$2)`, id, details)
			return err
		}
		if len(stale) != 0 {
			if _, err := tx.Exec(ctx, `DELETE FROM driver_onboarding_documents
 WHERE user_id=$1 AND application_version=$2 AND kind=ANY($3::text[])`, id, current.Version, stale); err != nil {
				return err
			}
		}
		_, err = tx.Exec(ctx, `UPDATE driver_onboarding_applications SET details=$3,
 draft_revision=draft_revision+1,updated_at=clock_timestamp()
 WHERE user_id=$1 AND application_version=$2 AND submitted_at IS NULL`, id, current.Version, details)
		return err
	})
}

func (s *Service) SubmitOnboarding(ctx context.Context, proof auth.AccessProof, submission Submission) (any, error) {
	return s.withOnboarding(ctx, proof, func(tx pgx.Tx, id int64, current onboardingApplication) error {
		if submission.Revision != current.Draft["revision"] {
			return onboardingConflict
		}
		if current.SubmittedAt != nil {
			return nil
		} // Retry after an uncertain response.
		if !submission.Confirmed || current.Draft["step"] != "3" || !completeDriver(current.Draft, onboardingToday()) ||
			!completeVehicle(current.Draft) || !completeEvidence(current.Draft, current.Documents, onboardingToday()) {
			return onboardingIncomplete
		}
		_, err := tx.Exec(ctx, `UPDATE driver_onboarding_applications SET submitted_at=clock_timestamp(),updated_at=clock_timestamp()
 WHERE user_id=$1 AND application_version=$2 AND submitted_at IS NULL`, id, current.Version)
		return err
	})
}

// validDriverName applies the existing byte and NUL bounds to Driver fields.
func validDriverName(name string) bool {
	return len(name) > 0 && len(name) <= 150 && !strings.ContainsRune(name, 0)
}
