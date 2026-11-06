package auth

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

var staleApplication = errors.New("stale_application")

type applicationSubmission struct {
	IdentityVersion int    `json:"identity_version"`
	VehicleID       string `json:"vehicle_id"`
	VehicleVersion  int    `json:"vehicle_version"`
	DraftRevision   string `json:"draft_revision"`
}

type driverApplication struct {
	ID          int64             `json:"id,omitempty"`
	Status      string            `json:"status"`
	Reason      string            `json:"reason,omitempty"`
	SubmittedAt *time.Time        `json:"submitted_at,omitempty"`
	Draft       map[string]string `json:"draft"`
}

func loadApplicationDraft(ctx context.Context, tx pgx.Tx, id int64) (map[string]string, error) {
	draft := make(map[string]string)
	var revision string
	err := tx.QueryRow(ctx, `SELECT details,revision::text FROM driver_application_drafts WHERE user_id=$1`, id).Scan(&draft, &revision)
	if errors.Is(err, pgx.ErrNoRows) {
		draft["revision"] = "0"
		return draft, nil
	}
	if err != nil {
		return nil, err
	}
	draft["revision"] = revision
	return draft, nil
}

func writeApplicationDraft(ctx context.Context, tx pgx.Tx, id int64, draft map[string]string) error {
	delete(draft, "revision")
	var revision string
	err := tx.QueryRow(ctx, `INSERT INTO driver_application_drafts(user_id,details) VALUES($1,$2)
 ON CONFLICT (user_id) DO UPDATE SET details=excluded.details,revision=driver_application_drafts.revision+1
 RETURNING revision::text`, id, draft).Scan(&revision)
	if err == nil {
		draft["revision"] = revision
	}
	return err
}

func matchDraft(ctx context.Context, tx pgx.Tx, id int64, revision string, fields map[string]string) (map[string]string, error) {
	draft, err := loadApplicationDraft(ctx, tx, id)
	if err != nil {
		return nil, err
	}
	if revision == "0" || draft["revision"] != revision {
		return nil, staleApplication
	}
	for key, value := range fields {
		saved := strings.TrimSpace(draft[key])
		if key == "registration_number" {
			saved = strings.ToUpper(saved)
		}
		if saved != value {
			return nil, staleApplication
		}
	}
	return draft, nil
}

func readDriverApplication(ctx context.Context, tx pgx.Tx, id int64) (driverApplication, error) {
	result := driverApplication{Status: "draft"}
	err := tx.QueryRow(ctx, `SELECT id,status,reason,submitted_at FROM current_driver_applications WHERE user_id=$1`, id).
		Scan(&result.ID, &result.Status, &result.Reason, &result.SubmittedAt)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return result, err
	}
	result.Draft, err = loadApplicationDraft(ctx, tx, id)
	return result, err
}

func (s *Server) withDriverApplication(ctx context.Context, bearer string, change func(pgx.Tx, int64) error) (int, any, error) {
	digest := tokenDigest(bearer, "at_")
	if digest == nil {
		return 0, nil, unauthorized
	}
	var result driverApplication
	err := pgx.BeginFunc(ctx, s.db, func(tx pgx.Tx) error {
		id, err := lockSessionAccount(ctx, tx, digest)
		if err != nil {
			return err
		}
		if change != nil {
			if err := change(tx, id); err != nil {
				return err
			}
		}
		result, err = readDriverApplication(ctx, tx, id)
		return err
	})
	return 200, result, err
}

func (s *Server) driverApplication(ctx context.Context, _ input, bearer string) (int, any, error) {
	return s.withDriverApplication(ctx, bearer, nil)
}

func (s *Server) saveDriverApplicationDraft(ctx context.Context, body input, bearer string) (int, any, error) {
	return s.withDriverApplication(ctx, bearer, func(tx pgx.Tx, id int64) error {
		draft := body.ApplicationDraft
		if draft == nil {
			return invalid
		}
		for key, value := range draft {
			switch key {
			case "legal_name", "make", "model", "manufacture_year", "color", "registration_number", "vehicle_id", "identity_version", "vehicle_version", "step", "revision":
			default:
				return invalid
			}
			if len(value) > 150 || strings.ContainsRune(value, 0) {
				return invalid
			}
		}
		current, err := loadApplicationDraft(ctx, tx, id)
		if err != nil {
			return err
		}
		expected := draft["revision"]
		if expected == "" {
			expected = "0"
		}
		if current["revision"] != expected {
			return staleApplication
		}
		// Only an upload transaction can attach a document version.
		if draft["identity_version"] != current["identity_version"] || draft["legal_name"] != current["legal_name"] {
			delete(draft, "identity_version")
		}
		if draft["vehicle_version"] != current["vehicle_version"] || draft["vehicle_id"] != current["vehicle_id"] ||
			draft["make"] != current["make"] || draft["model"] != current["model"] ||
			draft["manufacture_year"] != current["manufacture_year"] || draft["color"] != current["color"] ||
			draft["registration_number"] != current["registration_number"] {
			delete(draft, "vehicle_version")
		}
		return writeApplicationDraft(ctx, tx, id, draft)
	})
}

func (s *Server) submitDriverApplication(ctx context.Context, body input, bearer string) (int, any, error) {
	ref := body.ApplicationSubmission
	return s.withDriverApplication(ctx, bearer, func(tx pgx.Tx, id int64) error {
		vehicleID, err := strconv.ParseInt(ref.VehicleID, 10, 64)
		if err != nil || vehicleID < 1 || ref.IdentityVersion < 1 || ref.VehicleVersion < 1 || ref.DraftRevision == "" {
			return invalid
		}
		var current applicationSubmission
		err = tx.QueryRow(ctx, `SELECT identity_version,vehicle_id::text,vehicle_version FROM current_driver_applications WHERE user_id=$1`, id).
			Scan(&current.IdentityVersion, &current.VehicleID, &current.VehicleVersion)
		if err == nil && current.IdentityVersion == ref.IdentityVersion && current.VehicleID == ref.VehicleID && current.VehicleVersion == ref.VehicleVersion {
			return nil // Retry of the same explicit submission.
		}
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		draft, err := matchDraft(ctx, tx, id, ref.DraftRevision, map[string]string{
			"identity_version": strconv.Itoa(ref.IdentityVersion), "vehicle_id": ref.VehicleID, "vehicle_version": strconv.Itoa(ref.VehicleVersion),
		})
		if err != nil {
			return err
		}
		var inserted int64
		err = tx.QueryRow(ctx, `INSERT INTO driver_applications(user_id,identity_version,vehicle_id,vehicle_version)
 SELECT $1,d.version,v.vehicle_id,v.version
 FROM (SELECT version,cnic_front FROM driver_identity_submissions WHERE user_id=$1 ORDER BY version DESC LIMIT 1) d
 CROSS JOIN (SELECT vehicle_id,version,registration_image FROM driver_vehicle_submissions
             WHERE user_id=$1 AND vehicle_id=$3 ORDER BY version DESC LIMIT 1) v
 WHERE d.version=$2 AND v.version=$4 AND d.cnic_front IS NOT NULL AND v.registration_image IS NOT NULL
 ON CONFLICT DO NOTHING RETURNING id`, id, ref.IdentityVersion, vehicleID, ref.VehicleVersion).Scan(&inserted)
		if errors.Is(err, pgx.ErrNoRows) {
			return staleApplication
		}
		if err != nil {
			return err
		}
		delete(draft, "step")
		return writeApplicationDraft(ctx, tx, id, draft)
	})
}
