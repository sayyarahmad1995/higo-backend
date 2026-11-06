package auth

import (
	"context"
	"errors"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"
)

var staleApplication = errors.New("stale_application")

type applicationSubmission struct {
	IdentityVersion int    `json:"identity_version"`
	VehicleID       string `json:"vehicle_id"`
	VehicleVersion  int    `json:"vehicle_version"`
}

type driverApplication struct {
	Status string            `json:"status"`
	Reason string            `json:"reason,omitempty"`
	Draft  map[string]string `json:"draft"`
}

func readDriverApplication(ctx context.Context, tx pgx.Tx, id int64) (driverApplication, error) {
	result := driverApplication{Draft: make(map[string]string)}
	err := tx.QueryRow(ctx, `SELECT COALESCE(a.status,'draft'),COALESCE(a.reason,''),COALESCE(d.details,'{}'::jsonb)
 FROM auth_users u LEFT JOIN current_driver_applications a ON a.user_id=u.id
 LEFT JOIN driver_application_drafts d ON d.user_id=u.id WHERE u.id=$1`, id).
		Scan(&result.Status, &result.Reason, &result.Draft)
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
		if body.ApplicationDraft == nil {
			return invalid
		}
		for key, value := range body.ApplicationDraft {
			switch key {
			case "legal_name", "make", "model", "manufacture_year", "color", "registration_number", "vehicle_id", "identity_version", "vehicle_version", "step":
			default:
				return invalid
			}
			if len(value) > 150 || strings.ContainsRune(value, 0) {
				return invalid
			}
		}
		_, err := tx.Exec(ctx, `INSERT INTO driver_application_drafts(user_id,details) VALUES($1,$2)
 ON CONFLICT (user_id) DO UPDATE SET details=excluded.details`, id, body.ApplicationDraft)
		return err
	})
}

func (s *Server) submitDriverApplication(ctx context.Context, body input, bearer string) (int, any, error) {
	ref := body.ApplicationSubmission
	return s.withDriverApplication(ctx, bearer, func(tx pgx.Tx, id int64) error {
		vehicleID, err := strconv.ParseInt(ref.VehicleID, 10, 64)
		if err != nil || vehicleID < 1 || ref.IdentityVersion < 1 || ref.VehicleVersion < 1 {
			return invalid
		}
		var current applicationSubmission
		err = tx.QueryRow(ctx, `SELECT identity_version,vehicle_id::text,vehicle_version FROM current_driver_applications WHERE user_id=$1`, id).
			Scan(&current.IdentityVersion, &current.VehicleID, &current.VehicleVersion)
		if err == nil && current == ref {
			return nil // Retry of the same explicit submission.
		}
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		var inserted int64
		err = tx.QueryRow(ctx, `INSERT INTO driver_applications(user_id,identity_version,vehicle_id,vehicle_version)
 SELECT $1,d.version,v.vehicle_id,v.version
 FROM (SELECT version,cnic_front FROM driver_identity_submissions WHERE user_id=$1 ORDER BY version DESC LIMIT 1) d
 CROSS JOIN (SELECT vehicle_id,version,registration_image FROM driver_vehicle_submissions
             WHERE user_id=$1 AND vehicle_id=$3 ORDER BY version DESC LIMIT 1) v
 WHERE d.version=$2 AND v.version=$4 AND d.cnic_front IS NOT NULL AND v.registration_image IS NOT NULL
 AND NOT EXISTS (
   SELECT 1 FROM driver_applications old
   JOIN driver_application_checks c ON c.application_id=old.id AND c.decision='rejected'
   WHERE old.user_id=$1 AND ((c.kind='identity' AND old.identity_version=d.version)
      OR (c.kind='vehicle' AND old.vehicle_id=v.vehicle_id AND old.vehicle_version=v.version))
 )
 ON CONFLICT DO NOTHING RETURNING id`, id, ref.IdentityVersion, vehicleID, ref.VehicleVersion).Scan(&inserted)
		if errors.Is(err, pgx.ErrNoRows) {
			return staleApplication
		}
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `UPDATE driver_application_drafts SET details=details-'step' WHERE user_id=$1`, id)
		return err
	})
}
