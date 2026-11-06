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

const maxVehicleDocument = 2 * 1024 * 1024
const vehicleColumns = `vehicle_id,version,make,model,manufacture_year,color,registration_number,status,submitted_at`
const purgeSupersededVehicleDocuments = `UPDATE driver_vehicle_submissions v SET registration_image=NULL,insurance_image=NULL
 WHERE (v.user_id,v.vehicle_id,v.version) IN (SELECT old.user_id,old.vehicle_id,old.version FROM driver_vehicle_submissions old
 WHERE old.registration_image IS NOT NULL AND old.submitted_at<now()-interval '30 days'
 AND EXISTS(SELECT 1 FROM driver_vehicle_submissions newer WHERE newer.user_id=old.user_id AND newer.vehicle_id=old.vehicle_id AND newer.version>old.version)
 ORDER BY old.submitted_at LIMIT 500)`

var (
	identityRequired    = errors.New("driver_identity_required")
	vehicleNotFound     = errors.New("vehicle_not_found")
	registrationPattern = regexp.MustCompile(`^[A-Z0-9][A-Z0-9 -]{1,23}$`)
)

type vehicleSubmissionInput struct {
	VehicleID         string `json:"vehicle_id"`
	Make              string `json:"make"`
	Model             string `json:"model"`
	Year              string `json:"manufacture_year"`
	Color             string `json:"color"`
	Registration      string `json:"registration_number"`
	RegistrationImage []byte `json:"registration_image"`
	InsuranceImage    []byte `json:"insurance_image"`
}

type vehicleSubmission struct {
	VehicleID    int64     `json:"vehicle_id"`
	Version      int       `json:"version"`
	Make         string    `json:"make"`
	Model        string    `json:"model"`
	Year         int       `json:"manufacture_year"`
	Color        string    `json:"color"`
	Registration string    `json:"registration_number"`
	Status       string    `json:"status"`
	SubmittedAt  time.Time `json:"submitted_at"`
}

func scanVehicle(row pgx.Row) (vehicleSubmission, error) {
	var v vehicleSubmission
	err := row.Scan(&v.VehicleID, &v.Version, &v.Make, &v.Model, &v.Year, &v.Color, &v.Registration, &v.Status, &v.SubmittedAt)
	return v, err
}

func (s *Server) vehicles(ctx context.Context, _ input, bearer string) (int, any, error) {
	digest := tokenDigest(bearer, "at_")
	if digest == nil {
		return 0, nil, unauthorized
	}
	var vehicles []vehicleSubmission
	err := s.db.QueryRow(ctx, `SELECT COALESCE((SELECT jsonb_agg(v ORDER BY v.vehicle_id) FROM
 (SELECT DISTINCT ON (vehicle_id) `+vehicleColumns+` FROM driver_vehicle_submissions
 WHERE user_id=s.user_id ORDER BY vehicle_id,version DESC) v),'[]'::jsonb) FROM auth_sessions s
 WHERE s.access_digest=$1 AND s.revoked_at IS NULL AND s.access_expires_at>now() AND s.expires_at>now()`, digest).Scan(&vehicles)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, nil, unauthorized
	}
	return 200, map[string]any{"vehicles": vehicles}, err
}

func (s *Server) submitVehicle(ctx context.Context, body input, bearer string) (int, any, error) {
	if s.driverDocumentCipher == nil {
		return 0, nil, busy
	}
	digest := tokenDigest(bearer, "at_")
	if digest == nil {
		return 0, nil, unauthorized
	}
	f := body.VehicleSubmission
	v := vehicleSubmission{Make: strings.TrimSpace(f.Make), Model: strings.TrimSpace(f.Model), Color: strings.TrimSpace(f.Color), Registration: strings.ToUpper(strings.TrimSpace(f.Registration))}
	year, err := strconv.Atoi(f.Year)
	if err != nil || year < 1900 || year > time.Now().Year()+1 || !registrationPattern.MatchString(v.Registration) {
		return 0, nil, invalid
	}
	v.Year = year
	for _, value := range []string{v.Make, v.Model, v.Color} {
		if !validProfileName(value) || len(value) > 80 {
			return 0, nil, invalid
		}
	}
	if f.VehicleID != "" {
		v.VehicleID, err = strconv.ParseInt(f.VehicleID, 10, 64)
		if err != nil || v.VehicleID < 1 {
			return 0, nil, invalid
		}
	}
	select {
	case s.driverDocumentSlots <- struct{}{}:
		defer func() { <-s.driverDocumentSlots }()
	default:
		return 0, nil, busy
	}
	registration, err := normalizeDocumentImage(f.RegistrationImage, maxVehicleDocument)
	if err != nil {
		return 0, nil, err
	}
	insurance, err := normalizeDocumentImage(f.InsuranceImage, maxVehicleDocument)
	if err != nil {
		return 0, nil, err
	}
	err = pgx.BeginFunc(ctx, s.db, func(tx pgx.Tx) error {
		id, err := lockSessionAccount(ctx, tx, digest)
		if err != nil {
			return err
		}
		var exists bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM driver_identity_submissions WHERE user_id=$1)`, id).Scan(&exists); err != nil {
			return err
		}
		if !exists {
			return identityRequired
		}
		if err := allow(ctx, tx, fmt.Sprintf("vehicle/submission/%d", id), 24*time.Hour, 5); err != nil {
			return err
		}
		var total, retained, vehicleCount int
		if err := tx.QueryRow(ctx, `SELECT count(*),count(registration_image),count(DISTINCT vehicle_id) FROM driver_vehicle_submissions WHERE user_id=$1`, id).Scan(&total, &retained, &vehicleCount); err != nil {
			return err
		}
		if total >= 250 || retained >= 20 || (v.VehicleID == 0 && vehicleCount >= 10) {
			return documentQuota
		}
		if v.VehicleID == 0 {
			if err := tx.QueryRow(ctx, `SELECT nextval('driver_vehicle_id_seq')`).Scan(&v.VehicleID); err != nil {
				return err
			}
			v.Version = 1
		} else {
			if err := tx.QueryRow(ctx, `SELECT COALESCE(max(version),0)+1 FROM driver_vehicle_submissions WHERE user_id=$1 AND vehicle_id=$2`, id, v.VehicleID).Scan(&v.Version); err != nil {
				return err
			}
			if v.Version == 1 {
				return vehicleNotFound
			}
		}
		associated := fmt.Sprintf("driver-vehicle:%d:%d:%d:", id, v.VehicleID, v.Version)
		v, err = scanVehicle(tx.QueryRow(ctx, `INSERT INTO driver_vehicle_submissions(user_id,vehicle_id,version,make,model,manufacture_year,color,registration_number,registration_image,insurance_image)
 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING `+vehicleColumns, id, v.VehicleID, v.Version, v.Make, v.Model, v.Year, v.Color, v.Registration,
			s.driverDocumentCipher.Seal(nil, nil, registration, []byte(associated+"registration")), s.driverDocumentCipher.Seal(nil, nil, insurance, []byte(associated+"insurance"))))
		return err
	})
	return 201, v, err
}
