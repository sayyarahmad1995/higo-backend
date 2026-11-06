package auth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/jackc/pgx/v5"
)

var (
	reviewerRequired          = errors.New("reviewer_required")
	staleReview               = errors.New("stale_review")
	reviewDocumentUnavailable = errors.New("review_document_unavailable")
)

type reviewInput struct {
	Kind      string `json:"kind"`
	UserID    int64  `json:"user_id"`
	VehicleID int64  `json:"vehicle_id"`
	Version   int    `json:"version"`
	Side      string `json:"side"`
	Decision  string `json:"decision"`
	Reason    string `json:"reason"`
}

type reviewSummary struct {
	Kind      string `json:"kind"`
	UserID    int64  `json:"user_id"`
	VehicleID int64  `json:"vehicle_id"`
	Version   int    `json:"version"`
	Label     string `json:"label"`
}

func (r reviewInput) validTarget() bool {
	return r.UserID > 0 && r.Version > 0 && ((r.Kind == "identity" && r.VehicleID == 0) || (r.Kind == "vehicle" && r.VehicleID > 0))
}

func (s *Server) withReviewer(ctx context.Context, bearer string, target int64, run func(pgx.Tx, int64) error) error {
	digest := tokenDigest(bearer, "at_")
	if digest == nil {
		return unauthorized
	}
	return pgx.BeginFunc(ctx, s.db, func(tx pgx.Tx) error {
		// Reviewers may also be applicants. Lock both account rows in ID order
		// before revalidating the session and acquiring the reviewer grant.
		if target > 0 {
			var actor int64
			err := tx.QueryRow(ctx, `SELECT s.user_id FROM auth_sessions s
 WHERE s.access_digest=$1 AND s.revoked_at IS NULL
 AND s.access_expires_at>clock_timestamp() AND s.expires_at>clock_timestamp()`, digest).Scan(&actor)
			if errors.Is(err, pgx.ErrNoRows) {
				return unauthorized
			}
			if err != nil {
				return err
			}
			var allowed bool
			err = tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM onboarding_reviewers WHERE user_id=$1)`, actor).Scan(&allowed)
			if err != nil {
				return err
			}
			if !allowed {
				return reviewerRequired
			}
			_, err = tx.Exec(ctx, `SELECT id FROM auth_users WHERE id IN ($1,$2) ORDER BY id FOR UPDATE`, target, actor)
			if err != nil {
				return err
			}
		}
		id, err := lockSessionAccount(ctx, tx, digest)
		if err != nil {
			return err
		}
		var allowed int64
		err = tx.QueryRow(ctx, `SELECT user_id FROM onboarding_reviewers WHERE user_id=$1 FOR SHARE`, id).Scan(&allowed)
		if errors.Is(err, pgx.ErrNoRows) {
			return reviewerRequired
		}
		if err != nil {
			return err
		}
		return run(tx, id)
	})
}

func (s *Server) pendingReviews(ctx context.Context, _ input, bearer string) (int, any, error) {
	items := make([]reviewSummary, 0)
	err := s.withReviewer(ctx, bearer, 0, func(tx pgx.Tx, reviewer int64) error {
		rows, err := tx.Query(ctx, `SELECT kind,user_id,vehicle_id,version,label FROM (
 SELECT 'identity' AS kind,d.user_id,0::bigint AS vehicle_id,d.version,d.legal_name AS label,d.submitted_at
 FROM driver_identity_submissions d WHERE d.user_id<>$1 AND d.status='submitted' AND NOT EXISTS
 (SELECT 1 FROM driver_identity_submissions newer WHERE newer.user_id=d.user_id AND newer.version>d.version)
 UNION ALL SELECT 'vehicle',v.user_id,v.vehicle_id,v.version,v.make||' '||v.model||' · '||v.registration_number,v.submitted_at
 FROM driver_vehicle_submissions v WHERE v.user_id<>$1 AND v.status='submitted' AND NOT EXISTS
 (SELECT 1 FROM driver_vehicle_submissions newer WHERE newer.user_id=v.user_id AND newer.vehicle_id=v.vehicle_id AND newer.version>v.version)
 ) pending ORDER BY submitted_at,user_id,kind,vehicle_id LIMIT 100`, reviewer)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var item reviewSummary
			if err := rows.Scan(&item.Kind, &item.UserID, &item.VehicleID, &item.Version, &item.Label); err != nil {
				return err
			}
			items = append(items, item)
		}
		return rows.Err()
	})
	return 200, map[string]any{"submissions": items}, err
}

// Submission writers acquire the same account lock before allocating a version.
func lockReviewTarget(ctx context.Context, tx pgx.Tx, r reviewInput, reviewer int64) error {
	if reviewer == r.UserID {
		return reviewerRequired
	}
	var owner int64
	err := tx.QueryRow(ctx, `SELECT id FROM auth_users WHERE id=$1 FOR UPDATE`, r.UserID).Scan(&owner)
	if errors.Is(err, pgx.ErrNoRows) {
		return staleReview
	}
	if err != nil {
		return err
	}
	var version int
	var status string
	if r.Kind == "identity" {
		err = tx.QueryRow(ctx, `SELECT version,status FROM driver_identity_submissions WHERE user_id=$1 ORDER BY version DESC LIMIT 1`, r.UserID).Scan(&version, &status)
	} else {
		err = tx.QueryRow(ctx, `SELECT version,status FROM driver_vehicle_submissions WHERE user_id=$1 AND vehicle_id=$2 ORDER BY version DESC LIMIT 1`, r.UserID, r.VehicleID).Scan(&version, &status)
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return staleReview
	}
	if err != nil {
		return err
	}
	if version != r.Version || status != "submitted" {
		return staleReview
	}
	return nil
}

func (s *Server) reviewDocument(ctx context.Context, body input, bearer string) (int, any, error) {
	r := body.Review
	var data []byte
	var mime string
	err := s.withReviewer(ctx, bearer, r.UserID, func(tx pgx.Tx, reviewer int64) error {
		if !r.validTarget() {
			return invalid
		}
		if err := lockReviewTarget(ctx, tx, r, reviewer); err != nil {
			return err
		}
		if s.driverDocumentCipher == nil {
			return busy
		}
		var ciphertext []byte
		var associated string
		if r.Kind == "identity" {
			if r.Side != "front" && r.Side != "back" {
				return invalid
			}
			if err := tx.QueryRow(ctx, `SELECT CASE WHEN $3='front' THEN cnic_front ELSE cnic_back END FROM driver_identity_submissions
 WHERE user_id=$1 AND version=$2`, r.UserID, r.Version, r.Side).Scan(&ciphertext); err != nil {
				return err
			}
			associated = fmt.Sprintf("driver-cnic:%d:%d:%s", r.UserID, r.Version, r.Side)
		} else {
			if r.Side != "registration" && r.Side != "insurance" {
				return invalid
			}
			if err := tx.QueryRow(ctx, `SELECT CASE WHEN $4='registration' THEN registration_image ELSE insurance_image END FROM driver_vehicle_submissions
 WHERE user_id=$1 AND vehicle_id=$2 AND version=$3`, r.UserID, r.VehicleID, r.Version, r.Side).Scan(&ciphertext); err != nil {
				return err
			}
			associated = fmt.Sprintf("driver-vehicle:%d:%d:%d:%s", r.UserID, r.VehicleID, r.Version, r.Side)
		}
		if len(ciphertext) == 0 {
			return reviewDocumentUnavailable
		}
		var err error
		data, err = s.driverDocumentCipher.Open(nil, nil, ciphertext, []byte(associated))
		if err != nil {
			return err
		}
		mime = http.DetectContentType(data)
		if mime != "image/jpeg" && mime != "image/png" {
			return reviewDocumentUnavailable
		}
		_, err = tx.Exec(ctx, `INSERT INTO onboarding_document_access(reviewer_id,user_id,kind,vehicle_id,version,side)
 VALUES($1,$2,$3,$4,$5,$6)`, reviewer, r.UserID, r.Kind, r.VehicleID, r.Version, r.Side)
		return err
	})
	return 200, map[string]any{"mime": mime, "data": data}, err
}

func (s *Server) decideReview(ctx context.Context, body input, bearer string) (int, any, error) {
	r := body.Review
	reason := strings.TrimSpace(r.Reason)
	err := s.withReviewer(ctx, bearer, r.UserID, func(tx pgx.Tx, reviewer int64) error {
		if !r.validTarget() || (r.Decision != "approved" && r.Decision != "rejected") ||
			(r.Decision == "rejected") != (reason != "") || len(reason) > 1000 || strings.ContainsRune(reason, 0) {
			return invalid
		}
		if err := lockReviewTarget(ctx, tx, r, reviewer); err != nil {
			return err
		}
		if r.Kind == "identity" {
			tag, err := tx.Exec(ctx, `UPDATE driver_identity_submissions SET status=$3,reviewed_by=$4,reviewed_at=clock_timestamp(),rejection_reason=$5
 WHERE user_id=$1 AND version=$2 AND ($3='rejected' OR (cnic_front IS NOT NULL AND cnic_back IS NOT NULL))`, r.UserID, r.Version, r.Decision, reviewer, reason)
			if err == nil && tag.RowsAffected() != 1 {
				return reviewDocumentUnavailable
			}
			return err
		}
		tag, err := tx.Exec(ctx, `UPDATE driver_vehicle_submissions SET status=$4,reviewed_by=$5,reviewed_at=clock_timestamp(),rejection_reason=$6
 WHERE user_id=$1 AND vehicle_id=$2 AND version=$3 AND ($4='rejected' OR (registration_image IS NOT NULL AND insurance_image IS NOT NULL))`, r.UserID, r.VehicleID, r.Version, r.Decision, reviewer, reason)
		if err == nil && tag.RowsAffected() != 1 {
			return reviewDocumentUnavailable
		}
		return err
	})
	return 200, map[string]string{"status": r.Decision}, err
}
