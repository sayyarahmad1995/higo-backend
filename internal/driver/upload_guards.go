package driver

import (
	"context"
	"fmt"
	"time"

	"github.com/sayyarahmad1995/higo-backend/internal/ratelimit"
)

// AllowRequest applies the Driver routes' existing per-peer budget.
func (s *Service) AllowRequest(ctx context.Context, operation, peer string) error {
	return ratelimit.Allow(ctx, s.db, operation+"/ip/"+peer, time.Minute, 60)
}

// ReservePreview shares processing capacity with image normalization.
// The HTTP adapter calls it only after Auth checks the live session.
func (s *Service) ReservePreview() (func(), error) {
	select {
	case s.driverDocumentSlots <- struct{}{}:
		return func() { <-s.driverDocumentSlots }, nil
	default:
		return nil, busy
	}
}

// CheckUploadCooldown checks admission for the account resolved by Auth.
func (s *Service) CheckUploadCooldown(ctx context.Context, id int64) error {
	var coolingDown bool
	if err := s.db.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM auth_rate_limits WHERE key=$1 AND bucket=0 AND expires_at>now())`, uploadCooldownKey(id)).Scan(&coolingDown); err != nil {
		return err
	}
	if coolingDown {
		return ratelimit.ErrLimited
	}
	return nil
}

// ReserveUpload holds the account through body decoding and the global slot
// through the response. The caller releases each at its respective boundary.
func (s *Service) ReserveUpload(id int64) (releaseAccount, releaseSlot func(), err error) {
	if _, active := s.activeUploadAccounts.LoadOrStore(id, struct{}{}); active {
		return nil, nil, busy
	}
	slots := s.documentUploadSlots
	select {
	case slots <- struct{}{}:
		return func() { s.activeUploadAccounts.Delete(id) }, func() { <-slots }, nil
	default:
		s.activeUploadAccounts.Delete(id)
		return nil, nil, busy
	}
}

// RecordSlowUpload applies a cooldown even if the request has been canceled.
func (s *Service) RecordSlowUpload(ctx context.Context, id int64) {
	penaltyCtx, stop := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
	defer stop()
	_, _ = s.db.Exec(penaltyCtx, `INSERT INTO auth_rate_limits(key,bucket,attempts,expires_at) VALUES ($1,0,1,now()+interval '60 seconds')
 ON CONFLICT (key,bucket) DO UPDATE SET expires_at=excluded.expires_at`, uploadCooldownKey(id))
}

func uploadCooldownKey(id int64) string {
	return ratelimit.Key(fmt.Sprintf("document/slow-upload/%d", id))
}
