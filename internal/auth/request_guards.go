package auth

import (
	"context"
	"fmt"
	"time"
)

// AllowRequest applies the existing per-peer budget for the operation.
func (s *Server) AllowRequest(ctx context.Context, operation, peer string) error {
	limit := 60
	if operation == "auth/register" || operation == "auth/recovery/request" {
		limit = 10
	}
	return allow(ctx, s.db, operation+"/ip/"+peer, time.Minute, limit)
}

// ReservePreview authenticates the caller before acquiring a document slot.
func (s *Server) ReservePreview(ctx context.Context, bearer string) (func(), error) {
	if _, err := s.currentAccount(ctx, bearer); err != nil {
		return nil, err
	}
	select {
	case s.driverDocumentSlots <- struct{}{}:
		return func() { <-s.driverDocumentSlots }, nil
	default:
		return nil, busy
	}
}

// CheckUpload authenticates the caller and checks the account cooldown.
func (s *Server) CheckUpload(ctx context.Context, bearer string) (int64, error) {
	account, err := s.currentAccount(ctx, bearer)
	if err != nil {
		return 0, err
	}
	id := account.ID
	var coolingDown bool
	if err := s.db.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM auth_rate_limits WHERE key=$1 AND bucket=0 AND expires_at>now())`, uploadCooldownKey(id)).Scan(&coolingDown); err != nil {
		return 0, err
	}
	if coolingDown {
		return 0, limited
	}
	return id, nil
}

// ReserveUpload holds the account through body decoding and the global slot
// through the response. The caller releases each at its respective boundary.
func (s *Server) ReserveUpload(id int64) (releaseAccount, releaseSlot func(), err error) {
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
func (s *Server) RecordSlowUpload(ctx context.Context, id int64) {
	penaltyCtx, stop := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
	defer stop()
	_, _ = s.db.Exec(penaltyCtx, `INSERT INTO auth_rate_limits(key,bucket,attempts,expires_at) VALUES ($1,0,1,now()+interval '60 seconds')
 ON CONFLICT (key,bucket) DO UPDATE SET expires_at=excluded.expires_at`, uploadCooldownKey(id))
}

func uploadCooldownKey(id int64) string {
	return hexDigest(fmt.Sprintf("document/slow-upload/%d", id))
}
