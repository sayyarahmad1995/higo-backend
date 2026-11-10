package driver

import (
	"context"
	"log/slog"
	"time"
)

// PurgeDocuments runs the existing retention statements in their original order.
func (s *Service) PurgeDocuments(ctx context.Context) {
	for _, statement := range []string{
		purgeSupersededDriverDocuments,
		purgeSupersededVehicleDocuments,
		purgeAbandonedOnboardingDocuments,
	} {
		deadline, cancel := context.WithTimeout(ctx, 10*time.Second)
		_, err := s.db.Exec(deadline, statement)
		cancel()
		if err != nil && ctx.Err() == nil {
			slog.Warn("auth_cleanup_failed")
		}
	}
}

const purgeSupersededDriverDocuments = `UPDATE driver_identity_submissions d SET cnic_front=NULL,cnic_back=NULL
 WHERE (d.user_id,d.version) IN (SELECT old.user_id,old.version FROM driver_identity_submissions old
 WHERE old.cnic_front IS NOT NULL AND old.submitted_at < now()-interval '30 days'
 AND EXISTS (SELECT 1 FROM driver_identity_submissions newer WHERE newer.user_id=old.user_id AND newer.version>old.version)
 ORDER BY old.submitted_at LIMIT 500)`

const purgeSupersededVehicleDocuments = `UPDATE driver_vehicle_submissions v SET registration_image=NULL,insurance_image=NULL
 WHERE (v.user_id,v.vehicle_id,v.version) IN (SELECT old.user_id,old.vehicle_id,old.version FROM driver_vehicle_submissions old
 WHERE old.registration_image IS NOT NULL AND old.submitted_at<now()-interval '30 days'
 AND EXISTS(SELECT 1 FROM driver_vehicle_submissions newer WHERE newer.user_id=old.user_id AND newer.vehicle_id=old.vehicle_id AND newer.version>old.version)
 ORDER BY old.submitted_at LIMIT 500)`

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
