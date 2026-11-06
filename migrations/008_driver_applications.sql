CREATE TABLE driver_application_drafts (
    user_id bigint PRIMARY KEY REFERENCES auth_users(id) ON DELETE CASCADE,
    details jsonb NOT NULL CHECK (octet_length(details::text) <= 4096)
);

CREATE TABLE driver_applications (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id bigint NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE,
    identity_version integer NOT NULL,
    vehicle_id bigint NOT NULL,
    vehicle_version integer NOT NULL,
    submitted_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (user_id, identity_version, vehicle_id, vehicle_version),
    FOREIGN KEY (user_id,identity_version) REFERENCES driver_identity_submissions(user_id,version) ON DELETE CASCADE,
    FOREIGN KEY (user_id,vehicle_id,vehicle_version) REFERENCES driver_vehicle_submissions(user_id,vehicle_id,version) ON DELETE CASCADE
);
CREATE INDEX driver_applications_owner_latest ON driver_applications(user_id,id DESC);

CREATE TABLE driver_application_checks (
    application_id bigint NOT NULL REFERENCES driver_applications(id) ON DELETE CASCADE,
    kind text NOT NULL CHECK (kind IN ('identity','vehicle')),
    decision text NOT NULL CHECK (decision IN ('approved','rejected')),
    reviewer_id bigint NOT NULL,
    reviewed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    reason text NOT NULL CHECK ((decision='rejected') = (reason<>'') AND octet_length(reason)<=1000),
    PRIMARY KEY (application_id,kind)
);
ALTER TABLE onboarding_document_access ADD COLUMN application_id bigint;

CREATE VIEW current_driver_applications AS
SELECT a.*, d.legal_name, v.make, v.model, v.registration_number,
       COALESCE(di.decision,'pending') AS identity_check,
       COALESCE(ve.decision,'pending') AS vehicle_check,
       CASE WHEN di.decision='rejected' OR ve.decision='rejected' THEN 'rejected'
            WHEN di.decision='approved' AND ve.decision='approved' THEN 'approved'
            ELSE 'under_review' END AS status,
       COALESCE(NULLIF(di.reason,''),NULLIF(ve.reason,''),'') AS reason
FROM driver_applications a
JOIN driver_identity_submissions d ON (d.user_id,d.version)=(a.user_id,a.identity_version)
JOIN driver_vehicle_submissions v ON (v.user_id,v.vehicle_id,v.version)=(a.user_id,a.vehicle_id,a.vehicle_version)
LEFT JOIN driver_application_checks di ON di.application_id=a.id AND di.kind='identity'
LEFT JOIN driver_application_checks ve ON ve.application_id=a.id AND ve.kind='vehicle'
WHERE NOT EXISTS (SELECT 1 FROM driver_applications newer WHERE newer.user_id=a.user_id AND newer.id>a.id)
  AND NOT EXISTS (SELECT 1 FROM driver_identity_submissions newer WHERE newer.user_id=a.user_id AND newer.version>a.identity_version)
  AND NOT EXISTS (SELECT 1 FROM driver_vehicle_submissions newer WHERE newer.user_id=a.user_id AND newer.vehicle_id=a.vehicle_id AND newer.version>a.vehicle_version);

-- The separate Admin Operations service receives EXECUTE explicitly. It needs
-- no access to account credentials, session rows, or reviewer grants.
CREATE FUNCTION lock_onboarding_reviewer(session_digest bytea, target_id bigint)
RETURNS bigint LANGUAGE plpgsql SECURITY DEFINER AS $function$
DECLARE
    actor bigint;
BEGIN
    SELECT user_id INTO actor FROM auth_sessions
    WHERE access_digest=session_digest AND revoked_at IS NULL
      AND access_expires_at>clock_timestamp() AND expires_at>clock_timestamp();
    IF NOT FOUND THEN
        RETURN NULL;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM onboarding_reviewers WHERE user_id=actor) THEN
        RETURN 0;
    END IF;
    -- Upload and final-submit transactions use the same account row lock.
    PERFORM id FROM auth_users WHERE id IN (actor,target_id) ORDER BY id FOR UPDATE;
    PERFORM user_id FROM auth_sessions
    WHERE user_id=actor AND access_digest=session_digest AND revoked_at IS NULL
      AND access_expires_at>clock_timestamp() AND expires_at>clock_timestamp() FOR SHARE;
    IF NOT FOUND THEN
        RETURN NULL;
    END IF;
    PERFORM user_id FROM onboarding_reviewers WHERE user_id=actor FOR SHARE;
    IF NOT FOUND THEN
        RETURN 0;
    END IF;
    RETURN actor;
END;
$function$;
DO $migration$
BEGIN
    EXECUTE format('ALTER FUNCTION lock_onboarding_reviewer(bytea,bigint) SET search_path TO pg_catalog, %I, pg_temp', current_schema());
END;
$migration$;
REVOKE ALL ON FUNCTION lock_onboarding_reviewer(bytea,bigint) FROM PUBLIC;
