CREATE TABLE onboarding_reviewers (
    user_id bigint PRIMARY KEY REFERENCES auth_users(id) ON DELETE CASCADE
);

ALTER TABLE driver_identity_submissions
    DROP CONSTRAINT driver_identity_submissions_status_check,
    ADD COLUMN reviewed_by bigint,
    ADD COLUMN reviewed_at timestamptz,
    ADD COLUMN rejection_reason text NOT NULL DEFAULT '',
    ADD CHECK (status IN ('submitted','approved','rejected')),
    ADD CHECK ((status = 'submitted') = (reviewed_at IS NULL) AND (reviewed_at IS NULL) = (reviewed_by IS NULL)),
    ADD CHECK ((status = 'rejected') = (rejection_reason <> '') AND octet_length(rejection_reason) <= 1000);

ALTER TABLE driver_vehicle_submissions
    DROP CONSTRAINT driver_vehicle_submissions_status_check,
    ADD COLUMN reviewed_by bigint,
    ADD COLUMN reviewed_at timestamptz,
    ADD COLUMN rejection_reason text NOT NULL DEFAULT '',
    ADD CHECK (status IN ('submitted','approved','rejected')),
    ADD CHECK ((status = 'submitted') = (reviewed_at IS NULL) AND (reviewed_at IS NULL) = (reviewed_by IS NULL)),
    ADD CHECK ((status = 'rejected') = (rejection_reason <> '') AND octet_length(rejection_reason) <= 1000);

CREATE TABLE onboarding_document_access (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    reviewer_id bigint NOT NULL,
    user_id bigint NOT NULL,
    kind text NOT NULL CHECK (kind IN ('identity','vehicle')),
    vehicle_id bigint NOT NULL,
    version integer NOT NULL CHECK (version > 0),
    side text NOT NULL,
    accessed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CHECK ((kind='identity' AND vehicle_id=0 AND side IN ('front','back')) OR
           (kind='vehicle' AND vehicle_id>0 AND side IN ('registration','insurance')))
);
