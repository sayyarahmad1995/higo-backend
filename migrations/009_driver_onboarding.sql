-- An earlier draft of this branch created the identical schema as version 7.
CREATE TABLE IF NOT EXISTS driver_onboarding_applications (
    user_id bigint NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE,
    application_version integer NOT NULL DEFAULT 1 CHECK (application_version > 0),
    draft_revision bigint NOT NULL DEFAULT 1 CHECK (draft_revision > 0),
    details jsonb NOT NULL CHECK (octet_length(details::text) <= 4096),
    cnic_front bytea,
    cnic_back bytea,
    registration_image bytea,
    insurance_image bytea,
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    submitted_at timestamptz,
    PRIMARY KEY (user_id, application_version),
    CHECK ((cnic_front IS NULL) = (cnic_back IS NULL)),
    CHECK ((registration_image IS NULL) = (insurance_image IS NULL)),
    CHECK (octet_length(cnic_front) <= 1048604 AND octet_length(cnic_back) <= 1048604),
    CHECK (octet_length(registration_image) <= 2097180 AND octet_length(insurance_image) <= 2097180),
    CHECK (submitted_at IS NULL OR (cnic_front IS NOT NULL AND registration_image IS NOT NULL))
);

CREATE UNIQUE INDEX IF NOT EXISTS driver_onboarding_one_draft ON driver_onboarding_applications (user_id)
WHERE submitted_at IS NULL;
CREATE INDEX IF NOT EXISTS driver_onboarding_draft_expiry ON driver_onboarding_applications (updated_at)
WHERE submitted_at IS NULL AND (cnic_front IS NOT NULL OR registration_image IS NOT NULL);
