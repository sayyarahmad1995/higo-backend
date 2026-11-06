CREATE TABLE driver_application_drafts (
    user_id bigint PRIMARY KEY REFERENCES auth_users(id) ON DELETE CASCADE,
    revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
    details jsonb NOT NULL CHECK (octet_length(details::text) <= 4096)
);

CREATE TABLE driver_applications (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id bigint NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE,
    identity_version integer NOT NULL,
    vehicle_id bigint NOT NULL,
    vehicle_version integer NOT NULL,
    submitted_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    status text NOT NULL DEFAULT 'under_review' CHECK (status IN ('under_review','approved','rejected')),
    resolved_at timestamptz,
    reason text NOT NULL DEFAULT '',
    CHECK ((status='under_review') = (resolved_at IS NULL)),
    CHECK ((status='rejected') = (reason<>'') AND octet_length(reason)<=1000),
    UNIQUE (user_id, identity_version, vehicle_id, vehicle_version),
    FOREIGN KEY (user_id,identity_version) REFERENCES driver_identity_submissions(user_id,version) ON DELETE CASCADE,
    FOREIGN KEY (user_id,vehicle_id,vehicle_version) REFERENCES driver_vehicle_submissions(user_id,vehicle_id,version) ON DELETE CASCADE
);
CREATE INDEX driver_applications_owner_latest ON driver_applications(user_id,id DESC);

CREATE VIEW current_driver_applications AS
SELECT a.* FROM driver_applications a
WHERE NOT EXISTS (SELECT 1 FROM driver_applications newer WHERE newer.user_id=a.user_id AND newer.id>a.id)
  AND NOT EXISTS (SELECT 1 FROM driver_identity_submissions newer WHERE newer.user_id=a.user_id AND newer.version>a.identity_version)
  AND NOT EXISTS (SELECT 1 FROM driver_vehicle_submissions newer WHERE newer.user_id=a.user_id AND newer.vehicle_id=a.vehicle_id AND newer.version>a.vehicle_version);
