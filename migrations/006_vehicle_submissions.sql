CREATE SEQUENCE driver_vehicle_id_seq;

CREATE TABLE driver_vehicle_submissions (
    user_id bigint NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE,
    vehicle_id bigint NOT NULL CHECK (vehicle_id > 0),
    version integer NOT NULL CHECK (version > 0),
    make text NOT NULL,
    model text NOT NULL,
    manufacture_year integer NOT NULL,
    color text NOT NULL,
    registration_number text NOT NULL,
    status text NOT NULL DEFAULT 'submitted' CHECK (status = 'submitted'),
    registration_image bytea,
    insurance_image bytea,
    submitted_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (user_id,vehicle_id,version),
    CHECK ((registration_image IS NULL) = (insurance_image IS NULL)),
    CHECK (octet_length(registration_image) <= 2097180 AND octet_length(insurance_image) <= 2097180)
);
CREATE INDEX driver_vehicle_document_expiry ON driver_vehicle_submissions (submitted_at) WHERE registration_image IS NOT NULL;
