CREATE TABLE driver_identity_submissions (
    user_id bigint NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE,
    version integer NOT NULL CHECK (version > 0),
    legal_name text NOT NULL CHECK (octet_length(legal_name) BETWEEN 1 AND 150),
    status text NOT NULL DEFAULT 'submitted' CHECK (status = 'submitted'),
    cnic_front bytea,
    cnic_back bytea,
    submitted_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (user_id, version),
    CHECK ((cnic_front IS NULL) = (cnic_back IS NULL)),
    CHECK (octet_length(cnic_front) <= 1048604 AND octet_length(cnic_back) <= 1048604)
);
CREATE INDEX driver_identity_document_expiry ON driver_identity_submissions (submitted_at) WHERE cnic_front IS NOT NULL;
