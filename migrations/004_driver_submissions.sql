CREATE TABLE driver_identity_submissions (
    user_id bigint NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE,
    version integer NOT NULL CHECK (version > 0),
    legal_name text NOT NULL CHECK (octet_length(legal_name) BETWEEN 1 AND 150),
    status text NOT NULL DEFAULT 'submitted' CHECK (status = 'submitted'),
    cnic_front bytea NOT NULL,
    cnic_back bytea NOT NULL,
    submitted_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (user_id, version)
);
