CREATE TABLE auth_users (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    phone text NOT NULL UNIQUE CHECK (phone ~ '^\+[1-9][0-9]{7,14}$'),
    name text NOT NULL,
    email text NOT NULL DEFAULT '',
    password_hash text NOT NULL,
    password_version bigint NOT NULL DEFAULT 1,
    phone_verified_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE auth_challenges (
    id bytea PRIMARY KEY CHECK (octet_length(id) = 32),
    purpose text NOT NULL CHECK (purpose IN ('registration', 'recovery')),
    phone text NOT NULL,
    user_id bigint REFERENCES auth_users(id) ON DELETE CASCADE,
    password_version bigint,
    password_hash text,
    name text NOT NULL DEFAULT '',
    email text NOT NULL DEFAULT '',
    otp_digest bytea NOT NULL CHECK (octet_length(otp_digest) = 32),
    attempts integer NOT NULL DEFAULT 0 CHECK (attempts BETWEEN 0 AND 5),
    delivered boolean NOT NULL DEFAULT false,
    consumed boolean NOT NULL DEFAULT false,
    expires_at timestamptz NOT NULL,
    CHECK (
        (purpose = 'registration' AND user_id IS NULL AND password_version IS NULL AND password_hash IS NOT NULL)
        OR (purpose = 'recovery' AND password_hash IS NULL AND (user_id IS NULL) = (password_version IS NULL))
    )
);
CREATE INDEX auth_challenges_expiry ON auth_challenges(expires_at);

CREATE TABLE auth_recovery (
    digest bytea PRIMARY KEY CHECK (octet_length(digest) = 32),
    user_id bigint NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE,
    password_version bigint NOT NULL,
    expires_at timestamptz NOT NULL
);
CREATE INDEX auth_recovery_expiry ON auth_recovery(expires_at);

CREATE TABLE auth_sessions (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id bigint NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE,
    access_digest bytea NOT NULL UNIQUE CHECK (octet_length(access_digest) = 32),
    access_expires_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    revoked_at timestamptz
);
CREATE INDEX auth_sessions_user ON auth_sessions(user_id);
CREATE INDEX auth_sessions_expiry ON auth_sessions(expires_at);

CREATE TABLE auth_refresh (
    digest bytea PRIMARY KEY CHECK (octet_length(digest) = 32),
    session_id bigint NOT NULL REFERENCES auth_sessions(id) ON DELETE CASCADE,
    consumed boolean NOT NULL DEFAULT false
);
CREATE INDEX auth_refresh_session ON auth_refresh(session_id);
CREATE UNIQUE INDEX auth_refresh_one_current ON auth_refresh(session_id) WHERE NOT consumed;

CREATE TABLE auth_rate_limits (
    key text NOT NULL,
    bucket bigint NOT NULL,
    attempts integer NOT NULL CHECK (attempts > 0),
    expires_at timestamptz NOT NULL,
    PRIMARY KEY (key, bucket)
);
CREATE INDEX auth_rate_limits_expiry ON auth_rate_limits(expires_at);
