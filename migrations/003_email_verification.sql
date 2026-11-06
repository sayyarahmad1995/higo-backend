ALTER TABLE auth_users ADD COLUMN email_verified_at timestamptz;
ALTER TABLE auth_users ADD CHECK (email_verified_at IS NULL OR email <> '');

CREATE TABLE auth_email_challenges (
    user_id bigint PRIMARY KEY REFERENCES auth_users(id) ON DELETE CASCADE,
    target_email text NOT NULL CHECK (target_email <> ''),
    original_email text NOT NULL,
    password_version bigint NOT NULL,
    digest bytea NOT NULL CHECK (octet_length(digest) = 32),
    delivered boolean NOT NULL DEFAULT false,
    expires_at timestamptz NOT NULL
);
CREATE INDEX auth_email_challenges_expiry ON auth_email_challenges(expires_at);
