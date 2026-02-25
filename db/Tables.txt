CREATE TABLE users (
    user_id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username         TEXT UNIQUE NOT NULL,               -- e.g. "alice@example.com"
    created_at       TIMESTAMPTZ DEFAULT NOW(),
    last_active      TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE key_packages (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id          UUID NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    key_package      BYTEA NOT NULL,                       -- the serialized ~285 bytes
    ref_hash         BYTEA NOT NULL,                       -- KeyPackageRef (32 bytes hash)
    expires_at       TIMESTAMPTZ NOT NULL,                 -- e.g. now + 30 days
    created_at       TIMESTAMPTZ DEFAULT NOW(),
    used             BOOLEAN DEFAULT FALSE,                -- mark as used after being referenced in a commit
    UNIQUE (user_id, ref_hash)                             -- prevent duplicates
);

CREATE INDEX idx_key_packages_user_id ON key_packages(user_id);
CREATE INDEX idx_key_packages_expires_at ON key_packages(expires_at);
CREATE INDEX idx_key_packages_unused ON key_packages(used) WHERE used = FALSE;