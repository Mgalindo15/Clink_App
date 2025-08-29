-- Config SQLite
PRAGMA journal_mode = WAL; -- Write Ahead Log (for concurrent r/w (otherwise atomic), non-distributed aka all local)
PRAGMA foreign_keys = ON;

-- Legal Note: Non PII information in US less strict than EU --> Gender, Sex, Race etc. not covered and able to use in analytics

-- Core Profile (Non-PII)
CREATE TABLE IF NOT EXISTS profiles (
    profile_id          INTEGER PRIMARY KEY,  -- auto-increment
    schema_version      TEXT NOT NULL DEFAULT '1.0.0',
    created_at          TEXT NOT NULL,
    updated_at          TEXT NOT NULL,
    age_band            TEXT NOT NULL 
                            CHECK (age_band IN ('13_17', '18_25', '26_39', '40_plus')),
    education_level     TEXT NOT NULL 
                            CHECK (education_level IN ('middle_school', 'high_school', 'community_college', 'trade_school', 'university_or_four_year_college', 'graduate_school')),
    employment_status   TEXT
                            CHECK (employment_status IN (
                                'student',
                                'unemployed',
                                'part-time',
                                'full-time',
                                'self-employed',
                                'retired'
                            )),
    sex                 TEXT NOT NULL CHECK (sex IN ('male', 'female')),
    gender              TEXT,
    locale              TEXT NOT NULL
                            CHECK (locale GLOB '[a-z][a-z]-[A-Z][A-Z]'),
    consent_ok          INTEGER NOT NULL CHECK (consent_ok IN (0, 1)),
    guardian_required   INTEGER NOT NULL CHECK (guardian_required IN (0, 1))
);

-- PII Separated
CREATE TABLE IF NOT EXISTS profiles_private (
    pii_profile_id      INTEGER PRIMARY KEY,
    display_name        TEXT NOT NULL,
    dob                 TEXT NOT NULL,  -- ISO 'YYYY-MM-DD'
    FOREIGN KEY(pii_profile_id) REFERENCES profiles(profile_id) ON DELETE CASCADE
);

-- Auth (tri-linked with profiles/private)
CREATE TABLE IF NOT EXISTS auth_users (
    user_id             INTEGER PRIMARY KEY,
    username            TEXT NOT NULL UNIQUE,
    password_hash       TEXT NOT NULL,
    auth_profile_id     INTEGER NOT NULL,
    created_at          TEXT NOT NULL,
    is_admin            INTEGER NOT NULL DEFAULT 0;
    FOREIGN KEY(auth_profile_id) REFERENCES profiles(profile_id) ON DELETE CASCADE
);

-- Evidence Log (Append Only) -> tracks changes in profile (JSON), allowing traceability, debugging, auditing
CREATE TABLE IF NOT EXISTS evidence_log (
    id                  INTEGER PRIMARY KEY,
    log_profile_id      INTEGER NOT NULL,
    ts                  TEXT NOT NULL,
    source              TEXT NOT NULL,
    delta_json          TEXT NOT NULL,
    FOREIGN KEY(log_profile_id) REFERENCES profiles(profile_id) ON DELETE CASCADE
);

-- Snapshot (small, denormalized JSON for fast reads)
CREATE TABLE IF NOT EXISTS snapshots (
    snapshots_profile_id    INTEGER NOT NULL,
    snapshot_type       TEXT NOT NULL,
    json_blob           TEXT NOT NULL,
    last_built_at       TEXT NOT NULL,
    etag                TEXT,
    PRIMARY KEY(snapshots_profile_id, snapshot_type),
    FOREIGN KEY(snapshots_profile_id) REFERENCES profiles(profile_id) ON DELETE CASCADE
);
