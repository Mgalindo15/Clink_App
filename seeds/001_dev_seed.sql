PRAGMA foreign_keys=ON; -- auto toggled "0"
BEGIN;

WITH t(ts) AS (SELECT strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
INSERT INTO profiles (
    profile_id, schema_version, created_at, updated_at,
    age_band, education_level, employment_status, sex,
    gender, locale, consent_ok, guardian_required
)
SELECT
    1, '1.0.0', t.ts, t.ts,
    '26_39',
    'university_or_four_year_college',
    'student',
    'male',
    NULL,
    'en-US',
    1,
    0
FROM t;

-- PII row (separate table)
INSERT INTO profiles_private (pii_profile_id, display_name, dob)
VALUES (1, 'Matt Galindo', '1998-12-06');

-- Evidence log: initial creation event
WITH t(ts) AS (SELECT strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
INSERT INTO evidence_log (log_profile_id, ts, source, delta_json)
SELECT 1, t.ts, 'create_profile',
        '{"created":{"age_band":"18_25","education_level":"university_or_four_year_college"}}'
FROM t;

-- Snapshot (JSON blob prototype testing)
WITH t(ts) AS (SELECT strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
INSERT INTO snapshots (snapshots_profile_id, snapshot_type, json_blob, last_built_at, etag)
SELECT
    1,
    'chat_snapshot',
    '{"meta":{"schema_version":"1.0.0"},"demographics":{"age_band":"18_25","education_level":"university_or_four_year_college"},"flags":{"guardian_required":false}}',
    t.ts,
    'seed-v1'
FROM t;

COMMIT;