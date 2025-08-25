from fastapi import FastAPI, HTTPException, status
from datetime import datetime
from db import init_db, get_conn
from models import ProfileCreate, ProfilePublic, compute_age_band, utc_now_iso

app = FastAPI(title="Clink Lab", version="0.0.1")

@app.on_event("startup")
def on_startup():
    init_db()

@app.get("/health")
def health():
    return {"status": "ok", "ts": datetime.utcnow().isoformat() + "Z"}

@app.post("/profiles", response_model=ProfilePublic, status_code=status.HTTP_201_CREATED)
def create_profile(payload: ProfileCreate):
    if not payload.consent_ok:
        raise HTTPException(status_code=400, detail="consent is required to create a profile.")

    try:
        age_band = compute_age_band(payload.dob)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    guardian_required = (age_band == "13_17")
    now = utc_now_iso()
    schema_version = "1.0.0"

    with get_conn() as conn:
        cur = conn.cursor()
        try:
            # Non-PII
            cur.execute(
                """
                INSERT INTO profiles (
                  schema_version, created_at, updated_at,
                  age_band, education_level, employment_status,
                  sex, gender, locale, consent_ok, guardian_required
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    schema_version, now, now,
                    age_band, payload.education_level, payload.employment_status,
                    payload.sex, payload.gender, payload.locale,
                    1 if payload.consent_ok else 0,
                    1 if guardian_required else 0,
                ),
            )
            profile_id = cur.lastrowid

            # PII
            cur.execute(
                """
                INSERT INTO profiles_private (ppi_profile_id, display_name, dob)
                VALUES (?, ?, ?)
                """,
                (profile_id, payload.display_name, payload.dob.isoformat()),
            )

            # Evidence log
            cur.execute(
                """
                INSERT INTO evidence_log (log_profile_id, ts, source, delta_json)
                VALUES (?, ?, ?, ?)
                """,
                (
                    profile_id,
                    now,
                    "create_profile",
                    '{"created":{"age_band":"%s","education_level":"%s"}}'
                    % (age_band, payload.education_level),
                ),
            )

            conn.commit()
        except Exception:
            conn.rollback()
            raise

    return ProfilePublic(
        profile_id=profile_id,
        schema_version=schema_version,
        created_at=now,
        updated_at=now,
        age_band=age_band,
        education_level=payload.education_level,
        employment_status=payload.employment_status,
        sex=payload.sex,
        gender=payload.gender,
        locale=payload.locale,
        consent_ok=payload.consent_ok,
        guardian_required=guardian_required,
    )
