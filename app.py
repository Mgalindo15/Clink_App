import os, json
from fastapi import FastAPI, HTTPException, status, Header, Depends, Request
from fastapi.security import OAuth2PasswordBearer
from fastapi.security.utils import get_authorization_scheme_param
from fastapi.responses import JSONResponse
from contextlib import asynccontextmanager
from passlib.context import CryptContext
from jose import jwt, JWTError
from datetime import datetime, timezone, timedelta
from typing import Optional, List, TypedDict
from db import init_db, get_conn
from models import ProfileCreate, ProfilePublic, ProfilePII, ProfilePIIUpdate, ProfileUpdate, SnapShotOut, UserCreate, UserLogin, TokenOut, compute_age_band, utc_now_iso

# ----- DB INIT -----
@asynccontextmanager
async def lifespan(app: FastAPI):
    # --- startup ---
    init_db()
    yield
    # --- shutdown ---
    # blah blah

app = FastAPI(title="Clink Lab", version="0.0.1", lifespan=lifespan)

@app.get("/health")
def health():
    return {"status": "ok", "ts": datetime.utcnow().isoformat() + "Z"}

# ----- SECURITY -----
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/login", auto_error=False)

SECRET_KEY = os.environ.get("DEV_JWT_SECRET", "devsecret") # Check Esmerald WF for PROD
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 120

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(password: str, hash_: str) -> bool:
    return pwd_context.verify(password, hash_)

def create_access_token(data: dict, expires_delta: int=ACCESS_TOKEN_EXPIRE_MINUTES):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(minutes=expires_delta)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

# ----- PROFILE -----
class CurrentUser(TypedDict):
    username: str
    user_id: int
    profile_id: int
    is_admin: bool

def _extract_bearer_from_header(authorization: Optional[str]) -> Optional[str]:
    if not authorization:
        return None
    scheme, param = get_authorization_scheme_param(authorization)
    if scheme.lower() == "bearer" and param:
        return param
    return None

def get_current_user(
    request: Request,
    authorization: Optional[str] = Header(default=None),
    token_from_oauth: Optional[str] = Depends(oauth2_scheme),
) -> CurrentUser:
    
    #1) Prefer 0auth token
    token = token_from_oauth or _extract_bearer_from_header(authorization)
    #2) Default to cookie
    if not token:
        token = request.cookies.get("access_token")

    if not token:
        raise HTTPException(status_code=401, detail="Not Authenticated")
    
    # Attempt decode
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    username = payload.get("sub")
    if not isinstance(username, str) or not username:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    # Acc lookup (w/ auth)
    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute(
            "SELECT rowid AS user_id, username, profile_id, is_admin FROM auth_users WHERE username = ?",
            (username,),
        )
        row = cur.fetchone()
        if not row:
            raise HTTPException(status_code=401, detail="Invalid credentials")
        return CurrentUser(
            username=row["username"],
            user_id=row["user_id"],
            profile_id=row["profile_id"],
            is_admin=bool(row["is_admin"]),
        )

def require_owner_or_Admin(target_profile_id: int, me: CurrentUser) -> None:
    if me["is_admin"]:
        return
    if me["profile_id"] == target_profile_id:
        return
    raise HTTPException(status_code=403, detail="Forbidden (ownner or admin required)")

def require_admin(me: CurrentUser) -> None:
    if not me["is_admin"]:
        raise HTTPException(status_code=403, detail="Admin only")

# ----- ROUTES -----
@app.post("/register", response_model=dict)
def register_user(payload: UserCreate):
    now = utc_now_iso()
    with get_conn() as conn:
        cur = conn.cursor()
        try:
            cur.execute(
                """
                INSERT INTO auth_users (username, password_hash, auth_profile_id, created_at)
                VALUES (?, ?, ?, ?)
                """,
                (payload.username, hash_password(payload.password), payload.profile_id, now),
            )
            conn.commit()
        except Exception:
            conn.rollback()
            raise HTTPException(status_code=400, detail="Username already exists or profile missing")
    return {"msg": "User registered"}

@app.post("/login", response_model=TokenOut)
def login_user(payload: UserLogin):
    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute("SELECT password_hash FROM auth_users WHERE username = ?", (payload.username,))
        row = cur.fetchone()
        if not row or not verify_password(payload.password, row["password_hash"]):
            raise HTTPException(status_code=401, detail="Invalid credentials")
        
        token = create_access_token({"sub": payload.username})
        response = JSONResponse(content={"access_token": token, "token_type": "bearer"})
        response.set_cookie(key="access_token", value=token, httponly=True)
        return response

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
                INSERT INTO profiles_private (pii_profile_id, display_name, dob)
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

@app.get("/me")
def read_me(me: CurrentUser = Depends(get_current_user)):
    return {"username": me["username"], "profile_id": me["profile_id"], "is_admin": me["is_admin"]}

@app.get("/profiles", response_model=List[ProfilePublic])
def list_profiles(
    age_band: Optional[str] = None,
    education_level: Optional[str] = None,
    limit: int = 10,
    offset: int = 0,
):
    query = "SELECT * FROM profiles WHERE 1=1"
    params = []
    if age_band:
        query += " AND age_band = ?"
        params.append(age_band)
    if education_level:
        query += " AND education_level = ?"
        params.append(education_level)
    query += " ORDER BY profile_id LIMIT ? OFFSET ?"
    params.extend([limit, offset])

    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute(query, params)
        rows = cur.fetchall()

    return [
        ProfilePublic(
            profile_id=row["profile_id"],
            schema_version=row["schema_version"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
            age_band=row["age_band"],
            education_level=row["education_level"],
            employment_status=row["employment_status"],
            sex=row["sex"],
            gender=row["gender"],
            locale=row["locale"],
            consent_ok=bool(row["consent_ok"]),
            guardian_required=bool(row["guardian_required"]),
        )
        for row in rows
    ]

@app.get("/profiles/{profile_id}", response_model=ProfilePublic)
def get_profile(profile_id: int):
    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute(
            """
            SELECT
              profile_id, schema_version, created_at, updated_at,
              age_band, education_level, employment_status, sex, gender,
              locale, consent_ok, guardian_required
            FROM profiles
            WHERE profile_id = ?
            """,
            (profile_id,),
        )
        row = cur.fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="Profile not found.")

        # Make sure runns conn() --> rows can be read as dicts
        return ProfilePublic(
            profile_id=row["profile_id"],
            schema_version=row["schema_version"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
            age_band=row["age_band"],
            education_level=row["education_level"],
            employment_status=row["employment_status"],
            sex=row["sex"],
            gender=row["gender"],
            locale=row["locale"],
            consent_ok=bool(row["consent_ok"]),
            guardian_required=bool(row["guardian_required"]),
        )
    
@app.get("/profiles/{profile_id}/pii", response_model=ProfilePII)
def get_profile_pii(
    profile_id: int,
    # --- Validation ---> replace later w/ real auth
    #x_dev_key: Optional[str] = Header(default=None),
):
    """
    expected = os.environ.get("DEV_PII_KEY", "").strip()
    if not expected or (x_dev_key or "").strip() != expected:
        raise HTTPException(status_code=403, detail="PII access denied (missing/invalid dev key).")
    """
    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute(
            """
            SELECT p.profile_id, pr.display_name, pr.dob
            FROM profiles p
            JOIN profiles_private pr ON pr.pii_profile_id = p.profile_id
            WHERE p.profile_id = ?
            """,
            (profile_id,),
        )
        row = cur.fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="PII record not found.")

        # dob comes as str (YYYY-MM-DD), pydantic will coerce to 'date'
        return {
            "profile_id": row["profile_id"],
            "display_name": row["display_name"],
            "dob": row["dob"],
        }
    
@app.put("/profiles/{profile_id}", response_model=ProfilePublic)
def update_profile(profile_id: int, payload: ProfileUpdate):
    now = utc_now_iso()
    updates = {k: v for k, v in payload.model_dump().items() if v is not None}
    if not updates:
        raise HTTPException(status_code=400, detail="No fields to update.")

    set_clauses = ", ".join([f"{col} = ?" for col in updates])
    params = list(updates.values())

    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute("SELECT * FROM profiles WHERE profile_id = ?", (profile_id,))
        row = cur.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Profile not found.")

        cur.execute(
            f"UPDATE profiles SET {set_clauses}, updated_at = ? WHERE profile_id = ?",
            (*params, now, profile_id),
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
                "update_profile",
                json.dumps({"updated": updates}),
            ),
        )

        conn.commit()

    # Reuse existing get_profile to return updated object
    return get_profile(profile_id)
    


@app.get("/profiles/{profile_id}/history", response_model=List[dict])
def get_profile_history(profile_id: int):
    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute(
            """
            SELECT id, ts, source, delta_json
            FROM evidence_log
            WHERE log_profile_id = ?
            ORDER BY id DESC
            """,
            (profile_id,),
        )
        rows = cur.fetchall()

    return [
        {
            "id": row["id"],
            "ts": row["ts"],
            "source": row["source"],
            "delta": json.loads(row["delta_json"]),
        }
        for row in rows
    ]

@app.get("/profiles/{profile_id}/debug", response_model=dict)
def get_profile_debug(
    profile_id: int,
    #dev key
):
    # if gating for pii/non-pii split w/ dev key requirement (later)
    out = {}
    out["profile"] = get_profile(profile_id)

    # snapshot
    out["snapshot"] = get_snapshot(profile_id)

    # evidence history
    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute(
            """
            SELECT id, ts, source, delta_json
            FROM evidence_log
            WHERE log_profile_id = ?
            ORDER BY id DESC LIMIT 5
            """,
            (profile_id,),
        )
        rows = cur.fetchall()
        out["evidence"] = [
            {
                "id": r["id"],
                "ts": r["ts"],
                "source": r["source"],
                "delta": json.loads(r["delta_json"]),
            }
            for r in rows
        ]
    
    return out
    

@app.get("/profiles/{profile_id}/snapshot", response_model=dict)
def get_snapshot(profile_id: int, rebuild: bool = False):
    """
    Dev-friendly snapshot:
      - If exists and rebuild==False → return existing
      - Else (re)build a compact snapshot from the current row
    """
    snapshot_type = "chat_snapshot"
    now = utc_now_iso()

    with get_conn() as conn:
        cur = conn.cursor()

        # Try existing
        if not rebuild:
            cur.execute(
                """
                SELECT json_blob, last_built_at, etag
                FROM snapshots
                WHERE snapshots_profile_id = ? AND snapshot_type = ?
                """,
                (profile_id, snapshot_type),
            )
            snap = cur.fetchone()
            if snap:
                try:
                    parsed = json.loads(snap["json_blob"])
                except Exception:
                    parsed = {"_corrupt": True, "raw": snap["json_blob"]}
                return {
                    "profile_id": profile_id,
                    "snapshot_type": snapshot_type,
                    "last_built_at": snap["last_built_at"],
                    "etag": snap["etag"],
                    "json": parsed,
                }

        # Build from live profile row
        cur.execute(
            """
            SELECT schema_version, age_band, education_level, guardian_required
            FROM profiles
            WHERE profile_id = ?
            """,
            (profile_id,), 
        )
        row = cur.fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="Profile not found.")

        snapshot = {
            "meta": {"schema_version": row["schema_version"]},
            "demographics": {
                "age_band": row["age_band"],
                "education_level": row["education_level"],
            },
            "flags": {"guardian_required": bool(row["guardian_required"])},
        }

        # Upsert snapshot
        etag = f"onread-v1-{now}"
        cur.execute(
            """
            INSERT INTO snapshots (snapshots_profile_id, snapshot_type, json_blob, last_built_at, etag)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(snapshots_profile_id, snapshot_type)
            DO UPDATE SET
              json_blob = excluded.json_blob,
              last_built_at = excluded.last_built_at,
              etag = excluded.etag
            """,
            (profile_id, snapshot_type, json.dumps(snapshot), now, etag),
        )
        conn.commit()

        return {
            "profile_id": profile_id,
            "snapshot_type": snapshot_type,
            "last_built_at": now,
            "etag": etag,
            "json": snapshot,
        }



@app.patch("/profiles/{profile_id}/pii", response_model=ProfilePII)
def update_profile_pii(
    profile_id: int,
    payload: ProfilePIIUpdate,
    # x_dev_key: Optional[str] = Header(default=None),
):
    # expected = os.environ.get("DEV_PII_KEY", "").strip()
    # if not expected or (x_dev_key or "").strip() != expected:
        # raise HTTPException(status_code=403, detail="PII access denied (missing/invalid dev key).")

    updates = {k: v for k, v in payload.model_dump().items() if v is not None}
    if not updates:
        raise HTTPException(status_code=400, detail="No fields to update.")

    now = utc_now_iso()

    set_clauses = ", ".join([f"{col} = ?" for col in updates])
    params = list(updates.values())

    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute("SELECT * FROM profiles_private WHERE pii_profile_id = ?", (profile_id,))
        if not cur.fetchone():
            raise HTTPException(status_code=404, detail="PII record not found.")

        cur.execute(
            f"UPDATE profiles_private SET {set_clauses} WHERE pii_profile_id = ?",
            (*params, profile_id),
        )

        cur.execute(
            """
            INSERT INTO evidence_log (log_profile_id, ts, source, delta_json)
            VALUES (?, ?, ?, ?)
            """,
            (
                profile_id,
                now,
                "update_profile_pii",
                json.dumps({"updated": updates}),
            ),
        )

        conn.commit()

    # Return updated PII
    return get_profile_pii(profile_id)
