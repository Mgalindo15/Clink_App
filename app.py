import os, json, logging, sqlite3, traceback, time, uuid
from fastapi import FastAPI, HTTPException, status, Header, Depends, Request, Body
from fastapi.security import OAuth2PasswordBearer
from fastapi.security.utils import get_authorization_scheme_param
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from contextlib import asynccontextmanager
from passlib.context import CryptContext
from jose import jwt, JWTError
from datetime import datetime, timezone, timedelta
from typing import Optional, List, TypedDict
from db import init_db, get_conn
from models import ApiError, ProfileCreate, ProfilePublic, ProfilePII, ProfilePIIUpdate, ProfileUpdate, SnapShotOut, AdminToggle, UserCreate, UserLogin, TokenOut, compute_age_band, utc_now_iso

# ----- DB INIT ----- #
@asynccontextmanager
async def lifespan(app: FastAPI):
    # --- startup ---
    init_db()
    yield
    # --- shutdown ---
    # blah blah

app = FastAPI(title="Clink Lab", version="0.0.1", lifespan=lifespan)
logger = logging.getLogger("clink")

@app.get("/health")
def health():
    return {"status": "ok", "ts": utc_now_iso()}

# ----- ERROR HANDLERS ----- #
@app.exception_handler(RequestValidationError)
async def pydantic_error_handler(request: Request, exc: RequestValidationError):
    errors = []
    for e in exc.errors():
        errors.append({"loc": e.get("loc"), "msg": e.get("msg"), "type": e.get("type")})
    payload = ApiError(status=422, code="validation_error",
                                detail="Input validation failed", extra={"errors": errors})
    return JSONResponse(status_code=422, content=payload.model_dump())

@app.exception_handler(sqlite3.IntegrityError)
async def sqlite_integrity_handler(request: Request, exc: sqlite3.IntegrityError):
    msg = str(exc)
    code = "integrity_error"
    # common cases (non-exhuastive)
    if "UNIQUE constraint failed" in msg:
        code, human = "unique_violation", "Unique constraint failed"
    elif "FOREIGN KEY constraint failed" in msg:
        code, human = "foreign_key_violation", "Foreign key constraint failed"
    else:
        human = "Database integrity error"
    payload = ApiError(status=400, code=code, detail=human, extra={"db_msg": msg})
    return JSONResponse(status_code=400, content=payload.model_dump())

@app.exception_handler(sqlite3.OperationalError)
async def sqlite_operational_handler(request: Request, exc: sqlite3.OperationalError):
    payload = ApiError(status=500, code="db_operational_error",
                       detail="Database operational error", extra={"db_msg": str(exc)})
    return JSONResponse(status_code=500, content=payload.model_dump())

@app.exception_handler(Exception)
async def handled_handler(request: Request, exc: Exception):
    #traceback handler/cleanup
    logger.exception("Unhandled error")
    payload = ApiError(status=500, code="internal_error",
                       detail="Internal server error", extra={"db_msg": str(exc)})
    return JSONResponse(status_code=500, content=payload.model_dump())

# ----- MIDDLEWARE ----- #
class RequestContextMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        request_id = request.headers.get("X-Request-ID") or uuid.uuid4().hex
        start = time.perf_counter()
        # Make request_id available to handlers if needed
        request.state.request_id = request_id
        try:
            response = await call_next(request)
        finally:
            dur_ms = round((time.perf_counter() - start) * 1000, 2)
            # Try to extract current user (if dependency stuck it somewhere)
            user = getattr(request.state, "username", None)
            logger.info(
                "req id=%s method=%s path=%s status=%s dur_ms=%s user=%s",
                request_id, request.method, request.url.path,
                getattr(response, "status_code", "n/a"), dur_ms, user
            )
        # Propagate the request id back
        response.headers["X-Request-ID"] = request_id
        return response

app.add_middleware(RequestContextMiddleware)

# FE API
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ----- GENERAL SECURITY & VALIDATION ----- #
SECRET_KEY = os.environ.get("DEV_JWT_SECRET", "devsecret") # Check Esmerald WF for PROD
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 120

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/login", auto_error=False)

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(password: str, hash_: str) -> bool:
    return pwd_context.verify(password, hash_)

def create_access_token(data: dict, expires_delta: int=ACCESS_TOKEN_EXPIRE_MINUTES):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(minutes=expires_delta)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def _extract_bearer_from_header(authorization: Optional[str]) -> Optional[str]:
    if not authorization:
        return None
    scheme, param = get_authorization_scheme_param(authorization)
    if scheme.lower() == "bearer" and param:
        return param
    return None

# ----- USER IDENTITY & PRIVILEGES ----- #
class CurrentUser(TypedDict):
    username: str
    user_id: int
    profile_id: int
    is_admin: bool

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
            "SELECT rowid AS user_id, username, auth_profile_id AS profile_id, is_admin FROM auth_users WHERE username = ?",
            (username,),
        )
        row = cur.fetchone()
        if not row:
            raise HTTPException(status_code=401, detail="Invalid credentials")
        # push username into EH path for logging
        request.state.username = username
        return CurrentUser(
            username=row["username"],
            user_id=row["user_id"],
            profile_id=row["profile_id"],
            is_admin=bool(row["is_admin"]),
        )

def require_owner_or_admin(target_profile_id: int, me: CurrentUser) -> None:
    if me["is_admin"]:
        return
    if me["profile_id"] == target_profile_id:
        return
    raise HTTPException(status_code=403, detail="Forbidden (ownner or admin required)")

def require_admin(me: CurrentUser) -> None:
    if not me["is_admin"]:
        raise HTTPException(status_code=403, detail="Admin only")

# ---------- HTTP ROUTES ---------- #

# ---- USER ACTIONS ----- #
@app.post("/register", response_model=dict)
def register_user(payload: UserCreate):
    now = utc_now_iso()
    with get_conn() as conn:
        cur = conn.cursor()
        try:
            cur.execute(
                """
                INSERT INTO auth_users (username, password_hash, auth_profile_id, requested_admin, created_at)
                VALUES (?, ?, ?, ?)
                """,
                (payload.username, hash_password(payload.password), payload.profile_id, 1 if payload.requested_admin else 0, now),
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
    
@app.post("/logout")
def logout():
    resp = JSONResponse({"msg": "logged out"})
    resp.delete_cookie("access_token")
    return resp

@app.get("/me")
def read_me(me: CurrentUser = Depends(get_current_user)):
    return {"username": me["username"], "profile_id": me["profile_id"], "is_admin": me["is_admin"]}

# ----- PROFILE ACTIONS ----- #
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

@app.get("/profiles/{profile_id}", response_model=ProfilePublic)
def get_profile(profile_id: int, me: CurrentUser = Depends(get_current_user)):
    # PULL 1 USER PERSONAL INFORMATION
    require_owner_or_admin(profile_id, me)

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
def get_profile_pii(profile_id: int, me: CurrentUser = Depends(get_current_user)):
    # PULL 1 USER PRIVATE INFORMATION
    require_owner_or_admin(profile_id, me)
    
    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute(
            """
            SELECT profile_id, display_name, dob
            FROM profiles
            JOIN profiles_private ON pii_profile_id=profile_id
            WHERE profile_id = ?
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
def update_profile(profile_id: int, payload: ProfileUpdate, me: CurrentUser = Depends(get_current_user)):
    # USER PERSONAL INFORMATION UPDATE FIELDS
    require_owner_or_admin(profile_id, me)

    # Update any info
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

@app.patch("/profiles/{profile_id}/pii", response_model=ProfilePII)
def update_profile_pii(profile_id: int, payload: ProfilePIIUpdate, me: CurrentUser = Depends(get_current_user)):
    # USER PRIVATE INFORMATION UPDATE FIELDS (WILL NEED ADMIN ONLY FOR ADNMIN TOGGLE)
    require_owner_or_admin(profile_id, me)

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

# ----- ADMIN ONLY LOOKUPS ----- #
@app.patch("/admin/users/{username}/admin", response_model=dict)
def set_user_admin(username: str, payload: AdminToggle, me: CurrentUser = Depends(get_current_user)):
    require_admin(me)
    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute(
            "UPDATE auth_users SET is_admin = ? WHERE username = ?",
            (1 if payload.is_admin else 0, username),
        )
        if cur.rowcount == 0:
            raise HTTPException(status_code=404, detail="User not found")
        conn.commit()
    return {"username": username, "is_admin": payload.is_admin}

@app.get("/profiles", response_model=List[ProfilePublic])
def list_profiles(
    age_band: Optional[str] = None,
    education_level: Optional[str] = None,
    limit: int = 10,
    offset: int = 0,
    me: CurrentUser = Depends(get_current_user)
):
    # ADMIN ONLY, PULLS ALL PROFILES INFORMATION
    require_admin(me)

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

@app.get("/profiles/{profile_id}/history", response_model=List[dict])
def get_profile_history(profile_id: int, me: CurrentUser = Depends(get_current_user)):
    # ADMIN ONLY -- DEBUGGING PROTOCOL, CONTEXT DRIFT ANALYTICS                    
    require_admin(me)

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
def get_profile_debug(profile_id: int, me: CurrentUser = Depends(get_current_user)):
    # ADMIN FUNCTION ONLY
    require_admin(me)

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
def get_snapshot(profile_id: int, rebuild: bool = False, me: CurrentUser = Depends(get_current_user)):
    # ADMIN ONLY: USER DIRECT REQ --> ADMIN, AUTO-PULL FOR AI COMM (RAG)
    require_admin(me)

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

@app.get("/admin/requests", response_model=List[dict])
def list_admin_requests(limit: int = 50, offset: int = 0, me: CurrentUser = Depends(get_current_user)):
    require_admin(me)
    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute(
            """
            SELECT user_id, username, auth_profile_id AS profile_id, created_at
            FROM auth_users
            WHERE requested_admin = 1 AND is_admin = 0
            ORDER BY user_id DESC
            LIMIT ? OFFSET ?
            """,
            (limit, offset),
        )
        rows = cur.fetchall()
    return [
        {
            "user_id": r["user_id"],
            "username": r["username"],
            "profile_id": r["profile_id"],
            "created_at": r["created_at"],
        }
        for r in rows
    ]

