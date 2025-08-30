from datetime import date, datetime, timezone
from typing import Optional, Literal, Dict, Any
from pydantic import BaseModel, Field, field_validator

# ----- GLOBALS ----- #
AgeBand = Literal["13_17", "18_25", "26_39", "40_plus"]
Sex = Literal["male", "female"]
EducationLevel = Literal[
    "middle_school",
    "high_school",
    "community_college",
    "trade_school",
    "university_or_four_year_college",
    "graduate_school",
]
EmploymentStatus = Literal[
    "student",
    "unemployed",
    "part_time",
    "full_time",
    "self_employed",
    "retired",
]

# ----- FUNCTIONS ----- #
def compute_age_band(dob: date) -> AgeBand: 
    today = date.today()

    years = today.year - dob.year - ((today.month, today.day) < (dob.month, dob.day))
    if years < 0 or years > 120:
        raise ValueError("Please enter a valid date of birth.")
    if years < 13:
        raise ValueError("User must be at least 13 years old.")
    if years <= 17:
        return "13_17"
    if years <= 25:
        return "18_25"
    if years <= 39:
        return "26_39"
    return "40_plus"

def utc_now_iso() -> str:
    # e.g., "2025-08-24T21:07:12.345Z"
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")

# ----- ERROR HANDLING ----- #
class ApiError(BaseModel):
    status: int
    code: str
    detail: str
    extra: Optional[Dict[str, Any]] = None

# ----- SCHEMAS ----- #
class ProfileCreate(BaseModel):
    display_name: str = Field(min_length=1, max_length=50)
    dob: date
    education_level: EducationLevel
    employment_status: Optional[EmploymentStatus]
    sex: Sex
    gender: Optional[str] = None
    locale: str = Field(min_length=2, max_length=20, pattern=r"^[a-z]{2}-[A-Z]{2}$")
    consent_ok: bool

    @field_validator("display_name")
    @classmethod
    def normalize_name(cls, v: str) -> str:
        return " ".join(v.strip().split())

class ProfilePublic(BaseModel):
    profile_id: int
    schema_version: str
    created_at: str
    updated_at: str
    age_band: AgeBand
    education_level: EducationLevel
    employment_status: Optional[EmploymentStatus] = None
    sex: Sex
    gender: Optional[str] = None
    locale: str
    consent_ok: bool
    guardian_required: bool

class ProfileUpdate(BaseModel):
    education_level: Optional[EducationLevel] = None
    employment_status: Optional[EmploymentStatus] = None
    sex: Optional[Sex] = None
    gender: Optional[str] = None
    locale: Optional[str] = Field(None, pattern=r"^[a-z]{2}-[A-Z]{2}$")
    consent_ok: Optional[bool] = None

class ProfilePII(BaseModel):
    profile_id: int
    display_name: str
    dob: date

class ProfilePIIUpdate(BaseModel):
    display_name: Optional[str] = Field(None, min_length=1, max_length=50)
    dob: Optional[date] = None

class UserCreate(BaseModel):
    username: str = Field(min_length=6, max_length=30)
    password: str = Field(min_Length=8, max_length=128)
    profile_id: int

class UserLogin(BaseModel):
    username: str
    password: str

class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"

class AdminToggle(BaseModel):
    is_admin: bool

class SnapShotOut(BaseModel):
    profile_id: int
    snapshot_type: str
    last_built_at: str
    etag: str
    data: Dict[str, Any]
