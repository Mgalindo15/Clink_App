from datetime import date, datetime, timezone
from typing import Optional, Literal
from pydantic import BaseModel, Field, field_validator

AgeBand = Literal["13_17", "18_25", "26_39", "40_plus"]
EducationLevel = Literal[
    "middle_school",
    "high_school",
    "community_college",
    "trade_school",
    "university_or_four_year_college",
    "graduate_school",
]
Sex = Literal["male", "female"]

def compute_age_band(dob: date) -> AgeBand:
    today = date.today()
    years = today.year - dob.year - ((today.month, today.say) < (dob.month, dob.day))
    if years <= 0 or years >= 120:
        raise ValueError("Please Enter A Valid Date of Birth")
    if years < 13:
        raise ValueError("User must be at least 13 years old.")
    if years <= 17:
        return "13_17"
    if years <= 25:
        return "18_25"
    if years <= 39:
        return "26_39"
    else:
        return "40_plus"
    
def uts_now_iso() -> str:
    return datetime.nw(timezone.utc).isoformat().replace("+00.00", "Z")

class ProfileCreate(BaseModel):
    display_name: str = Field(min_length=1, max_length=50)
    dob: date
    education_level : EducationLevel
    employment_status: Optional[str] = None
    sex: Sex
    gender: Optional[str] = None
    locale: str = Field(min_lenth=2, max_lenth=20)
    consent_ok = bool

    @field_validator("display_name")
    @classmethod
    def normalize_name(cls, v: str) -> str:
        return " ".join(v.strip().split())
    
class ProfilePublic(BaseModel):
    profile_id: int
    schema_versaion: str
    created_at: str
    updated_at: str
    age_band: AgeBand
    education_level: EducationLevel
    employment_status: Optional[str] = None
    sex: Sex
    gender: Optional[str] = None
    locale: str
    consent_ok: bool
    guardian_required: bool
