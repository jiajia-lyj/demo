from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class CVERecord(BaseModel):
    cve_id: str = Field(pattern=r"^CVE-\d{4}-\d+$")
    description: str = Field(min_length=1)
    published_date: str | None = None
    updated_date: str | None = None
    affected_software: str | None = None
    raw_data: dict[str, Any] | None = None


class CVSSFeatures(BaseModel):
    cve_id: str
    attack_vector: str
    attack_complexity: str
    privileges_required: str
    user_interaction: str
    scope: str
    confidentiality: str
    integrity: str
    availability: str
    source: str = "rules"


class ScoreResult(BaseModel):
    cve_id: str
    cvss_vector: str
    cvss_base_score: float
    severity: str
    features: CVSSFeatures
    llm_confidence: float | None = None
    llm_model: str | None = None
    token_usage: dict[str, int] | None = None
    timestamp: datetime


class ImportResponse(BaseModel):
    imported: int
    skipped: int
    errors: list[str]


class BatchScoreRequest(BaseModel):
    cve_ids: list[str] | None = None
    limit: int = Field(default=20, ge=1, le=500)
