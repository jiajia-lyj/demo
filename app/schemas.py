from datetime import datetime
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, Field


# CVSS v3.1 metric values used by the conservative DONT_KNOW post-processor.
class AVEnum(str, Enum):
    NETWORK = "NETWORK"
    ADJACENT = "ADJACENT"
    LOCAL = "LOCAL"
    PHYSICAL = "PHYSICAL"
    DONT_KNOW = "DONT_KNOW"


class ACEnum(str, Enum):
    LOW = "LOW"
    HIGH = "HIGH"
    DONT_KNOW = "DONT_KNOW"


class PREnum(str, Enum):
    NONE = "NONE"
    LOW = "LOW"
    HIGH = "HIGH"
    DONT_KNOW = "DONT_KNOW"


class UIEnum(str, Enum):
    NONE = "NONE"
    REQUIRED = "REQUIRED"
    DONT_KNOW = "DONT_KNOW"


class SEnum(str, Enum):
    UNCHANGED = "UNCHANGED"
    CHANGED = "CHANGED"
    DONT_KNOW = "DONT_KNOW"


class CEnum(str, Enum):
    NONE = "NONE"
    LOW = "LOW"
    HIGH = "HIGH"
    DONT_KNOW = "DONT_KNOW"


class IEnum(str, Enum):
    NONE = "NONE"
    LOW = "LOW"
    HIGH = "HIGH"
    DONT_KNOW = "DONT_KNOW"


class AEnum(str, Enum):
    NONE = "NONE"
    LOW = "LOW"
    HIGH = "HIGH"
    DONT_KNOW = "DONT_KNOW"


class CvssAllPrediction(BaseModel):
    """Structured prediction containing all eight CVSS v3.1 base metrics."""

    av: AVEnum
    ac: ACEnum
    pr: PREnum
    ui: UIEnum
    s: SEnum
    c: CEnum
    i: IEnum
    a: AEnum


class AttackVector(BaseModel):
    value: Literal["NETWORK", "ADJACENT", "LOCAL", "PHYSICAL", "DONT_KNOW"]


class AttackComplexity(BaseModel):
    value: Literal["LOW", "HIGH", "DONT_KNOW"]


class PrivilegesRequired(BaseModel):
    value: Literal["NONE", "LOW", "HIGH", "DONT_KNOW"]


class UserInteraction(BaseModel):
    value: Literal["NONE", "REQUIRED", "DONT_KNOW"]


class Scope(BaseModel):
    value: Literal["UNCHANGED", "CHANGED", "DONT_KNOW"]


class ConfidentialityImpact(BaseModel):
    value: Literal["NONE", "LOW", "HIGH", "DONT_KNOW"]


class IntegrityImpact(BaseModel):
    value: Literal["NONE", "LOW", "HIGH", "DONT_KNOW"]


class AvailabilityImpact(BaseModel):
    value: Literal["NONE", "LOW", "HIGH", "DONT_KNOW"]


class CVSSLLMResponse(BaseModel):
    attack_vector: AttackVector
    attack_complexity: AttackComplexity
    privileges_required: PrivilegesRequired
    user_interaction: UserInteraction
    scope: Scope
    confidentiality: ConfidentialityImpact
    integrity: IntegrityImpact
    availability: AvailabilityImpact


class CVERecord(BaseModel):
    cve_id: str = Field(pattern=r"^CVE-\d{4}-\d+$")
    description: str = Field(min_length=1)
    published_date: str | None = None
    updated_date: str | None = None
    affected_software: str | None = None
    cvss_version: str | None = None
    cvss_vector: str | None = None
    cvss_base_score: float | None = None
    cvss_severity: str | None = None
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
    limit: int = Field(default=20, ge=1, le=20)
    use_llm: bool = True


class DTDPredictRequest(BaseModel):
    cve_description: str = Field(min_length=1)
    metric: str = Field(min_length=1)


class DTDPredictResponse(BaseModel):
    metric: str
    metric_name: str
    value: str
    valid_labels: list[str]


class DTDScoreResponse(BaseModel):
    cve_id: str
    cvss_vector: str
    cvss_base_score: float
    severity: str
    features: CVSSFeatures
    dtd_values: dict[str, str]
    llm_model: str | None = None
    timestamp: datetime

class PredictStrategy(str, Enum):
    DTD = "dtd"
    DTD_FEWSHOT = "dtd_fewshot"
    FVP = "fvp"
    STD = "std"


class CvssVersion(str, Enum):
    V31 = "3.1"
    V40 = "4.0"


class PredictRequest(BaseModel):
    cve_description: str = Field(min_length=1)
    metric: str = Field(min_length=1)
    strategy: PredictStrategy = PredictStrategy.DTD_FEWSHOT
    shots: int = Field(default=24, ge=0, le=64)
    model: str | None = None
    cvss_version: CvssVersion = CvssVersion.V31


class PredictResponse(BaseModel):
    metric: str
    metric_name: str
    value: str
    valid_labels: list[str]
    strategy: str
    shots_requested: int
    shots_used: int
    model: str
    cvss_version: str
    context_info: dict[str, Any] | None = None


class CompareViewRequest(BaseModel):
    cve_id: str = Field(pattern=r"^CVE-\d{4}-\d+$")


class CompareViewResponse(BaseModel):
    cve_id: str
    official_score: float | None = None
    official_vector: str | None = None
    official_metrics: dict[str, str] | None = None
    llm_score: float | None = None
    llm_vector: str | None = None
    llm_metrics: dict[str, str] | None = None
    worst_case_score: float | None = None
    worst_case_vector: str | None = None
    worst_case_metrics: dict[str, str] | None = None
    difference: float | None = None
