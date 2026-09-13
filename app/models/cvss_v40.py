"""CVSS v4.0 Base metric contract and score calculation."""

from decimal import Decimal, ROUND_UP
from enum import Enum
from typing import Mapping

from pydantic import BaseModel


class _Metric(str):
    pass


class AttackVectorV40(_Metric, Enum):
    DONT_KNOW = "DONT_KNOW"
    NETWORK = "NETWORK"
    ADJACENT = "ADJACENT"
    LOCAL = "LOCAL"
    PHYSICAL = "PHYSICAL"


class AttackComplexityV40(_Metric, Enum):
    DONT_KNOW = "DONT_KNOW"
    LOW = "LOW"
    HIGH = "HIGH"


class AttackRequirementsV40(_Metric, Enum):
    DONT_KNOW = "DONT_KNOW"
    NONE = "NONE"
    PRESENT = "PRESENT"


class PrivilegesRequiredV40(_Metric, Enum):
    DONT_KNOW = "DONT_KNOW"
    NONE = "NONE"
    LOW = "LOW"
    HIGH = "HIGH"


class UserInteractionV40(_Metric, Enum):
    DONT_KNOW = "DONT_KNOW"
    NONE = "NONE"
    PASSIVE = "PASSIVE"
    ACTIVE = "ACTIVE"


class ImpactV40(_Metric, Enum):
    DONT_KNOW = "DONT_KNOW"
    NONE = "NONE"
    LOW = "LOW"
    HIGH = "HIGH"


class CVSSv40Metrics(BaseModel):
    """The 11 CVSS v4.0 Base metrics."""

    av: AttackVectorV40
    ac: AttackComplexityV40
    at: AttackRequirementsV40
    pr: PrivilegesRequiredV40
    ui: UserInteractionV40
    vc: ImpactV40
    vi: ImpactV40
    va: ImpactV40
    sc: ImpactV40
    si: ImpactV40
    sa: ImpactV40


_AV = {"NETWORK": 0.85, "ADJACENT": 0.62, "LOCAL": 0.55, "PHYSICAL": 0.2}
_AC = {"LOW": 0.77, "HIGH": 0.44}
_AT = {"NONE": 1.0, "PRESENT": 0.8}
_PR = {"NONE": 0.85, "LOW": 0.62, "HIGH": 0.27}
_UI = {"NONE": 0.85, "PASSIVE": 0.62, "ACTIVE": 0.5}
_IMPACT = {"NONE": 0.0, "LOW": 0.22, "HIGH": 0.56}


def _round_up(value: float) -> float:
    return float(Decimal(str(value * 10)).quantize(Decimal("1"), rounding=ROUND_UP) / 10)


def _value(metrics: CVSSv40Metrics, name: str, table: dict[str, float]) -> float:
    value = getattr(metrics, name).value
    if value == "DONT_KNOW":
        raise ValueError(f"DONT_KNOW cannot be scored for CVSS v4 metric {name.upper()}")
    return table[value]


def calculate_cvss_v40_score(metrics: CVSSv40Metrics | Mapping[str, str]) -> float:
    """Calculate the CVSS v4.0 Base score, rounded up to one decimal place."""
    if not isinstance(metrics, CVSSv40Metrics):
        metrics = CVSSv40Metrics.model_validate(metrics)

    vulnerable_impact = 1 - (
        (1 - _value(metrics, "vc", _IMPACT))
        * (1 - _value(metrics, "vi", _IMPACT))
        * (1 - _value(metrics, "va", _IMPACT))
    )
    subsequent_impact = 1 - (
        (1 - _value(metrics, "sc", _IMPACT))
        * (1 - _value(metrics, "si", _IMPACT))
        * (1 - _value(metrics, "sa", _IMPACT))
    )
    if vulnerable_impact == 0:
        return 0.0

    impact = 6.0 * vulnerable_impact + 1.5 * subsequent_impact
    exploitability = (
        8.22
        * _value(metrics, "av", _AV)
        * _value(metrics, "ac", _AC)
        * _value(metrics, "at", _AT)
        * _value(metrics, "pr", _PR)
        * _value(metrics, "ui", _UI)
    )
    return _round_up(min(10.0, impact + exploitability))


__all__ = ["CVSSv40Metrics", "calculate_cvss_v40_score"]