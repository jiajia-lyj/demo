import pytest
from pydantic import ValidationError

from app.models.cvss_v40 import CVSSv40Metrics, calculate_cvss_v40_score


def _metrics(**overrides: str) -> dict[str, str]:
    values = {
        "av": "NETWORK", "ac": "LOW", "at": "NONE", "pr": "NONE", "ui": "NONE",
        "vc": "HIGH", "vi": "HIGH", "va": "HIGH", "sc": "NONE", "si": "NONE", "sa": "NONE",
    }
    values.update(overrides)
    return values


def test_cvss_v40_contract_has_eleven_base_metrics():
    metrics = CVSSv40Metrics.model_validate(_metrics())
    assert len(metrics.model_dump()) == 11
    assert metrics.av.value == "NETWORK"


def test_cvss_v40_accepts_dont_know_but_score_requires_known_values():
    metrics = CVSSv40Metrics.model_validate(_metrics(ui="DONT_KNOW"))
    assert metrics.ui.value == "DONT_KNOW"
    with pytest.raises(ValueError, match="DONT_KNOW"):
        calculate_cvss_v40_score(metrics)


def test_cvss_v40_rejects_invalid_metric():
    with pytest.raises(ValidationError):
        CVSSv40Metrics.model_validate(_metrics(av="INVALID"))


def test_cvss_v40_score_is_zero_without_vulnerable_impact():
    assert calculate_cvss_v40_score(_metrics(vc="NONE", vi="NONE", va="NONE")) == 0.0