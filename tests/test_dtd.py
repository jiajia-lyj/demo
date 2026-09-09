import importlib.util
import json
from pathlib import Path

import pytest
from unittest.mock import MagicMock, patch

from fastapi.testclient import TestClient

from app.api.endpoints import database
from app.config import Settings
from app.core.llm_enhancer import LLMEnhancer, MetricPrediction
from app.core.prompt_templates import (
    CVSS_V31_METRICS,
    DONT_KNOW,
    all_metric_keys,
    build_dtd_prompt,
)
from app.main import app
from app.schemas import CVERecord


ROOT = Path(__file__).resolve().parent.parent
client = TestClient(app)


def setup_module():
    database.upsert_cves([CVERecord(cve_id="CVE-2099-777", description="Remote unauthenticated arbitrary code execution.")])


METRIC_CASES = [
    ("attack_vector", "AV", "Attack Vector", ["NETWORK", "ADJACENT", "LOCAL", "PHYSICAL"]),
    ("attack_complexity", "AC", "Attack Complexity", ["LOW", "HIGH"]),
    ("privileges_required", "PR", "Privileges Required", ["NONE", "LOW", "HIGH"]),
    ("user_interaction", "UI", "User Interaction", ["NONE", "REQUIRED"]),
    ("scope", "S", "Scope", ["UNCHANGED", "CHANGED"]),
    ("confidentiality", "C", "Confidentiality Impact", ["NONE", "LOW", "HIGH"]),
    ("integrity", "I", "Integrity Impact", ["NONE", "LOW", "HIGH"]),
    ("availability", "A", "Availability Impact", ["NONE", "LOW", "HIGH"]),
]


@pytest.mark.parametrize("snake,abbr,name,labels", METRIC_CASES)
def test_build_dtd_prompt_for_each_metric(snake, abbr, name, labels):
    prompt = build_dtd_prompt(snake)
    assert prompt.metric_name == name
    assert prompt.metric_abbr == abbr
    expected = labels + [DONT_KNOW]
    assert prompt.valid_labels == expected
    assert "{cve_description}" in prompt.template
    assert prompt.spec_text in prompt.template
    for label in labels:
        assert label in prompt.spec_text


def test_build_dtd_prompt_resolves_name_aliases():
    full = build_dtd_prompt("Attack Vector")
    abbr = build_dtd_prompt("AV")
    snake = build_dtd_prompt("attack_vector")
    upper = build_dtd_prompt("ATTACK VECTOR")
    assert full.template == snake.template == abbr.template == upper.template


def test_build_dtd_prompt_unknown_metric_raises():
    with pytest.raises(ValueError):
        build_dtd_prompt("not_a_metric")


def test_dtd_prompt_render_substitutes_description():
    prompt = build_dtd_prompt("AV")
    rendered = prompt.render("A remote heap overflow.")
    assert "{cve_description}" not in rendered
    assert "A remote heap overflow." in rendered


def test_dtd_prompt_embeds_full_spec_text():
    prompt = build_dtd_prompt("scope")
    spec = CVSS_V31_METRICS["scope"]
    assert spec.description in prompt.spec_text
    assert "UNCHANGED" in prompt.spec_text
    assert "CHANGED" in prompt.spec_text
    assert "Scope" in prompt.spec_text


def test_all_metric_keys_returns_eight():
    keys = all_metric_keys()
    assert len(keys) == 8
    assert set(keys) == set(CVSS_V31_METRICS.keys())


def _disabled_enhancer() -> LLMEnhancer:
    return LLMEnhancer(Settings(llm_base_url="", llm_api_key=""))


def _enabled_settings() -> Settings:
    return Settings(llm_base_url="http://localhost", llm_api_key="key", llm_model="m")


def test_predict_with_dtd_disabled_returns_dont_know():
    enhancer = _disabled_enhancer()
    assert enhancer.predict_with_dtd("remote code execution", "AV") == DONT_KNOW


def test_predict_with_dtd_enabled_returns_label():
    enhancer = LLMEnhancer(_enabled_settings())
    mock_client = MagicMock()
    mock_client.chat.completions.create.return_value = MetricPrediction(value="NETWORK")
    with patch("app.core.llm_enhancer.get_instructor_client", return_value=mock_client):
        result = enhancer.predict_with_dtd("A remote unauthenticated exploit.", "AV")
    assert result == "NETWORK"
    call_kwargs = mock_client.chat.completions.create.call_args.kwargs
    assert call_kwargs["response_model"] is MetricPrediction
    assert call_kwargs["temperature"] == 0
    assert call_kwargs["model"] == "m"
    sent_content = call_kwargs["messages"][0]["content"]
    assert "A remote unauthenticated exploit." in sent_content
    assert "Attack Vector" in sent_content


def test_predict_with_dtd_normalizes_lowercase_label():
    enhancer = LLMEnhancer(_enabled_settings())
    mock_client = MagicMock()
    mock_client.chat.completions.create.return_value = MetricPrediction(value="network")
    with patch("app.core.llm_enhancer.get_instructor_client", return_value=mock_client):
        assert enhancer.predict_with_dtd("remote exploit", "AV") == "NETWORK"


def test_predict_with_dtd_invalid_label_falls_back():
    enhancer = LLMEnhancer(_enabled_settings())
    mock_client = MagicMock()
    mock_client.chat.completions.create.return_value = MetricPrediction(value="BOGUS")
    with patch("app.core.llm_enhancer.get_instructor_client", return_value=mock_client):
        assert enhancer.predict_with_dtd("desc", "AV") == DONT_KNOW


def test_predict_with_dtd_llm_exception_falls_back():
    enhancer = LLMEnhancer(_enabled_settings())
    mock_client = MagicMock()
    mock_client.chat.completions.create.side_effect = RuntimeError("timeout")
    with patch("app.core.llm_enhancer.get_instructor_client", return_value=mock_client):
        assert enhancer.predict_with_dtd("desc", "AV") == DONT_KNOW


def test_predict_with_dtd_unknown_metric_raises_even_when_disabled():
    enhancer = _disabled_enhancer()
    with pytest.raises(ValueError):
        enhancer.predict_with_dtd("desc", "BOGUS_METRIC")


def test_dtd_prompt_stable_with_long_description():
    long_desc = "A " + "remote " * 2000 + "vulnerability."
    prompt = build_dtd_prompt("confidentiality")
    rendered = prompt.render(long_desc)
    assert long_desc in rendered
    assert rendered.count("{cve_description}") == 0
    assert len(rendered) > len(long_desc)


def test_predict_with_dtd_long_description_does_not_crash_when_disabled():
    enhancer = _disabled_enhancer()
    long_desc = "X" * 8000
    assert enhancer.predict_with_dtd(long_desc, "integrity") == DONT_KNOW


def test_predict_with_dtd_long_description_passes_full_content_to_llm():
    enhancer = LLMEnhancer(_enabled_settings())
    long_desc = "A " + "crafted " * 3000 + "request causes a crash."
    mock_client = MagicMock()
    mock_client.chat.completions.create.return_value = MetricPrediction(value="HIGH")
    with patch("app.core.llm_enhancer.get_instructor_client", return_value=mock_client):
        result = enhancer.predict_with_dtd(long_desc, "availability")
    assert result == "HIGH"
    sent_content = mock_client.chat.completions.create.call_args.kwargs["messages"][0]["content"]
    assert long_desc in sent_content


def test_dtd_prompt_repeated_build_is_deterministic():
    first = build_dtd_prompt("PR")
    second = build_dtd_prompt("PR")
    assert first.template == second.template
    assert first.spec_text == second.spec_text
    assert first.valid_labels == second.valid_labels


def test_dtd_predict_endpoint_returns_dont_know_when_llm_disabled():
    response = client.post("/api/v1/score/dtd/predict", json={
        "cve_description": "A remote heap overflow.",
        "metric": "AV",
    })
    assert response.status_code == 200
    body = response.json()
    assert body["metric_name"] == "Attack Vector"
    assert body["value"] == DONT_KNOW
    assert "NETWORK" in body["valid_labels"]


def test_dtd_predict_endpoint_unknown_metric_returns_400():
    response = client.post("/api/v1/score/dtd/predict", json={
        "cve_description": "desc",
        "metric": "BOGUS",
    })
    assert response.status_code == 400


def test_dtd_score_cve_endpoint_local_fallback():
    response = client.post("/api/v1/score/dtd/CVE-2099-777")
    assert response.status_code == 200
    body = response.json()
    assert body["cve_id"] == "CVE-2099-777"
    assert body["severity"] == "CRITICAL"
    assert body["cvss_vector"].startswith("CVSS:3.1/")
    assert set(body["dtd_values"].keys()) == set(all_metric_keys())
    assert all(v == DONT_KNOW for v in body["dtd_values"].values())


def test_dtd_score_cve_endpoint_not_found_returns_404():
    response = client.post("/api/v1/score/dtd/CVE-2099-404")
    assert response.status_code == 404


def _load_distribution_module():
    spec = importlib.util.spec_from_file_location(
        "extract_metric_distribution", ROOT / "scripts" / "extract_metric_distribution.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _write_mini_nvd(path: Path, records: list[dict]) -> None:
    payload = {"CVE_Items": [
        {
            "cve": {"CVE_data_meta": {"ID": "CVE-2024-1"}, "description": {"description_data": [{"lang": "en", "value": "x"}]}},
            "impact": {"baseMetricV3": {"cvssV3": rec}},
        }
        for rec in records
    ]}
    path.write_text(json.dumps(payload), encoding="utf-8")


def test_extract_distribution_counts_labels(tmp_path):
    dist = _load_distribution_module()
    dataset = tmp_path / "nvd.json"
    _write_mini_nvd(dataset, [
        {"attackVector": "NETWORK", "attackComplexity": "LOW", "privilegesRequired": "NONE",
         "userInteraction": "NONE", "scope": "UNCHANGED", "confidentialityImpact": "HIGH",
         "integrityImpact": "HIGH", "availabilityImpact": "HIGH"},
        {"attackVector": "LOCAL", "attackComplexity": "HIGH", "privilegesRequired": "LOW",
         "userInteraction": "REQUIRED", "scope": "CHANGED", "confidentialityImpact": "LOW",
         "integrityImpact": "LOW", "availabilityImpact": "NONE"},
    ])
    counters, total = dist.extract_distribution(str(dataset))
    assert total == 2
    assert counters["attack_vector"]["NETWORK"] == 1
    assert counters["attack_vector"]["LOCAL"] == 1
    assert counters["scope"]["CHANGED"] == 1
    assert counters["availability"]["NONE"] == 1


def test_extract_distribution_normalizes_adjacent_network(tmp_path):
    dist = _load_distribution_module()
    dataset = tmp_path / "nvd.json"
    _write_mini_nvd(dataset, [
        {"attackVector": "ADJACENT_NETWORK", "attackComplexity": "LOW", "privilegesRequired": "NONE",
         "userInteraction": "NONE", "scope": "UNCHANGED", "confidentialityImpact": "HIGH",
         "integrityImpact": "HIGH", "availabilityImpact": "HIGH"},
    ])
    counters, total = dist.extract_distribution(str(dataset))
    assert total == 1
    assert counters["attack_vector"]["ADJACENT"] == 1
    assert "ADJACENT_NETWORK" not in counters["attack_vector"]


def test_compare_with_spec_detects_mismatch():
    dist = _load_distribution_module()
    from collections import Counter
    counters = {key: Counter() for key in all_metric_keys()}
    counters["attack_vector"]["NETWORK"] = 5
    counters["attack_vector"]["BOGUS_LABEL"] = 1
    report = dist.compare_with_spec(counters)
    assert "BOGUS_LABEL" in report["attack_vector"]["labels_in_dataset_not_in_spec"]
    assert report["attack_vector"]["labels_in_dataset_not_in_spec"]


def test_compare_with_spec_clean_dataset_has_no_mismatch(tmp_path):
    dist = _load_distribution_module()
    dataset = tmp_path / "nvd.json"
    _write_mini_nvd(dataset, [
        {"attackVector": "NETWORK", "attackComplexity": "LOW", "privilegesRequired": "NONE",
         "userInteraction": "NONE", "scope": "UNCHANGED", "confidentialityImpact": "HIGH",
         "integrityImpact": "HIGH", "availabilityImpact": "HIGH"},
    ])
    counters, _ = dist.extract_distribution(str(dataset))
    report = dist.compare_with_spec(counters)
    for info in report.values():
        assert not info["labels_in_dataset_not_in_spec"]