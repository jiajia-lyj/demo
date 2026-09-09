import json
import os
import random
from pathlib import Path
import pytest
from app.core.feature_extractor import calculate_score, infer_features
DATA_PATH = Path(os.getenv(
    "OFFICIAL_CVE_DATA_PATH",
    Path(__file__).resolve().parent.parent / "data" / "raw" / "nvdcve-1_1-2024.json",
))
WCL_BASELINE_ACCURACY = 0.595  # Worst-Case-Line baseline from the reference paper
SAMPLE_SIZE = 300              # keep local runs fast; raise for a fuller CI run

SHORT_AMBIGUOUS = {"N": "NONE", "L": "LOW", "H": "HIGH", "R": "REQUIRED", "U": "UNCHANGED", "C": "CHANGED", "A": "ADJACENT", "P": "PHYSICAL"}
FIELD_DECODERS = {
    "AV": {"N": "NETWORK", "A": "ADJACENT_NETWORK", "L": "LOCAL", "P": "PHYSICAL"},
    "AC": {"L": "LOW", "H": "HIGH"},
    "PR": {"N": "NONE", "L": "LOW", "H": "HIGH"},
    "UI": {"N": "NONE", "R": "REQUIRED"},
    "S": {"U": "UNCHANGED", "C": "CHANGED"},
    "C": {"N": "NONE", "L": "LOW", "H": "HIGH"},
    "I": {"N": "NONE", "L": "LOW", "H": "HIGH"},
    "A": {"N": "NONE", "L": "LOW", "H": "HIGH"},
}
VECTOR_FIELD_MAP = {"AV": "attack_vector", "AC": "attack_complexity", "PR": "privileges_required",
                     "UI": "user_interaction", "S": "scope", "C": "confidentiality",
                     "I": "integrity", "A": "availability"}
def _severity_of(score: float) -> str:
    return "NONE" if score == 0 else "LOW" if score <= 3.9 else "MEDIUM" if score <= 6.9 else "HIGH" if score <= 8.9 else "CRITICAL"
def _decode_official_vector(vector_string: str) -> dict:
    parts = dict(p.split(":") for p in vector_string.split("/")[1:])
    return {VECTOR_FIELD_MAP[k]: FIELD_DECODERS[k][v] for k, v in parts.items() if k in VECTOR_FIELD_MAP}
@pytest.fixture(scope="module")
def official_cve_sample():
    if not DATA_PATH.exists():
        pytest.skip(f"Official CVE dataset not found at {DATA_PATH}. Set OFFICIAL_CVE_DATA_PATH or copy the file there.")
    with DATA_PATH.open(encoding="utf-8") as fh:
        data = json.load(fh)
    items = [it for it in data["CVE_Items"] if (it.get("impact") or {}).get("baseMetricV3")]
    random.seed(42)
    return random.sample(items, min(SAMPLE_SIZE, len(items)))
def _description_of(item):
    entries = item["cve"]["description"]["description_data"]
    return next((e["value"] for e in entries if e.get("lang", "en") == "en"), "")
def _official_of(item):
    cvss = item["impact"]["baseMetricV3"]["cvssV3"]
    return cvss.get("vectorString"), cvss.get("baseScore"), cvss.get("baseSeverity")
# DEFECT 1 (Critical): scheduler._nvd_features() leaks the official CVSS
def test_true_zero_shot_does_not_trivially_match_official(official_cve_sample):
    """Sanity check: genuine zero-shot inference (text only) should NOT match
    the official vector at a suspiciously high rate. A rate above 20% here
    would indicate the 'zero-shot' path is still leaking official data."""
    matches = 0
    total = 0
    for item in official_cve_sample:
        description = _description_of(item)
        official_vector, official_score, _ = _official_of(item)
        if not description or official_score is None:
            continue
        features = infer_features(description, item["cve"]["CVE_data_meta"]["ID"], values=None)
        official_fields = _decode_official_vector(official_vector)
        if all(getattr(features, field) == official_fields.get(field) for field in official_fields):
            matches += 1
        total += 1
    rate = matches / total
    assert rate < 0.20, (
        f"Zero-shot full-vector match rate is {rate:.1%}, suspiciously high. "
        "If this ever approaches 100%, check scheduler._nvd_features() for data leakage "
        "(it currently pulls official AV/AC/PR/UI/S/C/I/A straight from raw_data)."
    )
# DEFECT 2: DK (local-rule) fallback accuracy vs the WCL paper baseline.
def test_dk_fallback_severity_accuracy_beats_wcl_baseline(official_cve_sample):
    """Zero-shot DK fallback severity-level (4-class) accuracy must exceed
    the WCL (Worst-Case-Line) baseline of 0.595, per the assigned QA target.
    Currently measured at ~0.55 -- BELOW baseline. Log as a defect against
    the feature-inference keyword rules (app/core/feature_extractor.py)."""
    correct = 0
    total = 0
    for item in official_cve_sample:
        description = _description_of(item)
        official_vector, official_score, official_severity = _official_of(item)
        if not description or official_score is None:
            continue
        features = infer_features(description, item["cve"]["CVE_data_meta"]["ID"], values=None)
        _, predicted_score, _ = calculate_score(features)
        if _severity_of(predicted_score) == official_severity:
            correct += 1
        total += 1
    accuracy = correct / total
    assert accuracy > WCL_BASELINE_ACCURACY, (
        f"DK fallback severity accuracy is {accuracy:.3f} on {total} zero-shot CVE samples, "
        f"which does NOT beat the WCL baseline of {WCL_BASELINE_ACCURACY}. "
        "The keyword-based feature inference needs improvement before DK fallback "
        "can be considered production-viable."
    )
# DEFECT 3: LLM-enhanced values are silently dropped due to a key-name
def test_llm_enhancement_values_are_actually_applied():
    """The LLM prompt in llm_enhancer.py instructs the model to return keys
    'AV, AC, PR, UI, S, C, I, A', but infer_features() only recognizes
    long-form keys like 'attack_vector'. This test proves the short-form
    keys are silently discarded, meaning LLM enhancement currently changes
    nothing about the final score. Log as Critical defect against the
    interface contract between llm_enhancer.py and feature_extractor.py."""
    description = "A local vulnerability requiring no user interaction."
    baseline = infer_features(description, "CVE-2099-1", values=None)
    # Exactly the shape llm_enhancer.py's prompt asks the model to return:
    llm_style_values = {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "H"}
    enhanced = infer_features(description, "CVE-2099-1", values=llm_style_values)

    changed_fields = {f for f in ("attack_vector", "attack_complexity", "privileges_required",
                                   "user_interaction", "scope", "confidentiality", "integrity", "availability")
                       if getattr(baseline, f) != getattr(enhanced, f)}
    assert changed_fields, (
        "LLM-style short-key output (AV/AC/PR/UI/S/C/I/A) produced NO change to the inferred "
        "features. infer_features()'s key-matching only accepts long-form field names, so "
        "LLM enhancement is currently a silent no-op. Fix the key mapping in "
        "app/core/feature_extractor.py's infer_features() before relying on LLM-enhanced scoring."
    )
# DEFECT 4: calculate_score() crashes on the real CVSS v3.1 value
def test_calculate_score_handles_adjacent_network_attack_vector():
    """Real NVD data uses 'ADJACENT_NETWORK' as the AV value, but
    VALUES['AV'] in feature_extractor.py only defines 'ADJACENT'. This
    crashes calculate_score() with a KeyError on ~1.4% of real-world CVEs.
    Log as defect against app/core/feature_extractor.py's VALUES dict."""
    features = infer_features(
        "A vulnerability requiring adjacent network access.",
        "CVE-2099-2",
        values={"attack_vector": "ADJACENT_NETWORK", "attack_complexity": "LOW",
                "privileges_required": "NONE", "user_interaction": "NONE",
                "scope": "UNCHANGED", "confidentiality": "HIGH",
                "integrity": "HIGH", "availability": "HIGH"},
    )
    try:
        calculate_score(features)
    except KeyError as error:
        pytest.fail(f"calculate_score() crashed on a real CVSS v3.1 value: {error}")
