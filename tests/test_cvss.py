from app.core.feature_extractor import calculate_score, infer_features
from app.core.preprocessor import Preprocessor


def test_cvss_31_known_critical_vector():
    features = infer_features("Remote unauthenticated arbitrary code execution.", "CVE-2024-1")
    vector, score, severity = calculate_score(features)
    assert vector.startswith("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U")
    assert score == 9.8
    assert severity == "CRITICAL"


def test_feature_inference_requires_interaction():
    features = infer_features("A local vulnerability requires user interaction and discloses sensitive information.", "CVE-2024-2")
    assert features.user_interaction == "REQUIRED"
    assert features.attack_vector == "LOCAL"


def test_preprocessor_reads_nvd_11_record(tmp_path):
        path = tmp_path / "nvd.json"
        path.write_text("""{
            "CVE_Items": [{
                "cve": {
                    "CVE_data_meta": {"ID": "CVE-2024-12345"},
                    "description": {"description_data": [{"lang": "en", "value": "A remote vulnerability."}]}
                },
                "configurations": {"nodes": [{"cpe_match": [{"cpe23Uri": "cpe:2.3:a:demo:product:1.0:*:*:*:*:*:*:*"}]}]},
                "publishedDate": "2024-01-15T00:00Z",
                "lastModifiedDate": "2024-01-16T00:00Z",
                "impact": {"baseMetricV3": {"cvssV3": {"baseScore": 9.8}}}
            }]
        }""", encoding="utf-8")

        records, errors = Preprocessor().load_file(str(path))

        assert not errors
        assert records[0].cve_id == "CVE-2024-12345"
        assert records[0].description == "A remote vulnerability."
        assert records[0].affected_software.startswith("cpe:2.3:a:demo:product")
