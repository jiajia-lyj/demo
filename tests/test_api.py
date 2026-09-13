from fastapi.testclient import TestClient

from app.api.endpoints import database
from app.main import app
from app.schemas import CVERecord


client = TestClient(app)


def setup_module():
    database.upsert_cves([CVERecord(cve_id="CVE-2099-1", description="Remote unauthenticated arbitrary code execution.")])


def test_health():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"
    assert "llm_model" in response.json()


def test_model_capabilities():
    response = client.get("/api/v1/models/capabilities")
    assert response.status_code == 200
    payload = response.json()
    assert payload["models"]
    assert "supports_few_shot" in payload["active_model"]
    assert "context_length" in payload["active_model"]


def test_score_without_llm():
    response = client.post("/api/v1/score/CVE-2099-1?use_llm=false")
    assert response.status_code == 200
    assert response.json()["severity"] == "CRITICAL"


def test_batch_score_without_llm():
    response = client.post("/api/v1/score/batch", json={"cve_ids": ["CVE-2099-1"], "use_llm": False})
    assert response.status_code == 200
    assert response.json()[0]["cve_id"] == "CVE-2099-1"


def test_missing_cve():
    assert client.get("/api/v1/cve/CVE-2099-404").status_code == 404
