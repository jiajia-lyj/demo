import json
import os
import sqlite3
from datetime import datetime, timezone
from typing import Any

from app.config import settings
from app.core.feature_extractor import FeatureExtractor
from app.core.llm_enhancer import LLMEnhancer
from app.schemas import CVERecord, ScoreResult


class Database:
    def __init__(self, path: str | None = None):
        self.path = path or settings.database_path
        os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
        self.initialize()

    def connect(self):
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        return connection

    def initialize(self) -> None:
        with self.connect() as connection:
            connection.executescript("""
                CREATE TABLE IF NOT EXISTS cve_records (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, cve_id TEXT UNIQUE NOT NULL,
                    description TEXT NOT NULL, published_date TEXT, updated_date TEXT,
                    affected_software TEXT, raw_data TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP
                );
                CREATE TABLE IF NOT EXISTS cvss_scores (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, cve_id TEXT NOT NULL,
                    cvss_vector TEXT, base_score REAL, severity TEXT, llm_model TEXT,
                    prompt_tokens INTEGER, completion_tokens INTEGER, confidence REAL,
                    scored_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (cve_id) REFERENCES cve_records(cve_id)
                );
            """)

    def upsert_cves(self, records: list[CVERecord]) -> int:
        with self.connect() as connection:
            for record in records:
                connection.execute("""INSERT INTO cve_records
                    (cve_id, description, published_date, updated_date, affected_software, raw_data)
                    VALUES (?, ?, ?, ?, ?, ?)
                    ON CONFLICT(cve_id) DO UPDATE SET description=excluded.description,
                    published_date=excluded.published_date, updated_date=excluded.updated_date,
                    affected_software=excluded.affected_software, raw_data=excluded.raw_data""",
                    (record.cve_id, record.description, record.published_date, record.updated_date,
                     record.affected_software, json.dumps(record.raw_data or {}, ensure_ascii=False)))
        return len(records)

    def get_cve(self, cve_id: str) -> dict[str, Any] | None:
        with self.connect() as connection:
            row = connection.execute("SELECT * FROM cve_records WHERE cve_id=?", (cve_id,)).fetchone()
        return dict(row) if row else None

    def list_cves(self, limit: int) -> list[dict[str, Any]]:
        with self.connect() as connection:
            rows = connection.execute("SELECT * FROM cve_records ORDER BY cve_id LIMIT ?", (limit,)).fetchall()
        return [dict(row) for row in rows]

    def save_score(self, cve_id: str, result: dict[str, Any]) -> None:
        usage = result.get("token_usage") or {}
        with self.connect() as connection:
            connection.execute("""INSERT INTO cvss_scores
                (cve_id, cvss_vector, base_score, severity, llm_model, prompt_tokens,
                 completion_tokens, confidence) VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (cve_id, result["cvss_vector"], result["cvss_base_score"], result["severity"],
                 result.get("llm_model"), usage.get("prompt_tokens"), usage.get("completion_tokens"), result.get("llm_confidence")))

    def latest_score(self, cve_id: str) -> dict[str, Any] | None:
        with self.connect() as connection:
            row = connection.execute("SELECT * FROM cvss_scores WHERE cve_id=? ORDER BY id DESC LIMIT 1", (cve_id,)).fetchone()
        return dict(row) if row else None


class Scheduler:
    def __init__(self, database: Database):
        self.database = database
        self.extractor = FeatureExtractor()
        self.llm = LLMEnhancer(settings)

    def _nvd_features(self, record: dict[str, Any]) -> dict[str, str]:
        try:
            raw = json.loads(record.get("raw_data") or "{}")
        except json.JSONDecodeError:
            return {}
        impact = raw.get("impact") or {}
        metric = impact.get("baseMetricV3") or impact.get("baseMetricV2") or {}
        cvss = metric.get("cvssV3") or metric.get("cvssV2") or {}
        fields = {
            "attackVector": "attack_vector",
            "attackComplexity": "attack_complexity",
            "privilegesRequired": "privileges_required",
            "userInteraction": "user_interaction",
            "scope": "scope",
            "confidentialityImpact": "confidentiality",
            "integrityImpact": "integrity",
            "availabilityImpact": "availability",
        }
        return {target: cvss[source] for source, target in fields.items() if source in cvss}

    def score(self, cve_id: str, use_llm: bool = True) -> ScoreResult:
        record = self.database.get_cve(cve_id)
        if not record:
            raise KeyError(cve_id)
        values = self._nvd_features(record)
        confidence = usage = None
        model = None
        if use_llm:
            try:
                llm_values, confidence, usage = self.llm.enhance(record["description"], cve_id)
                if llm_values:
                    values.update(llm_values)
                    model = settings.llm_model
            except Exception:
                pass
        features = self.extractor.extract(cve_id, record["description"], values)
        vector, score, severity = self.extractor.score(features)
        result = ScoreResult(cve_id=cve_id, cvss_vector=vector, cvss_base_score=score, severity=severity,
                             features=features, llm_confidence=confidence, llm_model=model,
                             token_usage=usage, timestamp=datetime.now(timezone.utc))
        self.database.save_score(cve_id, result.model_dump())
        return result
