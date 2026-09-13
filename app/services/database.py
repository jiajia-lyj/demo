import json
import os
import sqlite3
from typing import Any

from app.config import settings
from app.models.schemas import CVERecord


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
    affected_software TEXT, cvss_version TEXT, cvss_vector TEXT,
    cvss_base_score REAL, cvss_severity TEXT,
    raw_data TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
                CREATE TABLE IF NOT EXISTS cvss_scores (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, cve_id TEXT NOT NULL,
                    cvss_vector TEXT, base_score REAL, severity TEXT, llm_model TEXT,
                    prompt_tokens INTEGER, completion_tokens INTEGER, confidence REAL,
                    scored_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (cve_id) REFERENCES cve_records(cve_id)
                );
            """)

            columns = {
                row["name"]
                for row in connection.execute(
                    "PRAGMA table_info(cve_records)"
                ).fetchall()
            }

            migrations = {
                "cvss_version": "TEXT",
                "cvss_vector": "TEXT",
                "cvss_base_score": "REAL",
                "cvss_severity": "TEXT",
            }

            for column, column_type in migrations.items():
                if column not in columns:
                    connection.execute(
                        f"ALTER TABLE cve_records ADD COLUMN {column} {column_type}"
                    )

    def upsert_cves(self, records: list[CVERecord]) -> int:
        with self.connect() as connection:
            for record in records:
                connection.execute("""INSERT INTO cve_records
                    (cve_id, description, published_date, updated_date, affected_software,
                     cvss_version, cvss_vector, cvss_base_score, cvss_severity, raw_data)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(cve_id) DO UPDATE SET
                    description=excluded.description,
                    published_date=excluded.published_date,
                    updated_date=excluded.updated_date,
                    affected_software=excluded.affected_software,
                    cvss_version=excluded.cvss_version,
                    cvss_vector=excluded.cvss_vector,
                    cvss_base_score=excluded.cvss_base_score,
                    cvss_severity=excluded.cvss_severity,
                    raw_data=excluded.raw_data""",
                                   (
                                       record.cve_id,
                                       record.description,
                                       record.published_date,
                                       record.updated_date,
                                       record.affected_software,
                                       record.cvss_version,
                                       record.cvss_vector,
                                       record.cvss_base_score,
                                       record.cvss_severity,
                                       json.dumps(record.raw_data or {}, ensure_ascii=False),
                                   ))
        return len(records)

    def get_cve(self, cve_id: str) -> dict[str, Any] | None:
        with self.connect() as connection:
            row = connection.execute("SELECT * FROM cve_records WHERE cve_id=?", (cve_id,)).fetchone()
        return dict(row) if row else None

    def list_cves(self, limit: int | None = None) -> list[dict[str, Any]]:
        with self.connect() as connection:
            if limit is None:
                rows = connection.execute(
                    "SELECT * FROM cve_records ORDER BY cve_id"
                ).fetchall()
            else:
                rows = connection.execute(
                    "SELECT * FROM cve_records ORDER BY cve_id LIMIT ?",
                    (limit,),
                ).fetchall()

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
