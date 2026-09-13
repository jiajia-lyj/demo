import hashlib
import json
import math
import re
from pathlib import Path
from typing import Any


class RAGRetriever:
    """Persistent CVE similarity index implemented with the standard library."""

    def __init__(self, index_path: str = "data/rag_index.json", model_name: str = "hashing-256"):
        self.index_path = Path(index_path)
        self.model_name = model_name
        self.embedding_dimensions = 256
        self.records: dict[str, dict[str, Any]] = {}
        self._load()

    def _load(self) -> None:
        if not self.index_path.exists():
            return
        try:
            payload = json.loads(self.index_path.read_text(encoding="utf-8"))
            if payload.get("dimensions") == self.embedding_dimensions:
                self.records = payload.get("records", {})
        except (OSError, json.JSONDecodeError):
            self.records = {}

    def _save(self) -> None:
        self.index_path.parent.mkdir(parents=True, exist_ok=True)
        payload = {"model": self.model_name, "dimensions": self.embedding_dimensions, "records": self.records}
        temporary = self.index_path.with_suffix(".tmp")
        temporary.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
        temporary.replace(self.index_path)

    def embed(self, text: str) -> list[float]:
        vector = [0.0] * self.embedding_dimensions
        tokens = re.findall(r"[a-z0-9]+", text.lower())
        for token in tokens:
            digest = hashlib.blake2b(token.encode("utf-8"), digest_size=8).digest()
            index = int.from_bytes(digest, "big") % self.embedding_dimensions
            vector[index] += 1.0 if digest[0] & 1 else -1.0
        norm = math.sqrt(sum(value * value for value in vector))
        return [value / norm for value in vector] if norm else vector

    @staticmethod
    def _distance(left: list[float], right: list[float]) -> float:
        return 1.0 - sum(a * b for a, b in zip(left, right))

    def add_cve(self, cve_id: str, description: str, metadata: dict[str, Any] | None = None) -> None:
        self.records[cve_id] = {
            "description": description,
            "embedding": self.embed(description),
            "metadata": metadata or {"cve_id": cve_id},
        }
        self._save()

    def retrieve_similar_cves(self, description: str, top_k: int = 5, cvss_version: str | None = None) -> list[dict[str, Any]]:
        if top_k < 1:
            raise ValueError("top_k must be greater than 0")
        query = self.embed(description)
        results = []
        for cve_id, record in self.records.items():
            metadata = record.get("metadata") or {}
            if cvss_version and metadata.get("cvss_version") != cvss_version:
                continue
            results.append({
                "cve_id": cve_id,
                "description": record["description"],
                "metadata": metadata,
                "distance": self._distance(query, record["embedding"]),
            })
        return sorted(results, key=lambda item: item["distance"])[:top_k]

    def _extract_cvss_metadata(self, record: dict[str, Any]) -> dict[str, Any]:
        metadata: dict[str, Any] = {}
        for key in ("cvss_version", "cvss_vector", "cvss_severity"):
            if record.get(key):
                metadata[key] = str(record[key])
        if record.get("cvss_base_score") is not None:
            metadata["cvss_base_score"] = float(record["cvss_base_score"])
        return metadata

    def index_cves(self, records: list[dict[str, Any]]) -> int:
        count = 0
        for record in records:
            cve_id = record.get("cve_id")
            description = record.get("description")
            if not cve_id or not description:
                continue
            metadata = {
                "cve_id": cve_id,
                **({"published_date": str(record["published_date"])} if record.get("published_date") else {}),
                **({"updated_date": str(record["updated_date"])} if record.get("updated_date") else {}),
                **self._extract_cvss_metadata(record),
            }
            self.records[cve_id] = {"description": description, "embedding": self.embed(description), "metadata": metadata}
            count += 1
        if count:
            self._save()
        return count

    def all(self) -> list[dict[str, Any]]:
        return [{"id": cve_id, "document": record["description"], "metadata": record["metadata"]} for cve_id, record in self.records.items()]

    def get(self, cve_id: str) -> dict[str, Any] | None:
        record = self.records.get(cve_id)
        if not record:
            return None
        return {"id": cve_id, "document": record["description"], "metadata": record["metadata"]}

    def update_metadata(self, cve_id: str, metadata: dict[str, Any]) -> bool:
        if cve_id not in self.records:
            return False
        self.records[cve_id]["metadata"] = metadata
        return True

    def save(self) -> None:
        self._save()
