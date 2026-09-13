import csv
import json
import re
from pathlib import Path
from typing import Any

from app.schemas import CVERecord


class Preprocessor:
    def load_file(self, path: str) -> tuple[list[CVERecord], list[str]]:
        source = Path(path)
        if source.suffix.lower() == ".csv":
            return self._from_csv(source)
        if source.suffix.lower() == ".json":
            return self._from_json(source)
        raise ValueError("仅支持 JSON 或 CSV 文件")

    def _from_csv(self, path: Path) -> tuple[list[CVERecord], list[str]]:
        records, errors = [], []
        with path.open("r", encoding="utf-8-sig", newline="") as file:
            for number, row in enumerate(csv.DictReader(file), 2):
                try:
                    records.append(self._normalize(row))
                except ValueError as error:
                    errors.append(f"第{number}行: {error}")
        return records, errors

    def _from_json(self, path: Path) -> tuple[list[CVERecord], list[str]]:
        payload = json.loads(path.read_text(encoding="utf-8"))

        if isinstance(payload, dict) and "vulnerabilities" in payload:
            return self._from_nvd_v2(payload)

        if isinstance(payload, dict):
            items = payload.get("CVE_Items") or [payload]
        else:
            items = payload

        if isinstance(items, dict):
            items = [items]

        records, errors = [], []

        for number, item in enumerate(items, 1):
            try:
                records.append(self._normalize(item))
            except ValueError as error:
                errors.append(f"第{number}条: {error}")

        return records, errors

    def _from_nvd_v2(
            self,
            payload: dict[str, Any],
    ) -> tuple[list[CVERecord], list[str]]:
        records, errors = [], []

        vulnerabilities = payload.get("vulnerabilities", [])

        for number, item in enumerate(vulnerabilities, 1):
            try:
                if not isinstance(item, dict):
                    raise ValueError("Invalid NVD vulnerability item")

                cve = item.get("cve")

                if not isinstance(cve, dict):
                    raise ValueError("Missing NVD CVE object")

                cve_id = str(cve.get("id") or "").upper().strip()

                descriptions = cve.get("descriptions") or []

                description = next(
                    (
                        entry.get("value", "")
                        for entry in descriptions
                        if isinstance(entry, dict)
                           and entry.get("lang", "").lower() == "en"
                    ),
                    "",
                )

                metrics = cve.get("metrics") or {}

                cvss_version = None
                cvss_vector = None
                cvss_base_score = None
                cvss_severity = None

                try:
                    cvss_v4 = self._extract_cvss_v4(metrics)
                    cvss_version = "4.0"
                    cvss_vector = cvss_v4["vector"]
                    cvss_base_score = cvss_v4["base_score"]
                    cvss_severity = cvss_v4["severity"]
                except ValueError:
                    cvss_v3_entries = metrics.get("cvssMetricV31") or []

                    for entry in cvss_v3_entries:
                        if not isinstance(entry, dict):
                            continue

                        cvss_data = entry.get("cvssData")

                        if not isinstance(cvss_data, dict):
                            continue

                        if cvss_data.get("version") != "3.1":
                            continue

                        vector = str(cvss_data.get("vectorString") or "").strip()

                        if not vector:
                            continue

                        cvss_version = "3.1"
                        cvss_vector = vector
                        cvss_base_score = cvss_data.get("baseScore")
                        cvss_severity = cvss_data.get("baseSeverity")
                        break

                record = {
                    "cve_id": cve_id,
                    "description": description,
                    "published_date": cve.get("published"),
                    "updated_date": cve.get("lastModified"),
                    "cvss_version": cvss_version,
                    "cvss_vector": cvss_vector,
                    "cvss_base_score": cvss_base_score,
                    "cvss_severity": cvss_severity,
                    "raw_data": item,
                }

                normalized = self._normalize(record)
                records.append(normalized)

            except ValueError as error:
                errors.append(f"第{number}条: {error}")

        return records, errors

    def _extract_cvss_v4(
            self,
            metrics: dict[str, Any],
    ) -> dict[str, Any]:
        entries = metrics.get("cvssMetricV40") or []

        for entry in entries:
            if not isinstance(entry, dict):
                continue

            cvss_data = entry.get("cvssData")

            if not isinstance(cvss_data, dict):
                continue

            if cvss_data.get("version") != "4.0":
                continue

            vector = str(cvss_data.get("vectorString") or "").strip()

            if not vector:
                raise ValueError("Missing CVSS v4.0 vector")

            return {
                "vector": vector,
                "base_score": cvss_data.get("baseScore"),
                "severity": cvss_data.get("baseSeverity"),
            }

        raise ValueError("Missing CVSS v4.0 data")

    def _normalize(self, item: dict[str, Any]) -> CVERecord:
        nvd_cve = item.get("cve") if isinstance(item.get("cve"), dict) else {}
        metadata = nvd_cve.get("CVE_data_meta") if isinstance(nvd_cve.get("CVE_data_meta"), dict) else {}
        cve_id = str(item.get("cve_id") or item.get("id") or item.get("CVE-ID") or metadata.get("ID") or "").upper().strip()
        description = item.get("description") or item.get("summary") or nvd_cve.get("description") or ""
        if isinstance(description, dict):
            description = description.get("description_data") or description.get("value") or ""
        if isinstance(description, list):
            description = next((x.get("value", "") for x in description if isinstance(x, dict) and x.get("lang", "en").lower() == "en"), "")
        description = re.sub(r"\s+", " ", str(description)).strip()
        if not re.fullmatch(r"CVE-\d{4}-\d+", cve_id):
            raise ValueError(f"无效 CVE ID: {cve_id or '<空>'}")
        if not description:
            raise ValueError("缺少描述")
        affected_software = item.get("affected_software") or item.get("product")
        if not affected_software and isinstance(item.get("configurations"), dict):
            affected_software = ", ".join(self._collect_cpe_uris(item["configurations"])) or None
        return CVERecord(
            cve_id=cve_id,
            description=description,
            published_date=item.get("published_date") or item.get("published") or item.get("publishedDate"),
            updated_date=item.get("updated_date") or item.get("lastModified") or item.get("lastModifiedDate"),
            affected_software=affected_software,
            cvss_version=item.get("cvss_version"),
            cvss_vector=item.get("cvss_vector"),
            cvss_base_score=item.get("cvss_base_score"),
            cvss_severity=item.get("cvss_severity"),
            raw_data=item,
        )

    def _collect_cpe_uris(self, value: Any) -> list[str]:
        uris: list[str] = []
        if isinstance(value, dict):
            for key, child in value.items():
                if key in {"cpe23Uri", "cpe22Uri"} and isinstance(child, str):
                    uris.append(child)
                else:
                    uris.extend(self._collect_cpe_uris(child))
        elif isinstance(value, list):
            for child in value:
                uris.extend(self._collect_cpe_uris(child))
        return list(dict.fromkeys(uris))
