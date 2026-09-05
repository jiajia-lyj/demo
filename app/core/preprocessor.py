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
        if isinstance(payload, dict):
            items = payload.get("CVE_Items") or payload.get("vulnerabilities") or [payload]
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
        return CVERecord(cve_id=cve_id, description=description,
                         published_date=item.get("published_date") or item.get("published") or item.get("publishedDate"),
                         updated_date=item.get("updated_date") or item.get("lastModified") or item.get("lastModifiedDate"),
                         affected_software=affected_software, raw_data=item)

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
