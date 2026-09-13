import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.services.database import Database


def main() -> None:
    database = Database()
    records = database.list_cves()

    total = len(records)
    cvss_v3 = 0
    cvss_v4 = 0
    cvss_other = 0
    examples_v4 = []

    for record in records:
        raw_data = json.loads(record["raw_data"] or "{}")
        impact = raw_data.get("impact") or {}

        found_v3 = False
        found_v4 = False

        base_metric_v3 = impact.get("baseMetricV3") or {}
        cvss_v3_data = base_metric_v3.get("cvssV3") or {}

        if cvss_v3_data.get("version"):
            found_v3 = True

        base_metric_v4 = impact.get("baseMetricV4") or {}
        cvss_v4_data = base_metric_v4.get("cvssV4") or {}

        if cvss_v4_data.get("version"):
            found_v4 = True
            if len(examples_v4) < 5:
                examples_v4.append(
                    {
                        "cve_id": record["cve_id"],
                        "cvss": base_metric_v4,
                    }
                )

        if found_v3:
            cvss_v3 += 1

        if found_v4:
            cvss_v4 += 1

        if not found_v3 and not found_v4 and impact:
            cvss_other += 1

    print("=" * 60)
    print("CVSS dataset inspection")
    print("=" * 60)
    print(f"Total CVE records: {total}")
    print(f"Records with CVSS v3: {cvss_v3}")
    print(f"Records with CVSS v4: {cvss_v4}")
    print(f"Records with other CVSS data: {cvss_other}")

    print("\nCVSS v4 examples:")

    if examples_v4:
        for example in examples_v4:
            print("-" * 60)
            print(f"CVE: {example['cve_id']}")
            print(
                json.dumps(
                    example["cvss"],
                    ensure_ascii=False,
                    indent=2,
                )
            )
    else:
        print("No CVSS v4 records found.")


if __name__ == "__main__":
    main()