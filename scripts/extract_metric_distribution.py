"""从 NVD CVE 数据集统计 CVSS v3.1 八个 Base Metric 各标签分布，并与规范定义对比。

用法（从项目根目录运行）::

    python scripts/extract_metric_distribution.py <dataset.json> [--out report.json]

脚本会遍历数据集中所有含 CVSS v3.1 向量的记录，统计每个指标各标签的出现次数，
并与 ``app.core.prompt_templates.CVSS_V31_METRICS`` 中固化的官方规范标签集合
对比，验证规范定义的完整性。若数据集中出现规范未定义的标签，以非零退出码提示。
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from app.core.prompt_templates import CVSS_V31_METRICS, all_metric_keys  # noqa: E402

FIELD_MAP = {
    "attackVector": "attack_vector",
    "attackComplexity": "attack_complexity",
    "privilegesRequired": "privileges_required",
    "userInteraction": "user_interaction",
    "scope": "scope",
    "confidentialityImpact": "confidentiality",
    "integrityImpact": "integrity",
    "availabilityImpact": "availability",
}

LABEL_NORMALIZE: dict[str, dict[str, str]] = {
    "attack_vector": {"ADJACENT_NETWORK": "ADJACENT"},
}


def extract_distribution(dataset_path: str) -> tuple[dict[str, Counter], int]:
    """统计数据集中八个指标各标签的计数。

    Returns:
        ``(counters, total)``，``counters`` 为每个指标键到
        :class:`collections.Counter` 的映射，``total`` 为含 CVSS v3.1
        向量的记录数。
    """
    counters: dict[str, Counter] = {key: Counter() for key in all_metric_keys()}
    total = 0
    with open(dataset_path, "r", encoding="utf-8") as handle:
        data = json.load(handle)
    items = data.get("CVE_Items") or data.get("vulnerabilities") or []
    if isinstance(items, dict):
        items = [items]
    for item in items:
        impact = item.get("impact") or {}
        base_metric = impact.get("baseMetricV3") or {}
        cvss = base_metric.get("cvssV3") or {}
        if not cvss:
            continue
        total += 1
        for field, key in FIELD_MAP.items():
            raw = cvss.get(field)
            if raw is None:
                continue
            label = str(raw).upper()
            label = LABEL_NORMALIZE.get(key, {}).get(label, label)
            counters[key][label] += 1
    return counters, total


def compare_with_spec(counters: dict[str, Counter]) -> dict[str, dict]:
    """将数据集标签分布与固化的规范定义对比。"""
    report: dict[str, dict] = {}
    for key, spec in CVSS_V31_METRICS.items():
        spec_labels = set(spec.valid_labels)
        dataset_labels = set(counters[key].keys())
        report[key] = {
            "name": spec.name,
            "spec_labels": sorted(spec_labels),
            "dataset_labels": sorted(dataset_labels),
            "labels_in_dataset_not_in_spec": sorted(dataset_labels - spec_labels),
            "labels_in_spec_not_in_dataset": sorted(spec_labels - dataset_labels),
            "distribution": dict(counters[key]),
        }
    return report


def build_report(dataset_path: str) -> dict:
    counters, total = extract_distribution(dataset_path)
    return {
        "dataset": dataset_path,
        "total_cvssv3_records": total,
        "metrics": compare_with_spec(counters),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="统计 NVD 数据集中 CVSS v3.1 指标标签分布")
    parser.add_argument("dataset", nargs="?", default="data/raw/nvdcve-1.1-2024.json",
                        help="NVD JSON 数据集路径")
    parser.add_argument("--out", default=None, help="输出 JSON 报告路径")
    args = parser.parse_args()

    if not Path(args.dataset).exists():
        print(f"数据集文件不存在: {args.dataset}", file=sys.stderr)
        sys.exit(2)

    report = build_report(args.dataset)
    total = report["total_cvssv3_records"]
    print(f"数据集: {args.dataset}")
    print(f"含 CVSS v3.1 向量的记录数: {total}")
    for key, info in report["metrics"].items():
        spec_ok = not info["labels_in_dataset_not_in_spec"]
        status = "OK" if spec_ok else "MISMATCH"
        print(f"\n[{status}] {info['name']} ({key})")
        print(f"  规范标签: {info['spec_labels']}")
        print(f"  数据集标签: {info['dataset_labels']}")
        if info["labels_in_dataset_not_in_spec"]:
            print(f"  警告 数据集中出现但规范未定义: {info['labels_in_dataset_not_in_spec']}")
        print(f"  分布: {info['distribution']}")

    if args.out:
        Path(args.out).write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"\n报告已写入: {args.out}")

    bad = any(info["labels_in_dataset_not_in_spec"] for info in report["metrics"].values())
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()