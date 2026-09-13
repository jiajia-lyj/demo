from __future__ import annotations

import requests
from app.config import settings


class MR6RetrievalClient:
    def __init__(self):
        self.url = settings.mr6_retrieval_url
        self.timeout = 30

    def retrieve_top_k(self, query_text: str, k: int, target_metric: str) -> list[str]:
        """
        返回格式化好的少样本示例列表
        每个item: "CVE Description: xxxxxx\nLABEL: VALUE"
        """
        if not (settings.std_min_shots <= k <= settings.std_max_shots):
            raise ValueError(f"shots must between {settings.std_min_shots} ~ {settings.std_max_shots}")
        if not self.url:
            return []

        payload = {
            "query": query_text,
            "top_k": k
        }
        resp = requests.post(self.url, json=payload, timeout=self.timeout)
        resp.raise_for_status()
        raw = resp.json()
        results = raw.get("results", [])

        formatted_examples = []
        for item in results:
            desc = item.get("cve_description", "").strip()
            label = item.get(target_metric)
            if not desc or label is None:
                continue
            line = f"CVE Description: {desc}\nLABEL: {label}"
            formatted_examples.append(line)
        return formatted_examples
