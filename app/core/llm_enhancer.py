import json
import urllib.request
from typing import Any

from app.config import Settings


class LLMEnhancer:
    def __init__(self, settings: Settings):
        self.settings = settings

    @property
    def enabled(self) -> bool:
        return bool(self.settings.llm_base_url and self.settings.llm_api_key)

    def enhance(self, description: str, cve_id: str) -> tuple[dict[str, str] | None, float | None, dict[str, int] | None]:
        if not self.enabled:
            return None, None, None
        prompt = "你是CVSS v3.1专家。仅输出JSON，字段必须为 AV, AC, PR, UI, S, C, I, A。值使用官方短值。\n漏洞描述：" + description
        payload = {"model": self.settings.llm_model, "messages": [{"role": "user", "content": prompt}], "temperature": 0}
        request = urllib.request.Request(self.settings.llm_base_url.rstrip("/") + "/chat/completions", data=json.dumps(payload).encode(), headers={"Authorization": f"Bearer {self.settings.llm_api_key}", "Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(request, timeout=self.settings.llm_timeout) as response:
            result: dict[str, Any] = json.loads(response.read().decode())
        content = result["choices"][0]["message"]["content"].replace("```json", "").replace("```", "").strip()
        values = json.loads(content)
        usage = result.get("usage") or {}
        return values, 0.8, {"prompt_tokens": usage.get("prompt_tokens", 0), "completion_tokens": usage.get("completion_tokens", 0), "total_tokens": usage.get("total_tokens", 0)}
