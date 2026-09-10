import json
import logging
import urllib.request
from typing import Any

from pydantic import BaseModel

from app.config import Settings
from app.core.llm_client import get_instructor_client
from app.core.dk_handler import handle_dk_output
from app.core.prompt_templates import DONT_KNOW, build_dtd_prompt, build_std_prompt
from app.core.prompts.fvp_template import FVP_SYSTEM_PROMPT, FVP_USER_TEMPLATE
from app.schemas import CVSSLLMResponse, CvssAllPrediction
from app.utils.fvp_parser import parse_fvp_response


logger = logging.getLogger(__name__)


class MetricPrediction(BaseModel):
    value: str


class LLMEnhancer:
    def __init__(self, settings: Settings):
        self.settings = settings

    @property
    def enabled(self) -> bool:
        return bool(self.settings.llm_base_url and self.settings.llm_api_key)

    def enhance(self, description: str, cve_id: str) -> tuple[dict[str, str] | None, float | None, dict[str, int] | None]:
        if not self.enabled:
            return None, None, None
        prompt = (
            "你是 CVSS v3.1 专家。根据漏洞描述判断八个指标。"
            "无法确定时使用 DONT_KNOW，不要猜测。\n漏洞描述：" + description
        )
        client = get_instructor_client(self.settings)
        result = client.chat.completions.create(
            model=self.settings.llm_model,
            messages=[{"role": "user", "content": prompt}],
            response_model=CVSSLLMResponse,
            temperature=self.settings.llm_temperature,
        )
        values = {
            name: metric.value
            for name, metric in result.model_dump().items()
        }
        return values, 0.8, None

    def predict_with_dtd(self, cve_description: str, metric: str) -> str:
        prompt = build_dtd_prompt(metric)
        if not self.enabled:
            return DONT_KNOW
        client = get_instructor_client(self.settings)
        try:
            result = client.chat.completions.create(
                model=self.settings.llm_model,
                messages=[{"role": "user", "content": prompt.render(cve_description)}],
                response_model=MetricPrediction,
                temperature=self.settings.llm_temperature,
            )
        except Exception as error:
            error_text = str(error)
            if "402" in error_text or "Insufficient Balance" in error_text:
                logger.warning(
                    "DeepSeek balance is insufficient for DTD metric %s; "
                    "add balance or replace the configured API key",
                    metric,
                )
            else:
                logger.warning("DTD predict LLM call failed for %s: %s", metric, error)
            return DONT_KNOW
        value = str(result.value).strip().upper()
        if value not in prompt.valid_labels:
            logger.warning("DTD predict returned invalid label %r for %s", value, metric)
            return DONT_KNOW
        return value

    def predict_with_std(
        self, cve_description: str, metric: str, labels: list[str]
    ) -> tuple[dict[str, str] | None, dict[str, int] | None]:
        """Run the lightweight STD baseline and validate its JSON label."""
        if not self.enabled:
            return None, None

        try:
            messages = [{
                "role": "user",
                "content": build_std_prompt(metric, labels).format(text=cve_description),
            }]
            result = self._call_llm(messages)
            usage = result.get("usage") or {}
            token_usage = {
                "prompt_tokens": usage.get("prompt_tokens", 0),
                "completion_tokens": usage.get("completion_tokens", 0),
                "total_tokens": usage.get("total_tokens", 0),
            }
            content = result["choices"][0]["message"]["content"]
            values = json.loads(content.replace("```json", "").replace("```", "").strip())
            if values.get(metric) not in labels:
                return None, token_usage
            return values, token_usage
        except Exception as error:
            logger.warning("STD predict failed for %s: %s", metric, error)
            return None, None

    def predict_with_fvp(self, cve_description: str) -> dict[str, str]:
        """Predict and validate all eight CVSS v3.1 base metrics in one call."""
        if not self.enabled:
            raise RuntimeError("LLM 未启用，请检查配置 (llm_base_url 和 llm_api_key)")

        messages = [
            {"role": "system", "content": FVP_SYSTEM_PROMPT},
            {"role": "user", "content": FVP_USER_TEMPLATE.format(description=cve_description)},
        ]
        try:
            result = self._call_llm(messages)
            raw_output = result["choices"][0]["message"]["content"]
            logger.debug("FVP raw output: %s", raw_output)
        except Exception as error:
            logger.error("FVP LLM call failed: %s", error)
            raise RuntimeError(f"LLM 调用失败: {error}") from error

        try:
            parsed = parse_fvp_response(raw_output)
            parsed = self._apply_dk_postprocessing(parsed)
            logger.info("FVP parsed result: %s", parsed)
            return parsed
        except ValueError as error:
            logger.error("FVP parsing failed: %s. Raw output: %s", error, raw_output[:500])
            raise ValueError(f"FVP 解析失败: {error}") from error

    @staticmethod
    def _apply_dk_postprocessing(values: dict[str, str]) -> dict[str, str]:
        """Convert FVP's short-key output to the shared model and handle unknowns."""
        prediction = CvssAllPrediction(**{
            key.lower(): value for key, value in values.items()
        })
        handled = handle_dk_output(prediction)
        return {
            key.upper(): value.value if hasattr(value, "value") else value
            for key, value in handled.model_dump().items()
        }

    def _call_llm(self, messages: list[dict[str, str]]) -> dict[str, Any]:
        """Call the OpenAI-compatible endpoint used by the FVP text response."""
        payload = {
            "model": self.settings.llm_model,
            "messages": messages,
            "temperature": self.settings.llm_temperature,
        }
        url = self.settings.llm_base_url.rstrip("/") + "/chat/completions"
        request = urllib.request.Request(
            url,
            data=json.dumps(payload).encode(),
            headers={
                "Authorization": f"Bearer {self.settings.llm_api_key}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        request.headers["Content-Type"] = "application/json"
        with urllib.request.urlopen(request, timeout=self.settings.llm_timeout) as response:
            return json.loads(response.read().decode())
