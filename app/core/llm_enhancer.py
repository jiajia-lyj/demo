import json
import logging
import urllib.request
from typing import Any

from pydantic import BaseModel

from app.config import Settings
from app.core.llm_client import get_instructor_client
from app.services.llm_service import LLMFactory
from app.core.dk_handler import handle_dk_output
from app.core.prompt_templates import DONT_KNOW, build_dtd_prompt, build_std_prompt
from app.core.prompts.fvp_template import FVP_SYSTEM_PROMPT, FVP_USER_TEMPLATE
from app.schemas import CVSSLLMResponse, CvssAllPrediction
from app.utils.context_manager import ContextBudget, manage_context
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

    @property
    def api_model(self) -> str:
        return LLMFactory(self.settings).api_model

    def api_model_for(self, model: str) -> str:
        return LLMFactory(Settings(
            llm_base_url=self.settings.llm_base_url,
            llm_api_key=self.settings.llm_api_key,
            llm_model=model,
        )).api_model

    @staticmethod
    def _log_llm_error(error: Exception, metric: str, context: str) -> None:
        """Log LLM call errors, highlighting DeepSeek balance issues."""
        error_text = str(error)
        if "402" in error_text or "Insufficient Balance" in error_text:
            logger.warning(
                "DeepSeek balance insufficient for %s metric %s; "
                "add balance or replace DEEPSEEK_API_KEY",
                context, metric,
            )
        else:
            logger.warning("%s LLM call failed for %s: %s", context, metric, error)

    def enhance(
        self,
        description: str,
        cve_id: str,
        rag_context: str | None = None,
    ) -> tuple[dict[str, str] | None, float | None, dict[str, int] | None]:
        if not self.enabled:
            return None, None, None

        prompt = (
            "你是 CVSS v3.1 专家。根据漏洞描述判断八个指标。"
            "无法确定时使用 DONT_KNOW，不要猜测。\n"
        )

        if rag_context:
            prompt += (
                "以下是从历史 CVE 数据中检索到的相似漏洞。"
                "仅将其作为辅助参考，不要直接复制其评分；"
                "如果参考信息与当前漏洞描述不一致，以当前漏洞描述为准。\n"
                "相似漏洞参考：\n"
                + rag_context
                + "\n"
            )

        prompt += "当前漏洞描述：" + description

        client = get_instructor_client(self.settings)
        result = client.chat.completions.create(
            model=self.api_model,
            messages=[{"role": "user", "content": prompt}],
            response_model=CVSSLLMResponse,
            temperature=self.settings.llm_temperature,
        )
        values = {
            name: (
                metric.get("value")
                if isinstance(metric, dict)
                else getattr(metric, "value", metric)
            )
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
                model=self.api_model,
                messages=[{"role": "user", "content": prompt.render(cve_description)}],
                response_model=MetricPrediction,
                temperature=self.settings.llm_temperature,
            )
        except Exception as error:
            self._log_llm_error(error, metric, "DTD")
            return DONT_KNOW
        value = str(result.value).strip().upper()
        if value not in prompt.valid_labels:
            logger.warning("DTD predict returned invalid label %r for %s", value, metric)
            return DONT_KNOW
        return value

    def predict_with_dtd_fewshot(
        self,
        cve_description: str,
        metric: str,
        shots: int = 24,
        model: str | None = None,
    ) -> tuple[str, ContextBudget]:
        """DTD Few-Shot 预测：在零样本 DTD 基础上附加少样本示例。

        当「DTD 详细定义 + shots 个示例 + 漏洞描述」超出模型上下文窗口时，
        自动按优先级减少 shots 数量或截断描述，确保提示可被模型接受。

        Args:
            cve_description: 漏洞描述文本。
            metric: CVSS 指标名（支持全名/缩写/snake_case）。
            shots: 少样本示例数量，默认 24。
            model: 指定模型名覆盖 settings.llm_model（用于上下文窗口估算）。

        Returns:
            二元组 ``(value, budget)``：``value`` 为预测标签或 DONT_KNOW；
            ``budget`` 为上下文预算信息，含调整后的 shots 与截断原因。
        """
        target_model = model or self.settings.llm_model
        prompt = build_dtd_prompt(metric, shots=shots)
        budget = manage_context(
            spec_text=prompt.spec_text,
            fewshot_text=prompt.fewshot_text,
            cve_description=cve_description,
            shots=shots,
            model=target_model,
        )
        effective_prompt = build_dtd_prompt(metric, shots=budget.adjusted_shots)
        effective_description = budget.truncated_description

        if budget.adjusted_shots != shots:
            logger.info(
                "DTD few-shot context adjusted for %s: shots %d->%d, reason=%s",
                metric, shots, budget.adjusted_shots, budget.reason,
            )

        if not self.enabled:
            return DONT_KNOW, budget
        client = get_instructor_client(self.settings)
        try:
            result = client.chat.completions.create(
                model=self.api_model_for(target_model),
                messages=[{"role": "user", "content": effective_prompt.render(effective_description)}],
                response_model=MetricPrediction,
                temperature=self.settings.llm_temperature,
            )
        except Exception as error:
            self._log_llm_error(error, metric, "DTD few-shot")
            return DONT_KNOW, budget
        value = str(result.value).strip().upper()
        if value not in effective_prompt.valid_labels:
            logger.warning("DTD few-shot returned invalid label %r for %s", value, metric)
            return DONT_KNOW, budget
        return value, budget

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
            "model": self.api_model,
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
