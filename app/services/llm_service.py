"""Model registry and common OpenAI-compatible LLM client factory."""

from dataclasses import dataclass
from functools import lru_cache
from typing import Any

import instructor
from openai import OpenAI

from app.config import Settings, settings


@dataclass(frozen=True)
class ModelCapability:
    name: str
    context_length: int
    supports_few_shot: bool
    max_tokens: int


MODEL_REGISTRY: dict[str, ModelCapability] = {
    "DeepSeek-V4-Flash": ModelCapability(
        name="DeepSeek-V4-Flash", context_length=131072,
        supports_few_shot=True, max_tokens=4096,
    ),
    "deepseek-chat": ModelCapability(
        name="deepseek-chat", context_length=65536,
        supports_few_shot=True, max_tokens=4096,
    ),
}

MODEL_API_IDS = {
    "DeepSeek-V4-Flash": "deepseek-ai/DeepSeek-V4-Flash",
}


class LLMFactory:
    def __init__(self, config: Settings | None = None):
        self.config = config or settings

    def capability(self, model: str | None = None) -> ModelCapability:
        model_name = model or self.config.llm_model
        return MODEL_REGISTRY.get(
            model_name,
            ModelCapability(model_name, 0, False, self.config.llm_max_tokens),
        )

    def capabilities(self) -> list[ModelCapability]:
        return list(MODEL_REGISTRY.values())

    @property
    def api_model(self) -> str:
        """Return the provider-specific model ID used in API requests."""
        return MODEL_API_IDS.get(self.config.llm_model, self.config.llm_model)

    @lru_cache(maxsize=4)
    def create(self) -> instructor.Instructor:
        if not self.config.llm_base_url:
            raise ValueError("LLM_BASE_URL is required")
        if not self.config.llm_api_key:
            raise ValueError("LLM_API_KEY is required")
        client = OpenAI(
            api_key=self.config.llm_api_key,
            base_url=self.config.llm_base_url,
            timeout=self.config.llm_timeout,
            max_retries=self.config.llm_max_retries,
        )
        return instructor.from_openai(client)

    def request_options(self) -> dict[str, Any]:
        capability = self.capability()
        return {
            "temperature": self.config.llm_temperature,
            "max_tokens": min(self.config.llm_max_tokens, capability.max_tokens or self.config.llm_max_tokens),
        }
