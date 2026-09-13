from dataclasses import dataclass
import os
from dotenv import load_dotenv


load_dotenv()

DEFAULT_LLM_BASE_URL = "https://api.siliconflow.cn/v1"


def _configured_api_key() -> str:
    return (
        os.getenv("LLM_API_KEY")
        or os.getenv("SILICONFLOW_API_KEY")
        or os.getenv("DEEPSEEK_API_KEY", "")
    ).strip()


def resolve_llm_model(api_key: str, configured_model: str | None = None) -> str:
    """Use the remote model only when an API key is available."""
    if not api_key.strip():
        return "local-rules"
    return configured_model or "DeepSeek-V4-Flash"


def resolve_llm_base_url(api_key: str, configured_base_url: str | None = None) -> str:
    """Use the configured remote endpoint when a key is available."""
    if not api_key.strip():
        return ""
    return configured_base_url or DEFAULT_LLM_BASE_URL


@dataclass(frozen=True)
class Settings:
    database_path: str = os.getenv("DATABASE_PATH", "data/cvss.db")
    llm_base_url: str = resolve_llm_base_url(
        _configured_api_key(), os.getenv("LLM_BASE_URL")
    )
    llm_api_key: str = _configured_api_key()
    llm_model: str = resolve_llm_model(
        _configured_api_key(), os.getenv("LLM_MODEL")
    )
    llm_timeout: float = float(os.getenv("LLM_TIMEOUT", "30"))
    llm_temperature: float = float(os.getenv("LLM_TEMPERATURE", "0"))
    llm_max_tokens: int = int(os.getenv("LLM_MAX_TOKENS", "4096"))
    llm_max_retries: int = int(os.getenv("LLM_MAX_RETRIES", "2"))
    llm_batch_workers: int = int(os.getenv("LLM_BATCH_WORKERS", "4"))
    mr6_retrieval_url: str = os.getenv("MR6_RETRIEVAL_URL", "")
    std_min_shots: int = int(os.getenv("STD_MIN_SHOTS", "1"))
    std_max_shots: int = int(os.getenv("STD_MAX_SHOTS", "64"))
    default_shots: int = int(os.getenv("DEFAULT_SHOTS", "24"))
    cvss_version: str = os.getenv("CVSS_VERSION", "v3.1")


settings = Settings()
