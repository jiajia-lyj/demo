from dataclasses import dataclass
import os


@dataclass(frozen=True)
class Settings:
    database_path: str = os.getenv("DATABASE_PATH", "data/cvss.db")
    llm_base_url: str = os.getenv("LLM_BASE_URL", "")
    llm_api_key: str = os.getenv("LLM_API_KEY", "")
    llm_model: str = os.getenv("LLM_MODEL", "deepseek-chat")
    llm_timeout: float = float(os.getenv("LLM_TIMEOUT", "30"))


settings = Settings()
