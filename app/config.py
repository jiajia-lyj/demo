from dataclasses import dataclass
import os
from dotenv import load_dotenv


load_dotenv()


@dataclass(frozen=True)
class Settings:
    database_path: str = os.getenv("DATABASE_PATH", "data/cvss.db")
    llm_base_url: str = os.getenv("LLM_BASE_URL") or (
        "https://api.siliconflow.cn/v1"
        if os.getenv("SILICONFLOW_API_KEY")
        else "https://api.deepseek.com/v1" if os.getenv("DEEPSEEK_API_KEY") else ""
    )
    llm_api_key: str = (
        os.getenv("LLM_API_KEY")
        or os.getenv("SILICONFLOW_API_KEY")
        or os.getenv("DEEPSEEK_API_KEY", "")
    )
    llm_model: str = os.getenv("LLM_MODEL", "deepseek-ai/DeepSeek-V4-Flash")
    llm_timeout: float = float(os.getenv("LLM_TIMEOUT", "30"))
    llm_temperature: float = float(os.getenv("LLM_TEMPERATURE", "0"))


settings = Settings()
