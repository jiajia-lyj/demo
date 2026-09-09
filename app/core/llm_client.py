from openai import OpenAI

import instructor

from app.config import Settings, settings


def get_instructor_client(config: Settings | None = None) -> instructor.Instructor:
    """Create an Instructor client for any OpenAI-compatible chat API."""
    config = config or settings
    if not config.llm_base_url:
        raise ValueError("LLM_BASE_URL is required")
    if not config.llm_api_key:
        raise ValueError("LLM_API_KEY is required")

    client = OpenAI(
        api_key=config.llm_api_key,
        base_url=config.llm_base_url,
        timeout=config.llm_timeout,
    )
    return instructor.from_openai(client)