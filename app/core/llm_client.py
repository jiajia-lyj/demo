from app.config import Settings, settings
from app.services.llm_service import LLMFactory


def get_instructor_client(config: Settings | None = None):
    """Create the configured, retry-enabled Instructor client."""
    return LLMFactory(config or settings).create()