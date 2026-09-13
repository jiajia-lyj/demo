from unittest.mock import patch

from app.config import Settings, resolve_llm_base_url, resolve_llm_model
from app.services.llm_service import LLMFactory


def test_factory_returns_registered_model_capability():
    factory = LLMFactory(Settings(llm_model="deepseek-chat", llm_max_tokens=2048))
    capability = factory.capability()
    assert capability.supports_few_shot is True
    assert capability.context_length == 65536
    assert factory.request_options() == {"temperature": 0, "max_tokens": 2048}


def test_factory_maps_display_name_to_provider_model_id():
    factory = LLMFactory(Settings(llm_model="DeepSeek-V4-Flash"))
    assert factory.api_model == "deepseek-ai/DeepSeek-V4-Flash"


def test_model_selection_uses_local_model_without_api_key():
    assert resolve_llm_model("", "DeepSeek-V4-Flash") == "local-rules"


def test_model_selection_uses_configured_remote_model_with_api_key():
    assert resolve_llm_model("test-key", "DeepSeek-V4-Flash") == "DeepSeek-V4-Flash"
    assert resolve_llm_model("test-key") == "DeepSeek-V4-Flash"


def test_remote_endpoint_defaults_when_api_key_is_configured():
    assert resolve_llm_base_url("test-key") == "https://api.siliconflow.cn/v1"
    assert resolve_llm_base_url("test-key", "https://example.test/v1") == "https://example.test/v1"


def test_remote_endpoint_is_disabled_without_api_key():
    assert resolve_llm_base_url("") == ""


@patch("app.services.llm_service.OpenAI")
@patch("app.services.llm_service.instructor.from_openai")
def test_factory_builds_configured_client_with_retry(mock_from_openai, mock_openai):
    factory = LLMFactory(Settings(
        llm_base_url="https://example.test/v1", llm_api_key="key", llm_max_retries=5,
    ))
    factory.create()
    mock_openai.assert_called_once_with(
        api_key="key", base_url="https://example.test/v1", timeout=30,
        max_retries=5,
    )
    mock_from_openai.assert_called_once_with(mock_openai.return_value)