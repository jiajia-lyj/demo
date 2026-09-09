import json
from unittest.mock import patch, MagicMock

import pytest

from app.config import Settings
from app.core.llm_enhancer import LLMEnhancer
from app.core.prompt_templates import build_std_prompt
from app.schemas import CVSSFeatures

# CVSS每个维度合法标签，和feature_extractor保持一致
CVSS_LABELS = {
    "AV": ["NETWORK", "ADJACENT", "LOCAL", "PHYSICAL"],
    "AC": ["LOW", "HIGH"],
    "PR": ["NONE", "LOW", "HIGH"],
    "UI": ["NONE", "REQUIRED"],
    "S": ["UNCHANGED", "CHANGED"],
    "C": ["NONE", "LOW", "HIGH"],
    "I": ["NONE", "LOW", "HIGH"],
    "A": ["NONE", "LOW", "HIGH"],
}

# 短key -> pydantic长字段映射，和 infer_features逻辑对齐
SHORT_TO_LONG = {
    "AV": "attack_vector",
    "AC": "attack_complexity",
    "PR": "privileges_required",
    "UI": "user_interaction",
    "S": "scope",
    "C": "confidentiality",
    "I": "integrity",
    "A": "availability",
}


def test_build_std_prompt_template():
    """验证STD提示模板输出：仅指标名+候选标签，无额外CVSS专家知识"""
    prompt = build_std_prompt(metric_name="AV", labels=CVSS_LABELS["AV"])
    # STD策略：不出现"CVSS v3.1专家"这类专家提示（和原有enhance区分）
    assert "AV" in prompt
    assert "NETWORK" in prompt
    assert "ADJACENT" in prompt
    assert "{text}" in prompt
    assert "CVSS v3.1" not in prompt
    assert "专家" not in prompt


@patch("urllib.request.urlopen")
def test_predict_with_std_mr1_client_called_correctly(mock_urlopen):
    """
    验证STD策略正确调用MR1结构化输出客户端(openai兼容 /chat/completions)
    1. 请求url、header、post body参数正确
    2. 清洗markdown ```json 标记
    3. 返回结果可以映射并实例化Pydantic CVSSFeatures模型
    """
    # 模拟配置，开启LLM
    mock_settings = Settings(
        llm_base_url="http://mr1-internal/v1",
        llm_api_key="sk-fake-mr1-key",
        llm_model="mr1-structured",
        llm_timeout=45
    )
    llm_enhancer = LLMEnhancer(mock_settings)

    # mock MR1接口返回，模拟模型带```json markdown输出
    mock_resp = MagicMock()
    mock_payload = {
        "choices": [
            {
                "message": {
                    "content": "```json\n{\"AV\":\"NETWORK\"}\n```"
                }
            }
        ],
        "usage": {
            "prompt_tokens": 22,
            "completion_tokens": 4,
            "total_tokens": 26
        }
    }
    mock_resp.read.return_value = json.dumps(mock_payload).encode("utf-8")
    mock_urlopen.return_value.__enter__.return_value = mock_resp

    # 调用STD基线接口
    pred_result, token_usage = llm_enhancer.predict_with_std(
        cve_description="Remote network vulnerability, can trigger overflow",
        metric="AV",
        labels=CVSS_LABELS["AV"]
    )

    # ========== 验证MR1客户端调用参数 ==========
    call_args = mock_urlopen.call_args
    request_obj = call_args[0][0]
    # 校验请求URL（MR1 /chat/completions端点）
    assert request_obj.full_url == "http://mr1-internal/v1/chat/completions"
    # 校验Authorization Bearer token
    assert request_obj.headers["Authorization"] == "Bearer sk-fake-mr1-key"
    assert request_obj.headers["Content-Type"] == "application/json"
    req_body = json.loads(request_obj.data)
    assert req_body["model"] == "mr1-structured"
    assert req_body["temperature"] == 0
    assert len(req_body["messages"]) == 1

    # ========== 校验返回结果、token ==========
    assert pred_result is not None
    assert pred_result["AV"] == "NETWORK"
    assert token_usage["total_tokens"] == 26

    # ========== 短key转长字段，验证输出符合Pydantic CVSSFeatures模型 ==========
    feature_kwargs = {
        "cve_id": "CVE-2026-10000",
        "attack_vector": "LOCAL",
        "attack_complexity": "LOW",
        "privileges_required": "NONE",
        "user_interaction": "NONE",
        "scope": "UNCHANGED",
        "confidentiality": "LOW",
        "integrity": "LOW",
        "availability": "NONE",
    }
    # 将STD预测的短key结果覆盖进去
    short_key = next(iter(pred_result.keys()))
    long_field = SHORT_TO_LONG[short_key]
    feature_kwargs[long_field] = pred_result[short_key]

    # Pydantic校验：如果字段非法直接抛ValidationError，测试失败
    features = CVSSFeatures(**feature_kwargs)
    assert features.attack_vector == "NETWORK"


def test_predict_with_std_llm_disabled():
    """LLM未配置时，STD接口返回None，不抛异常"""
    settings = Settings(llm_base_url=None, llm_api_key=None)
    llm = LLMEnhancer(settings)
    pred, usage = llm.predict_with_std(
        cve_description="test vuln",
        metric="AC",
        labels=CVSS_LABELS["AC"]
    )
    assert pred is None
    assert usage is None
