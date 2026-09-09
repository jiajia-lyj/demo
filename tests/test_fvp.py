# tests/test_fvp.py

import pytest
from unittest.mock import Mock, patch
from app.core.llm_enhancer import LLMEnhancer
from app.config import Settings
from app.utils.fvp_parser import parse_fvp_response


@pytest.fixture
def mock_settings():
    settings = Mock(spec=Settings)
    settings.llm_base_url = "http://test"
    settings.llm_api_key = "test_key"
    settings.llm_model = "test_model"
    settings.llm_timeout = 30
    return settings


# ---------- 解析器单元测试 ----------
def test_parse_fvp_response_normal():
    text = """
    AV: NETWORK
    AC: LOW
    PR: NONE
    UI: NONE
    S: UNCHANGED
    C: HIGH
    I: HIGH
    A: HIGH
    """
    result = parse_fvp_response(text)
    expected = {
        "AV": "NETWORK",
        "AC": "LOW",
        "PR": "NONE",
        "UI": "NONE",
        "S": "UNCHANGED",
        "C": "HIGH",
        "I": "HIGH",
        "A": "HIGH"
    }
    assert result == expected


def test_parse_fvp_response_case_insensitive():
    text = """
    av: network
    Ac: low
    Pr: none
    Ui: required
    s: changed
    c: high
    i: low
    a: none
    """
    result = parse_fvp_response(text)
    expected = {
        "AV": "NETWORK",
        "AC": "LOW",
        "PR": "NONE",
        "UI": "REQUIRED",
        "S": "CHANGED",
        "C": "HIGH",
        "I": "LOW",
        "A": "NONE"
    }
    assert result == expected


def test_parse_fvp_response_missing_metric():
    text = """
    AV: NETWORK
    AC: LOW
    PR: NONE
    UI: NONE
    S: UNCHANGED
    C: HIGH
    I: HIGH
    # 缺少 A
    """
    with pytest.raises(ValueError):  # 只检查异常类型，不检查消息
        parse_fvp_response(text)


def test_parse_fvp_response_invalid_value():
    text = """
    AV: NETWORK
    AC: LOW
    PR: NONE
    UI: NONE
    S: UNCHANGED
    C: HIGH
    I: HIGH
    A: SUPER_HIGH   # 非法
    """
    with pytest.raises(ValueError):
        parse_fvp_response(text)


# ---------- LLMEnhancer 集成测试 ----------
@patch("app.core.llm_enhancer.LLMEnhancer._call_llm")
def test_predict_with_fvp_success(mock_call_llm, mock_settings):
    # 模拟 LLM 返回干净的指标块（无干扰文本）
    mock_call_llm.return_value = {
        "choices": [{
            "message": {
                "content": """
AV: NETWORK
AC: LOW
PR: NONE
UI: NONE
S: UNCHANGED
C: HIGH
I: HIGH
A: HIGH
"""
            }
        }]
    }
    enhancer = LLMEnhancer(mock_settings)
    result = enhancer.predict_with_fvp("Test CVE description")
    expected = {
        "AV": "NETWORK",
        "AC": "LOW",
        "PR": "NONE",
        "UI": "NONE",
        "S": "UNCHANGED",
        "C": "HIGH",
        "I": "HIGH",
        "A": "HIGH"
    }
    assert result == expected


@patch("app.core.llm_enhancer.LLMEnhancer._call_llm")
def test_predict_with_fvp_parsing_error(mock_call_llm, mock_settings):
    # 模拟不完整的响应（缺少多项指标）
    mock_call_llm.return_value = {
        "choices": [{
            "message": {
                "content": "AV: NETWORK\nAC: LOW\nPR: NONE\nUI: NONE\n"
            }
        }]
    }
    enhancer = LLMEnhancer(mock_settings)
    with pytest.raises(ValueError):
        enhancer.predict_with_fvp("Test CVE description")


@patch("app.core.llm_enhancer.LLMEnhancer._call_llm")
def test_predict_with_fvp_llm_error(mock_call_llm, mock_settings):
    mock_call_llm.side_effect = Exception("API timeout")
    enhancer = LLMEnhancer(mock_settings)
    with pytest.raises(RuntimeError):
        enhancer.predict_with_fvp("Test CVE description")