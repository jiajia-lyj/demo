import pytest
from app.core.dk_handler import handle_dk_output, WORST_CASE_MAP
from app.schemas import CvssAllPrediction


def test_handle_dk_all_dont_know():
    """全部字段为DONT_KNOW，校验全部替换为WorstCase"""
    raw = CvssAllPrediction(
        av="DONT_KNOW",
        ac="DONT_KNOW",
        pr="DONT_KNOW",
        ui="DONT_KNOW",
        s="DONT_KNOW",
        c="DONT_KNOW",
        i="DONT_KNOW",
        a="DONT_KNOW",
    )
    out = handle_dk_output(raw)
    assert out.av == WORST_CASE_MAP["av"]
    assert out.ac == WORST_CASE_MAP["ac"]
    assert out.pr == WORST_CASE_MAP["pr"]
    assert out.ui == WORST_CASE_MAP["ui"]
    assert out.s == WORST_CASE_MAP["s"]
    assert out.c == WORST_CASE_MAP["c"]
    assert out.i == WORST_CASE_MAP["i"]
    assert out.a == WORST_CASE_MAP["a"]


def test_handle_dk_mixed():
    """部分字段DONT_KNOW，部分正常值；仅DK字段被替换，正常值保持不变"""
    raw = CvssAllPrediction(
        av="DONT_KNOW",
        ac="HIGH",
        pr="DONT_KNOW",
        ui="REQUIRED",
        s="DONT_KNOW",
        c="LOW",
        i="DONT_KNOW",
        a="NONE",
    )
    out = handle_dk_output(raw)
    # DK字段替换
    assert out.av == "NETWORK"
    assert out.pr == "NONE"
    assert out.s == "CHANGED"
    assert out.i == "HIGH"
    # 非DK字段保持原值
    assert out.ac == "HIGH"
    assert out.ui == "REQUIRED"
    assert out.c == "LOW"
    assert out.a == "NONE"


def test_handle_dk_no_dont_know():
    """没有DONT_KNOW时，对象完全不变"""
    raw = CvssAllPrediction(
        av="LOCAL",
        ac="LOW",
        pr="HIGH",
        ui="NONE",
        s="UNCHANGED",
        c="HIGH",
        i="LOW",
        a="LOW",
    )
    out = handle_dk_output(raw)
    assert out == raw
