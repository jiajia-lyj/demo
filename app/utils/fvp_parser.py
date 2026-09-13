from __future__ import annotations

import re
import logging

logger = logging.getLogger(__name__)

# 所有指标及其合法取值（用于校验）
ALLOWED_VALUES = {
    "AV": ["NETWORK", "ADJACENT", "LOCAL", "PHYSICAL", "DONT_KNOW"],
    "AC": ["LOW", "HIGH", "DONT_KNOW"],
    "PR": ["NONE", "LOW", "HIGH", "DONT_KNOW"],
    "UI": ["NONE", "REQUIRED", "DONT_KNOW"],
    "S": ["UNCHANGED", "CHANGED", "DONT_KNOW"],
    "C": ["HIGH", "LOW", "NONE", "DONT_KNOW"],
    "I": ["HIGH", "LOW", "NONE", "DONT_KNOW"],
    "A": ["HIGH", "LOW", "NONE", "DONT_KNOW"],
}

METRIC_KEYS = list(ALLOWED_VALUES.keys())  # ["AV", "AC", ...]

def parse_fvp_response(text: str) -> dict[str, str]:
    """
    从 LLM 响应文本中解析 8 个 CVSS 指标。
    
    Args:
        text: LLM 返回的完整 CoT 文本
        
    Returns:
        字典，键为指标名（如 'AV'），值为解析后的标准值（大写）
        
    Raises:
        ValueError: 如果无法解析出全部 8 个指标，或值不合法
    """
    # 1. 尝试用正则匹配每一行 "AV: value"（忽略大小写和多余空白）
    pattern = re.compile(
        r"(?P<key>AV|AC|PR|UI|S|C|I|A)\s*:\s*(?P<value>[A-Za-z_]+)",
        re.IGNORECASE
    )
    matches = pattern.findall(text)
    
    # 2. 构建初步字典（保留原始大小写）
    parsed = {}
    for key, val in matches:
        key = key.upper()
        if key not in parsed:  # 只取第一个匹配
            parsed[key] = val.strip().upper()
    
    # 3. 检查是否全部指标都有
    missing = set(METRIC_KEYS) - set(parsed.keys())
    if missing:
        logger.warning(f"Missing metrics in LLM response: {missing}")
        # 尝试二次解析：也许格式为 "AV:value" 无空格？或整个块包含在代码块中？
        # 这里简单抛出异常，由上层触发回退
        raise ValueError(f"Failed to parse all metrics. Missing: {missing}. Raw text: {text[:200]}...")
    
    # 4. 校验每个值的合法性（不区分大小写）
    validated = {}
    for key, value in parsed.items():
        allowed = [v.upper() for v in ALLOWED_VALUES[key]]
        if value not in allowed:
            # 尝试模糊匹配（例如 "network" -> "NETWORK"）
            # 这里简单抛出异常，也可自行增加映射表
            raise ValueError(f"Invalid value '{value}' for metric '{key}'. Allowed: {allowed}")
        validated[key] = value
    
    # 5. 按标准顺序返回
    return {k: validated[k] for k in METRIC_KEYS}