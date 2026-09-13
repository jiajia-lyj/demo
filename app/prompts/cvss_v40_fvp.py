V40_METRICS = ["AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA"]

FVP_SYSTEM_PROMPT = """你是一名网络安全专家，请根据漏洞描述评估 CVSS v4.0 基础指标。

指标定义：
- AV 攻击向量: N=网络 A=相邻 L=本地 P=物理
- AC 攻击复杂度: L=低 H=高
- AT 攻击要求: N=无 P=存在
- PR 权限要求: N=无 L=低 H=高
- UI 用户交互: N=无 P=被动 A=主动
- VC/VI/VA 机密性/完整性/可用性(易受攻击系统): N=无 L=低 H=高
- SC/SI/SA 机密性/完整性/可用性(后续系统): N=无 L=低 H=高

请按以下步骤推理（Chain-of-Thought）：
步骤1：判断攻击向量和攻击复杂度
步骤2：分析权限要求和用户交互需求
步骤3：评估对易受攻击系统的影响（VC/VI/VA）
步骤4：评估对后续系统的影响（SC/SI/SA）
步骤5：输出完整 JSON
"""

FVP_OUTPUT_SCHEMA = """{
  "AV": "N", "AC": "L", "AT": "N", "PR": "N", "UI": "N",
  "VC": "H", "VI": "H", "VA": "H",
  "SC": "N", "SI": "N", "SA": "N",
  "reasoning": {
    "step1": "...", "step2": "...", "step3": "...", "step4": "..."
  }
}"""


def build_v40_fvp_prompt(vuln_description: str, few_shot: list) -> str:
    """构建 CVSS v4.0 的 FVP (Few-shot + Verification Prompt) 模板"""
    prompt = FVP_SYSTEM_PROMPT + "\n\n输出格式：\n" + FVP_OUTPUT_SCHEMA + "\n"
    if few_shot:
        prompt += "\n参考示例：\n"
        for i, ex in enumerate(few_shot, 1):
            prompt += f"\n示例{i}：\n描述：{ex['description']}\n输出：{ex['cvss_vector']}\n"
    prompt += f"\n待评估漏洞：\n{vuln_description}\n\n请逐步推理后输出 JSON："
    return prompt


def parse_v40_output(llm_output: str) -> dict:
    """解析 v4.0 输出，提取 11 个指标 + reasoning"""
    import json, re
    try:
        data = json.loads(llm_output)
    except json.JSONDecodeError:
        m = re.search(r'\{.*\}', llm_output, re.DOTALL)
        data = json.loads(m.group(0)) if m else {}

    valid_values = {
        "AV": {"N", "A", "L", "P"}, "AC": {"L", "H"}, "AT": {"N", "P"},
        "PR": {"N", "L", "H"}, "UI": {"N", "P", "A"},
        "VC": {"N", "L", "H"}, "VI": {"N", "L", "H"}, "VA": {"N", "L", "H"},
        "SC": {"N", "L", "H"}, "SI": {"N", "L", "H"}, "SA": {"N", "L", "H"},
    }
    metrics = {}
    for k, allowed in valid_values.items():
        v = str(data.get(k, "")).upper()
        metrics[k] = v if v in allowed else "N"  # 非法值回退
    metrics["reasoning"] = data.get("reasoning", {})
    return metrics