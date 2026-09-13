"""长上下文管理工具。

为 DTD Few-Shot 策略提供 token 估算与上下文超限时的动态调整能力。
"""

from __future__ import annotations

from dataclasses import dataclass


DEFAULT_MODEL_CONTEXT: dict[str, int] = {
    "deepseek-chat": 64000, "deepseek-reasoner": 64000, "deepseek-r1": 64000,
    "gpt-4o": 128000, "gpt-4o-mini": 128000,
    "qwen2.5:7b": 32000, "qwen2.5:14b": 32000, "llama3.1:8b": 32000,
}

FALLBACK_CONTEXT = 32000
CHARS_PER_TOKEN = 3.5
RESERVED_COMPLETION_TOKENS = 512


@dataclass(frozen=True)
class ContextBudget:
    max_tokens: int
    prompt_tokens: int
    fits: bool
    adjusted_shots: int
    truncated_description: str
    reason: str


def model_context_limit(model: str) -> int:
    if not model:
        return FALLBACK_CONTEXT
    key = model.lower().strip()
    if key in DEFAULT_MODEL_CONTEXT:
        return DEFAULT_MODEL_CONTEXT[key]
    for known, limit in DEFAULT_MODEL_CONTEXT.items():
        if known in key or key in known:
            return limit
    return FALLBACK_CONTEXT


def estimate_tokens(text: str) -> int:
    if not text:
        return 0
    return max(1, int(len(text) / CHARS_PER_TOKEN))


def manage_context(spec_text, fewshot_text, cve_description, shots, model, per_example_chars=600):
    max_tokens = model_context_limit(model)
    budget = max_tokens - RESERVED_COMPLETION_TOKENS
    spec_tokens = estimate_tokens(spec_text)
    desc_tokens = estimate_tokens(cve_description)

    def total_with(cs, desc):
        if cs == 0:
            return spec_tokens + estimate_tokens(desc)
        return spec_tokens + estimate_tokens(desc) + int(cs * per_example_chars / CHARS_PER_TOKEN)

    ct = total_with(shots, cve_description)
    if ct <= budget:
        return ContextBudget(max_tokens, ct, True, shots, cve_description, "ok")

    ratio = max(0.0, (budget - spec_tokens - desc_tokens) / max(1, shots * per_example_chars / CHARS_PER_TOKEN))
    adj = max(0, int(shots * ratio))
    ct = total_with(adj, cve_description)
    if ct <= budget:
        return ContextBudget(max_tokens, ct, True, adj, cve_description, f"reduced-shots:{shots}->{adj}")

    rem = budget - spec_tokens - int(adj * per_example_chars / CHARS_PER_TOKEN)
    mdc = max(200, int(rem * CHARS_PER_TOKEN))
    tr = cve_description[:mdc]
    if len(cve_description) > mdc:
        tr = tr.rstrip() + "…"
    ct = total_with(adj, tr)
    if ct <= budget:
        return ContextBudget(max_tokens, ct, True, adj, tr, f"reduced-shots:{shots}->{adj};truncated-desc:{len(cve_description)}->{len(tr)}")

    adj = 0
    rem = budget - spec_tokens
    mdc = max(200, int(rem * CHARS_PER_TOKEN))
    tr = cve_description[:mdc]
    if len(cve_description) > mdc:
        tr = tr.rstrip() + "…"
    ct = spec_tokens + estimate_tokens(tr)
    return ContextBudget(max_tokens, ct, ct <= budget, 0, tr, f"forced-zero-shots;truncated-desc:{len(cve_description)}->{len(tr)}")


@dataclass(frozen=True)
class FewShotExample:
    """少样本示例：一条问题描述与某指标的正确标签。"""

    cve_id: str
    description: str
    metric: str
    label: str


_METRIC_ALIASES: dict[str, str] = {
    "attack_vector": "attack_vector", "av": "attack_vector", "Attack Vector": "attack_vector",
    "attack_complexity": "attack_complexity", "ac": "attack_complexity", "Attack Complexity": "attack_complexity",
    "privileges_required": "privileges_required", "pr": "privileges_required", "Privileges Required": "privileges_required",
    "user_interaction": "user_interaction", "ui": "user_interaction", "User Interaction": "user_interaction",
    "scope": "scope", "s": "scope", "Scope": "scope",
    "confidentiality": "confidentiality", "c": "confidentiality", "Confidentiality": "confidentiality",
    "integrity": "integrity", "i": "integrity", "Integrity": "integrity",
    "availability": "availability", "a": "availability", "Availability": "availability",
}


FEWSHOT_POOL: list[FewShotExample] = [
    FewShotExample("CVE-2021-44228", "Apache Log4j2 JNDI features do not protect against attacker-controlled LDAP endpoints. An attacker who can control log messages can execute arbitrary code via JNDI lookup substitution.", "attack_vector", "NETWORK"),
    FewShotExample("CVE-2017-5638", "The Jakarta Multipart parser in Apache Struts 2 allows attackers to execute arbitrary commands via a crafted Content-Type HTTP header during file upload.", "attack_vector", "NETWORK"),
    FewShotExample("CVE-2020-1472", "An elevation of privilege issue exists in Netlogon protocol when an attacker establishes a vulnerable Netlogon secure channel connection to a domain controller on the same network.", "attack_vector", "ADJACENT"),
    FewShotExample("CVE-2021-3156", "Sudo before 1.9.5p2 has a Heap-based Buffer Overflow in the argument unescaping that allows privilege escalation to root from any local user account.", "attack_vector", "LOCAL"),
    FewShotExample("CVE-2021-44228", "Apache Log4j2 JNDI features allow arbitrary code execution via crafted log messages with JNDI lookup substitution, requiring no special attack complexity.", "attack_complexity", "LOW"),
    FewShotExample("CVE-2017-5638", "Apache Struts 2 Jakarta Multipart parser allows RCE via a #cmd= string in Content-Type header, exploitable with a single crafted HTTP request.", "attack_complexity", "LOW"),
    FewShotExample("CVE-2020-0674", "A remote code execution issue exists in the way the scripting engine handles objects in Internet Explorer. The issue could corrupt memory in a way that requires specific timing conditions.", "attack_complexity", "HIGH"),
    FewShotExample("CVE-2023-38505", "libssh2 before 1.11.0 has an integer overflow in the SSH packet processing that leads to heap buffer overflow. Exploitation requires a malicious SSH server and specific packet sequencing.", "attack_complexity", "HIGH"),
    FewShotExample("CVE-2021-44228", "Apache Log4j2 JNDI lookup substitution allows unauthenticated remote code execution when message lookup is enabled, requiring no privileges.", "privileges_required", "NONE"),
    FewShotExample("CVE-2017-5638", "Apache Struts 2 RCE via Content-Type header allows unauthenticated attackers to execute arbitrary commands with no prior privileges required.", "privileges_required", "NONE"),
    FewShotExample("CVE-2019-14287", "In Sudo before 1.8.28, an attacker with sudo privileges for the ALL keyword can bypass the Runas user restrictions and execute commands as root.", "privileges_required", "LOW"),
    FewShotExample("CVE-2023-22515", "Atlassian Confluence Data Center and Server allows an unauthenticated attacker to create administrator accounts via a crafted HTTP request to the setup action endpoint.", "privileges_required", "HIGH"),
    FewShotExample("CVE-2021-44228", "Apache Log4j2 JNDI lookup allows RCE via crafted log messages without any user interaction, exploitable by sending a crafted string to any logged field.", "user_interaction", "NONE"),
    FewShotExample("CVE-2017-5638", "Apache Struts 2 RCE via Content-Type HTTP header can be triggered by a single HTTP request without requiring any user interaction.", "user_interaction", "NONE"),
    FewShotExample("CVE-2021-40444", "Microsoft MSHTML remote code execution issue allows attackers to execute arbitrary code when a user opens a specially crafted Microsoft Office document containing an ActiveX control.", "user_interaction", "REQUIRED"),
    FewShotExample("CVE-2021-44228", "Apache Log4j2 JNDI features allow RCE via crafted log messages. The issue is exploitable within the same security context without scope change.", "scope", "UNCHANGED"),
    FewShotExample("CVE-2017-5638", "Apache Struts 2 Jakarta Multipart parser RCE via Content-Type header. The exploit runs within the same security context as the vulnerable component.", "scope", "UNCHANGED"),
    FewShotExample("CVE-2021-34527", "Windows Print Spooler service contains an issue that allows an authenticated remote attacker to execute arbitrary code with SYSTEM privileges, resulting in scope change.", "scope", "CHANGED"),
    FewShotExample("CVE-2019-0708", "Remote Desktop Services (RDP) in Windows allows an unauthenticated attacker to connect to target systems via RDP and execute arbitrary code, potentially gaining access across security boundaries.", "scope", "CHANGED"),
    FewShotExample("CVE-2021-44228", "Apache Log4j2 JNDI lookup allows remote code execution via crafted log messages, resulting in complete disclosure of all information on the affected system.", "confidentiality", "HIGH"),
    FewShotExample("CVE-2021-41773", "A path traversal issue in Apache HTTP Server 2.4.49 allows attackers to read files outside the document root via encoded path separators in URLs.", "confidentiality", "HIGH"),
    FewShotExample("CVE-2019-14317", "An XSS issue in WordPress allows remote attackers to inject arbitrary web script or HTML via a crafted post, resulting in limited information disclosure to the attacker.", "confidentiality", "LOW"),
    FewShotExample("CVE-2018-1098", "An issue in Prometheus allows remote attackers to cause a denial of service by sending crafted queries that consume excessive CPU resources without any data disclosure.", "confidentiality", "NONE"),
    FewShotExample("CVE-2021-44228", "Apache Log4j2 JNDI lookup allows remote code execution via crafted log messages, allowing the attacker to modify or delete all data on the affected system.", "integrity", "HIGH"),
    FewShotExample("CVE-2017-5638", "Apache Struts 2 RCE via Content-Type header allows attackers to execute arbitrary commands that can modify any data on the server.", "integrity", "HIGH"),
    FewShotExample("CVE-2021-41773", "Apache HTTP Server path traversal allows attackers to read files outside the document root. The issue does not allow modification of any data.", "integrity", "NONE"),
    FewShotExample("CVE-2018-1098", "Prometheus issue allows remote attackers to cause denial of service by consuming CPU resources. No data integrity is affected.", "integrity", "NONE"),
    FewShotExample("CVE-2021-44228", "Apache Log4j2 JNDI lookup allows remote code execution, allowing the attacker to disrupt or shut down all services on the affected system.", "availability", "HIGH"),
    FewShotExample("CVE-2014-0160", "The Heartbleed Bug in OpenSSL allows remote attackers to read process memory via crafted TLS heartbeat packets, causing limited availability impact through resource consumption.", "availability", "LOW"),
    FewShotExample("CVE-2021-41773", "Apache HTTP Server path traversal allows reading files outside the document root. The issue does not affect the availability of the server.", "availability", "NONE"),
]


def select_fewshot_examples(metric: str, n: int) -> list[FewShotExample]:
    """按指标名选取最多 n 条少样本示例。

    Args:
        metric: 指标名称，支持 snake_case、缩写、全名等别名。
        n: 最多返回的示例数量。

    Returns:
        匹配的少样本示例列表；若指标无法识别则返回空列表。
    """
    key = (
        _METRIC_ALIASES.get(metric)
        or _METRIC_ALIASES.get(str(metric).lower())
        or _METRIC_ALIASES.get(str(metric).upper())
    )
    if key is None:
        return []
    candidates = [ex for ex in FEWSHOT_POOL if ex.metric == key]
    return candidates[:n] if n > 0 else []