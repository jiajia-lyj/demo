"""CVSS v3.1 DTD（Detailed Task Description）零样本提示模板。

本模块将 CVSS v3.1 官方规范文档（FIRST.org Specification Document）中
八个 Base Metrics 的详细定义及各标签的完整描述固化为常量，供 DTD
零样本提示策略使用。规范文本取自 CVSS v3.1 官方规范，确保模型在不依赖
任何示例的情况下也能准确理解复杂指标语义。
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class MetricSpec:
    """单个 CVSS Base Metric 的规范定义。"""

    name: str
    abbr: str
    snake: str
    description: str
    values: dict[str, str] = field(default_factory=dict)

    @property
    def valid_labels(self) -> list[str]:
        return list(self.values.keys())


CVSS_V31_METRICS: dict[str, MetricSpec] = {
    "attack_vector": MetricSpec(
        name="Attack Vector",
        abbr="AV",
        snake="attack_vector",
        description=(
            "This metric reflects the context by which vulnerability exploitation is possible. "
            "The metric value is determined by the exploitable attack vector, considering the "
            "logical placement of the vulnerable component in the architecture. The metric "
            "values are ordered from most remote to most local. Increasingly remote values "
            "indicate that an attacker can exploit the vulnerability from further away, which "
            "is generally considered more severe."
        ),
        values={
            "NETWORK": (
                "A vulnerability exploitable over a network. An attacker can exploit this "
                "vulnerability without any local or adjacent network access. The vulnerable "
                "component is bound to the network stack and the attacker can send crafted "
                "packets or requests to it."
            ),
            "ADJACENT": (
                "A vulnerability exploitable via an adjacent network. The attacker must have "
                "access to a shared or adjacent physical or logical network. Examples include "
                "Bluetooth, IEEE 802.11 (Wi-Fi), or local area network (LAN) segments. The "
                "vulnerable component is not directly reachable over the internet."
            ),
            "LOCAL": (
                "A vulnerability exploitable only from within the local system. The attacker "
                "must have local interactive or non-interactive access to the vulnerable "
                "component. This may require the attacker to authenticate to the component, "
                "or rely on configuration changes to the component."
            ),
            "PHYSICAL": (
                "A vulnerability exploitable through physical access or manipulation. The "
                "attacker must physically touch or manipulate the vulnerable component. "
                "Physical interaction may be required to establish a channel of attack, such "
                "as connecting a malicious USB device, or to alter the configuration of the "
                "component."
            ),
        },
    ),
    "attack_complexity": MetricSpec(
        name="Attack Complexity",
        abbr="AC",
        snake="attack_complexity",
        description=(
            "This metric describes the conditions beyond the attacker's control that must "
            "exist in order to exploit the vulnerability. Such conditions may require the "
            "collection of more information about the target, or computational exceptions. "
            "The assessment of this metric excludes any requirements for user interaction "
            "or privileges. If a specific configuration is required for an attack to succeed, "
            "the Base metrics should be adjusted accordingly."
        ),
        values={
            "LOW": (
                "Specialized conditions are not required to exploit the vulnerability. The "
                "attack can be performed repeatedly and reliably, with a high success rate. "
                "The attacker does not need to perform any complex setup or rely on race "
                "conditions, timing, or environmental factors."
            ),
            "HIGH": (
                "A successful attack depends on conditions beyond the attacker's control. "
                "Exploitation may require the attacker to overcome significant technical "
                "constraints, such as a specific target configuration, race conditions, "
                "timing windows, or low-probability events. The attack cannot be performed "
                "at will and success is not guaranteed."
            ),
        },
    ),
    "privileges_required": MetricSpec(
        name="Privileges Required",
        abbr="PR",
        snake="privileges_required",
        description=(
            "This metric describes the level of privileges an attacker must possess before "
            "successfully exploiting the vulnerability. The metric value is determined by "
            "the attacker's privileges at the time of exploitation, considering only the "
            "vulnerable component itself. If the attacker must authenticate to the "
            "vulnerable component, this metric reflects the minimum privileges required."
        ),
        values={
            "NONE": (
                "The attacker is unauthenticated prior to exploitation. No authentication or "
                "authorization of any kind is required to reach and exploit the vulnerable "
                "component. The vulnerability can be exploited by an anonymous or guest user."
            ),
            "LOW": (
                "The attacker requires privileges that provide basic capabilities over the "
                "vulnerable component. These privileges typically correspond to a standard "
                "or non-privileged user account with limited access. The attacker is "
                "authenticated but not with administrative or elevated rights."
            ),
            "HIGH": (
                "The attacker requires privileges that provide significant control over the "
                "vulnerable component. These privileges typically correspond to an "
                "administrative, root, or other highly privileged account. The attacker "
                "must already possess elevated access to the system or application."
            ),
        },
    ),
    "user_interaction": MetricSpec(
        name="User Interaction",
        abbr="UI",
        snake="user_interaction",
        description=(
            "This metric captures the requirement for a user, other than the attacker, to "
            "participate in the successful compromise of the vulnerable component. This "
            "metric considers only the interaction required for exploitation, not the "
            "attacker's own actions. The metric value is determined by whether a user must "
            "perform some action before the vulnerability can be exploited."
        ),
        values={
            "NONE": (
                "The vulnerable system can be exploited without any interaction from a user. "
                "The attacker can compromise the vulnerable component entirely on their own, "
                "without any action by a victim or other user. Exploitation is fully "
                "automated or self-contained."
            ),
            "REQUIRED": (
                "Successful exploitation of the vulnerability requires a user to perform "
                "some explicit action. The user must be deceived, coerced, or otherwise "
                "induced into interacting with the malicious payload, such as clicking a "
                "link, opening a file, or entering data."
            ),
        },
    ),
    "scope": MetricSpec(
        name="Scope",
        abbr="S",
        snake="scope",
        description=(
            "This metric captures whether a vulnerability in one vulnerable component "
            "impacts resources in components beyond its security scope. The security scope "
            "of a component is the set of resources or services that the component is "
            "authorized to access. A changed scope indicates that the vulnerability allows "
            "an attacker to affect resources in a different security scope than the "
            "vulnerable component itself."
        ),
        values={
            "UNCHANGED": (
                "An exploited vulnerability can only affect resources managed by the same "
                "security authority. The impact is confined to the vulnerable component's "
                "own security scope. The attacker cannot gain access to resources or "
                "capabilities outside the authority of the vulnerable component."
            ),
            "CHANGED": (
                "An exploited vulnerability can affect resources beyond the security scope "
                "of the vulnerable component. The attacker can escape the original security "
                "authority and impact resources in a different component or at a different "
                "privilege level. This typically indicates privilege escalation or "
                "cross-component impact."
            ),
        },
    ),
    "confidentiality": MetricSpec(
        name="Confidentiality Impact",
        abbr="C",
        snake="confidentiality",
        description=(
            "This metric measures the impact to the confidentiality of the information "
            "resources managed by a software component due to a successfully exploited "
            "vulnerability. Confidentiality refers to limiting information access and "
            "disclosure to only authorized users, as well as preventing access by, or "
            "disclosure to, unauthorized ones."
        ),
        values={
            "NONE": (
                "There is no impact to confidentiality within the vulnerable component. "
                "The attacker cannot gain access to any protected information, and no "
                "confidential information is disclosed."
            ),
            "LOW": (
                "There is a limited impact to confidentiality. The attacker can gain access "
                "to some information, but cannot control which information is obtained, or "
                "the amount of information is limited. The disclosed information is "
                "non-sensitive or has limited value."
            ),
            "HIGH": (
                "There is a severe impact to confidentiality. The attacker can gain access "
                "to all or a significant subset of confidential information. The attacker "
                "can read sensitive data, such as credentials, private keys, or personal "
                "data, and the disclosure represents a total compromise of confidentiality."
            ),
        },
    ),
    "integrity": MetricSpec(
        name="Integrity Impact",
        abbr="I",
        snake="integrity",
        description=(
            "This metric measures the impact to integrity of a successfully exploited "
            "vulnerability. Integrity refers to the trustworthiness and veracity of "
            "information. Integrity of a system is impacted when an attacker causes "
            "unauthorized modification of data managed by the system."
        ),
        values={
            "NONE": (
                "There is no impact to integrity within the vulnerable component. The "
                "attacker cannot modify any data, and no unauthorized changes can be made "
                "to information managed by the component."
            ),
            "LOW": (
                "Modification of data is possible, but the attacker does not have control "
                "over the consequences of the modification, or the amount of modification "
                "is limited. The attacker can modify some data, but cannot fully control "
                "what is modified or the impact is constrained."
            ),
            "HIGH": (
                "There is a severe impact to integrity. The attacker can modify all or a "
                "significant subset of data managed by the vulnerable component. The "
                "attacker can perform arbitrary modification of data, including "
                "unauthorized changes that completely compromise the trustworthiness of "
                "the information."
            ),
        },
    ),
    "availability": MetricSpec(
        name="Availability Impact",
        abbr="A",
        snake="availability",
        description=(
            "This metric measures the impact to the availability of a successfully "
            "exploited vulnerability. Availability refers to the accessibility of "
            "information resources. Attacks that consume network bandwidth, processor "
            "cycles, or disk space all impact the availability of a system."
        ),
        values={
            "NONE": (
                "There is no impact to availability within the vulnerable component. The "
                "attacker cannot disrupt the service or degrade the availability of the "
                "system or data."
            ),
            "LOW": (
                "There is a limited impact to availability. The attacker can disrupt "
                "performance or availability, but cannot fully deny service. The impact "
                "is intermittent, partial, or recoverable without significant effort."
            ),
            "HIGH": (
                "There is a severe impact to availability. The attacker can fully deny "
                "service or access to the vulnerable component. The system becomes "
                "completely unavailable, or the attacker can cause a total loss of "
                "availability, such as a complete denial of service or system crash."
            ),
        },
    ),
}


_NAME_ALIASES: dict[str, str] = {}
for _snake, _spec in CVSS_V31_METRICS.items():
    _NAME_ALIASES[_snake] = _snake
    _NAME_ALIASES[_spec.abbr] = _snake
    _NAME_ALIASES[_spec.name] = _snake
    _NAME_ALIASES[_spec.name.upper()] = _snake
    _NAME_ALIASES[_spec.abbr.upper()] = _snake
    _NAME_ALIASES[_snake.upper()] = _snake

DONT_KNOW = "DONT_KNOW"

DTD_INSTRUCTION = (
    "你是 CVSS v3.1 评分专家。请仅依据下方给出的官方规范定义与漏洞描述，"
    "判断该漏洞在「{metric_name}」指标下最合适的取值。\n"
    "判断规则：\n"
    "1. 严格依据官方规范定义中各标签的含义进行匹配；\n"
    "2. 仅根据漏洞描述中明确陈述的事实判断，不要推测或引入外部知识；\n"
    "3. 若描述信息不足以判断，必须返回 DONT_KNOW，禁止猜测；\n"
    "4. 返回值必须是下列合法标签之一（含 DONT_KNOW）。\n"
    "请以 JSON 格式返回：{{\"value\": \"<标签>\"}}。"
)


@dataclass(frozen=True)
class DTDPrompt:
    """DTD 提示模板构建结果。"""

    metric_name: str
    metric_abbr: str
    valid_labels: list[str]
    spec_text: str
    template: str

    def render(self, cve_description: str) -> str:
        return self.template.replace("{cve_description}", cve_description)


def _resolve_metric(metric_name: str) -> MetricSpec:
    key = str(metric_name).strip()
    snake = _NAME_ALIASES.get(key) or _NAME_ALIASES.get(key.lower()) or _NAME_ALIASES.get(key.upper())
    if snake is None:
        valid = sorted({spec.name for spec in CVSS_V31_METRICS.values()} | {spec.abbr for spec in CVSS_V31_METRICS.values()} | set(CVSS_V31_METRICS.keys()))
        raise ValueError(f"未知的 CVSS 指标: {metric_name!r}，支持的指标: {valid}")
    return CVSS_V31_METRICS[snake]


def build_dtd_prompt(metric_name: str) -> DTDPrompt:
    """构建单个 CVSS 指标的 DTD 零样本提示模板。

    将 CVSS v3.1 官方规范文档中该指标的详细定义及各标签完整描述嵌入提示，
    形成可被 LLM 直接使用的零样本提示模板。模板中保留 ``{cve_description}``
    占位符，由调用方填充实际漏洞描述。

    Args:
        metric_name: 指标名称，支持全名（如 ``"Attack Vector"``）、
            缩写（如 ``"AV"``）或 snake_case（如 ``"attack_vector"``）。

    Returns:
        :class:`DTDPrompt`，包含规范文本、合法标签列表与提示模板。

    Raises:
        ValueError: 当 ``metric_name`` 无法识别时。
    """
    spec = _resolve_metric(metric_name)
    labels_block = "\n".join(
        f"- {label}: {desc}" for label, desc in spec.values.items()
    )
    valid_labels = spec.valid_labels + [DONT_KNOW]
    valid_block = ", ".join(valid_labels)

    spec_text = (
        f"## CVSS v3.1 Base Metric: {spec.name} ({spec.abbr})\n\n"
        f"### Metric Definition\n{spec.description}\n\n"
        f"### Metric Values\n{labels_block}"
    )

    instruction = DTD_INSTRUCTION.format(metric_name=f"{spec.name} ({spec.abbr})")

    template = (
        f"{spec_text}\n\n"
        f"### Vulnerability Description\n{{cve_description}}\n\n"
        f"### Instructions\n{instruction}\n\n"
        f"### Valid Labels\n{valid_block}\n\n"
        f"### Response Format\n返回 JSON: {{\"value\": \"<one of {valid_block}>\"}}"
    )

    return DTDPrompt(
        metric_name=spec.name,
        metric_abbr=spec.abbr,
        valid_labels=valid_labels,
        spec_text=spec_text,
        template=template,
    )


def all_metric_keys() -> list[str]:
    """返回全部八个指标的 snake_case 键名。"""
    return list(CVSS_V31_METRICS.keys())


def build_std_prompt(metric_name: str, labels: list[str]) -> str:
    """构建 STD（Simple Task Description）零样本提示。"""
    label_text = ", ".join(labels)
    return (
        f"Task: Predict value for metric {metric_name}.\n"
        f"Allowed labels: [{label_text}]\n"
        "Input vulnerability description: {text}\n"
        f"Output strictly single JSON object. Key name is `{metric_name}`, "
        "value must be one of allowed labels. No extra explanation. "
        "Do not output markdown code fence."
    )