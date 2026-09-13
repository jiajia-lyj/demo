"""CVSS v4.0 DTD（Detailed Task Description）提示模板。

本模块将 CVSS v4.0 官方规范文档（FIRST.org Specification Document v1.0）
中 Base Metrics 的详细定义及各标签的完整描述固化为常量，供 v4.0 DTD
零样本与少样本提示策略使用。

CVSS v4.0 相较 v3.1 的主要变化：
  - 新增 Attack Requirements (AT) 指标；
  - User Interaction 新增 PASSIVE 取值；
  - Scope 被拆分为 Vulnerable Component 与 Subsequent Component 两组共六个 Impact 指标
    （VC/VI/VA 与 SC/SI/SA），取代 v3.1 的 Scope + C/I/A 模型；
  - 引入 Threat / Environmental / Supplemental 三组扩展指标（本模块聚焦 Base Metrics）。

规范文本取自 CVSS v4.0 官方规范，确保模型准确理解 v4.0 语义。
"""

from __future__ import annotations

from dataclasses import dataclass, field

from app.core.prompt_templates import FewShotExample, select_fewshot_examples


DONT_KNOW = "DONT_KNOW"


@dataclass(frozen=True)
class MetricSpecV40:
    """单个 CVSS v4.0 Base Metric 的规范定义。"""

    name: str
    abbr: str
    snake: str
    description: str
    values: dict[str, str] = field(default_factory=dict)

    @property
    def valid_labels(self) -> list[str]:
        return list(self.values.keys())


CVSS_V40_BASE_METRICS: dict[str, MetricSpecV40] = {
    "attack_vector": MetricSpecV40(
        name="Attack Vector",
        abbr="AV",
        snake="attack_vector",
        description=(
            "This metric reflects the context by which vulnerability exploitation is possible. "
            "The metric value is determined by the exploitable attack vector, considering the "
            "logical placement of the vulnerable component in the architecture. In CVSS v4.0, "
            "this metric retains the same four values as v3.1, ordered from most remote to "
            "most local. Increasingly remote values indicate that an attacker can exploit the "
            "vulnerability from further away, which is generally considered more severe."
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
    "attack_complexity": MetricSpecV40(
        name="Attack Complexity",
        abbr="AC",
        snake="attack_complexity",
        description=(
            "This metric describes the conditions beyond the attacker's control that must "
            "exist in order to exploit the vulnerability. Such conditions may require the "
            "collection of more information about the target, or computational exceptions. "
            "In CVSS v4.0, this metric captures the deployment-specific conditions of the "
            "vulnerable component, separate from the Attack Requirements (AT) metric which "
            "captures environment-specific conditions."
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
    "attack_requirements": MetricSpecV40(
        name="Attack Requirements",
        abbr="AT",
        snake="attack_requirements",
        description=(
            "This metric captures the prerequisite conditions of the vulnerable component "
            "that enable the attack. It is new in CVSS v4.0 and separates environment-specific "
            "deployment conditions from the intrinsic Attack Complexity (AC). The metric "
            "evaluates whether the attack requires specific environmental or deployment "
            "conditions to be present, such as a race condition, man-in-the-middle positioning, "
            "or a specific execution environment."
        ),
        values={
            "NONE": (
                "Successful exploitation of the vulnerability does not require any "
                "prerequisite conditions. The attack can be carried out without any "
                "environment-specific or deployment-specific constraints being satisfied."
            ),
            "PRESENT": (
                "Successful exploitation of the vulnerability requires specific prerequisite "
                "conditions to be present. These conditions may include a race condition, "
                "man-in-the-middle positioning, a specific execution environment, or other "
                "environmental constraints that must be satisfied for the attack to succeed."
            ),
        },
    ),
    "privileges_required": MetricSpecV40(
        name="Privileges Required",
        abbr="PR",
        snake="privileges_required",
        description=(
            "This metric describes the level of privileges an attacker must possess before "
            "successfully exploiting the vulnerability. In CVSS v4.0, this metric retains the "
            "same three values as v3.1. The metric value is determined by the attacker's "
            "privileges at the time of exploitation, considering only the vulnerable component "
            "itself."
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
    "user_interaction": MetricSpecV40(
        name="User Interaction",
        abbr="UI",
        snake="user_interaction",
        description=(
            "This metric captures the requirement for a user, other than the attacker, to "
            "participate in the successful compromise of the vulnerable component. In CVSS "
            "v4.0, a new PASSIVE value is introduced to distinguish between active and passive "
            "user participation. ACTIVE corresponds to the v3.1 REQUIRED value, while PASSIVE "
            "captures scenarios where the user merely needs to be present or view content."
        ),
        values={
            "NONE": (
                "The vulnerable system can be exploited without any interaction from a user. "
                "The attacker can compromise the vulnerable component entirely on their own, "
                "without any action by a victim or other user. Exploitation is fully "
                "automated or self-contained."
            ),
            "PASSIVE": (
                "Successful exploitation requires passive user interaction. The user must be "
                "present or view content, but does not need to take any explicit action. "
                "Examples include a vulnerability that triggers when a user loads a page or "
                "views an email, without clicking or performing any deliberate action. This "
                "value is new in CVSS v4.0."
            ),
            "ACTIVE": (
                "Successful exploitation of the vulnerability requires a user to perform "
                "some explicit, deliberate action. The user must be deceived, coerced, or "
                "otherwise induced into interacting with the malicious payload, such as "
                "clicking a link, opening a file, or entering data. This corresponds to the "
                "v3.1 REQUIRED value."
            ),
        },
    ),
    "vulnerable_component_confidentiality": MetricSpecV40(
        name="Vulnerable Component Confidentiality Impact",
        abbr="VC",
        snake="vulnerable_component_confidentiality",
        description=(
            "This metric measures the impact to the confidentiality of the information "
            "resources managed by the vulnerable component due to a successfully exploited "
            "vulnerability. In CVSS v4.0, the impact is split between the vulnerable component "
            "and the subsequent component, replacing the v3.1 combined Confidentiality Impact "
            "and Scope model. VC captures the direct confidentiality impact on the component "
            "containing the vulnerability."
        ),
        values={
            "NONE": (
                "There is no impact to confidentiality within the vulnerable component. The "
                "attacker cannot gain access to any protected information, and no confidential "
                "information is disclosed."
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
    "vulnerable_component_integrity": MetricSpecV40(
        name="Vulnerable Component Integrity Impact",
        abbr="VI",
        snake="vulnerable_component_integrity",
        description=(
            "This metric measures the impact to integrity of a successfully exploited "
            "vulnerability on the vulnerable component itself. In CVSS v4.0, the integrity "
            "impact is split between the vulnerable component (VI) and the subsequent "
            "component (SI), replacing the v3.1 combined model. VI captures the direct "
            "integrity impact on the component containing the vulnerability."
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
    "vulnerable_component_availability": MetricSpecV40(
        name="Vulnerable Component Availability Impact",
        abbr="VA",
        snake="vulnerable_component_availability",
        description=(
            "This metric measures the impact to the availability of the vulnerable component "
            "due to a successfully exploited vulnerability. In CVSS v4.0, the availability "
            "impact is split between the vulnerable component (VA) and the subsequent "
            "component (SA), replacing the v3.1 combined model. VA captures the direct "
            "availability impact on the component containing the vulnerability."
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
    "subsequent_component_confidentiality": MetricSpecV40(
        name="Subsequent Component Confidentiality Impact",
        abbr="SC",
        snake="subsequent_component_confidentiality",
        description=(
            "This metric measures the impact to the confidentiality of information resources "
            "managed by a subsequent component due to a successfully exploited vulnerability. "
            "In CVSS v4.0, this replaces the v3.1 Scope=CHANGED + Confidentiality Impact "
            "combination. SC captures the confidentiality impact on components beyond the "
            "vulnerable component's own security scope. If the scope is unchanged, SC should "
            "be NONE."
        ),
        values={
            "NONE": (
                "There is no impact to confidentiality beyond the vulnerable component. The "
                "exploitation does not affect the confidentiality of any subsequent component "
                "or resources outside the vulnerable component's security scope."
            ),
            "LOW": (
                "There is a limited impact to confidentiality of a subsequent component. The "
                "attacker can gain access to some information in a component beyond the "
                "vulnerable component, but the disclosure is limited in scope or value."
            ),
            "HIGH": (
                "There is a severe impact to confidentiality of a subsequent component. The "
                "attacker can gain access to all or a significant subset of confidential "
                "information in a component beyond the vulnerable component, representing "
                "a total compromise of that component's confidentiality."
            ),
        },
    ),
    "subsequent_component_integrity": MetricSpecV40(
        name="Subsequent Component Integrity Impact",
        abbr="SI",
        snake="subsequent_component_integrity",
        description=(
            "This metric measures the impact to integrity of a subsequent component due to "
            "a successfully exploited vulnerability. In CVSS v4.0, this replaces the v3.1 "
            "Scope=CHANGED + Integrity Impact combination. SI captures the integrity impact "
            "on components beyond the vulnerable component's own security scope. If the scope "
            "is unchanged, SI should be NONE."
        ),
        values={
            "NONE": (
                "There is no impact to integrity beyond the vulnerable component. The "
                "exploitation does not affect the integrity of any subsequent component or "
                "resources outside the vulnerable component's security scope."
            ),
            "LOW": (
                "There is a limited impact to integrity of a subsequent component. The "
                "attacker can modify some data in a component beyond the vulnerable component, "
                "but the modification is limited in scope or consequence."
            ),
            "HIGH": (
                "There is a severe impact to integrity of a subsequent component. The "
                "attacker can perform arbitrary modification of data in a component beyond "
                "the vulnerable component, completely compromising its trustworthiness."
            ),
        },
    ),
    "subsequent_component_availability": MetricSpecV40(
        name="Subsequent Component Availability Impact",
        abbr="SA",
        snake="subsequent_component_availability",
        description=(
            "This metric measures the impact to the availability of a subsequent component "
            "due to a successfully exploited vulnerability. In CVSS v4.0, this replaces the "
            "v3.1 Scope=CHANGED + Availability Impact combination. SA captures the "
            "availability impact on components beyond the vulnerable component's own security "
            "scope. If the scope is unchanged, SA should be NONE."
        ),
        values={
            "NONE": (
                "There is no impact to availability beyond the vulnerable component. The "
                "exploitation does not affect the availability of any subsequent component "
                "or resources outside the vulnerable component's security scope."
            ),
            "LOW": (
                "There is a limited impact to availability of a subsequent component. The "
                "attacker can disrupt the availability of a component beyond the vulnerable "
                "component, but the disruption is intermittent, partial, or recoverable."
            ),
            "HIGH": (
                "There is a severe impact to availability of a subsequent component. The "
                "attacker can fully deny service or access to a component beyond the "
                "vulnerable component, causing a total loss of availability."
            ),
        },
    ),
}


_V40_NAME_ALIASES: dict[str, str] = {}
for _snake, _spec in CVSS_V40_BASE_METRICS.items():
    _V40_NAME_ALIASES[_snake] = _snake
    _V40_NAME_ALIASES[_spec.abbr] = _snake
    _V40_NAME_ALIASES[_spec.name] = _snake
    _V40_NAME_ALIASES[_spec.name.upper()] = _snake
    _V40_NAME_ALIASES[_spec.abbr.upper()] = _snake
    _V40_NAME_ALIASES[_snake.upper()] = _snake


V40_DTD_INSTRUCTION = (
    "你是 CVSS v4.0 评分专家。请仅依据下方给出的官方规范定义与漏洞描述，"
    "判断该漏洞在「{metric_name}」指标下最合适的取值。\n"
    "判断规则：\n"
    "1. 严格依据 CVSS v4.0 官方规范定义中各标签的含义进行匹配；\n"
    "2. 仅根据漏洞描述中明确陈述的事实判断，不要推测或引入外部知识；\n"
    "3. 若描述信息不足以判断，必须返回 DONT_KNOW，禁止猜测；\n"
    "4. 注意 CVSS v4.0 与 v3.1 的差异：新增 AT 指标、UI 新增 PASSIVE 取值、"
    "Scope 被拆分为 VC/VI/VA 与 SC/SI/SA 六个 Impact 指标；\n"
    "5. 返回值必须是下列合法标签之一（含 DONT_KNOW）。\n"
    "请以 JSON 格式返回：{{\"value\": \"<标签>\"}}。"
)


@dataclass(frozen=True)
class DTDPromptV40:
    """CVSS v4.0 DTD 提示模板构建结果。"""

    metric_name: str
    metric_abbr: str
    valid_labels: list[str]
    spec_text: str
    template: str
    fewshot_text: str = ""
    shots: int = 0

    def render(self, cve_description: str) -> str:
        return self.template.replace("{cve_description}", cve_description)


def _resolve_v40_metric(metric_name: str) -> MetricSpecV40:
    key = str(metric_name).strip()
    snake = _V40_NAME_ALIASES.get(key) or _V40_NAME_ALIASES.get(key.lower()) or _V40_NAME_ALIASES.get(key.upper())
    if snake is None:
        valid = sorted({spec.name for spec in CVSS_V40_BASE_METRICS.values()} | {spec.abbr for spec in CVSS_V40_BASE_METRICS.values()} | set(CVSS_V40_BASE_METRICS.keys()))
        raise ValueError(f"未知的 CVSS v4.0 指标: {metric_name!r}，支持的指标: {valid}")
    return CVSS_V40_BASE_METRICS[snake]


def _render_v40_fewshot_block(metric_snake: str, examples: list[FewShotExample]) -> str:
    if not examples:
        return ""
    lines = ["### Few-Shot Examples (CVSS v3.1 labels mapped for reference)", ""]
    for index, example in enumerate(examples, 1):
        lines.append(
            f"Example {index} [{example.cve_id}]\n"
            f"Description: {example.description}\n"
            f"Label: {example.label}"
        )
    lines.append("")
    return "\n".join(lines)


def _v31_alias_for_v40(v40_snake: str) -> str:
    mapping = {
        "attack_vector": "attack_vector",
        "attack_complexity": "attack_complexity",
        "attack_requirements": "attack_complexity",
        "privileges_required": "privileges_required",
        "user_interaction": "user_interaction",
        "vulnerable_component_confidentiality": "confidentiality",
        "vulnerable_component_integrity": "integrity",
        "vulnerable_component_availability": "availability",
        "subsequent_component_confidentiality": "confidentiality",
        "subsequent_component_integrity": "integrity",
        "subsequent_component_availability": "availability",
    }
    return mapping.get(v40_snake, v40_snake)


def build_v40_dtd_prompt(metric_name: str, shots: int = 0) -> DTDPromptV40:
    """构建单个 CVSS v4.0 指标的 DTD 提示模板（支持零样本与少样本）。

    将 CVSS v4.0 官方规范文档中该指标的详细定义及各标签完整描述嵌入提示。
    当 ``shots > 0`` 时，附加少样本示例区域（示例标签取自 v3.1 池并做语义映射）。

    Args:
        metric_name: 指标名称，支持全名/缩写/snake_case。
        shots: 少样本示例数量，``0`` 表示零样本（默认）。

    Returns:
        :class:`DTDPromptV40`。

    Raises:
        ValueError: 当 ``metric_name`` 无法识别时。
    """
    spec = _resolve_v40_metric(metric_name)
    labels_block = "\n".join(
        f"- {label}: {desc}" for label, desc in spec.values.items()
    )
    valid_labels = spec.valid_labels + [DONT_KNOW]
    valid_block = ", ".join(valid_labels)

    spec_text = (
        f"## CVSS v4.0 Base Metric: {spec.name} ({spec.abbr})\n\n"
        f"### Metric Definition\n{spec.description}\n\n"
        f"### Metric Values\n{labels_block}"
    )

    examples: list[FewShotExample] = []
    fewshot_text = ""
    if shots > 0:
        from app.core.prompt_templates import select_fewshot_examples
        examples = select_fewshot_examples(_v31_alias_for_v40(spec.snake), shots)
        fewshot_text = _render_v40_fewshot_block(spec.snake, examples)

    instruction = V40_DTD_INSTRUCTION.format(metric_name=f"{spec.name} ({spec.abbr})")

    sections = [spec_text]
    if fewshot_text:
        sections.append(fewshot_text)
    sections.extend([
        f"### Vulnerability Description\n{{cve_description}}",
        f"### Instructions\n{instruction}",
        f"### Valid Labels\n{valid_block}",
        f"### Response Format\n返回 JSON: {{\"value\": \"<one of {valid_block}>\"}}",
    ])
    template = "\n\n".join(sections)

    return DTDPromptV40(
        metric_name=spec.name,
        metric_abbr=spec.abbr,
        valid_labels=valid_labels,
        spec_text=spec_text,
        template=template,
        fewshot_text=fewshot_text,
        shots=len(examples),
    )


def all_v40_metric_keys() -> list[str]:
    """返回 CVSS v4.0 全部 Base Metrics 的 snake_case 键名。"""
    return list(CVSS_V40_BASE_METRICS.keys())