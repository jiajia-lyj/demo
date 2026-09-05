from decimal import Decimal, ROUND_UP

from app.schemas import CVSSFeatures


VALUES = {
    "AV": {"NETWORK": 0.85, "ADJACENT": 0.62, "LOCAL": 0.55, "PHYSICAL": 0.2},
    "AC": {"LOW": 0.77, "HIGH": 0.44},
    "PR": {"NONE": 0.85, "LOW": {"U": 0.62, "C": 0.68}, "HIGH": {"U": 0.27, "C": 0.5}},
    "UI": {"NONE": 0.85, "REQUIRED": 0.62},
    "CIA": {"NONE": 0.0, "LOW": 0.22, "HIGH": 0.56},
}


def _roundup(value: float) -> float:
    return float(Decimal(str(value * 10)).quantize(Decimal("1"), rounding=ROUND_UP) / 10)


def calculate_score(features: CVSSFeatures) -> tuple[str, float, str]:
    scope = features.scope[:1]
    privilege = VALUES["PR"][features.privileges_required]
    privilege_value = privilege if isinstance(privilege, float) else privilege[scope]
    impact = 1 - ((1 - VALUES["CIA"][features.confidentiality]) * (1 - VALUES["CIA"][features.integrity]) * (1 - VALUES["CIA"][features.availability]))
    impact_score = 6.42 * impact if scope == "U" else 7.52 * (impact - 0.029) - 3.25 * (impact - 0.02) ** 15
    exploitability = 8.22 * VALUES["AV"][features.attack_vector] * VALUES["AC"][features.attack_complexity] * privilege_value * VALUES["UI"][features.user_interaction]
    score = 0.0 if impact_score <= 0 else _roundup(min((impact_score + exploitability) if scope == "U" else 1.08 * (impact_score + exploitability), 10))
    severity = "NONE" if score == 0 else "LOW" if score <= 3.9 else "MEDIUM" if score <= 6.9 else "HIGH" if score <= 8.9 else "CRITICAL"
    vector = f"CVSS:3.1/AV:{features.attack_vector[0]}/AC:{features.attack_complexity[0]}/PR:{features.privileges_required[0]}/UI:{features.user_interaction[0]}/S:{scope}/C:{features.confidentiality[0]}/I:{features.integrity[0]}/A:{features.availability[0]}"
    return vector, score, severity


def infer_features(description: str, cve_id: str, values: dict[str, str] | None = None) -> CVSSFeatures:
    text = description.lower()
    result = {
        "attack_vector": "NETWORK" if any(word in text for word in ("remote", "network", "http", "crafted request")) else "LOCAL",
        "attack_complexity": "LOW",
        "privileges_required": "NONE" if any(word in text for word in ("unauthenticated", "without authentication", "no privileges")) else "LOW",
        "user_interaction": "REQUIRED" if any(word in text for word in ("user interaction", "victim", "click", "crafted file")) else "NONE",
        "scope": "CHANGED" if any(word in text for word in ("privilege escalation", "escape", "other component")) else "UNCHANGED",
        "confidentiality": "HIGH" if any(word in text for word in ("arbitrary read", "disclose", "sensitive information", "code execution")) else "LOW",
        "integrity": "HIGH" if any(word in text for word in ("arbitrary code", "code execution", "modify", "write")) else "LOW",
        "availability": "HIGH" if any(word in text for word in ("denial of service", "crash", "execute code", "code execution")) else "NONE",
    }
    short_values = {"N": "NONE", "L": "LOW", "H": "HIGH", "R": "REQUIRED", "U": "UNCHANGED", "C": "CHANGED", "A": "ADJACENT", "P": "PHYSICAL"}
    if values:
        normalized = {key: short_values.get(str(value).upper(), str(value).upper()) for key, value in values.items()}
        result.update({key: value for key, value in normalized.items() if key in result})
    return CVSSFeatures(cve_id=cve_id, **result)


class FeatureExtractor:
    def extract(self, cve_id: str, description: str, values: dict[str, str] | None = None) -> CVSSFeatures:
        return infer_features(description, cve_id, values)

    def score(self, features: CVSSFeatures) -> tuple[str, float, str]:
        return calculate_score(features)
