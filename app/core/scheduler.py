import json
from datetime import datetime, timezone
from typing import Any

from app.config import settings
from app.core.feature_extractor import FeatureExtractor
from app.core.llm_enhancer import LLMEnhancer
from app.core.prompt_templates import DONT_KNOW, all_metric_keys
from app.schemas import ScoreResult
from app.services.database import Database


class Scheduler:
    def __init__(self, database: Database):
        self.database = database
        self.extractor = FeatureExtractor()
        self.llm = LLMEnhancer(settings)

    def _nvd_features(self, record: dict[str, Any]) -> dict[str, str]:
        try:
            raw = json.loads(record.get("raw_data") or "{}")
        except json.JSONDecodeError:
            return {}
        impact = raw.get("impact") or {}
        metric = impact.get("baseMetricV3") or impact.get("baseMetricV2") or {}
        cvss = metric.get("cvssV3") or metric.get("cvssV2") or {}
        fields = {
            "attackVector": "attack_vector",
            "attackComplexity": "attack_complexity",
            "privilegesRequired": "privileges_required",
            "userInteraction": "user_interaction",
            "scope": "scope",
            "confidentialityImpact": "confidentiality",
            "integrityImpact": "integrity",
            "availabilityImpact": "availability",
        }
        return {target: cvss[source] for source, target in fields.items() if source in cvss}

    def score(self, cve_id: str, use_llm: bool = True) -> ScoreResult:
        record = self.database.get_cve(cve_id)
        if not record:
            raise KeyError(cve_id)
        values = self._nvd_features(record)
        confidence = usage = None
        model = None
        if use_llm:
            try:
                llm_values, confidence, usage = self.llm.enhance(record["description"], cve_id)
                if llm_values:
                    values.update({key: value for key, value in llm_values.items() if value != "DONT_KNOW"})
                    model = settings.llm_model
            except Exception:
                pass
        features = self.extractor.extract(cve_id, record["description"], values)
        vector, score, severity = self.extractor.score(features)
        result = ScoreResult(cve_id=cve_id, cvss_vector=vector, cvss_base_score=score, severity=severity,
                             features=features, llm_confidence=confidence, llm_model=model,
                             token_usage=usage, timestamp=datetime.now(timezone.utc))
        self.database.save_score(cve_id, result.model_dump())
        return result

    def score_with_dtd(self, cve_id: str) -> tuple[ScoreResult, dict[str, str]]:
        record = self.database.get_cve(cve_id)
        if not record:
            raise KeyError(cve_id)
        description = record["description"]
        values = self._nvd_features(record)
        dtd_values: dict[str, str] = {}
        model = None
        if self.llm.enabled:
            for metric_key in all_metric_keys():
                try:
                    value = self.llm.predict_with_dtd(description, metric_key)
                except Exception:
                    value = DONT_KNOW
                dtd_values[metric_key] = value
                if value != DONT_KNOW:
                    values[metric_key] = value
            model = settings.llm_model
        else:
            dtd_values = {key: DONT_KNOW for key in all_metric_keys()}
        features = self.extractor.extract(cve_id, description, values)
        vector, score, severity = self.extractor.score(features)
        result = ScoreResult(
            cve_id=cve_id,
            cvss_vector=vector,
            cvss_base_score=score,
            severity=severity,
            features=features,
            llm_model=model,
            timestamp=datetime.now(timezone.utc),
        )
        self.database.save_score(cve_id, result.model_dump())
        return result, dtd_values
