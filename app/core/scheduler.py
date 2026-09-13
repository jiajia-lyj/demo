import json
import logging
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from typing import Any

from app.config import settings
from app.core.feature_extractor import FeatureExtractor
from app.core.llm_enhancer import LLMEnhancer
from app.core.prompt_templates import DONT_KNOW, all_metric_keys
from app.schemas import ScoreResult
from app.services.database import Database


logger = logging.getLogger(__name__)


class Scheduler:
    def __init__(self, database: Database):
        self.database = database
        self.extractor = FeatureExtractor()
        self.llm = LLMEnhancer(settings)
        self.rag = None
        try:
            from app.core.rag_retriever import RAGRetriever
            self.rag = RAGRetriever()
        except Exception as error:
            logger.warning("RAG retriever unavailable, scoring will run without RAG context: %s", error)

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

        rag_context = None

        if self.rag is not None:
            try:
                similar_cves = self.rag.retrieve_similar_cves(
                    description=record["description"],
                    top_k=3,
                )

                rag_lines = []

                for item in similar_cves:
                    metadata = item.get("metadata") or {}
                    score = metadata.get("cvss_base_score")
                    severity = metadata.get("cvss_severity")

                    reference = item["cve_id"]

                    if score is not None:
                        reference += f" | CVSS {score}"
                    if severity:
                        reference += f" | {severity}"

                    rag_lines.append(
                        f"{reference}: {item['description']}"
                    )

                if rag_lines:
                    rag_context = "\n".join(rag_lines)

            except Exception as error:
                logger.warning("RAG context retrieval failed for %s: %s", cve_id, error)
                rag_context = None

        if use_llm:
            try:
                llm_values, confidence, usage = self.llm.enhance(
                    record["description"],
                    cve_id,
                    rag_context=rag_context,
                )
                if llm_values:
                    values.update({key: value for key, value in llm_values.items() if value != "DONT_KNOW"})
                    model = settings.llm_model
            except Exception as error:
                logger.warning("LLM enhancement failed for %s: %s", cve_id, error)
        features = self.extractor.extract(cve_id, record["description"], values)
        vector, score, severity = self.extractor.score(features)
        result = ScoreResult(cve_id=cve_id, cvss_vector=vector, cvss_base_score=score, severity=severity,
                             features=features, llm_confidence=confidence, llm_model=model,
                             token_usage=usage, timestamp=datetime.now(timezone.utc))
        self.database.save_score(cve_id, result.model_dump())
        return result

    def score_batch(self, cve_ids: list[str], use_llm: bool = True) -> list[ScoreResult]:
        if not use_llm or not self.llm.enabled or len(cve_ids) < 2:
            return [self.score(cve_id, use_llm=use_llm) for cve_id in cve_ids]

        worker_count = max(1, min(self.llm.settings.llm_batch_workers, len(cve_ids)))
        with ThreadPoolExecutor(max_workers=worker_count) as executor:
            futures = [executor.submit(self.score, cve_id, True) for cve_id in cve_ids]
            return [future.result() for future in futures]

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
                except Exception as error:
                    logger.warning("DTD prediction failed for metric %s: %s", metric_key, error)
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
