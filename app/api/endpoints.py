import csv
import io
import json
import logging
import tempfile
from pathlib import Path
from typing import Any

from fastapi import APIRouter, File, HTTPException, Query, UploadFile
from fastapi.responses import HTMLResponse, StreamingResponse
from fastapi.templating import Jinja2Templates
from starlette.requests import Request

from app.core.preprocessor import Preprocessor
from app.core.prompt_templates import build_dtd_prompt
from app.core.scheduler import Scheduler
from app.services.database import Database
from app.services.llm_service import LLMFactory
from app.schemas import (
    BatchScoreRequest,
    CVERecord,
    CompareViewResponse,
    DTDScoreResponse,
    DTDPredictRequest,
    DTDPredictResponse,
    ImportResponse,
    PredictRequest,
    PredictResponse,
)

logger = logging.getLogger(__name__)

database = Database()
preprocessor = Preprocessor()
scheduler = Scheduler(database)
router = APIRouter()
templates = Jinja2Templates(directory="app/templates")
llm_factory = LLMFactory()

rag_retriever = None
try:
    from app.core.rag_retriever import RAGRetriever
    rag_retriever = RAGRetriever()
except Exception as error:
    logger.warning("RAG retriever unavailable: %s", error)


@router.get("/", response_class=HTMLResponse, include_in_schema=False)
def home(request: Request) -> HTMLResponse:
    return templates.TemplateResponse(request=request, name="index.html")


@router.get("/health")
def health() -> dict[str, Any]:
    llm_enabled = scheduler.llm.enabled
    return {
        "status": "ok",
        "llm": "enabled" if llm_enabled else "local-fallback",
        "llm_provider": "SiliconFlow" if llm_enabled else "Local Rules",
        "llm_model": scheduler.llm.settings.llm_model if llm_enabled else "local-rules",
        "llm_batch_workers": scheduler.llm.settings.llm_batch_workers if llm_enabled else 0,
    }


@router.get("/api/v1/models/capabilities")
def model_capabilities() -> dict[str, Any]:
    """Return registered model capabilities and the active model settings."""
    active = llm_factory.capability()
    return {
        "active_model": active.__dict__,
        "models": [capability.__dict__ for capability in llm_factory.capabilities()],
    }


@router.post("/api/v1/cve/import", response_model=ImportResponse)
async def import_file(file: UploadFile = File(...)) -> ImportResponse:
    suffix = Path(file.filename or "").suffix.lower()
    if suffix not in {".json", ".csv"}:
        raise HTTPException(400, detail={"code": 40001, "message": "仅支持 JSON 或 CSV 文件"})
    content = await file.read()
    with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as temporary:
        temporary.write(content)
        path = temporary.name
    try:
        records, errors = preprocessor.load_file(path)
        imported = database.upsert_cves(records)

        if records and rag_retriever is not None:
            try:
                rag_records = [
                    {
                        "cve_id": record.cve_id,
                        "description": record.description,
                        "published_date": record.published_date,
                        "updated_date": record.updated_date,
                        "cvss_version": record.cvss_version,
                        "cvss_vector": record.cvss_vector,
                        "cvss_base_score": record.cvss_base_score,
                        "cvss_severity": record.cvss_severity,
                        "raw_data": record.raw_data,
                    }
                    for record in records
                ]
                rag_retriever.index_cves(rag_records)
            except Exception as error:
                logger.warning("RAG indexing failed for imported records: %s", error)

        return ImportResponse(imported=imported, skipped=len(errors), errors=errors)
    except (ValueError, json.JSONDecodeError) as error:
        raise HTTPException(400, detail={"code": 40001, "message": str(error)}) from error
    finally:
        Path(path).unlink(missing_ok=True)


@router.post("/api/v1/cve/preprocess")
def preprocess(records: list[CVERecord]) -> ImportResponse:
    return ImportResponse(imported=database.upsert_cves(records), skipped=0, errors=[])


@router.post("/api/v1/rag/retrieve")
def retrieve_similar_cves(
    description: str,
    top_k: int = Query(5, ge=1, le=50),
    cvss_version: str | None = Query(None),
) -> dict:
    if rag_retriever is None:
        raise HTTPException(503, detail={"code": 50301, "message": "RAG 检索服务不可用"})
    try:
        results = rag_retriever.retrieve_similar_cves(
            description=description,
            top_k=top_k,
            cvss_version=cvss_version,
        )
    except ValueError as error:
        raise HTTPException(
            400,
            detail={"code": 40003, "message": str(error)},
        ) from error

    return {
        "query": description,
        "top_k": top_k,
        "cvss_version": cvss_version,
        "results": results,
    }


@router.get("/api/v1/cve/{cve_id}")
def get_cve(cve_id: str) -> dict:
    record = database.get_cve(cve_id.upper())
    if not record:
        raise HTTPException(404, detail={"code": 40401, "message": "CVE ID不存在"})
    record.pop("raw_data", None)
    return record


@router.post("/api/v1/score/batch")
def score_batch(request: BatchScoreRequest) -> list[dict]:
    records = [database.get_cve(cve_id.upper()) for cve_id in request.cve_ids] if request.cve_ids else database.list_cves(request.limit)
    cve_ids = [record["cve_id"] for record in records if record]
    return [result.model_dump(mode="json") for result in scheduler.score_batch(cve_ids, use_llm=request.use_llm)]


@router.get("/api/v1/score/export")
def export_scores(
    cve_ids: str | None = Query(None),
    limit: int = Query(20, ge=1, le=20),
) -> StreamingResponse:
    if cve_ids:
        ids = [cve_id.strip().upper() for cve_id in cve_ids.split(",") if cve_id.strip()]
    else:
        records = database.list_cves(limit)
        ids = [record["cve_id"] for record in records]

    rows = []

    for cve_id in ids:
        score = database.latest_score(cve_id)

        if score:
            rows.append({
                "cve_id": cve_id,
                "cvss_vector": score.get("cvss_vector"),
                "base_score": score.get("base_score"),
                "severity": score.get("severity"),
                "llm_model": score.get("llm_model"),
                "confidence": score.get("confidence"),
                "scored_at": score.get("scored_at"),
            })

    output = io.StringIO()
    writer = csv.DictWriter(
        output,
        fieldnames=[
            "cve_id",
            "cvss_vector",
            "base_score",
            "severity",
            "llm_model",
            "confidence",
            "scored_at",
        ],
    )
    writer.writeheader()
    writer.writerows(rows)

    output.seek(0)

    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={
            "Content-Disposition": "attachment; filename=cvss_results.csv",
        },
    )


@router.post("/api/v1/score/{cve_id}")
def score_cve(cve_id: str, use_llm: bool = Query(True)) -> dict:
    try:
        return scheduler.score(cve_id.upper(), use_llm=use_llm).model_dump(mode="json")
    except KeyError as error:
        raise HTTPException(404, detail={"code": 40401, "message": "CVE ID不存在"}) from error


@router.get("/api/v1/score/{cve_id}/compare")
def compare_score(cve_id: str) -> dict:
    cve_id = cve_id.upper()
    record = database.get_cve(cve_id)
    latest = database.latest_score(cve_id)
    if not record:
        raise HTTPException(404, detail={"code": 40401, "message": "CVE ID不存在"})
    if not latest:
        latest = scheduler.score(cve_id, use_llm=False).model_dump(mode="json")
    try:
        raw = json.loads(record.get("raw_data") or "{}")
        official_score = raw.get("cvss_base_score") or raw.get("base_score")
        impact = raw.get("impact") or {}
        base_metric = impact.get("baseMetricV3") or impact.get("baseMetricV2") or {}
        cvss = base_metric.get("cvssV3") or base_metric.get("cvssV2") or {}
        official_score = official_score or cvss.get("baseScore")
    except json.JSONDecodeError:
        official_score = None
    llm_score = latest.get("base_score") or latest.get("cvss_base_score")
    return {"cve_id": cve_id, "llm_score": llm_score, "official_score": official_score,
            "difference": None if official_score is None else round(abs(llm_score - float(official_score)), 2)}


@router.post("/api/v1/score/dtd/predict", response_model=DTDPredictResponse)
def dtd_predict(request: DTDPredictRequest) -> DTDPredictResponse:
    try:
        prompt = build_dtd_prompt(request.metric)
    except ValueError as error:
        raise HTTPException(400, detail={"code": 40002, "message": str(error)}) from error
    value = scheduler.llm.predict_with_dtd(request.cve_description, request.metric)
    return DTDPredictResponse(
        metric=request.metric,
        metric_name=prompt.metric_name,
        value=value,
        valid_labels=prompt.valid_labels,
    )


@router.post("/api/v1/score/dtd/{cve_id}", response_model=DTDScoreResponse)
def dtd_score_cve(cve_id: str) -> DTDScoreResponse:
    try:
        result, dtd_values = scheduler.score_with_dtd(cve_id.upper())
    except KeyError as error:
        raise HTTPException(404, detail={"code": 40401, "message": "CVE ID不存在"}) from error
    return DTDScoreResponse(
        cve_id=result.cve_id,
        cvss_vector=result.cvss_vector,
        cvss_base_score=result.cvss_base_score,
        severity=result.severity,
        features=result.features,
        dtd_values=dtd_values,
        llm_model=result.llm_model,
        timestamp=result.timestamp,
    )


_NVD_FIELD_MAP = {
    "attackVector": "attack_vector", "attackComplexity": "attack_complexity",
    "privilegesRequired": "privileges_required", "userInteraction": "user_interaction",
    "scope": "scope", "confidentialityImpact": "confidentiality",
    "integrityImpact": "integrity", "availabilityImpact": "availability",
}

_WORST_CASE_METRICS = {
    "attack_vector": "NETWORK", "attack_complexity": "LOW", "privileges_required": "NONE",
    "user_interaction": "NONE", "scope": "CHANGED", "confidentiality": "HIGH",
    "integrity": "HIGH", "availability": "HIGH",
}


def _extract_official_score(record: dict) -> tuple[float | None, str | None, dict | None]:
    """从 CVE 记录的 raw_data 中提取官方评分、向量与指标。"""
    try:
        raw = json.loads(record.get("raw_data") or "{}")
    except json.JSONDecodeError:
        return None, None, None
    impact = raw.get("impact") or {}
    base_metric = impact.get("baseMetricV3") or impact.get("baseMetricV2") or {}
    cvss = base_metric.get("cvssV3") or base_metric.get("cvssV2") or {}
    official_score = cvss.get("baseScore")
    official_vector = cvss.get("vectorString")
    official_metrics = {_NVD_FIELD_MAP[k]: v for k, v in cvss.items() if k in _NVD_FIELD_MAP} or None
    return official_score, official_vector, official_metrics


def _build_worst_case(cve_id: str) -> tuple[str, float, dict[str, str]]:
    """构建 Worst Case 保守评分的向量、分数与指标。"""
    from app.core.feature_extractor import calculate_score
    from app.schemas import CVSSFeatures
    worst_features = CVSSFeatures(cve_id=cve_id, **_WORST_CASE_METRICS)
    worst_vector, worst_score, _ = calculate_score(worst_features)
    return worst_vector, worst_score, _WORST_CASE_METRICS


@router.post("/api/v1/predict", response_model=PredictResponse)
def predict(request: PredictRequest) -> PredictResponse:
    """统一预测接口，支持多模型、多策略、多 shots 与 CVSS v3.1/v4.0。

    策略说明：
      - ``dtd``：零样本 DTD，仅使用官方规范定义；
      - ``dtd_fewshot``：少样本 DTD，附加 shots 条示例并做长上下文管理；
      - ``fvp``：全向量预测，一次返回八个指标（此处仅返回请求指标对应值）；
      - ``std``：简单任务描述基线。
    """
    target_model = request.model or scheduler.llm.settings.llm_model
    strategy = request.strategy.value
    cvss_version = request.cvss_version.value

    prompt = _build_predict_prompt(request, cvss_version)

    context_info: dict | None = None
    shots_used = prompt.shots

    if strategy == "dtd":
        value = scheduler.llm.predict_with_dtd(request.cve_description, request.metric)
    elif strategy == "dtd_fewshot":
        value, budget = scheduler.llm.predict_with_dtd_fewshot(
            request.cve_description, request.metric, shots=request.shots, model=target_model,
        )
        shots_used = budget.adjusted_shots
        context_info = {
            "max_tokens": budget.max_tokens,
            "prompt_tokens": budget.prompt_tokens,
            "fits": budget.fits,
            "reason": budget.reason,
            "description_length": len(request.cve_description),
            "truncated_length": len(budget.truncated_description),
        }
    elif strategy == "fvp":
        value = _predict_fvp_single(request)
    elif strategy == "std":
        labels = [label for label in prompt.valid_labels if label != "DONT_KNOW"]
        values, _ = scheduler.llm.predict_with_std(request.cve_description, request.metric, labels)
        value = (values or {}).get(request.metric, "DONT_KNOW") if values else "DONT_KNOW"
    else:
        raise HTTPException(400, detail={"code": 40002, "message": f"未知策略: {strategy}"})

    return PredictResponse(
        metric=request.metric,
        metric_name=prompt.metric_name,
        value=value,
        valid_labels=prompt.valid_labels,
        strategy=strategy,
        shots_requested=request.shots,
        shots_used=shots_used,
        model=target_model,
        cvss_version=cvss_version,
        context_info=context_info,
    )


def _build_predict_prompt(request: PredictRequest, cvss_version: str):
    """根据 CVSS 版本构建预测提示，统一处理 ValueError。"""
    if cvss_version == "4.0":
        from app.core.prompts.cvss_v40_templates import build_v40_dtd_prompt
        builder = build_v40_dtd_prompt
    else:
        builder = build_dtd_prompt
    try:
        return builder(request.metric, shots=request.shots)
    except ValueError as error:
        raise HTTPException(400, detail={"code": 40002, "message": str(error)}) from error


def _predict_fvp_single(request: PredictRequest) -> str:
    """FVP 策略：全向量预测后提取请求指标对应值。"""
    try:
        all_values = scheduler.llm.predict_with_fvp(request.cve_description)
    except (RuntimeError, ValueError) as error:
        raise HTTPException(503, detail={"code": 50301, "message": str(error)}) from error
    from app.core.prompt_templates import _resolve_metric
    try:
        spec = _resolve_metric(request.metric)
        return all_values.get(spec.abbr, "DONT_KNOW")
    except ValueError as error:
        raise HTTPException(400, detail={"code": 40002, "message": str(error)}) from error


@router.get("/api/v1/compare/view/{cve_id}", response_model=CompareViewResponse)
def compare_view(cve_id: str) -> CompareViewResponse:
    """三方对比视图：官方评分 vs LLM 评分 vs Worst Case 保守评分。"""
    cve_id = cve_id.upper()
    record = database.get_cve(cve_id)
    if not record:
        raise HTTPException(404, detail={"code": 40401, "message": "CVE ID不存在"})

    official_score, official_vector, official_metrics = _extract_official_score(record)

    latest = database.latest_score(cve_id)
    if not latest:
        try:
            scored = scheduler.score(cve_id, use_llm=False)
            latest = scored.model_dump(mode="json")
        except KeyError as error:
            raise HTTPException(404, detail={"code": 40401, "message": "CVE ID不存在"}) from error
    llm_score = latest.get("base_score") or latest.get("cvss_base_score")
    llm_vector = latest.get("cvss_vector")
    llm_features = latest.get("features") or {}
    llm_metrics = {k: v for k, v in llm_features.items() if k != "cve_id" and k != "source"} or None

    worst_vector, worst_score, worst_metrics = _build_worst_case(cve_id)

    difference = None
    if official_score is not None and llm_score is not None:
        difference = round(abs(float(llm_score) - float(official_score)), 2)

    return CompareViewResponse(
        cve_id=cve_id,
        official_score=float(official_score) if official_score is not None else None,
        official_vector=official_vector,
        official_metrics=official_metrics,
        llm_score=float(llm_score) if llm_score is not None else None,
        llm_vector=llm_vector,
        llm_metrics=llm_metrics,
        worst_case_score=worst_score,
        worst_case_vector=worst_vector,
        worst_case_metrics=worst_metrics,
        difference=difference,
    )
