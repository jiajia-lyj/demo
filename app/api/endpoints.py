import json
import tempfile
from pathlib import Path

from fastapi import APIRouter, File, HTTPException, Query, UploadFile
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from starlette.requests import Request

from app.core.preprocessor import Preprocessor
from app.core.prompt_templates import build_dtd_prompt
from app.core.scheduler import Database, Scheduler
from app.schemas import (
    BatchScoreRequest,
    CVERecord,
    DTDScoreResponse,
    DTDPredictRequest,
    DTDPredictResponse,
    ImportResponse,
)


database = Database()
preprocessor = Preprocessor()
scheduler = Scheduler(database)
router = APIRouter()
templates = Jinja2Templates(directory="app/templates")


@router.get("/", response_class=HTMLResponse, include_in_schema=False)
def home(request: Request) -> HTMLResponse:
    return templates.TemplateResponse(request=request, name="index.html")


@router.get("/health")
def health() -> dict[str, str]:
    return {
        "status": "ok",
        "llm": "enabled" if scheduler.llm.enabled else "local-fallback",
        "llm_model": scheduler.llm.settings.llm_model if scheduler.llm.enabled else "local-rules",
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
        return ImportResponse(imported=database.upsert_cves(records), skipped=len(errors), errors=errors)
    except (ValueError, json.JSONDecodeError) as error:
        raise HTTPException(400, detail={"code": 40001, "message": str(error)}) from error
    finally:
        Path(path).unlink(missing_ok=True)


@router.post("/api/v1/cve/preprocess")
def preprocess(records: list[CVERecord]) -> ImportResponse:
    return ImportResponse(imported=database.upsert_cves(records), skipped=0, errors=[])


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
    return [scheduler.score(record["cve_id"], use_llm=request.use_llm).model_dump(mode="json") for record in records if record]


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
