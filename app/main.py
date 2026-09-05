from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from app.api.endpoints import router


app = FastAPI(
    title="基于LLM的CVSS指标评分系统",
    version="1.0.0",
    description="CVE预处理、CVSS特征提取与LLM评分服务",
)
app.mount("/static", StaticFiles(directory="app/static"), name="static")
app.include_router(router)
