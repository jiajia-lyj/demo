# 基于 LLM 的 CVSS 指标评分系统

这是一个可运行的 FastAPI 项目，用于 CVE 数据导入、清洗、CVSS 特征抽取、规则/LLM 评分、批量评估以及官方分数对比。项目支持 CVSS v3.1 和 v4.0 的统一预测接口，并在未配置 API Key 时自动回退到本地规则，因此适合离线演示和本地实验。

## 1. 项目概览

当前代码实现的核心能力包括：

- CVE 原始 JSON/CSV 导入与清洗
- SQLite 数据库存储与评分结果追踪
- 本地规则推断与 OpenAI 兼容 LLM 增强
- CVSS v3.1 / v4.0 统一预测接口
- DTD、STD、FVP 三种提示策略
- 批量评分、结果导出和官方分数对比
- RAG 风格相似漏洞检索
- 浏览器 Web 工作台

重要说明：

- 只要配置了任意一个 API Key（`LLM_API_KEY`、`SILICONFLOW_API_KEY`、`DEEPSEEK_API_KEY`），系统会启用远程模型；否则自动切换为 `local-rules`。
- 默认配置里，未设置 `LLM_BASE_URL` 时会回退到 `https://api.siliconflow.cn/v1`。

## 2. 环境要求

- Windows 10+ / Linux / macOS
- Python 3.10+
- 建议使用项目自带的 `.venv` 环境
- 若启用远程 LLM，则需要对应的 API Key 和可访问的 OpenAI 兼容接口

## 3. 安装依赖

在项目根目录执行：

```powershell
cd .
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

如果 PowerShell 不允许执行脚本：

```powershell
Set-ExecutionPolicy -Scope Process Bypass
```

也可以直接使用虚拟环境中的 Python：

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

## 4. 启动服务

### 4.1 使用本地 Python 运行

```powershell
cd .
.\.venv\Scripts\python.exe -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

启动成功后，控制台会出现类似输出：

```text
Uvicorn running on http://127.0.0.1:8000
```

可访问：

- Web 页面：http://127.0.0.1:8000/
- Swagger 文档：http://127.0.0.1:8000/docs
- 健康检查：http://127.0.0.1:8000/health

### 4.2 使用 Docker Compose

项目支持用 Docker 启动：

```powershell
docker compose up --build
```

访问：

- http://127.0.0.1:8000/

停止并清理：

```powershell
docker compose down
```

## 5. 导入数据

### 5.1 支持的数据格式

项目支持：

- NVD 1.1 JSON
- 扁平化 JSON 数组
- CSV

示例文件位于 `data/raw/sample_cves.json`。

标准 NVD 记录通常类似：

```json
{
  "cve": {
    "CVE_data_meta": {"ID": "CVE-2024-0001"},
    "description": {
      "description_data": [{"lang": "en", "value": "漏洞描述文本"}]
    }
  },
  "configurations": {"nodes": []},
  "impact": {
    "baseMetricV3": {
      "cvssV3": {
        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "baseScore": 9.8
      }
    }
  },
  "publishedDate": "2024-09-23T18:15Z",
  "lastModifiedDate": "2024-09-27T14:08Z"
}
```

程序会提取：

- `cve.CVE_data_meta.ID`
- `cve.description.description_data`
- `publishedDate` / `lastModifiedDate`
- `configurations` 中的受影响软件信息
- `impact.baseMetricV3.cvssV3` / `baseMetricV2` 中的官方分数

扁平 JSON 需要至少包含：

- `cve_id` 或 `id`
- `description` 或 `summary`

CSV 示例如下：

```csv
cve_id,description,published_date,updated_date,affected_software
CVE-2024-0001,"A condition exists in FlashArray Purity whereby a local account remains active.",2024-09-23,2024-09-27,"Pure Storage FlashArray Purity"
```

### 5.2 通过 API 导入

上传 JSON：

```powershell
curl.exe -X POST "http://127.0.0.1:8000/api/v1/cve/import" `
  -F "file=@data/raw/my_cves.json"
```

上传 CSV：

```powershell
curl.exe -X POST "http://127.0.0.1:8000/api/v1/cve/import" `
  -F "file=@data/raw/my_cves.csv"
```

成功响应示例：

```json
{
  "imported": 1,
  "skipped": 0,
  "errors": []
}
```

说明：

- `imported`：成功导入的记录数
- `skipped`：因格式错误跳过的记录数
- `errors`：错误详情
- 重复导入同一 CVE ID 会更新原记录

### 5.3 导入示例数据

```powershell
curl.exe -X POST "http://127.0.0.1:8000/api/v1/cve/import" `
  -F "file=@data/raw/sample_cves.json"
```

查询已导入数据：

```powershell
curl.exe "http://127.0.0.1:8000/api/v1/cve/CVE-2024-0001"
```

## 6. 评分与预测

### 6.1 单条评分

本地规则评分：

```powershell
curl.exe -X POST "http://127.0.0.1:8000/api/v1/score/CVE-2024-0001?use_llm=false"
```

启用远程 LLM：

```powershell
curl.exe -X POST "http://127.0.0.1:8000/api/v1/score/CVE-2024-0001?use_llm=true"
```

### 6.2 批量评分

按顺序评分前 N 条：

```powershell
curl.exe -X POST "http://127.0.0.1:8000/api/v1/score/batch" `
  -H "Content-Type: application/json" `
  -d '{"limit":20}'
```

指定 CVE 列表：

```powershell
curl.exe -X POST "http://127.0.0.1:8000/api/v1/score/batch" `
  -H "Content-Type: application/json" `
  -d '{"cve_ids":["CVE-2024-0001","CVE-2024-0002"]}'
```

### 6.3 评分对比

查看模型分数和官方分数差异：

```powershell
curl.exe "http://127.0.0.1:8000/api/v1/score/CVE-2024-0001/compare"
```

查看三方对比视图（官方 / LLM / Worst Case）：

```powershell
curl.exe "http://127.0.0.1:8000/api/v1/compare/view/CVE-2024-0001"
```

### 6.4 导出结果

```powershell
curl.exe "http://127.0.0.1:8000/api/v1/score/export?limit=20" --output cvss_results.csv
```

### 6.5 统一预测接口

统一预测接口支持多种策略：

```powershell
curl.exe -X POST "http://127.0.0.1:8000/api/v1/predict" `
  -H "Content-Type: application/json" `
  -d '{
    "cve_description":"A remote attacker can execute code without authentication.",
    "metric":"AV",
    "strategy":"dtd",
    "cvss_version":"3.1"
  }'
```

支持的 `strategy`：

- `dtd`
- `dtd_fewshot`
- `fvp`
- `std`

支持的 `cvss_version`：

- `3.1`
- `4.0`

## 7. 配置 LLM

### 7.1 自动判定逻辑

当前代码的逻辑是：

- 如果 `LLM_API_KEY`、`SILICONFLOW_API_KEY`、`DEEPSEEK_API_KEY` 全部为空，则自动使用 `local-rules`，且不发起远程请求。
- 只要存在任意一个 API Key，就会启用远程模型。
- 若 `LLM_BASE_URL` 未显式设置，则默认使用 `https://api.siliconflow.cn/v1`。
- 若 `LLM_MODEL` 未显式设置，则默认使用 `DeepSeek-V4-Flash`。

### 7.2 推荐配置方式

最简单的方式：只配置 SiliconFlow Key：

```powershell
$env:SILICONFLOW_API_KEY = "你的硅基流动API密钥"
```

也可以显式配置：

```powershell
$env:LLM_BASE_URL = "https://api.siliconflow.cn/v1"
$env:SILICONFLOW_API_KEY = "你的硅基流动API密钥"
$env:LLM_MODEL = "DeepSeek-V4-Flash"
```

再启动服务：

```powershell
.\.venv\Scripts\python.exe -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

可以在项目根目录创建 `.env` 文件，示例：

```dotenv
DATABASE_PATH=data/cvss.db
LLM_BASE_URL=https://api.siliconflow.cn/v1
LLM_API_KEY=
SILICONFLOW_API_KEY=你的硅基流动API密钥
DEEPSEEK_API_KEY=
LLM_MODEL=DeepSeek-V4-Flash
LLM_TIMEOUT=30
LLM_TEMPERATURE=0
LLM_BATCH_WORKERS=4
CVSS_VERSION=v3.1
DEFAULT_SHOTS=24
STD_MIN_SHOTS=1
STD_MAX_SHOTS=64
MR6_RETRIEVAL_URL=
```

### 7.3 Fallback 行为

- 远程请求失败时，会自动回退到本地规则评分
- LLM 无法确定的指标会返回 `DONT_KNOW`
- 评分流程会保留本地规则或原始 NVD 已有值，避免空值导致失败

## 8. 可配置环境变量

| 环境变量 | 默认值 | 说明 |
| --- | --- | --- |
| `DATABASE_PATH` | `data/cvss.db` | SQLite 数据库路径 |
| `LLM_BASE_URL` | `https://api.siliconflow.cn/v1` | OpenAI 兼容接口地址 |
| `LLM_API_KEY` | 空 | 通用 LLM API Key |
| `SILICONFLOW_API_KEY` | 空 | 硅基流动 Key |
| `DEEPSEEK_API_KEY` | 空 | 兼容旧配置的 DeepSeek Key |
| `LLM_MODEL` | `DeepSeek-V4-Flash` | 远程模型名称 |
| `LLM_TIMEOUT` | `30` | 请求超时时间（秒） |
| `LLM_TEMPERATURE` | `0` | 采样温度 |
| `LLM_MAX_TOKENS` | `4096` | 单次输出上限 |
| `LLM_MAX_RETRIES` | `2` | 重试次数 |
| `LLM_BATCH_WORKERS` | `4` | 批量评分并发数 |
| `CVSS_VERSION` | `v3.1` | 默认 CVSS 版本 |
| `DEFAULT_SHOTS` | `24` | 少样本默认示例数 |
| `STD_MIN_SHOTS` | `1` | 最小样本数 |
| `STD_MAX_SHOTS` | `64` | 最大样本数 |
| `MR6_RETRIEVAL_URL` | 空 | 额外检索服务地址 |

## 9. Web 工作台

启动服务后，在浏览器中访问：

- http://127.0.0.1:8000/

支持功能：

- 拖放或选择 JSON/CSV 文件导入
- 对已导入 CVE 执行本地规则或 LLM 评分
- 查看 CVSS 向量、分数、严重等级和各项指标
- 使用 DTD/STD/FVP 进行单指标核验
- 查询原始记录并与官方分数对比
- 批量导出评分结果

## 10. 主要接口速查

- `GET /health`：健康检查
- `GET /api/v1/models/capabilities`：查看模型能力
- `POST /api/v1/cve/import`：上传 JSON/CSV 文件导入
- `POST /api/v1/cve/preprocess`：直接提交结构化 CVE 列表
- `GET /api/v1/cve/{cve_id}`：查询单条 CVE
- `POST /api/v1/score/{cve_id}`：单条评分
- `POST /api/v1/score/batch`：批量评分
- `GET /api/v1/score/export`：导出 CSV
- `GET /api/v1/score/{cve_id}/compare`：比较官方与模型分数
- `POST /api/v1/score/dtd/predict`：单个指标 DTD 预测
- `POST /api/v1/score/dtd/{cve_id}`：对一条 CVE 进行 DTD 全量分析
- `POST /api/v1/predict`：统一预测接口
- `POST /api/v1/rag/retrieve`：相似漏洞检索
- `GET /api/v1/compare/view/{cve_id}`：三方对比视图

## 11. 常见问题

### 11.1 评分接口返回 404

通常是因为 CVE 还未导入数据库。先导入，再评分：

```powershell
curl.exe -X POST "http://127.0.0.1:8000/api/v1/cve/import" `
  -F "file=@data/raw/sample_cves.json"

curl.exe -X POST "http://127.0.0.1:8000/api/v1/score/CVE-2024-0001?use_llm=false"
```

### 11.2 无法连接到服务器

确认 Uvicorn 仍在运行：

```powershell
curl.exe "http://127.0.0.1:8000/health"
```

### 11.3 运行测试

在项目根目录执行：

```powershell
pytest -q
```

若需要真实 LLM 服务，请先配置 `LLM_BASE_URL` 和 API Key；未配置时，普通测试与本地规则评分仍可执行。

### 11.4 数据库位置

默认数据库路径：

```text
data/cvss.db
```

如果从其他目录启动服务，数据库相对路径可能会指向错误位置。

## 12. 代码目录结构

```text
demo/
├── app/
│   ├── __init__.py
│   ├── main.py
│   ├── config.py
│   ├── schemas.py
│   ├── api/
│   │   └── endpoints.py
│   ├── core/
│   │   ├── feature_extractor.py
│   │   ├── llm_enhancer.py
│   │   ├── preprocessor.py
│   │   ├── prompt_templates.py
│   │   ├── rag_retriever.py
│   │   ├── scheduler.py
│   │   └── prompts/
│   ├── models/
│   ├── services/
│   ├── static/
│   ├── templates/
│   └── utils/
├── data/
│   ├── raw/
│   ├── processed/
│   └── rag_index.json
├── docs/
├── tests/
├── .env.example
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
├── README.md
└── .gitignore
```

## 13. 总结

该项目同时兼顾研究原型和本地演示场景：

- 无需 LLM 也可运行
- 配置 API Key 后可接入 OpenAI 兼容大模型
- 支持多种评分策略和 CVSS 版本
- 适合 CVE 数据处理、评分、对比和实验复现

如果后续要扩展功能，例如更完整的前端筛选、Excel 导出、模型对比报告或自动化评测脚本，可以直接在现有接口和业务流程基础上继续构建。
