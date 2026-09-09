# 基于 LLM 的 CVSS 指标评分系统

一个可运行的 FastAPI 项目，实现 CVE 数据导入、清洗、CVSS v3.1 特征提取、评分、批量处理、DTD 单指标分析和结果对比。浏览器工作台集中覆盖导入、评分、记录查询和模型复核流程。配置 LLM 环境变量后，会通过 OpenAI 兼容的 `/chat/completions` 接口进行特征增强；未配置时自动使用本地规则推断，因此可离线演示。

## 一、运行环境

- Windows 10 或更高版本
- Python 3.10 或更高版本
- 建议使用项目自带的 `.venv` 虚拟环境

以下命令均在项目根目录执行。若 VS Code 终端已经打开在项目根目录，可直接执行命令。

## 二、安装依赖

```powershell
cd .
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

如果 PowerShell 禁止执行激活脚本：

```powershell
Set-ExecutionPolicy -Scope Process Bypass
```

也可以不激活虚拟环境：

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

## 三、启动服务

### 3.1 使用本地 Python 环境

在第一个 PowerShell 窗口执行：

```powershell
cd .
.\.venv\Scripts\python.exe -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

看到类似下面的日志，表示服务已启动：

```text
Uvicorn running on http://127.0.0.1:8000
```

启动服务的窗口需要保持运行。然后打开浏览器访问：

- Web 页面：http://127.0.0.1:8000/
- Swagger 接口文档：http://127.0.0.1:8000/docs
- 健康检查：http://127.0.0.1:8000/health

在第二个 PowerShell 窗口中执行后续导入和评分命令。

### 3.2 使用 Docker Compose

已安装 Docker Desktop 时，也可以在项目根目录执行：

```powershell
docker compose up --build
```

服务启动后访问 `http://127.0.0.1:8000/`。停止服务并删除容器：

```powershell
docker compose down
```

Compose 会将项目的 `data/` 映射到容器中的 `/app/data`，数据库数据会保留在本地。

## 四、导入外部数据集

### 4.1 JSON 数据格式

项目当前使用 NVD 1.1 JSON 格式。示例文件 `data/raw/sample_cves.json` 包含一条完整 CVE 记录，结构如下：
```json
{
  "cve": {
    "CVE_data_meta": {
      "ID": "CVE-2024-0001"
    },
    "description": {
      "description_data": [
        {
          "lang": "en",
          "value": "漏洞描述文本"
        }
      ]
    }
  },
  "configurations": {
    "nodes": []
  },
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

导入标准 NVD 数据集时，程序支持两种外层形式：包含多条记录的 `CVE_Items` 数组，或当前示例这种单条 CVE 对象。程序会读取以下字段：

- `cve.CVE_data_meta.ID`：CVE 编号
- `cve.description.description_data`：英文漏洞描述
- `publishedDate`、`lastModifiedDate`：发布时间和更新时间
- `configurations` 中的 `cpe23Uri`：受影响软件
- `impact.baseMetricV3.cvssV3`：CVSS v3 指标和官方基础分数

程序也兼容扁平 JSON 数组格式；此时每条记录至少需要包含 `cve_id`（或 `id`）和 `description`（或 `summary`）。

### 4.2 CSV 数据格式

将外部数据集保存为 `.csv` 文件，例如 `data/raw/my_cves.csv`：

```csv
cve_id,description,published_date,updated_date,affected_software
CVE-2024-0001,"A condition exists in FlashArray Purity whereby a local account remains active.",2024-09-23,2024-09-27,"Pure Storage FlashArray Purity"
```

CSV 第一行必须是字段名，至少包含 `cve_id` 和 `description`。

### 4.3 通过 API 上传数据集

在第二个 PowerShell 窗口执行。上传 JSON：

```powershell
cd .
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

`imported` 表示成功导入的记录数，`skipped` 表示格式错误而跳过的记录数，具体错误会列在 `errors` 中。相同 CVE ID 再次导入时会更新原记录。

### 4.4 导入项目自带示例数据

示例文件位于 `data/raw/sample_cves.json`。从项目根目录执行：

```powershell
curl.exe -X POST "http://127.0.0.1:8000/api/v1/cve/import" `
  -F "file=@data/raw/sample_cves.json"
```

导入成功后，可以查询当前示例记录：

```powershell
curl.exe "http://127.0.0.1:8000/api/v1/cve/CVE-2024-0001"
```

## 五、评分数据

确认数据导入成功后，对单条 CVE 进行本地规则评分：

```powershell
curl.exe -X POST "http://127.0.0.1:8000/api/v1/score/CVE-2024-0001?use_llm=false"
```

项目自带示例数据的 CVE 编号是 `CVE-2024-0001`；使用外部数据时请替换为已导入的编号。

批量评分全部已导入数据：

```powershell
curl.exe -X POST "http://127.0.0.1:8000/api/v1/score/batch" `
  -H "Content-Type: application/json" `
  -d '{"limit":20}'
```

批量评分指定 CVE：

```powershell
curl.exe -X POST "http://127.0.0.1:8000/api/v1/score/batch" `
  -H "Content-Type: application/json" `
  -d '{"cve_ids":["CVE-2024-12345","CVE-2024-23456"]}'
```

不传 `cve_ids` 时，接口按 CVE 编号顺序评分前 20 条记录；可以通过 `limit` 指定数量，范围为 1 到 500。

查看评分与原始数据中官方分数的差异：

```powershell
curl.exe "http://127.0.0.1:8000/api/v1/score/CVE-2024-0001/compare"
```

## 六、配置 LLM 评分

默认情况下使用本地规则完成评分，不需要 API Key。项目通过 `instructor` 将 OpenAI 兼容 API 的返回值约束为 Pydantic 模型，八个 CVSS v3.1 指标只接受官方标签或 `DONT_KNOW`。使用 LLM 增强时，在启动服务前于 PowerShell 设置环境变量：

```powershell
$env:LLM_BASE_URL = "https://api.deepseek.com/v1"
$env:LLM_API_KEY = "你的API密钥"
$env:LLM_MODEL = "deepseek-chat"
.\.venv\Scripts\python.exe -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

然后评分时不传 `use_llm=false`，或显式传入 `use_llm=true`。API 调用失败时会自动回退到本地规则评分。`.env.example` 和 `.env` 可用于 Docker Compose 配置；直接运行 Uvicorn 时，PowerShell 环境变量最可靠。

可选配置项如下：

| 环境变量 | 默认值 | 说明 |
| --- | --- | --- |
| `DATABASE_PATH` | `data/cvss.db` | SQLite 数据库路径 |
| `LLM_BASE_URL` | 空 | OpenAI 兼容接口地址 |
| `LLM_API_KEY` | 空 | LLM API 密钥 |
| `LLM_MODEL` | `deepseek-chat` | 使用的模型名称 |
| `LLM_TIMEOUT` | `30` | 请求超时时间，单位为秒 |
| `LLM_TEMPERATURE` | `0` | LLM 采样温度 |

其他模块可通过 `app.core.llm_client.get_instructor_client()` 获取统一的 Instructor 客户端；传入 `Settings` 可覆盖默认配置。LLM 无法判断的指标会返回 `DONT_KNOW`，评分流程会保留本地规则或 NVD 已有的可用值。

## 七、常见问题

### 评分接口返回 404

这通常表示 CVE 尚未导入数据库，而不是服务没有启动。先导入数据，再评分：

```powershell
curl.exe -X POST "http://127.0.0.1:8000/api/v1/cve/import" `
  -F "file=@data/raw/sample_cves.json"
curl.exe -X POST "http://127.0.0.1:8000/api/v1/score/CVE-2024-12345?use_llm=false"
```

### 无法连接到服务器

确认第一个 PowerShell 窗口仍在运行 Uvicorn，并检查：

```powershell
curl.exe "http://127.0.0.1:8000/health"
```

### 运行测试

安装依赖后，在项目根目录执行：

```powershell
pytest -q
```

需要真实 LLM 服务的端到端测试应在配置 `LLM_BASE_URL` 和 `LLM_API_KEY` 后运行；未配置时，普通测试和本地规则评分仍可执行。

### 数据库在哪里

默认数据库文件是 `data/cvss.db`。必须从项目根目录启动服务，否则相对路径可能指向其他目录。

## 主要接口

- `POST /api/v1/cve/import`：上传 JSON/CSV 数据集
- `POST /api/v1/cve/preprocess`：直接提交结构化 CVE JSON 数组
- `GET /api/v1/cve/{cve_id}`：查询 CVE
- `POST /api/v1/score/{cve_id}`：评分，`use_llm=false` 可强制本地模式
- `POST /api/v1/score/batch`：批量评分
- `GET /api/v1/score/{cve_id}/compare`：与原始数据中的官方分数对比
- `POST /api/v1/score/dtd/predict`：使用 DTD 提示分析单个 CVSS 指标
- `POST /api/v1/score/dtd/{cve_id}`：对单条 CVE 执行八项 DTD 分析并评分
- `GET /health`：健康检查

DTD 单指标分析请求示例：

```powershell
curl.exe -X POST "http://127.0.0.1:8000/api/v1/score/dtd/predict" `
  -H "Content-Type: application/json" `
  -d '{"cve_description":"A remote attacker can execute code without authentication.","metric":"AV"}'
```

批量评分请求体支持两种形式：`{"limit":20}`，或 `{"cve_ids":["CVE-2024-0001"]}`。接口返回评分结果数组。

## Web 工作台

打开 `http://127.0.0.1:8000/` 后，可以直接完成以下操作：

- 拖放或选择 JSON/CSV 数据集并导入
- 对已导入的 CVE 执行本地规则或 LLM 评分
- 查看 CVSS 向量、分数、严重等级和八项指标
- 使用 DTD 提示对单个指标进行核验
- 查询原始记录，并比较模型分数与官方分数
- 对单条 CVE 执行完整 DTD 评分


## 代码目录结构

demo/
│
├── app/                                    # 应用核心包
│   │
│   ├── __init__.py                         # 包初始化，定义应用工厂
│   ├── main.py                             # 应用入口（uvicorn 启动脚本）
│   ├── config.py                           # 全局配置管理（环境变量、数据库连接、API_KEY）
│   ├── schemas.py                          # Pydantic 数据模型（请求/响应结构体）
│   ├── models/                             # 兼容导出的模型路径
│   │   ├── __init__.py
│   │   └── schemas.py
│   ├── services/                           # 数据库服务
│   │   ├── __init__.py
│   │   └── database.py
│   ├── api/                                # 路由层（对外 RESTful 接口）
│   │   ├── __init__.py
│   │   └── endpoints.py                    # 具体 API 路由实现
│   ├── core/                               # 核心业务逻辑（算法/模型/数据流）
│   │   ├── __init__.py
│   │   ├── preprocessor.py                 # CVE 原始数据清洗、字段解析、结构化存储
│   │   ├── feature_extractor.py            # CVSS 基础/时间/环境特征向量提取
│   │   ├── llm_enhancer.py                 # LLM 特征增强与评分核心
│   │   ├── chroma_client.py                # 向量数据库客户端（ChromaDB 增删改查）
│   │   ├── scheduler.py                    # 主流程调度器（管线编排）
│   │   └── prompt_templates.py             # CVSS DTD 提示模板
│   ├── templates/                          # 前端 HTML 模板
│   │   └── index.html
│   ├── static/                             # 前端静态资源（CSS / JS）
│   │   ├── styles.css
│   │   └── app.js
│   └── utils/                              # 通用工具模块
│       ├── __init__.py
│       └── logger.py                       # 日志记录器（文件输出 + 控制台）
├── data/                                   # 数据存储目录（不纳入 Git 大文件）
│   ├── raw/                                # 原始 CVE 数据集（JSON/CSV）
│   ├── processed/                          # 清洗后的结构化数据（SQLite / Parquet）
│   └── chroma_db/                          # ChromaDB 持久化目录（向量数据）
├── tests/                                  # 测试套件（单元测试、集成测试、冒烟测试）
├── docs/                                   # 项目文档
├── requirements.txt                        # Python 依赖包列表（精确版本）
├── Dockerfile                              # Docker 镜像构建脚本
├── docker-compose.yml                      # 多容器编排（app + chromadb + nginx 可选）
├── .env                                    # 本地敏感配置（不提交 Git，含 API_KEY）
├── .env.example                            # 环境变量模板（提交 Git）
├── .gitignore                              # Git 忽略规则（忽略 data/、.env、__pycache__ 等）
└── README.md                               # 项目说明（简介、安装步骤、运行命令、API 示例）