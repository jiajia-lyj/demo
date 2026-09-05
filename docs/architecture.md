# 系统架构

系统采用分层结构：`app/main.py` 负责应用装配，`app/api/endpoints.py` 负责 REST API，`app/core/` 负责预处理、特征提取、LLM 增强、调度和向量存储，`app/utils/` 负责通用工具。

数据流为：CVE 文件 -> `Preprocessor` -> SQLite -> `FeatureExtractor` -> `Scheduler` -> 本地 CVSS 评分或 OpenAI 兼容 LLM。
