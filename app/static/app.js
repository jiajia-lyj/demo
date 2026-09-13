const $ = (selector) => document.querySelector(selector);

async function request(url, options = {}) {
  let response;
  try {
    response = await fetch(url, options);
  } catch (error) {
    throw new Error("无法连接服务，请确认后端仍在运行");
  }
  const contentType = response.headers.get("content-type") || "";
  const data = contentType.includes("application/json") ? await response.json() : {};
  if (!response.ok) {
    const detail = typeof data.detail === "object" ? data.detail.message : data.detail;
    throw new Error(detail || `请求失败 (${response.status})`);
  }
  return data;
}

function setBusy(button, busy, label) {
  if (!button.dataset.labelHtml) button.dataset.labelHtml = button.innerHTML;
  button.disabled = busy;
  button.setAttribute("aria-busy", String(busy));
  button.innerHTML = busy ? `<span class="button-spinner" aria-hidden="true"></span>${escapeHtml(label)}` : button.dataset.labelHtml;
}

function showMessage(target, message, error = false) {
  target.textContent = message;
  target.classList.toggle("error", error);
  target.setAttribute("role", error ? "alert" : "status");
}

function escapeHtml(value) {
  return String(value).replace(/[&<>'"]/g, (character) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", "'": "&#39;", '"': "&quot;",
  }[character]));
}

const METRICS = [
  { abbr: "AV", label: "攻击向量", key: "attack_vector", max: 4 },
  { abbr: "AC", label: "攻击复杂度", key: "attack_complexity", max: 2 },
  { abbr: "PR", label: "权限要求", key: "privileges_required", max: 3 },
  { abbr: "UI", label: "用户交互", key: "user_interaction", max: 2 },
  { abbr: "S",  label: "范围", key: "scope", max: 2 },
  { abbr: "C",  label: "机密性", key: "confidentiality", max: 3 },
  { abbr: "I",  label: "完整性", key: "integrity", max: 3 },
  { abbr: "A",  label: "可用性", key: "availability", max: 3 },
];

const FONT_SANS = "'Space Grotesk', system-ui, -apple-system, 'Segoe UI', 'Roboto', sans-serif";
const FONT_MONO = "'DM Mono', ui-monospace, 'SFMono-Regular', 'Menlo', 'Consolas', monospace";

const VALUE_CN_MAP = {
  NETWORK: "网络", ADJACENT: "相邻", LOCAL: "本地", PHYSICAL: "物理",
  LOW: "低", HIGH: "高", NONE: "无",
  REQUIRED: "需要", UNCHANGED: "不变", CHANGED: "改变",
  DONT_KNOW: "未知",
};

const STRATEGY_LABELS = {
  dtd: "DTD 零样本", dtd_fewshot: "DTD Few-Shot", fvp: "FVP 全向量", std: "STD 基线",
};

const VIZ_COLORS = ["#0d7b74", "#e86952", "#efc95d"];
const VIZ_NAMES = ["Official", "LLM", "Worst Case"];

const predictHistory = [];
const MAX_HISTORY = 5;

function valueCN(value) {
  return VALUE_CN_MAP[value] || value;
}

function providerLabel(model) {
  return (model || "LLM").toUpperCase().split(/[-._]/)[0];
}

function renderMetrics(features = {}) {
  return METRICS.map(({ abbr, label, key }) => {
    const value = features[key] || "DONT_KNOW";
    const unknown = value === "DONT_KNOW";
    return `<div class="metric ${unknown ? "unknown" : ""}"><span>${abbr}</span><strong>${escapeHtml(unknown ? "未知" : value)}</strong><small>${label}</small></div>`;
  }).join("");
}

function renderScore(data) {
  const severityClass = String(data.severity || "").toLowerCase();
  const provider = providerLabel(data.llm_model);
  const source = data.llm_model ? `${provider} · ${data.llm_model}` : "LOCAL RULES";
  const confidence = data.llm_confidence == null ? "未提供置信度" : `置信度 ${data.llm_confidence}`;
  const usage = data.token_usage?.total_tokens == null ? "未记录 token" : `${data.token_usage.total_tokens} tokens`;
  return `<div class="score-line"><span class="score-number">${escapeHtml(data.cvss_base_score)}</span><span class="severity severity-${escapeHtml(severityClass)}">${escapeHtml(data.severity)}</span></div><div class="vector-row"><div class="vector">${escapeHtml(data.cvss_vector)}</div><button class="copy-button" type="button" data-copy-vector="${escapeHtml(data.cvss_vector)}" title="复制 CVSS 向量">复制</button></div><div class="score-meta"><span>${escapeHtml(source)}</span><span>${escapeHtml(confidence)}</span><span>${escapeHtml(usage)}</span></div><div class="metric-grid">${renderMetrics(data.features)}</div>`;
}

function renderBatchResults(results) {
  if (!results.length) return "没有找到可分析的 CVE 记录";
  const average = (results.reduce((total, item) => total + Number(item.cvss_base_score || 0), 0) / results.length).toFixed(1);
  const rows = results.map((item) => `<tr><td>${escapeHtml(item.cve_id)}</td><td><strong>${escapeHtml(item.cvss_base_score)}</strong></td><td><span class="severity severity-${escapeHtml(String(item.severity).toLowerCase())}">${escapeHtml(item.severity)}</span></td><td>${escapeHtml(item.cvss_vector)}</td><td>${escapeHtml(item.llm_model || "LOCAL RULES")}</td></tr>`).join("");
  return `<div class="batch-summary">已完成 ${results.length} 条 · 平均分 ${average}</div><div class="table-wrap"><table><thead><tr><th>CVE</th><th>分数</th><th>等级</th><th>向量</th><th>模型</th></tr></thead><tbody>${rows}</tbody></table></div>`;
}

async function checkHealth() {
  try {
    const data = await request("/health");
    const enabled = data.llm === "enabled";
    const model = data.llm_model || "local-rules";
    $("#system-status").textContent = enabled ? `${model} 已配置` : "本地模式运行";
    $("#engine-stat").textContent = enabled ? `${providerLabel(model)} / ${model}` : "LOCAL RULES";
    $("#model-status").classList.toggle("enabled", enabled);
    $("#model-status span:last-child").textContent = enabled ? `模型：${model}` : "模型：本地规则回退";
    $("#mode-stat").textContent = "ONLINE";
    $(".status-dot").classList.add("ready");
  } catch (error) {
    $("#system-status").textContent = "服务不可用";
    $("#mode-stat").textContent = "OFFLINE";
    $("#model-status").classList.remove("enabled");
    $("#model-status span:last-child").textContent = "模型：服务不可用";
    $(".status-dot").classList.remove("ready");
  }
}

function updateFileName(file) {
  $("#file-name").textContent = file?.name || "选择数据集文件";
}

$("#dataset-file").addEventListener("change", (event) => updateFileName(event.target.files[0]));

$("#dropzone").addEventListener("dragover", (event) => {
  event.preventDefault();
  $("#dropzone").classList.add("dragging");
});

$("#dropzone").addEventListener("dragleave", () => $("#dropzone").classList.remove("dragging"));
$("#dropzone").addEventListener("drop", (event) => {
  event.preventDefault();
  $("#dropzone").classList.remove("dragging");
  const file = event.dataTransfer.files[0];
  if (file) {
    const transfer = new DataTransfer();
    transfer.items.add(file);
    $("#dataset-file").files = transfer.files;
    updateFileName(file);
  }
});

$("#import-button").addEventListener("click", async () => {
  const file = $("#dataset-file").files[0];
  const output = $("#import-result");
  if (!file) return showMessage(output, "请先选择 JSON 或 CSV 文件", true);
  if (!/\.(json|csv)$/i.test(file.name)) return showMessage(output, "文件格式不支持，请选择 JSON 或 CSV", true);
  const form = new FormData();
  form.append("file", file);
  const button = $("#import-button");
  setBusy(button, true, "导入中...");
  showMessage(output, "正在读取并清洗数据...");
  try {
    const data = await request("/api/v1/cve/import", { method: "POST", body: form });
    const suffix = data.errors?.length ? `，${data.errors.length} 条记录需要检查` : "";
    showMessage(output, `已导入 ${data.imported} 条，跳过 ${data.skipped} 条${suffix}`);
    $("#mode-stat").textContent = "DATA READY";
  } catch (error) {
    showMessage(output, `错误：${error.message}`, true);
  } finally {
    setBusy(button, false);
    output.removeAttribute("aria-busy");
  }
});

$("#batch-score-button").addEventListener("click", async () => {
  const output = $("#batch-result");
  const limit = Math.max(1, Math.min(20, Number($("#batch-limit").value) || 20));
  $("#batch-limit").value = limit;
  const button = $("#batch-score-button");
  setBusy(button, true, "分析中...");
  output.className = "batch-result";
  output.textContent = "正在分析已导入的数据集...";
  try {
    const data = await request("/api/v1/score/batch", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ limit, use_llm: $("#use-llm").checked }),
    });
    output.innerHTML = renderBatchResults(data);
    $("#mode-stat").textContent = "BATCH SCORED";
  } catch (error) {
    showMessage(output, `错误：${error.message}`, true);
  } finally {
    setBusy(button, false);
  }
});

$("#score-button").addEventListener("click", async () => {
  const id = $("#cve-id").value.trim().toUpperCase();
  const output = $("#score-result");
  if (!id) return showMessage(output, "请输入 CVE ID", true);
  const button = $("#score-button");
  setBusy(button, true, "分析中...");
  output.setAttribute("aria-busy", "true");
  output.className = "result-card";
  output.textContent = "正在计算 CVSS v3.1...";
  try {
    const data = await request(`/api/v1/score/${encodeURIComponent(id)}?use_llm=${$("#use-llm").checked}`, { method: "POST" });
    output.innerHTML = renderScore(data);
    $("#lookup-id").value = id;
    $("#mode-stat").textContent = "SCORED";
  } catch (error) {
    showMessage(output, `错误：${error.message}`, true);
  } finally {
    setBusy(button, false);
    output.removeAttribute("aria-busy");
  }
});

$("#score-result").addEventListener("click", async (event) => {
  const button = event.target.closest("[data-copy-vector]");
  if (!button) return;
  try {
    await navigator.clipboard.writeText(button.dataset.copyVector);
    button.textContent = "已复制";
    setTimeout(() => { button.textContent = "复制"; }, 1200);
  } catch (error) {
    button.textContent = "复制失败";
  }
});

$("#dtd-predict-button").addEventListener("click", async () => {
  const description = $("#dtd-description").value.trim();
  const output = $("#dtd-result");
  if (!description) return showMessage(output, "请输入漏洞描述", true);
  const button = $("#dtd-predict-button");
  setBusy(button, true, "分析中...");
  output.setAttribute("aria-busy", "true");
  output.className = "dtd-result";
  output.textContent = "正在生成单指标判断...";
  try {
    const data = await request("/api/v1/score/dtd/predict", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ metric: $("#dtd-metric").value, cve_description: description }),
    });
    output.innerHTML = `<span class="dtd-value">${escapeHtml(data.value)}</span><span class="dtd-name">${escapeHtml(data.metric_name)} · 合法值 ${data.valid_labels.map(escapeHtml).join(", ")}</span>`;
  } catch (error) {
    showMessage(output, `错误：${error.message}`, true);
  } finally {
    setBusy(button, false);
    output.removeAttribute("aria-busy");
  }
});

$("#lookup-button").addEventListener("click", async () => {
  const id = $("#lookup-id").value.trim().toUpperCase();
  const output = $("#lookup-result");
  if (!id) return showMessage(output, "请输入 CVE ID", true);
  const button = $("#lookup-button");
  setBusy(button, true, "查询中...");
  try {
    const data = await request(`/api/v1/cve/${encodeURIComponent(id)}`);
    output.textContent = JSON.stringify(data, null, 2);
    $("#dtd-description").value = data.description || "";
    $("#dtd-result").className = "dtd-result empty";
    $("#dtd-result").textContent = data.description ? "已将该 CVE 描述带入 DTD 分析" : "记录没有可用描述";
  } catch (error) {
    showMessage(output, `错误：${error.message}`, true);
  } finally {
    setBusy(button, false);
  }
});

$("#cve-id").addEventListener("keydown", (event) => {
  if (event.key === "Enter") $("#score-button").click();
});

$("#lookup-id").addEventListener("keydown", (event) => {
  if (event.key === "Enter") $("#lookup-button").click();
});

$("#compare-button").addEventListener("click", async () => {
  const id = $("#lookup-id").value.trim().toUpperCase();
  const output = $("#compare-result");
  if (!id) return showMessage(output, "请先输入 CVE ID", true);
  const button = $("#compare-button");
  setBusy(button, true, "比较中...");
  try {
    const data = await request(`/api/v1/score/${encodeURIComponent(id)}/compare`);
    output.innerHTML = `模型评分 <strong>${escapeHtml(data.llm_score ?? "-")}</strong><br>官方评分 ${escapeHtml(data.official_score ?? "暂无")}<br>差异 ${escapeHtml(data.difference ?? "暂无")}`;
  } catch (error) {
    showMessage(output, `错误：${error.message}`, true);
  } finally {
    setBusy(button, false);
  }
});

$("#dtd-score-button").addEventListener("click", async () => {
  const id = $("#lookup-id").value.trim().toUpperCase();
  const output = $("#compare-result");
  if (!id) return showMessage(output, "请先输入 CVE ID", true);
  const button = $("#dtd-score-button");
  setBusy(button, true, "评分中...");
  try {
    const data = await request(`/api/v1/score/dtd/${encodeURIComponent(id)}`, { method: "POST" });
    const values = Object.entries(data.dtd_values).map(([key, value]) => `${escapeHtml(key)}: ${escapeHtml(value)}`).join(" · ");
    output.innerHTML = `<strong>DTD ${escapeHtml(data.cvss_base_score)}</strong><br>${escapeHtml(data.cvss_vector)}<br><span class="review-meta">${values}</span>`;
  } catch (error) {
    showMessage(output, `错误：${error.message}`, true);
  } finally {
    setBusy(button, false);
  }
});

function renderPredictCard(data) {
  const ctx = data.context_info;
  const ctxLine = ctx ? `<div class="ctx-info">上下文: ${ctx.prompt_tokens}/${ctx.max_tokens} tokens · shots ${data.shots_used}/${data.shots_requested} · ${escapeHtml(ctx.reason)}</div>` : "";
  const labels = data.valid_labels.map((v) => `<span class="tag">${escapeHtml(v)}${valueCN(v) !== v ? `·${escapeHtml(valueCN(v))}` : ""}</span>`).join("");
  return `<div class="predict-card"><div class="predict-card-header"><span class="predict-value">${escapeHtml(data.value)}</span><span class="predict-value-cn">${escapeHtml(valueCN(data.value))}</span></div><div class="predict-card-meta"><span class="badge">${escapeHtml(data.metric_name)}</span><span class="badge strategy">${escapeHtml(STRATEGY_LABELS[data.strategy] || data.strategy)}</span><span class="badge">CVSS v${escapeHtml(data.cvss_version)}</span><span class="badge">${escapeHtml(data.model)}</span></div>${ctxLine}<div class="predict-labels"><small>合法值:</small>${labels}</div></div>`;
}

function renderPredictAllCard(results) {
  const vector = results.map((r) => r.value).join(":");
  const rows = results.map((r) => {
    const metric = METRICS.find((m) => m.key === r.metric);
    return `<tr><td>${metric ? metric.abbr : escapeHtml(r.metric)}</td><td>${metric ? escapeHtml(metric.label) : ""}</td><td><strong>${escapeHtml(r.value)}</strong></td><td>${escapeHtml(valueCN(r.value))}</td></tr>`;
  }).join("");
  return `<div class="predict-card"><div class="predict-card-header"><span class="predict-value">全指标预测</span><span class="predict-value-cn">${results.length} 项</span></div><div class="vector-row"><div class="vector">${escapeHtml(vector)}</div><button class="copy-button" type="button" data-copy-vector="${escapeHtml(vector)}" title="复制向量">复制</button></div><div class="table-wrap"><table><thead><tr><th>指标</th><th>名称</th><th>值</th><th>中文</th></tr></thead><tbody>${rows}</tbody></table></div></div>`;
}

function addPredictHistory(entry) {
  predictHistory.unshift(entry);
  if (predictHistory.length > MAX_HISTORY) predictHistory.pop();
  renderPredictHistory();
}

function renderPredictHistory() {
  const container = $("#predict-history");
  if (!predictHistory.length) { container.innerHTML = ""; return; }
  container.innerHTML = `<p class="history-title">预测历史（最近 ${predictHistory.length} 次）</p>` + predictHistory.map((item, i) => {
    const metric = METRICS.find((m) => m.key === item.metric);
    return `<div class="history-item" data-idx="${i}"><span class="history-idx">#${predictHistory.length - i}</span><span class="history-metric">${metric ? metric.abbr : escapeHtml(item.metric)}</span><span class="history-value">${escapeHtml(item.value)}</span><span class="history-strategy">${escapeHtml(STRATEGY_LABELS[item.strategy] || item.strategy)}</span><span class="history-time">${escapeHtml(item.time)}</span></div>`;
  }).join("");
  container.querySelectorAll(".history-item").forEach((el) => {
    el.addEventListener("click", () => {
      const idx = Number(el.dataset.idx);
      const item = predictHistory[idx];
      $("#predict-result").className = "predict-result";
      $("#predict-result").innerHTML = item.cardHtml;
    });
  });
}

$("#predict-button").addEventListener("click", async () => {
  const description = $("#predict-description").value.trim();
  const output = $("#predict-result");
  if (!description) return showMessage(output, "请输入漏洞描述", true);
  const payload = {
    cve_description: description,
    metric: $("#predict-metric").value,
    strategy: $("#predict-strategy").value,
    shots: Number($("#predict-shots").value) || 0,
    cvss_version: $("#predict-version").value,
  };
  const model = $("#predict-model").value.trim();
  if (model) payload.model = model;
  const button = $("#predict-button");
  setBusy(button, true, "预测中...");
  output.setAttribute("aria-busy", "true");
  output.className = "predict-result";
  output.textContent = "正在调用统一预测接口...";
  try {
    const data = await request("/api/v1/predict", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    const cardHtml = renderPredictCard(data);
    output.innerHTML = cardHtml;
    addPredictHistory({
      metric: data.metric, value: data.value, strategy: data.strategy,
      time: new Date().toLocaleTimeString("zh-CN", { hour12: false }),
      cardHtml,
    });
  } catch (error) {
    showMessage(output, `错误：${error.message}`, true);
  } finally {
    setBusy(button, false);
    output.removeAttribute("aria-busy");
  }
});

$("#predict-all-button").addEventListener("click", async () => {
  const description = $("#predict-description").value.trim();
  const output = $("#predict-result");
  if (!description) return showMessage(output, "请输入漏洞描述", true);
  const button = $("#predict-all-button");
  setBusy(button, true, "预测全部指标中...");
  output.setAttribute("aria-busy", "true");
  output.className = "predict-result";
  output.textContent = "正在预测全部 8 个指标...";
  const basePayload = {
    cve_description: description,
    strategy: $("#predict-strategy").value,
    shots: Number($("#predict-shots").value) || 0,
    cvss_version: $("#predict-version").value,
  };
  const model = $("#predict-model").value.trim();
  if (model) basePayload.model = model;
  try {
    const results = [];
    for (const { key } of METRICS) {
      const data = await request("/api/v1/predict", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ...basePayload, metric: key }),
      });
      results.push(data);
    }
    output.innerHTML = renderPredictAllCard(results);
  } catch (error) {
    showMessage(output, `错误：${error.message}`, true);
  } finally {
    setBusy(button, false);
    output.removeAttribute("aria-busy");
  }
});

const METRIC_AXIS = METRICS.map(({ key, abbr: label, max }) => ({ key, label, max }));

const LABEL_RANK = {
  attack_vector: { NONE: 0, PHYSICAL: 1, LOCAL: 2, ADJACENT: 3, NETWORK: 4 },
  attack_complexity: { NONE: 0, HIGH: 1, LOW: 2 },
  privileges_required: { NONE: 1, LOW: 2, HIGH: 3 },
  user_interaction: { NONE: 1, REQUIRED: 2 },
  scope: { UNCHANGED: 1, CHANGED: 2 },
  confidentiality: { NONE: 0, LOW: 1, HIGH: 2 },
  integrity: { NONE: 0, LOW: 1, HIGH: 2 },
  availability: { NONE: 0, LOW: 1, HIGH: 2 },
};

function metricToNumber(value, key) {
  const rank = LABEL_RANK[key] || {};
  return rank[value] ?? 0;
}

function drawRadarChart(canvas, datasets) {
  const ctx = canvas.getContext("2d");
  const width = canvas.width;
  const height = canvas.height;
  const cx = width / 2;
  const cy = height / 2;
  const radius = Math.min(width, height) / 2 - 50;
  const axes = METRIC_AXIS;
  const count = axes.length;
  ctx.clearRect(0, 0, width, height);
  for (let level = 1; level <= 4; level++) {
    const r = (radius * level) / 4;
    ctx.beginPath();
    for (let i = 0; i < count; i++) {
      const angle = (Math.PI * 2 * i) / count - Math.PI / 2;
      const x = cx + r * Math.cos(angle);
      const y = cy + r * Math.sin(angle);
      if (i === 0) ctx.moveTo(x, y); else ctx.lineTo(x, y);
    }
    ctx.closePath();
    ctx.strokeStyle = "rgba(13, 123, 116, 0.15)";
    ctx.lineWidth = 1;
    ctx.stroke();
  }
  for (let i = 0; i < count; i++) {
    const angle = (Math.PI * 2 * i) / count - Math.PI / 2;
    const x = cx + radius * Math.cos(angle);
    const y = cy + radius * Math.sin(angle);
    ctx.beginPath();
    ctx.moveTo(cx, cy);
    ctx.lineTo(x, y);
    ctx.strokeStyle = "rgba(13, 123, 116, 0.2)";
    ctx.stroke();
    const labelX = cx + (radius + 20) * Math.cos(angle);
    const labelY = cy + (radius + 20) * Math.sin(angle);
    ctx.fillStyle = "#17252a";
    ctx.font = `600 13px ${FONT_SANS}`;
    ctx.textAlign = "center";
    ctx.textBaseline = "middle";
    ctx.fillText(axes[i].label, labelX, labelY);
  }
  datasets.forEach((dataset, index) => {
    ctx.beginPath();
    for (let i = 0; i < count; i++) {
      const axis = axes[i];
      const normalized = dataset.values[i] / axis.max;
      const r = radius * Math.max(0, Math.min(1, normalized));
      const angle = (Math.PI * 2 * i) / count - Math.PI / 2;
      const x = cx + r * Math.cos(angle);
      const y = cy + r * Math.sin(angle);
      if (i === 0) ctx.moveTo(x, y); else ctx.lineTo(x, y);
    }
    ctx.closePath();
    ctx.fillStyle = VIZ_COLORS[index] + "33";
    ctx.fill();
    ctx.strokeStyle = VIZ_COLORS[index];
    ctx.lineWidth = 2;
    ctx.stroke();
  });
}

function drawEmptyState(canvas, text) {
  const ctx = canvas.getContext("2d");
  ctx.clearRect(0, 0, canvas.width, canvas.height);
  ctx.fillStyle = "#5f6d71";
  ctx.font = `500 14px ${FONT_SANS}`;
  ctx.textAlign = "center";
  ctx.textBaseline = "middle";
  ctx.fillText(text, canvas.width / 2, canvas.height / 2);
}

function renderVizLegendRow(datasets) {
  const container = $("#viz-legend-row");
  if (!datasets.length) { container.innerHTML = ""; return; }
  container.innerHTML = datasets.map((ds, i) =>
    `<span class="viz-legend-item"><span class="viz-legend-dot" style="background:${VIZ_COLORS[i]}"></span>${escapeHtml(ds.name)}</span>`
  ).join("");
}

function renderVizTable(data) {
  const container = $("#viz-table-wrap");
  const sources = [];
  if (data.official_metrics) sources.push({ name: "Official", metrics: data.official_metrics });
  if (data.llm_metrics) sources.push({ name: "LLM", metrics: data.llm_metrics });
  if (data.worst_case_metrics) sources.push({ name: "Worst Case", metrics: data.worst_case_metrics });
  if (sources.length === 0) { container.innerHTML = ""; return; }
  const header = `<tr><th>指标</th><th>名称</th>${sources.map((s) => `<th>${escapeHtml(s.name)}</th>`).join("")}</tr>`;
  const rows = METRICS.map(({ abbr, label, key }) => {
    const cells = sources.map((s) => {
      const val = s.metrics?.[key] || "—";
      const isDiff = sources.length >= 2 && s.name === "LLM" && sources[0].metrics && val !== (sources[0].metrics[key] || "—") && val !== "—";
      return `<td${isDiff ? ' class="diff"' : ""}>${escapeHtml(val)}</td>`;
    }).join("");
    return `<tr><td><strong>${abbr}</strong></td><td>${escapeHtml(label)}</td>${cells}</tr>`;
  }).join("");
  container.innerHTML = `<div class="table-wrap"><table class="viz-table"><thead>${header}</thead><tbody>${rows}</tbody></table></div>`;
}

function drawBarChart(canvas, bars) {
  const ctx = canvas.getContext("2d");
  const width = canvas.width;
  const height = canvas.height;
  ctx.clearRect(0, 0, width, height);
  const padding = 60;
  const chartWidth = width - padding * 2;
  const chartHeight = height - padding * 2;
  const maxScore = 10;
  const barWidth = chartWidth / bars.length * 0.6;
  const gap = chartWidth / bars.length * 0.4;
  const colors = VIZ_COLORS;
  ctx.fillStyle = "#5f6d71";
  ctx.font = `500 12px ${FONT_SANS}`;
  ctx.textAlign = "center";
  ctx.fillText("CVSS Base Score (0-10)", width / 2, 20);
  bars.forEach((bar, index) => {
    const x = padding + (chartWidth / bars.length) * index + gap / 2;
    const barHeight = chartHeight * Math.max(0, Math.min(1, (bar.value || 0) / maxScore));
    const y = padding + chartHeight - barHeight;
    ctx.fillStyle = colors[index] || "#0d7b74";
    ctx.fillRect(x, y, barWidth, barHeight);
    ctx.fillStyle = "#17252a";
    ctx.font = `600 13px ${FONT_SANS}`;
    ctx.textAlign = "center";
    ctx.fillText(bar.label, x + barWidth / 2, padding + chartHeight + 20);
    if (bar.value != null) {
      ctx.fillStyle = "#17252a";
      ctx.font = `700 15px ${FONT_SANS}`;
      ctx.fillText(String(bar.value), x + barWidth / 2, y - 8);
    }
  });
  ctx.strokeStyle = "rgba(13, 123, 116, 0.2)";
  ctx.lineWidth = 1;
  for (let level = 0; level <= 5; level++) {
    const y = padding + chartHeight - (chartHeight * level * 2) / maxScore;
    ctx.beginPath();
    ctx.moveTo(padding, y);
    ctx.lineTo(width - padding, y);
    ctx.stroke();
    ctx.fillStyle = "#5f6d71";
    ctx.font = `400 11px ${FONT_MONO}`;
    ctx.textAlign = "right";
    ctx.fillText(String(level * 2), padding - 8, y + 4);
  }
}

$("#viz-load-button").addEventListener("click", async () => {
  const id = $("#viz-cve-id").value.trim().toUpperCase();
  const legend = $("#viz-legend");
  if (!id) return showMessage(legend, "请输入 CVE ID", true);
  const button = $("#viz-load-button");
  setBusy(button, true, "加载中...");
  try {
    const data = await request(`/api/v1/compare/view/${encodeURIComponent(id)}`);
    const toNumeric = (metrics) => METRIC_AXIS.map((axis) => metricToNumber(metrics?.[axis.key] || "NONE", axis.key));
    const datasets = [];
    if (data.official_metrics) datasets.push({ name: "Official", values: toNumeric(data.official_metrics) });
    if (data.llm_metrics) datasets.push({ name: "LLM", values: toNumeric(data.llm_metrics) });
    if (data.worst_case_metrics) datasets.push({ name: "Worst Case", values: toNumeric(data.worst_case_metrics) });
    renderVizLegendRow(datasets);
    drawRadarChart($("#radar-chart"), datasets);
    const bars = [];
    if (data.official_score != null) bars.push({ label: "Official", value: data.official_score });
    if (data.llm_score != null) bars.push({ label: "LLM", value: data.llm_score });
    if (data.worst_case_score != null) bars.push({ label: "Worst Case", value: data.worst_case_score });
    drawBarChart($("#bar-chart"), bars);
    const diff = data.difference != null ? `差异 ${data.difference}` : "无可对比官方评分";
    legend.innerHTML = `<strong>${escapeHtml(data.cve_id)}</strong> · ${diff} · 官方 ${escapeHtml(data.official_score ?? "暂无")} / LLM ${escapeHtml(data.llm_score ?? "暂无")} / Worst ${escapeHtml(data.worst_case_score ?? "暂无")}`;
    renderVizTable(data);
  } catch (error) {
    showMessage(legend, `错误：${error.message}`, true);
  } finally {
    setBusy(button, false);
  }
});

drawEmptyState($("#radar-chart"), "输入 CVE ID 后加载雷达图");
drawEmptyState($("#bar-chart"), "输入 CVE ID 后加载对比图");

checkHealth();