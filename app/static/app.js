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

const metricLabels = [
  ["AV", "攻击向量", "attack_vector"], ["AC", "攻击复杂度", "attack_complexity"],
  ["PR", "权限要求", "privileges_required"], ["UI", "用户交互", "user_interaction"],
  ["S", "范围", "scope"], ["C", "机密性", "confidentiality"],
  ["I", "完整性", "integrity"], ["A", "可用性", "availability"],
];

function renderMetrics(features = {}) {
  return metricLabels.map(([shortName, label, key]) => {
    const value = features[key] || "DONT_KNOW";
    const unknown = value === "DONT_KNOW";
    return `<div class="metric ${unknown ? "unknown" : ""}"><span>${shortName}</span><strong>${escapeHtml(unknown ? "未知" : value)}</strong><small>${label}</small></div>`;
  }).join("");
}

function renderScore(data) {
  const severityClass = String(data.severity || "").toLowerCase();
  const source = data.llm_model ? `LLM · ${data.llm_model}` : "LOCAL RULES";
  const confidence = data.llm_confidence == null ? "未提供置信度" : `置信度 ${data.llm_confidence}`;
  const usage = data.token_usage?.total_tokens == null ? "未记录 token" : `${data.token_usage.total_tokens} tokens`;
  return `<div class="score-line"><span class="score-number">${escapeHtml(data.cvss_base_score)}</span><span class="severity severity-${escapeHtml(severityClass)}">${escapeHtml(data.severity)}</span></div><div class="vector-row"><div class="vector">${escapeHtml(data.cvss_vector)}</div><button class="copy-button" type="button" data-copy-vector="${escapeHtml(data.cvss_vector)}" title="复制 CVSS 向量">复制</button></div><div class="score-meta"><span>${escapeHtml(source)}</span><span>${escapeHtml(confidence)}</span><span>${escapeHtml(usage)}</span></div><div class="metric-grid">${renderMetrics(data.features)}</div>`;
}

function renderBatchResults(results) {
  if (!results.length) return "没有找到可分析的 CVE 记录";
  const average = (results.reduce((total, item) => total + Number(item.cvss_base_score || 0), 0) / results.length).toFixed(1);
  const rows = results.map((item) => `<tr><td>${escapeHtml(item.cve_id)}</td><td><strong>${escapeHtml(item.cvss_base_score)}</strong></td><td><span class="severity severity-${escapeHtml(String(item.severity).toLowerCase())}">${escapeHtml(item.severity)}</span></td><td>${escapeHtml(item.cvss_vector)}</td></tr>`).join("");
  return `<div class="batch-summary">已完成 ${results.length} 条 · 平均分 ${average}</div><div class="table-wrap"><table><thead><tr><th>CVE</th><th>分数</th><th>等级</th><th>向量</th></tr></thead><tbody>${rows}</tbody></table></div>`;
}

async function checkHealth() {
  try {
    const data = await request("/health");
    const enabled = data.llm === "enabled";
    $("#system-status").textContent = enabled ? "LLM 已连接" : "本地模式运行";
    $("#engine-stat").textContent = enabled ? "LLM + RULES" : "LOCAL RULES";
    $("#mode-stat").textContent = "ONLINE";
    $(".status-dot").classList.add("ready");
  } catch (error) {
    $("#system-status").textContent = "服务不可用";
    $("#mode-stat").textContent = "OFFLINE";
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
  const limit = Math.max(1, Math.min(500, Number($("#batch-limit").value) || 20));
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

checkHealth();