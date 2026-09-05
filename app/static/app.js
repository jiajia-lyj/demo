const $ = (selector) => document.querySelector(selector);

async function request(url, options = {}) {
  const response = await fetch(url, options);
  const data = await response.json();
  if (!response.ok) throw new Error(data.detail?.message || data.detail || `请求失败 (${response.status})`);
  return data;
}

function showError(target, error) {
  target.textContent = `错误：${error.message}`;
  target.style.color = "#e2614d";
}

async function checkHealth() {
  try {
    const data = await request("/health");
    $("#system-status").textContent = data.llm === "enabled" ? "LLM 已连接" : "本地模式运行";
    $(".status-dot").classList.add("ready");
  } catch (error) {
    $("#system-status").textContent = "服务不可用";
  }
}

$("#dataset-file").addEventListener("change", (event) => {
  $("#file-name").textContent = event.target.files[0]?.name || "选择数据集文件";
});

$("#import-button").addEventListener("click", async () => {
  const file = $("#dataset-file").files[0];
  const output = $("#import-result");
  if (!file) { output.textContent = "请先选择 JSON 或 CSV 文件"; output.style.color = "#e2614d"; return; }
  const form = new FormData(); form.append("file", file);
  output.textContent = "正在导入..."; output.style.color = "#087f76";
  try { const data = await request("/api/v1/cve/import", { method: "POST", body: form }); output.textContent = `已导入 ${data.imported} 条，跳过 ${data.skipped} 条`; } catch (error) { showError(output, error); }
});

$("#score-button").addEventListener("click", async () => {
  const id = $("#cve-id").value.trim().toUpperCase(); const output = $("#score-result");
  if (!id) { output.textContent = "请输入 CVE ID"; return; }
  output.className = "result-card"; output.textContent = "分析中...";
  try {
    const data = await request(`/api/v1/score/${encodeURIComponent(id)}?use_llm=${$("#use-llm").checked}`, { method: "POST" });
    output.innerHTML = `<div class="score-line"><span class="score-number">${data.cvss_base_score}</span><span class="severity">${data.severity}</span></div><div class="vector">${data.cvss_vector}</div>`;
    $("#lookup-id").value = id;
  } catch (error) { showError(output, error); }
});

$("#lookup-button").addEventListener("click", async () => {
  const id = $("#lookup-id").value.trim().toUpperCase(); const output = $("#lookup-result");
  try { output.textContent = JSON.stringify(await request(`/api/v1/cve/${encodeURIComponent(id)}`), null, 2); } catch (error) { showError(output, error); }
});

$("#compare-button").addEventListener("click", async () => {
  const id = $("#lookup-id").value.trim().toUpperCase(); const output = $("#compare-result");
  try { const data = await request(`/api/v1/score/${encodeURIComponent(id)}/compare`); output.innerHTML = `模型评分 <strong>${data.llm_score ?? "-"}</strong><br>官方评分 ${data.official_score ?? "暂无"}<br>差异 ${data.difference ?? "暂无"}`; } catch (error) { showError(output, error); }
});

checkHealth();
