const sample = {
  targetIp: "192.168.3.73",
  alert: {
    alert_id: "LAB-WAF-001",
    type: "SQL Injection Attempt",
    source_ip: "192.168.3.73",
    payload: "c3lz.R2V0U2hlbGwoKQ==",
    target_url: "/login.php?user=admin%27%20OR%201=1--",
    http_status: 200
  },
  log: "192.168.3.73 - - [29/Jul/2026:12:00:00 +0800] \"GET /login.php?user=admin%27%20OR%201=1-- HTTP/1.1\" 200 2326"
};

const elements = {
  form: document.querySelector("#agentForm"),
  targetIp: document.querySelector("#targetIp"),
  alertJson: document.querySelector("#alertJson"),
  logLine: document.querySelector("#logLine"),
  useLlm: document.querySelector("#useLlm"),
  externalLookup: document.querySelector("#externalLookup"),
  runButton: document.querySelector("#runButton"),
  loadSample: document.querySelector("#loadSample"),
  formError: document.querySelector("#formError"),
  systemStatus: document.querySelector("#systemStatus"),
  modelBadge: document.querySelector("#modelBadge"),
  statusDot: document.querySelector(".status-dot"),
  heroState: document.querySelector("#heroState"),
  workflowId: document.querySelector("#workflowId"),
  workflowSteps: [...document.querySelectorAll("#workflow li")],
  riskScore: document.querySelector("#riskScore"),
  severityText: document.querySelector("#severityText"),
  iocCount: document.querySelector("#iocCount"),
  serviceCount: document.querySelector("#serviceCount"),
  vulnCount: document.querySelector("#vulnCount"),
  actionBadge: document.querySelector("#actionBadge"),
  summaryText: document.querySelector("#summaryText"),
  findingGrid: document.querySelector("#findingGrid"),
  traceOutput: document.querySelector("#traceOutput"),
  copyReport: document.querySelector("#copyReport")
};

let latestReport = null;

function loadSample() {
  elements.targetIp.value = sample.targetIp;
  elements.alertJson.value = JSON.stringify(sample.alert, null, 2);
  elements.logLine.value = sample.log;
}

async function checkHealth() {
  try {
    const response = await fetch("/api/health");
    const health = await response.json();
    elements.statusDot.classList.add("online");
    elements.systemStatus.textContent = "Agent 在线";
    elements.modelBadge.textContent = health.llm_enabled ? health.model : "RULES ONLY";
  } catch {
    elements.systemStatus.textContent = "Agent 离线";
    elements.modelBadge.textContent = "OFFLINE";
  }
}

function resetWorkflow() {
  elements.workflowSteps.forEach((step) => {
    step.classList.remove("running", "completed");
    step.querySelector(".step-state").textContent = "等待";
  });
}

function setStage(stage, status) {
  const step = elements.workflowSteps.find((item) => item.dataset.stage === stage);
  if (!step) return;
  step.classList.remove("running", "completed");
  step.classList.add(status);
  step.querySelector(".step-state").textContent = status === "completed" ? "完成" : "执行中";
}

function animatePendingStages() {
  resetWorkflow();
  const stages = ["ingest", "analysis", "triage", "investigation", "assessment", "report"];
  let index = 0;
  setStage(stages[index], "running");
  return window.setInterval(() => {
    setStage(stages[index], "completed");
    index += 1;
    if (index < stages.length) setStage(stages[index], "running");
  }, 650);
}

function renderReport(report) {
  latestReport = report;
  elements.workflowSteps.forEach((step) => setStage(step.dataset.stage, "completed"));
  elements.workflowId.textContent = report.workflow_id;
  elements.riskScore.textContent = String(report.risk_score).padStart(2, "0");
  elements.severityText.textContent = `${report.severity} severity`;
  elements.iocCount.textContent = report.triage?.extracted_iocs?.length ?? 0;
  elements.serviceCount.textContent = report.scan?.services?.length ?? 0;
  elements.vulnCount.textContent = report.vulnerabilities?.length ?? 0;
  elements.actionBadge.textContent = report.recommended_action || "Review";
  elements.summaryText.textContent = report.summary;
  elements.heroState.textContent = "分析完成";

  const decoded = report.investigation?.payload_decoding?.decoded || "未解码出有效载荷";
  const services = report.scan?.services?.map((item) => `${item.port}/${item.service} ${item.version}`).join(" · ") || "未发现预置服务";
  const vulnerabilities = report.vulnerabilities?.map((item) => item.cve).join(", ") || "未匹配已知漏洞";
  elements.findingGrid.innerHTML = [
    ["ATTACK SIGNAL", report.log_analysis?.attack_type || report.triage?.severity || "Unknown"],
    ["DECODED PAYLOAD", decoded],
    ["EXPOSED SERVICES", services],
    ["VULNERABILITY", vulnerabilities],
    ["ANALYSIS ENGINE", `${report.log_analysis?.engine || "n/a"} / ${report.triage?.engine || "n/a"}`],
    ["SCAN MODE", report.scan?.mode || "not requested"]
  ].map(([label, value]) => `<div class="finding"><span>${escapeHtml(label)}</span><strong>${escapeHtml(String(value))}</strong></div>`).join("");

  const trace = report.events.map((event) => `[${event.timestamp}] ${event.stage.toUpperCase()} :: ${event.detail}`).join("\n");
  elements.traceOutput.textContent = `${trace}\n\n${JSON.stringify(report, null, 2)}`;
}

function escapeHtml(value) {
  return value.replace(/[&<>'"]/g, (char) => ({"&": "&amp;", "<": "&lt;", ">": "&gt;", "'": "&#39;", '"': "&quot;"}[char]));
}

elements.form.addEventListener("submit", async (event) => {
  event.preventDefault();
  elements.formError.textContent = "";
  let alert;
  try {
    alert = JSON.parse(elements.alertJson.value);
  } catch {
    elements.formError.textContent = "告警 JSON 格式不正确，请检查后重试。";
    elements.alertJson.focus();
    return;
  }

  elements.runButton.disabled = true;
  elements.runButton.querySelector("span").textContent = "Agent 正在分析...";
  elements.heroState.textContent = "执行中";
  elements.workflowId.textContent = "RUNNING";
  elements.traceOutput.textContent = "$ workflow started\n$ agents are processing the security event...";
  const timer = animatePendingStages();

  try {
    const response = await fetch("/api/run", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({
        target_ip: elements.targetIp.value.trim(),
        alert,
        log_line: elements.logLine.value.trim(),
        use_llm: elements.useLlm.checked,
        allow_external_lookup: elements.externalLookup.checked
      })
    });
    const report = await response.json();
    if (!response.ok) throw new Error(report.error || "请求失败");
    renderReport(report);
  } catch (error) {
    resetWorkflow();
    elements.heroState.textContent = "执行失败";
    elements.formError.textContent = error.message;
    elements.traceOutput.textContent = `$ error: ${error.message}`;
  } finally {
    window.clearInterval(timer);
    elements.runButton.disabled = false;
    elements.runButton.querySelector("span").textContent = "启动安全工作流";
  }
});

elements.loadSample.addEventListener("click", loadSample);
elements.copyReport.addEventListener("click", async () => {
  if (!latestReport) return;
  await navigator.clipboard.writeText(JSON.stringify(latestReport, null, 2));
  elements.copyReport.title = "已复制";
  window.setTimeout(() => { elements.copyReport.title = "复制 JSON 报告"; }, 1200);
});

loadSample();
checkHealth();
