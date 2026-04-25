const state = {
  token: localStorage.getItem("velloraq_token") || localStorage.getItem("slssec_token"),
  user: JSON.parse(localStorage.getItem("velloraq_user") || localStorage.getItem("slssec_user") || "null"),
  selectedScanId: null,
  selectedResult: null,
};

const $ = (id) => document.getElementById(id);

function showToast(message) {
  const toast = $("toast");
  toast.textContent = message;
  toast.classList.remove("hidden");
  setTimeout(() => toast.classList.add("hidden"), 3500);
}

async function api(path, options = {}) {
  const headers = {"Content-Type": "application/json", ...(options.headers || {})};
  if (state.token) headers.Authorization = `Bearer ${state.token}`;
  const response = await fetch(path, {...options, headers});
  const text = await response.text();
  const data = text ? JSON.parse(text) : null;
  if (!response.ok) {
    throw new Error(data?.detail || `HTTP ${response.status}`);
  }
  return data;
}

function setSession(token, user) {
  state.token = token;
  state.user = user;
  localStorage.setItem("velloraq_token", token);
  localStorage.setItem("velloraq_user", JSON.stringify(user));
  localStorage.removeItem("slssec_token");
  localStorage.removeItem("slssec_user");
  renderSession();
}

function clearSession() {
  fetch("/auth/logout", {method: "POST"}).catch(() => {});
  state.token = null;
  state.user = null;
  state.selectedScanId = null;
  state.selectedResult = null;
  localStorage.removeItem("velloraq_token");
  localStorage.removeItem("velloraq_user");
  localStorage.removeItem("slssec_token");
  localStorage.removeItem("slssec_user");
  renderSession();
}

function renderSession() {
  const signedIn = Boolean(state.token);
  $("auth-panel").classList.toggle("hidden", signedIn);
  $("app-panel").classList.toggle("hidden", !signedIn);
  $("logout-button").classList.toggle("hidden", !signedIn);
  $("session-label").textContent = signedIn ? `${state.user.email} (${state.user.role})` : "Signed out";
  if (signedIn) refreshScans();
}

function selectedOptions(select) {
  return Array.from(select.selectedOptions).map((option) => option.value);
}

function csv(id) {
  return $(id).value.split(",").map((item) => item.trim()).filter(Boolean);
}

async function login(event) {
  event.preventDefault();
  const data = await api("/auth/login", {
    method: "POST",
    body: JSON.stringify({
      email: $("login-email").value,
      password: $("login-password").value,
    }),
  });
  setSession(data.access_token, data.user);
  showToast("Logged in");
}

async function register(event) {
  event.preventDefault();
  await api("/auth/register", {
    method: "POST",
    body: JSON.stringify({
      email: $("register-email").value,
      password: $("register-password").value,
    }),
  });
  showToast("Account created. Login is ready.");
}

async function launchScan() {
  const minSeverity = $("scan-min-severity").value || null;
  const payload = {
    providers: selectedOptions($("scan-providers")),
    regions: csv("scan-regions"),
    source_paths: csv("scan-source-paths"),
    dependency_manifests: csv("scan-manifests"),
    disabled_rules: csv("scan-disabled-rules"),
    exclude_resources: csv("scan-exclusions"),
    include_inventory: $("scan-inventory").checked,
  };
  if (minSeverity) payload.min_severity = minSeverity;
  const scan = await api("/scans", {method: "POST", body: JSON.stringify(payload)});
  showToast(`Scan queued: ${scan.id}`);
  await refreshScans();
}

async function refreshScans() {
  if (!state.token) return;
  const scans = await api("/scans?limit=50");
  const list = $("scan-list");
  list.innerHTML = "";
  scans.forEach((scan) => {
    const row = document.createElement("div");
    row.className = "scan-row";
    const scanId = escapeHtml(scan.id);
    const provider = escapeHtml(scan.provider);
    const status = escapeHtml(scan.status);
    const statusClass = cssClass(scan.status);
    const createdAt = escapeHtml(new Date(scan.created_at).toLocaleString());
    const reportButtons = terminalStatus(scan.status)
      ? `<div class="row-actions">
          <button class="link-button" data-action="view-report" data-scan-id="${scanId}" type="button">View HTML Report</button>
          <button class="link-button" data-action="download-report" data-scan-id="${scanId}" type="button">Download HTML Report</button>
        </div>`
      : `<div></div>`;
    row.innerHTML = `
      <div>
        <strong>${scanId}</strong>
        <span>${provider} - ${createdAt}</span>
      </div>
      ${reportButtons}
      <span class="badge ${statusClass}">${status}</span>
    `;
    row.addEventListener("click", (event) => {
      const action = event.target?.dataset?.action;
      const actionScanId = event.target?.dataset?.scanId;
      if (action === "view-report") {
        event.stopPropagation();
        selectScan(actionScanId, scan.status)
          .then(() => viewReport(actionScanId))
          .catch((error) => showToast(error.message));
        return;
      }
      if (action === "download-report") {
        event.stopPropagation();
        downloadReport(actionScanId).catch((error) => showToast(error.message));
        return;
      }
      selectScan(scan.id, scan.status);
    });
    list.appendChild(row);
  });
}

async function selectScan(scanId, status) {
  state.selectedScanId = scanId;
  $("result-actions").classList.add("hidden");
  $("report-preview-panel").classList.add("hidden");
  $("view-findings").classList.add("hidden");
  $("report-frame").removeAttribute("src");
  $("report-status").textContent = "";
  $("summary").innerHTML = `<p class="muted">Selected scan ${escapeHtml(scanId)} is ${escapeHtml(status)}.</p>`;
  $("findings").innerHTML = "";
  if (status !== "succeeded" && status !== "failed") return;
  try {
    const result = await api(`/scans/${scanId}/results`);
    state.selectedResult = result;
    renderResults(scanId, result);
  } catch (error) {
    showToast(error.message);
  }
}

function terminalStatus(status) {
  return status === "succeeded" || status === "failed";
}

function renderResults(scanId, result) {
  const counts = result.summary.by_severity || {};
  $("summary").innerHTML = `
    ${metric("Total", result.summary.total_findings || 0)}
    ${metric("Critical", counts.Critical || 0)}
    ${metric("High", counts.High || 0)}
    ${metric("Medium", counts.Medium || 0)}
    ${metric("Low", counts.Low || 0)}
  `;
  $("result-actions").classList.remove("hidden");
  $("report-preview-panel").classList.add("hidden");
  $("view-findings").classList.add("hidden");
  $("findings").classList.remove("hidden");
  $("report-frame").removeAttribute("src");
  $("findings").innerHTML = "";
  result.findings.forEach((finding) => {
    const item = document.createElement("article");
    const severityLabel = escapeHtml(finding.severity);
    const severityClass = cssClass(finding.severity);
    item.className = `finding ${severityClass}`;
    const evidence = finding.evidence?.length
      ? `<details class="evidence"><summary>Evidence</summary><pre>${escapeHtml(JSON.stringify(finding.evidence, null, 2))}</pre></details>`
      : "";
    item.innerHTML = `
      <h3><span class="severity ${severityClass}">${severityLabel}</span>${escapeHtml(finding.title)}</h3>
      <p class="muted">${escapeHtml(finding.provider)} / ${escapeHtml(finding.service)} / ${escapeHtml(finding.rule_id)}</p>
      <p>${escapeHtml(finding.description)}</p>
      <p><strong>Recommendation:</strong> ${escapeHtml(finding.recommendation)}</p>
      ${evidence}
    `;
    $("findings").appendChild(item);
  });
  if (!result.findings.length) {
    $("findings").innerHTML = `<p class="muted">No findings detected.</p>`;
  }
}

function metric(label, value) {
  return `<div class="metric"><span>${label}</span><strong>${value}</strong></div>`;
}

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

$("login-form").addEventListener("submit", login);
$("register-form").addEventListener("submit", register);
$("logout-button").addEventListener("click", clearSession);
$("launch-scan").addEventListener("click", () => launchScan().catch((error) => showToast(error.message)));
$("refresh-scans").addEventListener("click", () => refreshScans().catch((error) => showToast(error.message)));
$("view-findings").addEventListener("click", () => {
  if (state.selectedResult && state.selectedScanId) {
    renderResults(state.selectedScanId, state.selectedResult);
  }
});
$("view-report").addEventListener("click", () => viewReport(state.selectedScanId).catch((error) => showToast(error.message)));
$("download-report").addEventListener("click", () => downloadReport(state.selectedScanId).catch((error) => showToast(error.message)));
$("view-json").addEventListener("click", () => viewJson(state.selectedScanId).catch((error) => showToast(error.message)));

async function exportResult(format) {
  if (!state.selectedScanId) return;
  const response = await fetch(`/scans/${state.selectedScanId}/export/${format}`, {
    headers: {Authorization: `Bearer ${state.token}`},
  });
  if (!response.ok) throw new Error(`Export failed: HTTP ${response.status}`);
  const blob = await response.blob();
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = `scan-${state.selectedScanId}.${format === "siem" ? "jsonl" : format}`;
  link.click();
  URL.revokeObjectURL(url);
}

async function ensureReportAvailable(scanId) {
  if (!scanId) throw new Error("Select a completed scan first");
  const response = await fetch(`/scans/${scanId}/report/html`, {
    headers: {Authorization: `Bearer ${state.token}`},
  });
  if (response.status === 404) throw new Error("Report not available");
  if (!response.ok) throw new Error(`Report request failed: HTTP ${response.status}`);
  return true;
}

async function viewReport(scanId) {
  await renderReportPreview(scanId);
}

async function viewJson(scanId) {
  if (!scanId) throw new Error("Select a completed scan first");
  const response = await fetch(`/scans/${scanId}/export/json`, {
    headers: {Authorization: `Bearer ${state.token}`},
  });
  if (!response.ok) throw new Error(`JSON report unavailable: HTTP ${response.status}`);
  window.open(`/scans/${scanId}/export/json`, "_blank", "noopener,noreferrer");
}

async function downloadReport(scanId) {
  await ensureReportAvailable(scanId);
  const link = document.createElement("a");
  link.href = `/scans/${scanId}/report/download`;
  link.download = `report_${scanId}.html`;
  link.rel = "noreferrer";
  document.body.appendChild(link);
  link.click();
  link.remove();
}

async function renderReportPreview(scanId) {
  await ensureReportAvailable(scanId);
  $("findings").classList.add("hidden");
  $("report-frame").src = `/scans/${scanId}/report/html`;
  $("report-status").textContent = "Loaded";
  $("view-findings").classList.remove("hidden");
  $("report-preview-panel").classList.remove("hidden");
}

function cssClass(value) {
  return String(value ?? "").replace(/[^a-zA-Z0-9_-]/g, "") || "Unknown";
}

renderSession();
setInterval(() => {
  if (state.token) refreshScans().catch(() => {});
}, 8000);
