const state = {
  currentReport: null,
  demoTargets: []
};

const elements = {
  form: document.querySelector("#scan-form"),
  input: document.querySelector("#target-input"),
  presetButtons: document.querySelector("#preset-buttons"),
  scoreGrade: document.querySelector("#score-grade"),
  scoreValue: document.querySelector("#score-value"),
  scoreSummary: document.querySelector("#score-summary"),
  metricCoverage: document.querySelector("#metric-coverage"),
  metricRemediation: document.querySelector("#metric-remediation"),
  metricPriority: document.querySelector("#metric-priority"),
  metricLatency: document.querySelector("#metric-latency"),
  scanMode: document.querySelector("#scan-mode"),
  findingsList: document.querySelector("#findings-list"),
  remediationList: document.querySelector("#remediation-list"),
  cloudList: document.querySelector("#cloud-list"),
  historyList: document.querySelector("#history-list"),
  refreshHistory: document.querySelector("#refresh-history"),
  copyReport: document.querySelector("#copy-report")
};

function severityClass(severity) {
  return `severity-${String(severity || "Info").toLowerCase()}`;
}

function statusClass(status) {
  return `status-${String(status || "info").toLowerCase()}`;
}

function setLoading(isLoading) {
  const button = elements.form.querySelector("button");

  if (isLoading) {
    button.disabled = true;
    button.textContent = "Scanning...";
  } else {
    button.disabled = false;
    button.textContent = "Run Posture Scan";
  }
}

async function loadDemoTargets() {
  const response = await fetch("/api/demo-targets");
  const data = await response.json();
  state.demoTargets = data.targets || [];

  elements.presetButtons.innerHTML = state.demoTargets.map((target) => `
    <button class="preset-button" type="button" data-target="${target.id}">
      <strong>${target.name}</strong>
      <span>${target.description}</span>
    </button>
  `).join("");

  document.querySelectorAll(".preset-button").forEach((button) => {
    button.addEventListener("click", () => {
      elements.input.value = button.dataset.target;
      runScan(button.dataset.target);
    });
  });
}

async function runScan(target) {
  setLoading(true);

  try {
    const response = await fetch("/api/scan", {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({ target })
    });

    const report = await response.json();

    if (!response.ok) {
      throw new Error(report.error || "Scan failed.");
    }

    state.currentReport = report;
    renderReport(report);
    loadHistory();
  } catch (error) {
    renderError(error.message);
  } finally {
    setLoading(false);
  }
}

function renderError(message) {
  elements.scoreGrade.textContent = "!";
  elements.scoreValue.textContent = "Scan failed";
  elements.scoreSummary.textContent = message;
  elements.findingsList.className = "findings-list empty-state";
  elements.findingsList.textContent = message;
}

function renderReport(report) {
  elements.scoreGrade.textContent = report.grade;
  elements.scoreValue.textContent = `${report.score}/100`;
  elements.scoreSummary.textContent = report.executiveSummary;

  elements.metricCoverage.textContent = `${report.metrics.headerCoveragePercent}%`;
  elements.metricRemediation.textContent = report.metrics.remediationItems;
  elements.metricPriority.textContent = `${report.metrics.criticalCount}/${report.metrics.highCount}`;
  elements.metricLatency.textContent = `${report.elapsedMs} ms`;

  elements.scanMode.textContent = report.scanMode === "demo-fixture"
    ? "Demo fixture"
    : "Safe network scan";

  renderFindings(report.findings);
  renderRemediation(report.remediationQueue, report.remediationSummary);
  renderCloudRecommendations(report.cloudOperations);
}

function renderFindings(findings) {
  elements.findingsList.className = "findings-list";
  elements.findingsList.innerHTML = findings.map((finding) => `
    <article class="finding-card ${statusClass(finding.status)}">
      <div class="finding-topline">
        <div>
          <h3>${finding.label}</h3>
          <p>${finding.key}</p>
        </div>
        <span class="pill ${severityClass(finding.severity)}">${finding.severity}</span>
      </div>
      <p class="finding-detail">${finding.details}</p>
      <p class="finding-action">${finding.remediation}</p>
    </article>
  `).join("");
}

function renderRemediation(queue, summary) {
  if (!queue.length) {
    elements.remediationList.className = "remediation-list empty-state";
    elements.remediationList.textContent = summary;
    return;
  }

  elements.remediationList.className = "remediation-list";
  elements.remediationList.innerHTML = `
    <p class="queue-summary">${summary}</p>
    ${queue.map((item, index) => `
      <article class="queue-item">
        <div class="queue-index">${index + 1}</div>
        <div>
          <div class="queue-title">
            <strong>${item.title}</strong>
            <span class="pill ${severityClass(item.severity)}">${item.severity}</span>
          </div>
          <p>${item.action}</p>
          <small>Owner: ${item.owner} · Impact weight: ${item.impact}</small>
        </div>
      </article>
    `).join("")}
  `;
}

function renderCloudRecommendations(items) {
  elements.cloudList.className = "cloud-list";
  elements.cloudList.innerHTML = items.map((item) => `
    <article class="cloud-item">
      <strong>${item.area}</strong>
      <p>${item.recommendation}</p>
    </article>
  `).join("");
}

async function loadHistory() {
  const response = await fetch("/api/history");
  const data = await response.json();

  if (!data.scans || data.scans.length === 0) {
    elements.historyList.className = "history-list empty-state";
    elements.historyList.textContent = "No scans have been run in this server session yet.";
    return;
  }

  elements.historyList.className = "history-list";
  elements.historyList.innerHTML = data.scans.map((scan) => `
    <article class="history-item">
      <div>
        <strong>${scan.target}</strong>
        <p>${scan.summary}</p>
      </div>
      <span class="history-score">${scan.grade} · ${scan.score}</span>
    </article>
  `).join("");
}

async function copyReport() {
  if (!state.currentReport) {
    elements.copyReport.textContent = "Run a scan first";
    setTimeout(() => {
      elements.copyReport.textContent = "Copy Current JSON Report";
    }, 1500);
    return;
  }

  await navigator.clipboard.writeText(JSON.stringify(state.currentReport, null, 2));
  elements.copyReport.textContent = "Copied";
  setTimeout(() => {
    elements.copyReport.textContent = "Copy Current JSON Report";
  }, 1500);
}

elements.form.addEventListener("submit", (event) => {
  event.preventDefault();
  runScan(elements.input.value.trim());
});

elements.refreshHistory.addEventListener("click", loadHistory);
elements.copyReport.addEventListener("click", copyReport);

loadDemoTargets()
  .then(() => runScan("demo:hardened-saas"))
  .then(loadHistory)
  .catch((error) => renderError(error.message));

