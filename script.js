const overviewItems = [
    { title: "Review Type", text: "Web Application Security Review" },
    { title: "Target Scope", text: "Customer-Facing Application" },
    { title: "Review Status", text: "Findings Identified And Prioritized" },
    { title: "Primary Goal", text: "Reduce Exposure And Improve Security Posture" }
];

const headerFindings = [
    { title: "Content-Security-Policy", text: "Missing from reviewed application response set.", status: "Missing" },
    { title: "Strict-Transport-Security", text: "Present and supports secure transport requirements.", status: "Present" },
    { title: "X-Frame-Options", text: "Present and configured to reduce framing risk.", status: "Present" },
    { title: "X-Content-Type-Options", text: "Missing and should be added to reduce MIME confusion risk.", status: "Missing" },
    { title: "Referrer-Policy", text: "Present with controlled referrer behavior.", status: "Present" }
];

const dependencyFindings = [
    { title: "jQuery Dependency Review", text: "Legacy version flagged for upgrade review due to age and potential exposure." },
    { title: "Third-Party UI Package", text: "Moderate review item due to patch lag and inconsistent update cadence." },
    { title: "Build Library Baseline", text: "No immediate critical concern, but lifecycle monitoring should continue." }
];

const remediationFindings = [
    {
        title: "Add Content-Security-Policy Header",
        severity: "High",
        owner: "Application Security",
        dueDate: "2026-05-08",
        text: "Define and enforce a baseline CSP policy for production responses."
    },
    {
        title: "Add X-Content-Type-Options",
        severity: "Medium",
        owner: "Platform Engineering",
        dueDate: "2026-05-05",
        text: "Set nosniff header across reviewed application endpoints."
    },
    {
        title: "Upgrade Legacy jQuery Reference",
        severity: "High",
        owner: "Frontend Team",
        dueDate: "2026-05-12",
        text: "Replace or patch legacy dependency to reduce client-side exposure risk."
    },
    {
        title: "Document Secure Header Standard",
        severity: "Low",
        owner: "Security Governance",
        dueDate: "2026-05-15",
        text: "Create internal review baseline for required response headers."
    },
    {
        title: "Review Third-Party UI Package Versioning",
        severity: "Medium",
        owner: "Engineering Lead",
        dueDate: "2026-05-10",
        text: "Validate patch currency and long-term support viability."
    },
    {
        title: "Re-Run Validation Review After Fixes",
        severity: "Critical",
        owner: "Security Review Team",
        dueDate: "2026-05-18",
        text: "Confirm remediation is complete and evidence is ready for stakeholder review."
    }
];

function scrollToSection(id) {
    document.getElementById(id).scrollIntoView({ behavior: "smooth" });
}

function renderOverview() {
    const container = document.getElementById("summaryGrid");
    container.innerHTML = overviewItems.map(item => `
        <article class="summary-card">
            <h3>${item.title}</h3>
            <p>${item.text}</p>
        </article>
    `).join("");
}

function renderCards(containerId, items, renderer) {
    const container = document.getElementById(containerId);
    container.innerHTML = items.map(renderer).join("");
}

function updateMetrics() {
    document.getElementById("criticalCount").textContent = remediationFindings.filter(item => item.severity === "Critical").length;
    document.getElementById("highCount").textContent = remediationFindings.filter(item => item.severity === "High").length;
    document.getElementById("mediumCount").textContent = remediationFindings.filter(item => item.severity === "Medium").length;
    document.getElementById("lowCount").textContent = remediationFindings.filter(item => item.severity === "Low").length;
}

function renderRemediationQueue() {
    const selectedSeverity = document.getElementById("severityFilter").value;
    const visibleItems = selectedSeverity === "All"
        ? remediationFindings
        : remediationFindings.filter(item => item.severity === selectedSeverity);

    const container = document.getElementById("findingGrid");

    if (visibleItems.length === 0) {
        container.innerHTML = `<p class="empty-state">No findings match the current severity filter.</p>`;
        return;
    }

    container.innerHTML = visibleItems.map(item => `
        <article class="card">
            <h3>${item.title}</h3>
            <p>${item.text}</p>
            <p><strong>Owner:</strong> ${item.owner}</p>
            <p><strong>Due Date:</strong> ${item.dueDate}</p>
            <span class="severity-tag severity-${item.severity}">${item.severity}</span>
        </article>
    `).join("");
}

document.addEventListener("DOMContentLoaded", () => {
    renderOverview();
    updateMetrics();

    renderCards("headerGrid", headerFindings, item => `
        <article class="card">
            <h3>${item.title}</h3>
            <p>${item.text}</p>
            <span class="status-tag status-${item.status}">${item.status}</span>
        </article>
    `);

    renderCards("dependencyGrid", dependencyFindings, item => `
        <article class="card">
            <h3>${item.title}</h3>
            <p>${item.text}</p>
        </article>
    `);

    renderRemediationQueue();

    document.getElementById("severityFilter").addEventListener("change", renderRemediationQueue);
});
