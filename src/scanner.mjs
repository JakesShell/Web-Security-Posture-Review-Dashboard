import { randomUUID } from "node:crypto";
import { demoTargets } from "./data/demoTargets.mjs";

const REQUIRED_HEADER_RULES = [
  {
    key: "content-security-policy",
    label: "Content Security Policy",
    weight: 20,
    severity: "Critical",
    category: "Browser Exploit Control",
    remediation: "Deploy a strict CSP that limits script, object, frame, image, and connection sources. Start in report-only mode, review violations, then enforce."
  },
  {
    key: "strict-transport-security",
    label: "HTTP Strict Transport Security",
    weight: 14,
    severity: "High",
    category: "Transport Security",
    remediation: "Enable HSTS with a long max-age, includeSubDomains, and preload once the domain is ready."
  },
  {
    key: "x-frame-options",
    label: "Clickjacking Protection",
    weight: 10,
    severity: "High",
    category: "UI Redress Protection",
    remediation: "Set X-Frame-Options to DENY or SAMEORIGIN. Prefer CSP frame-ancestors for modern control."
  },
  {
    key: "x-content-type-options",
    label: "MIME Sniffing Protection",
    weight: 8,
    severity: "Medium",
    category: "Content Handling",
    remediation: "Set X-Content-Type-Options to nosniff on all web responses."
  },
  {
    key: "referrer-policy",
    label: "Referrer Policy",
    weight: 8,
    severity: "Medium",
    category: "Data Leakage Control",
    remediation: "Use strict-origin-when-cross-origin or a stricter policy to reduce accidental URL data leakage."
  },
  {
    key: "permissions-policy",
    label: "Permissions Policy",
    weight: 8,
    severity: "Medium",
    category: "Browser Capability Control",
    remediation: "Restrict browser features such as camera, microphone, geolocation, payment, and USB to only what the app requires."
  },
  {
    key: "cross-origin-opener-policy",
    label: "Cross-Origin Opener Policy",
    weight: 6,
    severity: "Medium",
    category: "Cross-Origin Isolation",
    remediation: "Set Cross-Origin-Opener-Policy to same-origin where compatible with the application."
  },
  {
    key: "cross-origin-resource-policy",
    label: "Cross-Origin Resource Policy",
    weight: 6,
    severity: "Medium",
    category: "Cross-Origin Isolation",
    remediation: "Set Cross-Origin-Resource-Policy to same-origin or same-site depending on asset sharing requirements."
  },
  {
    key: "cache-control",
    label: "Sensitive Cache Control",
    weight: 5,
    severity: "Low",
    category: "Data Handling",
    remediation: "Use no-store or private cache controls for authenticated or sensitive responses."
  }
];

const EXPOSURE_RULES = [
  {
    key: "server",
    label: "Server Version Exposure",
    penalty: 5,
    severity: "Low",
    remediation: "Hide or minimize the Server header at the reverse proxy, CDN, or application gateway layer."
  },
  {
    key: "x-powered-by",
    label: "Framework Exposure",
    penalty: 8,
    severity: "Medium",
    remediation: "Remove X-Powered-By so the application does not advertise its framework or runtime."
  }
];

const severityRank = {
  Critical: 4,
  High: 3,
  Medium: 2,
  Low: 1,
  Info: 0
};

function clampScore(value) {
  return Math.max(0, Math.min(100, Math.round(value)));
}

function safePreview(value) {
  if (!value) {
    return "";
  }

  const text = String(value).replace(/\s+/g, " ").trim();
  return text.length > 140 ? `${text.slice(0, 140)}...` : text;
}

function normalizeHeaders(headers = {}) {
  const normalized = {};

  for (const [key, value] of Object.entries(headers)) {
    normalized[String(key).toLowerCase()] = Array.isArray(value)
      ? value.join("; ")
      : String(value);
  }

  return normalized;
}

function getGrade(score) {
  if (score >= 90) return "A";
  if (score >= 80) return "B";
  if (score >= 70) return "C";
  if (score >= 60) return "D";
  return "F";
}

function buildExecutiveSummary({ grade, score, criticalCount, highCount, reachable }) {
  if (!reachable) {
    return "Target could not be reached safely. Treat this as an availability and validation issue before launch review.";
  }

  if (grade === "A") {
    return "Strong posture. The target is close to launch-ready from a browser security header perspective.";
  }

  if (criticalCount > 0 || highCount > 1) {
    return `High-priority remediation required. Current score is ${score}, with launch-blocking browser security gaps.`;
  }

  return `Moderate posture. Current score is ${score}, with several improvements recommended before production release.`;
}

function summarizeRemediation(queue) {
  if (queue.length === 0) {
    return "No urgent remediation items detected in this scan.";
  }

  const critical = queue.filter((item) => item.severity === "Critical").length;
  const high = queue.filter((item) => item.severity === "High").length;

  if (critical > 0) {
    return `${critical} critical item(s) should be fixed before public launch.`;
  }

  if (high > 0) {
    return `${high} high-priority item(s) should be scheduled in the next hardening sprint.`;
  }

  return "Remaining items are mostly medium or low risk hardening tasks.";
}

function evaluateCookies(headers, remediationQueue, findings) {
  const cookieHeader = headers["set-cookie"];

  if (!cookieHeader) {
    findings.push({
      label: "Cookie Attribute Review",
      key: "set-cookie",
      status: "not-observed",
      severity: "Info",
      category: "Session Security",
      details: "No Set-Cookie header was observed in the scanned response.",
      remediation: "Review authenticated paths separately to confirm Secure, HttpOnly, and SameSite are enforced."
    });

    return 0;
  }

  let penalty = 0;
  const lowerCookie = cookieHeader.toLowerCase();
  const missing = [];

  if (!lowerCookie.includes("secure")) {
    missing.push("Secure");
    penalty += 5;
  }

  if (!lowerCookie.includes("httponly")) {
    missing.push("HttpOnly");
    penalty += 5;
  }

  if (!lowerCookie.includes("samesite")) {
    missing.push("SameSite");
    penalty += 4;
  }

  if (missing.length > 0) {
    const item = {
      label: "Weak Cookie Attributes",
      key: "set-cookie",
      status: "warning",
      severity: "High",
      category: "Session Security",
      details: `Observed Set-Cookie header is missing: ${missing.join(", ")}.`,
      remediation: "Set Secure, HttpOnly, and SameSite attributes on session cookies. Re-test authenticated paths after deployment."
    };

    findings.push(item);
    remediationQueue.push({
      title: item.label,
      severity: item.severity,
      impact: penalty,
      owner: "Application Security / Backend",
      action: item.remediation
    });
  } else {
    findings.push({
      label: "Cookie Attribute Review",
      key: "set-cookie",
      status: "pass",
      severity: "Info",
      category: "Session Security",
      details: "Observed cookie attributes include Secure, HttpOnly, and SameSite.",
      remediation: "Continue validating authenticated routes during release checks."
    });
  }

  return penalty;
}

export function buildSecurityReport({
  target,
  finalUrl,
  statusCode,
  headers,
  reachable,
  error,
  elapsedMs,
  scanMode
}) {
  const normalizedHeaders = normalizeHeaders(headers);
  const findings = [];
  const remediationQueue = [];
  let score = reachable ? 100 : 28;

  const urlProtocol = finalUrl?.startsWith("https://") ? "https" : "http-or-unknown";

  if (urlProtocol !== "https") {
    score -= 18;
    remediationQueue.push({
      title: "HTTPS Enforcement",
      severity: "Critical",
      impact: 18,
      owner: "Cloud Platform / CDN",
      action: "Force HTTPS at the load balancer, CDN, application gateway, or reverse proxy layer."
    });
  }

  let passedRequired = 0;

  for (const rule of REQUIRED_HEADER_RULES) {
    const value = normalizedHeaders[rule.key];

    if (value) {
      passedRequired += 1;
      findings.push({
        label: rule.label,
        key: rule.key,
        status: "pass",
        severity: "Info",
        category: rule.category,
        details: `Detected: ${safePreview(value)}`,
        remediation: "No immediate action required. Keep this control in infrastructure-as-code checks."
      });
    } else {
      score -= rule.weight;

      const finding = {
        label: rule.label,
        key: rule.key,
        status: "fail",
        severity: rule.severity,
        category: rule.category,
        details: "Header is missing from the scanned response.",
        remediation: rule.remediation
      };

      findings.push(finding);
      remediationQueue.push({
        title: rule.label,
        severity: rule.severity,
        impact: rule.weight,
        owner: rule.severity === "Critical" ? "Security Engineering" : "Cloud Support / App Team",
        action: rule.remediation
      });
    }
  }

  for (const rule of EXPOSURE_RULES) {
    const value = normalizedHeaders[rule.key];

    if (value) {
      score -= rule.penalty;

      const finding = {
        label: rule.label,
        key: rule.key,
        status: "warning",
        severity: rule.severity,
        category: "Information Disclosure",
        details: `Observed: ${safePreview(value)}`,
        remediation: rule.remediation
      };

      findings.push(finding);
      remediationQueue.push({
        title: rule.label,
        severity: rule.severity,
        impact: rule.penalty,
        owner: "Platform / DevOps",
        action: rule.remediation
      });
    }
  }

  score -= evaluateCookies(normalizedHeaders, remediationQueue, findings);

  score = clampScore(score);
  const grade = getGrade(score);

  remediationQueue.sort((a, b) => {
    const severityDifference = severityRank[b.severity] - severityRank[a.severity];
    return severityDifference || b.impact - a.impact;
  });

  const criticalCount = remediationQueue.filter((item) => item.severity === "Critical").length;
  const highCount = remediationQueue.filter((item) => item.severity === "High").length;
  const mediumCount = remediationQueue.filter((item) => item.severity === "Medium").length;
  const lowCount = remediationQueue.filter((item) => item.severity === "Low").length;

  return {
    id: randomUUID(),
    target,
    finalUrl,
    scanMode,
    reachable,
    statusCode,
    elapsedMs,
    scannedAt: new Date().toISOString(),
    score,
    grade,
    error: error || null,
    executiveSummary: buildExecutiveSummary({
      grade,
      score,
      criticalCount,
      highCount,
      reachable
    }),
    remediationSummary: summarizeRemediation(remediationQueue),
    metrics: {
      requiredHeaders: REQUIRED_HEADER_RULES.length,
      passedRequiredHeaders: passedRequired,
      headerCoveragePercent: Math.round((passedRequired / REQUIRED_HEADER_RULES.length) * 100),
      remediationItems: remediationQueue.length,
      criticalCount,
      highCount,
      mediumCount,
      lowCount
    },
    cloudOperations: [
      {
        area: "CDN / Edge",
        recommendation: "Enforce HTTPS, HSTS, and baseline response headers at the edge where possible."
      },
      {
        area: "Infrastructure as Code",
        recommendation: "Convert accepted header policy into reusable IaC checks for launch readiness."
      },
      {
        area: "Incident Readiness",
        recommendation: "Escalate Critical and High findings before public release or customer migration."
      },
      {
        area: "Support Workflow",
        recommendation: "Attach this report to the remediation ticket and retest after each fix."
      }
    ],
    findings,
    remediationQueue,
    evidence: {
      observedHeaders: normalizedHeaders,
      assessedRules: REQUIRED_HEADER_RULES.map((rule) => ({
        key: rule.key,
        label: rule.label,
        severity: rule.severity,
        weight: rule.weight
      }))
    }
  };
}

function normalizeUrl(rawTarget) {
  const target = rawTarget.trim();

  if (!/^https?:\/\//i.test(target)) {
    return `https://${target}`;
  }

  return target;
}

function isBlockedHost(hostname) {
  const host = hostname.toLowerCase();

  if (
    host === "localhost" ||
    host === "127.0.0.1" ||
    host === "::1" ||
    host.startsWith("10.") ||
    host.startsWith("192.168.")
  ) {
    return true;
  }

  const parts = host.split(".").map(Number);

  if (parts.length === 4 && parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) {
    return true;
  }

  return false;
}

export async function scanTarget(rawTarget) {
  const startedAt = Date.now();
  const normalizedTarget = normalizeUrl(rawTarget);
  const parsedUrl = new URL(normalizedTarget);

  if (!["http:", "https:"].includes(parsedUrl.protocol)) {
    throw new Error("Only HTTP and HTTPS targets are supported.");
  }

  if (isBlockedHost(parsedUrl.hostname)) {
    return buildSecurityReport({
      target: rawTarget,
      finalUrl: normalizedTarget,
      statusCode: 0,
      headers: {},
      reachable: false,
      error: "Local and private network targets are blocked to reduce SSRF risk in this portfolio scanner.",
      elapsedMs: Date.now() - startedAt,
      scanMode: "safe-network-scan"
    });
  }

  const timeoutMs = Number(process.env.SCAN_TIMEOUT_MS || 8500);
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const response = await fetch(normalizedTarget, {
      method: "GET",
      redirect: "follow",
      signal: controller.signal,
      headers: {
        "User-Agent": "AegisLens-Portfolio-Scanner/2.0"
      }
    });

    const headers = Object.fromEntries(response.headers.entries());

    return buildSecurityReport({
      target: rawTarget,
      finalUrl: response.url,
      statusCode: response.status,
      headers,
      reachable: true,
      elapsedMs: Date.now() - startedAt,
      scanMode: "safe-network-scan"
    });
  } catch (error) {
    return buildSecurityReport({
      target: rawTarget,
      finalUrl: normalizedTarget,
      statusCode: 0,
      headers: {},
      reachable: false,
      error: error.name === "AbortError" ? "Scan timed out." : error.message,
      elapsedMs: Date.now() - startedAt,
      scanMode: "safe-network-scan"
    });
  } finally {
    clearTimeout(timeout);
  }
}

export function analyzeDemoTarget(targetId) {
  const demo = demoTargets.find((item) => item.id === targetId);

  if (!demo) {
    throw new Error("Demo target not found.");
  }

  return buildSecurityReport({
    target: demo.name,
    finalUrl: demo.url,
    statusCode: demo.statusCode,
    headers: demo.headers,
    reachable: true,
    elapsedMs: demo.elapsedMs,
    scanMode: "demo-fixture"
  });
}

export function listDemoTargets() {
  return demoTargets.map((target) => ({
    id: target.id,
    name: target.name,
    description: target.description,
    url: target.url
  }));
}
