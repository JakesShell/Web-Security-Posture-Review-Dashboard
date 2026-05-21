import assert from "node:assert/strict";
import {
  analyzeDemoTarget,
  buildSecurityReport
} from "../src/scanner.mjs";

const hardened = analyzeDemoTarget("demo:hardened-saas");
assert.equal(hardened.grade, "A");
assert.ok(hardened.score >= 90);
assert.equal(hardened.metrics.criticalCount, 0);

const weak = analyzeDemoTarget("demo:misconfigured-customer-app");
assert.ok(weak.score < 60);
assert.ok(weak.metrics.criticalCount >= 1);
assert.ok(weak.remediationQueue.length >= 5);

const custom = buildSecurityReport({
  target: "unit-test",
  finalUrl: "https://unit-test.example",
  statusCode: 200,
  reachable: true,
  elapsedMs: 10,
  scanMode: "unit-test",
  headers: {
    "content-security-policy": "default-src 'self'",
    "strict-transport-security": "max-age=31536000",
    "x-frame-options": "DENY",
    "x-content-type-options": "nosniff",
    "referrer-policy": "strict-origin-when-cross-origin",
    "permissions-policy": "camera=()",
    "cross-origin-opener-policy": "same-origin",
    "cross-origin-resource-policy": "same-origin",
    "cache-control": "no-store"
  }
});

assert.equal(custom.metrics.headerCoveragePercent, 100);
assert.ok(custom.remediationQueue.length === 0);

console.log("Scanner tests passed.");
