export const demoTargets = [
  {
    id: "demo:hardened-saas",
    name: "Hardened SaaS Launch",
    description: "A strong launch-readiness profile with modern browser security controls.",
    url: "https://app.hardened-saas.example",
    statusCode: 200,
    elapsedMs: 148,
    headers: {
      "content-security-policy": "default-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'",
      "strict-transport-security": "max-age=31536000; includeSubDomains; preload",
      "x-frame-options": "DENY",
      "x-content-type-options": "nosniff",
      "referrer-policy": "strict-origin-when-cross-origin",
      "permissions-policy": "camera=(), microphone=(), geolocation=()",
      "cross-origin-opener-policy": "same-origin",
      "cross-origin-resource-policy": "same-origin",
      "cache-control": "no-store",
      "set-cookie": "sessionId=demo; Path=/; Secure; HttpOnly; SameSite=Lax"
    }
  },
  {
    id: "demo:legacy-commerce",
    name: "Legacy Commerce Portal",
    description: "A partially hardened web app with several launch blockers.",
    url: "https://legacy-commerce.example",
    statusCode: 200,
    elapsedMs: 382,
    headers: {
      "strict-transport-security": "max-age=15552000",
      "x-frame-options": "SAMEORIGIN",
      "x-content-type-options": "nosniff",
      "referrer-policy": "strict-origin-when-cross-origin",
      "server": "nginx",
      "set-cookie": "sessionId=abc123; Path=/; HttpOnly"
    }
  },
  {
    id: "demo:misconfigured-customer-app",
    name: "Misconfigured Customer App",
    description: "A high-risk posture used to show triage, escalation, and remediation planning.",
    url: "http://customer-app.example",
    statusCode: 200,
    elapsedMs: 611,
    headers: {
      "server": "Apache",
      "x-powered-by": "PHP/8.1",
      "set-cookie": "authToken=demo-value; Path=/"
    }
  }
];
