import express from "express";
import cors from "cors";
import helmet from "helmet";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  scanTarget,
  analyzeDemoTarget,
  listDemoTargets
} from "./src/scanner.mjs";

const app = express();
const PORT = process.env.PORT || 8080;

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const publicDirectory = path.join(__dirname, "public");

const scanHistory = [];

app.use(helmet({
  contentSecurityPolicy: false
}));

app.use(cors());
app.use(express.json({ limit: "1mb" }));
app.use(express.static(publicDirectory));

app.get("/api/health", (request, response) => {
  response.json({
    status: "healthy",
    service: "AegisLens Web Security Posture Console",
    version: "2.0.0",
    timestamp: new Date().toISOString()
  });
});

app.get("/api/demo-targets", (request, response) => {
  response.json({
    targets: listDemoTargets()
  });
});

app.get("/api/history", (request, response) => {
  response.json({
    count: scanHistory.length,
    scans: scanHistory
  });
});

app.post("/api/scan", async (request, response) => {
  try {
    const target = String(request.body?.target || "").trim();

    if (!target) {
      return response.status(400).json({
        error: "A target URL or demo target is required."
      });
    }

    let report;

    if (target.startsWith("demo:")) {
      report = analyzeDemoTarget(target);
    } else {
      report = await scanTarget(target);
    }

    scanHistory.unshift({
      id: report.id,
      target: report.target,
      grade: report.grade,
      score: report.score,
      statusCode: report.statusCode,
      reachable: report.reachable,
      scannedAt: report.scannedAt,
      summary: report.executiveSummary
    });

    if (scanHistory.length > 20) {
      scanHistory.pop();
    }

    response.json(report);
  } catch (error) {
    response.status(500).json({
      error: "Scan failed unexpectedly.",
      details: error.message
    });
  }
});

app.get("/api/report/:id", (request, response) => {
  const report = scanHistory.find((item) => item.id === request.params.id);

  if (!report) {
    return response.status(404).json({
      error: "Report not found in current runtime history."
    });
  }

  response.json(report);
});

app.use((request, response) => {
  response.sendFile(path.join(publicDirectory, "index.html"));
});

app.listen(PORT, () => {
  console.log(`AegisLens running at http://localhost:${PORT}`);
});

