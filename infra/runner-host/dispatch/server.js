"use strict";

// Hacker Bob dispatch service HTTP wiring. Runs on the runner host under
// systemd (EnvironmentFile=/etc/bob-dispatch/env). Exposes POST /dispatch
// (the www handoff) and GET /health (the ALB target-group check).

const http = require("http");

const {
  createService,
} = require("./service.js");

const PORT = Number(process.env.DISPATCH_PORT || 8080);
const MAX_BODY_BYTES = 1024 * 1024;

const service = createService({
  secret: process.env.DISPATCH_SECRET || "",
  ledgerDir: process.env.LEDGER_DIR || "/var/lib/bob-dispatch/ledger",
  runsDir: process.env.RUNS_DIR || "/var/lib/bob-dispatch/runs",
  logsDir: process.env.LOGS_DIR || "/var/lib/bob-dispatch/logs",
  runnerImageUri: process.env.RUNNER_IMAGE_URI || "",
  containerEnv: {
    RUNNER_SECRET: process.env.RUNNER_SECRET,
    REPORTS_SECRET: process.env.REPORTS_SECRET,
    DEEPSEEK_API_KEY: process.env.DEEPSEEK_API_KEY,
    BOB_PROJECTION_URL: process.env.BOB_PROJECTION_URL,
    BOB_CONVEX_URL: process.env.BOB_CONVEX_URL,
  },
  maxConcurrent: Number(process.env.MAX_CONCURRENT_RUNS || 2),
  runTimeoutMs: Number(process.env.RUN_TIMEOUT_MINUTES || 90) * 60 * 1000,
});

function readJsonBody(request) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    request.on("data", (chunk) => {
      size += chunk.length;
      if (size > MAX_BODY_BYTES) {
        reject(new Error("payload too large"));
        request.destroy();
        return;
      }
      chunks.push(chunk);
    });
    request.on("end", () => {
      const raw = Buffer.concat(chunks).toString("utf8");
      if (!raw) return resolve(null);
      try {
        resolve(JSON.parse(raw));
      } catch {
        reject(new Error("request body must be JSON"));
      }
    });
    request.on("error", reject);
  });
}

const server = http.createServer(async (request, response) => {
  if (request.method === "GET" && request.url === "/health") {
    response.writeHead(200, { "Content-Type": "application/json" });
    response.end(JSON.stringify({ status: "ok", ...service.snapshot() }));
    return;
  }
  if (request.method === "POST" && request.url === "/dispatch") {
    let body;
    try {
      body = await readJsonBody(request);
    } catch (error) {
      response.writeHead(400, { "Content-Type": "application/json" });
      response.end(JSON.stringify({ error: error.message || "bad request" }));
      return;
    }
    const result = service.accept(
      body,
      request.headers["idempotency-key"],
      request.headers.authorization,
    );
    response.writeHead(result.status, { "Content-Type": "application/json" });
    response.end(JSON.stringify(result.body));
    return;
  }
  response.writeHead(404, { "Content-Type": "application/json" });
  response.end(JSON.stringify({ error: "not found" }));
});

server.listen(PORT, "0.0.0.0", () => {
  console.log(`bob-dispatch listening on :${PORT}`);
});
