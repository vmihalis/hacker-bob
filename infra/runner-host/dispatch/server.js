"use strict";

const http = require("node:http");

const {
  MAX_BODY_BYTES,
  createConvexControlPlaneSink,
  createService,
} = require("./service.js");

class RequestBodyError extends Error {
  constructor(message, status, code) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

const JSON_RESPONSE_HEADERS = Object.freeze({
  "Content-Type": "application/json",
  "Cache-Control": "no-store",
  "X-Content-Type-Options": "nosniff",
});

function sendJson(response, status, body, headers = {}) {
  response.writeHead(status, {
    ...JSON_RESPONSE_HEADERS,
    ...headers,
  });
  response.end(JSON.stringify(body));
}

function positiveInteger(value, fallback, name) {
  const candidate = value === undefined || value === "" ? fallback : Number(value);
  if (!Number.isSafeInteger(candidate) || candidate < 1) throw new Error(`${name} must be a positive integer`);
  return candidate;
}

function readJsonBody(request, maxBytes = MAX_BODY_BYTES) {
  return new Promise((resolve, reject) => {
    const declaredLength = Number(request.headers["content-length"] || 0);
    if (Number.isFinite(declaredLength) && declaredLength > maxBytes) {
      request.resume();
      reject(new RequestBodyError("payload too large", 413, "payload_too_large"));
      return;
    }
    const chunks = [];
    let size = 0;
    let rejected = false;
    request.on("data", (chunk) => {
      if (rejected) return;
      size += chunk.length;
      if (size > maxBytes) {
        rejected = true;
        chunks.length = 0;
        reject(new RequestBodyError("payload too large", 413, "payload_too_large"));
        return;
      }
      chunks.push(chunk);
    });
    request.on("end", () => {
      if (rejected) return;
      const raw = Buffer.concat(chunks).toString("utf8");
      if (!raw) {
        resolve(null);
        return;
      }
      try {
        resolve(JSON.parse(raw));
      } catch {
        reject(new RequestBodyError("request body must be JSON", 400, "invalid_json"));
      }
    });
    request.on("error", (error) => {
      if (!rejected) reject(error);
    });
  });
}

function createHttpServer(service) {
  const server = http.createServer(async (request, response) => {
    if (request.method === "GET" && request.url === "/health") {
      sendJson(response, 200, { status: "ok" });
      return;
    }
    if (request.method === "POST" && request.url === "/dispatch") {
      let body;
      try {
        body = await readJsonBody(request);
      } catch (error) {
        const expected = error instanceof RequestBodyError;
        sendJson(
          response,
          expected ? error.status : 400,
          expected
            ? { error: error.message, code: error.code }
            : { error: "bad request", code: "invalid_request" },
        );
        return;
      }
      let result;
      try {
        result = await service.accept(
          body,
          request.headers["idempotency-key"],
          request.headers.authorization,
        );
      } catch {
        sendJson(response, 503, {
          error: "dispatch service unavailable",
          code: "service_unavailable",
        });
        return;
      }
      sendJson(response, result.status, result.body, result.headers || {});
      return;
    }
    sendJson(response, 404, { error: "not found" });
  });
  server.requestTimeout = 15_000;
  server.headersTimeout = 10_000;
  server.keepAliveTimeout = 5_000;
  return server;
}

function serviceFromEnvironment(environment = process.env) {
  const runnerSecret = environment.RUNNER_SECRET || "";
  const controlPlaneSink = createConvexControlPlaneSink({
    url: environment.BOB_CONVEX_URL || "",
    secret: runnerSecret,
  });
  return createService({
    secret: environment.DISPATCH_SECRET || "",
    ledgerDir: environment.LEDGER_DIR || "/var/lib/bob-dispatch/ledger",
    runsDir: environment.RUNS_DIR || "/run/bob-dispatch",
    logsDir: environment.LOGS_DIR || "/var/lib/bob-dispatch/logs",
    runnerImageUri: environment.RUNNER_IMAGE_URI || "",
    containerEnv: {
      RUNNER_SECRET: runnerSecret,
      DEEPSEEK_API_KEY: environment.DEEPSEEK_API_KEY,
      BOB_PROJECTION_URL: environment.BOB_PROJECTION_URL,
      BOB_CONVEX_URL: environment.BOB_CONVEX_URL,
    },
    maxConcurrent: positiveInteger(environment.MAX_CONCURRENT_RUNS, 2, "MAX_CONCURRENT_RUNS"),
    maxQueued: positiveInteger(environment.MAX_QUEUED_RUNS, 8, "MAX_QUEUED_RUNS"),
    maxQueueAgeMs: positiveInteger(environment.MAX_QUEUE_AGE_MS, 900000, "MAX_QUEUE_AGE_MS"),
    runTimeoutMs: positiveInteger(environment.RUN_TIMEOUT_MINUTES, 90, "RUN_TIMEOUT_MINUTES") * 60 * 1000,
    ledgerCompactRows: positiveInteger(environment.LEDGER_COMPACT_ROWS, 10000, "LEDGER_COMPACT_ROWS"),
    controlPlaneSink,
  });
}

if (require.main === module) {
  const port = positiveInteger(process.env.DISPATCH_PORT, 8080, "DISPATCH_PORT");
  const service = serviceFromEnvironment();
  const server = createHttpServer(service);
  server.listen(port, "0.0.0.0", () => {
    console.log(`bob-dispatch listening on :${port}`);
  });
}

module.exports = {
  RequestBodyError,
  createHttpServer,
  positiveInteger,
  readJsonBody,
  serviceFromEnvironment,
};
