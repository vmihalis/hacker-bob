"use strict";

const crypto = require("node:crypto");
const http = require("node:http");
const { Readable } = require("node:stream");
const { pipeline } = require("node:stream/promises");

const LISTEN_HOST = "127.0.0.1";
const LISTEN_PORT = 48125;
const MAX_REQUEST_BYTES = 16 * 1024 * 1024;
const UPSTREAM_URL = "https://api.deepseek.com/responses";
const BOB_NAMESPACE = "mcp__hacker_bob";
const BOB_TOOL_RE = /^bob_[a-z0-9_]+$/;
const MODEL_RE = /^deepseek-v4-(?:flash|pro)$/;

function fixedWorkEqual(candidate, expected) {
  const candidateDigest = crypto.createHash("sha256").update(
    typeof candidate === "string" ? candidate : "",
  ).digest();
  const expectedDigest = crypto.createHash("sha256").update(
    typeof expected === "string" ? expected : "",
  ).digest();
  const equal = crypto.timingSafeEqual(candidateDigest, expectedDigest);
  return equal && typeof candidate === "string" && candidate.length > 0
    && typeof expected === "string" && expected.length > 0;
}

function bearerToken(header) {
  if (typeof header !== "string" || !header.startsWith("Bearer ")) return "";
  return header.slice("Bearer ".length);
}

function hasExactKeys(value, keys) {
  return value && typeof value === "object" && !Array.isArray(value)
    && Object.keys(value).length === keys.length
    && keys.every((key) => Object.hasOwn(value, key));
}

function filteredRequestBody(serialized) {
  let body;
  try {
    body = JSON.parse(serialized);
  } catch {
    throw new Error("invalid_json");
  }
  if (!body || typeof body !== "object" || Array.isArray(body)) {
    throw new Error("invalid_body");
  }
  if (!MODEL_RE.test(body.model)) throw new Error("invalid_model");
  if (!Array.isArray(body.tools)) throw new Error("missing_tools");

  const namespaces = body.tools.filter((tool) => (
    tool && tool.type === "namespace" && tool.name === BOB_NAMESPACE
  ));
  if (namespaces.length !== 1) throw new Error("bob_namespace_mismatch");
  const namespace = namespaces[0];
  if (
    !hasExactKeys(namespace, ["type", "name", "description", "tools"])
    || typeof namespace.description !== "string"
    || !Array.isArray(namespace.tools)
    || namespace.tools.length === 0
  ) {
    throw new Error("bob_tools_missing");
  }
  const seen = new Set();
  const tools = [];
  for (const tool of namespace.tools) {
    if (
      !hasExactKeys(tool, ["type", "name", "description", "parameters", "strict"])
      || tool.type !== "function"
      || !BOB_TOOL_RE.test(tool.name)
      || typeof tool.description !== "string"
      || !tool.parameters
      || typeof tool.parameters !== "object"
      || Array.isArray(tool.parameters)
      || tool.strict !== false
      || seen.has(tool.name)
    ) {
      throw new Error("bob_tool_invalid");
    }
    seen.add(tool.name);
    tools.push({
      type: "function",
      name: tool.name,
      description: tool.description,
      parameters: tool.parameters,
      strict: false,
    });
  }

  body.tools = [{
    type: "namespace",
    name: BOB_NAMESPACE,
    description: namespace.description,
    tools,
  }];
  body.tool_choice = "auto";
  return JSON.stringify(body);
}

function readBoundedBody(request, maxBytes = MAX_REQUEST_BYTES) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let bytes = 0;
    let rejected = false;
    request.on("data", (chunk) => {
      if (rejected) return;
      bytes += chunk.length;
      if (bytes > maxBytes) {
        rejected = true;
        chunks.length = 0;
        reject(new Error("request_too_large"));
        return;
      }
      chunks.push(chunk);
    });
    request.on("end", () => {
      if (!rejected) resolve(Buffer.concat(chunks).toString("utf8"));
    });
    request.on("error", reject);
  });
}

function safeResponseHeaders(headers) {
  const result = {};
  for (const name of ["content-type", "cache-control", "x-request-id"]) {
    const value = headers.get(name);
    if (value) result[name] = value;
  }
  return result;
}

function createToolFilterHandler({ apiKey, clientKey = apiKey, fetchImpl = fetch } = {}) {
  if (typeof apiKey !== "string" || apiKey.length === 0) {
    throw new Error("DEEPSEEK_API_KEY is required");
  }
  if (typeof clientKey !== "string" || clientKey.length === 0) {
    throw new Error("proxy client key is required");
  }
  return async function toolFilterHandler(request, response) {
    if (request.method !== "POST" || request.url !== "/responses") {
      response.writeHead(404, { "content-type": "application/json" });
      response.end('{"error":"not_found"}');
      return;
    }
    if (!fixedWorkEqual(bearerToken(request.headers.authorization), clientKey)) {
      response.writeHead(401, { "content-type": "application/json" });
      response.end('{"error":"unauthorized"}');
      return;
    }

    const controller = new AbortController();
    request.once("aborted", () => controller.abort());
    response.once("close", () => {
      if (!response.writableEnded) controller.abort();
    });
    let filtered;
    try {
      const serialized = await readBoundedBody(request);
      filtered = filteredRequestBody(serialized);
    } catch (error) {
      if (controller.signal.aborted) {
        response.destroy();
        return;
      }
      const status = error && error.message === "request_too_large" ? 413 : 400;
      response.writeHead(status, { "content-type": "application/json" });
      response.end('{"error":"request_rejected"}');
      return;
    }

    try {
      const upstream = await fetchImpl(UPSTREAM_URL, {
        method: "POST",
        redirect: "error",
        signal: controller.signal,
        headers: {
          accept: "text/event-stream, application/json",
          authorization: `Bearer ${apiKey}`,
          "content-type": "application/json",
          "user-agent": "hacker-bob-codex-runner/1",
        },
        body: filtered,
      });
      response.writeHead(upstream.status, safeResponseHeaders(upstream.headers));
      if (!upstream.body) {
        response.end();
        return;
      }
      await pipeline(Readable.fromWeb(upstream.body), response);
    } catch {
      if (controller.signal.aborted || response.headersSent) {
        response.destroy();
        return;
      }
      response.writeHead(502, { "content-type": "application/json" });
      response.end('{"error":"upstream_unavailable"}');
    }
  };
}

function startToolFilterProxy({
  apiKey = process.env.DEEPSEEK_API_KEY,
  clientKey = apiKey,
  fetchImpl = fetch,
  host = LISTEN_HOST,
  port = LISTEN_PORT,
} = {}) {
  const server = http.createServer(createToolFilterHandler({ apiKey, clientKey, fetchImpl }));
  server.keepAliveTimeout = 5_000;
  server.headersTimeout = 10_000;
  server.requestTimeout = 310_000;
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, host, () => {
      server.removeListener("error", reject);
      resolve(server);
    });
  });
}

module.exports = {
  BOB_NAMESPACE,
  LISTEN_HOST,
  LISTEN_PORT,
  MAX_REQUEST_BYTES,
  UPSTREAM_URL,
  createToolFilterHandler,
  filteredRequestBody,
  fixedWorkEqual,
  startToolFilterProxy,
};
