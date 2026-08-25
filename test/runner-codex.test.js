"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const http = require("node:http");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");
const { EventEmitter } = require("node:events");
const { PassThrough } = require("node:stream");

const {
  BOB_NAMESPACE,
  MAX_REQUEST_BYTES,
  UPSTREAM_URL,
  filteredRequestBody,
  startToolFilterProxy,
} = require("../infra/runner/codex/tool-filter-proxy.js");
const {
  sanitizedMcpEnvironment,
} = require("../infra/runner/codex/mcp-launcher.js");
const codexRunner = require("../infra/runner/codex/run-codex.js");

const CORE_ROOT = path.resolve(__dirname, "..");
const CODEX_SOURCE = path.join(CORE_ROOT, "infra", "runner", "codex");
const PINNED_CODEX_BIN = path.join(CODEX_SOURCE, "node_modules", ".bin", "codex");

function request(server, { authorization, body }) {
  const address = server.address();
  return new Promise((resolve, reject) => {
    const req = http.request({
      hostname: "127.0.0.1",
      port: address.port,
      path: "/responses",
      method: "POST",
      headers: {
        authorization,
        "content-type": "application/json",
      },
    }, (response) => {
      const chunks = [];
      response.on("data", (chunk) => chunks.push(chunk));
      response.on("end", () => resolve({
        status: response.statusCode,
        body: Buffer.concat(chunks).toString("utf8"),
      }));
    });
    req.once("error", reject);
    req.end(body);
  });
}

function closeServer(server) {
  if (typeof server.closeAllConnections === "function") server.closeAllConnections();
  return new Promise((resolve) => server.close(() => resolve()));
}

function validRequest(overrides = {}) {
  return {
    model: "deepseek-v4-flash",
    input: "authorized task",
    tools: [
      { type: "function", name: "update_plan", parameters: { type: "object" } },
      {
        type: "namespace",
        name: BOB_NAMESPACE,
        description: "Hacker Bob tools",
        tools: [
          {
            type: "function",
            name: "bob_session_status",
            description: "Read session status",
            parameters: { type: "object" },
            strict: false,
          },
          {
            type: "function",
            name: "bob_init_session",
            description: "Initialize a session",
            parameters: { type: "object" },
            strict: false,
          },
        ],
      },
      { type: "function", name: "read_mcp_resource", parameters: { type: "object" } },
    ],
    ...overrides,
  };
}

function waitForExit(child, timeoutMs = 45_000) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      child.kill("SIGKILL");
      reject(new Error("Codex process timed out"));
    }, timeoutMs);
    child.once("error", (error) => {
      clearTimeout(timer);
      reject(error);
    });
    child.once("exit", (code, signal) => {
      clearTimeout(timer);
      resolve({ code, signal });
    });
  });
}

test("tool filter leaves exactly the Bob namespace for DeepSeek", () => {
  const filtered = JSON.parse(filteredRequestBody(JSON.stringify(validRequest())));
  assert.equal(filtered.model, "deepseek-v4-flash");
  assert.equal(filtered.tool_choice, "auto");
  assert.deepEqual(filtered.tools.map((tool) => tool.name), [BOB_NAMESPACE]);
  assert.deepEqual(filtered.tools[0].tools.map((tool) => tool.name), [
    "bob_session_status",
    "bob_init_session",
  ]);

  assert.throws(
    () => filteredRequestBody(JSON.stringify(validRequest({ model: "deepseek-v4-vision" }))),
    /invalid_model/,
  );
  assert.throws(
    () => filteredRequestBody(JSON.stringify(validRequest({ tools: [] }))),
    /bob_namespace_mismatch/,
  );
  const badNamespace = validRequest();
  badNamespace.tools[1].tools.push({ type: "function", name: "shell", parameters: {} });
  assert.throws(() => filteredRequestBody(JSON.stringify(badNamespace)), /bob_tool_invalid/);
});

test("loopback proxy authenticates, filters, and forwards to fixed DeepSeek endpoint", async (t) => {
  const secret = `profile-${crypto.randomBytes(16).toString("hex")}`;
  const forwarded = [];
  const server = await startToolFilterProxy({
    apiKey: secret,
    port: 0,
    fetchImpl: async (url, options) => {
      forwarded.push({ url, options });
      return new Response('{"ok":true}', {
        status: 200,
        headers: { "content-type": "application/json", "content-encoding": "br" },
      });
    },
  });
  t.after(() => closeServer(server));

  const denied = await request(server, {
    authorization: "Bearer wrong",
    body: JSON.stringify(validRequest()),
  });
  assert.equal(denied.status, 401);
  assert.equal(denied.body.includes(secret), false);
  assert.equal(forwarded.length, 0);

  const accepted = await request(server, {
    authorization: `Bearer ${secret}`,
    body: JSON.stringify(validRequest()),
  });
  assert.equal(accepted.status, 200);
  assert.equal(accepted.body, '{"ok":true}');
  assert.equal(forwarded.length, 1);
  assert.equal(forwarded[0].url, UPSTREAM_URL);
  assert.equal(forwarded[0].options.redirect, "error");
  assert.equal(forwarded[0].options.headers.authorization, `Bearer ${secret}`);
  const forwardedBody = JSON.parse(forwarded[0].options.body);
  assert.deepEqual(forwardedBody.tools.map((tool) => tool.name), [BOB_NAMESPACE]);

  const invalid = await request(server, {
    authorization: `Bearer ${secret}`,
    body: "not-json",
  });
  assert.equal(invalid.status, 400);
  assert.equal(forwarded.length, 1);

  const oversized = await request(server, {
    authorization: `Bearer ${secret}`,
    body: "x".repeat(MAX_REQUEST_BYTES + 1),
  });
  assert.equal(oversized.status, 413);
  assert.equal(forwarded.length, 1);
});

test("loopback proxy maps upstream transport failure to a retryable response", async (t) => {
  const server = await startToolFilterProxy({
    apiKey: "transport-contract-key",
    port: 0,
    fetchImpl: async () => {
      throw new Error("transport details must not cross the proxy");
    },
  });
  t.after(() => closeServer(server));
  const result = await request(server, {
    authorization: "Bearer transport-contract-key",
    body: JSON.stringify(validRequest()),
  });
  assert.equal(result.status, 502);
  assert.equal(result.body, '{"error":"upstream_unavailable"}');
});

test("MCP launcher exposes only the runner capability environment", () => {
  const environment = sanitizedMcpEnvironment({
    BOB_SESSIONS_ROOT: "/workspace/sessions",
    BOB_PROJECTION_URL: "https://projection.example/api/findings",
    BOB_RUN_SLUG: "runner-slug-1234",
    BOB_PROJECTION_KEY: "P".repeat(43),
    BOB_RUN_KIND: "assessment",
    BOB_RETEST_OF: "prior-run",
    BOB_REPORT_SLUG: "runner-slug-1234-report",
    RUNNER_SECRET: "runner-secret",
    BOB_CONVEX_URL: "https://deployment.convex.cloud",
    BOB_PAYLOAD_JSON: "{}",
    DEEPSEEK_API_KEY: "model-secret",
  });
  assert.deepEqual(Object.keys(environment).sort(), [
    "BOB_PROJECTION_KEY",
    "BOB_PROJECTION_URL",
    "BOB_REPORT_SLUG",
    "BOB_RETEST_OF",
    "BOB_RUN_KIND",
    "BOB_RUN_SLUG",
    "BOB_SESSIONS_ROOT",
    "HOME",
    "NODE_ENV",
    "PATH",
    "RUNNER_SECRET",
  ]);
  assert.equal(JSON.stringify(environment).includes("model-secret"), false);
  assert.equal(Object.hasOwn(environment, "BOB_CONVEX_URL"), false);
  assert.equal(Object.hasOwn(environment, "BOB_PAYLOAD_JSON"), false);
});

test("Codex wrapper suppresses child output and uses the pinned headless invocation", async (t) => {
  const child = new EventEmitter();
  child.stdout = new PassThrough();
  child.stderr = new PassThrough();
  child.killed = false;
  child.kill = () => {
    child.killed = true;
    return true;
  };
  let spawnInvocation;
  let proxyKey;
  let closed = false;
  const output = [];
  t.mock.method(process.stdout, "write", (chunk) => {
    output.push(String(chunk));
    return true;
  });
  t.mock.method(process.stderr, "write", (chunk) => {
    output.push(String(chunk));
    return true;
  });

  const codePromise = codexRunner.main({
    argv: ["one task"],
    environment: { DEEPSEEK_API_KEY: "model-secret", BOB_RUN_SLUG: "runner-slug-1234" },
    spawnFactory: (command, args, options) => {
      spawnInvocation = { command, args, options };
      process.nextTick(() => {
        child.stdout.end("sensitive model response");
        child.stderr.end("sensitive tool arguments");
        child.emit("exit", 0, null);
      });
      return child;
    },
    startProxy: async ({ apiKey }) => {
      proxyKey = apiKey;
      return {
        closeAllConnections() {},
        close(callback) {
          closed = true;
          callback();
        },
      };
    },
  });
  assert.equal(await codePromise, 0);
  assert.equal(proxyKey, "model-secret");
  assert.equal(spawnInvocation.command, codexRunner.CODEX_BIN);
  assert.deepEqual(spawnInvocation.args, [...codexRunner.CODEX_ARGS, "one task"]);
  assert.deepEqual(spawnInvocation.options.stdio, ["ignore", "pipe", "pipe"]);
  assert.equal(closed, true);
  const emitted = output.join("");
  assert.match(emitted, /Codex runner completed\./);
  assert.equal(emitted.includes("sensitive model response"), false);
  assert.equal(emitted.includes("sensitive tool arguments"), false);
});

test("pinned Codex request reaches DeepSeek with only real Bob MCP tools", {
  timeout: 60_000,
  skip: fs.existsSync(PINNED_CODEX_BIN) ? false : "pinned Codex runtime is installed by check:runner-codex-profile",
}, async () => {
  const codexBin = PINNED_CODEX_BIN;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-codex-contract-"));
  const sessionsRoot = path.join(home, "sessions");
  fs.mkdirSync(sessionsRoot);
  const fixtureLauncher = path.join(home, "mcp-launcher.js");
  fs.writeFileSync(
    fixtureLauncher,
    `require(${JSON.stringify(path.join(CORE_ROOT, "mcp", "server.js"))}).startServer();\n`,
  );
  let config = fs.readFileSync(path.join(CODEX_SOURCE, "config.toml"), "utf8");
  config = config
    .replaceAll("/opt/codex-home", home)
    .replaceAll("/opt/hacker-bob", CORE_ROOT)
    .replace(`args = ["${home}/mcp-launcher.js"]`, `args = [${JSON.stringify(fixtureLauncher)}]`);
  fs.writeFileSync(path.join(home, "config.toml"), config);
  fs.copyFileSync(path.join(CODEX_SOURCE, "models.json"), path.join(home, "models.json"));
  fs.copyFileSync(path.join(CODEX_SOURCE, "instructions.txt"), path.join(home, "instructions.txt"));

  const forwarded = [];
  const proxy = await startToolFilterProxy({
    apiKey: "codex-contract-key",
    fetchImpl: async (_url, options) => {
      forwarded.push(JSON.parse(String(options.body)));
      return new Response(JSON.stringify({
        error: { message: "contract captured", type: "invalid_request_error" },
      }), {
        status: 400,
        headers: { "content-type": "application/json" },
      });
    },
  });
  let child;
  const stderr = [];
  let exitResult;
  try {
    child = require("node:child_process").spawn(codexBin, [
      "exec",
      "--strict-config",
      "--ephemeral",
      "--ignore-rules",
      "--skip-git-repo-check",
      "--sandbox",
      "read-only",
      "--color",
      "never",
      "-C",
      CORE_ROOT,
      "Use one Hacker Bob status tool and stop.",
    ], {
      cwd: CORE_ROOT,
      env: {
        PATH: `${path.dirname(codexBin)}:${process.env.PATH}`,
        HOME: home,
        CODEX_HOME: home,
        DEEPSEEK_API_KEY: "codex-contract-key",
        BOB_SESSIONS_ROOT: sessionsRoot,
        BOB_RUN_SLUG: "runner-contract-1234",
        BOB_REPORT_SLUG: "runner-contract-1234-report",
        BOB_RUN_KIND: "assessment",
        BOB_RETEST_OF: "",
        BOB_PROJECTION_URL: "https://projection.example/api/findings",
        BOB_PROJECTION_KEY: "Q".repeat(43),
        RUNNER_SECRET: "runner-contract-secret",
      },
      stdio: ["ignore", "ignore", "pipe"],
    });
    child.stderr.on("data", (chunk) => stderr.push(Buffer.from(chunk)));
    exitResult = await waitForExit(child);
  } finally {
    if (child && child.exitCode === null && !child.killed) child.kill("SIGKILL");
    await closeServer(proxy);
    fs.rmSync(home, { recursive: true, force: true });
  }

  const diagnostic = Buffer.concat(stderr).toString("utf8").replaceAll("codex-contract-key", "[REDACTED]").slice(-4_096);
  assert.ok(
    forwarded.length >= 1,
    `Codex must send a Responses request (exit ${exitResult?.code}, signal ${exitResult?.signal}): ${diagnostic}`,
  );
  for (const outbound of forwarded) {
    assert.equal(outbound.model, "deepseek-v4-pro");
    assert.equal(outbound.tool_choice, "auto");
    assert.match(outbound.instructions, /Hacker Bob/);
    assert.doesNotMatch(outbound.instructions, /\b(?:GPT-5|OpenAI)\b/i);
    const serializedOutbound = JSON.stringify(outbound);
    for (const secret of ["codex-contract-key", "Q".repeat(43), "runner-contract-secret"]) {
      assert.equal(serializedOutbound.includes(secret), false);
    }
    assert.equal(outbound.tools.length, 1);
    assert.equal(outbound.tools[0].type, "namespace");
    assert.equal(outbound.tools[0].name, BOB_NAMESPACE);
    assert.ok(outbound.tools[0].tools.length > 0);
    assert.ok(outbound.tools[0].tools.every((tool) => /^bob_[a-z0-9_]+$/.test(tool.name)));
  }
});
