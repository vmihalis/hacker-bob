"use strict";

// fx-gate-bypass defense 2 — the stdio server's caller-auth token check.
// A rogue second engine instance the model spawns directly via Bash (e.g.
// `env -u BOB_AGENTCORE node .../mcp/server.js`) inherits only the model's
// own ambient env, never the mcp-config `env` block the CLI applies
// exclusively to the MCP-server child it spawns -- so it never receives
// BOB_MCP_CALLER_TOKEN. These tests exercise mcp/lib/transport.js's
// enforcement directly (unit-level, deterministic, no real process.exit)
// plus one real spawned-process smoke test for end-to-end confidence.

const test = require("node:test");
const assert = require("node:assert/strict");
const path = require("path");
const { spawn } = require("child_process");

const {
  createMcpMessageHandler,
  createStdioServer,
} = require("../mcp/lib/transport.js");

const SERVER_PATH = path.join(__dirname, "..", "mcp", "server.js");
const VALID_TOKEN = "a".repeat(64);

function fakeTools() {
  return [];
}

async function fakeExecuteTool() {
  return JSON.stringify({ ok: true, data: {}, meta: { tool: "noop", version: 1 } });
}

function harness({ env }) {
  const sent = [];
  const stderrChunks = [];
  const exitCalls = [];
  const handleMessage = createMcpMessageHandler({
    tools: fakeTools(),
    executeTool: fakeExecuteTool,
    send: (msg) => sent.push(msg),
    stderr: { write: (chunk) => stderrChunks.push(chunk) },
    env,
    exit: (code) => exitCalls.push(code),
  });
  return { handleMessage, sent, stderrChunks, exitCalls };
}

test("caller-auth gate is fully inert when BOB_AGENTCORE is unset (local/dev/CI default, no new required env var)", async () => {
  const { handleMessage, sent, exitCalls } = harness({ env: {} });
  await handleMessage({ jsonrpc: "2.0", id: 1, method: "initialize", params: {} });
  assert.equal(exitCalls.length, 0, "must never call exit when enforcement is inactive");
  assert.equal(sent.length, 1, "must respond normally when enforcement is inactive");
  assert.equal(sent[0].result.serverInfo.name, "hacker-bob");
});

test("caller-auth gate is inert when BOB_AGENTCORE is set but not exactly \"1\"", async () => {
  const { handleMessage, sent, exitCalls } = harness({ env: { BOB_AGENTCORE: "true" } });
  await handleMessage({ jsonrpc: "2.0", id: 1, method: "initialize", params: {} });
  assert.equal(exitCalls.length, 0);
  assert.equal(sent.length, 1);
});

test("caller-auth gate rejects the first message and exits non-zero when BOB_MCP_CALLER_TOKEN is absent under enforcement", async () => {
  const { handleMessage, sent, stderrChunks, exitCalls } = harness({ env: { BOB_AGENTCORE: "1" } });
  await handleMessage({ jsonrpc: "2.0", id: 1, method: "initialize", params: {} });
  assert.deepEqual(exitCalls, [1], "must exit(1) exactly once");
  assert.equal(sent.length, 0, "must never send a response for the rejected first message");
  assert.ok(
    stderrChunks.some((chunk) => /BOB_MCP_CALLER_TOKEN/.test(chunk)),
    "must write a diagnostic mentioning BOB_MCP_CALLER_TOKEN to stderr",
  );
});

test("caller-auth gate rejects when BOB_MCP_CALLER_TOKEN is malformed (wrong length / non-hex / uppercase)", async () => {
  for (const malformed of ["", "not-hex", "a".repeat(63), "a".repeat(65), "A".repeat(64), "g".repeat(64)]) {
    const { handleMessage, sent, exitCalls } = harness({
      env: { BOB_AGENTCORE: "1", BOB_MCP_CALLER_TOKEN: malformed },
    });
    await handleMessage({ jsonrpc: "2.0", id: 1, method: "initialize", params: {} });
    assert.deepEqual(exitCalls, [1], `must exit(1) for malformed token ${JSON.stringify(malformed)}`);
    assert.equal(sent.length, 0, `must not respond for malformed token ${JSON.stringify(malformed)}`);
  }
});

test("caller-auth gate accepts a well-formed 64-lowercase-hex token and dispatches normally", async () => {
  const { handleMessage, sent, exitCalls } = harness({
    env: { BOB_AGENTCORE: "1", BOB_MCP_CALLER_TOKEN: VALID_TOKEN },
  });
  await handleMessage({ jsonrpc: "2.0", id: 1, method: "initialize", params: {} });
  assert.equal(exitCalls.length, 0);
  assert.equal(sent.length, 1);
  assert.equal(sent[0].result.serverInfo.name, "hacker-bob");
});

test("caller-auth gate only checks the FIRST message: a valid first message clears the gate for later messages regardless of later env drift", async () => {
  const env = { BOB_AGENTCORE: "1", BOB_MCP_CALLER_TOKEN: VALID_TOKEN };
  const { handleMessage, sent, exitCalls } = harness({ env });
  await handleMessage({ jsonrpc: "2.0", id: 1, method: "ping", params: {} });
  delete env.BOB_MCP_CALLER_TOKEN;
  await handleMessage({ jsonrpc: "2.0", id: 2, method: "ping", params: {} });
  assert.equal(exitCalls.length, 0, "the gate is a one-time check on the first message only");
  assert.equal(sent.length, 2);
});

test("createStdioServer wires stderr/env/exit through to the caller-auth gate (rejects malformed token via the real dispatch path)", async () => {
  const exitCalls = [];
  const stderrChunks = [];
  const sentRaw = [];
  const server = createStdioServer({
    stdin: { on: () => {} },
    stdout: { write: (chunk) => sentRaw.push(chunk) },
    stderr: { write: (chunk) => stderrChunks.push(chunk) },
    tools: fakeTools(),
    executeTool: fakeExecuteTool,
    env: { BOB_AGENTCORE: "1", BOB_MCP_CALLER_TOKEN: "short" },
    exit: (code) => exitCalls.push(code),
  });
  await server.handleMessage({ jsonrpc: "2.0", id: 1, method: "initialize", params: {} });
  assert.deepEqual(exitCalls, [1]);
  assert.equal(sentRaw.length, 0, "no JSON-RPC response bytes reach stdout for the rejected first message");
  assert.ok(stderrChunks.some((chunk) => /BOB_MCP_CALLER_TOKEN/.test(chunk)));
});

// --- Real spawned-process smoke test -------------------------------------

function spawnServer(env, { input } = {}) {
  const child = spawn(process.execPath, [SERVER_PATH], {
    env: { ...process.env, ...env },
    stdio: ["pipe", "pipe", "pipe"],
  });
  let stderr = "";
  let stdout = "";
  child.stderr.on("data", (chunk) => { stderr += chunk.toString("utf8"); });
  child.stdout.on("data", (chunk) => { stdout += chunk.toString("utf8"); });
  // "close" (not "exit"): stdio pipes deliver "data" asynchronously on POSIX
  // and can still be draining when "exit" fires; "close" fires only after all
  // stdio streams have ended, guaranteeing `stderr`/`stdout` are fully
  // accumulated by the time callers inspect them.
  const exited = new Promise((resolve) => {
    child.on("close", (code) => resolve(code));
  });
  if (input != null) {
    child.stdin.write(input);
  }
  return { child, exited, get stderr() { return stderr; }, get stdout() { return stdout; } };
}

async function waitUntil(predicate, timeoutMs = 15000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (predicate()) return true;
    await new Promise((resolve) => setTimeout(resolve, 25));
  }
  return predicate();
}

test("a real `node mcp/server.js` process exits non-zero on its first request when BOB_AGENTCORE=1 and no caller token is set, without echoing a JSON-RPC response", async () => {
  const fs = require("fs");
  const os = require("os");
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-caller-auth-"));
  try {
    const initMessage = JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: {} });
    const server = spawnServer(
      { HOME: home, BOB_AGENTCORE: "1" },
      { input: `${initMessage}\n` },
    );
    const code = await server.exited;
    assert.notEqual(code, 0, `server must exit non-zero; stderr=${server.stderr}`);
    assert.ok(/BOB_MCP_CALLER_TOKEN/.test(server.stderr), `stderr must mention the missing token; got: ${server.stderr}`);
    assert.equal(server.stdout.includes("\"result\""), false, "no JSON-RPC result must ever reach stdout");
  } finally {
    fs.rmSync(home, { recursive: true, force: true });
  }
});

test("a real `node mcp/server.js` process behaves identically to today (no BOB_MCP_CALLER_TOKEN required) when BOB_AGENTCORE is unset", async () => {
  const fs = require("fs");
  const os = require("os");
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-caller-auth-inert-"));
  let server = null;
  try {
    const initMessage = JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: {} });
    server = spawnServer({ HOME: home }, { input: `${initMessage}\n` });
    const responded = await waitUntil(() => server.stdout.includes("\"result\""));
    assert.ok(responded, `must respond normally when enforcement is inactive; stdout=${server.stdout}; stderr=${server.stderr}`);
  } finally {
    // Under the full parallel MCP matrix process startup can exceed a fixed
    // 500 ms sleep. Always tear the child down even when the readiness
    // assertion fails, otherwise its open stdio handles wedge the entire test
    // runner instead of reporting a bounded failure.
    if (server && server.child.exitCode == null) server.child.kill("SIGTERM");
    if (server) await server.exited;
    fs.rmSync(home, { recursive: true, force: true });
  }
});
