"use strict";

// Cycle T.1 — Patchright session-driver MCP tool contracts.
//
// Coverage:
//   - Tool registry membership + role-bundle wiring.
//   - Expression sandbox at the wrapper level (defense-in-depth).
//   - Patchright availability gate: every tool returns a structured
//     patchright_unavailable envelope when the optional dependency is missing.
//   - Per-domain concurrency limit enforced by the session registry.
//   - Idle timeout reaps a subprocess.
//   - Smoke: when patchright IS installed, spawn a session against a local
//     data URL, navigate, snapshot, evaluate 1+1, close. Off-scope navigate
//     refused. Off-scope fetch inside evaluate refused.
//
// Tests that require a real Chromium are skipped (with reason) when patchright
// is not installed in the runtime environment — matching the install-graceful
// contract.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const path = require("path");

const {
  TOOL_MANIFEST,
  TOOLS,
  toolNamesForRoleBundle,
} = require("../mcp/tools/tool-registry.js");
const {
  EXPLICIT_AUTHORITY_CLASS_BY_TOOL,
} = require("../mcp/core/session/session-authority.js");
const browserSessions = require("../mcp/domains/web/browser-sessions.js");
const browserToolsShared = require("../mcp/domains/web/browser-tools-shared.js");

const BROWSER_TOOLS = Object.freeze([
  "bob_browser_session_start",
  "bob_browser_navigate",
  "bob_browser_snapshot",
  "bob_browser_click",
  "bob_browser_type",
  "bob_browser_evaluate",
  "bob_browser_network_requests",
  "bob_browser_console_messages",
  "bob_browser_wait_for",
  "bob_browser_press_key",
  "bob_browser_take_screenshot",
  "bob_browser_fill_form",
  "bob_browser_session_close",
]);

const BROWSER_BUNDLES = Object.freeze([
  "evaluator-shared",
  "surface-discovery",
  "deep-surface-discovery",
]);

const PATCHRIGHT_AVAILABLE = browserSessions.isPatchrightAvailable();
// Real-browser tests run only where a headless driver session can actually be
// hosted: a Chromium binary must be present AND the environment must not have
// opted out via BOB_SKIP_BROWSER_TESTS (CI that ships Chrome but can't start a
// headless session sets this — a present binary doesn't prove a session works).
const BROWSER_LAUNCHABLE =
  !process.env.BOB_SKIP_BROWSER_TESTS && browserSessions.isBrowserLaunchable();
const PATCHRIGHT_SKIP_REASON =
  "patchright optional dependency not installed; install via `npm install` + `npx patchright install chromium` to enable this test";

function loadHandler(toolName) {
  const moduleSlug = toolName.replace(/^bob_/, "").replace(/_/g, "-");
  // eslint-disable-next-line import/no-dynamic-require, node/no-missing-require
  const mod = require(path.join("..", "mcp", "tools", "web", `${moduleSlug}.js`));
  return mod.handler;
}

async function callTool(toolName, args) {
  const handler = loadHandler(toolName);
  const raw = await handler(args);
  return JSON.parse(raw);
}

// ── Registry contracts ──

test("every bob_browser_* tool is registered and shares the browser-driver bundles", () => {
  for (const name of BROWSER_TOOLS) {
    const meta = TOOL_MANIFEST[name];
    assert.ok(meta, `${name} must be registered`);
    assert.equal(meta.browser_access, true, `${name} must have browser_access: true`);
    assert.equal(
      meta.global_preapproval,
      false,
      `${name} must not be globally pre-approved`,
    );
    assert.deepEqual(
      [...meta.role_bundles].sort(),
      [...BROWSER_BUNDLES].sort(),
      `${name} must be in the canonical browser-driver bundles`,
    );
  }
});

test("browser-driver tools are NOT in the orchestrator role bundle", () => {
  const orchestratorTools = new Set(toolNamesForRoleBundle("orchestrator"));
  for (const name of BROWSER_TOOLS) {
    assert.ok(
      !orchestratorTools.has(name),
      `${name} must not be in orchestrator (orchestrator dispatches; agents drive)`,
    );
  }
});

test("browser-driver tools carry initialized_session_mutation authority", () => {
  for (const name of BROWSER_TOOLS) {
    assert.equal(
      EXPLICIT_AUTHORITY_CLASS_BY_TOOL[name],
      "initialized_session_mutation",
      `${name} must declare initialized_session_mutation authority`,
    );
  }
});

test("session_start and navigate declare scope_url_fields", () => {
  const sessionStart = TOOLS.find((t) => t.name === "bob_browser_session_start");
  const navigate = TOOLS.find((t) => t.name === "bob_browser_navigate");
  assert.ok(sessionStart, "bob_browser_session_start must be registered");
  assert.ok(navigate, "bob_browser_navigate must be registered");
  const sessionStartMeta = TOOL_MANIFEST.bob_browser_session_start;
  const navigateMeta = TOOL_MANIFEST.bob_browser_navigate;
  assert.ok(sessionStartMeta.scope_url_fields.includes("target_url"));
  assert.ok(navigateMeta.scope_url_fields.includes("url"));
});

// ── Expression sandbox (wrapper-level defense-in-depth) ──

test("expression sandbox rejects fetch(...) at the wrapper layer", async () => {
  const response = await callTool("bob_browser_evaluate", {
    target_domain: "example.com",
    session_id: "bs-fakefakefake",
    expression: "fetch('https://example.com/foo')",
  });
  assert.equal(response.ok, false);
  // When patchright is missing, the patchright check fires first and short-
  // circuits the sandbox check. Either gate satisfies the defense-in-depth
  // intent: agents can never invoke a forbidden expression that reaches the
  // page context without first crossing one of these two gates.
  assert.ok(
    response.error.code === "evaluate_sandbox_violation"
      || response.error.code === "patchright_unavailable",
    `unexpected error code: ${response.error.code}`,
  );
});

test("expression sandbox rejects XMLHttpRequest at the wrapper layer", async () => {
  const response = await callTool("bob_browser_evaluate", {
    target_domain: "example.com",
    session_id: "bs-fakefakefake",
    expression: "new XMLHttpRequest()",
  });
  assert.equal(response.ok, false);
  assert.ok(
    response.error.code === "evaluate_sandbox_violation"
      || response.error.code === "patchright_unavailable",
  );
});

test("expression sandbox rejects WebSocket and EventSource and sendBeacon", async () => {
  for (const expression of [
    "new WebSocket('wss://example.com')",
    "new EventSource('/stream')",
    "navigator.sendBeacon('/log', 'data')",
  ]) {
    const response = await callTool("bob_browser_evaluate", {
      target_domain: "example.com",
      session_id: "bs-fakefakefake",
      expression,
    });
    assert.equal(response.ok, false);
    assert.ok(
      response.error.code === "evaluate_sandbox_violation"
        || response.error.code === "patchright_unavailable",
      `${expression} should be sandboxed (got ${response.error.code})`,
    );
  }
});

test("shared sandbox helper rejects the forbidden patterns", () => {
  for (const expression of [
    // Direct network IO from page context.
    "fetch('/x')",
    "new XMLHttpRequest()",
    "navigator.sendBeacon('/x', 'y')",
    "new EventSource('/sse')",
    "new WebSocket('wss://example')",
    // Top-level navigation writes (agent's only remaining bypass to point the
    // browser at an off-target page outside of the scope-checked navigate gate).
    "window.location = 'https://attacker.test'",
    "window.location='https://attacker.test'",
    "location.href = 'https://attacker.test'",
    "location.assign('https://attacker.test')",
    "location.replace('https://attacker.test')",
    "document.location = 'https://attacker.test'",
    "top.location = 'https://attacker.test'",
    "parent.location = 'https://attacker.test'",
    "window.open('https://attacker.test')",
  ]) {
    assert.throws(
      () => browserToolsShared.assertExpressionSandbox(expression),
      /evaluate_sandbox_violation/,
      `expression ${expression} must be rejected by the shared sandbox`,
    );
  }
  // Allowed expressions don't throw.
  assert.equal(browserToolsShared.assertExpressionSandbox("1+1"), "1+1");
  assert.equal(
    browserToolsShared.assertExpressionSandbox("document.title"),
    "document.title",
  );
  // Reading location is allowed; only writes / open() are blocked.
  assert.equal(
    browserToolsShared.assertExpressionSandbox("location.pathname"),
    "location.pathname",
  );
  assert.equal(
    browserToolsShared.assertExpressionSandbox("document.location.host"),
    "document.location.host",
  );
});

test("driver setup does NOT install a network-level scope interceptor", () => {
  const driverSrc = fs.readFileSync(
    path.join(__dirname, "..", "mcp", "browser-driver.js"),
    "utf8",
  );
  // Subresource interception was wrong: it broke modern targets that load
  // anti-bot fingerprint scripts (Kasada), CDN bundles, OAuth callback chains.
  // Scope is enforced at agent-input gates instead (navigate + evaluate
  // sandbox). Regress on this and we lose Nike, every Akamai-protected site,
  // anything with payment iframes.
  assert.ok(
    !/context\.route\s*\(\s*["'`]\*\*\/\*["'`]/.test(driverSrc),
    "browser-driver.js must not install context.route('**/*', ...) — that interceptor aborts page-decided subresource loads (Kasada, CDN bundles, OAuth callbacks).",
  );
  // The scope helper still has to be IMPORTED — it gates navigate / session
  // start. But it must NOT appear inside an attached route handler.
  assert.ok(
    /assertSafeResolvedRequestUrl/.test(driverSrc),
    "browser-driver.js still imports/uses assertSafeResolvedRequestUrl for the navigate + start gates.",
  );
});

// ── Patchright availability gate ──

test("every bob_browser_* tool returns a structured patchright_unavailable error when patchright is missing", { skip: PATCHRIGHT_AVAILABLE }, async () => {
  // We're only in this branch when patchright was not resolved at process
  // start. Each handler must return the install-graceful envelope rather than
  // throwing or crashing.
  const args = {
    target_domain: "example.com",
    session_id: "bs-fakefakefake",
    target_url: "https://example.com",
    url: "https://example.com",
    ref: "selector:#x",
    text: "x",
    expression: "1+1",
    key: "Enter",
    predicate: { kind: "load_state", value: "load" },
    fields: [{ ref: "selector:#x", value: "y" }],
  };
  for (const name of BROWSER_TOOLS) {
    const response = await callTool(name, args);
    assert.equal(response.ok, false, `${name} should not succeed without patchright`);
    assert.equal(
      response.error.code,
      "patchright_unavailable",
      `${name} must return patchright_unavailable (got ${response.error.code})`,
    );
  }
});

// ── Concurrency cap (per-domain) ──

test("startSession refuses a 4th concurrent session per target_domain", { skip: !BROWSER_LAUNCHABLE, todo: BROWSER_LAUNCHABLE ? undefined : PATCHRIGHT_SKIP_REASON }, async () => {
  const domain = "example.com";
  const url = "https://example.com/";
  const opened = [];
  try {
    for (let i = 0; i < browserSessions.MAX_SESSIONS_PER_DOMAIN; i += 1) {
      const session = await browserSessions.startSession({
        targetDomain: domain,
        targetUrl: url,
        headless: true,
      });
      opened.push(session.session_id);
    }
    await assert.rejects(
      browserSessions.startSession({
        targetDomain: domain,
        targetUrl: url,
        headless: true,
      }),
      (err) => err && err.code === "browser_session_limit",
    );
  } finally {
    for (const sessionId of opened) {
      await browserSessions.closeSession(sessionId).catch(() => {});
    }
  }
});

// ── Smoke: spawn, navigate, snapshot, evaluate, close ──

test("smoke: start → navigate → snapshot → evaluate(1+1) → close all succeed", { skip: !BROWSER_LAUNCHABLE, todo: BROWSER_LAUNCHABLE ? undefined : PATCHRIGHT_SKIP_REASON }, async () => {
  // example.com is the canonical in-scope smoke target. We navigate first
  // because the default about:blank page has an empty accessibility tree on
  // some Chromium builds, which would fail the snapshot assertion below.
  const start = await callTool("bob_browser_session_start", {
    target_domain: "example.com",
    target_url: "https://example.com",
    headless: true,
  });
  assert.equal(start.ok, true, `session_start failed: ${JSON.stringify(start)}`);
  const sessionId = start.session_id;
  try {
    const nav = await callTool("bob_browser_navigate", {
      target_domain: "example.com",
      session_id: sessionId,
      url: "https://example.com/",
    });
    assert.equal(nav.ok, true, `navigate failed: ${JSON.stringify(nav)}`);

    const snapshot = await callTool("bob_browser_snapshot", {
      target_domain: "example.com",
      session_id: sessionId,
    });
    assert.equal(snapshot.ok, true, `snapshot failed: ${JSON.stringify(snapshot)}`);

    const evalResult = await callTool("bob_browser_evaluate", {
      target_domain: "example.com",
      session_id: sessionId,
      expression: "1 + 1",
    });
    assert.equal(evalResult.ok, true, `evaluate failed: ${JSON.stringify(evalResult)}`);
    assert.equal(evalResult.result, 2);
  } finally {
    const close = await callTool("bob_browser_session_close", {
      target_domain: "example.com",
      session_id: sessionId,
    });
    assert.equal(close.ok, true);
  }
});

test("bob_browser_evaluate declares an optional timeout_ms in its input schema", () => {
  const mod = require(path.join("..", "mcp", "tools", "web", "browser-evaluate.js"));
  const prop = mod.inputSchema.properties.timeout_ms;
  assert.ok(prop, "bob_browser_evaluate must expose a timeout_ms property");
  assert.equal(prop.type, "number");
  assert.ok(!mod.inputSchema.required.includes("timeout_ms"), "timeout_ms must stay optional");
});

test("bob_browser_evaluate honors timeout_ms and returns code evaluate_timeout for a never-settling expression", { skip: !BROWSER_LAUNCHABLE, todo: BROWSER_LAUNCHABLE ? undefined : PATCHRIGHT_SKIP_REASON }, async () => {
  // End-to-end through the public tool: proves the wrapper forwards timeout_ms,
  // the driver bounds page.evaluate, and the distinct evaluate_timeout code
  // surfaces in the envelope. No navigation needed (about:blank).
  const start = await callTool("bob_browser_session_start", {
    target_domain: "example.com",
    target_url: "https://example.com",
    headless: true,
  });
  assert.equal(start.ok, true);
  const sessionId = start.session_id;
  try {
    const startedAt = Date.now();
    const response = await callTool("bob_browser_evaluate", {
      target_domain: "example.com",
      session_id: sessionId,
      expression: "new Promise(function(){})",
      timeout_ms: 400,
    });
    assert.equal(response.ok, false, `expected timeout, got ${JSON.stringify(response)}`);
    assert.equal(response.error.code, "evaluate_timeout");
    assert.ok(Date.now() - startedAt < 6000, "must bound at the forwarded 400ms, not the 90s IPC ceiling");
  } finally {
    await callTool("bob_browser_session_close", {
      target_domain: "example.com",
      session_id: sessionId,
    });
  }
});

test("off-scope navigate is refused with a structured scope error", { skip: !BROWSER_LAUNCHABLE, todo: BROWSER_LAUNCHABLE ? undefined : PATCHRIGHT_SKIP_REASON }, async () => {
  const start = await callTool("bob_browser_session_start", {
    target_domain: "example.com",
    target_url: "https://example.com",
    headless: true,
  });
  assert.equal(start.ok, true);
  const sessionId = start.session_id;
  try {
    const response = await callTool("bob_browser_navigate", {
      target_domain: "example.com",
      session_id: sessionId,
      url: "https://attacker.test/",
    });
    assert.equal(response.ok, false);
    assert.equal(response.error.code, "scope_blocked");
  } finally {
    await callTool("bob_browser_session_close", {
      target_domain: "example.com",
      session_id: sessionId,
    });
  }
});

test("off-scope fetch inside evaluate is refused (sandbox blocks before scope)", { skip: !BROWSER_LAUNCHABLE, todo: BROWSER_LAUNCHABLE ? undefined : PATCHRIGHT_SKIP_REASON }, async () => {
  const start = await callTool("bob_browser_session_start", {
    target_domain: "example.com",
    target_url: "https://example.com",
    headless: true,
  });
  assert.equal(start.ok, true);
  const sessionId = start.session_id;
  try {
    const response = await callTool("bob_browser_evaluate", {
      target_domain: "example.com",
      session_id: sessionId,
      expression: "fetch('https://attacker.test/').then(r => r.text())",
    });
    assert.equal(response.ok, false);
    assert.equal(response.error.code, "evaluate_sandbox_violation");
  } finally {
    await callTool("bob_browser_session_close", {
      target_domain: "example.com",
      session_id: sessionId,
    });
  }
});

// ── Idle-timeout reaping ──

test("idle timeout closes the subprocess", { skip: !BROWSER_LAUNCHABLE, todo: BROWSER_LAUNCHABLE ? undefined : PATCHRIGHT_SKIP_REASON }, async () => {
  // Shrink the idle timeout so we don't wait 5 minutes for the reaper. The
  // setter is the test-harness path; production constants stay at 5/30 min.
  browserSessions.setTimeoutsForTesting({ idleTimeoutMs: 250 });
  try {
    const session = await browserSessions.startSession({
      targetDomain: "example.com",
      targetUrl: "https://example.com",
      headless: true,
    });
    // Wait past the (now short) idle timeout; the reaper should mark the
    // session closed and exit the subprocess.
    await new Promise((r) => setTimeout(r, 1500));
    const entry = browserSessions.getSession(session.session_id);
    assert.ok(!entry || entry.closed, "session should be reaped after idle timeout");
  } finally {
    browserSessions.resetTimeoutsForTesting();
  }
});
