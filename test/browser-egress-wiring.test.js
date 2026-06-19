"use strict";

// Cycle: browser-egress-wiring — egress profiles flow into Patchright launch.
//
// Contract: bob_browser_session_start and bob_browser_session_start_recording
// accept an optional egress_profile name. The tool wrapper resolves the
// profile through egress-profiles.js (file lookup → ${BOB_EGRESS_*} env
// expansion → scheme validation), parses the proxy_url into Playwright's
// { server, username?, password? } shape, and threads it into the subprocess
// init handshake. The driver then composes the proxy with the anti-detection
// stack (channel=chrome, ignoreDefaultArgs, etc.) when calling
// chromium.launch({ proxy }).
//
// Tests use a fixture egress-profiles.json written under a temp HOME so the
// operator's real config is never touched. The egress-profiles file actually
// lives at <projectRoot>/.claude/bob/egress-profiles.json; we override the
// project root by stubbing readEgressProfilesDocument via a temp project tree.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const browserSessions = require("../mcp/lib/browser-sessions.js");
const browserToolsShared = require("../mcp/lib/browser-tools-shared.js");

const PATCHRIGHT_AVAILABLE = browserSessions.isPatchrightAvailable();

function loadHandler(toolName) {
  const moduleSlug = toolName.replace(/^bob_/, "").replace(/_/g, "-");
  // eslint-disable-next-line import/no-dynamic-require, node/no-missing-require
  const mod = require(path.join("..", "mcp", "lib", "tools", `${moduleSlug}.js`));
  return mod.handler;
}

async function callTool(toolName, args) {
  const handler = loadHandler(toolName);
  const raw = await handler(args);
  return JSON.parse(raw);
}

// resolveEgressProfile uses projectRootFromMcp() by default. Point
// BOB_PROJECT_DIR at a temp project root so the default path is exercised
// without touching the operator's real .claude/bob/egress-profiles.json.
function withDefaultEgressConfig(document, fn) {
  const projectRoot = fs.mkdtempSync(path.join(os.tmpdir(), "bob-browser-egress-project-"));
  const filePath = path.join(projectRoot, ".claude", "bob", "egress-profiles.json");
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, `${JSON.stringify(document, null, 2)}\n`, "utf8");
  const previousProjectDir = process.env.BOB_PROJECT_DIR;
  process.env.BOB_PROJECT_DIR = projectRoot;
  const cleanup = () => {
    if (previousProjectDir === undefined) delete process.env.BOB_PROJECT_DIR;
    else process.env.BOB_PROJECT_DIR = previousProjectDir;
    fs.rmSync(projectRoot, { recursive: true, force: true });
  };
  try {
    const result = fn();
    if (result && typeof result.then === "function") {
      return result.finally(cleanup);
    }
    cleanup();
    return result;
  } catch (err) {
    cleanup();
    throw err;
  }
}

// startSession accepts spawnFn for test substitution so we can assert what
// the subprocess WOULD receive without launching Chromium. The stub fakes
// the ready handshake and ignores subsequent commands.
function makeSpawnStub(captured) {
  const { EventEmitter } = require("node:events");
  return function stub(execPath, args, opts) {
    const child = new EventEmitter();
    const writeQueue = [];
    child.stdout = new EventEmitter();
    child.stdout.setEncoding = () => {};
    child.stderr = new EventEmitter();
    child.stderr.setEncoding = () => {};
    child.stdin = {
      writable: true,
      destroyed: false,
      write(chunk) { writeQueue.push(chunk); return true; },
      end() { this.destroyed = true; },
    };
    child.killed = false;
    child.kill = () => { child.killed = true; };
    captured.push({
      execPath,
      args,
      env: opts && opts.env ? opts.env : {},
      writes: writeQueue,
    });
    // Emit ready on the next tick so startSession's awaited promise resolves.
    setImmediate(() => {
      const init = JSON.parse(opts.env.BOB_BROWSER_DRIVER_INIT);
      child.stdout.emit("data", `${JSON.stringify({ ready: true, session_id: init.session_id })}\n`);
    });
    return child;
  };
}

// ── parseProxyUrlForPlaywright unit coverage ──

test("parseProxyUrlForPlaywright: http URL with credentials → server + username + password", () => {
  const parsed = browserToolsShared.parseProxyUrlForPlaywright(
    "http://alice:secret@proxy.example:8080",
  );
  assert.deepEqual(parsed, {
    server: "http://proxy.example:8080",
    username: "alice",
    password: "secret",
  });
});

test("parseProxyUrlForPlaywright: https URL without credentials → server only", () => {
  // Note: Node's URL constructor strips the default port (443 for https, 80
  // for http). Playwright accepts the scheme-implied default, so we don't add
  // it back. A non-default port is preserved as-is.
  const parsed = browserToolsShared.parseProxyUrlForPlaywright("https://proxy.example:8443");
  assert.deepEqual(parsed, { server: "https://proxy.example:8443" });
  const stripped = browserToolsShared.parseProxyUrlForPlaywright("https://proxy.example:443");
  assert.deepEqual(stripped, { server: "https://proxy.example" });
});

test("parseProxyUrlForPlaywright: socks5 URL with credentials → server + creds", () => {
  const parsed = browserToolsShared.parseProxyUrlForPlaywright(
    "socks5://user:pw@socks.example:1080",
  );
  assert.deepEqual(parsed, {
    server: "socks5://socks.example:1080",
    username: "user",
    password: "pw",
  });
});

test("parseProxyUrlForPlaywright: percent-encoded credentials are decoded", () => {
  const parsed = browserToolsShared.parseProxyUrlForPlaywright(
    "http://alice%40acme:pa%24%24word@proxy.example:8080",
  );
  assert.equal(parsed.username, "alice@acme");
  assert.equal(parsed.password, "pa$$word");
});

test("parseProxyUrlForPlaywright: socks5h is REFUSED (Playwright only knows socks5)", () => {
  assert.throws(
    () => browserToolsShared.parseProxyUrlForPlaywright("socks5h://host:1080"),
    (err) => err && err.code === "egress_proxy_url_unsupported_scheme",
  );
});

test("parseProxyUrlForPlaywright: ftp scheme is REFUSED", () => {
  assert.throws(
    () => browserToolsShared.parseProxyUrlForPlaywright("ftp://host:21"),
    (err) => err && err.code === "egress_proxy_url_unsupported_scheme",
  );
});

test("parseProxyUrlForPlaywright: null input → null output (no proxy = direct)", () => {
  assert.equal(browserToolsShared.parseProxyUrlForPlaywright(null), null);
});

// ── resolveBrowserEgressProfile envelope shape ──

test("resolveBrowserEgressProfile: omitted name → ok:true with proxy:null (direct)", () => {
  const result = browserToolsShared.resolveBrowserEgressProfile(undefined);
  assert.equal(result.ok, true);
  assert.equal(result.proxy, null);
  assert.equal(result.profile.name, "default");
  assert.equal(result.profile.proxy_configured, false);
});

test('resolveBrowserEgressProfile: "default" → ok:true with proxy:null (direct, no file read)', () => {
  const result = browserToolsShared.resolveBrowserEgressProfile("default");
  assert.equal(result.ok, true);
  assert.equal(result.proxy, null);
  assert.equal(result.profile.name, "default");
});

test("resolveBrowserEgressProfile: invalid name shape → egress_profile_invalid_name (no file read)", () => {
  const result = browserToolsShared.resolveBrowserEgressProfile("../etc/passwd");
  assert.equal(result.ok, false);
  const parsed = JSON.parse(result.envelope);
  assert.equal(parsed.ok, false);
  assert.equal(parsed.error.code, "egress_profile_invalid_name");
});

test("resolveBrowserEgressProfile: nonexistent profile → egress_profile_not_found", () => {
  withDefaultEgressConfig({
    version: 1,
    profiles: [
      { name: "default", proxy_url: null, region: null, description: "Direct", enabled: true },
    ],
  }, () => {
    const result = browserToolsShared.resolveBrowserEgressProfile("nonexistent");
    assert.equal(result.ok, false);
    const parsed = JSON.parse(result.envelope);
    assert.equal(parsed.error.code, "egress_profile_not_found");
    assert.equal(parsed.error.egress_profile, "nonexistent");
  });
});

test("resolveBrowserEgressProfile: disabled profile → egress_profile_disabled", () => {
  withDefaultEgressConfig({
    version: 1,
    profiles: [
      { name: "default", proxy_url: null, region: null, description: "Direct", enabled: true },
      {
        name: "disabled-one",
        proxy_url: "${BOB_EGRESS_DISABLED_ONE}",
        region: "DE",
        description: "Disabled fixture",
        enabled: false,
      },
    ],
  }, () => {
    const result = browserToolsShared.resolveBrowserEgressProfile("disabled-one");
    assert.equal(result.ok, false);
    const parsed = JSON.parse(result.envelope);
    assert.equal(parsed.error.code, "egress_profile_disabled");
  });
});

test("resolveBrowserEgressProfile: env var not set → egress_profile_env_missing", () => {
  withDefaultEgressConfig({
    version: 1,
    profiles: [
      { name: "default", proxy_url: null, region: null, description: "Direct", enabled: true },
      {
        name: "env-needed",
        proxy_url: "${BOB_EGRESS_TEST_NEVER_SET_12345}",
        region: "FR",
        description: "Needs env",
        enabled: true,
      },
    ],
  }, () => {
    // Make sure the env var is genuinely missing for this run.
    delete process.env.BOB_EGRESS_TEST_NEVER_SET_12345;
    const result = browserToolsShared.resolveBrowserEgressProfile("env-needed");
    assert.equal(result.ok, false);
    const parsed = JSON.parse(result.envelope);
    assert.equal(parsed.error.code, "egress_profile_env_missing");
  });
});

test("resolveBrowserEgressProfile: clean resolve → ok:true with parsed proxy", () => {
  withDefaultEgressConfig({
    version: 1,
    profiles: [
      { name: "default", proxy_url: null, region: null, description: "Direct", enabled: true },
      {
        name: "operator",
        proxy_url: "${BOB_EGRESS_WIRING_TEST_PROXY}",
        region: "EU",
        description: "Test proxy",
        enabled: true,
      },
    ],
  }, () => {
    process.env.BOB_EGRESS_WIRING_TEST_PROXY = "http://alice:secret@proxy.test:3128";
    try {
      const result = browserToolsShared.resolveBrowserEgressProfile("operator");
      assert.equal(result.ok, true);
      assert.deepEqual(result.proxy, {
        server: "http://proxy.test:3128",
        username: "alice",
        password: "secret",
      });
      assert.equal(result.profile.name, "operator");
      assert.equal(result.profile.region, "EU");
      assert.equal(result.profile.proxy_configured, true);
    } finally {
      delete process.env.BOB_EGRESS_WIRING_TEST_PROXY;
    }
  });
});

// ── tool wrapper envelopes (patchright-independent) ──
//
// These call the real handler. When patchright is missing the handler returns
// patchright_unavailable BEFORE egress resolution runs, so we cannot exercise
// the egress error codes through the handler. Skip in that case — the
// resolveBrowserEgressProfile unit tests above cover the error envelope shape
// (the handler just returns whatever envelope the resolver hands back).

test("bob_browser_session_start: no egress_profile arg → ok with egress_profile_resolved=default and no proxy passed", { skip: !PATCHRIGHT_AVAILABLE }, async () => {
  const captured = [];
  const originalStartSession = browserSessions.startSession;
  browserSessions.startSession = async (opts) => {
    captured.push(opts);
    return {
      session_id: "bs-test-1",
      target_domain: opts.targetDomain,
      target_url: opts.targetUrl,
      driver_session_id: "bs-test-1",
      headless: opts.headless,
      record_mode: opts.recordMode === true,
    };
  };
  try {
    const response = await callTool("bob_browser_session_start", {
      target_domain: "example.com",
      target_url: "https://example.com",
      headless: true,
    });
    assert.equal(response.ok, true, JSON.stringify(response));
    assert.equal(response.egress_profile_resolved, "default");
    assert.equal(response.proxy_configured, false);
    assert.equal(captured.length, 1);
    assert.equal(captured[0].proxy, null);
  } finally {
    browserSessions.startSession = originalStartSession;
  }
});

test("bob_browser_session_start: egress_profile=default → ok with same direct behavior", { skip: !PATCHRIGHT_AVAILABLE }, async () => {
  const captured = [];
  const originalStartSession = browserSessions.startSession;
  browserSessions.startSession = async (opts) => {
    captured.push(opts);
    return {
      session_id: "bs-test-2",
      target_domain: opts.targetDomain,
      target_url: opts.targetUrl,
      driver_session_id: "bs-test-2",
      headless: opts.headless,
      record_mode: opts.recordMode === true,
    };
  };
  try {
    const response = await callTool("bob_browser_session_start", {
      target_domain: "example.com",
      target_url: "https://example.com",
      headless: true,
      egress_profile: "default",
    });
    assert.equal(response.ok, true);
    assert.equal(response.egress_profile_resolved, "default");
    assert.equal(captured[0].proxy, null);
  } finally {
    browserSessions.startSession = originalStartSession;
  }
});

test("bob_browser_session_start: nonexistent profile → egress_profile_not_found, subprocess NOT spawned", { skip: !PATCHRIGHT_AVAILABLE }, async () => {
  await withDefaultEgressConfig({
    version: 1,
    profiles: [
      { name: "default", proxy_url: null, region: null, description: "Direct", enabled: true },
    ],
  }, async () => {
    let spawnCalled = 0;
    const originalStartSession = browserSessions.startSession;
    browserSessions.startSession = async () => { spawnCalled += 1; throw new Error("should not be called"); };
    try {
      const response = await callTool("bob_browser_session_start", {
        target_domain: "example.com",
        target_url: "https://example.com",
        headless: true,
        egress_profile: "nonexistent",
      });
      assert.equal(response.ok, false);
      assert.equal(response.error.code, "egress_profile_not_found");
      assert.equal(spawnCalled, 0, "startSession must NOT be called when egress resolution fails");
    } finally {
      browserSessions.startSession = originalStartSession;
    }
  });
});

test("bob_browser_session_start: disabled profile → egress_profile_disabled, subprocess NOT spawned", { skip: !PATCHRIGHT_AVAILABLE }, async () => {
  await withDefaultEgressConfig({
    version: 1,
    profiles: [
      { name: "default", proxy_url: null, region: null, description: "Direct", enabled: true },
      {
        name: "disabled-one",
        proxy_url: "${BOB_EGRESS_DISABLED_ONE}",
        region: "DE",
        description: "Disabled fixture",
        enabled: false,
      },
    ],
  }, async () => {
    let spawnCalled = 0;
    const originalStartSession = browserSessions.startSession;
    browserSessions.startSession = async () => { spawnCalled += 1; throw new Error("should not be called"); };
    try {
      const response = await callTool("bob_browser_session_start", {
        target_domain: "example.com",
        target_url: "https://example.com",
        headless: true,
        egress_profile: "disabled-one",
      });
      assert.equal(response.ok, false);
      assert.equal(response.error.code, "egress_profile_disabled");
      assert.equal(spawnCalled, 0);
    } finally {
      browserSessions.startSession = originalStartSession;
    }
  });
});

test("bob_browser_session_start: env var unset → egress_profile_env_missing, subprocess NOT spawned", { skip: !PATCHRIGHT_AVAILABLE }, async () => {
  await withDefaultEgressConfig({
    version: 1,
    profiles: [
      { name: "default", proxy_url: null, region: null, description: "Direct", enabled: true },
      {
        name: "env-required",
        proxy_url: "${BOB_EGRESS_TEST_NEVER_SET_67890}",
        region: "JP",
        description: "Needs env",
        enabled: true,
      },
    ],
  }, async () => {
    delete process.env.BOB_EGRESS_TEST_NEVER_SET_67890;
    let spawnCalled = 0;
    const originalStartSession = browserSessions.startSession;
    browserSessions.startSession = async () => { spawnCalled += 1; throw new Error("should not be called"); };
    try {
      const response = await callTool("bob_browser_session_start", {
        target_domain: "example.com",
        target_url: "https://example.com",
        headless: true,
        egress_profile: "env-required",
      });
      assert.equal(response.ok, false);
      assert.equal(response.error.code, "egress_profile_env_missing");
      assert.equal(spawnCalled, 0);
    } finally {
      browserSessions.startSession = originalStartSession;
    }
  });
});

test("bob_browser_session_start: resolved profile → startSession receives parsed proxy and response carries egress_profile_resolved", { skip: !PATCHRIGHT_AVAILABLE }, async () => {
  await withDefaultEgressConfig({
    version: 1,
    profiles: [
      { name: "default", proxy_url: null, region: null, description: "Direct", enabled: true },
      {
        name: "operator",
        proxy_url: "${BOB_EGRESS_WIRING_RESOLVED}",
        region: "EU",
        description: "Test proxy",
        enabled: true,
      },
    ],
  }, async () => {
    process.env.BOB_EGRESS_WIRING_RESOLVED = "http://bob:hunter2@proxy.test:3128";
    const captured = [];
    const originalStartSession = browserSessions.startSession;
    browserSessions.startSession = async (opts) => {
      captured.push(opts);
      return {
        session_id: "bs-test-3",
        target_domain: opts.targetDomain,
        target_url: opts.targetUrl,
        driver_session_id: "bs-test-3",
        headless: opts.headless,
        record_mode: opts.recordMode === true,
      };
    };
    try {
      const response = await callTool("bob_browser_session_start", {
        target_domain: "example.com",
        target_url: "https://example.com",
        headless: true,
        egress_profile: "operator",
      });
      assert.equal(response.ok, true, JSON.stringify(response));
      assert.equal(response.egress_profile_resolved, "operator");
      assert.equal(response.egress_region, "EU");
      assert.equal(response.proxy_configured, true);
      assert.equal(captured.length, 1);
      assert.deepEqual(captured[0].proxy, {
        server: "http://proxy.test:3128",
        username: "bob",
        password: "hunter2",
      });
    } finally {
      browserSessions.startSession = originalStartSession;
      delete process.env.BOB_EGRESS_WIRING_RESOLVED;
    }
  });
});

// ── bob_browser_session_start_recording mirrors session_start ──

test("bob_browser_session_start_recording: resolved profile → startSession receives parsed proxy + record_mode and response carries egress_profile_resolved", { skip: !PATCHRIGHT_AVAILABLE }, async () => {
  await withDefaultEgressConfig({
    version: 1,
    profiles: [
      { name: "default", proxy_url: null, region: null, description: "Direct", enabled: true },
      {
        name: "rec-op",
        proxy_url: "${BOB_EGRESS_WIRING_REC}",
        region: "EU",
        description: "Rec proxy",
        enabled: true,
      },
    ],
  }, async () => {
    process.env.BOB_EGRESS_WIRING_REC = "socks5://carol:rocks@socks.test:1080";
    const captured = [];
    const originalStartSession = browserSessions.startSession;
    browserSessions.startSession = async (opts) => {
      captured.push(opts);
      return {
        session_id: "bs-test-rec",
        target_domain: opts.targetDomain,
        target_url: opts.targetUrl,
        driver_session_id: "bs-test-rec",
        headless: opts.headless,
        record_mode: true,
      };
    };
    try {
      const response = await callTool("bob_browser_session_start_recording", {
        target_domain: "example.com",
        target_url: "https://example.com",
        headless: true,
        egress_profile: "rec-op",
      });
      assert.equal(response.ok, true, JSON.stringify(response));
      assert.equal(response.record_mode, true);
      assert.equal(response.egress_profile_resolved, "rec-op");
      assert.equal(response.egress_region, "EU");
      assert.equal(response.proxy_configured, true);
      assert.equal(captured.length, 1);
      assert.equal(captured[0].recordMode, true);
      assert.deepEqual(captured[0].proxy, {
        server: "socks5://socks.test:1080",
        username: "carol",
        password: "rocks",
      });
    } finally {
      browserSessions.startSession = originalStartSession;
      delete process.env.BOB_EGRESS_WIRING_REC;
    }
  });
});

test("bob_browser_session_start_recording: nonexistent profile → egress_profile_not_found, subprocess NOT spawned", { skip: !PATCHRIGHT_AVAILABLE }, async () => {
  await withDefaultEgressConfig({
    version: 1,
    profiles: [
      { name: "default", proxy_url: null, region: null, description: "Direct", enabled: true },
    ],
  }, async () => {
    let spawnCalled = 0;
    const originalStartSession = browserSessions.startSession;
    browserSessions.startSession = async () => { spawnCalled += 1; throw new Error("should not be called"); };
    try {
      const response = await callTool("bob_browser_session_start_recording", {
        target_domain: "example.com",
        target_url: "https://example.com",
        headless: true,
        egress_profile: "nonexistent",
      });
      assert.equal(response.ok, false);
      assert.equal(response.error.code, "egress_profile_not_found");
      assert.equal(spawnCalled, 0);
    } finally {
      browserSessions.startSession = originalStartSession;
    }
  });
});

// ── startSession handshake: spawn-stub asserts proxy lands in subprocess env ──
//
// This bypasses the handler stub above and exercises the real
// browserSessions.startSession with an injected spawnFn so we can confirm
// the BOB_BROWSER_DRIVER_INIT env var carries proxy.server etc. This is what
// the subprocess would actually see at boot.

test("browserSessions.startSession: proxy is serialized into BOB_BROWSER_DRIVER_INIT", { skip: !PATCHRIGHT_AVAILABLE }, async () => {
  const captured = [];
  const session = await browserSessions.startSession({
    targetDomain: "example.com",
    targetUrl: "https://example.com",
    headless: true,
    proxy: { server: "http://proxy.test:3128", username: "alice", password: "secret" },
    spawnFn: makeSpawnStub(captured),
    patchrightCheck: () => true,
  });
  assert.equal(captured.length, 1);
  const init = JSON.parse(captured[0].env.BOB_BROWSER_DRIVER_INIT);
  assert.deepEqual(init.proxy, {
    server: "http://proxy.test:3128",
    username: "alice",
    password: "secret",
  });
  assert.equal(init.target_domain, "example.com");
  // Clean up the tracked entry so other tests don't see a stale slot.
  await browserSessions.closeSession(session.session_id).catch(() => {});
});

test("browserSessions.startSession: no proxy → BOB_BROWSER_DRIVER_INIT carries proxy:null", { skip: !PATCHRIGHT_AVAILABLE }, async () => {
  const captured = [];
  const session = await browserSessions.startSession({
    targetDomain: "example.com",
    targetUrl: "https://example.com",
    headless: true,
    spawnFn: makeSpawnStub(captured),
    patchrightCheck: () => true,
  });
  assert.equal(captured.length, 1);
  const init = JSON.parse(captured[0].env.BOB_BROWSER_DRIVER_INIT);
  assert.equal(init.proxy, null);
  await browserSessions.closeSession(session.session_id).catch(() => {});
});

// ── IPC deadline tracks the command's operation timeout ──

test("callBrowser forwards an explicit positive timeout_ms to the IPC deadline (+ margin), and omits it otherwise", async () => {
  const calls = [];
  const original = browserSessions.sendCommand;
  browserSessions.sendCommand = async (sessionId, command, args, options) => {
    calls.push({ command, options });
    return { ok: true };
  };
  try {
    await browserToolsShared.callBrowser("navigate", "bs-x", { url: "https://example.com", timeout_ms: 8000 });
    await browserToolsShared.callBrowser("snapshot", "bs-x", {});
    await browserToolsShared.callBrowser("wait_for", "bs-x", { timeout_ms: 0 });
  } finally {
    browserSessions.sendCommand = original;
  }
  // navigate carried an explicit timeout → IPC deadline = timeout + margin.
  assert.deepEqual(calls[0].options, { timeoutMs: 8000 + browserToolsShared.IPC_DEADLINE_MARGIN_MS });
  // snapshot has no operation timeout → falls back to the registry default.
  assert.equal(calls[1].options, undefined);
  // timeout_ms: 0 (Playwright "disable") is not a positive bound → default.
  assert.equal(calls[2].options, undefined);
});

test("sendCommand rejects at the passed IPC deadline, not the 90s ceiling, when the subprocess never replies", async () => {
  const captured = [];
  const session = await browserSessions.startSession({
    targetDomain: "example.com",
    targetUrl: "https://example.com",
    headless: true,
    spawnFn: makeSpawnStub(captured), // ready handshake only; never answers commands
    patchrightCheck: () => true,
  });
  try {
    const start = Date.now();
    await assert.rejects(
      () => browserSessions.sendCommand(session.session_id, "navigate", {}, { timeoutMs: 300 }),
      (err) => {
        assert.match(err.message, /browser_command_timeout:navigate/);
        return true;
      },
    );
    const elapsed = Date.now() - start;
    // Proves the deadline honored the passed 300ms, not COMMAND_TIMEOUT_MS (90s).
    assert.ok(elapsed < 5000, `expected fast IPC timeout, took ${elapsed}ms`);
  } finally {
    await browserSessions.closeSession(session.session_id).catch(() => {});
  }
});

// ── driver-side per-operation timeout bounds ──

test("browser-driver clamps non-positive timeout_ms to the per-operation default", () => {
  const driverSrc = fs.readFileSync(path.join(__dirname, "..", "mcp", "browser-driver.js"), "utf8");
  // The clamp must guard timeout_ms with a `> 0` check so an agent-supplied 0
  // (which Playwright treats as "no timeout") cannot disable the op bound.
  assert.match(driverSrc, /function resolveOpTimeout\(args, defaultMs\)/);
  assert.match(driverSrc, /Number\.isFinite\(requested\)\s*&&\s*requested\s*>\s*0/);
  // navigate and wait_for must route their timeout through the clamp.
  assert.match(driverSrc, /resolveOpTimeout\(args, DEFAULT_NAVIGATE_TIMEOUT_MS\)/);
  assert.match(driverSrc, /resolveOpTimeout\(args, DEFAULT_WAIT_FOR_TIMEOUT_MS\)/);
});

test("browser-driver bounds page.evaluate with a wall-clock race", () => {
  const driverSrc = fs.readFileSync(path.join(__dirname, "..", "mcp", "browser-driver.js"), "utf8");
  // page.evaluate takes no Playwright timeout, so it must be raced against a
  // timer or a runaway expression pins the session to the 90s IPC ceiling.
  assert.match(driverSrc, /Promise\.race\(\[\s*evalPromise/);
  assert.match(driverSrc, /evaluate_timeout after \$\{timeout\}ms/);
  assert.match(driverSrc, /resolveOpTimeout\(args, DEFAULT_EVALUATE_TIMEOUT_MS\)/);
});

test("browser-driver passes an explicit timeout to page.screenshot", () => {
  const driverSrc = fs.readFileSync(path.join(__dirname, "..", "mcp", "browser-driver.js"), "utf8");
  assert.match(driverSrc, /\.screenshot\(\{[^}]*timeout:\s*DEFAULT_SCREENSHOT_TIMEOUT_MS/);
});

test("browser-driver evaluate returns a fast evaluate_timeout for a never-resolving expression", { skip: !PATCHRIGHT_AVAILABLE }, async () => {
  // Real Chromium; no navigation needed — the initial page is about:blank.
  const session = await browserSessions.startSession({
    targetDomain: "example.com",
    targetUrl: "https://example.com",
    headless: true,
  });
  try {
    const start = Date.now();
    await assert.rejects(
      () => browserSessions.sendCommand(
        session.session_id,
        "evaluate",
        { expression: "new Promise(function(){})", timeout_ms: 400 },
      ),
      (err) => {
        assert.match(err.message, /evaluate_timeout|evaluate_failed/);
        return true;
      },
    );
    const elapsed = Date.now() - start;
    // The driver race fires at ~400ms; the 90s IPC ceiling is never reached.
    assert.ok(elapsed < 6000, `expected fast evaluate timeout, took ${elapsed}ms`);
  } finally {
    await browserSessions.closeSession(session.session_id).catch(() => {});
  }
});

// ── browser-driver source-level contracts (no Chromium required) ──

test("browser-driver.js threads proxy into chromium.launch({ proxy }) (source check)", () => {
  const driverSrc = fs.readFileSync(
    path.join(__dirname, "..", "mcp", "browser-driver.js"),
    "utf8",
  );
  // The driver must set launchOptions.proxy from the init payload's proxy
  // field. Regress on this and operators with --egress still ship browser
  // sessions over the default IP (the gap the cycle exists to close).
  assert.ok(
    /launchOptions\.proxy\s*=\s*this\.proxy/.test(driverSrc),
    "browser-driver.js must thread this.proxy into chromium.launch options",
  );
  // The proxy must NOT replace any of the anti-detection options. ignoreDefaultArgs
  // and the AutomationControlled disable flag must remain present.
  assert.ok(
    /ignoreDefaultArgs:\s*\["--enable-automation"\]/.test(driverSrc),
    "browser-driver.js must keep ignoreDefaultArgs anti-detection option",
  );
  assert.ok(
    /--disable-blink-features=AutomationControlled/.test(driverSrc),
    "browser-driver.js must keep AutomationControlled disable flag",
  );
  // The bootstrap must accept the proxy field from BOB_BROWSER_DRIVER_INIT.
  assert.ok(
    /initConfig\.proxy/.test(driverSrc),
    "browser-driver.js bootstrap must read initConfig.proxy",
  );
});

// ── Schema surface contracts ──

test("bob_browser_session_start inputSchema declares optional egress_profile string", () => {
  const tool = require("../mcp/lib/tools/browser-session-start.js");
  const prop = tool.inputSchema.properties.egress_profile;
  assert.ok(prop, "egress_profile must be in inputSchema.properties");
  assert.equal(prop.type, "string");
  assert.ok(prop.pattern, "egress_profile must declare a pattern");
  assert.ok(!tool.inputSchema.required.includes("egress_profile"), "egress_profile must not be required");
});

test("bob_browser_session_start_recording inputSchema declares optional egress_profile string", () => {
  const tool = require("../mcp/lib/tools/browser-session-start-recording.js");
  const prop = tool.inputSchema.properties.egress_profile;
  assert.ok(prop, "egress_profile must be in inputSchema.properties");
  assert.equal(prop.type, "string");
  assert.ok(prop.pattern, "egress_profile must declare a pattern");
  assert.ok(!tool.inputSchema.required.includes("egress_profile"), "egress_profile must not be required");
});

// ── Patchright-gated smoke: real Chromium dials a fake proxy ──
//
// Skips if patchright is missing. Uses a deliberately unreachable proxy
// (127.0.0.1:1 — port 1 is reserved/never listening). The launch must error
// in a way that proves Chromium tried to dial the proxy (timeout, connection
// refused). Anything else (e.g. successful navigation, off-target IP) would
// mean the proxy config was dropped.

test("patchright smoke: Chromium attempts to dial the configured proxy (connection error proves the proxy was honored)", { skip: !PATCHRIGHT_AVAILABLE }, async () => {
  await withDefaultEgressConfig({
    version: 1,
    profiles: [
      { name: "default", proxy_url: null, region: null, description: "Direct", enabled: true },
      {
        name: "smoke-proxy",
        proxy_url: "${BOB_EGRESS_WIRING_SMOKE}",
        region: "TEST",
        description: "Unreachable proxy for smoke test",
        enabled: true,
      },
    ],
  }, async () => {
    process.env.BOB_EGRESS_WIRING_SMOKE = "http://127.0.0.1:1";
    let sessionId = null;
    try {
      const response = await callTool("bob_browser_session_start", {
        target_domain: "example.com",
        target_url: "https://example.com",
        headless: true,
        egress_profile: "smoke-proxy",
      });
      // Two acceptable outcomes that both prove the proxy was honored:
      //   (a) session_start fails with a navigation/launch error mentioning
      //       the proxy / connection. browser_launch_failed surfaces the
      //       underlying Chromium error including ERR_PROXY_* codes.
      //   (b) session_start succeeds (launch with a proxy is async; the dial
      //       happens on first navigation), in which case the FIRST navigate
      //       fails with a proxy-related error.
      if (response.ok === false) {
        // Accept any error that mentions proxy, connection, network, or
        // refers to the ERR_ tag Chromium prints for proxy failures.
        const message = JSON.stringify(response.error);
        assert.match(
          message,
          /proxy|ERR_|connect|tunnel|browser_launch_failed/i,
          `expected proxy-related error, got: ${message}`,
        );
        return;
      }
      sessionId = response.session_id;
      const nav = await callTool("bob_browser_navigate", {
        target_domain: "example.com",
        session_id: sessionId,
        url: "https://example.com/",
      });
      assert.equal(nav.ok, false, `navigation through unreachable proxy should fail; got: ${JSON.stringify(nav)}`);
      assert.match(
        JSON.stringify(nav.error),
        /proxy|ERR_|connect|tunnel|net::|timeout/i,
        `expected proxy-related navigation error, got: ${JSON.stringify(nav.error)}`,
      );
    } finally {
      if (sessionId) {
        await callTool("bob_browser_session_close", {
          target_domain: "example.com",
          session_id: sessionId,
        }).catch(() => {});
      }
      delete process.env.BOB_EGRESS_WIRING_SMOKE;
    }
  });
});
