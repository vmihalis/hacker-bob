"use strict";

// PR1 — the trusted `authed_fetch` browser transport for the offensive mass-read producer.
//
// Contract: a SERVER-SIDE-ONLY driver command (`authed_fetch`) issues an authenticated
// request from the real-Chrome page context (so it carries Chrome's TLS/HTTP-2 fingerprint
// and survives a WAF/Cloudflare that 403s safeFetch's bare-Node fingerprint) and returns
// the response body. Cookie auth is injected at session start from the in-process producer
// (never an agent). The agent-facing `evaluate` sandbox (no fetch/XHR) is UNCHANGED, and no
// bob_browser_* MCP tool maps to `authed_fetch`, so an agent cannot reach this transport.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const http = require("node:http");

const browserSessions = require("../mcp/lib/browser-sessions.js");

const BROWSER_LAUNCHABLE =
  !process.env.BOB_SKIP_BROWSER_TESTS && browserSessions.isBrowserLaunchable();

const DRIVER_SRC = fs.readFileSync(path.join(__dirname, "..", "mcp", "browser-driver.js"), "utf8");

// Spawn stub (mirrors browser-egress-wiring.test.js): assert what the subprocess WOULD
// receive in BOB_BROWSER_DRIVER_INIT without launching Chromium.
function makeSpawnStub(captured) {
  const { EventEmitter } = require("node:events");
  return function stub(execPath, args, opts) {
    const child = new EventEmitter();
    child.stdout = new EventEmitter();
    child.stdout.setEncoding = () => {};
    child.stderr = new EventEmitter();
    child.stderr.setEncoding = () => {};
    child.stdin = { writable: true, destroyed: false, write() { return true; }, end() { this.destroyed = true; } };
    child.killed = false;
    child.kill = () => { child.killed = true; };
    captured.push({ env: opts && opts.env ? opts.env : {} });
    setImmediate(() => {
      const init = JSON.parse(opts.env.BOB_BROWSER_DRIVER_INIT);
      child.stdout.emit("data", `${JSON.stringify({ ready: true, session_id: init.session_id })}\n`);
    });
    return child;
  };
}

// ── init-payload threading (no Chromium) ──

test("startSession serializes authCookies into BOB_BROWSER_DRIVER_INIT.auth_cookies", async () => {
  const captured = [];
  const cookies = [{ name: "sid", value: "abc", url: "https://example.com" }];
  const session = await browserSessions.startSession({
    targetDomain: "example.com",
    targetUrl: "https://example.com",
    headless: true,
    authCookies: cookies,
    spawnFn: makeSpawnStub(captured),
    patchrightCheck: () => true,
  });
  assert.equal(captured.length, 1);
  const init = JSON.parse(captured[0].env.BOB_BROWSER_DRIVER_INIT);
  assert.deepEqual(init.auth_cookies, cookies);
  await browserSessions.closeSession(session.session_id).catch(() => {});
});

test("startSession with no authCookies → init.auth_cookies is null (unauthenticated control arm)", async () => {
  const captured = [];
  const session = await browserSessions.startSession({
    targetDomain: "example.com",
    targetUrl: "https://example.com",
    headless: true,
    spawnFn: makeSpawnStub(captured),
    patchrightCheck: () => true,
  });
  const init = JSON.parse(captured[0].env.BOB_BROWSER_DRIVER_INIT);
  assert.equal(init.auth_cookies, null);
  await browserSessions.closeSession(session.session_id).catch(() => {});
});

// ── source-level contracts (no Chromium) ──

test("driver registers the authed_fetch command and an authedFetch method", () => {
  assert.match(DRIVER_SRC, /case "authed_fetch":/);
  assert.match(DRIVER_SRC, /async authedFetch\(args\)/);
});

test("authed_fetch issues an IN-PAGE fetch (real Chrome stack), not a Node client", () => {
  // The fetch expression must run via page.evaluate so it carries the browser TLS
  // fingerprint; a Node-side context.request would be CF-403'd like safeFetch.
  assert.match(DRIVER_SRC, /const expr = `\(async \(\) => \{\s*const __r = await fetch\(/);
  assert.match(DRIVER_SRC, /this\.page\.evaluate\(expr\)/);
  assert.match(DRIVER_SRC, /credentials: "include"/);
});

test("authed_fetch scope-checks the URL and guards origin drift", () => {
  assert.match(DRIVER_SRC, /assertSafeResolvedRequestUrl\(url, this\.targetDomain/);
  assert.match(DRIVER_SRC, /authed_fetch_origin_drift/);
});

test("authed_fetch races a wall-clock timeout (no session pin) and caps the body", () => {
  assert.match(DRIVER_SRC, /authed_fetch_timeout after \$\{timeout\}ms/);
  assert.match(DRIVER_SRC, /MAX_AUTHED_FETCH_BODY_BYTES/);
  assert.match(DRIVER_SRC, /body_truncated/);
});

test("authed_fetch restricts the method to read-intent GET/POST", () => {
  assert.match(DRIVER_SRC, /method !== "GET" && method !== "POST"/);
});

test("session start injects producer cookies via context.addCookies", () => {
  assert.match(DRIVER_SRC, /this\.context\.addCookies\(this\.authCookies\)/);
  assert.match(DRIVER_SRC, /initConfig\.auth_cookies/);
});

test("authed_fetch does NOT follow redirects (redirect:manual — no off-scope auth leak)", () => {
  assert.match(DRIVER_SRC, /redirect: "manual"/);
});

test("authed_fetch stream-reads the body with a cap enforced WHILE reading (no full buffering)", () => {
  assert.match(DRIVER_SRC, /__r\.body\.getReader/);
  assert.match(DRIVER_SRC, /__acc\.length >= __cap/);
});

test("authed_fetch navigates with waitUntil:commit to minimize authed-page execution", () => {
  assert.match(DRIVER_SRC, /waitUntil: "commit"/);
});

test("authed_fetch honors a producer block_internal_hosts policy in BOTH scope checks", () => {
  assert.match(DRIVER_SRC, /block_internal_hosts === true/);
  const checks = DRIVER_SRC.match(/assertSafeResolvedRequestUrl\([^)]*\{ blockInternalHosts \}\)/g) || [];
  assert.ok(checks.length >= 2, "both the fetch URL and the navigated origin must be policy-checked");
});

test("driver scrubs BOB_BROWSER_DRIVER_INIT from env before launch (no child-process auth inheritance)", () => {
  assert.match(DRIVER_SRC, /delete process\.env\.BOB_BROWSER_DRIVER_INIT/);
});

test("the agent-facing evaluate sandbox is UNCHANGED: fetch( still blocked in evaluate", () => {
  // The transport must NOT loosen the agent sandbox — only the trusted authed_fetch path
  // (a separate command with no MCP tool wrapper) issues page-context network IO.
  assert.match(DRIVER_SRC, /const FORBIDDEN_EVAL_PATTERN =\s*\n?\s*\/[^\n]*fetch\\\(/);
  assert.match(DRIVER_SRC, /if \(FORBIDDEN_EVAL_PATTERN\.test\(expression\)\)/);
  assert.match(DRIVER_SRC, /evaluate_sandbox_violation/);
});

test("no bob_browser_* MCP tool exposes authed_fetch (transport is server-side-only)", () => {
  const toolsDir = path.join(__dirname, "..", "mcp", "lib", "tools");
  const offenders = fs.readdirSync(toolsDir)
    .filter((f) => f.startsWith("browser-") && f.endsWith(".js"))
    .filter((f) => fs.readFileSync(path.join(toolsDir, f), "utf8").includes("authed_fetch"));
  assert.deepEqual(offenders, [], "no browser tool wrapper may reference authed_fetch");
});

// ── real-Chromium end-to-end differential (gated on BROWSER_LAUNCHABLE) ──
//
// A local cookie-gated JSON endpoint stands in for a WAF-fronted API: "/" is public
// (so the navigate lands), "/api/listing" returns records ONLY when the auth cookie is
// present (200) else 401. The authed session must read the records (cookie carried by the
// in-page fetch); the no-cookie control must be denied — the mass-read differential.

function startCookieGatedServer() {
  return new Promise((resolve) => {
    const server = http.createServer((req, res) => {
      if (req.url === "/") {
        res.writeHead(200, { "content-type": "text/html" });
        res.end("<!doctype html><html><body>ok</body></html>");
        return;
      }
      if (req.url === "/api/listing") {
        const authed = (req.headers.cookie || "").includes("massread_auth=letmein");
        if (authed) {
          res.writeHead(200, { "content-type": "application/json" });
          res.end(JSON.stringify([{ email: "a@x.test" }, { email: "b@x.test" }, { email: "c@x.test" }]));
        } else {
          res.writeHead(401, { "content-type": "application/json" });
          res.end(JSON.stringify({ error: "unauthorized" }));
        }
        return;
      }
      res.writeHead(404); res.end();
    });
    server.listen(0, "127.0.0.1", () => resolve(server));
  });
}

// The driver's scope guard requires a PUBLIC DNS domain (it refuses raw 127.0.0.1), so a
// hermetic local server is reached via localtest.me, which resolves to 127.0.0.1. Skips
// cleanly where that domain does not resolve to loopback (offline / locked-down DNS).
function lookupLoopback(host) {
  return new Promise((resolve) => {
    require("dns").lookup(host, (err, addr) => resolve(err ? null : addr));
  });
}

test("authed_fetch carries injected cookie auth and captures the body (authed vs control differential)", { skip: !BROWSER_LAUNCHABLE }, async (t) => {
  if (await lookupLoopback("localtest.me") !== "127.0.0.1") {
    t.skip("localtest.me does not resolve to loopback in this environment");
    return;
  }
  const server = await startCookieGatedServer();
  const port = server.address().port;
  const origin = `http://localtest.me:${port}`;
  const listingUrl = `${origin}/api/listing`;
  let authedSession = null;
  let controlSession = null;
  try {
    // attacker arm: cookie injected → reads the records
    authedSession = await browserSessions.startSession({
      targetDomain: "localtest.me",
      targetUrl: origin,
      headless: true,
      authCookies: [{ name: "massread_auth", value: "letmein", url: origin }],
    });
    const authed = await browserSessions.sendCommand(authedSession.session_id, "authed_fetch", {
      url: listingUrl, method: "GET",
    });
    assert.equal(authed.status, 200, JSON.stringify(authed));
    const records = JSON.parse(authed.body);
    assert.equal(records.length, 3, "authed arm reads the full collection");
    assert.equal(authed.body_truncated, false);

    // control arm: no cookie → denied
    controlSession = await browserSessions.startSession({
      targetDomain: "localtest.me",
      targetUrl: origin,
      headless: true,
    });
    const control = await browserSessions.sendCommand(controlSession.session_id, "authed_fetch", {
      url: listingUrl, method: "GET",
    });
    assert.equal(control.status, 401, "control arm is denied the bulk data");
  } finally {
    if (authedSession) await browserSessions.closeSession(authedSession.session_id).catch(() => {});
    if (controlSession) await browserSessions.closeSession(controlSession.session_id).catch(() => {});
    await new Promise((r) => server.close(r));
  }
});

test("authed_fetch refuses an out-of-scope URL", { skip: !BROWSER_LAUNCHABLE }, async (t) => {
  if (await lookupLoopback("localtest.me") !== "127.0.0.1") {
    t.skip("localtest.me does not resolve to loopback in this environment");
    return;
  }
  const session = await browserSessions.startSession({
    targetDomain: "localtest.me",
    targetUrl: "http://localtest.me/",
    headless: true,
  });
  try {
    await assert.rejects(
      () => browserSessions.sendCommand(session.session_id, "authed_fetch", {
        url: "https://example.com/api/listing", method: "GET",
      }),
      (err) => { assert.match(err.message, /scope_blocked/); return true; },
    );
  } finally {
    await browserSessions.closeSession(session.session_id).catch(() => {});
  }
});
