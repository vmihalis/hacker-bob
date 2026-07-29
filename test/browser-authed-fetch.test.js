"use strict";

// PR1 — the trusted `authed_fetch` browser transport for the offensive mass-read producer.
//
// Contract: a SERVER-SIDE-ONLY driver command (`authed_fetch`) issues an authenticated
// request from the real-Chrome page context (so it carries Chrome's TLS/HTTP-2 fingerprint
// and survives a WAF/Cloudflare that 403s safeFetch's bare-Node fingerprint) and returns
// the response body. Cookie auth is injected via a second server-side-only command
// (`set_auth_cookies`) over stdin — never the process environment, never an agent. The
// agent-facing `evaluate` sandbox (no fetch/XHR) is UNCHANGED, and no bob_browser_* MCP tool
// maps to either command, so an agent cannot reach this transport.
//
// Round-3 hardening covered here: DNS-rebinding pin (--host-resolver-rules), per-cookie scope
// validation, byte-accurate body cap, in-page AbortSignal self-abort, native-fetch capture.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const http = require("node:http");

const browserSessions = require("../mcp/lib/browser-sessions.js");

const BROWSER_LAUNCHABLE =
  !process.env.BOB_SKIP_BROWSER_TESTS && browserSessions.isBrowserLaunchable();

const DRIVER_SRC = fs.readFileSync(path.join(__dirname, "..", "mcp", "browser-driver.js"), "utf8");
const MAX_AUTHED_FETCH_BODY_BYTES = 2 * 1024 * 1024;

// Spawn stub (mirrors browser-egress-wiring.test.js): assert what the subprocess WOULD
// receive WITHOUT launching Chromium. It captures the spawn env + every stdin command line,
// and auto-acks each command so startSession (which now sends set_auth_cookies over stdin)
// can complete.
function makeSpawnStub(captured) {
  const { EventEmitter } = require("node:events");
  return function stub(execPath, args, opts) {
    const child = new EventEmitter();
    child.stdout = new EventEmitter();
    child.stdout.setEncoding = () => {};
    child.stderr = new EventEmitter();
    child.stderr.setEncoding = () => {};
    const record = { env: opts && opts.env ? opts.env : {}, args: args || [], commands: [] };
    child.stdin = {
      writable: true,
      destroyed: false,
      write(chunk) {
        const line = String(chunk).trim();
        try {
          const msg = JSON.parse(line);
          if (msg && msg.command_id) {
            record.commands.push({ command: msg.command, args: msg.args });
            // Auto-ack pending commands so sendCommand resolves.
            if (!String(msg.command_id).startsWith("close-")) {
              setImmediate(() => {
                const count = msg.args && Array.isArray(msg.args.cookies) ? msg.args.cookies.length : 0;
                child.stdout.emit(
                  "data",
                  `${JSON.stringify({ command_id: msg.command_id, result: { ok: true, count } })}\n`,
                );
              });
            }
          }
        } catch (e) { /* not a command line */ }
        return true;
      },
      end() { this.destroyed = true; },
    };
    child.killed = false;
    child.kill = () => { child.killed = true; };
    captured.push(record);
    setImmediate(() => {
      const init = JSON.parse(opts.env.BOB_BROWSER_DRIVER_INIT);
      child.stdout.emit("data", `${JSON.stringify({ ready: true, session_id: init.session_id })}\n`);
    });
    return child;
  };
}

// ── cookie auth travels over stdin, NEVER the env (no Chromium) ──

test("startSession does NOT put auth cookies in the child process env", async () => {
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
  const init = JSON.parse(captured[0].env.BOB_BROWSER_DRIVER_INIT);
  assert.equal(init.auth_cookies, undefined, "cookies must not be serialized into the init env");
  await browserSessions.closeSession(session.session_id).catch(() => {});
});

test("startSession sends auth cookies via the set_auth_cookies stdin command", async () => {
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
  const setAuth = captured[0].commands.find((c) => c.command === "set_auth_cookies");
  assert.ok(setAuth, "a set_auth_cookies command must be sent over stdin");
  assert.deepEqual(setAuth.args.cookies, cookies);
  await browserSessions.closeSession(session.session_id).catch(() => {});
});

test("startSession with no authCookies sends no set_auth_cookies command (control arm)", async () => {
  const captured = [];
  const session = await browserSessions.startSession({
    targetDomain: "example.com",
    targetUrl: "https://example.com",
    headless: true,
    spawnFn: makeSpawnStub(captured),
    patchrightCheck: () => true,
  });
  const setAuth = captured[0].commands.find((c) => c.command === "set_auth_cookies");
  assert.equal(setAuth, undefined, "control arm must not inject any cookies");
  await browserSessions.closeSession(session.session_id).catch(() => {});
});

// ── source-level contracts (no Chromium) ──

test("driver registers authed_fetch + set_auth_cookies commands and methods", () => {
  assert.match(DRIVER_SRC, /case "authed_fetch":/);
  assert.match(DRIVER_SRC, /async authedFetch\(args\)/);
  assert.match(DRIVER_SRC, /case "set_auth_cookies":/);
  assert.match(DRIVER_SRC, /async setAuthCookies\(args\)/);
});

test("authed_fetch issues an IN-PAGE fetch (real Chrome stack), not a Node client", () => {
  // The fetch expression must run via page.evaluate so it carries the browser TLS
  // fingerprint; a Node-side context.request would be CF-403'd like safeFetch.
  assert.match(DRIVER_SRC, /this\.page\.evaluate\(expr\)/);
  assert.match(DRIVER_SRC, /credentials: "include"/);
});

test("authed_fetch documents page-controlled fetch as an accepted residual (not a broken native-capture)", () => {
  // Round-3: a "native fetch capture" was tried and reverted — it breaks under the Patchright
  // stealth driver. The residual is accepted with compensating controls (commit-nav +
  // differential). Guard against silently reintroducing the capture.
  assert.match(DRIVER_SRC, /ACCEPTED RESIDUAL — page-controlled fetch/);
  assert.doesNotMatch(DRIVER_SRC, /__bobNativeFetch/, "the unreliable native-fetch capture must stay removed");
});

test("authed_fetch self-aborts the in-page fetch at the deadline and surfaces a timeout sentinel", () => {
  // Aborts AT the timeout (not timeout+grace) so the authenticated request is actually
  // cancelled, and converts the abort to a deterministic { __timeout: true } sentinel.
  assert.match(DRIVER_SRC, /AbortSignal\.timeout\(\$\{timeout\}\)/);
  assert.match(DRIVER_SRC, /e\.name === "TimeoutError" \|\| e\.name === "AbortError"/);
  assert.match(DRIVER_SRC, /return \{ __timeout: true \}/);
  assert.match(DRIVER_SRC, /if \(result && result\.__timeout\)/);
  assert.doesNotMatch(DRIVER_SRC, /inPageAbortMs/, "the timeout+grace fudge must be gone");
});

test("authed_fetch caps the body in BYTES, not UTF-16 code units", () => {
  // Regression for the round-2 finding: __acc.length (UTF-16) → byteLength on Uint8Array.
  assert.match(DRIVER_SRC, /__chunk\.byteLength/);
  assert.match(DRIVER_SRC, /__bytes \+ __chunk\.byteLength > __cap/);
  assert.match(DRIVER_SRC, /__chunk\.subarray\(0, __cap - __bytes\)/);
  assert.doesNotMatch(DRIVER_SRC, /__acc\.length >= __cap/, "the UTF-16 length cap must be gone");
});

test("set_auth_cookies validates EACH cookie's target host against target_domain", () => {
  assert.match(DRIVER_SRC, /assertSafeRequestUrl\(scopeUrl, this\.targetDomain\)/);
  assert.match(DRIVER_SRC, /set_auth_cookies_scope_blocked/);
});

test("set_auth_cookies rejects the ambiguous both-url-and-domain cookie form", () => {
  assert.match(DRIVER_SRC, /must set EITHER url OR domain, not both/);
});

test("driver DNS-pins the target host via --host-resolver-rules and records internal-ness", () => {
  assert.match(DRIVER_SRC, /resolveSafeAddress\(pinHost/);
  assert.match(DRIVER_SRC, /--host-resolver-rules=/);
  assert.match(DRIVER_SRC, /MAP \$\{pinHost\} \$\{ipForRule\}/);
  // round-4: the pin records {address, internal} (not a bare address), so a private pinned IP
  // cannot satisfy block_internal_hosts by presence alone.
  assert.match(DRIVER_SRC, /this\.pinnedHosts\.set\(pinHost, \{ address, internal: isBlockedInternalHost\(address\) \}\)/);
});

test("authed_fetch REQUIRES the DNS pin on every call (not opt-in) + internal/proxy guards", () => {
  // round-5: the pin is enforced unconditionally on the non-proxied path (a credentialed fetch
  // must never ride a rebound hostname), with the internal-IP check additionally under
  // block_internal_hosts, and a proxy refusing only under block_internal_hosts.
  assert.match(DRIVER_SRC, /was not DNS-pinned at launch; a credentialed fetch must target the pinned host/);
  assert.match(DRIVER_SRC, /if \(blockInternalHosts && pin\.internal\)/); // internal-IP guard gated on policy
  assert.match(DRIVER_SRC, /pins to an internal address/);
  assert.match(DRIVER_SRC, /cannot enforce block_internal_hosts through an egress proxy/);
});

test("authed_fetch requests are NOT recorded into the agent-readable request log (no auth leak)", () => {
  // round-6/7: a per-op flag suppresses the priming nav + fetch; once cookies are injected the
  // WHOLE credentialed session is suppressed so cookies can't leak via a later page request.
  assert.match(DRIVER_SRC, /if \(this\.authedFetchOp \|\| this\.credentialedSession\) return;/);
  assert.match(DRIVER_SRC, /this\.authedFetchOp = \{ host: fetchHost \}/);
  assert.match(DRIVER_SRC, /this\.authedFetchOp = null/);
});

test("set_auth_cookies marks the session credentialed (session-wide log suppression)", () => {
  assert.match(DRIVER_SRC, /this\.credentialedSession = true;/);
});

test("authed_fetch allowlists benign headers and rejects everything else (auth must flow via set_auth_cookies, not the page world)", () => {
  // The headers param lives in the page world (in-page fetch init), so a credential header could
  // be read by a page-overridden fetch. Fail-closed ALLOWLIST — only benign non-credential headers
  // pass; ANY other (Authorization, Cookie, X-Api-Key, a bearer under a custom name) is rejected,
  // closing the gap where a 3-name denylist let custom-header auth leak into the page world.
  assert.match(DRIVER_SRC, /ALLOWED_AUTHED_FETCH_HEADERS/);
  assert.match(DRIVER_SRC, /the \$\{hname\} header is not allowed/);
  assert.match(DRIVER_SRC, /use set_auth_cookies for credentials/);
});

test("authed_fetch does NOT install a context.route interceptor (transport must survive Kasada/CDN/OAuth)", () => {
  // The priming-redirect residual is dispositioned, NOT fixed with a network interceptor: a
  // context.route('**/*') would abort page-decided subresource loads (the no-route invariant in
  // browser-driver-tools.test.js). Guard against reintroducing it here too.
  assert.doesNotMatch(DRIVER_SRC, /context\.route\s*\(\s*["'`]\*\*\/\*["'`]/);
  assert.match(DRIVER_SRC, /ACCEPTED RESIDUAL — priming redirect under block_internal_hosts/);
});

test("authed_fetch scope-checks the URL and guards origin drift", () => {
  assert.match(DRIVER_SRC, /assertSafeResolvedRequestUrl\(url, this\.targetDomain/);
  assert.match(DRIVER_SRC, /authed_fetch_origin_drift/);
});

test("authed_fetch scope-checks the FULL priming redirect chain, not just the landed origin", () => {
  // SSRF/scope-bypass regression: page.goto follows 3xx while ALREADY credentialed. Checking
  // only the LANDED origin lets a bounce (origin -> attacker -> origin) pass — a credentialed
  // request already reached `attacker`. The op must walk the whole chain via redirectedFrom()
  // (the final request back to the first) and scope-check EVERY hop, fail-closed on any that
  // is off-scope. The landed-origin check stays as a first-line guard.
  assert.match(DRIVER_SRC, /navResp\.request\(\)/, "the chain walk starts from the nav response's request");
  assert.match(DRIVER_SRC, /\.redirectedFrom\(\)/, "the redirect chain is walked via redirectedFrom()");
  // Every collected hop is validated with the same resolved-scope predicate the fetch URL uses,
  // honoring the block_internal_hosts policy threaded into runAuthedFetchOp.
  assert.match(
    DRIVER_SRC,
    /for \(const hopUrl of hopUrls\)[\s\S]*?assertSafeResolvedRequestUrl\(hopUrl, this\.targetDomain, \{ blockInternalHosts \}\)/,
    "each redirect hop must be scope-checked, not only the landed origin",
  );
  assert.match(
    DRIVER_SRC,
    /runAuthedFetchOp\(\{[^}]*blockInternalHosts[^}]*\}\)/,
    "the block_internal_hosts policy must be threaded into the redirect-chain check",
  );
  // An off-scope hop fails closed with a structured origin-drift error that names the hop.
  assert.match(DRIVER_SRC, /authed_fetch_origin_drift: priming redirect hop \$\{hopUrl\} is off-scope/);
  // The landed-origin check is preserved (it is not replaced by the chain walk).
  assert.match(DRIVER_SRC, /authed_fetch_origin_drift: landed on \$\{landedOrigin\} not \$\{origin\}/);
  // The fix must NOT reach for the forbidden catch-all route interceptor.
  assert.doesNotMatch(DRIVER_SRC, /context\.route\s*\(\s*["'`]\*\*\/\*["'`]/);
});

test("authed_fetch races a wall-clock timeout (no session pin) and caps the body", () => {
  assert.match(DRIVER_SRC, /authed_fetch_timeout after \$\{timeout\}ms/);
  assert.match(DRIVER_SRC, /MAX_AUTHED_FETCH_BODY_BYTES/);
  assert.match(DRIVER_SRC, /body_truncated/);
});

test("authed_fetch restricts the method to read-intent GET/POST", () => {
  assert.match(DRIVER_SRC, /method !== "GET" && method !== "POST"/);
});

test("authed_fetch does NOT follow redirects (redirect:manual — no off-scope auth leak)", () => {
  assert.match(DRIVER_SRC, /redirect: "manual"/);
});

test("authed_fetch stream-reads the body with a cap enforced WHILE reading (no full buffering)", () => {
  assert.match(DRIVER_SRC, /__r\.body\.getReader/);
});

test("authed_fetch navigates with waitUntil:commit to minimize authed-page execution", () => {
  assert.match(DRIVER_SRC, /waitUntil: "commit"/);
});

test("authed_fetch honors a producer block_internal_hosts policy in BOTH scope checks", () => {
  assert.match(DRIVER_SRC, /block_internal_hosts === true/);
  const checks = DRIVER_SRC.match(/assertSafeResolvedRequestUrl\([^)]*\{ blockInternalHosts \}\)/g) || [];
  assert.ok(checks.length >= 2, "both the fetch URL and the navigated origin must be policy-checked");
});

test("driver scrubs BOB_BROWSER_DRIVER_INIT from env before launch (no child-process inheritance)", () => {
  assert.match(DRIVER_SRC, /delete process\.env\.BOB_BROWSER_DRIVER_INIT/);
});

test("the agent-facing evaluate sandbox is UNCHANGED: fetch( still blocked in evaluate", () => {
  // The transport must NOT loosen the agent sandbox — only the trusted authed_fetch path
  // (a separate command with no MCP tool wrapper) issues page-context network IO.
  assert.match(DRIVER_SRC, /const FORBIDDEN_EVAL_PATTERN =\s*\n?\s*\/[^\n]*fetch\\\(/);
  assert.match(DRIVER_SRC, /if \(FORBIDDEN_EVAL_PATTERN\.test\(expression\)\)/);
  assert.match(DRIVER_SRC, /evaluate_sandbox_violation/);
});

test("no bob_browser_* MCP tool exposes authed_fetch OR set_auth_cookies (server-side-only)", () => {
  const toolsDir = path.join(__dirname, "..", "mcp", "lib", "tools");
  const offenders = fs.readdirSync(toolsDir)
    .filter((f) => f.startsWith("browser-") && f.endsWith(".js"))
    .filter((f) => {
      const src = fs.readFileSync(path.join(toolsDir, f), "utf8");
      return src.includes("authed_fetch") || src.includes("set_auth_cookies");
    });
  assert.deepEqual(offenders, [], "no browser tool wrapper may reference the trusted transport commands");
});

// ── real-Chromium end-to-end (gated on BROWSER_LAUNCHABLE) ──
//
// A local cookie-gated JSON endpoint stands in for a WAF-fronted API: "/" is public (so the
// navigate lands), "/api/listing" returns records ONLY when the auth cookie is present (200)
// else 401, "/api/redirect" 302s, and "/api/big" returns an oversized body. The authed
// session reads the records (cookie carried by the in-page fetch); the no-cookie control is
// denied — the mass-read differential.

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
      if (req.url === "/api/redirect") {
        res.writeHead(302, { location: "/" });
        res.end();
        return;
      }
      if (req.url === "/api/big") {
        res.writeHead(200, { "content-type": "text/plain" });
        res.end("x".repeat(MAX_AUTHED_FETCH_BODY_BYTES + 4096));
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
    // attacker arm: cookie injected (via set_auth_cookies stdin path) → reads the records
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

test("authed_fetch credentialed request is absent from the agent-readable network log", { skip: !BROWSER_LAUNCHABLE }, async (t) => {
  if (await lookupLoopback("localtest.me") !== "127.0.0.1") {
    t.skip("localtest.me does not resolve to loopback in this environment");
    return;
  }
  const server = await startCookieGatedServer();
  const port = server.address().port;
  const origin = `http://localtest.me:${port}`;
  let session = null;
  try {
    session = await browserSessions.startSession({
      targetDomain: "localtest.me", targetUrl: origin, headless: true,
      authCookies: [{ name: "massread_auth", value: "letmein", url: origin }],
    });
    const authed = await browserSessions.sendCommand(session.session_id, "authed_fetch", {
      url: `${origin}/api/listing`, method: "GET",
    });
    assert.equal(authed.status, 200);
    const log = await browserSessions.sendCommand(session.session_id, "network_requests", {});
    const leaked = (log.requests || []).filter((r) => r.url && r.url.includes("/api/listing"));
    assert.deepEqual(leaked, [], "the credentialed authed_fetch request must not appear in the network log");
  } finally {
    if (session) await browserSessions.closeSession(session.session_id).catch(() => {});
    await new Promise((r) => server.close(r));
  }
});

test("authed_fetch does NOT follow a 3xx (redirect:manual → opaqueredirect, status 0)", { skip: !BROWSER_LAUNCHABLE }, async (t) => {
  if (await lookupLoopback("localtest.me") !== "127.0.0.1") {
    t.skip("localtest.me does not resolve to loopback in this environment");
    return;
  }
  const server = await startCookieGatedServer();
  const port = server.address().port;
  const origin = `http://localtest.me:${port}`;
  let session = null;
  try {
    session = await browserSessions.startSession({
      targetDomain: "localtest.me", targetUrl: origin, headless: true,
    });
    const res = await browserSessions.sendCommand(session.session_id, "authed_fetch", {
      url: `${origin}/api/redirect`, method: "GET",
    });
    // A followed redirect would surface the 200 of "/"; redirect:manual surfaces status 0.
    assert.equal(res.status, 0, `redirect must not be followed: ${JSON.stringify(res)}`);
    assert.equal(res.type, "opaqueredirect");
  } finally {
    if (session) await browserSessions.closeSession(session.session_id).catch(() => {});
    await new Promise((r) => server.close(r));
  }
});

test("authed_fetch caps an oversized body at the byte limit and flags truncation", { skip: !BROWSER_LAUNCHABLE }, async (t) => {
  if (await lookupLoopback("localtest.me") !== "127.0.0.1") {
    t.skip("localtest.me does not resolve to loopback in this environment");
    return;
  }
  const server = await startCookieGatedServer();
  const port = server.address().port;
  const origin = `http://localtest.me:${port}`;
  let session = null;
  try {
    session = await browserSessions.startSession({
      targetDomain: "localtest.me", targetUrl: origin, headless: true,
    });
    const res = await browserSessions.sendCommand(session.session_id, "authed_fetch", {
      url: `${origin}/api/big`, method: "GET",
    });
    assert.equal(res.status, 200);
    assert.equal(res.body_truncated, true, "oversized body must be flagged truncated");
    assert.ok(
      Buffer.byteLength(res.body) <= MAX_AUTHED_FETCH_BODY_BYTES,
      `capped body must be <= ${MAX_AUTHED_FETCH_BODY_BYTES} bytes, got ${Buffer.byteLength(res.body)}`,
    );
  } finally {
    if (session) await browserSessions.closeSession(session.session_id).catch(() => {});
    await new Promise((r) => server.close(r));
  }
});

test("set_auth_cookies rejects an out-of-scope cookie (session fails closed)", { skip: !BROWSER_LAUNCHABLE }, async (t) => {
  if (await lookupLoopback("localtest.me") !== "127.0.0.1") {
    t.skip("localtest.me does not resolve to loopback in this environment");
    return;
  }
  const server = await startCookieGatedServer();
  const port = server.address().port;
  const origin = `http://localtest.me:${port}`;
  try {
    await assert.rejects(
      () => browserSessions.startSession({
        targetDomain: "localtest.me",
        targetUrl: origin,
        headless: true,
        // cookie scoped to an OFF-target host — must be refused before it reaches the context
        authCookies: [{ name: "evil", value: "x", url: "https://attacker.example.com/" }],
      }),
      (err) => { assert.match(err.message, /scope_blocked/); return true; },
    );
  } finally {
    await new Promise((r) => server.close(r));
  }
});

test("authed_fetch refuses an in-scope but UNPINNED host even without block_internal_hosts", { skip: !BROWSER_LAUNCHABLE }, async (t) => {
  if (await lookupLoopback("localtest.me") !== "127.0.0.1") {
    t.skip("localtest.me does not resolve to loopback in this environment");
    return;
  }
  // round-5: the session pins only the target_url host (localtest.me). A credentialed
  // authed_fetch to a DIFFERENT in-scope host (sub.localtest.me) is refused on the default
  // path (no block_internal_hosts) — the round-4 hole where the default path was rebindable.
  const server = await startCookieGatedServer();
  const port = server.address().port;
  const origin = `http://localtest.me:${port}`;
  let session = null;
  try {
    session = await browserSessions.startSession({
      targetDomain: "localtest.me", targetUrl: origin, headless: true,
    });
    await assert.rejects(
      () => browserSessions.sendCommand(session.session_id, "authed_fetch", {
        url: `http://sub.localtest.me:${port}/api/listing`, method: "GET",
      }),
      (err) => { assert.match(err.message, /scope_blocked.*not DNS-pinned/); return true; },
    );
  } finally {
    if (session) await browserSessions.closeSession(session.session_id).catch(() => {});
    await new Promise((r) => server.close(r));
  }
});

test("authed_fetch under block_internal_hosts refuses a host pinned to an internal IP", { skip: !BROWSER_LAUNCHABLE }, async (t) => {
  if (await lookupLoopback("localtest.me") !== "127.0.0.1") {
    t.skip("localtest.me does not resolve to loopback in this environment");
    return;
  }
  // End-to-end: an authed_fetch to a loopback-resolving target under block_internal_hosts is
  // refused (defense in depth — the resolved-scope check and the pin-internal guard both reject
  // a private IP). The pin.internal branch specifically closes the rebind case (public IP at
  // check-time, private pinned IP at connect-time); that branch is asserted by the source test.
  const server = await startCookieGatedServer();
  const port = server.address().port;
  const origin = `http://localtest.me:${port}`;
  let session = null;
  try {
    session = await browserSessions.startSession({
      targetDomain: "localtest.me", targetUrl: origin, headless: true,
    });
    await assert.rejects(
      () => browserSessions.sendCommand(session.session_id, "authed_fetch", {
        url: `${origin}/api/listing`, method: "GET", block_internal_hosts: true,
      }),
      (err) => { assert.match(err.message, /scope_blocked/); return true; },
    );
  } finally {
    if (session) await browserSessions.closeSession(session.session_id).catch(() => {});
    await new Promise((r) => server.close(r));
  }
});

test("authed_fetch rejects an Authorization header (credentials must use set_auth_cookies)", { skip: !BROWSER_LAUNCHABLE }, async (t) => {
  if (await lookupLoopback("localtest.me") !== "127.0.0.1") {
    t.skip("localtest.me does not resolve to loopback in this environment");
    return;
  }
  const server = await startCookieGatedServer();
  const port = server.address().port;
  const origin = `http://localtest.me:${port}`;
  let session = null;
  try {
    session = await browserSessions.startSession({
      targetDomain: "localtest.me", targetUrl: origin, headless: true,
    });
    await assert.rejects(
      () => browserSessions.sendCommand(session.session_id, "authed_fetch", {
        url: `${origin}/api/listing`, method: "GET", headers: { Authorization: "Bearer secret-token" },
      }),
      (err) => { assert.match(err.message, /not allowed.*set_auth_cookies/); return true; },
    );
  } finally {
    if (session) await browserSessions.closeSession(session.session_id).catch(() => {});
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
