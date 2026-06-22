#!/usr/bin/env node
// Long-running Patchright (stealth Playwright fork) session driver.
// Spawned by mcp/lib/browser-sessions.js for the bob_browser_* MCP tool family.
//
// Anti-detection stack inherited from auto-signup.js:
//   1. Patchright — fixes Runtime.Enable CDP leak
//   2. channel: "chrome" — real system Chrome (TLS, fonts, WebGL match)
//   3. Headed mode by default — avoids headless signals
//   4. ignoreDefaultArgs: ["--enable-automation"] — removes automation flag
//   5. Human-like timing — randomized delays between interactions
//
// Protocol:
//   stdin:  newline-delimited JSON { command_id, command, args }
//   stdout: newline-delimited JSON { command_id, result | error }
//   The first line on stdout is { ready: true, session_id } once the
//   browser context is up.
//
// Lifecycle:
//   - Idle timeout: 5 min (kill if no commands received).
//   - Hard timeout: 30 min (kill regardless of activity).
//   - Receiving `close` exits cleanly. If record_mode was enabled, the
//     close response carries any remaining buffered requests so the parent
//     can pipe them through import-http-traffic.js (T.7, T-R5).
//
// Init payload (BOB_BROWSER_DRIVER_INIT env var, JSON):
//   { session_id, target_domain, target_url, headless?, sessions_root?,
//     record_mode?, proxy? }. record_mode=true installs a per-page request
//     listener that buffers http(s) requests; the buffer is flushed via the
//     `flush_recorded_requests` command and on the final `close`. proxy, when
//     present, must be { server, username?, password? } in Patchright/
//     Playwright launch-options shape and is threaded into
//     chromium.launch({ proxy }) BEFORE the anti-detection stack runs so the
//     operator still gets a real Chrome fingerprint behind the proxy.

"use strict";

const fs = require("fs");
const path = require("path");
const os = require("os");
const readline = require("readline");
const crypto = require("crypto");

const {
  assertSafeResolvedRequestUrl,
  assertSafeRequestUrl,
  resolveSafeAddress,
} = require("./lib/safe-fetch.js");
const { isBlockedInternalHost } = require("./lib/url-surface.js");

const IDLE_TIMEOUT_MS = 5 * 60 * 1000;
const HARD_TIMEOUT_MS = 30 * 60 * 1000;
const DEFAULT_NAVIGATE_TIMEOUT_MS = 30_000;
const DEFAULT_WAIT_FOR_TIMEOUT_MS = 15_000;
const DEFAULT_EVALUATE_TIMEOUT_MS = 15_000;
const DEFAULT_SCREENSHOT_TIMEOUT_MS = 30_000;
const MAX_EVAL_RESULT_BYTES = 256 * 1024;
const MAX_SNAPSHOT_BYTES = 512 * 1024;
// Body cap for the trusted `authed_fetch` transport. Generous (2 MiB ≈ thousands of
// records) because the offensive mass-read producer needs the full collection to derive
// its masked count/field-shape summary; bodies past the cap return body_truncated:true.
const MAX_AUTHED_FETCH_BODY_BYTES = 2 * 1024 * 1024;
// Ceiling on any agent-supplied per-operation timeout, mirroring
// browser-tools-shared.js. A non-positive value can't disable the bound and a
// pathological value can't pin the single-page session far past its useful life.
const MAX_OPERATION_TIMEOUT_MS = 5 * 60 * 1000;

// Agent-supplied timeout_ms is the per-operation deadline. A non-finite or
// non-positive value — notably 0, which Playwright treats as "no timeout" —
// must never disable the bound, or an agent could request an unbounded driver
// op that pins the single-page session until the reaper. Clamp to the
// operation default below, and to MAX_OPERATION_TIMEOUT_MS above.
function resolveOpTimeout(args, defaultMs) {
  const requested = Number(args && args.timeout_ms);
  if (!Number.isFinite(requested) || requested <= 0) return defaultMs;
  return Math.min(requested, MAX_OPERATION_TIMEOUT_MS);
}

// Expression sandbox: agents must not turn the browser into a covert HTTP
// transport. Network IO from the page context bypasses Bob's scope checks
// and the audit ledger; agents should use bob_http_scan or
// bob_browser_navigate (both scope-checked) for HTTP traffic.
const FORBIDDEN_EVAL_PATTERN =
  /XMLHttpRequest|fetch\(|navigator\.sendBeacon|new\s+EventSource|new\s+WebSocket|window\.open\(|(?:window|document|top|parent)\.location\s*=|location\.(?:href|assign|replace)/i;

// ── Helpers ──

function randomDelay(min = 100, max = 400) {
  return new Promise((r) => setTimeout(r, min + Math.random() * (max - min)));
}

function humanType(chars) {
  // Mirrors auto-signup.js humanType: per-character delay that grows slightly
  // around punctuation so the keystroke cadence looks natural.
  return chars.split("").map((c) => ({
    char: c,
    delay: 30 + Math.random() * 120 + (c === "@" || c === "." ? 200 * Math.random() : 0),
  }));
}

function logErr(message) {
  // Stderr is reserved for unstructured driver-level diagnostics; the parent
  // ignores it for protocol decisions but surfaces it in test failures.
  try {
    process.stderr.write(`[browser-driver] ${message}\n`);
  } catch {
    // best-effort
  }
}

function writeResponse(payload) {
  try {
    process.stdout.write(`${JSON.stringify(payload)}\n`);
  } catch (err) {
    logErr(`failed to write response: ${err && err.message ? err.message : err}`);
  }
}

function emitReady(sessionId) {
  writeResponse({ ready: true, session_id: sessionId });
}

function truncateForResponse(value, max) {
  if (typeof value !== "string") return value;
  if (value.length <= max) return value;
  return `${value.slice(0, max)}…[truncated ${value.length - max} chars]`;
}

function safeJsonClone(value, maxBytes) {
  if (value === undefined) return null;
  let serialized;
  try {
    serialized = JSON.stringify(value, (_key, item) => {
      if (typeof item === "function") return `[Function ${item.name || "anonymous"}]`;
      if (typeof item === "bigint") return item.toString();
      return item;
    });
  } catch (err) {
    return { _serialize_error: err && err.message ? err.message : String(err) };
  }
  if (typeof serialized !== "string") return null;
  if (serialized.length <= maxBytes) {
    try {
      return JSON.parse(serialized);
    } catch {
      return serialized;
    }
  }
  return {
    _truncated: true,
    _byte_length: serialized.length,
    preview: serialized.slice(0, maxBytes),
  };
}

function ensureDir(dir) {
  fs.mkdirSync(dir, { recursive: true });
}

function screenshotsDirFor(domain, sessionsRoot) {
  return path.join(sessionsRoot, domain, "browser-screenshots");
}

function sanitizeDomainForPath(domain) {
  return String(domain || "unknown").replace(/[^A-Za-z0-9._-]/g, "_");
}

// ── Driver core ──

class BrowserDriver {
  constructor({ sessionId, targetDomain, targetUrl, headless, sessionsRoot, recordMode, proxy }) {
    this.sessionId = sessionId;
    this.targetDomain = targetDomain;
    this.targetUrl = targetUrl;
    this.headless = headless === true;
    this.sessionsRoot = sessionsRoot || path.join(os.homedir(), "hacker-bob-sessions");
    this.browser = null;
    this.context = null;
    this.page = null;
    this.requests = []; // { method, url, resource_type, headers, post_data, timestamp }
    this.consoles = []; // { type, text, location, timestamp }
    this.screenshotSeq = 0;
    this.idleTimer = null;
    this.hardTimer = null;
    this.closing = false;
    // T.7 record mode: when enabled, every browser-emitted HTTP(S) request is
    // captured into recordedRequests for later flushing through
    // import-http-traffic.js (which holds the session lock — see T-R5).
    this.recordMode = recordMode === true;
    this.recordedRequests = [];
    // Egress proxy is { server, username?, password? } in Playwright's launch-
    // options shape. Already resolved + env-expanded + scheme-validated by the
    // tool wrapper. null = direct egress.
    this.proxy = proxy && typeof proxy === "object" && typeof proxy.server === "string"
      ? proxy
      : null;
    // DNS-rebinding pin: host(lowercased) -> { address, internal }. The browser is started with
    // --host-resolver-rules so Chrome connects to the SAME IP we resolved at launch, closing the
    // TOCTOU where the static scope check passes for a hostname but the browser independently
    // re-resolves it to an internal/attacker IP. `internal` records whether that pinned IP is a
    // private/blocked address so authed_fetch can refuse it under block_internal_hosts (presence
    // alone must NOT satisfy the no-internal-host promise). Empty under an egress proxy (DNS
    // resolves at the proxy, not locally) or if launch-time resolution failed.
    this.pinnedHosts = new Map();
    // Session-level cookie auth for the trusted `authed_fetch` transport arrives AFTER ready
    // via the server-side-only `set_auth_cookies` stdin command (never an agent, never the
    // process environment). null/empty = unauthenticated (the control arm of the mass-read
    // differential). Tracked only to reject a second, conflicting injection.
    this.authCookiesApplied = false;
    // Set to { host } for the duration of a trusted authed_fetch op so attachListeners() skips
    // recording its (credentialed) requests into the agent-readable log / record buffer. null =
    // idle. (NOT a network interceptor — see the no-context.route invariant in
    // browser-driver-tools.test.js; the host is kept for diagnostics only.)
    this.authedFetchOp = null;
  }

  async start() {
    let patchright;
    try {
      patchright = require("patchright");
    } catch {
      const err = new Error(
        "patchright_unavailable: optional dependency patchright is not installed. Run `npm install` and `npx patchright install chromium`.",
      );
      err.code = "patchright_unavailable";
      throw err;
    }

    // DNS-rebinding pin (round-3): resolve the target host ONCE in Node and force Chrome to
    // connect to that exact IP via --host-resolver-rules. Without this, the browser does its
    // own DNS resolution when authed_fetch navigates/fetches, so an attacker-controlled record
    // could return a public IP to our scope check and a private IP (169.254.169.254 / 127.x)
    // to Chrome. Skipped under a proxy (egress DNS happens at the proxy). Best-effort: a
    // resolution failure leaves the host unpinned, and authed_fetch then fails closed under
    // block_internal_hosts (see authedFetch).
    const resolverRules = [];
    if (!this.proxy) {
      try {
        const pinHost = new URL(this.targetUrl).hostname.toLowerCase();
        // Resolve WITHOUT throwing on internal so we can pin loopback in tests / policy-off
        // sessions, but RECORD whether the pinned IP is internal so the authed_fetch guard can
        // refuse it under block_internal_hosts (a pin to a private IP must NOT satisfy the
        // no-internal-host promise just by being present).
        const { address } = await resolveSafeAddress(pinHost, { blockInternalHosts: false });
        if (address) {
          this.pinnedHosts.set(pinHost, { address, internal: isBlockedInternalHost(address) });
          // Chrome resolver-rules want IPv6 literals bracketed; MAP carries the port through.
          const ipForRule = address.includes(":") ? `[${address}]` : address;
          resolverRules.push(`MAP ${pinHost} ${ipForRule}`);
        }
      } catch {
        // leave unpinned — authed_fetch enforces the consequence
      }
    }

    const launchOptions = {
      headless: this.headless,
      args: [
        "--disable-blink-features=AutomationControlled",
        "--no-first-run",
        "--no-default-browser-check",
        "--disable-infobars",
        "--window-size=1440,900",
      ],
      ignoreDefaultArgs: ["--enable-automation"],
    };
    if (resolverRules.length) {
      // MAP only matches the pinned host; other hosts (CDNs, third-party subresources) still
      // resolve normally, so this does not break legitimate page loads.
      launchOptions.args.push(`--host-resolver-rules=${resolverRules.join(",")}`);
    }
    // Proxy is composed with — not in place of — the anti-detection stack:
    // channel=chrome, the AutomationControlled disable flag, and the
    // ignoreDefaultArgs filter all still apply, so the proxy carries a real
    // Chrome fingerprint instead of leaking a headless/Playwright signature.
    // The proxy was env-expanded and scheme-validated upstream
    // (mcp/lib/browser-tools-shared.js#resolveBrowserEgressProfile) — the
    // driver only sees the structured { server, username?, password? } form.
    if (this.proxy) {
      launchOptions.proxy = this.proxy;
    }

    try {
      this.browser = await patchright.chromium.launch({ ...launchOptions, channel: "chrome" });
    } catch {
      // Fall back to bundled Chromium if the system Chrome channel is missing.
      try {
        this.browser = await patchright.chromium.launch(launchOptions);
      } catch (err) {
        const wrapped = new Error(`browser_launch_failed: ${err && err.message ? err.message : err}`);
        wrapped.code = "browser_launch_failed";
        throw wrapped;
      }
    }

    this.context = await this.browser.newContext({
      viewport: { width: 1440, height: 900 },
      userAgent:
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
      locale: "en-US",
      timezoneId: Intl.DateTimeFormat().resolvedOptions().timeZone,
      colorScheme: "light",
      reducedMotion: "no-preference",
      serviceWorkers: "allow",
    });

    await this.installScopedRequestGuard();
    this.page = await this.context.newPage();
    this.attachListeners();
    this.touchIdle();
    this.scheduleHardTimeout();
  }

  async installScopedRequestGuard() {
    if (typeof this.context.routeWebSocket === "function") {
      await this.context.routeWebSocket("**/*", (socketRoute) => {
        if (socketRoute && typeof socketRoute.close === "function") {
          socketRoute.close();
        }
      });
    }

    // Subresource interception is intentionally NOT installed here. Modern
    // web apps depend on hundreds of off-target requests just to render —
    // anti-bot fingerprint scripts (Kasada, Akamai, PerimeterX), CDN bundles,
    // analytics, OAuth redirect chains, payment iframes, WebAuthn platform
    // calls. Blocking page-initiated subresource loads at the network layer
    // breaks every realistic target.
    //
    // The scope boundary is enforced where the AGENT makes a navigation
    // decision:
    //   • bob_browser_session_start  → assertSafeResolvedRequestUrl(target_url)
    //   • bob_browser_navigate       → assertSafeResolvedRequestUrl(url)
    //   • bob_browser_evaluate       → expression sandbox blocks location/open
    //                                  writes and direct network IO
    // Page-initiated requests (subresources, server-driven redirects, JS
    // navigations the agent didn't author) are observed by attachListeners()
    // and the record-mode buffer for capture/replay; they are not blocked.
  }

  attachListeners() {
    this.page.on("request", (request) => {
      // Do NOT record the trusted authed_fetch op (priming nav + the credentialed fetch): its
      // headers/cookies carry the producer's auth material and must not leak into the
      // agent-readable request log or the record-mode buffer (which is flushed to the audit
      // trail). These are server-side producer requests, not agent-observable recon traffic.
      if (this.authedFetchOp) return;
      const headers = {};
      try {
        const raw = request.headers() || {};
        for (const [name, value] of Object.entries(raw)) {
          headers[name] = String(value);
        }
      } catch {
        // ignore — best-effort capture
      }
      const url = request.url();
      const method = request.method();
      const resourceType = request.resourceType();
      const postData = request.postData() ? truncateForResponse(request.postData(), 8192) : null;
      this.requests.push({
        index: this.requests.length,
        method,
        url,
        resource_type: resourceType,
        headers,
        post_data: postData,
        timestamp: Date.now(),
      });
      // T.7: record_mode captures the same request shape into a separate
      // buffer that the parent flushes through import-http-traffic.js. Only
      // http(s) schemes are captured — data:, blob:, chrome-extension:, ws://
      // and other non-HTTP transports are excluded because the http-records
      // ingestion path validates URLs against the scoped HTTP scope checker.
      if (this.recordMode && /^https?:/i.test(url)) {
        let frameUrl = null;
        try {
          const frame = request.frame();
          if (frame && typeof frame.url === "function") {
            frameUrl = frame.url() || null;
          }
        } catch {
          // best-effort — frame URL is informational only
        }
        this.recordedRequests.push({
          method,
          url,
          resource_type: resourceType,
          headers,
          post_data: postData,
          frame_url: frameUrl,
          timestamp: Date.now(),
        });
      }
    });

    this.page.on("console", (msg) => {
      let text = "";
      try {
        text = msg.text();
      } catch {
        text = "";
      }
      let location = null;
      try {
        const loc = msg.location();
        if (loc && (loc.url || loc.lineNumber != null)) {
          location = { url: loc.url || null, line: loc.lineNumber == null ? null : loc.lineNumber };
        }
      } catch {
        // ignore
      }
      this.consoles.push({
        index: this.consoles.length,
        type: msg.type(),
        text: truncateForResponse(text, 4096),
        location,
        timestamp: Date.now(),
      });
    });
  }

  touchIdle() {
    if (this.idleTimer) clearTimeout(this.idleTimer);
    this.idleTimer = setTimeout(() => {
      logErr(`session ${this.sessionId} idle timeout (${IDLE_TIMEOUT_MS} ms) — closing`);
      this.shutdown("idle_timeout");
    }, IDLE_TIMEOUT_MS);
    // Allow Node to exit even if a long timeout is pending under tests.
    if (this.idleTimer && typeof this.idleTimer.unref === "function") {
      this.idleTimer.unref();
    }
  }

  scheduleHardTimeout() {
    if (this.hardTimer) clearTimeout(this.hardTimer);
    this.hardTimer = setTimeout(() => {
      logErr(`session ${this.sessionId} hard timeout (${HARD_TIMEOUT_MS} ms) — closing`);
      this.shutdown("hard_timeout");
    }, HARD_TIMEOUT_MS);
    if (this.hardTimer && typeof this.hardTimer.unref === "function") {
      this.hardTimer.unref();
    }
  }

  async shutdown(reason) {
    if (this.closing) return;
    this.closing = true;
    try {
      if (this.idleTimer) clearTimeout(this.idleTimer);
      if (this.hardTimer) clearTimeout(this.hardTimer);
      if (this.browser) {
        await this.browser.close();
      }
    } catch (err) {
      logErr(`shutdown ${reason} error: ${err && err.message ? err.message : err}`);
    }
    process.exit(0);
  }

  async handleCommand(command, args = {}) {
    this.touchIdle();
    switch (command) {
      case "navigate":
        return await this.navigate(args);
      case "snapshot":
        return await this.snapshot(args);
      case "click":
        return await this.click(args);
      case "type":
        return await this.type(args);
      case "evaluate":
        return await this.evaluate(args);
      case "authed_fetch":
        // TRUSTED, server-side-only transport — no bob_browser_* MCP tool maps to it, so
        // an agent cannot reach it; only the in-process offensive mass-read producer does.
        return await this.authedFetch(args);
      case "set_auth_cookies":
        // TRUSTED, server-side-only — injects producer-supplied cookie auth for the
        // authed_fetch transport. Like authed_fetch, no bob_browser_* MCP tool maps to it, so
        // an agent cannot inject auth. Cookies arrive over stdin (never the process env), and
        // each is scope-validated against target_domain before it reaches the context.
        return await this.setAuthCookies(args);
      case "network_requests":
        return await this.networkRequests(args);
      case "console_messages":
        return await this.consoleMessages(args);
      case "wait_for":
        return await this.waitFor(args);
      case "press_key":
        return await this.pressKey(args);
      case "take_screenshot":
        return await this.takeScreenshot(args);
      case "fill_form":
        return await this.fillForm(args);
      case "flush_recorded_requests":
        return this.flushRecordedRequests();
      case "close":
        // Final close response includes any remaining record-mode buffer so the
        // parent can ingest it through import-http-traffic.js before the
        // subprocess exits.
        return {
          closed: true,
          record_mode: this.recordMode === true,
          recorded: this.recordMode ? this.flushRecordedRequests().recorded : [],
        };
      default:
        throw new Error(`unknown_command: ${command}`);
    }
  }

  flushRecordedRequests() {
    if (!this.recordMode) {
      return { recorded: [], record_mode: false };
    }
    const recorded = this.recordedRequests;
    this.recordedRequests = [];
    return { recorded, record_mode: true };
  }

  async navigate(args) {
    const url = String(args && args.url ? args.url : "").trim();
    if (!url) throw new Error("navigate.url is required");
    try {
      await assertSafeResolvedRequestUrl(url, this.targetDomain, {
        blockInternalHosts: false,
      });
    } catch (err) {
      const wrapped = new Error(`scope_blocked: ${err && err.message ? err.message : err}`);
      wrapped.code = "scope_blocked";
      throw wrapped;
    }
    const timeout = resolveOpTimeout(args, DEFAULT_NAVIGATE_TIMEOUT_MS);
    const response = await this.page.goto(url, { waitUntil: "domcontentloaded", timeout });
    await randomDelay(150, 400);
    return {
      status: response ? response.status() : null,
      final_url: this.page.url(),
    };
  }

  async snapshot() {
    // Newer Playwright/Patchright dropped the legacy `page.accessibility`
    // namespace in favor of `page.ariaSnapshot()` (YAML serialization of the
    // accessibility tree). The shape is different but the intent is the same:
    // a structured, role-named summary the agent can read for ref derivation.
    let tree = null;
    try {
      if (typeof this.page.ariaSnapshot === "function") {
        tree = await this.page.ariaSnapshot();
      } else if (this.page.accessibility && typeof this.page.accessibility.snapshot === "function") {
        tree = await this.page.accessibility.snapshot({ interestingOnly: true });
      } else {
        // Last-resort fallback: title + visible text outline keeps the
        // snapshot useful even when both accessibility surfaces are missing.
        tree = await this.page.evaluate(() => {
          return {
            title: document.title || "",
            url: location.href,
            body_text_preview: (document.body && document.body.innerText
              ? document.body.innerText.slice(0, 2000)
              : ""),
          };
        });
      }
    } catch (err) {
      throw new Error(`snapshot_failed: ${err && err.message ? err.message : err}`);
    }
    const cloned = safeJsonClone(tree, MAX_SNAPSHOT_BYTES);
    return { snapshot: cloned };
  }

  async resolveLocator(ref) {
    const refValue = typeof ref === "string" ? ref.trim() : "";
    if (!refValue) throw new Error("ref is required");
    // ref formats: "selector:<css>", "text:<accessible name>", "role:<role>:<name>"
    if (refValue.startsWith("selector:")) {
      return this.page.locator(refValue.slice(9)).first();
    }
    if (refValue.startsWith("text:")) {
      return this.page.getByText(refValue.slice(5), { exact: false }).first();
    }
    if (refValue.startsWith("role:")) {
      const rest = refValue.slice(5);
      const [role, ...nameParts] = rest.split(":");
      const name = nameParts.join(":").trim();
      const opts = name ? { name, exact: false } : undefined;
      return this.page.getByRole(role.trim(), opts).first();
    }
    // Default: treat as raw CSS selector.
    return this.page.locator(refValue).first();
  }

  async click(args) {
    const locator = await this.resolveLocator(args && args.ref);
    await randomDelay(80, 220);
    await locator.click({ timeout: DEFAULT_WAIT_FOR_TIMEOUT_MS });
    return { ok: true };
  }

  async type(args) {
    const text = String(args && args.text != null ? args.text : "");
    const locator = await this.resolveLocator(args && args.ref);
    await locator.click({ timeout: DEFAULT_WAIT_FOR_TIMEOUT_MS });
    await randomDelay(60, 180);
    for (const { char, delay } of humanType(text)) {
      await locator.pressSequentially(char, { delay: 0 });
      await new Promise((r) => setTimeout(r, delay));
    }
    return { ok: true };
  }

  async evaluate(args) {
    const expression = String(args && args.expression != null ? args.expression : "");
    if (!expression.trim()) throw new Error("evaluate.expression is required");
    if (FORBIDDEN_EVAL_PATTERN.test(expression)) {
      const err = new Error(
        "evaluate_sandbox_violation: expression contains forbidden network-IO pattern (XMLHttpRequest, fetch(, sendBeacon, EventSource, WebSocket). Use bob_http_scan or bob_browser_navigate for HTTP traffic; the browser-driver expression sandbox blocks page-context network calls.",
      );
      err.code = "evaluate_sandbox_violation";
      throw err;
    }
    // page.evaluate takes no Playwright timeout, so a runaway expression
    // (`while(true){}`, `new Promise(()=>{})`) would pin the page until the IPC
    // backstop fires ~90s later, leaving the single-page session dead. Race it
    // against a wall-clock bound so the command returns a precise
    // evaluate_timeout instead; async-hang sessions stay usable afterward.
    const timeout = resolveOpTimeout(args, DEFAULT_EVALUATE_TIMEOUT_MS);
    const evalPromise = this.page.evaluate(expression);
    // If the bound wins the race the evaluate stays pending and may reject
    // later when the page is torn down; swallow that so it is not an unhandled
    // rejection.
    evalPromise.catch(() => {});
    let timer;
    let result;
    try {
      // page.evaluate accepts a function or string; the string form runs the
      // expression in the page world and returns the value.
      result = await Promise.race([
        evalPromise,
        new Promise((_, reject) => {
          timer = setTimeout(() => {
            const e = new Error(
              `evaluate_timeout after ${timeout}ms — expression did not settle. If it blocks the renderer (e.g. an infinite loop) the page is wedged; close this session and start a new one.`,
            );
            e.code = "evaluate_timeout";
            reject(e);
          }, timeout);
          if (timer && typeof timer.unref === "function") timer.unref();
        }),
      ]);
    } catch (err) {
      // Preserve the evaluate_timeout code so the agent can tell a runaway /
      // wedged expression apart from an ordinary evaluation error and recycle
      // the session.
      if (err && err.code === "evaluate_timeout") throw err;
      throw new Error(`evaluate_failed: ${err && err.message ? err.message : err}`);
    } finally {
      clearTimeout(timer);
    }
    return { result: safeJsonClone(result, MAX_EVAL_RESULT_BYTES) };
  }

  // TRUSTED, server-side-only — inject producer-supplied cookie auth for authed_fetch.
  // Cookies arrive over the stdin IPC channel (NEVER the process environment, so no child
  // process or /proc/<pid>/environ snapshot can leak them), and EACH cookie's target host is
  // scope-validated against target_domain before it reaches the browser context — an
  // out-of-scope cookie (one that would be sent to a non-target origin) is rejected fail-closed.
  async setAuthCookies(args) {
    const cookies = args && Array.isArray(args.cookies) ? args.cookies : null;
    if (!cookies || !cookies.length) {
      throw new Error("set_auth_cookies.cookies must be a non-empty array");
    }
    if (this.authCookiesApplied) {
      // One injection per session: re-injection would let a later call widen the cookie set.
      throw new Error("set_auth_cookies_already_applied");
    }
    for (const cookie of cookies) {
      if (!cookie || typeof cookie !== "object") {
        throw new Error("set_auth_cookies: each cookie must be an object");
      }
      const hasUrl = typeof cookie.url === "string" && cookie.url;
      const hasDomain = typeof cookie.domain === "string" && cookie.domain;
      // Reject the ambiguous both-set form: with both `url` and `domain`, Playwright picks one
      // and our scope check could validate a different target than what is actually written.
      // Require exactly one so the validated host == the host the cookie is sent to.
      if (hasUrl && hasDomain) {
        throw new Error("set_auth_cookies: a cookie must set EITHER url OR domain, not both");
      }
      // Validate the EXACT host the cookie will be sent to: url.host, or the de-dotted domain
      // (a leading-dot domain also covers subdomains — in scope iff the de-dotted host is). One
      // out-of-scope cookie taints the session, so we refuse the whole batch.
      let scopeUrl = null;
      if (hasUrl) {
        scopeUrl = cookie.url;
      } else if (hasDomain) {
        const host = cookie.domain.replace(/^\./, "");
        scopeUrl = `https://${host}${typeof cookie.path === "string" && cookie.path ? cookie.path : "/"}`;
      } else {
        throw new Error("set_auth_cookies: each cookie needs a url or a domain");
      }
      try {
        assertSafeRequestUrl(scopeUrl, this.targetDomain);
      } catch (err) {
        const e = new Error(
          `set_auth_cookies_scope_blocked: cookie target ${scopeUrl} is outside ${this.targetDomain}: ${err && err.message ? err.message : err}`,
        );
        e.code = "scope_blocked";
        throw e;
      }
    }
    await this.context.addCookies(cookies);
    this.authCookiesApplied = true;
    return { ok: true, count: cookies.length };
  }

  // TRUSTED, server-side-only transport (NOT agent-reachable — no MCP tool maps to the
  // "authed_fetch" command). Issues an authenticated request from the PAGE context so it
  // carries the real Chrome TLS/HTTP-2 fingerprint and survives a WAF/Cloudflare that
  // 403s safeFetch's bare-Node fingerprint — the gap that left the offensive rail unable
  // to confirm the broken-auth/mass-read class. The agent-facing `evaluate` sandbox
  // (FORBIDDEN_EVAL_PATTERN) is UNCHANGED: this builds the fetch expression SERVER-SIDE
  // from a scope-checked URL + producer-supplied headers and runs it via the trusted path.
  async authedFetch(args) {
    const url = String(args && args.url ? args.url : "").trim();
    if (!url) throw new Error("authed_fetch.url is required");
    // GET, or POST for query-style listing/search endpoints (real mass-read APIs are often
    // POST). The transport CANNOT verify a POST is non-mutating — read-intent is the
    // PRODUCER's responsibility (it targets only listing/search surfaces, guarded by
    // assertReadOnlyPath + the operator), so this is not labelled a read-only guarantee.
    const method = String(args && args.method ? args.method : "GET").toUpperCase();
    if (method !== "GET" && method !== "POST") {
      throw new Error("authed_fetch.method must be GET or POST");
    }
    const headers = args && args.headers && typeof args.headers === "object" && !Array.isArray(args.headers)
      ? args.headers
      : {};
    const body = args && typeof args.body === "string" ? args.body : null;
    // The producer threads the session block_internal_hosts policy; when on, the scope checks
    // below reject internal/private resolutions — an AUTHENTICATED request to an internal host
    // is worse than the unauth navigate default. The producer ALSO refuses to run under this
    // policy (mirrors bob_http_xss_confirm), so this is defense in depth.
    const blockInternalHosts = !!(args && args.block_internal_hosts === true);
    let parsed;
    try {
      parsed = new URL(url);
    } catch {
      throw new Error("authed_fetch.url is not a valid absolute URL");
    }
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
      throw new Error("authed_fetch.url must be http(s)");
    }
    const origin = parsed.origin;
    // Scope-check BOTH the fetch URL and the origin we navigate to, honoring the policy.
    try {
      await assertSafeResolvedRequestUrl(url, this.targetDomain, { blockInternalHosts });
      await assertSafeResolvedRequestUrl(origin, this.targetDomain, { blockInternalHosts });
    } catch (err) {
      const wrapped = new Error(`scope_blocked: ${err && err.message ? err.message : err}`);
      wrapped.code = "scope_blocked";
      throw wrapped;
    }
    // DNS-rebinding + internal-host enforcement (round-3/4/5). The launch pin makes Chrome
    // connect to the IP we resolved (no re-resolution), but only for the pinned host. Because
    // authed_fetch is ALWAYS credentialed, the pin is REQUIRED on every call (not opt-in under
    // block_internal_hosts): a credentialed request must never ride an attacker-rebound
    // hostname to a different IP. The producer therefore starts the session with target_url on
    // the exact host it will read, so that host is the one pinned at launch.
    const fetchHost = parsed.hostname.toLowerCase();
    if (this.proxy) {
      // Under an egress proxy, DNS resolves at the proxy — we cannot pin or vet the IP the
      // browser connects to. We can't keep the no-internal-host promise, so refuse it; without
      // it, proxied egress is the operator's deliberate, trusted config.
      if (blockInternalHosts) {
        const e = new Error(
          "scope_blocked: authed_fetch cannot enforce block_internal_hosts through an egress proxy (DNS resolves at the proxy)",
        );
        e.code = "scope_blocked";
        throw e;
      }
    } else {
      const pin = this.pinnedHosts.get(fetchHost);
      if (!pin) {
        // Not pinned at launch → the browser would re-resolve it, so a credentialed fetch could
        // ride a rebind. Refuse ALWAYS (the round-4 hole: this was only enforced under
        // block_internal_hosts, leaving the default path rebindable).
        const e = new Error(
          `scope_blocked: authed_fetch host ${parsed.hostname} was not DNS-pinned at launch; a credentialed fetch must target the pinned host (start the session with target_url on this host)`,
        );
        e.code = "scope_blocked";
        throw e;
      }
      if (blockInternalHosts && pin.internal) {
        // The pinned IP itself is private/blocked — being pinned is not enough; the no-internal
        // promise must reject it (this is the round-3 hole: a presence-only check passed here).
        const e = new Error(
          `scope_blocked: authed_fetch host ${parsed.hostname} pins to an internal address; refusing under block_internal_hosts`,
        );
        e.code = "scope_blocked";
        throw e;
      }
    }
    const timeout = resolveOpTimeout(args, DEFAULT_NAVIGATE_TIMEOUT_MS);
    // Trusted-op flag: suppress logging of the priming nav + the credentialed fetch from the
    // agent-readable request log / record buffer (they carry the producer's auth). Cleared in
    // the finally so a thrown op can't leave logging suppressed for later agent traffic.
    //
    // ACCEPTED RESIDUAL — priming redirect under block_internal_hosts: page.goto follows
    // redirects, so a server-driven 3xx to an internal host could fire ONE request before the
    // origin-drift guard rejects the fetch. We deliberately do NOT block it with a catch-all
    // network-route interceptor — that is forbidden (browser-driver-tools.test.js): such an
    // interceptor aborts page-decided subresource loads (Kasada/Akamai anti-bot, CDN bundles,
    // OAuth callbacks), the exact WAF-protected flows this transport exists to survive, so it
    // would defeat the transport's purpose. Bounded instead by: the producer REFUSES under
    // block_internal_hosts (this is a direct-driver defense-in-depth path); the pin connects the
    // target host to a validated IP; the origin-drift guard refuses the fetch after any
    // redirect; and the scope check validates the URL's resolved IP under block_internal_hosts.
    this.authedFetchOp = { host: fetchHost };
    try {
      return await this.runAuthedFetchOp({ origin, url, method, headers, body, timeout });
    } finally {
      this.authedFetchOp = null;
    }
  }

  // Executes the priming navigation + the in-page credentialed fetch for authedFetch(). Split
  // out so authedFetch() can wrap it in the trusted-op guards (request-log suppression + the
  // strict per-host request abort) with a single try/finally cleanup.
  async runAuthedFetchOp({ origin, url, method, headers, body, timeout }) {
    // waitUntil:"commit" returns as soon as the response begins — it minimizes execution of
    // the (authenticated) origin page's own JS before the in-page fetch. Same-origin context
    // is still required (a cross-origin fetch would be CORS-opaque), so a minimal navigation
    // is unavoidable; commit keeps that side-effect surface as small as possible.
    const navResp = await this.page.goto(origin, { waitUntil: "commit", timeout });
    let landedOrigin = null;
    try { landedOrigin = new URL(this.page.url()).origin; } catch { landedOrigin = null; }
    if (landedOrigin !== origin) {
      const e = new Error(`authed_fetch_origin_drift: landed on ${landedOrigin} not ${origin}`);
      e.code = "authed_fetch_origin_drift";
      throw e;
    }
    await randomDelay(150, 400);
    // redirect:"manual" — do NOT follow redirects: an authenticated request that followed a
    // 3xx could leak the auth to an OFF-SCOPE origin (the scope check only covers the first
    // hop). A redirect surfaces as type "opaqueredirect" / status 0, so the producer's 2xx
    // oracle fails closed.
    const fetchInit = { method, headers, credentials: "include", redirect: "manual" };
    if (body != null && method !== "GET") fetchInit.body = body;
    // Built server-side from validated inputs; runs in the page world (real Chrome stack).
    // Hardening:
    //  • self-aborts via AbortSignal.timeout AT the deadline so the authenticated request is
    //    actually cancelled in the renderer (not left running after the caller is told it timed
    //    out). The in-page catch converts that abort into a { __timeout: true } sentinel so the
    //    timeout is surfaced deterministically (no fragile error-message matching); the
    //    wall-clock race below remains a backstop for a page.evaluate that hangs entirely.
    //  • streams the body with a hard cap measured in BYTES (Uint8Array.byteLength), not
    //    UTF-16 code units, enforced WHILE reading, so an oversized/hostile response cannot
    //    buffer unbounded memory and "2 MiB" means 2 MiB.
    // ACCEPTED RESIDUAL — page-controlled fetch: the request runs in the page world, so a
    // hostile target page could in principle override window.fetch / Response to forge the
    // result. This is INHERENT to the transport's purpose: carrying the real Chrome TLS/HTTP-2
    // fingerprint REQUIRES the page network stack (a Node-side context.request is CF-403'd —
    // the gap this transport exists to close), and capturing a "native" fetch reference is
    // unreliable under the Patchright stealth driver (its fetch wrapper rejects a detached
    // call). Compensating controls: waitUntil:"commit" minimizes page-script execution before
    // the fetch. On integrity, the differential is NOT tamper-proof — the target can tell the
    // authed arm (it carries the cookie) from the control arm and could serve forged data — but
    // a target forging a vuln against ITSELF gains nothing (it would be self-reporting), the
    // per-tool ceiling bounds a forged result, and the producer treats a single capture as
    // evidence, not proof (the operator corroborates for integrity-sensitive use).
    const fetchInitJson = JSON.stringify(fetchInit);
    const expr = `(async () => {
      const __cap = ${MAX_AUTHED_FETCH_BODY_BYTES};
      const __init = ${fetchInitJson};
      try { __init.signal = AbortSignal.timeout(${timeout}); } catch (e) {}
      try {
        const __r = await fetch(${JSON.stringify(url)}, __init);
        let __bytes = 0;
        let __truncated = false;
        const __dec = new TextDecoder();
        const __parts = [];
        if (__r.body && typeof __r.body.getReader === "function") {
          const __reader = __r.body.getReader();
          for (;;) {
            const { done, value } = await __reader.read();
            if (done) break;
            let __chunk = value;
            if (__bytes + __chunk.byteLength > __cap) {
              __chunk = __chunk.subarray(0, __cap - __bytes);
              __truncated = true;
            }
            __bytes += __chunk.byteLength;
            __parts.push(__dec.decode(__chunk, { stream: true }));
            if (__truncated) { try { await __reader.cancel(); } catch (e) {} break; }
          }
          __parts.push(__dec.decode());
        } else {
          const __buf = new Uint8Array(await __r.arrayBuffer());
          __truncated = __buf.byteLength > __cap;
          __parts.push(__dec.decode(__buf.subarray(0, __cap)));
        }
        return { status: __r.status, type: __r.type, final_url: __r.url, body: __parts.join(""), body_truncated: __truncated };
      } catch (e) {
        if (e && (e.name === "TimeoutError" || e.name === "AbortError")) return { __timeout: true };
        throw e;
      }
    })()`;
    // Same wall-clock race as evaluate() so a hung fetch returns a precise timeout instead
    // of pinning the single-page session until the IPC backstop fires.
    const evalPromise = this.page.evaluate(expr);
    evalPromise.catch(() => {});
    let timer;
    let result;
    try {
      result = await Promise.race([
        evalPromise,
        new Promise((_, reject) => {
          timer = setTimeout(() => {
            const e = new Error(`authed_fetch_timeout after ${timeout}ms`);
            e.code = "authed_fetch_timeout";
            reject(e);
          }, timeout);
          if (timer && typeof timer.unref === "function") timer.unref();
        }),
      ]);
    } catch (err) {
      if (err && err.code === "authed_fetch_timeout") throw err;
      throw new Error(`authed_fetch_failed: ${err && err.message ? err.message : err}`);
    } finally {
      clearTimeout(timer);
    }
    if (result && result.__timeout) {
      // The in-page AbortSignal.timeout fired AT the deadline and cancelled the fetch.
      const e = new Error(`authed_fetch_timeout after ${timeout}ms`);
      e.code = "authed_fetch_timeout";
      throw e;
    }
    return {
      status: result && Number.isInteger(result.status) ? result.status : null,
      // "opaqueredirect" (status 0) means the endpoint 3xx'd and redirect:"manual" refused to
      // follow it — the producer treats this as non-confirming (not a 2xx bulk read).
      type: result && result.type ? String(result.type) : null,
      final_url: result && result.final_url ? String(result.final_url) : null,
      body: result && typeof result.body === "string" ? result.body : "",
      body_truncated: !!(result && result.body_truncated),
      nav_status: navResp ? navResp.status() : null,
    };
  }

  async networkRequests(args) {
    const since = Number.isInteger(args && args.since_index) ? Math.max(0, args.since_index) : 0;
    const slice = this.requests.slice(since);
    return {
      requests: slice,
      next_index: this.requests.length,
      since_index: since,
    };
  }

  async consoleMessages(args) {
    const since = Number.isInteger(args && args.since_index) ? Math.max(0, args.since_index) : 0;
    const slice = this.consoles.slice(since);
    return {
      messages: slice,
      next_index: this.consoles.length,
      since_index: since,
    };
  }

  async waitFor(args) {
    const predicate = args && typeof args.predicate === "object" ? args.predicate : null;
    if (!predicate || typeof predicate.kind !== "string") {
      throw new Error("wait_for.predicate must be a structured object with a `kind`");
    }
    const timeout = resolveOpTimeout(args, DEFAULT_WAIT_FOR_TIMEOUT_MS);
    const startedAt = Date.now();
    try {
      switch (predicate.kind) {
        case "selector": {
          const value = typeof predicate.value === "string" ? predicate.value : null;
          if (!value) throw new Error("wait_for.predicate.value (selector string) is required");
          await this.page.waitForSelector(value, { timeout });
          break;
        }
        case "url": {
          const value = predicate.value;
          // Accept exact string or a regex source.
          if (typeof value === "string") {
            await this.page.waitForURL(value, { timeout });
          } else if (value && typeof value === "object" && typeof value.regex === "string") {
            const flags = typeof value.flags === "string" ? value.flags : "";
            await this.page.waitForURL(new RegExp(value.regex, flags), { timeout });
          } else {
            throw new Error("wait_for.predicate.value must be a URL string or {regex, flags?}");
          }
          break;
        }
        case "network_idle":
          await this.page.waitForLoadState("networkidle", { timeout });
          break;
        case "load_state": {
          const value = predicate.value;
          const allowed = ["load", "domcontentloaded", "networkidle"];
          if (typeof value !== "string" || !allowed.includes(value)) {
            throw new Error(`wait_for.predicate.value must be one of ${allowed.join(", ")}`);
          }
          await this.page.waitForLoadState(value, { timeout });
          break;
        }
        default:
          throw new Error(`wait_for.predicate.kind ${predicate.kind} is not supported`);
      }
      return { matched: true, elapsed_ms: Date.now() - startedAt };
    } catch (err) {
      return {
        matched: false,
        elapsed_ms: Date.now() - startedAt,
        error: err && err.message ? err.message : String(err),
      };
    }
  }

  async pressKey(args) {
    const key = String(args && args.key != null ? args.key : "");
    if (!key) throw new Error("press_key.key is required");
    await this.page.keyboard.press(key);
    return { ok: true };
  }

  async takeScreenshot(args) {
    const fullPage = args && args.full_page === true;
    const dir = screenshotsDirFor(sanitizeDomainForPath(this.targetDomain), this.sessionsRoot);
    ensureDir(dir);
    this.screenshotSeq += 1;
    const fileName = `${this.sessionId}-${String(this.screenshotSeq).padStart(4, "0")}.png`;
    const artifactPath = path.join(dir, fileName);
    await this.page.screenshot({ path: artifactPath, fullPage, timeout: DEFAULT_SCREENSHOT_TIMEOUT_MS });
    return { artifact_path: artifactPath };
  }

  async fillForm(args) {
    const fields = Array.isArray(args && args.fields) ? args.fields : [];
    if (!fields.length) throw new Error("fill_form.fields must be a non-empty array");
    const errors = [];
    let filled = 0;
    for (const field of fields) {
      if (!field || typeof field !== "object") {
        errors.push({ ref: null, error: "field must be an object {ref, value}" });
        continue;
      }
      const { ref, value } = field;
      try {
        const locator = await this.resolveLocator(ref);
        await locator.click({ timeout: DEFAULT_WAIT_FOR_TIMEOUT_MS });
        await randomDelay(50, 150);
        const text = value == null ? "" : String(value);
        for (const { char, delay } of humanType(text)) {
          await locator.pressSequentially(char, { delay: 0 });
          await new Promise((r) => setTimeout(r, delay));
        }
        await randomDelay(120, 320);
        filled += 1;
      } catch (err) {
        errors.push({ ref, error: err && err.message ? err.message : String(err) });
      }
    }
    const result = { filled };
    if (errors.length) result.errors = errors;
    return result;
  }
}

// ── Bootstrap ──

async function main() {
  let initConfig;
  try {
    const raw = (process.env.BOB_BROWSER_DRIVER_INIT || "").trim();
    if (!raw) {
      writeResponse({ ready: false, error: "init_missing: BOB_BROWSER_DRIVER_INIT env var is required" });
      process.exit(2);
      return;
    }
    initConfig = JSON.parse(raw);
  } catch (err) {
    writeResponse({ ready: false, error: `init_parse_error: ${err && err.message ? err.message : err}` });
    process.exit(2);
    return;
  }

  const sessionId = String(initConfig.session_id || crypto.randomBytes(8).toString("hex"));
  const targetDomain = String(initConfig.target_domain || "").trim();
  const targetUrl = String(initConfig.target_url || "").trim();
  const headless = initConfig.headless === true;
  const recordMode = initConfig.record_mode === true;
  const sessionsRoot = initConfig.sessions_root || path.join(os.homedir(), "hacker-bob-sessions");
  // Egress proxy already validated by the tool wrapper before spawn; the
  // driver just trusts the structured shape and refuses anything else.
  const proxy = initConfig.proxy && typeof initConfig.proxy === "object"
    && typeof initConfig.proxy.server === "string"
    ? initConfig.proxy
    : null;
  // NOTE: cookie auth for the trusted authed_fetch transport is NO LONGER carried in the init
  // env — it arrives after ready via the server-side-only `set_auth_cookies` stdin command, so
  // auth secrets never touch the process environment (no child/renderer inheritance, no
  // /proc/<pid>/environ snapshot).

  if (!targetDomain) {
    writeResponse({ ready: false, error: "init_invalid: target_domain is required" });
    process.exit(2);
    return;
  }
  if (!targetUrl) {
    writeResponse({ ready: false, error: "init_invalid: target_url is required" });
    process.exit(2);
    return;
  }

  try {
    await assertSafeResolvedRequestUrl(targetUrl, targetDomain, { blockInternalHosts: false });
  } catch (err) {
    writeResponse({ ready: false, error: `scope_blocked: ${err && err.message ? err.message : err}` });
    process.exit(2);
    return;
  }

  // Scrub the init env BEFORE launching Chromium so the browser's child/renderer processes do
  // NOT inherit proxy credentials via their environment. (The driver's own /proc/environ
  // retains the spawn-time value — the documented same-UID boundary, #131 — but cross-process
  // child inheritance is the avoidable delta, closed here. Cookie auth is no longer in the env
  // at all; it arrives over stdin via set_auth_cookies.)
  delete process.env.BOB_BROWSER_DRIVER_INIT;

  const driver = new BrowserDriver({
    sessionId,
    targetDomain,
    targetUrl,
    headless,
    sessionsRoot,
    recordMode,
    proxy,
  });
  try {
    await driver.start();
  } catch (err) {
    writeResponse({
      ready: false,
      error: err && err.message ? err.message : String(err),
      code: err && err.code ? err.code : "browser_start_failed",
    });
    process.exit(2);
    return;
  }
  emitReady(sessionId);

  const rl = readline.createInterface({ input: process.stdin });
  rl.on("line", async (line) => {
    let request;
    try {
      request = JSON.parse(line);
    } catch (err) {
      writeResponse({ command_id: null, error: `invalid_json: ${err && err.message ? err.message : err}` });
      return;
    }
    const { command_id: commandId = null, command, args } = request || {};
    try {
      const result = await driver.handleCommand(command, args || {});
      writeResponse({ command_id: commandId, result });
      if (command === "close") {
        await driver.shutdown("close_command");
      }
    } catch (err) {
      writeResponse({
        command_id: commandId,
        error: err && err.message ? err.message : String(err),
        code: err && err.code ? err.code : null,
      });
    }
  });

  rl.on("close", async () => {
    await driver.shutdown("stdin_closed");
  });
}

main().catch((err) => {
  writeResponse({ ready: false, error: err && err.message ? err.message : String(err) });
  process.exit(2);
});
