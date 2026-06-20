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
} = require("./lib/safe-fetch.js");

const IDLE_TIMEOUT_MS = 5 * 60 * 1000;
const HARD_TIMEOUT_MS = 30 * 60 * 1000;
const DEFAULT_NAVIGATE_TIMEOUT_MS = 30_000;
const DEFAULT_WAIT_FOR_TIMEOUT_MS = 15_000;
const DEFAULT_EVALUATE_TIMEOUT_MS = 15_000;
const DEFAULT_SCREENSHOT_TIMEOUT_MS = 30_000;
const MAX_EVAL_RESULT_BYTES = 256 * 1024;
const MAX_SNAPSHOT_BYTES = 512 * 1024;
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
