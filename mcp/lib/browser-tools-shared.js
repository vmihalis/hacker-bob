"use strict";

// Shared envelope + scope-check helpers for the bob_browser_* MCP tool family.
// Each tool wrapper validates its target_domain, optionally validates a URL
// against scope (defense-in-depth on top of the driver's own check), then
// routes through browser-sessions.js. Failures convert to a structured JSON
// envelope rather than throwing into the registry — keeps the agent's view
// stable when patchright is absent or a session has been reaped.

const {
  assertNonEmptyString,
} = require("./validation.js");
const browserSessions = require("./browser-sessions.js");
const {
  EGRESS_PROFILE_NAME_RE,
  resolveEgressProfile,
} = require("./egress-profiles.js");

// Playwright's chromium.launch accepts proxy: { server, username?, password?,
// bypass? }. We coerce the egress-profile proxy_url (already env-expanded and
// scheme-validated by resolveEgressProfile) into that shape here so the
// subprocess only ever sees the structured form.
const PLAYWRIGHT_PROXY_SCHEMES = new Set(["http:", "https:", "socks5:"]);

function errorEnvelope(code, message, extra = {}) {
  return {
    ok: false,
    error: { code, message, ...extra },
  };
}

function parseProxyUrlForPlaywright(proxyUrl) {
  if (proxyUrl == null) return null;
  let parsed;
  try {
    parsed = new URL(proxyUrl);
  } catch (err) {
    const wrapped = new Error(`egress_proxy_url_malformed: ${err && err.message ? err.message : err}`);
    wrapped.code = "egress_proxy_url_malformed";
    throw wrapped;
  }
  if (!PLAYWRIGHT_PROXY_SCHEMES.has(parsed.protocol)) {
    // socks5h is supported by the HTTP proxy-agent but Patchright/Playwright's
    // chromium.launch only knows http/https/socks5. Refuse rather than silently
    // dropping into a wrong-scheme proxy.
    const err = new Error(
      `egress_proxy_url_unsupported_scheme: ${parsed.protocol} (allowed for browser sessions: http://, https://, socks5://)`,
    );
    err.code = "egress_proxy_url_unsupported_scheme";
    throw err;
  }
  if (!parsed.hostname) {
    const err = new Error("egress_proxy_url_missing_host");
    err.code = "egress_proxy_url_malformed";
    throw err;
  }
  const portFragment = parsed.port ? `:${parsed.port}` : "";
  const server = `${parsed.protocol}//${parsed.hostname}${portFragment}`;
  const proxy = { server };
  // URL decodes percent-encoded username/password automatically; pass through
  // the decoded form (Playwright handles re-encoding in CONNECT headers).
  if (parsed.username) {
    proxy.username = decodeURIComponent(parsed.username);
  }
  if (parsed.password) {
    proxy.password = decodeURIComponent(parsed.password);
  }
  return proxy;
}

// Returns:
//   { ok: true,  proxy, profile: { name, region, proxy_configured } }
//   { ok: false, envelope: <structured error string ready to return to caller> }
//
// Direct (no proxy) is signaled by ok:true + proxy:null. The default profile
// always resolves to { ok:true, proxy:null } (no env lookup, no validation).
function resolveBrowserEgressProfile(requestedName) {
  const trimmed = typeof requestedName === "string" ? requestedName.trim() : "";
  const name = trimmed || "default";

  // Cheap shape check at the wrapper so an obviously bad name returns a stable
  // error code before we read the config file.
  if (!EGRESS_PROFILE_NAME_RE.test(name)) {
    return {
      ok: false,
      envelope: JSON.stringify(errorEnvelope(
        "egress_profile_invalid_name",
        `egress_profile name must match ${EGRESS_PROFILE_NAME_RE.source}`,
        { egress_profile: name },
      )),
    };
  }

  if (name === "default") {
    // Preserve current direct-egress behavior: the default profile is always
    // present, always enabled, and uses proxy_url: null. Skip the file read so
    // an absent .claude/bob/egress-profiles.json still resolves cleanly.
    return {
      ok: true,
      proxy: null,
      profile: { name: "default", region: null, proxy_configured: false },
    };
  }

  let resolved;
  try {
    resolved = resolveEgressProfile(name);
  } catch (err) {
    const message = err && err.message ? err.message : String(err);
    let code = "egress_profile_resolve_failed";
    if (/was not found/i.test(message)) code = "egress_profile_not_found";
    else if (/is disabled/i.test(message)) code = "egress_profile_disabled";
    else if (/env var .* is not set/i.test(message)) code = "egress_profile_env_missing";
    else if (/unsupported egress proxy protocol/i.test(message)) code = "egress_profile_unsupported_protocol";
    else if (/proxy URL is malformed/i.test(message)) code = "egress_profile_malformed_url";
    return {
      ok: false,
      envelope: JSON.stringify(errorEnvelope(code, message, { egress_profile: name })),
    };
  }

  let proxy = null;
  if (resolved.proxy_url != null) {
    try {
      proxy = parseProxyUrlForPlaywright(resolved.proxy_url);
    } catch (err) {
      return {
        ok: false,
        envelope: JSON.stringify(errorEnvelope(
          err && err.code ? err.code : "egress_profile_malformed_url",
          err && err.message ? err.message : String(err),
          { egress_profile: name },
        )),
      };
    }
  }

  return {
    ok: true,
    proxy,
    profile: {
      name: resolved.name,
      region: resolved.region || null,
      proxy_configured: resolved.proxy_configured === true,
    },
  };
}

// Defense-in-depth: the wrapper rejects the same forbidden patterns the driver
// rejects, so we never even spawn the subprocess for an obviously bad expr.
//
// Two classes of agent-controlled bypass are blocked:
//   (1) Direct network IO from page context: XMLHttpRequest, fetch(),
//       navigator.sendBeacon(), EventSource, WebSocket. Agents should use
//       bob_http_scan or bob_browser_navigate for HTTP traffic.
//   (2) Top-level navigation writes: location.href=, location.assign,
//       location.replace, window.location=, document.location=, window.open,
//       top.location / parent.location. The agent-controlled navigation gate
//       is bob_browser_navigate (scope-checked); without these patterns the
//       evaluate sandbox would let the agent point the browser anywhere.
//
// Page-initiated subresource loads (CDN bundles, anti-bot fingerprint scripts,
// OAuth callbacks the server redirects to, analytics, etc.) are NOT the
// agent's choice — the page itself wired them in HTML/JS. They run unblocked.
const FORBIDDEN_EVAL_PATTERN =
  /XMLHttpRequest|fetch\(|navigator\.sendBeacon|new\s+EventSource|new\s+WebSocket|window\.open\(|(?:window|document|top|parent)\.location\s*=|location\.(?:href|assign|replace)/i;

function patchrightUnavailableEnvelope() {
  return errorEnvelope(
    "patchright_unavailable",
    "Optional dependency patchright is not installed; the bob_browser_* tools cannot start a session. Run `npm install` and `npx patchright install chromium` to enable browser-shaped surface coverage.",
  );
}

function safeSessionId(value) {
  return assertNonEmptyString(value, "session_id");
}

function safeTargetDomain(value) {
  return assertNonEmptyString(value, "target_domain");
}

function assertExpressionSandbox(expression) {
  if (typeof expression !== "string" || !expression.trim()) {
    const err = new Error("expression must be a non-empty string");
    err.code = "invalid_arguments";
    throw err;
  }
  if (FORBIDDEN_EVAL_PATTERN.test(expression)) {
    const err = new Error(
      "evaluate_sandbox_violation: expression contains forbidden network-IO pattern (XMLHttpRequest, fetch(, sendBeacon, EventSource, WebSocket). Use bob_http_scan or bob_browser_navigate for HTTP traffic; the expression sandbox blocks page-context network calls.",
    );
    err.code = "evaluate_sandbox_violation";
    throw err;
  }
  return expression;
}

// The IPC round-trip deadline (browser-sessions.js raceWithTimeout) must track
// the command's own operation timeout, not sit at a flat 90s ceiling. Without
// this: a command's documented timeout_ms can't shorten an IPC-level wedge
// (subprocess stalled in Chromium before it ever replies), so an agent setting
// a small timeout_ms to fail fast still holds the slot for the full ceiling;
// and a timeout_ms LARGER than the ceiling is silently cut at 90s, orphaning
// subprocess work that then blocks every later command on the same single-page
// session. When the command carries an explicit positive timeout_ms, arm the
// IPC deadline at timeout_ms + a margin so the driver's own per-operation
// timeout fires first with a precise error and the IPC race is only the
// backstop. Commands without an operation timeout keep the registry default.
const IPC_DEADLINE_MARGIN_MS = 5_000;

async function callBrowser(command, sessionId, args = {}) {
  const opTimeout = args && Number.isFinite(args.timeout_ms) ? Number(args.timeout_ms) : null;
  const options = opTimeout != null && opTimeout > 0
    ? { timeoutMs: opTimeout + IPC_DEADLINE_MARGIN_MS }
    : undefined;
  return browserSessions.sendCommand(sessionId, command, args, options);
}

function ensureSessionMatchesDomain(sessionId, targetDomain) {
  const entry = browserSessions.getSession(sessionId);
  if (!entry) {
    const err = new Error(`browser_session_not_found: ${sessionId}`);
    err.code = "browser_session_not_found";
    throw err;
  }
  if (entry.closed) {
    const err = new Error(`browser_session_closed: ${sessionId}`);
    err.code = "browser_session_closed";
    throw err;
  }
  if (entry.targetDomain !== targetDomain) {
    const err = new Error(
      `browser_session_domain_mismatch: session ${sessionId} is bound to ${entry.targetDomain}, not ${targetDomain}`,
    );
    err.code = "browser_session_domain_mismatch";
    throw err;
  }
  return entry;
}

function envelopeSuccess(fields) {
  return JSON.stringify({ ok: true, ...fields });
}

function envelopeFromError(err) {
  return JSON.stringify(
    errorEnvelope(
      err && err.code ? err.code : "browser_tool_error",
      err && err.message ? err.message : String(err),
    ),
  );
}

module.exports = {
  FORBIDDEN_EVAL_PATTERN,
  IPC_DEADLINE_MARGIN_MS,
  PLAYWRIGHT_PROXY_SCHEMES,
  assertExpressionSandbox,
  browserSessions,
  callBrowser,
  ensureSessionMatchesDomain,
  envelopeFromError,
  envelopeSuccess,
  errorEnvelope,
  parseProxyUrlForPlaywright,
  patchrightUnavailableEnvelope,
  resolveBrowserEgressProfile,
  safeSessionId,
  safeTargetDomain,
};
