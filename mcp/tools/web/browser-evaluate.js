"use strict";

const {
  assertExpressionSandbox,
  browserSessions,
  callBrowser,
  ensureSessionMatchesDomain,
  envelopeFromError,
  envelopeSuccess,
  patchrightUnavailableEnvelope,
  safeSessionId,
  safeTargetDomain,
} = require("../../domains/web/browser-tools-shared.js");

const BROWSER_BUNDLES = ["evaluator-shared", "surface-discovery", "deep-surface-discovery"];

async function handler(args = {}) {
  if (!browserSessions.isPatchrightAvailable()) {
    return JSON.stringify(patchrightUnavailableEnvelope());
  }
  try {
    const targetDomain = safeTargetDomain(args.target_domain);
    const sessionId = safeSessionId(args.session_id);
    // Defense-in-depth: wrapper rejects forbidden patterns before invoking
    // the driver. The driver applies the same check, so off-scope or
    // adversarial expressions never reach the page context.
    const expression = assertExpressionSandbox(args.expression);
    ensureSessionMatchesDomain(sessionId, targetDomain);
    const result = await callBrowser("evaluate", sessionId, {
      expression,
      timeout_ms: Number.isFinite(args.timeout_ms) ? args.timeout_ms : undefined,
    });
    return envelopeSuccess(result);
  } catch (err) {
    return envelopeFromError(err);
  }
}

module.exports = Object.freeze({
  name: "bob_browser_evaluate",
  description:
    "Evaluate a JavaScript expression in the page context and return the value. SANDBOXED: the expression is rejected if it contains any of XMLHttpRequest, fetch(, navigator.sendBeacon, new EventSource, or new WebSocket. Use bob_http_scan or bob_browser_navigate for HTTP traffic — page-context network calls bypass Bob's scope and audit ledger. Use this tool for DOM inspection, attribute reads, postMessage probes, storage reads, and other read-shaped JS.",
  inputSchema: {
    type: "object",
    properties: {
      target_domain: { type: "string" },
      session_id: { type: "string" },
      expression: {
        type: "string",
        description: "JavaScript expression evaluated in the page context. Forbidden tokens: XMLHttpRequest, fetch(, navigator.sendBeacon, new EventSource, new WebSocket — Bob refuses these because page-origin network calls bypass scope checks and the request audit. Use the HTTP-aware MCP tools instead.",
      },
      timeout_ms: { type: "number", description: "Optional evaluate timeout (ms). Default 15000. A runaway expression returns error code evaluate_timeout; if it blocks the renderer the session is wedged — close it and start a new one." },
    },
    required: ["target_domain", "session_id", "expression"],
  },
  handler,
  role_bundles: BROWSER_BUNDLES,
  mutating: false,
  global_preapproval: false,
  network_access: false,
  browser_access: true,
  scope_required: true,
  sensitive_output: true,
 session_artifacts_written: [],
  required_session_axes: ["url"],
});
