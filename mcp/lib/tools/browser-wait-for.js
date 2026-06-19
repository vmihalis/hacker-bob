"use strict";

const {
  browserSessions,
  callBrowser,
  ensureSessionMatchesDomain,
  envelopeFromError,
  envelopeSuccess,
  patchrightUnavailableEnvelope,
  safeSessionId,
  safeTargetDomain,
} = require("../browser-tools-shared.js");

const BROWSER_BUNDLES = ["evaluator-shared", "surface-discovery", "deep-surface-discovery"];

async function handler(args = {}) {
  if (!browserSessions.isPatchrightAvailable()) {
    return JSON.stringify(patchrightUnavailableEnvelope());
  }
  try {
    const targetDomain = safeTargetDomain(args.target_domain);
    const sessionId = safeSessionId(args.session_id);
    if (!args.predicate || typeof args.predicate !== "object" || Array.isArray(args.predicate)) {
      throw new Error("predicate must be an object with a kind field");
    }
    ensureSessionMatchesDomain(sessionId, targetDomain);
    const result = await callBrowser("wait_for", sessionId, {
      predicate: args.predicate,
      timeout_ms: Number.isFinite(args.timeout_ms) ? args.timeout_ms : undefined,
    });
    return envelopeSuccess(result);
  } catch (err) {
    return envelopeFromError(err);
  }
}

module.exports = Object.freeze({
  name: "bob_browser_wait_for",
  description:
    "Wait until the page satisfies a structured predicate. predicate.kind is one of: 'selector' (value: CSS selector string), 'url' (value: string or {regex, flags}), 'network_idle' (value ignored), 'load_state' (value: 'load'|'domcontentloaded'|'networkidle'). Raw JS functions are NOT accepted — predicates are structured.",
  inputSchema: {
    type: "object",
    properties: {
      target_domain: { type: "string" },
      session_id: { type: "string" },
      predicate: {
        type: "object",
        properties: {
          kind: { type: "string", enum: ["selector", "url", "network_idle", "load_state"] },
          value: { description: "Selector string, URL string or {regex, flags?}, or load-state name. May be omitted for kind 'network_idle'." },
        },
        required: ["kind"],
      },
      timeout_ms: { type: "number", description: "Optional wait timeout (ms). Default 15000." },
    },
    required: ["target_domain", "session_id", "predicate"],
  },
  handler,
  role_bundles: BROWSER_BUNDLES,
  mutating: false,
  global_preapproval: false,
  network_access: false,
  browser_access: true,
  scope_required: true,
  sensitive_output: false,
  session_artifacts_written: [],
});
