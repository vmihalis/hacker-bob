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
const {
  assertNonEmptyString,
} = require("../validation.js");

const BROWSER_BUNDLES = ["evaluator-shared", "surface-discovery", "deep-surface-discovery"];

async function handler(args = {}) {
  if (!browserSessions.isPatchrightAvailable()) {
    return JSON.stringify(patchrightUnavailableEnvelope());
  }
  try {
    const targetDomain = safeTargetDomain(args.target_domain);
    const sessionId = safeSessionId(args.session_id);
    const ref = assertNonEmptyString(args.ref, "ref");
    if (args.text == null || typeof args.text !== "string") {
      throw new Error("text must be a string");
    }
    ensureSessionMatchesDomain(sessionId, targetDomain);
    const result = await callBrowser("type", sessionId, { ref, text: args.text });
    return envelopeSuccess(result);
  } catch (err) {
    return envelopeFromError(err);
  }
}

module.exports = Object.freeze({
  name: "bob_browser_type",
  description:
    "Type text into an element with human-like keystroke timing (inherits auto-signup.js's humanType cadence). The ref accepts 'selector:<css>', 'text:<name>', or 'role:<role>:<name>'.",
  inputSchema: {
    type: "object",
    properties: {
      target_domain: { type: "string" },
      session_id: { type: "string" },
      ref: { type: "string" },
      text: { type: "string", description: "Literal text to type. Use bob_browser_fill_form for multiple fields." },
    },
    required: ["target_domain", "session_id", "ref", "text"],
  },
  handler,
  role_bundles: BROWSER_BUNDLES,
  mutating: true,
  global_preapproval: false,
  network_access: false,
  browser_access: true,
  scope_required: true,
  sensitive_output: false,
  session_artifacts_written: [],
});
