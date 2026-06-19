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
    ensureSessionMatchesDomain(sessionId, targetDomain);
    const result = await callBrowser("click", sessionId, { ref });
    return envelopeSuccess(result);
  } catch (err) {
    return envelopeFromError(err);
  }
}

module.exports = Object.freeze({
  name: "bob_browser_click",
  description:
    "Click an element in the current page. The ref accepts three shapes: 'selector:<css>', 'text:<accessible name>', or 'role:<role>:<accessible name>'.",
  inputSchema: {
    type: "object",
    properties: {
      target_domain: { type: "string" },
      session_id: { type: "string" },
      ref: { type: "string", description: "Locator: selector:<css> | text:<name> | role:<role>:<name>." },
    },
    required: ["target_domain", "session_id", "ref"],
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
