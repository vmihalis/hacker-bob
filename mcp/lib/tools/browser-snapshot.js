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
    ensureSessionMatchesDomain(sessionId, targetDomain);
    const result = await callBrowser("snapshot", sessionId, {});
    return envelopeSuccess(result);
  } catch (err) {
    return envelopeFromError(err);
  }
}

module.exports = Object.freeze({
  name: "bob_browser_snapshot",
  description:
    "Return the accessibility tree (interestingOnly) for the current page in the session. Use the snapshot to discover refs for click/type/fill_form (selector:, text:, role:role:name).",
  inputSchema: {
    type: "object",
    properties: {
      target_domain: { type: "string" },
      session_id: { type: "string" },
    },
    required: ["target_domain", "session_id"],
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
});
