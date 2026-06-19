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
    const key = assertNonEmptyString(args.key, "key");
    ensureSessionMatchesDomain(sessionId, targetDomain);
    const result = await callBrowser("press_key", sessionId, { key });
    return envelopeSuccess(result);
  } catch (err) {
    return envelopeFromError(err);
  }
}

module.exports = Object.freeze({
  name: "bob_browser_press_key",
  description:
    "Press a keyboard key on the current page (e.g., 'Enter', 'Escape', 'Tab', 'ArrowDown'). Uses real keyboard events.",
  inputSchema: {
    type: "object",
    properties: {
      target_domain: { type: "string" },
      session_id: { type: "string" },
      key: { type: "string", description: "Key name accepted by Playwright (e.g., Enter, Escape, ArrowDown, Tab)." },
    },
    required: ["target_domain", "session_id", "key"],
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
