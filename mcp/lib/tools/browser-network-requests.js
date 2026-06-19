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
    const result = await callBrowser("network_requests", sessionId, {
      since_index: Number.isInteger(args.since_index) ? args.since_index : undefined,
    });
    return envelopeSuccess(result);
  } catch (err) {
    return envelopeFromError(err);
  }
}

module.exports = Object.freeze({
  name: "bob_browser_network_requests",
  description:
    "Return browser-captured request records since session start (or since the optional since_index for incremental polling). Each record carries method, url, resource_type, headers, post_data, and timestamp.",
  inputSchema: {
    type: "object",
    properties: {
      target_domain: { type: "string" },
      session_id: { type: "string" },
      since_index: { type: "number", description: "Optional integer; only return records at this index or later. Use next_index from a prior call." },
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
