"use strict";

const {
  assertSafeResolvedRequestUrl,
} = require("../safe-fetch.js");
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
    const url = assertNonEmptyString(args.url, "url");
    ensureSessionMatchesDomain(sessionId, targetDomain);
    try {
      await assertSafeResolvedRequestUrl(url, targetDomain, {
        blockInternalHosts: false,
      });
    } catch (err) {
      const wrapped = new Error(`scope_blocked: ${err && err.message ? err.message : err}`);
      wrapped.code = "scope_blocked";
      throw wrapped;
    }
    const result = await callBrowser("navigate", sessionId, {
      url,
      timeout_ms: args.timeout_ms,
    });
    return envelopeSuccess(result);
  } catch (err) {
    return envelopeFromError(err);
  }
}

module.exports = Object.freeze({
  name: "bob_browser_navigate",
  description:
    "Navigate an existing browser session to an in-scope URL. The URL is scope-checked before the navigation is dispatched; off-scope navigations are refused with code scope_blocked.",
  inputSchema: {
    type: "object",
    properties: {
      target_domain: { type: "string", description: "Session anchor; must match the session's target_domain." },
      session_id: { type: "string", description: "session_id from bob_browser_session_start." },
      url: { type: "string", description: "Target URL; host must equal target_domain or be a subdomain." },
      timeout_ms: { type: "number", description: "Optional navigation timeout (ms). Default 30000." },
    },
    required: ["target_domain", "session_id", "url"],
  },
  handler,
  role_bundles: BROWSER_BUNDLES,
  mutating: true,
  global_preapproval: false,
  network_access: true,
  browser_access: true,
  scope_required: true,
  scope_url_fields: ["url"],
  sensitive_output: false,
  session_artifacts_written: [],
});
