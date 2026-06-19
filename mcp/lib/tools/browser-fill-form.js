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
    if (!Array.isArray(args.fields) || args.fields.length === 0) {
      throw new Error("fields must be a non-empty array of {ref, value}");
    }
    for (const field of args.fields) {
      if (!field || typeof field !== "object" || typeof field.ref !== "string" || !field.ref.trim()) {
        throw new Error("each field must be an object with a non-empty ref string");
      }
    }
    ensureSessionMatchesDomain(sessionId, targetDomain);
    const result = await callBrowser("fill_form", sessionId, { fields: args.fields });
    return envelopeSuccess(result);
  } catch (err) {
    return envelopeFromError(err);
  }
}

module.exports = Object.freeze({
  name: "bob_browser_fill_form",
  description:
    "Fill multiple form fields with human-like keystroke timing (reuses auto-signup.js humanType cadence). fields is an array of { ref, value } where ref accepts 'selector:<css>', 'text:<name>', or 'role:<role>:<name>'.",
  inputSchema: {
    type: "object",
    properties: {
      target_domain: { type: "string" },
      session_id: { type: "string" },
      fields: {
        type: "array",
        items: {
          type: "object",
          properties: {
            ref: { type: "string" },
            value: { type: "string" },
          },
          required: ["ref"],
        },
      },
    },
    required: ["target_domain", "session_id", "fields"],
  },
  handler,
  role_bundles: BROWSER_BUNDLES,
  mutating: true,
  global_preapproval: false,
  network_access: false,
  browser_access: true,
  scope_required: true,
  sensitive_output: true,
  session_artifacts_written: [],
});
