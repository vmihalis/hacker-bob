"use strict";

// T.7 — Browser-driven traffic capture (Patchright record mode).
//
// Wraps bob_browser_session_start with record_mode: true and an optional
// navigation_plan. Captured traffic is buffered inside the subprocess; the
// caller pulls it via bob_browser_flush_recorded_requests, which routes the
// records through import-http-traffic.js (the session-lock-holding ingestion
// path — see T-R5).
//
// The plan supports the small set of actions that drive a typical
// authenticated capture: navigate → click → type → wait_for. Anything more
// elaborate should be driven via the individual bob_browser_* tools after
// this wrapper returns the session_id.

const {
  assertSafeResolvedRequestUrl,
} = require("../safe-fetch.js");
const {
  browserSessions,
  callBrowser,
  envelopeFromError,
  envelopeSuccess,
  patchrightUnavailableEnvelope,
  resolveBrowserEgressProfile,
  safeTargetDomain,
} = require("../browser-tools-shared.js");
const {
  assertNonEmptyString,
} = require("../validation.js");
const {
  EGRESS_PROFILE_NAME_RE,
} = require("../egress-profiles.js");

const BROWSER_BUNDLES = ["evaluator-shared", "surface-discovery", "deep-surface-discovery"];

const PLAN_ACTIONS = new Set(["navigate", "click", "type", "wait_for"]);
const MAX_PLAN_STEPS = 25;

function asObject(value) {
  return value && typeof value === "object" && !Array.isArray(value) ? value : null;
}

function normalizeStep(step, index) {
  const obj = asObject(step);
  if (!obj) {
    throw Object.assign(new Error(`navigation_plan[${index}] must be an object`), {
      code: "invalid_arguments",
    });
  }
  const action = typeof obj.action === "string" ? obj.action.trim() : "";
  if (!action) {
    throw Object.assign(new Error(`navigation_plan[${index}].action is required`), {
      code: "invalid_arguments",
    });
  }
  if (!PLAN_ACTIONS.has(action)) {
    throw Object.assign(new Error(
      `navigation_plan[${index}].action ${action} is not supported (allowed: ${Array.from(PLAN_ACTIONS).join(", ")})`,
    ), { code: "invalid_arguments" });
  }
  const args = asObject(obj.args) || {};
  return { action, args };
}

async function runNavigationPlan(sessionId, targetDomain, plan) {
  for (let index = 0; index < plan.length; index += 1) {
    const { action, args } = plan[index];
    if (action === "navigate") {
      const url = assertNonEmptyString(args.url, `navigation_plan[${index}].args.url`);
      // The driver's own scope guard would also block this, but failing fast
      // at the wrapper makes the per-step error legible to the agent.
      await assertSafeResolvedRequestUrl(url, targetDomain, {
        blockInternalHosts: false,
      });
      await callBrowser("navigate", sessionId, {
        url,
        timeout_ms: args.timeout_ms,
      });
      continue;
    }
    if (action === "click") {
      await callBrowser("click", sessionId, {
        ref: assertNonEmptyString(args.ref, `navigation_plan[${index}].args.ref`),
      });
      continue;
    }
    if (action === "type") {
      await callBrowser("type", sessionId, {
        ref: assertNonEmptyString(args.ref, `navigation_plan[${index}].args.ref`),
        text: args.text == null ? "" : String(args.text),
      });
      continue;
    }
    if (action === "wait_for") {
      await callBrowser("wait_for", sessionId, {
        predicate: args.predicate,
        timeout_ms: args.timeout_ms,
      });
      continue;
    }
  }
}

async function handler(args = {}) {
  if (!browserSessions.isPatchrightAvailable()) {
    return JSON.stringify(patchrightUnavailableEnvelope());
  }
  try {
    const targetDomain = safeTargetDomain(args.target_domain);
    const targetUrl = assertNonEmptyString(args.target_url, "target_url");
    try {
      await assertSafeResolvedRequestUrl(targetUrl, targetDomain, {
        blockInternalHosts: false,
      });
    } catch (err) {
      const wrapped = new Error(`scope_blocked: ${err && err.message ? err.message : err}`);
      wrapped.code = "scope_blocked";
      throw wrapped;
    }

    let plan = [];
    if (args.navigation_plan != null) {
      if (!Array.isArray(args.navigation_plan)) {
        const err = new Error("navigation_plan must be an array of steps");
        err.code = "invalid_arguments";
        throw err;
      }
      if (args.navigation_plan.length > MAX_PLAN_STEPS) {
        const err = new Error(`navigation_plan exceeds ${MAX_PLAN_STEPS} steps`);
        err.code = "invalid_arguments";
        throw err;
      }
      plan = args.navigation_plan.map((step, index) => normalizeStep(step, index));
    }

    // Egress resolution runs BEFORE the subprocess spawn. If it fails (unknown
    // profile, disabled, env var missing, scheme unsupported) we return the
    // structured envelope and never start Chromium. Default profile = direct
    // egress, preserving the pre-cycle behavior.
    const egress = resolveBrowserEgressProfile(args.egress_profile);
    if (!egress.ok) {
      return egress.envelope;
    }

    const started = await browserSessions.startSession({
      targetDomain,
      targetUrl,
      headless: args.headless === true,
      recordMode: true,
      proxy: egress.proxy,
    });

    if (plan.length > 0) {
      try {
        await runNavigationPlan(started.session_id, targetDomain, plan);
      } catch (err) {
        // Tear the session down so a partially driven session does not
        // linger consuming a concurrency slot. The caller can restart.
        try {
          await browserSessions.closeSession(started.session_id, "navigation_plan_failed");
        } catch {
          // ignore — the session may have already entered the closed state
        }
        const wrapped = new Error(
          `navigation_plan_failed: ${err && err.message ? err.message : err}`,
        );
        wrapped.code = err && err.code ? err.code : "navigation_plan_failed";
        throw wrapped;
      }
    }

    return envelopeSuccess({
      session_id: started.session_id,
      target_domain: started.target_domain,
      target_url: started.target_url,
      headless: started.headless,
      record_mode: true,
      recorded_count: 0,
      navigation_plan_executed: plan.length,
      egress_profile_resolved: egress.profile.name,
      egress_region: egress.profile.region,
      proxy_configured: egress.profile.proxy_configured,
    });
  } catch (err) {
    return envelopeFromError(err);
  }
}

module.exports = Object.freeze({
  name: "bob_browser_session_start_recording",
  description:
    "Start a Patchright browser session with record_mode: true so every browser-emitted HTTP(S) request is buffered for ingestion via bob_browser_flush_recorded_requests. Useful for capturing client-side auth flows (OAuth callbacks, SPA login posts, in-page CSRF/anti-bot tokens) so the captured requests can be mutated and replayed through bob_http_scan. Optionally drives a navigation_plan immediately after session start; each step is one of {action: navigate|click|type|wait_for, args}. Captured traffic does NOT flow on its own — the caller must pull batches via bob_browser_flush_recorded_requests (which is what writes them to http-records.jsonl). Optional egress_profile names an entry from .claude/bob/egress-profiles.json; the resolved proxy_url is threaded into Patchright chromium.launch({proxy}) (default = direct). Limitation: this tool drives DOM events but cannot impersonate a WebAuthn authenticator; ceremonies that require navigator.credentials cannot be replayed from the captured request alone.",
  inputSchema: {
    type: "object",
    properties: {
      target_domain: { type: "string", description: "Session domain anchor; the URL host must equal this or be a subdomain." },
      target_url: { type: "string", description: "Initial in-scope URL the browser will eventually navigate to. Scope-checked via the same validator that gates bob_http_scan." },
      headless: { type: "boolean", description: "Run headless. Default false (headed) to preserve anti-detection fingerprint." },
      egress_profile: {
        type: "string",
        pattern: EGRESS_PROFILE_NAME_RE.source,
        description: "Name of an enabled profile from .claude/bob/egress-profiles.json. Defaults to 'default' (direct connection). The resolved proxy_url is parsed (env-var expansion + http/https/socks5 scheme validation) and threaded into Patchright chromium.launch({proxy}) before the anti-detection stack runs, so the operator still gets a real Chrome fingerprint behind the proxy.",
      },
      navigation_plan: {
        type: "array",
        description: "Optional sequence of actions driven immediately after session start. Each step: {action: 'navigate'|'click'|'type'|'wait_for', args: {...}}. navigate.args.url is scope-checked. The session is torn down if any step fails.",
        items: {
          type: "object",
          properties: {
            action: { type: "string" },
            args: { type: "object", additionalProperties: true },
          },
          required: ["action"],
        },
      },
    },
    required: ["target_domain", "target_url"],
  },
  handler,
  role_bundles: BROWSER_BUNDLES,
  mutating: true,
  global_preapproval: false,
  network_access: true,
  browser_access: true,
  scope_required: true,
  scope_url_fields: ["target_url"],
  sensitive_output: false,
  session_artifacts_written: [],
});
