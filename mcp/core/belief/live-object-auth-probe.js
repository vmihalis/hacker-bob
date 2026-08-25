"use strict";

// Live object-authorization control-probe loop (HTTP, K=1).
//
// CB-D1 (differential-tester.js) decides a deterministic AND-over-controls
// verdict from per-control `reached` booleans ONLY — it never executes anything.
// This module is the missing producer of those booleans from REAL execution, so
// the verdict the live verifier (LV-2) re-derives is no longer hand-passed.
//
// Each CB-D1 control is a distinct request expressed as an (auth_profile, url)
// variation — NOT a header mutation — so it flows through the existing
// makePerCallHttpScanFetcher ({url, method, auth_profile}) unchanged:
//   attacker_owned_control : attacker profile -> attacker's OWN object  (positive)
//   victim_auth_same_object: victim profile   -> victim object          (positive)
//   no_auth_same_object    : no profile (anon)-> victim object          (discriminating)
//   nonexistent_object     : attacker profile -> synthetic/garbage id   (discriminating)
//   public_object_check    : no profile (anon)-> known-public object    (discriminating)
//   stale_session_check    : stale profile    -> victim object          (discriminating)
//   cache_nonce_check      : attacker profile -> victim object + url cache-bust param
// The PRIMARY effect (the attack) is the attacker principal reaching the victim
// object — a request distinct from attacker_owned_control.
//
// A control whose probe is DEGRADED (scope-blocked, fetch error, no status, or a
// truncated body) is recorded in `degraded_controls` and OMITTED from `controls`,
// so evaluateObjectAuthDifferential treats it as MISSING (=> inconclusive) rather
// than as a clean reached=false. A degraded oracle must never silently confirm or
// deny.

const { computeResponseSignature } = require("../auth-differential.js");
const { OBJECT_AUTH_CONTROLS } = require("./intervention-calculus.js");
const { inferFailureMode } = require("../validity/index.js");

const OBJECT_AUTH_CONTROL_SET = new Set(OBJECT_AUTH_CONTROLS);
// computeResponseSignature.response_class for a 2xx body-return.
const REACHED_RESPONSE_CLASS = "ok";

function isNonEmptyString(value) {
  return typeof value === "string" && value.length > 0;
}

// A probe is degraded when the request did not produce a trustworthy response:
// the adapter surfaces a fetch_error or a scope_decision other than "allowed",
// or there is no numeric status to classify, or the body was truncated. Any of
// these makes `reached` unknowable, not false.
function probeDegradation(parsed) {
  if (parsed == null || typeof parsed !== "object") return "no_response";
  if (isNonEmptyString(parsed.fetch_error)) return "fetch_error";
  if (isNonEmptyString(parsed.scope_decision) && parsed.scope_decision !== "allowed") {
    return `scope_${parsed.scope_decision}`;
  }
  if (typeof parsed.status !== "number") return "no_status";
  // httpScan renders bodies it cannot return verbatim as synthetic strings with NO
  // structured truncation flag (http-scan.js): text/JSON/XML/HTML are sliced to
  // 12000 chars + a "[TRUNCATED — ...]" marker; binary bodies become a
  // "[Binary: N bytes ..., type: ...]" SUMMARY (never the real bytes). Neither can
  // be trusted for the byte-identical victim-object match — two distinct objects
  // sharing a 12 KB prefix, or two distinct binaries of the same size+type, would
  // hash-collide. Degrade both so a summary can never mint body_match.
  const bodyStr = typeof parsed.body === "string"
    ? parsed.body
    : (parsed.body && typeof parsed.body === "object" ? JSON.stringify(parsed.body) : "");
  if (bodyStr.includes("[TRUNCATED")) return "truncated_body";
  if (/^\s*\[Binary:/.test(bodyStr)) return "binary_body";
  return null;
}

async function runProbe(fetch_fn, validate_scope_fn, target_domain, { method, url, auth_profile }) {
  if (!isNonEmptyString(url)) {
    return { degraded: "missing_url" };
  }
  // F4 belt-and-suspenders: validate the generated per-control URL against scope
  // BEFORE the fetch. httpScan also enforces scope, but the joined control URL is
  // generated inside the verifier and is not covered by the registry's
  // top-level scope_url_fields gate.
  if (typeof validate_scope_fn === "function") {
    try {
      validate_scope_fn(url, target_domain);
    } catch (err) {
      return { degraded: "scope_blocked", scope_error: err && err.message ? err.message : String(err) };
    }
  }
  let parsed;
  try {
    parsed = await fetch_fn({ url, method: method || "GET", auth_profile });
  } catch (err) {
    return { degraded: "fetch_threw", fetch_error: err && err.message ? err.message : String(err) };
  }
  const degraded = probeDegradation(parsed);
  if (degraded) {
    return { degraded, status: parsed && typeof parsed.status === "number" ? parsed.status : null };
  }
  const signature = computeResponseSignature({
    status: parsed.status,
    body: parsed.body,
    sent_with_auth: parsed.sent_with_auth === true,
  });
  return {
    degraded: null,
    status: parsed.status,
    response_class: signature.response_class,
    body_hash: signature.body_hash,
    sensitive_field_count: signature.sensitive_field_count,
    failure_mode: inferFailureMode({
      control: auth_profile === "stale" ? "stale_session_check" : null,
      reached: signature.response_class === REACHED_RESPONSE_CLASS,
      status: parsed.status,
      response_class: signature.response_class,
      body: parsed.body,
    }),
    reached: signature.response_class === REACHED_RESPONSE_CLASS,
  };
}

// runObjectAuthControlProbe — execute the live battery and shape the result for
// evaluateObjectAuthDifferential.
//
// input:
//   { target_domain, fetch_fn, validate_scope_fn?,
//     primary: { method, url, auth_profile },             // the attack request
//     control_plan: [ { control, method, url, auth_profile, evidence_ref? } ] }
//
// returns:
//   { primary_effect: { reached, degraded, response_class, body_match },
//     controls: { <control>: { reached, status, response_class, evidence_ref? } },
//     degraded_controls: [ { control, reason, status? } ],
//     probe_log: [ ... per-request evidence ... ] }
async function runObjectAuthControlProbe(input) {
  if (input == null || typeof input !== "object") {
    throw new TypeError("input must be { target_domain, fetch_fn, primary, control_plan }");
  }
  const { target_domain, fetch_fn, validate_scope_fn } = input;
  if (typeof fetch_fn !== "function") {
    throw new TypeError("fetch_fn must be a function");
  }
  if (input.primary == null || typeof input.primary !== "object") {
    throw new TypeError("primary must be { method, url, auth_profile }");
  }
  const controlPlan = Array.isArray(input.control_plan) ? input.control_plan : [];

  const controls = {};
  const degradedControls = [];
  const probeLog = [];
  // victim_auth_same_object's body is the reference the attacker's response must
  // match (objection-9 anti-echo): the attacker is only "reached" if it obtained
  // the SAME victim object bytes the legitimate owner sees.
  let victimAuthBodyHash = null;

  for (const entry of controlPlan) {
    if (entry == null || typeof entry !== "object" || !OBJECT_AUTH_CONTROL_SET.has(entry.control)) {
      // An unknown / malformed control is simply not run; CB-D1 will see it as
      // missing. Record it so the omission is auditable.
      degradedControls.push({ control: entry && entry.control ? String(entry.control) : "unknown", reason: "unknown_control" });
      continue;
    }
    const result = await runProbe(fetch_fn, validate_scope_fn, target_domain, entry);
    probeLog.push({ control: entry.control, url: entry.url, auth_profile: entry.auth_profile || null, ...result });
    if (result.degraded) {
      degradedControls.push({ control: entry.control, reason: result.degraded, status: result.status ?? null });
      continue;
    }
    if (entry.control === "victim_auth_same_object" && isNonEmptyString(result.body_hash)) {
      victimAuthBodyHash = result.body_hash;
    }
    const controlEntry = {
      reached: result.reached === true,
      status: result.status,
      response_class: result.response_class,
      failure_mode: result.failure_mode || null,
    };
    if (isNonEmptyString(entry.evidence_ref)) controlEntry.evidence_ref = entry.evidence_ref;
    controls[entry.control] = controlEntry;
  }

  // The attack probe last, so victimAuthBodyHash is available for the anti-echo
  // comparison.
  const primaryResult = await runProbe(fetch_fn, validate_scope_fn, target_domain, input.primary);
  probeLog.push({ control: "__primary__", url: input.primary.url, auth_profile: input.primary.auth_profile || null, ...primaryResult });

  let primaryReached = false;
  let bodyMatch = null;
  if (!primaryResult.degraded && primaryResult.response_class === REACHED_RESPONSE_CLASS) {
    if (victimAuthBodyHash) {
      // Strong signal: attacker obtained byte-identical victim object content.
      bodyMatch = primaryResult.body_hash === victimAuthBodyHash;
      primaryReached = bodyMatch === true;
    } else {
      // Weaker fallback when the victim baseline is unavailable: a 2xx that
      // returns at least one sensitive field. Documented as weaker — without the
      // victim baseline a reflective endpoint is not fully excluded.
      primaryReached = (primaryResult.sensitive_field_count || 0) > 0;
    }
  }

  return {
    primary_effect: {
      reached: primaryReached,
      degraded: primaryResult.degraded || null,
      response_class: primaryResult.response_class || null,
      body_match: bodyMatch,
    },
    controls,
    degraded_controls: degradedControls,
    probe_log: probeLog,
  };
}

module.exports = {
  runObjectAuthControlProbe,
  probeDegradation,
  REACHED_RESPONSE_CLASS,
};
