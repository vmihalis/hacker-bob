"use strict";

// Executable mechanism-template registry — the edge_type -> verifier-template
// dispatch table the composition LIVE verifier resolves against.
//
// invariant-template-corpus.js hosts mechanism DESCRIPTORS (required_entities,
// interventions, evidence_predicate — pure metadata, keyed by template id and
// loaded through a shape validator that would reject function fields). This file
// is the orthogonal CODE registry: it maps an OPEN-VOCAB edge_type string to a
// template carrying the FOUR executable callables the dispatcher needs:
//
//   discriminator_predicate(leaf)                       -> bool
//     Does this template own this leaf (right edge_type + the live re-execution
//     inputs the template's geometry requires)? A false yields the dispatcher's
//     missing-inputs inconclusive record.
//   plan_validator(offlineRequest, baseUrl, primary, controlPlan) -> string[]
//     The mechanism's confounder-completeness geometry. A non-empty list makes
//     the leaf inconclusive — the differential is not bound to the offline leaf.
//   live_verifier(ctx, leaf) -> probe
//     Re-execute the mechanism's control battery live (the RE-EXECUTION half).
//   differential_evaluator(probe) -> verdict
//     Derive the deterministic { disposition, verdict_hash, reason, ... } from the
//     executed outcomes.
//
// The dispatcher reads payload.edge_type (any non-empty string), looks the
// template up here, and dispatches. No registered template for an edge_type =>
// inconclusive (annotate-don't-gate, never an enum drop). The OBJECT_AUTH
// template is registered for edge_type "guard" and runs the EXACT CB-D1 object-
// authorization battery — its geometry (the SAME/DIFF/ANON control sets and the
// plan validator) lives here so the dispatcher stays mechanism-agnostic.
//
// This is a pure in-process code registry: not a tool, not an audit-graded path.

const {
  runObjectAuthControlProbe,
} = require("./belief/live-object-auth-probe.js");
const {
  evaluateObjectAuthDifferential,
} = require("./belief/differential-tester.js");

// Shared URL helpers. The dispatcher and the OBJECT_AUTH plan geometry both
// resolve leaf-supplied request paths onto the scoped base_url; they import these
// from here so there is a single resolution, no divergent copy.
//
// Join a leaf-supplied request path onto the scoped base_url. An already-absolute
// URL is passed through (validateHttpScanScope still gates it before any fetch).
function joinUrl(baseUrl, requestUrl) {
  if (typeof requestUrl !== "string" || requestUrl.length === 0) return requestUrl;
  if (/^https?:\/\//i.test(requestUrl)) return requestUrl;
  if (typeof baseUrl !== "string" || baseUrl.length === 0) return requestUrl;
  const trimmedBase = baseUrl.replace(/\/+$/, "");
  return `${trimmedBase}${requestUrl.startsWith("/") ? "" : "/"}${requestUrl}`;
}

function resolveRequest(baseUrl, request) {
  if (request == null || typeof request !== "object") return request;
  return { ...request, url: joinUrl(baseUrl, request.url) };
}

// The object-auth battery is only meaningful if its probes actually form a
// cross-principal SAME-object differential, bound to the object the offline leaf
// names. Without this, an agent can bind a leaf to one observation while proving a
// different bug (or "attacker reads its own object") and still mint verified_pass.
// These sets express the battery's geometry:
//   SAME_OBJECT — must hit the offline leaf's victim object, varying only principal
//   DIFF_OBJECT — must hit a DIFFERENT object (own / public / nonexistent)
//   ANON        — must carry NO auth profile
// The object SELECTOR can live in the path OR the query (/api/document?id=victim),
// so object identity is the full key = pathname + sorted query, not pathname alone.
// SAME_OBJECT controls must hit the exact same key; DIFF_OBJECT controls must differ
// in the key (a different id in the query counts). cache_nonce is the one same-object
// control allowed to ADD params (the cache-bust), so it is checked by containment.
const SAME_OBJECT_CONTROLS = new Set([
  "victim_auth_same_object",
  "no_auth_same_object",
  "stale_session_check",
]);
const DIFF_OBJECT_CONTROLS = new Set([
  "attacker_owned_control",
  "public_object_check",
  "nonexistent_object",
]);
const ANON_CONTROLS = new Set(["no_auth_same_object", "public_object_check"]);

function urlParts(baseUrl, requestUrl) {
  const joined = joinUrl(baseUrl, requestUrl);
  if (typeof joined !== "string" || !joined) return null;
  try {
    const u = new URL(joined);
    // RAW search (u.search), not decoded/sorted searchParams: order, duplicates,
    // and percent-encoding are preserved so two raw requests the server resolves
    // to DIFFERENT objects cannot collide to one key (e.g. ?id=a&id=b vs ?id=b&id=a,
    // or ?a=x&b=y vs ?a=x%26b%3Dy). Decoding+sorting was the collision bug.
    return { pathname: u.pathname, search: u.search, origin: u.origin };
  } catch {
    const qIndex = joined.indexOf("?");
    const pathname = qIndex === -1 ? joined : joined.slice(0, qIndex);
    const search = qIndex === -1 ? "" : joined.slice(qIndex);
    return { pathname, search, origin: null };
  }
}

// Canonical object key: pathname + RAW query string. /api/document?id=victim and
// /api/document?id=attacker are different objects; order/encoding are significant,
// so honest plans use the byte-identical victim URL for same-object controls.
function urlObjectKey(parts) {
  if (!parts) return null;
  return `${parts.pathname}${parts.search || ""}`;
}

function rawQueryPairs(parts) {
  if (!parts || !parts.search) return [];
  return parts.search.replace(/^\?/, "").split("&").filter((p) => p.length > 0);
}

// Decoded param key, so a percent-encoded key (i%64) cannot smuggle a duplicate of
// a victim selector key (id) past the disjoint check on a name-decoding backend.
function decodedPairKey(rawPair) {
  const rawKey = rawPair.split("=")[0];
  try { return decodeURIComponent(rawKey); } catch { return rawKey; }
}

// cache_nonce_check is the SAME object plus a cache-bust param. To resist a
// duplicate-key collision (e.g. ?id=victim&id=attacker, which a last-wins backend
// resolves to attacker), require the victim's raw pairs to be an exact ORDERED
// PREFIX of the cache request's, and every EXTRA pair to introduce a key the victim
// did not use (no overriding the selector).
function cacheNoncePreservesObject(victimParts, cacheParts) {
  if (!victimParts || !cacheParts) return false;
  if (victimParts.pathname !== cacheParts.pathname) return false;
  const vPairs = rawQueryPairs(victimParts);
  const cPairs = rawQueryPairs(cacheParts);
  if (cPairs.length < vPairs.length) return false;
  for (let i = 0; i < vPairs.length; i++) {
    if (cPairs[i] !== vPairs[i]) return false; // exact ordered prefix
  }
  const victimKeys = new Set(vPairs.map(decodedPairKey));
  for (let i = vPairs.length; i < cPairs.length; i++) {
    if (victimKeys.has(decodedPairKey(cPairs[i]))) return false; // no selector override
  }
  return true;
}

// Validate that the live re-execution inputs (primary + control_plan) form a genuine
// cross-principal same-object battery bound to the offline observation's request URL.
// Returns a list of violations; a non-empty list makes the leaf inconclusive (never
// verified). Only controls actually present are checked — absent controls are handled
// by CB-D1's missing => inconclusive.
function validateObjectAuthPlan(offlineRequest, baseUrl, primary, controlPlan) {
  const violations = [];
  let baseOrigin = null;
  try { baseOrigin = new URL(baseUrl).origin; } catch { baseOrigin = null; }

  const offlineUrl = offlineRequest && typeof offlineRequest === "object" ? offlineRequest.url : null;
  const victimParts = urlParts(baseUrl, offlineUrl);
  const victimKey = urlObjectKey(victimParts);
  if (!victimKey) {
    violations.push("offline observation has no bindable request.url");
  }
  // The object key excludes origin, so an absolute offline URL must itself sit on
  // base_url's origin — otherwise a live differential on base_url's origin could be
  // credited to a leaf that named a different first-party host (debug.example.com).
  if (victimParts && victimParts.origin && baseOrigin && victimParts.origin !== baseOrigin) {
    violations.push(`offline leaf names a different origin (${victimParts.origin}) than base_url`);
  }

  const checkOrigin = (label, parts) => {
    if (!baseOrigin || !parts) return;
    if (parts.origin && parts.origin !== baseOrigin) violations.push(`${label} drifts to a different origin (${parts.origin})`);
  };

  // primary = the attack: attacker principal reaching the SAME victim object (exact
  // object key, query selector included).
  const primaryParts = urlParts(baseUrl, primary && primary.url);
  checkOrigin("primary", primaryParts);
  if (victimKey && urlObjectKey(primaryParts) !== victimKey) {
    violations.push("primary does not target the offline leaf's victim object");
  }
  const attackerProfile = primary && typeof primary.auth_profile === "string" ? primary.auth_profile : "";
  if (!attackerProfile) violations.push("primary lacks an attacker auth_profile");

  for (const entry of controlPlan) {
    if (entry == null || typeof entry !== "object") continue;
    const name = entry.control;
    const entryParts = urlParts(baseUrl, entry.url);
    checkOrigin(name, entryParts);
    const entryKey = urlObjectKey(entryParts);
    if (SAME_OBJECT_CONTROLS.has(name) && victimKey && entryKey !== victimKey) {
      violations.push(`${name} must target the same victim object as the leaf`);
    }
    if (name === "cache_nonce_check" && victimKey && !cacheNoncePreservesObject(victimParts, entryParts)) {
      violations.push("cache_nonce_check must target the same victim object (same path + object params, cache-bust extra)");
    }
    if (DIFF_OBJECT_CONTROLS.has(name) && victimKey && entryKey === victimKey) {
      violations.push(`${name} must target a different object than the victim`);
    }
    if (name === "victim_auth_same_object") {
      const victimProfile = typeof entry.auth_profile === "string" ? entry.auth_profile : "";
      if (!victimProfile) violations.push("victim_auth_same_object lacks a victim auth_profile");
      else if (victimProfile === attackerProfile) {
        violations.push("victim_auth_same_object must use a DISTINCT principal from the attacker");
      }
    }
    if (ANON_CONTROLS.has(name) && typeof entry.auth_profile === "string" && entry.auth_profile.length > 0) {
      violations.push(`${name} must be anonymous (no auth_profile)`);
    }
  }
  return violations;
}

// The OBJECT_AUTH mechanism template. edge_type "guard" is the OPEN-VOCAB dispatch
// key (a string the dispatcher looks up, not a hardcoded rail). mechanism_id /
// id mirror the descriptor in invariant-template-corpus.js
// (OBJECT_AUTHORIZATION_MECHANISM_TEMPLATE, edge_type "guard") — the descriptor is
// pure metadata; THIS carries the executable hooks. The two are cross-linked by
// edge_type, never merged.
const OBJECT_AUTH_MECHANISM_TEMPLATE = Object.freeze({
  edge_type: "guard",
  mechanism_id: "CWE-639",
  id: "object_authorization",

  // Owns a leaf only when it carries the live re-execution inputs the object-auth
  // battery needs: a primary request object and a control_plan array.
  discriminator_predicate(leaf) {
    return (
      leaf != null &&
      typeof leaf === "object" &&
      leaf.primary != null &&
      typeof leaf.primary === "object" &&
      Array.isArray(leaf.control_plan)
    );
  },

  // The whole confounder-completeness geometry: a cross-principal SAME-object
  // differential bound to the offline leaf, with controls DISTINCT from the attack.
  plan_validator: validateObjectAuthPlan,

  // Re-execute the CB-D1 control battery live. resolveRequest maps the leaf's
  // primary + control_plan onto the scoped base_url.
  live_verifier(ctx, leaf) {
    return runObjectAuthControlProbe({
      target_domain: ctx.target_domain,
      fetch_fn: ctx.fetch_fn,
      validate_scope_fn: ctx.validate_scope_fn,
      primary: resolveRequest(ctx.base_url, leaf.primary),
      control_plan: leaf.control_plan.map((c) => resolveRequest(ctx.base_url, c)),
    });
  },

  // Derive the frozen { disposition, verdict_hash, reason, ... } from the EXECUTED
  // outcomes — never from a predicate name.
  differential_evaluator(probe) {
    return evaluateObjectAuthDifferential({
      primary_effect: probe.primary_effect,
      controls: probe.controls,
    });
  },
});

// edge_type -> executable template. Open-vocab: any non-empty string can register;
// an unregistered edge_type resolves to no template (the dispatcher's inconclusive
// rail), never an enum gate.
const TEMPLATES_BY_EDGE_TYPE = new Map();

function registerVerifierTemplate(edgeType, template) {
  if (typeof edgeType !== "string" || !edgeType) {
    throw new TypeError("edge_type must be a non-empty string");
  }
  if (
    template == null ||
    typeof template !== "object" ||
    typeof template.discriminator_predicate !== "function" ||
    typeof template.plan_validator !== "function" ||
    typeof template.live_verifier !== "function" ||
    typeof template.differential_evaluator !== "function"
  ) {
    throw new TypeError("template must carry discriminator_predicate, plan_validator, live_verifier, differential_evaluator callables");
  }
  TEMPLATES_BY_EDGE_TYPE.set(edgeType, template);
  return template;
}

// Resolve the executable template registered for an edge_type, or null when none is
// registered (=> the dispatcher returns an inconclusive leaf record).
function lookupVerifierTemplate(edgeType) {
  if (typeof edgeType !== "string" || !edgeType) return null;
  return TEMPLATES_BY_EDGE_TYPE.get(edgeType) || null;
}

registerVerifierTemplate(OBJECT_AUTH_MECHANISM_TEMPLATE.edge_type, OBJECT_AUTH_MECHANISM_TEMPLATE);

module.exports = {
  OBJECT_AUTH_MECHANISM_TEMPLATE,
  registerVerifierTemplate,
  lookupVerifierTemplate,
  joinUrl,
  resolveRequest,
};
