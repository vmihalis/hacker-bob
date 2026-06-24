"use strict";

const fs = require("fs");

// Composition LIVE verifier — SC1 confirm-half for object-auth/HTTP guard edges.
//
// The offline composition harness (composition-experiment-harness.js) is a SHAPE
// gate: it confirms a path's leaves are replay-shaped, discriminating, and
// tamper-evident, and carries that as `verification_required: true`. It executes
// nothing, so a self-consistent counterfeit observation passes it. This module is
// the semantic half: it RE-EXECUTES each guard leaf's CB-D1 control battery live,
// re-derives the deterministic verdict (evaluateObjectAuthDifferential), and only
// mints a `verified_pass` when the verdict reproduces and AGREES with the leaf's
// offline claim. A counterfeit flip dies here because the negative control is
// actually re-run and must classify to the opposite reached state.
//
// Producer-independence is structural, enforced at the INTEGRITY boundary, not by
// the producer's good behavior:
//   1. This is the only writer of composition-verified.jsonl, which is audit-graded
//      (paths.js AUDIT_GRADED_BASENAMES) — agents cannot Write-forge it.
//   2. It emits NO frontier event — adding observation.recorded events is the exact
//      laundering surface the offline gate cannot defend, so the verified record
//      lives ONLY in the protected ledger that SC1 grades on (LV-3 telemetry).
//   3. The leaf's live re-execution inputs (primary + control_plan) are re-issued
//      by THIS handler; the verdict is re-derived from the bytes it captured, not
//      from the producer's claimed request/response.
//
// K=1 boundary (honest scope): only an object-auth `guard` edge is live-verifiable
// today. Every non-`guard` edge_type, and any guard leaf lacking re-execution
// inputs, returns `inconclusive` — never a producer-string fallback, never a
// verified_pass. Generalizing past object-auth is SC3 (a committed per-edge-type
// control-semantics table).

const {
  runPathCompositionExperiment,
} = require("./composition-experiment-harness.js");
const {
  readFrontierEvents,
} = require("./frontier-events.js");
const {
  runObjectAuthControlProbe,
} = require("./belief/live-object-auth-probe.js");
const {
  evaluateObjectAuthDifferential,
} = require("./belief/differential-tester.js");
const {
  makePerCallHttpScanFetcher,
} = require("./http-scan-adapter.js");
const {
  validateHttpScanScope,
} = require("./scope.js");
const {
  assertSafeDomain,
  compositionVerifiedJsonlPath,
} = require("./paths.js");
const {
  appendJsonlLine,
  withSessionLock,
} = require("./storage.js");
const {
  hashCanonicalJson,
} = require("./verification-contracts.js");
const {
  emitVerifiedInterventionSignal,
} = require("./belief/outcome-bridge.js");

const COMPOSITION_VERIFIED_VERSION = 1;
const COMPOSITION_VERIFIED_MAX_RECORDS = 2000;
const EVIDENCE_REF_PREFIX = "frontier_event:";

// Path-level outcomes.
const RESULT_VERIFIED_PASS = "verified_pass";
const RESULT_REFUTED = "refuted";
const RESULT_INCONCLUSIVE = "inconclusive";
const RESULT_OFFLINE_REFUSED = "offline_refused";

// Per-leaf outcomes.
const LEAF_VERIFIED = "verified";
const LEAF_REFUTED = "refuted";
const LEAF_INCONCLUSIVE = "inconclusive";

// Only an object-auth guard edge is live-verifiable at K=1.
const VERIFIABLE_EDGE_TYPE = "guard";

function indexEventsById(events) {
  const index = new Map();
  for (const event of events) {
    if (event && typeof event.event_id === "string") index.set(event.event_id, event);
  }
  return index;
}

function leafEventId(leaf) {
  const ref = leaf && typeof leaf === "object" ? leaf.evidence_ref : null;
  if (typeof ref !== "string" || !ref.startsWith(EVIDENCE_REF_PREFIX)) return null;
  return ref.slice(EVIDENCE_REF_PREFIX.length);
}

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

// Verify one leaf by re-executing its object-auth battery. `offlineEvent` is the
// resolved observation.recorded the offline gate already accepted. Returns a
// per-leaf record; never throws on a probe failure (that becomes inconclusive).
async function verifyLeaf(leaf, offlineEvent, ctx) {
  const base = {
    edge_id: leaf && typeof leaf.edge_id === "string" ? leaf.edge_id : null,
    evidence_ref: leaf && typeof leaf.evidence_ref === "string" ? leaf.evidence_ref : null,
  };
  const payload = offlineEvent && offlineEvent.payload && typeof offlineEvent.payload === "object"
    ? offlineEvent.payload
    : {};
  const edgeType = typeof payload.edge_type === "string" ? payload.edge_type : null;
  const claimedVerdict = typeof payload.verdict === "string" ? payload.verdict : null;
  base.edge_type = edgeType;
  base.claimed_verdict = claimedVerdict;

  // K=1 rail: only object-auth guard edges are live-verifiable. Everything else is
  // inconclusive — NOT a producer-string fallback.
  if (edgeType !== VERIFIABLE_EDGE_TYPE) {
    return { ...base, leaf_status: LEAF_INCONCLUSIVE, reason: `edge_type '${edgeType}' not live-verifiable at K=1 (object-auth guard only)` };
  }
  if (leaf.primary == null || typeof leaf.primary !== "object" || !Array.isArray(leaf.control_plan)) {
    return { ...base, leaf_status: LEAF_INCONCLUSIVE, reason: "guard leaf lacks live re-execution inputs (primary + control_plan)" };
  }

  // Bind the live re-execution to the offline leaf: the battery must be a genuine
  // cross-principal SAME-object differential aimed at the object the offline
  // observation names, on the same origin. Otherwise the verifier would prove a
  // DIFFERENT predicate than the leaf claims — refuse rather than mint verified.
  const planViolations = validateObjectAuthPlan(payload.request, ctx.base_url, leaf.primary, leaf.control_plan);
  if (planViolations.length > 0) {
    return { ...base, leaf_status: LEAF_INCONCLUSIVE, reason: `control plan is not a cross-principal same-object battery bound to the leaf: ${planViolations.join("; ")}` };
  }

  let probe;
  try {
    probe = await runObjectAuthControlProbe({
      target_domain: ctx.target_domain,
      fetch_fn: ctx.fetch_fn,
      validate_scope_fn: ctx.validate_scope_fn,
      primary: resolveRequest(ctx.base_url, leaf.primary),
      control_plan: leaf.control_plan.map((c) => resolveRequest(ctx.base_url, c)),
    });
  } catch (err) {
    return { ...base, leaf_status: LEAF_INCONCLUSIVE, reason: `probe error: ${err && err.message ? err.message : String(err)}` };
  }

  const verdict = evaluateObjectAuthDifferential({
    primary_effect: probe.primary_effect,
    controls: probe.controls,
  });
  const leafRecord = {
    ...base,
    disposition: verdict.disposition,
    live_verdict_hash: verdict.verdict_hash,
    degraded_controls: probe.degraded_controls,
    primary_reached: probe.primary_effect.reached === true,
    primary_body_match: probe.primary_effect.body_match,
  };

  // A leaf is verified ONLY when the live re-derivation is confirmed AND it agrees
  // with the leaf's offline claim. Live-denied contradicts the claim -> refuted.
  // Live-inconclusive (missing/degraded controls) -> inconclusive.
  if (verdict.disposition === "confirmed") {
    if (claimedVerdict === "confirmed") {
      return { ...leafRecord, leaf_status: LEAF_VERIFIED };
    }
    return { ...leafRecord, leaf_status: LEAF_REFUTED, reason: `live confirmed but leaf claimed '${claimedVerdict}'` };
  }
  if (verdict.disposition === "denied") {
    return { ...leafRecord, leaf_status: LEAF_REFUTED, reason: `live re-execution denied: ${verdict.reason}` };
  }
  return { ...leafRecord, leaf_status: LEAF_INCONCLUSIVE, reason: `live re-execution inconclusive: ${verdict.reason}` };
}

// verifyCompositionPath — re-execute a composition path live and mint a
// verified_pass only when every guard leaf live-reproduces its claimed flip.
//
// input: { target_domain, base_url, path: [ { evidence_ref, edge_id, primary, control_plan } ],
//          block_internal_hosts?, egress_profile? }
// deps:  { httpScanFn }  (injected so tests run without a network)
async function verifyCompositionPath(input, deps = {}) {
  if (input == null || typeof input !== "object") {
    throw new TypeError("input must be { target_domain, base_url, path }");
  }
  const targetDomain = assertSafeDomain(input.target_domain);
  if (!Array.isArray(input.path) || input.path.length === 0) {
    throw new Error("path must contain at least one leaf edge");
  }
  if (typeof deps.httpScanFn !== "function") {
    throw new TypeError("deps.httpScanFn must be a function");
  }

  // Step 1: the offline shape gate is a hard precondition. A path that is not even
  // replay-shaped cannot be live-verified — there is nothing trustworthy to re-run.
  const offline = runPathCompositionExperiment(targetDomain, {
    path: input.path.map((leaf) => ({
      evidence_ref: leaf && leaf.evidence_ref,
      edge_id: leaf && leaf.edge_id,
    })),
  });

  const fetch_fn = makePerCallHttpScanFetcher({
    httpScanFn: deps.httpScanFn,
    target_domain: targetDomain,
    block_internal_hosts: input.block_internal_hosts,
    egress_profile: input.egress_profile,
  });
  const ctx = {
    target_domain: targetDomain,
    base_url: input.base_url,
    fetch_fn,
    validate_scope_fn: (url, td) => validateHttpScanScope(url, td || targetDomain),
  };

  const index = indexEventsById(readFrontierEvents(targetDomain));
  const leaves = [];
  let result;

  if (offline.result !== "pass") {
    // The offline gate refused; record the refusal without re-executing anything.
    result = RESULT_OFFLINE_REFUSED;
  } else {
    for (const leaf of input.path) {
      const eventId = leafEventId(leaf);
      const offlineEvent = eventId ? index.get(eventId) : null;
      // The offline gate already proved every leaf resolves to a typed observation,
      // so offlineEvent is present; guard defensively regardless.
      // eslint-disable-next-line no-await-in-loop
      const leafRecord = await verifyLeaf(leaf, offlineEvent, ctx);
      leaves.push(leafRecord);
    }
    const anyRefuted = leaves.some((l) => l.leaf_status === LEAF_REFUTED);
    const allVerified = leaves.every((l) => l.leaf_status === LEAF_VERIFIED);
    if (anyRefuted) result = RESULT_REFUTED;
    else if (allVerified) result = RESULT_VERIFIED_PASS;
    else result = RESULT_INCONCLUSIVE;
  }

  const verifiedLeafCount = leaves.filter((l) => l.leaf_status === LEAF_VERIFIED).length;
  const body = {
    version: COMPOSITION_VERIFIED_VERSION,
    target_domain: targetDomain,
    ts: new Date().toISOString(),
    result,
    offline_result: offline.result,
    path_hash: offline.path_hash,
    leaf_count: input.path.length,
    verified_leaf_count: verifiedLeafCount,
    leaves,
  };
  const record = { ...body, results_hash: hashCanonicalJson(body) };

  withSessionLock(targetDomain, () => {
    appendJsonlLine(compositionVerifiedJsonlPath(targetDomain), record, {
      maxRecords: COMPOSITION_VERIFIED_MAX_RECORDS,
    });
  });

  // Outcome-bridge: ONE-WAY executed-reality -> belief, advisory only. This runs
  // strictly AFTER the audit-graded append and is internally try/catch-swallowed, so
  // a belief write failure can never alter `result` or composition-verified.jsonl.
  // Only a verified_pass with LEAF_VERIFIED leaves emits anything; each emitted
  // record is tagged with this row's results_hash and sharpens exactly the matching
  // request_equivalence latent. NO frontier event, NO grade/claim write (NO GATING).
  if (result === RESULT_VERIFIED_PASS) {
    emitVerifiedInterventionSignal({
      target_domain: targetDomain,
      base_url: input.base_url,
      path: input.path,
      leaves: leaves.map((leaf) => ({ ...leaf, results_hash: record.results_hash })),
      event_index: index,
      leaf_verified_status: LEAF_VERIFIED,
    });
  }

  return {
    target_domain: targetDomain,
    result,
    offline_result: offline.result,
    path_hash: offline.path_hash,
    leaf_count: input.path.length,
    verified_leaf_count: verifiedLeafCount,
    results_hash: record.results_hash,
    leaves,
  };
}

// Summarize the verified_pass ledger for SC1 grading. This is the AUTHORITATIVE
// SC1 confirm-half signal — it reads the MCP-write-only composition-verified.jsonl
// (audit-graded), never a frontier event, so the count cannot be hand-forged.
function readCompositionVerifiedSummary(domain) {
  const targetDomain = assertSafeDomain(domain);
  let records = [];
  try {
    const raw = fs.readFileSync(compositionVerifiedJsonlPath(targetDomain), "utf8");
    records = raw
      .split("\n")
      .filter((line) => line.trim())
      .map((line) => { try { return JSON.parse(line); } catch { return null; } })
      .filter(Boolean);
  } catch {
    records = [];
  }
  const verified = records.filter((r) => r.result === RESULT_VERIFIED_PASS);
  const lastVerified = verified.length > 0 ? verified[verified.length - 1] : null;
  // The full set of path_hash values of EVERY executed verified_pass row for the
  // domain. The consumer binds a verdict iff THIS path's hash is a member, so the
  // binding is path-precise: a different recently-verified path no longer
  // satisfies the binding via the coarse last-hash, and a path whose hash is not
  // the last but IS in the executed set is no longer wrongly rejected. Same
  // executed set as verified_pass_count (no recomputation); duplicates collapsed.
  const verifiedPathHashes = Array.from(
    new Set(
      verified
        .map((r) => r.path_hash)
        .filter((h) => typeof h === "string" && h),
    ),
  );
  return {
    total_runs: records.length,
    verified_pass_count: verified.length,
    refuted_count: records.filter((r) => r.result === RESULT_REFUTED).length,
    inconclusive_count: records.filter((r) => r.result === RESULT_INCONCLUSIVE).length,
    offline_refused_count: records.filter((r) => r.result === RESULT_OFFLINE_REFUSED).length,
    // Authoritative per-path membership set for verdict binding.
    verified_path_hashes: verifiedPathHashes,
    // Retained for back-compat; the array above is authoritative for binding.
    last_verified_path_hash: lastVerified ? lastVerified.path_hash : null,
    // SC1's confirm-half is satisfied ONLY by at least one live verified_pass.
    sc1_confirm_half_satisfied: verified.length > 0,
  };
}

module.exports = {
  COMPOSITION_VERIFIED_MAX_RECORDS,
  COMPOSITION_VERIFIED_VERSION,
  readCompositionVerifiedSummary,
  RESULT_VERIFIED_PASS,
  RESULT_REFUTED,
  RESULT_INCONCLUSIVE,
  RESULT_OFFLINE_REFUSED,
  LEAF_VERIFIED,
  LEAF_REFUTED,
  LEAF_INCONCLUSIVE,
  verifyCompositionPath,
};
