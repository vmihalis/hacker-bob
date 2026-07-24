"use strict";

// offensive-secondorder-producer.js — the SECOND-ORDER / stored-effect re-read
// collector. Two handlers, modelled on the OOB collector's mint/reread SPLIT
// (oob-collector.js oobMint/oobPoll) so the prover is WRITE-ISOLATED: it never
// performs the injection it reports on, and it only ever issues GET/HEAD re-reads.
//
//   bob_secondorder_mint  — NON-signing allocator. Server-mints a high-entropy 256-bit
//                           canary + a DISTINCT silent decoy canary, binds an in-scope
//                           INJECTION endpoint and a DISTINCT in-scope OBSERVATION
//                           endpoint from the routed surface_id (by endpoint locus,
//                           single-host guarded), and writes the audit-graded
//                           canary->surface binding. Returns ONLY the benign canary the
//                           agent injects into the target via other target-facing tools.
//                           The decoy is server-secret and is NEVER returned. NO network,
//                           never signs.
//   bob_secondorder_reread — the SIGNING producer. RE-READS the bound OBSERVATION
//                           endpoint via safeFetch (a channel Bob controls, not the
//                           agent) and applies the exact-parsed-leaf oracle. A POSITIVE
//                           (expect:interaction) requires the EXACT server-minted canary
//                           present as a parsed LEAF value (never a substring, never
//                           whole-body equality) AND the decoy ABSENT — proving the
//                           surfaced value is specifically the injected canary, not an
//                           ambient echo. The decoy-silent CONTROL (expect:silence)
//                           confirms the un-injected decoy is absent against a reachable
//                           endpoint and signs a blocked_by_defense row, so the injected-
//                           and-surfaced positive can EARN a finding-differential
//                           verified_pass by flipping against it.
//
// SOUNDNESS: the canary is a 256-bit nonce the server minted and the agent cannot
// pre-know; a deterministic/reflective server that never stored it cannot fabricate it
// at a DISTINCT read endpoint. Bob RE-READS that endpoint itself (safeFetch), so the
// observation is target-sourced by construction — unlike an OOB callback, there is no
// agent self-hit on the observation channel. The signed row is NOT self-closing: it
// stamps oracle_kind:"second_order_reread" (a MAC-covered sibling in the frozen
// stampable set), which the read-time exploit-run skip (claims.js) recognizes as a
// non-self-contained oracle — so a lone positive must flip against the decoy-silent
// control rather than self-skip.
//
// SEVERITY: a stored-effect surfacing is a MEDIUM-at-most LEAD unless the effect itself
// is the impact — the ceiling is a frozen MEDIUM (SECONDORDER_ORACLE_DEMONSTRATED_CEILING)
// and demonstratedSeverityOverride is ALWAYS passed explicitly (requireExplicitSeverity),
// so an omission fails CLOSED to MEDIUM rather than open to a producer default.
//
// INTEGRITY BOUNDARY (honest, NOT closed here; the SAME assumption Bob's wave-handoff
// signing and the other offensive producers make): the row MAC is TAMPER-EVIDENT against
// an agent confined to the MCP + guarded-Bash surface; it is NOT cryptographically
// un-forgeable — a same-UID agent running arbitrary in-process code (a node -e that reads
// the 0600 signing key) can forge a row. Closed only by the deferred offensive-SANDBOX
// (UID/network-separation) work. The second handler parameter ({ observation_source })
// is WITHIN this in-process boundary (a caller that can pass it can already read the key);
// the MCP dispatcher always calls the handlers with NO second argument (LIVE).

const crypto = require("crypto");
const fs = require("fs");

const {
  ERROR_CODES,
  ToolError,
} = require("./envelope.js");
const {
  readSessionStateStrict,
} = require("./session-state-store.js");
const {
  blockInternalHostsPolicyFields,
} = require("./session-state-contracts.js");
const {
  createProxyAgent,
} = require("./egress-profiles.js");
const {
  resolveAndAssertSessionEgressIdentity,
} = require("./session-state.js");
const {
  assertSafeRequestUrl,
  safeFetch,
} = require("./safe-fetch.js");
const {
  assertEnumValue,
  assertRequiredText,
} = require("./validation.js");
const {
  findRoutedSurface,
  candidateSurfaceEndpoints,
  resolveSurfaceOrigins,
  originFromState,
  urlFromEndpoint,
  assertReadOnlyPath,
  auditConfirmRequest,
  assertNoForbiddenInputs,
  sensitiveShapesPresent,
  mintSensitiveShapeSafeToken,
  SCOPE_VALIDATION_OPTS,
} = require("./offensive-http-common.js");
const {
  canonicalizeExploitTarget,
} = require("./claims.js");
const {
  buildAndSignOffensiveRow,
} = require("./offensive-capture-writer.js");
const {
  // Exact-parsed-leaf canary primitives, reused VERBATIM so the second-order oracle
  // is byte-identical to the IDOR producer's canary witness (exact leaf equality via
  // BFS discovery — NEVER a substring, NEVER whole-body equality).
  canaryAt,
  discoverCanaryFieldPath,
} = require("./offensive-idor-producer.js");
const {
  withSessionLock,
  appendJsonlLine,
} = require("./storage.js");
const {
  canonicalJson,
} = require("./verification-contracts.js");
const {
  secondorderTokensJsonlPath,
} = require("./paths.js");

const MINT_TOOL_ID = "bob_secondorder_mint";
const REREAD_TOOL_ID = "bob_secondorder_reread";
// The ONE oracle kind these handlers stamp — a MAC-covered sibling the read-time
// exploit-run skip recognizes as non-self-contained (constants.OFFENSIVE_ROW_ORACLE_KIND_VALUES).
const ORACLE_KIND_VALUES = Object.freeze(["second_order_reread"]);
// Read-only method LABELS: the re-read never mutates; GET/HEAD only.
const SECONDORDER_METHODS = Object.freeze(["GET", "HEAD"]);

// AC HARD MEDIUM: a stored-effect surfacing (an injected canary reflected on a distinct
// read endpoint) is a MEDIUM-at-most LEAD unless the effect itself is the impact. Frozen
// + "use strict" means an in-process actor's `MAP.x = "critical"` THROWS.
// demonstrated_severity is stamped from here, NEVER agent-supplied, NEVER content-derived.
const SECONDORDER_ORACLE_DEMONSTRATED_CEILING = Object.freeze({ second_order_reread: "medium" });

// The agent never supplies the canary / decoy / endpoints / severity — they are
// server-minted or server-derived. Defense-in-depth behind the descriptor's
// additionalProperties:false allowlist (mirrors the OOB / IDOR forbidden-extras sets).
const SECONDORDER_FORBIDDEN_EXTRAS = Object.freeze([
  "canary", "decoy", "canary_value", "decoy_value", "token", "token_value",
  "canary_payload", "payload", "injection_endpoint", "observation_endpoint",
  "injection_url", "observation_url", "host", "hostname", "domain",
]);

// Per-session bound on live (un-consumed) bindings — bounds the reread match scan + the
// audit-graded ledger (the async mint->inject->reread split would otherwise accumulate
// bindings with no daemon to expire them).
const MAX_LIVE_SECONDORDER_TOKENS = 64;
// A minted binding is only re-readable within this window (a stored effect may take time
// to propagate, but an unbounded TTL grows the ledger forever).
const SECONDORDER_TOKEN_TTL_MS = 48 * 60 * 60 * 1000;
const REREAD_TIMEOUT_MS = 10_000;
// Bound the body read for the JSON parse + PII screen (well under safe-fetch's 1 MB
// response cap). The exact-leaf oracle reads a parsed leaf, never a substring of this.
const OBS_BODY_CAP = 256 * 1024;

// ── small helpers ────────────────────────────────────────────────────────────

function rejectInvalidArguments(message, details = null) {
  throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, message, details);
}

function normalizeMethod(value) {
  const method = value == null ? "GET" : assertRequiredText(value, "method").toUpperCase();
  return assertEnumValue(method, SECONDORDER_METHODS, "method");
}

function normalizeOracleKind(value) {
  return assertEnumValue(assertRequiredText(value, "oracle_kind"), ORACLE_KIND_VALUES, "oracle_kind");
}

// reread arm selector. "interaction" (default) requires the exact canary present + decoy
// absent and signs the exploited_safely positive; "silence" is the negative control — the
// server-minted DECOY (never returned, never injectable) confirmed absent against a
// reachable endpoint, signed blocked_by_defense so finding-differential can FLIP the pair.
// It is an arm selector, never a target input.
const EXPECT_VALUES = Object.freeze(["interaction", "silence"]);
function normalizeExpect(value) {
  if (value == null) return "interaction";
  return assertEnumValue(assertRequiredText(value, "expect"), EXPECT_VALUES, "expect");
}

// An endpoint LOCUS is an integer index into the surface's server-recorded endpoint list
// (candidateSurfaceEndpoints, stable order). It is a server-bounded selector, NOT a raw
// URL — the agent can only point at endpoints the routed surface already records.
function normalizeLocus(value, field, dflt) {
  if (value == null) return dflt;
  if (typeof value !== "number" || !Number.isInteger(value) || value < 0) {
    rejectInvalidArguments(`${field} must be a non-negative integer index into the surface's recorded endpoints`);
  }
  return value;
}

// Mint a 256-bit hex canary (crypto.randomBytes(32)) that carries NO PII / secret shape.
// 256 bits mirrors the IDOR producer's canary width; rejection-sampling against
// sensitiveShapesPresent (the shared http-common screen mintSensitiveShapeSafeToken uses)
// guarantees Bob's own nonce can never make a clean capture look like operator PII.
function mintCanaryToken(prefix) {
  if (!/^[a-z]{1,16}$/.test(String(prefix || ""))) {
    throw new TypeError("canary prefix must be 1-16 lowercase ASCII letters");
  }
  for (let attempt = 0; attempt < 128; attempt += 1) {
    const token = `${prefix}${crypto.randomBytes(32).toString("hex")}`;
    if (!sensitiveShapesPresent(token)) return token;
  }
  throw new Error("failed to mint a sensitive-shape-safe canary");
}

function notMinted(reason, outcome = "blocked_by_design") {
  return { minted: false, offensive_outcome: outcome, row_written: false, reason };
}

function notConfirmed(outcome, reason, extra = {}) {
  return { confirmed: false, offensive_outcome: outcome, row_written: false, reason, ...extra };
}

// Read the audit-graded binding ledger, fail-closed on a torn/corrupt line (a partial
// line must never be silently skipped — same discipline as readOffensiveRunRecords). The
// signed row's target is RE-DERIVED live from the routed surface at reread, never from a
// stored target here, so this ledger cannot launder an attacker-chosen target even if a
// Bash-planted line were smuggled in; audit-grading additionally Write-blocks the agent.
function readSecondorderTokenRecords(domain) {
  let raw;
  try {
    raw = fs.readFileSync(secondorderTokensJsonlPath(domain), "utf8");
  } catch (err) {
    if (err && err.code === "ENOENT") return [];
    throw new ToolError(ERROR_CODES.STATE_CONFLICT, `unable to read secondorder-tokens.jsonl: ${err.message}`);
  }
  const records = [];
  for (const line of raw.split("\n")) {
    if (!line.trim()) continue;
    let parsed;
    try {
      parsed = JSON.parse(line);
    } catch {
      throw new ToolError(ERROR_CODES.STATE_CONFLICT, "secondorder-tokens.jsonl contains a corrupt line");
    }
    records.push(parsed);
  }
  return records;
}

// token_handle -> { binding (kind:"binding"), consume (kind:"consume") | null }.
function resolveBinding(domain, tokenHandle) {
  let binding = null;
  let consume = null;
  for (const r of readSecondorderTokenRecords(domain)) {
    if (!r || r.token_handle !== tokenHandle) continue;
    if (r.kind === "binding") binding = r;
    else if (r.kind === "consume") consume = r;
  }
  return { binding, consume };
}

// A binding counts toward the per-session cap only if it is BOTH unconsumed AND not yet
// expired — an expired binding is unreadable (token_expired), so counting it would let a
// mint-without-reread session permanently brick new mints once the cap fills with dead
// bindings.
function countLiveBindings(domain, clock = Date.now) {
  const now = clock();
  const consumed = new Set();
  const bindings = new Map();
  for (const r of readSecondorderTokenRecords(domain)) {
    if (!r || typeof r.token_handle !== "string") continue;
    if (r.kind === "binding") bindings.set(r.token_handle, r);
    else if (r.kind === "consume") consumed.add(r.token_handle);
  }
  let live = 0;
  for (const [handle, b] of bindings) {
    if (consumed.has(handle)) continue;
    const ttl = typeof b.ttl_ms === "number" ? b.ttl_ms : SECONDORDER_TOKEN_TTL_MS;
    if (typeof b.minted_at === "number" && now - b.minted_at > ttl) continue;
    live += 1;
  }
  return live;
}

// Resolve the endpoint at `locus` to a SINGLE in-scope URL under a single-host guard
// (mirrors oob-collector's resolveInScopeEndpoint intent so attribution cannot drift to a
// sibling host): a relative endpoint that resolves in-scope against MORE THAN ONE declared
// host is AMBIGUOUS, so we fail closed rather than silently pick one and sign the wrong
// asset. Returns { ok:true, url } or { ok:false, reason }.
function resolveInScopeEndpointAtLocus(domain, surface, state, locus, field, toolId) {
  const endpoints = candidateSurfaceEndpoints(surface);
  if (!Number.isInteger(locus) || locus < 0 || locus >= endpoints.length) {
    return { ok: false, reason: `${field}_out_of_range` };
  }
  const stateOrigin = originFromState(domain, state, toolId);
  const origins = resolveSurfaceOrigins(surface, stateOrigin);
  const endpoint = endpoints[locus];
  const inScope = new Map();
  for (const origin of origins) {
    let candidate;
    try {
      candidate = urlFromEndpoint(endpoint.value, origin, endpoint.field);
    } catch {
      continue;
    }
    try {
      assertSafeRequestUrl(candidate.toString(), domain, SCOPE_VALIDATION_OPTS);
    } catch {
      continue;
    }
    if (!inScope.has(candidate.origin)) inScope.set(candidate.origin, candidate);
  }
  if (inScope.size === 0) return { ok: false, reason: `${field}_out_of_scope` };
  if (inScope.size > 1) return { ok: false, reason: `${field}_ambiguous_host` };
  return { ok: true, url: inScope.values().next().value };
}

// Resolve the injection + observation endpoints from the routed surface + their loci. The
// injection endpoint MUST be DISTINCT from the observation endpoint — otherwise a
// "second-order" re-read degenerates to a same-endpoint reflection, which the reflect
// producer already covers and which a decoy-silent control cannot make second-order.
function resolveInjectionAndObservation(domain, surface, state, injLocus, obsLocus, toolId) {
  if (injLocus === obsLocus) {
    return { ok: false, reason: "injection_and_observation_endpoint_must_differ" };
  }
  const inj = resolveInScopeEndpointAtLocus(domain, surface, state, injLocus, "injection_locus", toolId);
  if (!inj.ok) return inj;
  const obs = resolveInScopeEndpointAtLocus(domain, surface, state, obsLocus, "observation_locus", toolId);
  if (!obs.ok) return obs;
  const injTarget = canonicalizeExploitTarget(inj.url.toString());
  const obsTarget = canonicalizeExploitTarget(obs.url.toString());
  // Distinct RESOLVED targets — two different loci could still resolve to the same URL.
  if (injTarget === obsTarget) {
    return { ok: false, reason: "injection_and_observation_endpoint_must_differ" };
  }
  return { ok: true, injectionUrl: inj.url, observationUrl: obs.url, injectionTarget: injTarget, observationTarget: obsTarget };
}

// Replace Bob's OWN minted canary/decoy with a neutral token before a FOREIGN-PII/secret
// scan of the surfaced body: the nonces are known-safe, definitionally not foreign data,
// and stripping the EXACT nonce runs cannot hide adjacent real PII (only the nonce itself
// is removed, never a neighbouring value) — precision-only, mirrors the IDOR neutralizer.
function neutralizeCanaries(text, canaries) {
  let s = String(text);
  for (const c of canaries) {
    if (typeof c === "string" && c) s = s.split(c).join("CANARY");
  }
  return s;
}

function observationBodyText(response, limit = OBS_BODY_CAP) {
  if (!response || !Buffer.isBuffer(response.bodyBytes) || response.bodyBytes.length === 0) return "";
  return response.bodyBytes.toString("utf8", 0, Math.min(response.bodyBytes.length, limit));
}

// Parse the re-read body as JSON. A non-parsing body returns null (fail closed → the
// exact-leaf oracle then finds nothing → negative), so a non-JSON / truncated body can
// never sign a positive.
function parseObservationBody(response) {
  const text = observationBodyText(response);
  if (!text.trim()) return null;
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}

// Issue the read-only re-read. Test/seam path: the injected source returns a response-like
// { status, bodyBytes } directly (within the conceded in-process boundary). Live path: a
// single scope-validated safeFetch to the in-scope observation endpoint honoring the
// session egress + internal-host policy. Either way the probe is audited so the circuit
// breaker / request budget count it; a swallowed audit write ABORTS (the producer must
// never sign a proof for an un-audited live probe).
async function fetchObservation({ domain, state, observationUrl, method, surfaceId, observationSource, startedAt }) {
  const url = observationUrl.toString();
  let response;
  let error;
  let egressProfileName = null;
  try {
    if (typeof observationSource === "function") {
      response = await observationSource(url, { method });
    } else {
      const internalHostPolicy = blockInternalHostsPolicyFields(state);
      const blockInternalHosts = internalHostPolicy.block_internal_hosts === true;
      const requestedEgressProfile = typeof state.egress_profile === "string" && state.egress_profile.trim()
        ? state.egress_profile
        : "default";
      const { profile: egressProfile, identity } = resolveAndAssertSessionEgressIdentity(domain, requestedEgressProfile, {
        source: REREAD_TOOL_ID,
      });
      if (blockInternalHosts && egressProfile && egressProfile.proxy_url) {
        throw new ToolError(
          ERROR_CODES.SCOPE_BLOCKED,
          "block_internal_hosts cannot be verified with proxy-backed egress for bob_secondorder_reread",
          { scope_decision: "blocked", egress_profile: identity.egress_profile },
        );
      }
      egressProfileName = identity.egress_profile || requestedEgressProfile;
      response = await safeFetch(url, {
        method,
        body: undefined,
        followRedirects: false,
        timeoutMs: REREAD_TIMEOUT_MS,
        targetDomain: domain,
        blockInternalHosts,
        agent: createProxyAgent(egressProfile.proxy_url),
      });
    }
  } catch (e) {
    error = e;
  }
  const auditOk = auditConfirmRequest({
    domain,
    surfaceId,
    method,
    url,
    egressProfile: egressProfileName,
    status: response ? response.status : null,
    scopeDecision: error && error.scope_decision === "blocked" ? "blocked" : null,
    error: error ? (error.message || String(error)) : null,
    startedAt,
    toolId: REREAD_TOOL_ID,
  });
  if (auditOk === false) {
    const auditErr = new ToolError(ERROR_CODES.STATE_CONFLICT, "reread http-audit write failed");
    auditErr.probe_audit_failed = true;
    throw auditErr;
  }
  if (error) throw error;
  return response;
}

// ── bob_secondorder_mint ───────────────────────────────────────────────────────

async function secondorderMint(args, { clock = Date.now } = {}) {
  assertNoForbiddenInputs(args, MINT_TOOL_ID, SECONDORDER_FORBIDDEN_EXTRAS);
  const domain = assertRequiredText(args.target_domain, "target_domain");
  const surfaceId = assertRequiredText(args.surface_id, "surface_id");
  const method = normalizeMethod(args.method);
  normalizeOracleKind(args.oracle_kind);
  const injectionLocus = normalizeLocus(args.injection_locus, "injection_locus", 0);
  const observationLocus = normalizeLocus(args.observation_locus, "observation_locus", 1);

  const { state } = readSessionStateStrict(domain);
  const { surface } = findRoutedSurface(domain, surfaceId);
  const resolved = resolveInjectionAndObservation(domain, surface, state, injectionLocus, observationLocus, MINT_TOOL_ID);
  if (!resolved.ok) {
    return notMinted(resolved.reason);
  }
  // The bound endpoints are the surface's OWN in-scope endpoints; screen them so no PII /
  // secret shape in a recorded path persists into the durable binding / signed row.
  if (sensitiveShapesPresent(resolved.injectionTarget) || sensitiveShapesPresent(resolved.observationTarget)) {
    return notMinted("proof_endpoint_contains_sensitive_value", "blocked_operator_pii");
  }

  if (countLiveBindings(domain, clock) >= MAX_LIVE_SECONDORDER_TOKENS) {
    return notMinted("secondorder_token_cap_reached", "blocked_by_infra");
  }

  const tokenHandle = mintSensitiveShapeSafeToken("soh");
  const canary = mintCanaryToken("socan");
  const decoy = mintCanaryToken("sodec");
  const binding = {
    kind: "binding",
    token_handle: tokenHandle,
    canary,
    decoy,
    surface_id: surfaceId,
    injection_locus: injectionLocus,
    observation_locus: observationLocus,
    method,
    minted_at: clock(),
    ttl_ms: SECONDORDER_TOKEN_TTL_MS,
  };
  // The binding write + the cap read are only race-safe under the session lock.
  withSessionLock(domain, () => {
    if (countLiveBindings(domain, clock) >= MAX_LIVE_SECONDORDER_TOKENS) {
      throw new ToolError(ERROR_CODES.STATE_CONFLICT, "secondorder_token_cap_reached");
    }
    appendJsonlLine(secondorderTokensJsonlPath(domain), binding);
  });

  return {
    minted: true,
    target_domain: domain,
    surface_id: surfaceId,
    token_handle: tokenHandle,
    // The benign canary the agent injects into the target's INJECTION endpoint via a
    // target-facing tool. It is a Bob nonce returned BY DESIGN so the agent can place it;
    // it is not target-sensitive. The DECOY is deliberately NOT returned — it must stay
    // silent to serve as the un-injectable negative control.
    canary_payload: canary,
    injection_endpoint: resolved.injectionTarget,
    observation_endpoint: resolved.observationTarget,
    oracle_kind: ORACLE_KIND_VALUES[0],
    note: "Inject canary_payload into injection_endpoint via a target-facing tool, then call bob_secondorder_reread with this token_handle (expect:interaction). For the finding-differential control, mint a SEPARATE binding, DO NOT inject it, and call bob_secondorder_reread expect:silence.",
  };
}

// ── bob_secondorder_reread ──────────────────────────────────────────────────────

async function secondorderReread(args, { observation_source = null, clock = Date.now } = {}) {
  assertNoForbiddenInputs(args, REREAD_TOOL_ID, SECONDORDER_FORBIDDEN_EXTRAS);
  const domain = assertRequiredText(args.target_domain, "target_domain");
  const tokenHandle = assertRequiredText(args.token_handle, "token_handle");
  const expect = normalizeExpect(args.expect);

  const { binding } = resolveBinding(domain, tokenHandle);
  if (!binding || typeof binding.canary !== "string" || typeof binding.decoy !== "string") {
    return notConfirmed("blocked_by_design", "unknown_token_handle");
  }
  if (typeof binding.minted_at === "number" && clock() - binding.minted_at > (binding.ttl_ms || SECONDORDER_TOKEN_TTL_MS)) {
    return notConfirmed("blocked_by_infra", "token_expired");
  }

  const { state } = readSessionStateStrict(domain);
  const { surface } = findRoutedSurface(domain, binding.surface_id);
  // RE-DERIVE both endpoints from the routed surface + stored loci — NEVER a stored target
  // — so a tampered binding cannot stamp an attacker-chosen / sibling target.
  const resolved = resolveInjectionAndObservation(
    domain, surface, state, binding.injection_locus, binding.observation_locus, REREAD_TOOL_ID,
  );
  if (!resolved.ok) {
    return notConfirmed("blocked_by_design", resolved.reason);
  }
  const observationUrl = resolved.observationUrl;
  // Scope re-validate + read-only shape guard on the actual re-read target (defense in
  // depth on top of the mint-time resolution).
  try {
    assertSafeRequestUrl(observationUrl.toString(), domain, SCOPE_VALIDATION_OPTS);
    assertReadOnlyPath(observationUrl.toString(), REREAD_TOOL_ID);
  } catch {
    return notConfirmed("blocked_by_design", "observation_endpoint_not_read_safe");
  }
  if (sensitiveShapesPresent(resolved.injectionTarget) || sensitiveShapesPresent(resolved.observationTarget)) {
    return notConfirmed("blocked_operator_pii", "proof_endpoint_contains_sensitive_value");
  }

  const startedAt = Date.now();
  let response;
  try {
    response = await fetchObservation({
      domain, state, observationUrl, method: binding.method || "GET", surfaceId: binding.surface_id,
      observationSource: observation_source, startedAt,
    });
  } catch {
    // Unreachable / scope-blocked / audit-failed → no proof, never a false positive.
    return notConfirmed("blocked_by_infra", "observation_unreachable");
  }

  // Screen the surfaced body (minus Bob's own nonces) for foreign PII / secret shapes
  // BEFORE any sign — even though the raw body never enters the capture, a proof that
  // surfaces operator PII must not be attested.
  const bodyText = observationBodyText(response);
  if (bodyText && sensitiveShapesPresent(neutralizeCanaries(bodyText, [binding.canary, binding.decoy]))) {
    return notConfirmed("blocked_operator_pii", "observation_body_contains_sensitive_value");
  }

  const parsed = parseObservationBody(response);
  // EXACT-PARSED-LEAF only (discoverCanaryFieldPath = BFS to a leaf whose value === the
  // 256-bit nonce). A substring-only or non-parsing body yields null → negative.
  const canaryPath = parsed != null ? discoverCanaryFieldPath(parsed, binding.canary) : null;
  const decoyPath = parsed != null ? discoverCanaryFieldPath(parsed, binding.decoy) : null;
  // Re-confirm the discovered leaf is EXACTLY the nonce (canaryAt walks the fixed path and
  // returns the leaf string only on exact type/shape) — belt-and-braces on the discovery.
  const canaryPresent = canaryPath != null && canaryAt(parsed, canaryPath) === binding.canary;
  const decoyPresent = decoyPath != null && canaryAt(parsed, decoyPath) === binding.decoy;
  const observationStatus = response && typeof response.status === "number" ? response.status : null;

  if (expect === "silence") {
    // CONTROL ARM (decoy-silent). The decoy was NEVER returned to the agent, so it is
    // un-injectable; its ABSENCE against a REACHABLE endpoint is an affirmative silent
    // control proving the endpoint does not ambient-echo an arbitrary server-minted nonce.
    // A decoy that DID surface is refused (either the sink echoes any nonce, or the ledger
    // was tampered) — never signed as a silent control.
    if (decoyPresent) {
      return notConfirmed("blocked_by_design", "decoy_surfaced");
    }
    const stdoutContent = canonicalJson({
      decoy: binding.decoy,
      bound_injection_endpoint: resolved.injectionTarget,
      bound_observation_endpoint: resolved.observationTarget,
      bound_surface_id: binding.surface_id,
      decoy_silent: true,
    });
    const stderrContent = canonicalJson({
      observation_status: observationStatus,
      decoy_match: "none",
      reread_channel_bob_controlled: true,
    });
    if (
      sensitiveShapesPresent(resolved.observationTarget)
      || sensitiveShapesPresent(stdoutContent)
      || sensitiveShapesPresent(stderrContent)
    ) {
      return notConfirmed("blocked_operator_pii", "capture_contains_sensitive_value");
    }
    const controlRelation = {
      canary_minted_server_side: true,
      decoy_minted_server_side: true,
      decoy_absent_against_reachable_endpoint: true,
      observation_endpoint_distinct_from_injection: true,
      reread_read_only: true,
      reread_channel_bob_controlled: true,
      decoy_silent: true,
    };
    const controlResult = withSessionLock(domain, () => {
      const reread = resolveBinding(domain, tokenHandle);
      if (reread.consume && typeof reread.consume.run_id === "string") {
        return { idempotent: true, run_id: reread.consume.run_id };
      }
      const row = buildAndSignOffensiveRow(domain, {
        runIdPrefix: "soctl",
        toolId: REREAD_TOOL_ID,
        method: binding.method || "GET",
        canonicalTarget: resolved.observationTarget,
        surfaceId: binding.surface_id,
        identityTag: "unauth-secondorder-control",
        stdoutContent,
        stderrContent,
        relationBooleans: controlRelation,
        // A denial, never a positive cause leg. blocked_by_defense is the affirmative
        // safe-variant the finding-differential flip contract requires for a control.
        offensiveOutcome: "blocked_by_defense",
        oracleKind: ORACLE_KIND_VALUES[0],
        demonstratedSeverityOverride: SECONDORDER_ORACLE_DEMONSTRATED_CEILING[ORACLE_KIND_VALUES[0]],
        requireExplicitSeverity: true,
      });
      appendJsonlLine(secondorderTokensJsonlPath(domain), {
        kind: "consume",
        token_handle: tokenHandle,
        run_id: row.run_id,
        consumed_at: clock(),
      });
      return { idempotent: false, row };
    });
    if (controlResult.idempotent) {
      return {
        confirmed: false,
        control: true,
        idempotent: true,
        row_written: false,
        target_domain: domain,
        surface_id: binding.surface_id,
        oracle_kind: ORACLE_KIND_VALUES[0],
        offensive_outcome: "blocked_by_defense",
        run_id: controlResult.run_id,
        note: "token already consumed; returning the previously-signed control run_id (no second row)",
      };
    }
    const controlRow = controlResult.row;
    return {
      confirmed: false,
      control: true,
      idempotent: false,
      row_written: true,
      target_domain: domain,
      surface_id: binding.surface_id,
      oracle_kind: ORACLE_KIND_VALUES[0],
      offensive_outcome: "blocked_by_defense",
      run_id: controlRow.run_id,
      tool_id: controlRow.tool_id,
      target: controlRow.target,
      command_hash: controlRow.command_hash,
      stdout_hash: controlRow.stdout_hash,
      stderr_hash: controlRow.stderr_hash,
      exit_code: controlRow.exit_code,
      demonstrated_severity: controlRow.demonstrated_severity,
      note: "silent decoy control signed (blocked_by_defense); pair it with the injected-and-surfaced positive via bob_verify_finding_differential",
    };
  }

  // POSITIVE ARM (expect:interaction). Require the EXACT canary present AND the decoy
  // absent: the decoy's silence proves the surfaced value is specifically the injected
  // canary, not an ambient echo the endpoint would emit for any server-minted nonce.
  if (!canaryPresent) {
    return notConfirmed("blocked_by_infra", "canary_absent");
  }
  if (decoyPresent) {
    // The decoy ALSO surfaced → the endpoint echoes arbitrary nonces (or the ledger was
    // tampered). Fail closed — a positive is not attributable to the injection.
    return notConfirmed("blocked_by_design", "decoy_surfaced");
  }

  const canaryLeafDepth = Array.isArray(canaryPath) ? canaryPath.length : 0;
  const stdoutContent = canonicalJson({
    canary: binding.canary,
    decoy: binding.decoy,
    bound_injection_endpoint: resolved.injectionTarget,
    bound_observation_endpoint: resolved.observationTarget,
    bound_surface_id: binding.surface_id,
    canary_leaf_depth: canaryLeafDepth,
  });
  const stderrContent = canonicalJson({
    observation_status: observationStatus,
    canary_match: "exact_leaf",
    decoy_silent: true,
    reread_channel_bob_controlled: true,
    canary_leaf_depth: canaryLeafDepth,
  });
  if (
    sensitiveShapesPresent(resolved.observationTarget)
    || sensitiveShapesPresent(stdoutContent)
    || sensitiveShapesPresent(stderrContent)
  ) {
    return notConfirmed("blocked_operator_pii", "capture_contains_sensitive_value");
  }

  const relationBooleans = {
    canary_minted_server_side: true,
    canary_present_exact_leaf: true,
    decoy_minted_server_side: true,
    decoy_absent: true,
    observation_endpoint_distinct_from_injection: true,
    reread_read_only: true,
    reread_channel_bob_controlled: true,
    // NOTE: we do NOT stamp a boolean asserting THIS injection caused the surfacing — the
    // producer does not perform the injection and cannot prove causation from a single
    // re-read. The finding-differential flip against the decoy-silent control carries the
    // non-ambience proof; oracle_kind:"second_order_reread" keeps this row non-self-closing.
  };

  const result = withSessionLock(domain, () => {
    const reread = resolveBinding(domain, tokenHandle);
    if (reread.consume && typeof reread.consume.run_id === "string") {
      return { idempotent: true, run_id: reread.consume.run_id };
    }
    const row = buildAndSignOffensiveRow(domain, {
      runIdPrefix: "so",
      toolId: REREAD_TOOL_ID,
      method: binding.method || "GET",
      canonicalTarget: resolved.observationTarget,
      surfaceId: binding.surface_id,
      identityTag: "unauth-secondorder",
      stdoutContent,
      stderrContent,
      relationBooleans,
      offensiveOutcome: "exploited_safely",
      // Stamp the oracle kind into the MAC-covered row. A single re-read does not, alone,
      // prove the injection caused the surfacing, so the read-time exploit-run skip refuses
      // to treat this row as a self-contained binding — it must earn a finding-differential
      // verified_pass against the blocked_by_defense decoy control.
      oracleKind: ORACLE_KIND_VALUES[0],
      // ALWAYS explicit (requireExplicitSeverity) so an omission fails CLOSED to the frozen
      // MEDIUM ceiling rather than open to a producer default.
      demonstratedSeverityOverride: SECONDORDER_ORACLE_DEMONSTRATED_CEILING[ORACLE_KIND_VALUES[0]],
      requireExplicitSeverity: true,
    });
    appendJsonlLine(secondorderTokensJsonlPath(domain), {
      kind: "consume",
      token_handle: tokenHandle,
      run_id: row.run_id,
      consumed_at: clock(),
    });
    return { idempotent: false, row };
  });

  if (result.idempotent) {
    return {
      confirmed: true,
      idempotent: true,
      row_written: false,
      target_domain: domain,
      surface_id: binding.surface_id,
      oracle_kind: ORACLE_KIND_VALUES[0],
      run_id: result.run_id,
      note: "token already consumed; returning the previously-signed run_id (no second row)",
    };
  }

  const row = result.row;
  // MASKED oracle return (booleans + hashes + run_id + bound surface_id) — NEVER raw
  // response bytes and NEVER the target's field names.
  return {
    confirmed: true,
    idempotent: false,
    target_domain: domain,
    surface_id: binding.surface_id,
    oracle_kind: ORACLE_KIND_VALUES[0],
    offensive_outcome: "exploited_safely",
    row_written: true,
    run_id: row.run_id,
    tool_id: row.tool_id,
    target: row.target,
    command_hash: row.command_hash,
    stdout_hash: row.stdout_hash,
    stderr_hash: row.stderr_hash,
    exit_code: row.exit_code,
    demonstrated_severity: row.demonstrated_severity,
    masked_oracle: {
      relation: relationBooleans,
      canary_present: true,
      decoy_present: false,
      canary_leaf_depth: canaryLeafDepth,
      capture_hash: row.stdout_hash,
    },
  };
}

module.exports = {
  MINT_TOOL_ID,
  REREAD_TOOL_ID,
  ORACLE_KIND_VALUES,
  SECONDORDER_METHODS,
  SECONDORDER_ORACLE_DEMONSTRATED_CEILING,
  secondorderMint,
  secondorderReread,
  // Exported for unit tests (seeded; no live target — the reread is driven through the
  // observation_source seam).
  readSecondorderTokenRecords,
  resolveBinding,
  countLiveBindings,
  // NOTE: buildAndSignOffensiveRow (offensive-capture-writer.js) is intentionally NOT
  // re-exported — it signs+writes a row WITHOUT the oracle gates above, so re-exporting it
  // would give an internal caller a gate-bypassing signed-row path (mirrors oob-collector).
};
