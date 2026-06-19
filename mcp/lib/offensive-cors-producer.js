"use strict";

// bob_http_cors_confirm — CORS-misconfiguration signed-row PRODUCER (in-process, LIVE).
//
// THE ORACLE (sound, #110-clean): the producer sends two GET probes to a routed in-scope
// endpoint, each carrying a DISTINCT server-minted `Origin: https://bob-cors-<32hex>.example`
// the target has NEVER seen. The POSITIVE is BOTH responses echoing their OWN distinct origin
// in `Access-Control-Allow-Origin` AND setting `Access-Control-Allow-Credentials: true`. A
// server cannot guess two unguessable 32-hex origins, so echoing each is a DETERMINISTIC
// witness that the server reflects ARBITRARY origins with credentials — i.e. a malicious
// cross-origin page can read the victim's AUTHENTICATED responses. This is the reflected-canary
// soundness class (the minted origin is the canary): a deterministic/static server cannot
// fabricate it, so it is not the #110 server-noise trap. Two distinct origins (not one)
// distinguish true reflection from a coincidentally-matching static ACAO.
//
// SEVERITY: HARD MEDIUM by construction, stamped from OFFENSIVE_TOOL_DEMONSTRATED_CEILING in
// buildAndSignOffensiveRow (NEVER from here, NEVER agent-supplied). The MISCONFIGURATION is
// proven; the FULL cross-origin-data-theft impact is additionally gated on (a) the endpoint
// returning sensitive data and (b) the session cookie being cross-site-sendable
// (SameSite=None / no SameSite). Those gates are stated honestly in the report, never signed.
//
// INTEGRITY BOUNDARY (honest, NOT closed here): the row MAC is TAMPER-EVIDENT against an agent
// confined to the MCP + guarded-Bash surface; it is NOT cryptographically un-forgeable — a
// same-UID agent running arbitrary in-process code (a node -e that reads the 0600 signing key
// and hand-MACs a row) can forge a row around the gates, the SAME assumption Bob's wave-handoff
// signing makes (tracked in #131). Absolute un-fakeability requires the deferred
// offensive-SANDBOX (UID/container) PR; do NOT advertise un-fakeability. Blast radius is bounded
// to a fabricated MEDIUM by the frozen per-tool ceiling. The second handler parameter
// ({ fetch_fn }) — the seam tests use to drive the oracle without a live target — is WITHIN this
// same in-process boundary (a caller that can pass it can already read the key and forge a row
// directly), so it does not widen the trust boundary. The MCP dispatcher always calls
// corsConfirm(args) with NO second argument (LIVE).
//
// EGRESS RESIDUAL (honest): block_internal_hosts defaults OFF, so unless the session opted in,
// safeFetch does not resolve+reject internal/private addresses. The producer refuses to run
// under proxy-backed egress while block_internal_hosts is on (it cannot verify the policy
// through a proxy), mirroring the reflect/IDOR producers.

const crypto = require("crypto");

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
  safeFetch,
} = require("./safe-fetch.js");
const {
  assertNonEmptyString,
} = require("./validation.js");
const {
  findRoutedSurface,
  resolveSurfaceEndpoint,
  assertReadOnlyPath,
  auditConfirmRequest,
  assertNoForbiddenInputs,
  sensitiveShapesPresent,
} = require("./offensive-http-common.js");
const {
  canonicalizeExploitTarget,
} = require("./claims.js");
const {
  buildAndSignOffensiveRow,
} = require("./offensive-capture-writer.js");
const {
  withSessionLock,
} = require("./storage.js");
const {
  canonicalJson,
} = require("./verification-contracts.js");

const TOOL_ID = "bob_http_cors_confirm";
const DEFAULT_TIMEOUT_MS = 10_000;

// HARD MEDIUM by construction. Frozen + "use strict" means an in-process actor's
// `MAP.x = "high"` THROWS. demonstrated_severity is stamped from the registry in
// buildAndSignOffensiveRow (OFFENSIVE_TOOL_DEMONSTRATED_CEILING), NEVER from here and NEVER
// agent-supplied; this frozen map documents the intent + anchors a test.
const CORS_DEMONSTRATED_CEILING = Object.freeze({ bob_http_cors_confirm: "medium" });

function rejectInvalidArguments(message, details = null) {
  throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, message, details);
}

// A unique, syntactically-valid origin the server has NEVER seen. The 32-hex random label
// means the server cannot pre-configure or guess it — echoing it back in
// Access-Control-Allow-Origin is therefore a SOUND deterministic witness of arbitrary-origin
// reflection. Server-minted, never agent-supplied.
function mintOrigin() {
  return `https://bob-cors-${crypto.randomBytes(16).toString("hex")}.example`;
}

// Read a single response header case-insensitively from either a SafeFetchHeaders/Headers
// object (.get) or a plain object map (seeded tests). Returns null when absent.
function headerValue(response, name) {
  if (!response) return null;
  const headers = response.headers;
  if (!headers) return null;
  if (typeof headers.get === "function") {
    const value = headers.get(name);
    return value == null ? null : String(value);
  }
  if (typeof headers === "object") {
    const lower = name.toLowerCase();
    for (const key of Object.keys(headers)) {
      if (key.toLowerCase() === lower) {
        const value = headers[key];
        return value == null ? null : String(value);
      }
    }
  }
  return null;
}

// ACAO echoes EXACTLY the minted origin (not "*", not a static value, not absent).
function acaoEchoes(response, origin) {
  const value = headerValue(response, "access-control-allow-origin");
  return typeof value === "string" && value.trim() === origin;
}

// ACAC is the literal "true" (case-insensitive) — the dangerous credentialed case.
function allowsCredentials(response) {
  const value = headerValue(response, "access-control-allow-credentials");
  return typeof value === "string" && value.trim().toLowerCase() === "true";
}

function blocked(outcome, reason, extra = {}) {
  return {
    confirmed: false,
    offensive_outcome: outcome,
    row_written: false,
    reason,
    tool_id: TOOL_ID,
    ...extra,
  };
}

// Run a single probe via the injectable fetch_fn (seeded tests) or safeFetch. Audits every
// probe so the circuit breaker / request budget count the live traffic; a swallowed audit
// write aborts (the producer signs a durable proof row, so it must not fire un-audited probes).
async function runProbe({
  fetchFn, url, headers, domain, surfaceId, egressProfile, blockInternalHosts, agent, startedAt,
}) {
  let response;
  let error;
  try {
    if (typeof fetchFn === "function") {
      response = await fetchFn({ url, method: "GET", headers });
    } else {
      response = await safeFetch(url, {
        method: "GET",
        headers,
        body: undefined,
        followRedirects: false,
        timeoutMs: DEFAULT_TIMEOUT_MS,
        targetDomain: domain,
        blockInternalHosts,
        agent,
      });
    }
  } catch (e) {
    error = e;
  }
  const auditOk = auditConfirmRequest({
    domain,
    surfaceId,
    method: "GET",
    url,
    egressProfile,
    status: response ? response.status : null,
    scopeDecision: error && error.scope_decision === "blocked" ? "blocked" : null,
    error: error ? (error.message || String(error)) : null,
    startedAt,
    toolId: TOOL_ID,
  });
  if (auditOk === false) {
    const auditErr = new ToolError(ERROR_CODES.STATE_CONFLICT, "probe http-audit write failed");
    auditErr.probe_audit_failed = true;
    throw auditErr;
  }
  if (error) throw error;
  return response;
}

// The full oracle. `fetch_fn` is injectable so seeded tests need no live target; with no
// fetch_fn the MCP dispatcher drives the LIVE arm via safeFetch.
async function corsConfirm(args = {}, { fetch_fn = null } = {}) {
  // The request is server-derived. The agent may supply ONLY target_domain + surface_id —
  // never a raw URL, origin, header, marker, or severity.
  assertNoForbiddenInputs(args, TOOL_ID, [
    "origin", "origins", "header", "headers", "url", "endpoint",
    "marker", "acao", "acac", "credentials",
  ]);

  const startedAt = Date.now();
  const domain = assertNonEmptyString(args.target_domain, "target_domain");
  const surfaceId = assertNonEmptyString(args.surface_id, "surface_id");

  const { state } = readSessionStateStrict(domain);
  const internalHostPolicy = blockInternalHostsPolicyFields(state);
  const blockInternalHosts = internalHostPolicy.block_internal_hosts === true;

  const fail = (outcome, reason) => blocked(outcome, reason, {
    target_domain: domain,
    surface_id: surfaceId,
    ...internalHostPolicy,
  });

  // Resolve + route the surface, then derive a representative in-scope endpoint SERVER-SIDE
  // (never an agent-supplied URL). The CORS policy is keyed on origin+path, so any recorded
  // endpoint of the surface is a valid probe target.
  const { surface } = findRoutedSurface(domain, surfaceId);
  const endpointUrl = resolveSurfaceEndpoint({ domain, surface, state, toolName: TOOL_ID });
  // Read-only + scope guard on the resolved endpoint (catches a verb-named path segment).
  assertReadOnlyPath(endpointUrl.toString(), TOOL_ID);

  // Value-blind target: keeps origin+path (query stripped). A PII/secret shape in a fixed
  // PATH segment would persist into the durable row target.
  const canonicalTarget = canonicalizeExploitTarget(endpointUrl.toString());
  if (sensitiveShapesPresent(canonicalTarget)) {
    return fail("blocked_operator_pii", "proof_target_contains_sensitive_value");
  }

  // Egress identity (mirrors the reflect / IDOR producers).
  const requestedEgressProfile = typeof state.egress_profile === "string" && state.egress_profile.trim()
    ? state.egress_profile
    : "default";
  const { profile: egressProfile, identity } = resolveAndAssertSessionEgressIdentity(domain, requestedEgressProfile, {
    source: TOOL_ID,
  });
  if (blockInternalHosts && egressProfile && egressProfile.proxy_url) {
    throw new ToolError(
      ERROR_CODES.SCOPE_BLOCKED,
      "block_internal_hosts cannot be verified with proxy-backed egress for bob_http_cors_confirm",
      { scope_decision: "blocked", egress_profile: identity.egress_profile },
    );
  }
  const agent = createProxyAgent(egressProfile.proxy_url);
  const egressProfileName = identity.egress_profile || requestedEgressProfile;

  // Two DISTINCT server-minted origins. Reflecting BOTH (each its own unique value) proves the
  // server echoes ARBITRARY origins — not a static ACAO that coincidentally matched one.
  const origin1 = mintOrigin();
  const origin2 = mintOrigin();
  const url = endpointUrl.toString();
  const probeBase = {
    fetchFn: fetch_fn, url, domain, surfaceId, egressProfile: egressProfileName, blockInternalHosts, agent, startedAt,
  };

  const resp1 = await runProbe({ ...probeBase, headers: { Origin: origin1 } });
  const resp2 = await runProbe({ ...probeBase, headers: { Origin: origin2 } });

  if (!acaoEchoes(resp1, origin1) || !acaoEchoes(resp2, origin2)) {
    // Static ACAO, wildcard "*", or no ACAO → not arbitrary-origin reflection.
    return fail("blocked_by_defense", "acao_does_not_reflect_arbitrary_origin");
  }
  if (!allowsCredentials(resp1) || !allowsCredentials(resp2)) {
    // Reflected origin WITHOUT credentials: a cross-origin page can read only
    // unauthenticated/public responses — not the dangerous credentialed case. v1 signs only
    // the credentialed misconfiguration; fail closed here.
    return fail("blocked_by_design", "reflection_without_credentials");
  }

  // ── build the canonical proof (value-blind, PII-screened) ──
  // The ONLY reflected values captured are Bob's OWN minted origins (never the target's body
  // or other headers) — no PII capture by design; screened anyway.
  const stdoutContent = canonicalJson({
    acao_echoed_origin_1: origin1,
    acao_echoed_origin_2: origin2,
    acac_credentials: true,
  });
  const stderrContent = canonicalJson({
    probe1_status: resp1 ? resp1.status : null,
    probe2_status: resp2 ? resp2.status : null,
    acao_reflects_arbitrary_origin: true,
    acac_credentials_true: true,
  });
  if (sensitiveShapesPresent(stdoutContent) || sensitiveShapesPresent(stderrContent)) {
    return fail("blocked_operator_pii", "capture_contains_sensitive_value");
  }

  const relationBooleans = {
    acao_reflects_arbitrary_origin: true,
    two_distinct_origins_echoed: true,
    acac_credentials_true: true,
  };

  // demonstrated_severity is DERIVED from the per-tool registry inside buildAndSignOffensiveRow
  // (never passed from here). Capture FIRST, recompute hashes from on-disk bytes, sign LAST,
  // hardened append — under the session lock (the run_id single-use guard is only race-safe there).
  const row = withSessionLock(domain, () => buildAndSignOffensiveRow(domain, {
    runIdPrefix: "cors",
    toolId: TOOL_ID,
    method: "GET",
    canonicalTarget,
    surfaceId,
    identityTag: "unauth-cors",
    stdoutContent,
    stderrContent,
    relationBooleans,
  }));

  // Masked oracle return (sensitive_output:true) — booleans + hashes + run_id, NEVER raw bytes.
  return {
    confirmed: true,
    target_domain: domain,
    surface_id: surfaceId,
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
      fragment_hash: row.stdout_hash,
    },
    ...internalHostPolicy,
  };
}

module.exports = {
  corsConfirm,
  headerValue,
  acaoEchoes,
  allowsCredentials,
  mintOrigin,
  TOOL_ID,
  CORS_DEMONSTRATED_CEILING,
};
