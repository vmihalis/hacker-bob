"use strict";

const { redactUrlSensitiveValues } = require("../../redaction.js");
const {
  assertNonEmptyString,
  assertRequiredText,
  parseAgentId,
  parseWaveId,
} = require("../../core/io/validation.js");
const {
  appendHttpAuditRecord,
} = require("../../core/io/http-records.js");
const {
  blockInternalHostsPolicyFields,
} = require("../../core/session/session-state-contracts.js");
const {
  blockInternalHostsRequestPolicy,
} = require("../../core/session/session-state-store.js");
const {
  assertBlockInternalHostsCompatibleWithEgress,
  resolveAndAssertSessionEgressIdentity,
  readStateSummary,
} = require("../../core/session/session-state.js");
const {
  safeUrlObject,
} = require("../../core/url-surface.js");
const {
  resolveAuthProfile,
  applyAuthProfileHeaders,
} = require("../../core/auth/auth.js");
const {
  resolveHttpScanTargetDomain,
} = require("../../core/scope.js");
const {
  assertSafeRequestUrl,
  resolveSafeAddress,
} = require("../../core/io/safe-fetch.js");
const {
  createProxyAgent,
} = require("../../core/egress-profiles.js");

let ws;
try {
  ws = require("ws");
} catch (_) {
  ws = null;
}

function scopeAuditFields(scopeDecision) {
  if (!scopeDecision || typeof scopeDecision !== "object") return {};
  const fields = {};
  for (const field of ["registrable_domain", "public_suffix", "public_suffix_source", "psl_overlay_file"]) {
    if (scopeDecision[field] != null) fields[field] = scopeDecision[field];
  }
  return fields;
}

function isMissingSessionStateError(error) {
  return /Missing session state:|requires an initialized session/.test(
    error && error.message ? error.message : String(error),
  );
}

function sessionStateExistsForEgressContext(targetDomain) {
  try {
    readStateSummary({ target_domain: targetDomain });
    return true;
  } catch (error) {
    if (isMissingSessionStateError(error)) return false;
    throw error;
  }
}

function scopeBlockedEgressContext(targetDomain, requestedEgressProfile, fallback) {
  if (!sessionStateExistsForEgressContext(targetDomain)) return fallback;
  try {
    return resolveAndAssertSessionEgressIdentity(targetDomain, requestedEgressProfile, {
      source: "bob_ws_probe_scope_blocked",
    }).identity;
  } catch (error) {
    if (isMissingSessionStateError(error)) return fallback;
    throw error;
  }
}

function wsUrlToHttpUrl(wsUrl) {
  return wsUrl.replace(/^ws:\/\//i, "http://").replace(/^wss:\/\//i, "https://");
}

// Resource bound (mirrors safe-fetch's 1MB response cap, which did NOT carry over to
// the WS path): a hostile in-scope endpoint could stream unbounded frames to OOM the
// scanner. WS_MAX_FRAME_BYTES is the per-frame protocol cap (ws rejects larger frames
// at the library level); WS_MAX_TOTAL_BYTES bounds the aggregate buffered across frames.
const WS_MAX_FRAME_BYTES = 1_000_000;
const WS_MAX_TOTAL_BYTES = 1_000_000;

// Bounds on caller-settable handshake headers. These cap the UPGRADE request so a
// caller cannot smuggle an oversized or multi-header payload into the HTTP handshake.
const WS_MAX_CUSTOM_HEADERS = 16;
const WS_MAX_HEADER_NAME_BYTES = 256;
const WS_MAX_HEADER_VALUE_BYTES = 4096;

// RFC 7230 token — the legal set for an HTTP header name. Anything outside it (spaces,
// separators, and every control char incl. CR/LF) is rejected. PURE.
function assertSafeHeaderName(name) {
  if (typeof name !== "string" || name.length === 0) {
    throw new Error("header name must be a non-empty string");
  }
  if (Buffer.byteLength(name) > WS_MAX_HEADER_NAME_BYTES) {
    throw new Error(`header name exceeds ${WS_MAX_HEADER_NAME_BYTES} bytes`);
  }
  if (!/^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/.test(name)) {
    throw new Error(`invalid header name "${name}" (illegal token or control chars)`);
  }
}

// A header value must be a bounded string with NO CR/LF or other C0/DEL control chars,
// so the value cannot inject additional header lines / smuggle a second HTTP request
// into the WebSocket upgrade. PURE.
function assertSafeHeaderValue(name, value) {
  if (typeof value !== "string") {
    throw new Error(`header "${name}" value must be a string`);
  }
  if (Buffer.byteLength(value) > WS_MAX_HEADER_VALUE_BYTES) {
    throw new Error(`header "${name}" value exceeds ${WS_MAX_HEADER_VALUE_BYTES} bytes`);
  }
  if (/[\x00-\x1F\x7F]/.test(value)) {
    throw new Error(`header "${name}" value contains control characters`);
  }
}

// buildCallerHeaders — assemble the caller-settable NON-CREDENTIAL base handshake
// headers (User-Agent + a small bounded custom-header map). These are transport headers
// that go to BOTH arms of the CSWSH differential (see cswshArmHeaders), so they can
// never forge a credential-dependent verdict. Every name/value is validated (CR/LF and
// control chars rejected; count/length bounded) — a validation failure throws so the
// handler can fail closed with the request NOT sent. PURE: returns a NEW object, never
// mutates args. Credentials belong on an auth_profile, not here.
function buildCallerHeaders(userAgent, headers) {
  const out = {};
  if (userAgent != null) {
    if (typeof userAgent !== "string") throw new Error("user_agent must be a string");
    assertSafeHeaderValue("User-Agent", userAgent);
    out["User-Agent"] = userAgent;
  }
  if (headers != null) {
    if (typeof headers !== "object" || Array.isArray(headers)) {
      throw new Error("headers must be an object of string values");
    }
    const entries = Object.entries(headers);
    if (entries.length > WS_MAX_CUSTOM_HEADERS) {
      throw new Error(`headers exceeds the ${WS_MAX_CUSTOM_HEADERS}-entry cap`);
    }
    for (const [name, value] of entries) {
      assertSafeHeaderName(name);
      assertSafeHeaderValue(name, value);
      out[name] = value;
    }
  }
  return out;
}

// cswshArmHeaders — the header maps for the two CSWSH handshake arms. The authed arm
// carries the full extraHeaders (base + any auth-profile credentials); the uncredentialed
// control carries ONLY the non-credential base headers (User-Agent / custom). Both get
// the foreign Origin, so the two arms differ EXACTLY by credential material — a UA-based
// WAF 403 hits both arms identically and can never forge cswsh_vulnerable=true. PURE.
function cswshArmHeaders({ headers, baseHeaders, foreignOrigin }) {
  return {
    authed: { ...(headers || {}), Origin: foreignOrigin },
    control: { ...(baseHeaders || {}), Origin: foreignOrigin },
  };
}

const JSON_RPC_STANDARD_METHODS = [
  "eth_blockNumber",
  "net_version",
  "eth_chainId",
  "eth_syncing",
  "web3_clientVersion",
];

const JSON_RPC_ADMIN_METHODS = [
  "debug_traceTransaction",
  "debug_storageRangeAt",
  "admin_peers",
  "admin_nodeInfo",
  "admin_addPeer",
  "txpool_content",
  "txpool_inspect",
  "txpool_status",
  "miner_start",
  "personal_listAccounts",
  "personal_newAccount",
];

function makeJsonRpcCall(method, id) {
  return JSON.stringify({ jsonrpc: "2.0", id, method, params: [] });
}

// Attribute a reply to its request by JSON-RPC `id` (not arrival position): returns
// the first collected frame whose parsed id === requestId, or null. Out-of-order
// replies, subscription pushes, and unsolicited frames are skipped. PURE.
function matchJsonRpcResponse(responses, requestId) {
  for (const r of Array.isArray(responses) ? responses : []) {
    let parsed;
    try { parsed = JSON.parse(r); } catch { continue; }
    if (parsed && parsed.id === requestId) return r;
  }
  return null;
}

function classifyJsonRpcResponse(responseText, method) {
  let parsed;
  try {
    parsed = JSON.parse(responseText);
  } catch (_) {
    return "unknown";
  }
  if (parsed.error) {
    const code = parsed.error.code;
    if (code === -32601) return "disabled";
    if (code === -32000) return "not_enabled";
    return "error";
  }
  if (Object.prototype.hasOwnProperty.call(parsed, "result")) return "enabled";
  return "unknown";
}

// wsConnectPlan — mirror safe-fetch.js requestOnce: decide whether to pin the
// resolved address and/or route through the egress proxy agent. When egressing
// through a proxy and NOT blocking internal hosts, the proxy owns DNS resolution
// (a local pin cannot bind the proxy's lookup), so skip the pin; otherwise pin so
// the socket hits the exact address the scope check validated (closes the
// check-time/connect-time DNS-rebind divergence). PURE.
function wsConnectPlan({ hasProxy, blockInternalHosts }) {
  return {
    useProxyAgent: !!hasProxy,
    pinLookup: !(hasProxy && !blockInternalHosts),
  };
}

// buildWsConnectContext — resolve the egress proxy agent and, when required by
// wsConnectPlan, resolve+validate the address at connect time and build a pinned
// `lookup` so the WebSocket socket binds the exact IP the scope check approved.
// resolveSafeAddress throws a scope_decision:"blocked" error for an internal/private
// address — that propagates to the handler's catch and is audited as blocked.
async function buildWsConnectContext(httpEquivUrl, { proxyUrl, blockInternalHosts }) {
  const proxyAgent = proxyUrl ? createProxyAgent(proxyUrl) : null;
  const plan = wsConnectPlan({ hasProxy: proxyAgent != null, blockInternalHosts });
  let lookup = null;
  if (plan.pinLookup) {
    const parsed = new URL(httpEquivUrl);
    const selected = await resolveSafeAddress(parsed.hostname, { blockInternalHosts });
    lookup = (_hostname, lookupOptions, callback) => {
      const cb = typeof lookupOptions === "function" ? lookupOptions : callback;
      if (lookupOptions && lookupOptions.all) {
        cb(null, [{ address: selected.address, family: selected.family }]);
        return;
      }
      cb(null, selected.address, selected.family);
    };
  }
  return { agent: plan.useProxyAgent ? proxyAgent : null, lookup };
}

function connectWsNative(url, { headers = {}, timeoutMs = 10000, agent = null, lookup = null } = {}) {
  return new Promise((resolve, reject) => {
    const wsOptions = { headers, maxPayload: WS_MAX_FRAME_BYTES };
    if (agent) wsOptions.agent = agent;
    if (lookup) wsOptions.lookup = lookup;
    const socket = new ws(url, wsOptions);
    const upgradeHeaders = {};
    let timer = null;

    timer = setTimeout(() => {
      socket.terminate();
      reject(Object.assign(new Error(`WebSocket connect timeout after ${timeoutMs}ms`), { timeout: true }));
    }, timeoutMs);

    socket.on("upgrade", (response) => {
      for (const [k, v] of Object.entries(response.headers)) {
        upgradeHeaders[k] = v;
      }
    });

    socket.on("open", () => {
      clearTimeout(timer);
      resolve({ socket, upgradeHeaders });
    });

    // Persistent error sink. Before 'open' this rejects the connect promise; AFTER
    // 'open' the reject is a no-op but the listener MUST stay attached for the life of
    // the socket — it is the only thing standing between a post-handshake socket reset
    // (mid JSON-RPC enumeration) and an uncatchable ERR_UNHANDLED_ERROR process crash.
    // Do not remove it; collectMessagesNative is careful to strip only its OWN listeners.
    socket.on("error", (err) => {
      clearTimeout(timer);
      reject(err);
    });
  });
}

function collectMessagesNative(socket, { maxMessages = 5, timeoutMs = 10000, maxBytes = WS_MAX_TOTAL_BYTES } = {}) {
  return new Promise((resolve) => {
    const messages = [];
    let byteTotal = 0;
    let timer = null;
    let settled = false;
    // Remove ONLY our own named listeners — NOT removeAllListeners("error"), which
    // would strip connectWsNative's persistent error sink and leave the socket with
    // zero 'error' listeners between sends in the enumeration loop, so a reset from a
    // hostile endpoint would throw ERR_UNHANDLED_ERROR (an uncatchable process crash).
    const onMessage = (data) => {
      const remaining = maxBytes - byteTotal;
      if (remaining <= 0) { finish(); return; }
      const text = String(data);
      // Aggregate byte cap: truncate the frame that would cross the budget and stop,
      // so unbounded streaming from a hostile endpoint cannot exhaust scanner memory.
      const capped = text.length > remaining ? text.slice(0, remaining) : text;
      messages.push(capped);
      byteTotal += capped.length;
      if (messages.length >= maxMessages || byteTotal >= maxBytes) finish();
    };
    const onError = () => finish();
    const onClose = () => finish();
    function finish() {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      socket.removeListener("message", onMessage);
      socket.removeListener("error", onError);
      socket.removeListener("close", onClose);
      resolve(messages);
    }

    timer = setTimeout(finish, timeoutMs);
    socket.on("message", onMessage);
    socket.on("error", onError);
    socket.on("close", onClose);
  });
}

function sendFrameNative(socket, frame) {
  return new Promise((resolve, reject) => {
    socket.send(frame, (err) => {
      if (err) reject(err);
      else resolve();
    });
  });
}

async function runJsonRpcEnumerateNative(url, { timeoutMs, headers, agent, lookup }) {
  const allMethods = [...JSON_RPC_STANDARD_METHODS, ...JSON_RPC_ADMIN_METHODS];
  const enabledMethods = [];
  const disabledMethods = [];
  const unknownMethods = [];

  let socketObj;
  try {
    socketObj = await connectWsNative(url, { headers, timeoutMs, agent, lookup });
  } catch (err) {
    throw err;
  }
  const { socket, upgradeHeaders } = socketObj;

  try {
    for (let i = 0; i < allMethods.length; i++) {
      const method = allMethods[i];
      const requestId = i + 1;
      await sendFrameNative(socket, makeJsonRpcCall(method, requestId));
      // Collect a few frames and attribute the reply by its JSON-RPC `id`. Matching on
      // id (not position) means an out-of-order reply, a subscription push, or any
      // unsolicited frame cannot be misclassified as THIS method's response.
      const responses = await collectMessagesNative(socket, { maxMessages: 4, timeoutMs: 3000 });
      const matchedText = matchJsonRpcResponse(responses, requestId);
      if (matchedText === null) {
        unknownMethods.push(method);
        continue;
      }
      const classification = classifyJsonRpcResponse(matchedText, method);
      if (classification === "enabled") enabledMethods.push(method);
      else if (classification === "disabled" || classification === "not_enabled" || classification === "error") disabledMethods.push(method);
      else unknownMethods.push(method);
    }
  } finally {
    socket.terminate();
  }

  return { enabled_methods: enabledMethods, disabled_methods: disabledMethods, unknown_methods: unknownMethods, upgrade_headers: upgradeHeaders };
}

// classifyCswsh — the CSWSH oracle. A bare foreign-Origin handshake success only
// proves the server did not reject on Origin at upgrade — the NORMAL state for the
// public/unauthenticated endpoints mode 1 enumerates, so flagging it is a guaranteed
// false positive (the evaluating.md "no theoretical bugs / demonstrated impact" bar).
// Real CSWSH requires the cross-origin connection to ride ambient credentials AND
// reach session state. We model that with a credentialed differential: a foreign-
// Origin handshake carrying the session auth_profile is compared against an identical
// foreign-Origin handshake with NO credentials. cswsh_vulnerable is true ONLY when the
// credentialed attempt is accepted where the uncredentialed control is rejected — i.e.
// acceptance depends on the supplied session, not on the endpoint being open. Without
// an auth_profile the tool sends no ambient credentials and CANNOT demonstrate CSWSH,
// so it never flags. PURE.
function classifyCswsh({ hasAuth, authedAccepted, controlAccepted }) {
  const foreignOriginAccepted = !!authedAccepted;
  if (!hasAuth) {
    return {
      connected: foreignOriginAccepted,
      foreign_origin_accepted: foreignOriginAccepted,
      unauth_control_accepted: foreignOriginAccepted,
      cswsh_vulnerable: false,
      cswsh_note: foreignOriginAccepted
        ? "Foreign-Origin handshake accepted, but no auth_profile was supplied so no ambient credentials were sent. This only shows the server does not reject on Origin at upgrade, which is normal for public/unauthenticated endpoints — not a vulnerability. Re-run with auth_profile to test for credentialed cross-origin access (CSWSH)."
        : "Foreign-Origin handshake rejected at upgrade.",
    };
  }
  const cswshVulnerable = !!authedAccepted && !controlAccepted;
  let note;
  if (!authedAccepted) {
    note = "Credentialed foreign-Origin handshake was rejected at upgrade — Origin appears enforced.";
  } else if (controlAccepted) {
    note = "Both the credentialed and the uncredentialed foreign-Origin handshakes were accepted — the endpoint accepts any Origin without relying on credentials (open endpoint, not CSWSH).";
  } else {
    note = "Credentialed foreign-Origin handshake accepted where the uncredentialed control was rejected — acceptance depends on the supplied session credentials (CSWSH-relevant). Confirm the socket exposes session-scoped data post-handshake before reporting.";
  }
  return {
    connected: !!authedAccepted,
    foreign_origin_accepted: !!authedAccepted,
    unauth_control_accepted: !!controlAccepted,
    cswsh_vulnerable: cswshVulnerable,
    cswsh_note: note,
  };
}

async function attemptHandshakeNative(url, headers, { timeoutMs, agent, lookup }) {
  try {
    const { socket, upgradeHeaders } = await connectWsNative(url, { headers, timeoutMs, agent, lookup });
    try { socket.terminate(); } catch { /* socket already gone */ }
    return { accepted: true, upgradeHeaders };
  } catch (err) {
    if (err && err.scope_decision === "blocked") throw err; // connect-time scope block must surface
    return { accepted: false, upgradeHeaders: {} };
  }
}

async function runCswshProbeNative(url, { origin, timeoutMs, headers, baseHeaders, agent, lookup, hasAuth }) {
  const foreignOrigin = origin || "https://evil.example.com";
  const arms = cswshArmHeaders({ headers, baseHeaders, foreignOrigin });
  const authed = await attemptHandshakeNative(url, arms.authed, { timeoutMs, agent, lookup });
  // The uncredentialed control isolates the credential dependence: it carries the SAME
  // non-credential base headers (User-Agent / custom) as the authed arm but NONE of the
  // auth-profile credential material, so the two arms differ ONLY by credentials — a
  // transport-header WAF (e.g. a UA-based 403) hits both arms and cannot forge a verdict.
  const control = hasAuth
    ? await attemptHandshakeNative(url, arms.control, { timeoutMs, agent, lookup })
    : null;
  const verdict = classifyCswsh({
    hasAuth: !!hasAuth,
    authedAccepted: authed.accepted,
    controlAccepted: control ? control.accepted : null,
  });
  return { ...verdict, upgrade_headers: authed.upgradeHeaders || {} };
}

async function runSubscriptionProbeNative(url, { messages, maxMessages, timeoutMs, headers, agent, lookup }) {
  const { socket, upgradeHeaders } = await connectWsNative(url, { headers, timeoutMs, agent, lookup });
  const frames = Array.isArray(messages) ? messages : [];

  try {
    for (const frame of frames) {
      await sendFrameNative(socket, typeof frame === "string" ? frame : JSON.stringify(frame));
    }
    const received = await collectMessagesNative(socket, { maxMessages: maxMessages || 5, timeoutMs });
    return { messages_received: received, upgrade_headers: upgradeHeaders };
  } finally {
    socket.terminate();
  }
}

async function runRawNative(url, { messages, maxMessages, timeoutMs, headers, agent, lookup }) {
  const { socket, upgradeHeaders } = await connectWsNative(url, { headers, timeoutMs, agent, lookup });
  const frames = Array.isArray(messages) ? messages : [];

  try {
    for (const frame of frames) {
      await sendFrameNative(socket, String(frame));
    }
    const received = await collectMessagesNative(socket, { maxMessages: maxMessages || 5, timeoutMs });
    return { messages_received: received, upgrade_headers: upgradeHeaders };
  } finally {
    socket.terminate();
  }
}

async function wsProbe(args) {
  const url = assertRequiredText(args.url, "url");
  const startedAt = Date.now();
  const mode = args.mode || "json_rpc_enumerate";
  const timeoutMs = args.timeout_ms || 10000;
  const maxMessages = args.max_messages || 5;
  const origin = args.origin || null;
  const authProfile = args.auth_profile || null;

  const httpEquivUrl = wsUrlToHttpUrl(url);
  const explicitTargetDomain = args.target_domain
    ? assertNonEmptyString(args.target_domain, "target_domain")
    : null;
  const targetDomain = resolveHttpScanTargetDomain(httpEquivUrl, explicitTargetDomain);
  if (!targetDomain) {
    return JSON.stringify({
      error: "target_domain is required for scoped WebSocket probes",
      scope_decision: "blocked",
    });
  }

  const internalHostPolicy = blockInternalHostsRequestPolicy(targetDomain, args, {
    allowMissingSession: true,
  });
  const blockInternalHosts = internalHostPolicy.block_internal_hosts === true;
  const internalHostContext = blockInternalHostsPolicyFields(internalHostPolicy);
  const parsedUrl = safeUrlObject(httpEquivUrl);
  const requestedEgressProfile = args.egress_profile == null
    ? "default"
    : assertNonEmptyString(args.egress_profile, "egress_profile");
  let egressContext = {
    egress_profile: requestedEgressProfile,
    egress_region: null,
    proxy_configured: false,
    egress_profile_identity_hash: null,
    egress_profile_identity_version: null,
  };

  const auditUrl = redactUrlSensitiveValues(url);
  const auditParsedUrl = safeUrlObject(redactUrlSensitiveValues(httpEquivUrl)) || parsedUrl;
  const auditBase = targetDomain ? {
    version: 1,
    ts: new Date().toISOString(),
    target_domain: targetDomain,
    method: "WS",
    url: auditUrl,
    host: parsedUrl ? parsedUrl.hostname.toLowerCase() : null,
    path: auditParsedUrl ? `${auditParsedUrl.pathname}${auditParsedUrl.search}` : null,
    wave: args.wave == null ? null : parseWaveId(args.wave),
    agent: args.agent == null ? null : parseAgentId(args.agent),
    surface_id: args.surface_id == null ? null : assertNonEmptyString(args.surface_id, "surface_id"),
    auth_profile: authProfile,
    egress_profile: requestedEgressProfile,
    egress_region: null,
    ...internalHostContext,
  } : null;

  const audit = (fields) => {
    if (!auditBase) return;
    appendHttpAuditRecord({
      ...auditBase,
      ...egressContext,
      ...fields,
      ts: new Date().toISOString(),
      duration_ms: Date.now() - startedAt,
    });
  };

  let initialScopeDecision = null;
  try {
    initialScopeDecision = assertSafeRequestUrl(httpEquivUrl, targetDomain, { blockInternalHosts });
  } catch (error) {
    egressContext = scopeBlockedEgressContext(targetDomain, requestedEgressProfile, egressContext);
    audit({
      status: null,
      error: error.message || String(error),
      scope_decision: "blocked",
      ...scopeAuditFields(error.details),
    });
    return JSON.stringify({
      error: error.message || String(error),
      scope_decision: "blocked",
      ...egressContext,
      ...internalHostContext,
    });
  }

  let resolvedProfile = null;
  try {
    const { profile, identity } = resolveAndAssertSessionEgressIdentity(targetDomain, requestedEgressProfile, {
      source: "bob_ws_probe",
    });
    resolvedProfile = profile;
    egressContext = identity;
    assertBlockInternalHostsCompatibleWithEgress(internalHostPolicy, profile);
  } catch (error) {
    if (error && error.code === "STATE_CONFLICT") throw error;
    const message = error.message || String(error);
    const scopeDecision = error && (error.scope_decision === "blocked" || error.code === "SCOPE_BLOCKED")
      ? "blocked"
      : "egress_error";
    audit({
      status: null,
      error: message,
      scope_decision: scopeDecision,
      ...scopeAuditFields(initialScopeDecision),
    });
    return JSON.stringify({
      error: `${message} — request was NOT sent.`,
      scope_decision: scopeDecision,
      ...egressContext,
      ...internalHostContext,
    });
  }

  // Caller-settable NON-CREDENTIAL base handshake headers (User-Agent + bounded custom
  // headers). Validated fail-closed: a CR/LF or control char, an oversized value, or too
  // many headers rejects the request BEFORE any socket opens (like auth_missing/egress_error).
  let baseHeaders;
  try {
    baseHeaders = buildCallerHeaders(args.user_agent, args.headers);
  } catch (error) {
    audit({
      status: null,
      error: error.message || String(error),
      scope_decision: "invalid_header",
      ...scopeAuditFields(initialScopeDecision),
    });
    return JSON.stringify({
      error: `${error.message || String(error)} — request was NOT sent.`,
      scope_decision: "invalid_header",
      ...egressContext,
      ...internalHostContext,
    });
  }

  // extraHeaders = the AUTHED header set. Without an auth_profile it is exactly the base
  // (non-credential) headers; with one, the profile's credential/header fields are merged
  // on top. baseHeaders stays pure (see cswsh control arm below).
  let extraHeaders = baseHeaders;

  if (authProfile) {
    const auth = resolveAuthProfile(authProfile, httpEquivUrl, targetDomain);
    if (auth) {
      // Merge ONLY the profile's header fields through the canonical chokepoint, which
      // strips every PROFILE_METADATA_KEY (credentials/storage + the synthetic mailbox,
      // email, email_origin, provisioned_via, expiry provenance fields). A hand-rolled
      // `k !== "credentials"` denylist would leak that provenance to the target as WS
      // handshake headers and deanonymize the scanner — same chokepoint bob_http_scan uses.
      // applyAuthProfileHeaders is PURE (new object) and preserves caller keys by presence,
      // so an explicit user_agent overrides a profile-supplied one and baseHeaders is untouched.
      extraHeaders = applyAuthProfileHeaders(baseHeaders, auth);
    } else {
      audit({
        status: null,
        error: `auth_profile "${authProfile}" requested but not found`,
        scope_decision: "auth_missing",
        ...scopeAuditFields(initialScopeDecision),
      });
      return JSON.stringify({
        error: `auth_profile "${authProfile}" requested but not found — request was NOT sent. Store auth first via bob_auth_store.`,
        ...egressContext,
      });
    }
  }

  const proxyUrl = resolvedProfile ? resolvedProfile.proxy_url : null;
  const hasAuth = Boolean(authProfile);

  try {
    let probeResult;

    // ws is a hard dependency. If it is somehow unavailable the install is broken —
    // fail closed rather than diverging through a second (python) implementation. A dual
    // transport was the root of native-vs-fallback drift (audit/classification divergence,
    // unsafe f-string header construction) and could honor neither the egress proxy nor
    // the connect-time lookup pin.
    if (!ws) {
      audit({
        status: null,
        error: "ws_npm_unavailable",
        scope_decision: "egress_unavailable",
        ...scopeAuditFields(initialScopeDecision),
      });
      return JSON.stringify({
        error: "bob_ws_probe requires the 'ws' npm package — request was NOT sent.",
        scope_decision: "egress_unavailable",
        ...egressContext,
        ...internalHostContext,
      });
    }
    // Resolve+validate the address at connect time and pin it (or route through the
    // egress proxy agent), so the socket egresses exactly where the audit ledger says it
    // does and binds the exact IP the scope check approved.
    const { agent, lookup } = await buildWsConnectContext(httpEquivUrl, { proxyUrl, blockInternalHosts });
    const connect = { timeoutMs, headers: extraHeaders, agent, lookup };
    if (mode === "json_rpc_enumerate") {
      probeResult = await runJsonRpcEnumerateNative(url, connect);
    } else if (mode === "cswsh_probe") {
      probeResult = await runCswshProbeNative(url, { ...connect, baseHeaders, origin: origin || "https://evil.example.com", hasAuth });
    } else if (mode === "subscription_probe") {
      probeResult = await runSubscriptionProbeNative(url, { ...connect, messages: args.messages, maxMessages });
    } else {
      probeResult = await runRawNative(url, { ...connect, messages: args.messages, maxMessages });
    }

    const connected = probeResult.connected !== false && !probeResult.error;

    audit({
      status: connected ? 101 : null,
      error: probeResult.error || null,
      scope_decision: probeResult.error ? "request_error" : "allowed",
      ...scopeAuditFields(initialScopeDecision),
    });

    return JSON.stringify({
      mode,
      url: auditUrl,
      connected,
      cswsh_vulnerable: probeResult.cswsh_vulnerable ?? null,
      foreign_origin_accepted: probeResult.foreign_origin_accepted ?? null,
      unauth_control_accepted: probeResult.unauth_control_accepted ?? null,
      cswsh_note: probeResult.cswsh_note ?? null,
      enabled_methods: probeResult.enabled_methods ?? null,
      disabled_methods: probeResult.disabled_methods ?? null,
      unknown_methods: probeResult.unknown_methods ?? null,
      messages_received: probeResult.messages_received ?? null,
      upgrade_headers: probeResult.upgrade_headers ?? null,
      error: probeResult.error ?? null,
      ...egressContext,
      ...internalHostContext,
    }, null, 2);
  } catch (err) {
    const errorMessage = err && err.timeout
      ? `timeout after ${timeoutMs}ms`
      : (err.message || String(err));
    const isBlocked = err && err.scope_decision === "blocked";
    audit({
      status: null,
      error: errorMessage,
      scope_decision: isBlocked ? "blocked" : "request_error",
      ...scopeAuditFields(initialScopeDecision),
      ...scopeAuditFields(err && err.details),
    });
    return JSON.stringify(isBlocked
      ? { error: errorMessage, scope_decision: "blocked", ...egressContext, ...internalHostContext }
      : {
        mode,
        url: auditUrl,
        connected: false,
        error: errorMessage,
        ...egressContext,
        ...internalHostContext,
      });
  }
}

module.exports = {
  wsProbe,
  classifyCswsh,
  wsConnectPlan,
  collectMessagesNative,
  matchJsonRpcResponse,
  buildCallerHeaders,
  cswshArmHeaders,
};
