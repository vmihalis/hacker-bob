"use strict";

// oob-collector.js — PR6 OOB (out-of-band) collector. Two handlers:
//   bob_oob_mint  — NON-signing token allocator. Mints a high-entropy token bound
//                   to a CONSTANT, server-owned OOB host, resolves the IN-SCOPE
//                   injection endpoint from surface_id, and writes the audit-graded
//                   token->surface binding. Returns the payload forms the agent
//                   injects into the TARGET (via other target-facing tools). NO
//                   network; never signs.
//   bob_oob_poll  — the SIGNING producer. Polls Bob's OWN sink for an interaction
//                   carrying the exact minted token; on a hit, mints a signed
//                   offensive-runs row (demonstrated_severity MEDIUM, from the
//                   per-tool ceiling). Empty / mismatched / unconfigured → signs
//                   nothing (the #110 never-sign-noise discipline).
//
// SOUNDNESS: an interaction carrying the EXACT server-minted 128-bit token at Bob's
// sink is a sound positive — the token is placed ONLY into the target (the agent
// injects token.<host>; these tools only READ the poll API, never write the sink),
// so a server that never saw the unguessable nonce cannot fabricate it. The signed
// row.target is the IN-SCOPE injection endpoint resolved at mint, NEVER the OOB host
// (the OOB host + token live only in the capture). demonstrated_severity is a HARD
// MEDIUM (server-side egress reachability, NOT proven RCE/exfil).
//
// AIM-EXEMPTION (the one constant Bob-owned egress): poll fetches the constant sink
// via safeFetch with NO targetDomain (skips the first-party scope check) but with
// blockInternalHosts:true + followRedirects:false + NO session egress proxy, so the
// internal/private/metadata reject + anti-rebinding pin still run. The host is read
// once from process.env at module load and FROZEN — an agent confined to the MCP +
// guarded-Bash surface cannot supply or repoint it (it is never a tool arg).
//
// INTEGRITY BOUNDARY (honest, NOT closed here; stated verbatim in the tool
// descriptions): the row MAC is TAMPER-EVIDENT against an agent confined to the MCP
// + guarded-Bash surface; it is NOT cryptographically un-forgeable. A same-UID
// agent running arbitrary in-process code (a node -e that reads the 0600 signing
// key and hand-MACs a row) can forge a row — the SAME assumption Bob's wave-handoff
// signing makes. PR6 adds an AGENT SELF-HIT arm: the agent legitimately HOLDS the
// token (returned by design), so on the wide-open net it can curl token.<host> to
// fabricate a callback poll would sign — requiring only NORMAL network capability
// (STRICTLY WEAKER than the in-process key-read), bounded to a MEDIUM in-scope
// finding. TRUSTED REPORTER: the gate never inspects capture content, so a
// compromised/buggy sink that fabricates a token-matched interaction induces a
// false signed row. INTERMEDIARY ATTRIBUTION: an unfurler / proxy / SIEM-scanner in
// the target's request path that fetches the token also satisfies the oracle, so
// the honest demonstrated claim is "server-side egress reachability triggered by
// the injection, not isolated to the bound surface". All three close only with the
// deferred offensive-SANDBOX (UID/network-separation) PR; do NOT advertise
// un-fakeability. The second handler parameter ({ config, interaction_source }) is
// WITHIN this same in-process boundary (a caller that can pass it can already read
// the key); the MCP dispatcher always calls with NO second argument (LIVE).

const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const {
  ERROR_CODES,
  ToolError,
} = require("./envelope.js");
const {
  readSessionStateStrict,
} = require("./session-state-store.js");
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
  assertNoForbiddenInputs,
  sensitiveShapesPresent,
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
  oobTokensJsonlPath,
  sessionsRoot,
  assertSafeDomain,
} = require("./paths.js");
const {
  isBlockedInternalHost,
} = require("./url-surface.js");
const {
  assertHttpScopeDomain,
} = require("./scope.js");

const MINT_TOOL_ID = "bob_oob_mint";
const POLL_TOOL_ID = "bob_oob_poll";
const ORACLE_KIND_VALUES = Object.freeze(["out_of_band_interaction"]);
// Read-ish method LABELS for the eventual row's command_hash. mint/poll NEVER
// fetch the target (the agent injects the payload via other target-facing tools),
// so this is a proof LABEL, not a request — but keep it bounded + non-destructive.
const OOB_METHODS = Object.freeze(["GET", "POST", "PUT", "PATCH", "HEAD"]);

// The agent never supplies the OOB host / token / payload / sink — they are
// server-derived or server-minted. This denylist is defense-in-depth behind the
// descriptor's additionalProperties:false allowlist (mirrors how object_id /
// severity are forbidden for the other producers).
const OOB_FORBIDDEN_EXTRAS = Object.freeze([
  "oob_host", "host", "hostname", "domain", "token", "token_value", "canary",
  "payload", "payload_dns", "payload_http", "sink", "sink_url", "poll_url",
  "callback", "callback_url", "collaborator", "interactsh_server",
]);

// Per-session bound on live (un-consumed) tokens — bounds poll's match scan + the
// audit-graded binding file (the async mint->inject->poll split would otherwise
// accumulate tokens with no dev-box daemon to expire them).
const MAX_LIVE_OOB_TOKENS = 64;
// A minted token is only pollable within this window (blind callbacks are often
// delayed, but an unbounded TTL grows the binding file forever).
const OOB_TOKEN_TTL_MS = 48 * 60 * 60 * 1000;
const POLL_TIMEOUT_MS = 10_000;
const MAX_SINK_BODY = 256 * 1024;

// ── env config: read ONCE at module load + frozen (agent-un-suppliable) ──────
//
// Exposed as a pure function (env injectable) so the inert/configured/internal
// branches are unit-testable without re-requiring the module; production binds the
// process-launch env once into OOB_CONFIG below.
function loadOobConfig(env = process.env) {
  const host = typeof env.BOB_OOB_HOST === "string" ? env.BOB_OOB_HOST.trim() : "";
  const pollUrl = typeof env.BOB_OOB_POLL_URL === "string" ? env.BOB_OOB_POLL_URL.trim() : "";
  const selfEgressIp = typeof env.BOB_OOB_SELF_EGRESS_IP === "string" ? env.BOB_OOB_SELF_EGRESS_IP.trim() : "";
  if (!host || !pollUrl) {
    return Object.freeze({ configured: false, reason: "oob_sink_not_configured" });
  }
  try {
    // Host must be a public-registrable, non-internal domain (never localhost /
    // *.internal / a private/link-local literal) — fail closed to INERT otherwise.
    assertHttpScopeDomain(host);
    if (isBlockedInternalHost(host)) {
      return Object.freeze({ configured: false, reason: "oob_host_internal" });
    }
    const parsed = new URL(pollUrl);
    if (parsed.protocol !== "https:") {
      return Object.freeze({ configured: false, reason: "oob_poll_url_not_https" });
    }
    if (isBlockedInternalHost(parsed.hostname)) {
      return Object.freeze({ configured: false, reason: "oob_poll_host_internal" });
    }
  } catch {
    return Object.freeze({ configured: false, reason: "oob_config_invalid" });
  }
  return Object.freeze({
    configured: true,
    host,
    pollUrl,
    selfEgressIp: selfEgressIp || null,
  });
}

const OOB_CONFIG = loadOobConfig();

// ── small helpers ────────────────────────────────────────────────────────────

function rejectInvalidArguments(message) {
  throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, message);
}

function normalizeMethod(value) {
  const method = value == null ? "GET" : assertRequiredText(value, "method").toUpperCase();
  return assertEnumValue(method, OOB_METHODS, "method");
}

function normalizeOracleKind(value) {
  return assertEnumValue(assertRequiredText(value, "oracle_kind"), ORACLE_KIND_VALUES, "oracle_kind");
}

// prefix + 128 bits of hex = a DNS-label-safe ([a-z0-9], <= 63 chars), high-entropy
// nonce. No metacharacters, never an action verb — the only thing the sink ever
// keys on.
function mintToken(prefix) {
  return `${prefix}${crypto.randomBytes(16).toString("hex")}`;
}

function notConfirmed(outcome, reason, extra = {}) {
  return { confirmed: false, offensive_outcome: outcome, row_written: false, reason, ...extra };
}

// Read the audit-graded token ledger with the SAME realpath / O_NOFOLLOW / nlink
// discipline as the append path. The ledger BINDS each token to its in-scope
// surface + canonical_target, and bob_oob_poll trusts that binding to stamp the
// signed row — so a plain readFileSync would let an evaluator (with a Bash `ln`
// the Write-tool guard does not cover) plant oob-tokens.jsonl as a symlink to a
// chosen binding and drive a signed row with an attacker-picked target. Returns
// null when the ledger does not exist yet.
function readOobTokensRawHardened(domain) {
  const nominalDir = path.dirname(oobTokensJsonlPath(domain));
  let realDir;
  try {
    realDir = fs.realpathSync(nominalDir);
  } catch (err) {
    if (err && err.code === "ENOENT") return null;
    throw new ToolError(ERROR_CODES.STATE_CONFLICT, `unable to resolve oob-tokens.jsonl dir: ${err.message}`);
  }
  const expectedDir = path.join(fs.realpathSync(sessionsRoot()), assertSafeDomain(domain));
  if (realDir !== expectedDir) {
    throw new ToolError(ERROR_CODES.STATE_CONFLICT, `oob-tokens.jsonl dir must stay inside its session root without symlinks: ${nominalDir}`);
  }
  const realLeaf = path.join(realDir, "oob-tokens.jsonl");
  const noFollow = fs.constants.O_NOFOLLOW || 0;
  let fd = null;
  try {
    fd = fs.openSync(realLeaf, fs.constants.O_RDONLY | noFollow);
  } catch (err) {
    if (err && err.code === "ENOENT") return null;
    if (err && (err.code === "ELOOP" || err.code === "EMLINK")) {
      throw new ToolError(ERROR_CODES.STATE_CONFLICT, `oob-tokens.jsonl must not be a symlink: ${realLeaf}`);
    }
    throw new ToolError(ERROR_CODES.STATE_CONFLICT, `unable to read oob-tokens.jsonl: ${err.message}`);
  }
  try {
    const stats = fs.fstatSync(fd);
    if (!stats.isFile()) {
      throw new ToolError(ERROR_CODES.STATE_CONFLICT, `oob-tokens.jsonl must be a regular file: ${realLeaf}`);
    }
    if (stats.nlink !== 1) {
      throw new ToolError(ERROR_CODES.STATE_CONFLICT, `oob-tokens.jsonl must not be hard-linked: ${realLeaf}`);
    }
    return fs.readFileSync(fd, "utf8");
  } finally {
    try { fs.closeSync(fd); } catch {}
  }
}

// Parse the hardened ledger read, fail-closed on a torn/corrupt line exactly like
// readOffensiveRunRecords (a partial line must never be silently skipped).
function readOobTokenRecords(domain) {
  const raw = readOobTokensRawHardened(domain);
  if (raw == null) return [];
  const records = [];
  for (const line of raw.split("\n")) {
    if (!line.trim()) continue;
    let parsed;
    try {
      parsed = JSON.parse(line);
    } catch {
      throw new ToolError(ERROR_CODES.STATE_CONFLICT, "oob-tokens.jsonl contains a corrupt line");
    }
    records.push(parsed);
  }
  return records;
}

// token_handle -> { binding (kind:"binding"), consume (kind:"consume") | null }.
function resolveBinding(domain, tokenHandle) {
  let binding = null;
  let consume = null;
  for (const r of readOobTokenRecords(domain)) {
    if (!r || r.token_handle !== tokenHandle) continue;
    if (r.kind === "binding") binding = r;
    else if (r.kind === "consume") consume = r;
  }
  return { binding, consume };
}

function countLiveBindings(domain) {
  const consumed = new Set();
  const bindings = new Set();
  for (const r of readOobTokenRecords(domain)) {
    if (!r || typeof r.token_handle !== "string") continue;
    if (r.kind === "binding") bindings.add(r.token_handle);
    else if (r.kind === "consume") consumed.add(r.token_handle);
  }
  let live = 0;
  for (const h of bindings) if (!consumed.has(h)) live += 1;
  return live;
}

// Append one complete JSON line to the audit-graded oob-tokens.jsonl with the same
// realpath / O_NOFOLLOW / nlink / atomic-line discipline as the offensive-runs
// writer (so a symlinked session dir or a torn line can never corrupt the binding
// ledger). MCP-owned: agents are Write-blocked on this audit-graded path.
function appendOobTokenRecordHardened(domain, record) {
  const nominalPath = oobTokensJsonlPath(domain);
  const nominalDir = path.dirname(nominalPath);
  fs.mkdirSync(nominalDir, { recursive: true });
  const realRoot = fs.realpathSync(sessionsRoot());
  const expectedDir = path.join(realRoot, assertSafeDomain(domain));
  const realDir = fs.realpathSync(nominalDir);
  if (realDir !== expectedDir) {
    throw new ToolError(
      ERROR_CODES.STATE_CONFLICT,
      `oob-tokens.jsonl directory must stay inside its session root without symlinks: ${nominalDir}`,
    );
  }
  const realLeaf = path.join(realDir, "oob-tokens.jsonl");
  const noFollow = fs.constants.O_NOFOLLOW || 0;
  if (!noFollow && fs.existsSync(realLeaf)) {
    const lst = fs.lstatSync(realLeaf);
    if (lst.isSymbolicLink()) {
      throw new ToolError(ERROR_CODES.STATE_CONFLICT, `oob-tokens.jsonl must not be a symlink: ${realLeaf}`);
    }
  }
  const line = `${JSON.stringify(record)}\n`;
  let fd = null;
  try {
    fd = fs.openSync(realLeaf, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_APPEND | noFollow, 0o600);
    const stats = fs.fstatSync(fd);
    if (!stats.isFile()) {
      throw new ToolError(ERROR_CODES.STATE_CONFLICT, `oob-tokens.jsonl must be a regular file: ${realLeaf}`);
    }
    if (stats.nlink !== 1) {
      throw new ToolError(ERROR_CODES.STATE_CONFLICT, `oob-tokens.jsonl must not be hard-linked: ${realLeaf}`);
    }
    fs.writeSync(fd, line);
    fs.fsyncSync(fd);
  } finally {
    if (fd != null) {
      try { fs.closeSync(fd); } catch {}
    }
  }
}

// Resolve the surface's representative IN-SCOPE recorded endpoint (the first
// candidate that resolves + passes the scope check). Unlike the IDOR oracle,
// OOB has no {id} resource-read semantic — the bound proof target is simply an
// in-scope endpoint of the routed surface, so this does NOT require a
// path_template / {id} slot. The query is stripped downstream by
// canonicalizeExploitTarget so the bound target is value-blind.
// Returns { ok:true, url } or { ok:false, reason }. SINGLE-endpoint / single-host
// HARD SCOPE (mirrors the IDOR producer's single-endpoint guard): mint gives the
// agent only surface_id, so a multi-endpoint or multi-host surface would let the
// agent inject into one endpoint while poll stamps row.target with a DIFFERENT
// in-scope endpoint of the same surface — a wrong-target attribution that still
// passes the surface-id proof gates. Refuse the ambiguity (multi-endpoint OOB
// binding is deferred).
function resolveInScopeEndpoint(domain, surface, state) {
  const stateOrigin = originFromState(domain, state, MINT_TOOL_ID);
  const origins = resolveSurfaceOrigins(surface, stateOrigin);
  const endpoints = candidateSurfaceEndpoints(surface);
  if (endpoints.length !== 1 || origins.length !== 1) {
    return { ok: false, reason: "oob_surface_not_single_endpoint" };
  }
  let candidate;
  try {
    candidate = urlFromEndpoint(endpoints[0].value, origins[0], endpoints[0].field);
  } catch {
    return { ok: false, reason: "oob_surface_endpoint_unresolvable" };
  }
  try {
    assertSafeRequestUrl(candidate.toString(), domain, SCOPE_VALIDATION_OPTS);
  } catch {
    return { ok: false, reason: "oob_surface_endpoint_out_of_scope" };
  }
  return { ok: true, url: candidate };
}

// ── bob_oob_mint ──────────────────────────────────────────────────────────────

async function oobMint(args, { config = OOB_CONFIG, clock = Date.now } = {}) {
  assertNoForbiddenInputs(args, MINT_TOOL_ID, OOB_FORBIDDEN_EXTRAS);
  const domain = assertRequiredText(args.target_domain, "target_domain");
  const surfaceId = assertRequiredText(args.surface_id, "surface_id");
  const method = normalizeMethod(args.method);
  normalizeOracleKind(args.oracle_kind);

  if (!config.configured) {
    return notConfirmed("blocked_by_infra", config.reason || "oob_sink_not_configured", { minted: false });
  }

  // Resolve the IN-SCOPE injection endpoint server-side from the routed surface.
  // This becomes the bound canonical_target the signed row's target is stamped
  // from at poll — NEVER the OOB host.
  const { state } = readSessionStateStrict(domain);
  const { surface } = findRoutedSurface(domain, surfaceId);
  const resolved = resolveInScopeEndpoint(domain, surface, state);
  if (!resolved.ok) {
    return notConfirmed("blocked_by_design", resolved.reason, { minted: false });
  }
  const canonicalTarget = canonicalizeExploitTarget(resolved.url.toString());
  if (sensitiveShapesPresent(canonicalTarget)) {
    return notConfirmed("blocked_operator_pii", "proof_target_contains_sensitive_value", { minted: false });
  }

  if (countLiveBindings(domain) >= MAX_LIVE_OOB_TOKENS) {
    return notConfirmed("blocked_by_infra", "oob_token_cap_reached", { minted: false });
  }

  const tokenHandle = mintToken("oobh");
  const token = mintToken("oob");
  const binding = {
    kind: "binding",
    token_handle: tokenHandle,
    token,
    surface_id: surfaceId,
    canonical_target: canonicalTarget,
    method,
    minted_at: clock(),
    ttl_ms: OOB_TOKEN_TTL_MS,
  };
  // The binding write + the cap read are only race-safe under the session lock.
  withSessionLock(domain, () => {
    if (countLiveBindings(domain) >= MAX_LIVE_OOB_TOKENS) {
      throw new ToolError(ERROR_CODES.STATE_CONFLICT, "oob_token_cap_reached");
    }
    appendOobTokenRecordHardened(domain, binding);
  });

  return {
    minted: true,
    target_domain: domain,
    surface_id: surfaceId,
    token_handle: tokenHandle,
    // The benign, token-only payload forms the agent injects into the TARGET. The
    // token is a Bob nonce returned BY DESIGN so the agent can place it; it is not
    // target-sensitive.
    payload_dns: `${token}.${config.host}`,
    // http:// (not https://) — the reference sink's callback listener is plain
    // HTTP; the DNS payload is scheme-agnostic and the primary detector. (The
    // poll API Bob queries is separately HTTPS; that is Bob->sink, not target->sink.)
    payload_http: `http://${config.host}/${token}`,
    oracle_kind: ORACLE_KIND_VALUES[0],
    note: "Inject payload_dns or payload_http into the target via a target-facing tool, then call bob_oob_poll with this token_handle.",
  };
}

// ── bob_oob_poll ────────────────────────────────────────────────────────────

async function fetchSinkInteractions(config, token, interactionSource) {
  // Test/seam path: the injected source returns the parsed sink response directly
  // (within the conceded in-process boundary). Live path: a single direct fetch to
  // the constant sink — NO targetDomain (aim-exempt), blockInternalHosts:true +
  // followRedirects:false EXPLICIT, and NO session egress proxy attached.
  if (typeof interactionSource === "function") {
    return interactionSource(token);
  }
  const url = new URL(config.pollUrl);
  url.searchParams.set("token", token);
  const response = await safeFetch(url.toString(), {
    method: "GET",
    blockInternalHosts: true,
    followRedirects: false,
    timeout: POLL_TIMEOUT_MS,
  });
  if (!response || response.status !== 200) {
    throw new ToolError(ERROR_CODES.STATE_CONFLICT, `oob sink poll returned status ${response ? response.status : "none"}`);
  }
  const body = response.bodyBytes
    ? response.bodyBytes.toString("utf8", 0, Math.min(response.bodyBytes.length, MAX_SINK_BODY))
    : "";
  let parsed;
  try {
    parsed = JSON.parse(body);
  } catch {
    throw new ToolError(ERROR_CODES.STATE_CONFLICT, "oob sink poll response was not valid JSON");
  }
  return parsed;
}

function normalizeInteractions(parsed) {
  const list = parsed && Array.isArray(parsed.interactions) ? parsed.interactions : [];
  return list.filter((i) => i && typeof i === "object");
}

async function oobPoll(args, { config = OOB_CONFIG, interaction_source = null, clock = Date.now } = {}) {
  assertNoForbiddenInputs(args, POLL_TOOL_ID, OOB_FORBIDDEN_EXTRAS);
  const domain = assertRequiredText(args.target_domain, "target_domain");
  const tokenHandle = assertRequiredText(args.token_handle, "token_handle");

  if (!config.configured) {
    return notConfirmed("blocked_by_infra", config.reason || "oob_sink_not_configured", { available: false });
  }

  const { binding } = resolveBinding(domain, tokenHandle);
  if (!binding || typeof binding.token !== "string") {
    return notConfirmed("blocked_by_design", "unknown_token_handle");
  }
  if (typeof binding.minted_at === "number" && clock() - binding.minted_at > (binding.ttl_ms || OOB_TOKEN_TTL_MS)) {
    return notConfirmed("blocked_by_infra", "token_expired");
  }

  let parsed;
  try {
    parsed = await fetchSinkInteractions(config, binding.token, interaction_source);
  } catch {
    // Sink unreachable / non-200 / bad JSON → no proof, never a false negative.
    return notConfirmed("blocked_by_infra", "sink_unreachable");
  }

  // Exact-token match ONLY. Stray / non-minted interactions are dropped → no row.
  const matched = normalizeInteractions(parsed).filter((i) => i.token === binding.token);
  if (matched.length === 0) {
    return notConfirmed("blocked_by_infra", "no_matching_interaction");
  }

  // Protocol + source attribution. DNS hits come from the target's recursive
  // resolver (source is NOT the host), so DNS-only attribution is weak — but token
  // secrecy is the anchor, so a DNS-only hit is still a sufficient MEDIUM positive.
  const httpHit = matched.find((i) => i.protocol === "http") || null;
  const protocol = httpHit ? "http" : (matched[0].protocol === "dns" ? "dns" : "unknown");
  const dnsOnly = protocol === "dns";

  // SELF-HIT withhold (defense-in-depth, HTTP-only): if the sink reports an HTTP
  // source IP equal to the configured session egress IP, the callback may be the
  // agent's own curl, not the target — withhold the signed row. Useless for DNS
  // (source = resolver), so DNS hits are never withheld on this basis.
  let sourceDistinct = true;
  if (httpHit && config.selfEgressIp && typeof httpHit.source_ip === "string") {
    // Normalize IPv4-mapped IPv6 (a Node server on :: reports IPv4 clients as
    // "::ffff:203.0.113.99") so the documented plain-IPv4 config still matches.
    const norm = (ip) => String(ip).replace(/^::ffff:/i, "");
    const sameEgress = norm(httpHit.source_ip) === norm(config.selfEgressIp);
    if (sameEgress) {
      return notConfirmed("blocked_by_design", "self_hit_suspected");
    }
    sourceDistinct = !sameEgress;
  }

  // CAPTURE: Bob's OWN observation ONLY — token + constant host + protocol + ts +
  // bound surface. NEVER the raw inbound request or the prepended FQDN labels.
  const firstSeen = typeof matched[0].first_seen_ts === "number" ? matched[0].first_seen_ts : clock();
  const stdoutContent = canonicalJson({
    token: binding.token,
    oob_host: config.host,
    protocol,
    first_seen_ts: firstSeen,
    bound_surface_id: binding.surface_id,
  });
  const stderrContent = canonicalJson({
    interaction_count: matched.length,
    token_match: "exact",
    protocol,
    source_is_remote: true,
    source_distinct_from_session_egress: sourceDistinct,
    dns_only_attribution_weak: dnsOnly,
  });
  // Defense in depth: even the bounded capture + the bound target must carry no PII
  // / credential shape (structurally impossible for nonce+host, screened anyway).
  if (
    sensitiveShapesPresent(binding.canonical_target) ||
    sensitiveShapesPresent(stdoutContent) ||
    sensitiveShapesPresent(stderrContent)
  ) {
    return notConfirmed("blocked_operator_pii", "capture_contains_sensitive_value");
  }

  const relationBooleans = {
    oob_host_is_constant: true,
    token_minted_server_side: true,
    interaction_observed: true,
    token_match_exact: true,
    source_is_remote: true,
    source_distinct_from_session_egress: sourceDistinct,
    dns_only_attribution_weak: dnsOnly,
    // NOTE: we do NOT stamp a "no pre-injection hit" control — no pre-injection
    // poll is performed, so asserting it in the signed MAC would claim an
    // observation that never happened. Freshness of the 128-bit token is already
    // covered by token_minted_server_side (it cannot collide with a prior hit).
  };

  // Sign LAST + the token-consumed double-sign guard, BOTH under the SAME session
  // lock acquisition (buildAndSignOffensiveRow's run_id single-use guard requires
  // the caller to hold the lock; newRunId mints a fresh UUID per call, so without
  // this guard two polls of one delayed callback would mint two findings).
  const result = withSessionLock(domain, () => {
    const reread = resolveBinding(domain, tokenHandle);
    if (reread.consume && typeof reread.consume.run_id === "string") {
      return { idempotent: true, run_id: reread.consume.run_id };
    }
    const row = buildAndSignOffensiveRow(domain, {
      runIdPrefix: "oob",
      toolId: POLL_TOOL_ID,
      method: binding.method || "GET",
      canonicalTarget: binding.canonical_target,
      surfaceId: binding.surface_id,
      identityTag: "unauth-oob",
      stdoutContent,
      stderrContent,
      relationBooleans,
    });
    appendOobTokenRecordHardened(domain, {
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
  // Masked oracle return (sensitive_output:true) — booleans + hashes + run_id,
  // NEVER raw response bytes.
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
      protocol,
      relation: relationBooleans,
      interaction_count: matched.length,
      capture_hash: row.stdout_hash,
    },
  };
}

module.exports = {
  MINT_TOOL_ID,
  POLL_TOOL_ID,
  ORACLE_KIND_VALUES,
  OOB_METHODS,
  oobMint,
  oobPoll,
  // Exported for unit tests (env-injectable; no live sink / no live target).
  loadOobConfig,
  readOobTokenRecords,
  resolveBinding,
  // NOTE: buildAndSignOffensiveRow (offensive-capture-writer.js) is intentionally
  // NOT re-exported — it signs+writes a row WITHOUT the oracle gates above, so
  // re-exporting it would give an internal caller a gate-bypassing signed-row path.
};
