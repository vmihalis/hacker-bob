"use strict";

const fs = require("fs");
const crypto = require("crypto");
const path = require("path");
const {
  bobVersion,
} = require("./runtime-resources.js");
const {
  appendJsonlLine,
  readFileUtf8,
} = require("./storage.js");
const {
  TELEMETRY_TOOL_INVOCATIONS_FILE_NAME,
  statePath,
  telemetryDir,
  telemetryToolInvocationsJsonlPath,
} = require("./paths.js");
const {
  assertHttpScopeDomain,
} = require("./scope.js");
const {
  AUTHORITY_CLASSES,
  normalizeAuthorityTelemetry,
  validateSessionAuthorityState,
} = require("./session-authority.js");
const {
  migrateLegacyTelemetryAgentRunsFile,
} = require("./telemetry-migration.js");

const TOOL_TELEMETRY_VERSION = 1;
const TOOL_INVOCATION_TELEMETRY_VERSION = 1;
const TOOL_EVENTS_FILE_NAME = "tool-events.jsonl";
const TOOL_INVOCATIONS_FILE_NAME = TELEMETRY_TOOL_INVOCATIONS_FILE_NAME;
const ERROR_MESSAGE_MAX_CHARS = 200;
const SAFE_LABEL_MAX_CHARS = 200;
const SAFE_PATH_MAX_CHARS = 1000;
const DEFAULT_RECENT_FAILURE_LIMIT = 10;
const MAX_RECENT_FAILURE_LIMIT = 100;
const TOOL_TELEMETRY_MAX_RECORDS = 5000;
const TOOL_INVOCATION_TELEMETRY_MAX_RECORDS = 5000;
const INVALID_FILTER_VALUE = Symbol("invalid-filter-value");

const SENSITIVE_MESSAGE_RE = /\b(?:authorization|bearer|cookie|set-cookie|password|passwd|secret|api[_-]?key|access[_-]?token|refresh[_-]?token|id[_-]?token)\b/i;
const URL_RE = /\bhttps?:\/\/[^\s"'<>]+/gi;
const ISO_TIMESTAMP_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/;
const VERSION_LABEL_RE = /^[0-9A-Za-z][0-9A-Za-z._+-]{0,79}$/;
const AUTHORITY_CLASS_VALUES = new Set(AUTHORITY_CLASSES);
const AUTHORITY_MODE_VALUES = new Set(["enforce", "shadow"]);
const AUTHORITY_SOURCE_VALUES = new Set([
  "bootstrap",
  "session_state",
  "global",
  "optional_absent",
  "cross_session",
  "legacy_normalized",
  "preapproval_global",
  "recorded_replay",
]);
const AUTHORITY_RESULT_VALUES = new Set(["allowed", "blocked", "shadow_blocked", "not_applicable"]);
const AUTHORITY_ERROR_CODE_VALUES = new Set([
  "none",
  "normalization_failed",
  "no_session",
  "malformed_state",
  "raw_target_drift",
  "target_url_drift",
  "scoped_url_drift",
  "legacy_security_field_missing",
  "class_missing",
  "shadow_not_allowed",
  "replay_authority_drift",
]);

function telemetryEnabled(env = process.env) {
  return env.BOUNTY_TELEMETRY !== "0";
}

function toolTelemetryPath(env = process.env) {
  return path.join(telemetryDir(env), TOOL_EVENTS_FILE_NAME);
}

function toolInvocationTelemetryPath(env = process.env) {
  migrateLegacyTelemetryAgentRunsFile({ env });
  return telemetryToolInvocationsJsonlPath(env);
}

function safeTelemetryPath(filePath) {
  const name = path.basename(String(filePath || ""));
  if (name === TOOL_EVENTS_FILE_NAME || name === TOOL_INVOCATIONS_FILE_NAME) {
    return `[telemetry-dir]/${name}`;
  }
  return "[telemetry-dir]";
}

function safeTranscriptPath(value) {
  return capString(value, SAFE_PATH_MAX_CHARS) ? "[transcript-path]" : null;
}

function safeTelemetryLabel(value, maxChars = SAFE_LABEL_MAX_CHARS) {
  const text = capString(value, maxChars);
  if (!text) return null;
  if (/[:/?#@\\]/.test(text)) return null;
  const redacted = redactSensitiveFragments(redactUrlsInText(text));
  if (redacted !== text) return null;
  if (SENSITIVE_MESSAGE_RE.test(text)) return null;
  return text;
}

function safeIdentityHash(value) {
  const text = capString(value, 128);
  return /^[a-f0-9]{64}$/i.test(text) ? text.toLowerCase() : null;
}

function safeTimestamp(value) {
  const text = capString(value, 40);
  if (!text || !ISO_TIMESTAMP_RE.test(text)) return null;
  return Number.isNaN(Date.parse(text)) ? null : text;
}

function safeVersionLabel(value) {
  const text = safeTelemetryLabel(value, 80);
  return text && VERSION_LABEL_RE.test(text) ? text : null;
}

function safeAuthorityVersion(value) {
  if (value == null) return "legacy";
  if (Number.isInteger(value) && value > 0 && value <= 1000) return value;
  return null;
}

function safeEnumLabel(value, allowedValues, maxChars = SAFE_LABEL_MAX_CHARS) {
  const text = safeTelemetryLabel(value, maxChars);
  return text && allowedValues.has(text) ? text : null;
}

function hasFilterValue(value) {
  return value != null && String(value).trim() !== "";
}

function safeFilterLabel(value, maxChars = SAFE_LABEL_MAX_CHARS) {
  if (!hasFilterValue(value)) return null;
  return safeTelemetryLabel(value, maxChars) || INVALID_FILTER_VALUE;
}

function safeTargetDomainFilter(value) {
  if (!hasFilterValue(value)) return null;
  return capDomain(value) || INVALID_FILTER_VALUE;
}

function publicFilterValue(value) {
  return value === INVALID_FILTER_VALUE ? null : value;
}

function matchesFilterValue(eventValue, filterValue) {
  if (filterValue === INVALID_FILTER_VALUE) return false;
  return !filterValue || eventValue === filterValue;
}

function toolInvocationSidecarPath(runId, env = process.env) {
  return path.join(telemetryDir(env), "runs", `${runId}.json`);
}

function capString(value, maxChars = SAFE_LABEL_MAX_CHARS) {
  if (value == null) return null;
  const text = String(value).replace(/[\r\n\t]+/g, " ").trim();
  if (!text) return null;
  return text.length > maxChars ? text.slice(0, maxChars) : text;
}

function capDomain(value) {
  if (typeof value !== "string" || !value.trim()) return null;
  try {
    return capString(assertHttpScopeDomain(value), SAFE_LABEL_MAX_CHARS);
  } catch {
    return null;
  }
}

function buildRunId(event) {
  const input = [
    event.run_type,
    event.target_domain,
    event.wave,
    event.agent,
    event.surface_id,
    event.ts,
    event.transcript_path,
  ];
  return crypto.createHash("sha256")
    .update(JSON.stringify(input))
    .digest("hex")
    .slice(0, 16);
}

function extractSafeContext(args) {
  if (!args || typeof args !== "object" || Array.isArray(args)) {
    return {
      target_domain: null,
      wave: null,
      agent: null,
      surface_id: null,
    };
  }

  const wave = safeTelemetryLabel(args.wave, 40) ||
    (Number.isInteger(args.wave_number) && args.wave_number > 0 ? `w${args.wave_number}` : null);

  return {
    target_domain: capDomain(args.target_domain),
    wave,
    agent: safeTelemetryLabel(args.agent, 40),
    surface_id: safeTelemetryLabel(args.surface_id),
  };
}

function registryMetadata(tool) {
  if (!tool) return null;
  return {
    role_bundles: Array.isArray(tool.role_bundles) ? tool.role_bundles.slice() : [],
    mutating: !!tool.mutating,
    global_preapproval: !!tool.global_preapproval,
    network_access: !!tool.network_access,
    browser_access: !!tool.browser_access,
    scope_required: !!tool.scope_required,
    sensitive_output: !!tool.sensitive_output,
    session_artifacts_written: Array.isArray(tool.session_artifacts_written)
      ? tool.session_artifacts_written.slice()
      : [],
  };
}

function pickEgressTelemetryFields(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return {};
  const fields = {};
  for (const [field, maxChars] of [
    ["egress_profile", 80],
    ["egress_region", 80],
  ]) {
    const safe = safeTelemetryLabel(value[field], maxChars);
    if (safe) fields[field] = safe;
  }
  const identityHash = safeIdentityHash(value.egress_profile_identity_hash);
  if (identityHash) fields.egress_profile_identity_hash = identityHash;
  if (typeof value.proxy_configured === "boolean") {
    fields.proxy_configured = value.proxy_configured;
  }
  if (
    Number.isInteger(value.egress_profile_identity_version) &&
    value.egress_profile_identity_version > 0
  ) {
    fields.egress_profile_identity_version = value.egress_profile_identity_version;
  }
  return fields;
}

function hasEgressIdentity(fields) {
  return !!(
    fields &&
    (fields.egress_profile ||
      fields.egress_region ||
      fields.egress_profile_identity_hash ||
      typeof fields.proxy_configured === "boolean" ||
      Number.isInteger(fields.egress_profile_identity_version))
  );
}

function readSessionEgressTelemetryFields(targetDomain, { validateAuthority = false } = {}) {
  const domain = capDomain(targetDomain);
  if (!domain) return {};
  try {
    if (validateAuthority) {
      validateSessionAuthorityState(domain);
    }
    const filePath = statePath(domain);
    if (!fs.existsSync(filePath)) return {};
    return pickEgressTelemetryFields(JSON.parse(fs.readFileSync(filePath, "utf8")));
  } catch {
    return {};
  }
}

function egressTelemetryFieldsFromEnvelope(envelope) {
  const root = envelope && envelope.ok === true ? envelope.data : null;
  const rootFields = pickEgressTelemetryFields(root);
  if (hasEgressIdentity(rootFields)) return rootFields;

  const stateFields = pickEgressTelemetryFields(root && root.state);
  if (hasEgressIdentity(stateFields)) return stateFields;

  const details = envelope && envelope.ok === false && envelope.error
    ? envelope.error.details
    : null;
  if (!details || typeof details !== "object" || Array.isArray(details)) return {};

  const directFields = pickEgressTelemetryFields(details);
  if (hasEgressIdentity(directFields)) return directFields;

  const expectedFields = pickEgressTelemetryFields(details.expected);
  if (hasEgressIdentity(expectedFields)) return expectedFields;

  const requestedFields = pickEgressTelemetryFields(details.requested);
  if (hasEgressIdentity(requestedFields)) return requestedFields;

  return {};
}

function shouldReadSessionEgressTelemetry(authority) {
  return !!(
    authority &&
    authority.authority_result === "allowed" &&
    authority.authority_error_code === "none"
  );
}

function redactUrlsInText(text) {
  return text.replace(URL_RE, "[url]");
}

function redactSessionPaths(text) {
  // Cycle P.2: redact both the canonical `hacker-bob-sessions` root and the
  // legacy `bounty-agent-sessions` root so telemetry never leaks home-prefixed
  // session paths during the v2.0/v2.1 coexistence window.
  return text.replace(
    /(?:~|\/[^\s"'<>)]*)\/(?:hacker-bob-sessions|bounty-agent-sessions)\/[^\s"'<>)]*/g,
    "[session-path]",
  );
}

function redactSensitiveFragments(text) {
  return text
    .replace(/\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]+/gi, "$1 REDACTED")
    .replace(
      /\b(authorization|cookie|set-cookie|password|passwd|secret|token|session|credential|api[_-]?key|access[_-]?token|refresh[_-]?token|id[_-]?token|handoff[_-]?token)\b\s*[:=]\s*("[^"]*"|'[^']*'|[^\s,;)]+)/gi,
      "$1=REDACTED",
    );
}

function safeErrorMessage(message, { errorCode = null, registry = null } = {}) {
  if (message == null) return null;
  if (errorCode === "UNKNOWN_TOOL") return "Unknown tool";
  if (registry && registry.sensitive_output) return null;

  let text = capString(message, ERROR_MESSAGE_MAX_CHARS);
  if (!text) return null;
  text = redactSessionPaths(redactSensitiveFragments(redactUrlsInText(text)));

  if (SENSITIVE_MESSAGE_RE.test(text)) {
    return null;
  }
  return capString(text, ERROR_MESSAGE_MAX_CHARS);
}

function currentBobVersion(value = null, env = process.env) {
  const explicit = safeVersionLabel(value);
  if (explicit) return explicit;
  try {
    return safeVersionLabel(bobVersion(env));
  } catch {
    return null;
  }
}

function buildToolTelemetryEvent({
  toolName,
  tool,
  args,
  envelope,
  elapsedMs,
  authority = null,
  bob_version: bobVersionInput = null,
  now = new Date(),
}) {
  const registry = registryMetadata(tool);
  const errorCode = envelope && envelope.ok === false && envelope.error
    ? capString(envelope.error.code, 80)
    : null;
  const context = extractSafeContext(args);
  const authorityTelemetry = normalizeAuthorityTelemetry(authority);
  const egressFields = {
    ...egressTelemetryFieldsFromEnvelope(envelope),
    ...(shouldReadSessionEgressTelemetry(authorityTelemetry)
      ? readSessionEgressTelemetryFields(context.target_domain, { validateAuthority: true })
      : {}),
  };
  const event = {
    version: TOOL_TELEMETRY_VERSION,
    bob_version: currentBobVersion(bobVersionInput),
    ts: now.toISOString(),
    tool: safeTelemetryLabel(toolName, 120) || "<unknown>",
    ok: !!(envelope && envelope.ok === true),
    elapsed_ms: Number.isFinite(elapsedMs) ? Math.max(0, Math.round(elapsedMs)) : 0,
    error_code: errorCode,
    target_domain: context.target_domain,
    wave: context.wave,
    agent: context.agent,
    surface_id: context.surface_id,
    ...egressFields,
    registry,
  };
  if (authorityTelemetry) {
    event.authority = authorityTelemetry;
  }

  if (!event.ok) {
    const errorMessage = safeErrorMessage(envelope && envelope.error && envelope.error.message, {
      errorCode,
      registry,
    });
    if (errorMessage) {
      event.error_message = errorMessage;
    }
  }

  return event;
}

function appendToolTelemetryEvent(event, { env = process.env } = {}) {
  if (!telemetryEnabled(env)) return false;
  const filePath = toolTelemetryPath(env);
  appendJsonlLine(filePath, event, { maxRecords: TOOL_TELEMETRY_MAX_RECORDS });
  return true;
}

function recordToolTelemetry(input, options = {}) {
  const event = buildToolTelemetryEvent(input);
  appendToolTelemetryEvent(event, options);
  return event;
}

function safeRecordToolTelemetry(input, options = {}) {
  try {
    return recordToolTelemetry(input, options);
  } catch {
    return null;
  }
}

function normalizeToolInvocationHandoff(handoff) {
  const value = handoff && typeof handoff === "object" && !Array.isArray(handoff) ? handoff : {};
  const chainNotesCount = Number.isFinite(value.chain_notes_count)
    ? Math.max(0, Math.trunc(value.chain_notes_count))
    : null;

  return {
    present: value.present == null ? null : value.present === true,
    valid: value.valid == null ? null : value.valid === true,
    provenance: safeTelemetryLabel(value.provenance, 80),
    surface_status: safeTelemetryLabel(value.surface_status, 80),
    summary_present: value.summary_present == null ? null : value.summary_present === true,
    chain_notes_count: chainNotesCount,
  };
}

function normalizeToolInvocationCoverage(coverage) {
  const value = coverage && typeof coverage === "object" && !Array.isArray(coverage) ? coverage : {};
  const byStatusInput = value.by_status && typeof value.by_status === "object" && !Array.isArray(value.by_status)
    ? value.by_status
    : {};
  const byStatus = {};
  let total = Number.isFinite(value.total) ? Math.max(0, Math.trunc(value.total)) : 0;
  let computedTotal = 0;

  for (const [status, count] of Object.entries(byStatusInput)) {
    const safeStatus = safeTelemetryLabel(status, 80);
    if (!safeStatus || !Number.isFinite(count)) continue;
    const safeCount = Math.max(0, Math.trunc(count));
    byStatus[safeStatus] = safeCount;
    computedTotal += safeCount;
  }

  if (!Number.isFinite(value.total) && computedTotal > 0) {
    total = computedTotal;
  }

  return {
    total,
    by_status: byStatus,
  };
}

function normalizeToolInvocationFindings(findings) {
  const value = findings && typeof findings === "object" && !Array.isArray(findings) ? findings : {};
  return {
    count: Number.isFinite(value.count) ? Math.max(0, Math.trunc(value.count)) : 0,
  };
}

function buildToolInvocationTelemetryEvent({
  runType,
  run_type: runTypeSnake,
  status,
  blockCode,
  block_code: blockCodeSnake = null,
  target_domain: targetDomain,
  wave,
  agent,
  surface_id: surfaceId,
  transcript_path: transcriptPath,
  handoff,
  coverage,
  findings,
  telemetry_source: telemetrySource = "agent-run-stop",
  bob_version: bobVersionInput = null,
  now = new Date(),
}) {
  const normalizedRunType = runType || runTypeSnake || "evaluator";
  const normalizedBlockCode = blockCode == null ? blockCodeSnake : blockCode;
  const event = {
    version: TOOL_INVOCATION_TELEMETRY_VERSION,
    bob_version: currentBobVersion(bobVersionInput),
    ts: now.toISOString(),
    run_id: null,
    run_type: safeTelemetryLabel(normalizedRunType, 80) || "evaluator",
    status: status === "allowed" ? "allowed" : "blocked",
    block_code: status === "allowed" ? null : safeTelemetryLabel(normalizedBlockCode, 120),
    target_domain: capDomain(targetDomain),
    wave: safeTelemetryLabel(wave, 40),
    agent: safeTelemetryLabel(agent, 40),
    surface_id: safeTelemetryLabel(surfaceId),
    transcript_path: capString(transcriptPath, SAFE_PATH_MAX_CHARS),
    handoff: normalizeToolInvocationHandoff(handoff),
    coverage: normalizeToolInvocationCoverage(coverage),
    findings: normalizeToolInvocationFindings(findings),
    telemetry_source: safeTelemetryLabel(telemetrySource, 120) || "agent-run-stop",
  };
  event.run_id = buildRunId(event);
  return event;
}

function appendToolInvocationTelemetryEvent(event, { env = process.env } = {}) {
  if (!telemetryEnabled(env)) return false;
  const filePath = toolInvocationTelemetryPath(env);
  appendJsonlLine(filePath, event, { maxRecords: TOOL_INVOCATION_TELEMETRY_MAX_RECORDS });

  const sidecarPath = toolInvocationSidecarPath(event.run_id, env);
  fs.mkdirSync(path.dirname(sidecarPath), { recursive: true });
  fs.writeFileSync(sidecarPath, `${JSON.stringify(event, null, 2)}\n`, "utf8");
  return true;
}

function recordToolInvocationTelemetry(input, options = {}) {
  const event = buildToolInvocationTelemetryEvent(input);
  appendToolInvocationTelemetryEvent(event, options);
  return event;
}

function safeRecordToolInvocationTelemetry(input, options = {}) {
  try {
    return recordToolInvocationTelemetry(input, options);
  } catch {
    return null;
  }
}

function normalizeRecentFailureLimit(limit) {
  if (limit == null) return DEFAULT_RECENT_FAILURE_LIMIT;
  if (!Number.isFinite(limit)) return DEFAULT_RECENT_FAILURE_LIMIT;
  return Math.max(1, Math.min(MAX_RECENT_FAILURE_LIMIT, Math.trunc(limit)));
}

function normalizeAuthorityForSummary(authority) {
  if (!authority || typeof authority !== "object" || Array.isArray(authority)) return null;
  const authorityVersion = safeAuthorityVersion(authority.authority_version);
  const authorityClass = safeEnumLabel(authority.authority_class, AUTHORITY_CLASS_VALUES, 80);
  const authorityMode = safeEnumLabel(authority.authority_mode, AUTHORITY_MODE_VALUES, 40);
  const authoritySource = safeEnumLabel(authority.authority_source, AUTHORITY_SOURCE_VALUES, 80);
  const authorityResult = safeEnumLabel(authority.authority_result, AUTHORITY_RESULT_VALUES, 40);
  const authorityErrorCode = safeEnumLabel(
    authority.authority_error_code,
    AUTHORITY_ERROR_CODE_VALUES,
    80,
  );
  const authorityBlockReason = safeEnumLabel(
    authority.authority_block_reason,
    AUTHORITY_ERROR_CODE_VALUES,
    80,
  ) || authorityErrorCode;
  if (
    !authorityVersion ||
    !authorityClass ||
    !authorityMode ||
    !authoritySource ||
    !authorityResult ||
    !authorityErrorCode
  ) {
    return null;
  }
  return {
    authority_version: authorityVersion,
    authority_class: authorityClass,
    authority_mode: authorityMode,
    authority_source: authoritySource,
    authority_result: authorityResult,
    authority_error_code: authorityErrorCode,
    authority_block_reason: authorityBlockReason,
    authority_shadowed: authority.authority_shadowed === true,
  };
}

function isPlainEvent(event) {
  return event && typeof event === "object" && !Array.isArray(event) && event.version === TOOL_TELEMETRY_VERSION;
}

function normalizeEventForSummary(event) {
  const errorCode = safeTelemetryLabel(event.error_code, 80);
  return {
    ts: safeTimestamp(event.ts),
    bob_version: safeVersionLabel(event.bob_version),
    tool: safeTelemetryLabel(event.tool, 120) || "<unknown>",
    ok: event.ok === true,
    elapsed_ms: Number.isFinite(event.elapsed_ms) ? Math.max(0, Math.round(event.elapsed_ms)) : 0,
    error_code: errorCode,
    error_message: safeErrorMessage(event.error_message, {
      errorCode,
      registry: event.registry && typeof event.registry === "object" && !Array.isArray(event.registry)
        ? { sensitive_output: event.registry.sensitive_output === true }
        : null,
    }),
    target_domain: capDomain(event.target_domain),
    wave: safeTelemetryLabel(event.wave, 40),
    agent: safeTelemetryLabel(event.agent, 40),
    surface_id: safeTelemetryLabel(event.surface_id),
    ...pickEgressTelemetryFields(event),
    authority: normalizeAuthorityForSummary(event.authority),
  };
}

function eventMatchesFilters(event, filters) {
  return matchesFilterValue(event.tool, filters.tool) &&
    matchesFilterValue(event.target_domain, filters.target_domain);
}

function isPlainToolInvocationEvent(event) {
  return (
    event &&
    typeof event === "object" &&
    !Array.isArray(event) &&
    event.version === TOOL_INVOCATION_TELEMETRY_VERSION &&
    typeof event.run_id === "string" &&
    typeof event.run_type === "string" &&
    (event.status === "allowed" || event.status === "blocked")
  );
}

function normalizeToolInvocationEventForSummary(event) {
  return {
    ts: safeTimestamp(event.ts),
    bob_version: safeVersionLabel(event.bob_version),
    run_id: safeTelemetryLabel(event.run_id, 80),
    run_type: safeTelemetryLabel(event.run_type, 80) || "evaluator",
    status: event.status === "allowed" ? "allowed" : "blocked",
    block_code: safeTelemetryLabel(event.block_code, 120),
    target_domain: capDomain(event.target_domain),
    wave: safeTelemetryLabel(event.wave, 40),
    agent: safeTelemetryLabel(event.agent, 40),
    surface_id: safeTelemetryLabel(event.surface_id),
    transcript_path: safeTranscriptPath(event.transcript_path),
    handoff: normalizeToolInvocationHandoff(event.handoff),
    coverage: normalizeToolInvocationCoverage(event.coverage),
    findings: normalizeToolInvocationFindings(event.findings),
    telemetry_source: safeTelemetryLabel(event.telemetry_source, 120),
  };
}

function toolInvocationMatchesFilters(event, filters) {
  return matchesFilterValue(event.target_domain, filters.target_domain) &&
    matchesFilterValue(event.run_type, filters.agent_run_type) &&
    matchesFilterValue(event.wave, filters.wave) &&
    matchesFilterValue(event.agent, filters.agent) &&
    matchesFilterValue(event.surface_id, filters.surface_id);
}

function readToolTelemetryEvents({ target_domain: targetDomain, tool, env = process.env } = {}) {
  const filePath = toolTelemetryPath(env);
  const filters = {
    target_domain: safeTargetDomainFilter(targetDomain),
    tool: safeFilterLabel(tool, 120),
  };
  const result = {
    enabled: telemetryEnabled(env),
    telemetry_path: safeTelemetryPath(filePath),
    events: [],
    malformed_lines: 0,
  };

  if (!result.enabled || !fs.existsSync(filePath)) {
    return result;
  }

  const lines = readFileUtf8(filePath, { label: TOOL_EVENTS_FILE_NAME }).split(/\r?\n/);
  for (const line of lines) {
    if (!line.trim()) continue;
    let parsed;
    try {
      parsed = JSON.parse(line);
    } catch {
      result.malformed_lines += 1;
      continue;
    }
    if (!isPlainEvent(parsed)) {
      result.malformed_lines += 1;
      continue;
    }
    const normalized = normalizeEventForSummary(parsed);
    if (eventMatchesFilters(normalized, filters)) {
      result.events.push(normalized);
    }
  }

  return result;
}

function readToolInvocationTelemetryEvents({
  target_domain: targetDomain,
  agent_run_type: agentRunType,
  wave,
  agent,
  surface_id: surfaceId,
  env = process.env,
} = {}) {
  const filePath = toolInvocationTelemetryPath(env);
  const filters = {
    target_domain: safeTargetDomainFilter(targetDomain),
    agent_run_type: safeFilterLabel(agentRunType, 80),
    wave: safeFilterLabel(wave, 40),
    agent: safeFilterLabel(agent, 40),
    surface_id: safeFilterLabel(surfaceId),
  };
  const result = {
    enabled: telemetryEnabled(env),
    telemetry_path: safeTelemetryPath(filePath),
    events: [],
    malformed_lines: 0,
  };

  if (!result.enabled || !fs.existsSync(filePath)) {
    return result;
  }

  const lines = readFileUtf8(filePath, { label: TOOL_INVOCATIONS_FILE_NAME }).split(/\r?\n/);
  for (const line of lines) {
    if (!line.trim()) continue;
    let parsed;
    try {
      parsed = JSON.parse(line);
    } catch {
      result.malformed_lines += 1;
      continue;
    }
    if (!isPlainToolInvocationEvent(parsed)) {
      result.malformed_lines += 1;
      continue;
    }
    const normalized = normalizeToolInvocationEventForSummary(parsed);
    if (toolInvocationMatchesFilters(normalized, filters)) {
      result.events.push(normalized);
    }
  }

  return result;
}

function percentile(values, percentileValue) {
  if (!values.length) return null;
  const sorted = values.slice().sort((a, b) => a - b);
  const index = Math.min(
    sorted.length - 1,
    Math.max(0, Math.ceil((percentileValue / 100) * sorted.length) - 1),
  );
  return sorted[index];
}

function slimEvent(event) {
  const result = {
    ts: event.ts,
    bob_version: event.bob_version,
    tool: event.tool,
    ok: event.ok,
    elapsed_ms: event.elapsed_ms,
    error_code: event.error_code,
    target_domain: event.target_domain,
    wave: event.wave,
    agent: event.agent,
    surface_id: event.surface_id,
    ...pickEgressTelemetryFields(event),
  };
  if (event.authority) {
    result.authority = event.authority;
  }
  if (event.error_message) {
    result.error_message = event.error_message;
  }
  return result;
}

function incrementBucket(bucket, key) {
  const safeKey = capString(key, 120) || "unknown";
  bucket[safeKey] = (bucket[safeKey] || 0) + 1;
}

function summarizeAuthority(events) {
  const summary = {
    total_events: 0,
    by_version: {},
    by_class: {},
    by_result: {},
    by_error_code: {},
  };

  for (const event of events) {
    const authority = event.authority;
    if (!authority) continue;
    summary.total_events += 1;
    incrementBucket(summary.by_version, authority.authority_version);
    incrementBucket(summary.by_class, authority.authority_class);
    incrementBucket(summary.by_result, authority.authority_result);
    incrementBucket(summary.by_error_code, authority.authority_error_code);
  }

  return summary;
}

function summarizeEventGroup(toolName, events, limit) {
  const calls = events.length;
  const successes = events.filter((event) => event.ok).length;
  const failures = calls - successes;
  const elapsedValues = events
    .map((event) => event.elapsed_ms)
    .filter((elapsedMs) => Number.isFinite(elapsedMs));
  const error_codes = {};
  for (const event of events) {
    if (!event.error_code) continue;
    error_codes[event.error_code] = (error_codes[event.error_code] || 0) + 1;
  }
  const failureEvents = events.filter((event) => !event.ok);

  return {
    tool: toolName,
    calls,
    successes,
    failures,
    success_rate: calls ? Number((successes / calls).toFixed(4)) : 0,
    latency_ms: {
      p50: percentile(elapsedValues, 50),
      p95: percentile(elapsedValues, 95),
    },
    error_codes,
    authority: summarizeAuthority(events),
    last_call: calls ? slimEvent(events[events.length - 1]) : null,
    recent_failures: failureEvents.slice(-limit).reverse().map(slimEvent),
  };
}

function summarizeToolTelemetryEvents(events, { limit = DEFAULT_RECENT_FAILURE_LIMIT } = {}) {
  const recentFailureLimit = normalizeRecentFailureLimit(limit);
  const byTool = new Map();
  for (const event of events) {
    if (!byTool.has(event.tool)) {
      byTool.set(event.tool, []);
    }
    byTool.get(event.tool).push(event);
  }

  const tools = Array.from(byTool.entries())
    .map(([toolName, toolEvents]) => summarizeEventGroup(toolName, toolEvents, recentFailureLimit))
    .sort((a, b) => b.calls - a.calls || a.tool.localeCompare(b.tool));

  return {
    observed_bob_versions: observedBobVersions(events),
    authority: summarizeAuthority(events),
    totals: summarizeEventGroup("all", events, recentFailureLimit),
    tools,
    recent_failures: events.filter((event) => !event.ok).slice(-recentFailureLimit).reverse().map(slimEvent),
  };
}

function slimToolInvocationEvent(event) {
  return {
    ts: event.ts,
    bob_version: event.bob_version,
    run_id: event.run_id,
    run_type: event.run_type,
    status: event.status,
    block_code: event.block_code,
    target_domain: event.target_domain,
    wave: event.wave,
    agent: event.agent,
    surface_id: event.surface_id,
    transcript_path: safeTranscriptPath(event.transcript_path),
    handoff: event.handoff,
    coverage: event.coverage,
    findings: event.findings,
    telemetry_source: event.telemetry_source,
  };
}

function summarizeToolInvocationTelemetryEvents(events, {
  limit = DEFAULT_RECENT_FAILURE_LIMIT,
  readResult = null,
  filters = {},
  env = process.env,
} = {}) {
  const recentBlockedLimit = normalizeRecentFailureLimit(limit);
  const byStatus = {
    allowed: 0,
    blocked: 0,
  };
  const byBlockCode = {};

  for (const event of events) {
    byStatus[event.status] = (byStatus[event.status] || 0) + 1;
    if (event.status === "blocked" && event.block_code) {
      byBlockCode[event.block_code] = (byBlockCode[event.block_code] || 0) + 1;
    }
  }

  return {
    version: TOOL_INVOCATION_TELEMETRY_VERSION,
    bob_version: currentBobVersion(null, env),
    observed_bob_versions: observedBobVersions(events),
    enabled: readResult ? readResult.enabled : telemetryEnabled(),
    telemetry_path: readResult ? readResult.telemetry_path : safeTelemetryPath(toolInvocationTelemetryPath()),
    filters,
    total_runs: events.length,
    malformed_lines: readResult ? readResult.malformed_lines : 0,
    totals: {
      runs: events.length,
      by_status: byStatus,
      by_block_code: byBlockCode,
    },
    latest_run: events.length ? slimToolInvocationEvent(events[events.length - 1]) : null,
    recent_blocked_runs: events
      .filter((event) => event.status === "blocked")
      .slice(-recentBlockedLimit)
      .reverse()
      .map(slimToolInvocationEvent),
  };
}

function readToolTelemetry(args = {}, { env = process.env } = {}) {
  const limit = normalizeRecentFailureLimit(args.limit);
  const readResult = readToolTelemetryEvents({
    target_domain: args.target_domain,
    tool: args.tool,
    env,
  });
  const summary = summarizeToolTelemetryEvents(readResult.events, { limit });

  const response = {
    version: TOOL_TELEMETRY_VERSION,
    bob_version: currentBobVersion(null, env),
    enabled: readResult.enabled,
    telemetry_path: readResult.telemetry_path,
    filters: {
      target_domain: publicFilterValue(safeTargetDomainFilter(args.target_domain)),
      tool: publicFilterValue(safeFilterLabel(args.tool, 120)),
      limit,
    },
    total_events: readResult.events.length,
    malformed_lines: readResult.malformed_lines,
    ...summary,
  };

  if (args.include_agent_runs === true) {
    const toolInvocationFilters = {
      target_domain: publicFilterValue(safeTargetDomainFilter(args.target_domain)),
      agent_run_type: publicFilterValue(safeFilterLabel(args.agent_run_type, 80)),
      wave: publicFilterValue(safeFilterLabel(args.wave, 40)),
      agent: publicFilterValue(safeFilterLabel(args.agent, 40)),
      surface_id: publicFilterValue(safeFilterLabel(args.surface_id)),
      limit,
    };
    const toolInvocationReadResult = readToolInvocationTelemetryEvents({
      target_domain: args.target_domain,
      agent_run_type: args.agent_run_type,
      wave: args.wave,
      agent: args.agent,
      surface_id: args.surface_id,
      env,
    });
    response.agent_runs = summarizeToolInvocationTelemetryEvents(toolInvocationReadResult.events, {
      limit,
      readResult: toolInvocationReadResult,
      filters: toolInvocationFilters,
      env,
    });
  }

  return response;
}

function observedBobVersions(events) {
  return Array.from(new Set(
    events
      .map((event) => capString(event.bob_version, 80))
      .map((version) => safeVersionLabel(version))
      .filter(Boolean),
  )).sort();
}

module.exports = {
  TOOL_EVENTS_FILE_NAME,
  TOOL_INVOCATIONS_FILE_NAME,
  TOOL_INVOCATION_TELEMETRY_MAX_RECORDS,
  TOOL_INVOCATION_TELEMETRY_VERSION,
  TOOL_TELEMETRY_MAX_RECORDS,
  TOOL_TELEMETRY_VERSION,
  appendToolInvocationTelemetryEvent,
  appendToolTelemetryEvent,
  buildToolInvocationTelemetryEvent,
  buildToolTelemetryEvent,
  readToolInvocationTelemetryEvents,
  readToolTelemetry,
  readToolTelemetryEvents,
  recordToolInvocationTelemetry,
  safeErrorMessage,
  safeRecordToolInvocationTelemetry,
  safeRecordToolTelemetry,
  summarizeToolInvocationTelemetryEvents,
  summarizeToolTelemetryEvents,
  telemetryDir,
  telemetryEnabled,
  toolInvocationSidecarPath,
  toolInvocationTelemetryPath,
  toolTelemetryPath,
};
