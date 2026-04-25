"use strict";

const fs = require("fs");
const crypto = require("crypto");
const os = require("os");
const path = require("path");
const {
  redactUrlSensitiveValues,
} = require("../redaction.js");

const TOOL_TELEMETRY_VERSION = 1;
const AGENT_RUN_TELEMETRY_VERSION = 1;
const TELEMETRY_DIR_NAME = "bounty-agent-telemetry";
const TOOL_EVENTS_FILE_NAME = "tool-events.jsonl";
const AGENT_RUNS_FILE_NAME = "agent-runs.jsonl";
const ERROR_MESSAGE_MAX_CHARS = 200;
const SAFE_LABEL_MAX_CHARS = 200;
const SAFE_PATH_MAX_CHARS = 1000;
const DEFAULT_RECENT_FAILURE_LIMIT = 10;
const MAX_RECENT_FAILURE_LIMIT = 100;

const SENSITIVE_MESSAGE_RE = /\b(?:authorization|bearer|cookie|set-cookie|password|passwd|secret|api[_-]?key|access[_-]?token|refresh[_-]?token|id[_-]?token)\b/i;
const URL_RE = /\bhttps?:\/\/[^\s"'<>]+/gi;

function telemetryEnabled(env = process.env) {
  return env.BOUNTY_TELEMETRY !== "0";
}

function telemetryDir(env = process.env) {
  const override = typeof env.BOUNTY_TELEMETRY_DIR === "string"
    ? env.BOUNTY_TELEMETRY_DIR.trim()
    : "";
  return override ? path.resolve(override) : path.join(os.homedir(), TELEMETRY_DIR_NAME);
}

function toolTelemetryPath(env = process.env) {
  return path.join(telemetryDir(env), TOOL_EVENTS_FILE_NAME);
}

function agentRunTelemetryPath(env = process.env) {
  return path.join(telemetryDir(env), AGENT_RUNS_FILE_NAME);
}

function agentRunSidecarPath(runId, env = process.env) {
  return path.join(telemetryDir(env), "runs", `${runId}.json`);
}

function capString(value, maxChars = SAFE_LABEL_MAX_CHARS) {
  if (value == null) return null;
  const text = String(value).replace(/[\r\n\t]+/g, " ").trim();
  if (!text) return null;
  return text.length > maxChars ? text.slice(0, maxChars) : text;
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

  const wave = capString(args.wave) ||
    (Number.isInteger(args.wave_number) && args.wave_number > 0 ? `w${args.wave_number}` : null);

  return {
    target_domain: capString(args.target_domain),
    wave,
    agent: capString(args.agent),
    surface_id: capString(args.surface_id),
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
    hook_required: !!tool.hook_required,
  };
}

function redactUrlsInText(text) {
  return text.replace(URL_RE, (url) => redactUrlSensitiveValues(url));
}

function redactSensitiveFragments(text) {
  return text
    .replace(/\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]+/gi, "$1 REDACTED")
    .replace(
      /\b(authorization|cookie|set-cookie|password|passwd|secret|token|session|credential|api[_-]?key|access[_-]?token|refresh[_-]?token|id[_-]?token)\b\s*[:=]\s*("[^"]*"|'[^']*'|[^\s,;)]+)/gi,
      "$1=REDACTED",
    );
}

function safeErrorMessage(message, { errorCode = null, registry = null } = {}) {
  if (message == null) return null;
  if (errorCode === "UNKNOWN_TOOL") return "Unknown tool";
  if (registry && registry.sensitive_output) return null;

  let text = capString(message, ERROR_MESSAGE_MAX_CHARS);
  if (!text) return null;
  text = redactSensitiveFragments(redactUrlsInText(text));

  if (SENSITIVE_MESSAGE_RE.test(text)) {
    return null;
  }
  return capString(text, ERROR_MESSAGE_MAX_CHARS);
}

function buildToolTelemetryEvent({
  toolName,
  tool,
  args,
  envelope,
  elapsedMs,
  now = new Date(),
}) {
  const registry = registryMetadata(tool);
  const errorCode = envelope && envelope.ok === false && envelope.error
    ? capString(envelope.error.code, 80)
    : null;
  const context = extractSafeContext(args);
  const event = {
    version: TOOL_TELEMETRY_VERSION,
    ts: now.toISOString(),
    tool: capString(toolName, 120) || "<unknown>",
    ok: !!(envelope && envelope.ok === true),
    elapsed_ms: Number.isFinite(elapsedMs) ? Math.max(0, Math.round(elapsedMs)) : 0,
    error_code: errorCode,
    target_domain: context.target_domain,
    wave: context.wave,
    agent: context.agent,
    surface_id: context.surface_id,
    registry,
  };

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
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.appendFileSync(filePath, `${JSON.stringify(event)}\n`, "utf8");
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

function normalizeAgentRunHandoff(handoff) {
  const value = handoff && typeof handoff === "object" && !Array.isArray(handoff) ? handoff : {};
  const chainNotesCount = Number.isFinite(value.chain_notes_count)
    ? Math.max(0, Math.trunc(value.chain_notes_count))
    : null;

  return {
    present: value.present == null ? null : value.present === true,
    valid: value.valid == null ? null : value.valid === true,
    provenance: capString(value.provenance, 80),
    surface_status: capString(value.surface_status, 80),
    summary_present: value.summary_present == null ? null : value.summary_present === true,
    chain_notes_count: chainNotesCount,
  };
}

function normalizeAgentRunCoverage(coverage) {
  const value = coverage && typeof coverage === "object" && !Array.isArray(coverage) ? coverage : {};
  const byStatusInput = value.by_status && typeof value.by_status === "object" && !Array.isArray(value.by_status)
    ? value.by_status
    : {};
  const byStatus = {};
  let total = Number.isFinite(value.total) ? Math.max(0, Math.trunc(value.total)) : 0;
  let computedTotal = 0;

  for (const [status, count] of Object.entries(byStatusInput)) {
    const safeStatus = capString(status, 80);
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

function normalizeAgentRunFindings(findings) {
  const value = findings && typeof findings === "object" && !Array.isArray(findings) ? findings : {};
  return {
    count: Number.isFinite(value.count) ? Math.max(0, Math.trunc(value.count)) : 0,
  };
}

function buildAgentRunTelemetryEvent({
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
  telemetry_source: telemetrySource = "hunter-subagent-stop",
  now = new Date(),
}) {
  const normalizedRunType = runType || runTypeSnake || "hunter";
  const normalizedBlockCode = blockCode == null ? blockCodeSnake : blockCode;
  const event = {
    version: AGENT_RUN_TELEMETRY_VERSION,
    ts: now.toISOString(),
    run_id: null,
    run_type: capString(normalizedRunType, 80) || "hunter",
    status: status === "allowed" ? "allowed" : "blocked",
    block_code: status === "allowed" ? null : capString(normalizedBlockCode, 120),
    target_domain: capString(targetDomain),
    wave: capString(wave, 40),
    agent: capString(agent, 40),
    surface_id: capString(surfaceId),
    transcript_path: capString(transcriptPath, SAFE_PATH_MAX_CHARS),
    handoff: normalizeAgentRunHandoff(handoff),
    coverage: normalizeAgentRunCoverage(coverage),
    findings: normalizeAgentRunFindings(findings),
    telemetry_source: capString(telemetrySource, 120) || "hunter-subagent-stop",
  };
  event.run_id = buildRunId(event);
  return event;
}

function appendAgentRunTelemetryEvent(event, { env = process.env } = {}) {
  if (!telemetryEnabled(env)) return false;
  const filePath = agentRunTelemetryPath(env);
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.appendFileSync(filePath, `${JSON.stringify(event)}\n`, "utf8");

  const sidecarPath = agentRunSidecarPath(event.run_id, env);
  fs.mkdirSync(path.dirname(sidecarPath), { recursive: true });
  fs.writeFileSync(sidecarPath, `${JSON.stringify(event, null, 2)}\n`, "utf8");
  return true;
}

function recordAgentRunTelemetry(input, options = {}) {
  const event = buildAgentRunTelemetryEvent(input);
  appendAgentRunTelemetryEvent(event, options);
  return event;
}

function safeRecordAgentRunTelemetry(input, options = {}) {
  try {
    return recordAgentRunTelemetry(input, options);
  } catch {
    return null;
  }
}

function normalizeRecentFailureLimit(limit) {
  if (limit == null) return DEFAULT_RECENT_FAILURE_LIMIT;
  if (!Number.isFinite(limit)) return DEFAULT_RECENT_FAILURE_LIMIT;
  return Math.max(1, Math.min(MAX_RECENT_FAILURE_LIMIT, Math.trunc(limit)));
}

function isPlainEvent(event) {
  return event && typeof event === "object" && !Array.isArray(event) && event.version === TOOL_TELEMETRY_VERSION;
}

function normalizeEventForSummary(event) {
  return {
    ts: capString(event.ts, 40),
    tool: capString(event.tool, 120) || "<unknown>",
    ok: event.ok === true,
    elapsed_ms: Number.isFinite(event.elapsed_ms) ? Math.max(0, Math.round(event.elapsed_ms)) : 0,
    error_code: capString(event.error_code, 80),
    error_message: capString(event.error_message, ERROR_MESSAGE_MAX_CHARS),
    target_domain: capString(event.target_domain),
    wave: capString(event.wave),
    agent: capString(event.agent),
    surface_id: capString(event.surface_id),
  };
}

function eventMatchesFilters(event, filters) {
  if (filters.tool && event.tool !== filters.tool) return false;
  if (filters.target_domain && event.target_domain !== filters.target_domain) return false;
  return true;
}

function isPlainAgentRunEvent(event) {
  return (
    event &&
    typeof event === "object" &&
    !Array.isArray(event) &&
    event.version === AGENT_RUN_TELEMETRY_VERSION &&
    typeof event.run_id === "string" &&
    typeof event.run_type === "string" &&
    (event.status === "allowed" || event.status === "blocked")
  );
}

function normalizeAgentRunEventForSummary(event) {
  return {
    ts: capString(event.ts, 40),
    run_id: capString(event.run_id, 80),
    run_type: capString(event.run_type, 80) || "hunter",
    status: event.status === "allowed" ? "allowed" : "blocked",
    block_code: capString(event.block_code, 120),
    target_domain: capString(event.target_domain),
    wave: capString(event.wave, 40),
    agent: capString(event.agent, 40),
    surface_id: capString(event.surface_id),
    transcript_path: capString(event.transcript_path, SAFE_PATH_MAX_CHARS),
    handoff: normalizeAgentRunHandoff(event.handoff),
    coverage: normalizeAgentRunCoverage(event.coverage),
    findings: normalizeAgentRunFindings(event.findings),
    telemetry_source: capString(event.telemetry_source, 120),
  };
}

function agentRunMatchesFilters(event, filters) {
  if (filters.target_domain && event.target_domain !== filters.target_domain) return false;
  if (filters.agent_run_type && event.run_type !== filters.agent_run_type) return false;
  if (filters.wave && event.wave !== filters.wave) return false;
  if (filters.agent && event.agent !== filters.agent) return false;
  if (filters.surface_id && event.surface_id !== filters.surface_id) return false;
  return true;
}

function readToolTelemetryEvents({ target_domain: targetDomain, tool, env = process.env } = {}) {
  const filePath = toolTelemetryPath(env);
  const filters = {
    target_domain: capString(targetDomain),
    tool: capString(tool, 120),
  };
  const result = {
    enabled: telemetryEnabled(env),
    telemetry_path: filePath,
    events: [],
    malformed_lines: 0,
  };

  if (!result.enabled || !fs.existsSync(filePath)) {
    return result;
  }

  const lines = fs.readFileSync(filePath, "utf8").split(/\r?\n/);
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

function readAgentRunTelemetryEvents({
  target_domain: targetDomain,
  agent_run_type: agentRunType,
  wave,
  agent,
  surface_id: surfaceId,
  env = process.env,
} = {}) {
  const filePath = agentRunTelemetryPath(env);
  const filters = {
    target_domain: capString(targetDomain),
    agent_run_type: capString(agentRunType, 80),
    wave: capString(wave, 40),
    agent: capString(agent, 40),
    surface_id: capString(surfaceId),
  };
  const result = {
    enabled: telemetryEnabled(env),
    telemetry_path: filePath,
    events: [],
    malformed_lines: 0,
  };

  if (!result.enabled || !fs.existsSync(filePath)) {
    return result;
  }

  const lines = fs.readFileSync(filePath, "utf8").split(/\r?\n/);
  for (const line of lines) {
    if (!line.trim()) continue;
    let parsed;
    try {
      parsed = JSON.parse(line);
    } catch {
      result.malformed_lines += 1;
      continue;
    }
    if (!isPlainAgentRunEvent(parsed)) {
      result.malformed_lines += 1;
      continue;
    }
    const normalized = normalizeAgentRunEventForSummary(parsed);
    if (agentRunMatchesFilters(normalized, filters)) {
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
    tool: event.tool,
    ok: event.ok,
    elapsed_ms: event.elapsed_ms,
    error_code: event.error_code,
    target_domain: event.target_domain,
    wave: event.wave,
    agent: event.agent,
    surface_id: event.surface_id,
  };
  if (event.error_message) {
    result.error_message = event.error_message;
  }
  return result;
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
    totals: summarizeEventGroup("all", events, recentFailureLimit),
    tools,
    recent_failures: events.filter((event) => !event.ok).slice(-recentFailureLimit).reverse().map(slimEvent),
  };
}

function slimAgentRunEvent(event) {
  return {
    ts: event.ts,
    run_id: event.run_id,
    run_type: event.run_type,
    status: event.status,
    block_code: event.block_code,
    target_domain: event.target_domain,
    wave: event.wave,
    agent: event.agent,
    surface_id: event.surface_id,
    transcript_path: event.transcript_path,
    handoff: event.handoff,
    coverage: event.coverage,
    findings: event.findings,
    telemetry_source: event.telemetry_source,
  };
}

function summarizeAgentRunTelemetryEvents(events, {
  limit = DEFAULT_RECENT_FAILURE_LIMIT,
  readResult = null,
  filters = {},
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
    version: AGENT_RUN_TELEMETRY_VERSION,
    enabled: readResult ? readResult.enabled : telemetryEnabled(),
    telemetry_path: readResult ? readResult.telemetry_path : agentRunTelemetryPath(),
    filters,
    total_runs: events.length,
    malformed_lines: readResult ? readResult.malformed_lines : 0,
    totals: {
      runs: events.length,
      by_status: byStatus,
      by_block_code: byBlockCode,
    },
    latest_run: events.length ? slimAgentRunEvent(events[events.length - 1]) : null,
    recent_blocked_runs: events
      .filter((event) => event.status === "blocked")
      .slice(-recentBlockedLimit)
      .reverse()
      .map(slimAgentRunEvent),
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
    enabled: readResult.enabled,
    telemetry_path: readResult.telemetry_path,
    filters: {
      target_domain: capString(args.target_domain),
      tool: capString(args.tool, 120),
      limit,
    },
    total_events: readResult.events.length,
    malformed_lines: readResult.malformed_lines,
    ...summary,
  };

  if (args.include_agent_runs === true) {
    const agentRunFilters = {
      target_domain: capString(args.target_domain),
      agent_run_type: capString(args.agent_run_type, 80),
      wave: capString(args.wave, 40),
      agent: capString(args.agent, 40),
      surface_id: capString(args.surface_id),
      limit,
    };
    const agentRunReadResult = readAgentRunTelemetryEvents({
      target_domain: args.target_domain,
      agent_run_type: args.agent_run_type,
      wave: args.wave,
      agent: args.agent,
      surface_id: args.surface_id,
      env,
    });
    response.agent_runs = summarizeAgentRunTelemetryEvents(agentRunReadResult.events, {
      limit,
      readResult: agentRunReadResult,
      filters: agentRunFilters,
    });
  }

  return response;
}

module.exports = {
  AGENT_RUNS_FILE_NAME,
  AGENT_RUN_TELEMETRY_VERSION,
  TOOL_EVENTS_FILE_NAME,
  TOOL_TELEMETRY_VERSION,
  agentRunSidecarPath,
  agentRunTelemetryPath,
  appendAgentRunTelemetryEvent,
  appendToolTelemetryEvent,
  buildAgentRunTelemetryEvent,
  buildToolTelemetryEvent,
  recordAgentRunTelemetry,
  readAgentRunTelemetryEvents,
  readToolTelemetry,
  readToolTelemetryEvents,
  safeRecordAgentRunTelemetry,
  safeErrorMessage,
  safeRecordToolTelemetry,
  summarizeAgentRunTelemetryEvents,
  summarizeToolTelemetryEvents,
  telemetryDir,
  telemetryEnabled,
  toolTelemetryPath,
};
