"use strict";

const fs = require("fs");
const path = require("path");
const {
  COVERAGE_STATUS_VALUES,
  GRADE_VERDICT_VALUES,
  PHASE_VALUES,
  SEVERITY_VALUES,
  VERIFICATION_ROUND_VALUES,
} = require("./constants.js");
const {
  assertNonEmptyString,
  parseAgentId,
  parseWaveId,
} = require("./validation.js");
const {
  attackSurfacePath,
  coverageJsonlPath,
  findingsJsonlPath,
  gradeArtifactPaths,
  pipelineEventsJsonlPath,
  reportMarkdownPath,
  sessionDir,
  sessionsRoot,
  statePath,
  verificationRoundPaths,
} = require("./paths.js");
const {
  appendJsonlLine,
  readJsonFile,
  withSessionLock,
} = require("./storage.js");
const {
  loadWaveAssignments,
} = require("./assignments.js");
const {
  readAgentRunTelemetryEvents,
  readToolTelemetryEvents,
  summarizeToolTelemetryEvents,
} = require("./tool-telemetry.js");

const PIPELINE_ANALYTICS_VERSION = 1;
const PIPELINE_EVENT_VERSION = 1;
const DEFAULT_WINDOW_DAYS = 30;
const MAX_WINDOW_DAYS = 365;
const DEFAULT_LIMIT = 20;
const MAX_LIMIT = 100;
const STALE_PENDING_WAVE_MS = 2 * 60 * 60 * 1000;
const HIGH_TOOL_FAILURE_RATE = 0.2;
const HIGH_TOOL_FAILURE_MIN_FAILURES = 3;

const PIPELINE_EVENT_TYPES = Object.freeze([
  "session_started",
  "phase_transitioned",
  "wave_started",
  "hunter_stopped",
  "wave_merge_pending",
  "wave_merged",
  "coverage_logged",
  "finding_recorded",
  "verification_written",
  "grade_written",
]);

function pipelineAnalyticsEnabled(env = process.env) {
  return env.BOUNTY_PIPELINE_ANALYTICS !== "0";
}

function isPlainObject(value) {
  return value != null && typeof value === "object" && !Array.isArray(value);
}

function capString(value, maxChars = 200) {
  if (value == null) return null;
  const text = String(value).replace(/[\r\n\t]+/g, " ").trim();
  if (!text) return null;
  return text.length > maxChars ? text.slice(0, maxChars) : text;
}

function normalizeIsoTimestamp(value, fallback = new Date()) {
  if (value instanceof Date && Number.isFinite(value.getTime())) {
    return value.toISOString();
  }
  const text = capString(value, 80);
  if (text) {
    const parsedMs = Date.parse(text);
    if (Number.isFinite(parsedMs)) return new Date(parsedMs).toISOString();
  }
  return fallback.toISOString();
}

function timestampMs(value) {
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) ? parsed : 0;
}

function fileMtimeIso(filePath) {
  try {
    return new Date(fs.statSync(filePath).mtimeMs).toISOString();
  } catch {
    return null;
  }
}

function updateLatestIso(current, candidate) {
  if (!candidate) return current;
  if (!current) return candidate;
  return timestampMs(candidate) > timestampMs(current) ? candidate : current;
}

function normalizePositiveInteger(value, defaultValue, maxValue) {
  if (!Number.isFinite(value)) return defaultValue;
  return Math.max(1, Math.min(maxValue, Math.trunc(value)));
}

function normalizeCounts(counts) {
  if (!isPlainObject(counts)) return null;
  const normalized = {};
  for (const [key, value] of Object.entries(counts)) {
    const safeKey = capString(key, 80);
    if (!safeKey) continue;
    if (Number.isFinite(value)) {
      normalized[safeKey] = Math.max(0, Math.trunc(value));
    } else if (value === true || value === false) {
      normalized[safeKey] = value ? 1 : 0;
    }
  }
  return Object.keys(normalized).length ? normalized : null;
}

function normalizeWaveNumber(value) {
  if (Number.isInteger(value) && value > 0) return value;
  if (typeof value === "string") {
    const match = value.match(/^w([1-9][0-9]*)$/);
    if (match) return Number(match[1]);
  }
  return null;
}

function normalizePipelineEvent(targetDomain, type, fields = {}) {
  const domain = assertNonEmptyString(targetDomain || fields.target_domain, "target_domain");
  const eventType = capString(type || fields.type, 80);
  if (!PIPELINE_EVENT_TYPES.includes(eventType)) {
    throw new Error(`unknown pipeline event type: ${eventType || "<empty>"}`);
  }

  const event = {
    version: PIPELINE_EVENT_VERSION,
    ts: normalizeIsoTimestamp(fields.ts || fields.now),
    target_domain: domain,
    type: eventType,
  };

  const phase = capString(fields.phase, 40);
  const fromPhase = capString(fields.from_phase, 40);
  const toPhase = capString(fields.to_phase, 40);
  if (phase) event.phase = phase;
  if (fromPhase) event.from_phase = fromPhase;
  if (toPhase) event.to_phase = toPhase;

  const waveNumber = normalizeWaveNumber(fields.wave_number == null ? fields.wave : fields.wave_number);
  if (waveNumber != null) event.wave_number = waveNumber;

  const agent = capString(fields.agent, 40);
  const surfaceId = capString(fields.surface_id, 200);
  const status = capString(fields.status, 120);
  const blockCode = capString(fields.block_code, 120);
  const source = capString(fields.source, 120);
  const counts = normalizeCounts(fields.counts);
  if (agent) event.agent = agent;
  if (surfaceId) event.surface_id = surfaceId;
  if (status) event.status = status;
  if (blockCode) event.block_code = blockCode;
  if (counts) event.counts = counts;
  if (source) event.source = source;
  if (typeof fields.force_merge === "boolean") event.force_merge = fields.force_merge;
  if (typeof fields.override === "boolean") event.override = fields.override;
  const overrideReason = capString(fields.override_reason, 1000);
  if (overrideReason) event.override_reason = overrideReason;

  return event;
}

function appendPipelineEventDirect(targetDomain, type, fields = {}, { env = process.env } = {}) {
  if (!pipelineAnalyticsEnabled(env)) return null;
  const event = normalizePipelineEvent(targetDomain, type, fields);
  appendJsonlLine(pipelineEventsJsonlPath(event.target_domain), event);
  return event;
}

function safeAppendPipelineEventDirect(targetDomain, type, fields = {}, options = {}) {
  try {
    return appendPipelineEventDirect(targetDomain, type, fields, options);
  } catch {
    return null;
  }
}

function safeAppendPipelineEventWithSessionLock(targetDomain, type, fields = {}, options = {}) {
  if (!pipelineAnalyticsEnabled(options.env || process.env)) return null;
  try {
    return withSessionLock(targetDomain, () => appendPipelineEventDirect(targetDomain, type, fields, options));
  } catch {
    return null;
  }
}

function safeRecordHunterStoppedPipelineEvent(input, options = {}) {
  if (!input || !input.target_domain) return null;
  return safeAppendPipelineEventWithSessionLock(input.target_domain, "hunter_stopped", {
    wave: input.wave,
    agent: input.agent,
    surface_id: input.surface_id,
    status: input.status,
    block_code: input.block_code == null ? input.blockCode : input.block_code,
    source: input.source || input.telemetry_source || "hunter-subagent-stop",
    now: input.now,
    counts: {
      coverage: input.coverage && Number.isFinite(input.coverage.total) ? input.coverage.total : 0,
      findings: input.findings && Number.isFinite(input.findings.count) ? input.findings.count : 0,
      handoff_present: input.handoff && input.handoff.present === true ? 1 : 0,
      handoff_valid: input.handoff && input.handoff.valid === true ? 1 : 0,
    },
  }, options);
}

function readJsonSafe(filePath, label) {
  const result = {
    exists: fs.existsSync(filePath),
    path: filePath,
    document: null,
    error: null,
    mtime: fileMtimeIso(filePath),
  };
  if (!result.exists) return result;
  try {
    result.document = readJsonFile(filePath);
  } catch (error) {
    result.error = `Malformed ${label}: ${error.message || String(error)}`;
  }
  return result;
}

function readJsonlSafe(filePath, label) {
  const result = {
    exists: fs.existsSync(filePath),
    path: filePath,
    records: [],
    malformed_lines: 0,
    error: null,
    mtime: fileMtimeIso(filePath),
  };
  if (!result.exists) return result;
  let content;
  try {
    content = fs.readFileSync(filePath, "utf8");
  } catch (error) {
    result.error = `Unreadable ${label}: ${error.message || String(error)}`;
    return result;
  }
  const lines = content.split(/\r?\n/);
  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index];
    if (!line.trim()) continue;
    try {
      const parsed = JSON.parse(line);
      if (!isPlainObject(parsed)) {
        result.malformed_lines += 1;
        continue;
      }
      result.records.push(parsed);
    } catch {
      result.malformed_lines += 1;
    }
  }
  return result;
}

function normalizePipelineEventForRead(record, expectedDomain) {
  if (!isPlainObject(record) || record.version !== PIPELINE_EVENT_VERSION) return null;
  const type = capString(record.type, 80);
  const targetDomain = capString(record.target_domain);
  if (!PIPELINE_EVENT_TYPES.includes(type) || !targetDomain) return null;
  if (expectedDomain && targetDomain !== expectedDomain) return null;
  const event = {
    version: PIPELINE_EVENT_VERSION,
    ts: normalizeIsoTimestamp(record.ts),
    target_domain: targetDomain,
    type,
  };
  for (const field of ["phase", "from_phase", "to_phase", "agent", "surface_id", "status", "block_code", "source"]) {
    const safe = capString(record[field], field === "surface_id" ? 200 : 120);
    if (safe) event[field] = safe;
  }
  const waveNumber = normalizeWaveNumber(record.wave_number);
  if (waveNumber != null) event.wave_number = waveNumber;
  const counts = normalizeCounts(record.counts);
  if (counts) event.counts = counts;
  if (typeof record.force_merge === "boolean") event.force_merge = record.force_merge;
  if (typeof record.override === "boolean") event.override = record.override;
  const overrideReason = capString(record.override_reason, 1000);
  if (overrideReason) event.override_reason = overrideReason;
  return event;
}

function listWaveAssignmentNumbers(targetDomain) {
  const dir = sessionDir(targetDomain);
  if (!fs.existsSync(dir)) return [];
  return fs.readdirSync(dir)
    .map((fileName) => {
      const match = fileName.match(/^wave-([1-9][0-9]*)-assignments\.json$/);
      return match ? Number(match[1]) : null;
    })
    .filter((waveNumber) => Number.isInteger(waveNumber))
    .sort((a, b) => a - b);
}

function listHandoffFiles(dir, waveId) {
  if (!fs.existsSync(dir)) return [];
  return fs.readdirSync(dir)
    .filter((fileName) => fileName.startsWith(`handoff-${waveId}-`) && fileName.endsWith(".json"))
    .sort();
}

function validateHandoffMetadata(document, { targetDomain, wave, agent, surfaceId, requiresToken }) {
  if (!isPlainObject(document)) throw new Error("handoff payload must be an object");
  if (document.target_domain != null && document.target_domain !== targetDomain) throw new Error("target_domain mismatch");
  if (parseWaveId(document.wave) !== wave) throw new Error("wave mismatch");
  if (parseAgentId(document.agent) !== agent) throw new Error("agent mismatch");
  if (assertNonEmptyString(document.surface_id, "surface_id") !== surfaceId) throw new Error("surface_id mismatch");
  if (!["complete", "partial"].includes(capString(document.surface_status, 40))) {
    throw new Error("invalid surface_status");
  }
  if (requiresToken && document.provenance !== "verified") {
    throw new Error("handoff provenance is not verified");
  }
}

function readWaveReadiness(targetDomain, waveNumber) {
  const wave = `w${waveNumber}`;
  const result = {
    wave_number: waveNumber,
    assignments_total: 0,
    handoffs_total: 0,
    received_agents: [],
    missing_agents: [],
    invalid_agents: [],
    unexpected_agents: [],
    is_complete: false,
    error: null,
  };

  let artifacts;
  try {
    artifacts = loadWaveAssignments(targetDomain, waveNumber);
  } catch (error) {
    result.error = error.message || String(error);
    return result;
  }

  result.assignments_total = artifacts.assignments.length;
  const handoffFiles = listHandoffFiles(artifacts.dir, wave);
  result.handoffs_total = handoffFiles.length;
  const handoffPathByAgent = new Map();
  for (const fileName of handoffFiles) {
    const agent = fileName.slice(`handoff-${wave}-`.length, -".json".length);
    if (!artifacts.assignmentByAgent.has(agent)) {
      result.unexpected_agents.push(agent);
    } else {
      handoffPathByAgent.set(agent, path.join(artifacts.dir, fileName));
    }
  }

  for (const assignment of artifacts.assignments) {
    const handoffPath = handoffPathByAgent.get(assignment.agent);
    if (!handoffPath) {
      result.missing_agents.push(assignment.agent);
      continue;
    }
    try {
      validateHandoffMetadata(readJsonFile(handoffPath), {
        targetDomain,
        wave,
        agent: assignment.agent,
        surfaceId: assignment.surface_id,
        requiresToken: !!assignment.handoff_token_sha256,
      });
      result.received_agents.push(assignment.agent);
    } catch {
      result.invalid_agents.push(assignment.agent);
    }
  }

  result.is_complete = result.missing_agents.length === 0 && result.invalid_agents.length === 0;
  return result;
}

function summarizeFindingsJsonl(targetDomain) {
  const read = readJsonlSafe(findingsJsonlPath(targetDomain), "findings.jsonl");
  const bySeverity = SEVERITY_VALUES.reduce((result, severity) => {
    result[severity] = 0;
    return result;
  }, {});
  for (const record of read.records) {
    const severity = capString(record.severity, 40);
    if (Object.prototype.hasOwnProperty.call(bySeverity, severity)) {
      bySeverity[severity] += 1;
    }
  }
  return {
    exists: read.exists,
    total: read.records.length,
    by_severity: bySeverity,
    malformed_lines: read.malformed_lines,
    error: read.error,
    mtime: read.mtime,
  };
}

function summarizeCoverageJsonl(targetDomain) {
  const read = readJsonlSafe(coverageJsonlPath(targetDomain), "coverage.jsonl");
  const byStatus = COVERAGE_STATUS_VALUES.reduce((result, status) => {
    result[status] = 0;
    return result;
  }, {});
  const surfaces = new Set();
  for (const record of read.records) {
    const status = capString(record.status, 40);
    if (Object.prototype.hasOwnProperty.call(byStatus, status)) {
      byStatus[status] += 1;
    }
    if (typeof record.surface_id === "string" && record.surface_id.trim()) {
      surfaces.add(record.surface_id.trim());
    }
  }
  return {
    exists: read.exists,
    total_records: read.records.length,
    surface_count: surfaces.size,
    by_status: byStatus,
    malformed_lines: read.malformed_lines,
    error: read.error,
    mtime: read.mtime,
  };
}

function summarizeVerificationArtifacts(targetDomain) {
  const rounds = {};
  let latestMtime = null;
  const errors = [];
  for (const round of VERIFICATION_ROUND_VALUES) {
    const paths = verificationRoundPaths(targetDomain, round);
    const read = readJsonSafe(paths.json, `${round} verification round JSON`);
    latestMtime = updateLatestIso(latestMtime, read.mtime);
    const summary = {
      exists: read.exists,
      valid: false,
      results_count: 0,
      reportable_count: 0,
      confirmed_count: 0,
      mtime: read.mtime,
      error: read.error,
    };
    if (read.error) errors.push(read.error);
    if (isPlainObject(read.document) && Array.isArray(read.document.results)) {
      summary.valid = read.document.target_domain === targetDomain && read.document.round === round;
      summary.results_count = read.document.results.length;
      summary.reportable_count = read.document.results.filter((result) => result && result.reportable === true).length;
      summary.confirmed_count = read.document.results.filter((result) => result && result.disposition === "confirmed").length;
      if (!summary.valid) {
        summary.error = `${round} verification artifact metadata mismatch`;
        errors.push(summary.error);
      }
    }
    rounds[round] = summary;
  }
  return {
    rounds,
    final_results_count: rounds.final.results_count,
    final_reportable_count: rounds.final.reportable_count,
    errors,
    latest_mtime: latestMtime,
  };
}

function summarizeGradeArtifact(targetDomain) {
  const paths = gradeArtifactPaths(targetDomain);
  const read = readJsonSafe(paths.json, "grade verdict JSON");
  const summary = {
    exists: read.exists,
    valid: false,
    verdict: null,
    total_score: null,
    findings_count: 0,
    error: read.error,
    mtime: read.mtime,
  };
  if (isPlainObject(read.document)) {
    const verdict = capString(read.document.verdict, 40);
    summary.valid = read.document.target_domain === targetDomain && GRADE_VERDICT_VALUES.includes(verdict);
    summary.verdict = verdict;
    summary.total_score = Number.isFinite(read.document.total_score) ? Math.trunc(read.document.total_score) : null;
    summary.findings_count = Array.isArray(read.document.findings) ? read.document.findings.length : 0;
    if (!summary.valid) {
      summary.error = "grade artifact metadata mismatch";
    }
  }
  return summary;
}

function summarizeAttackSurfaceCoverage(targetDomain, state) {
  const read = readJsonSafe(attackSurfacePath(targetDomain), "attack_surface.json");
  if (!isPlainObject(read.document) || !Array.isArray(read.document.surfaces)) {
    return {
      exists: read.exists,
      error: read.error,
      total_surfaces: 0,
      non_low_total: 0,
      non_low_explored: 0,
      coverage_pct: null,
      unexplored_high: 0,
      mtime: read.mtime,
    };
  }
  const exploredSet = new Set(Array.isArray(state?.explored) ? state.explored : []);
  const surfaces = read.document.surfaces.filter((surface) => isPlainObject(surface) && typeof surface.id === "string");
  const nonLowSurfaces = surfaces.filter((surface) => (surface.priority || "HIGH").toUpperCase() !== "LOW");
  const highSurfaces = surfaces.filter((surface) => ["CRITICAL", "HIGH"].includes((surface.priority || "HIGH").toUpperCase()));
  const exploredNonLow = nonLowSurfaces.filter((surface) => exploredSet.has(surface.id)).length;
  return {
    exists: true,
    error: null,
    total_surfaces: surfaces.length,
    non_low_total: nonLowSurfaces.length,
    non_low_explored: exploredNonLow,
    coverage_pct: nonLowSurfaces.length ? Math.round((exploredNonLow / nonLowSurfaces.length) * 100) : 100,
    unexplored_high: highSurfaces.filter((surface) => !exploredSet.has(surface.id)).length,
    mtime: read.mtime,
  };
}

function readSessionArtifactSummary(targetDomain) {
  const dir = sessionDir(targetDomain);
  const stateRead = readJsonSafe(statePath(targetDomain), "session state");
  const state = isPlainObject(stateRead.document) ? stateRead.document : null;
  const waveNumbers = listWaveAssignmentNumbers(targetDomain);
  if (state && Number.isInteger(state.pending_wave) && state.pending_wave > 0 && !waveNumbers.includes(state.pending_wave)) {
    waveNumbers.push(state.pending_wave);
    waveNumbers.sort((a, b) => a - b);
  }

  const waves = waveNumbers.map((waveNumber) => readWaveReadiness(targetDomain, waveNumber));
  const findings = summarizeFindingsJsonl(targetDomain);
  const coverage = summarizeCoverageJsonl(targetDomain);
  const attackSurfaceCoverage = summarizeAttackSurfaceCoverage(targetDomain, state);
  const verification = summarizeVerificationArtifacts(targetDomain);
  const grade = summarizeGradeArtifact(targetDomain);
  const reportPath = reportMarkdownPath(targetDomain);
  const reportMtime = fileMtimeIso(reportPath);

  let latestMtime = null;
  for (const value of [
    stateRead.mtime,
    findings.mtime,
    coverage.mtime,
    attackSurfaceCoverage.mtime,
    verification.latest_mtime,
    grade.mtime,
    reportMtime,
  ]) {
    latestMtime = updateLatestIso(latestMtime, value);
  }

  const artifactErrors = [];
  if (!stateRead.exists) artifactErrors.push("Missing session state");
  if (stateRead.error) artifactErrors.push(stateRead.error);
  if (findings.error) artifactErrors.push(findings.error);
  if (coverage.error) artifactErrors.push(coverage.error);
  if (findings.malformed_lines > 0) artifactErrors.push(`Malformed findings.jsonl lines: ${findings.malformed_lines}`);
  if (coverage.malformed_lines > 0) artifactErrors.push(`Malformed coverage.jsonl lines: ${coverage.malformed_lines}`);
  for (const wave of waves) {
    if (wave.error) artifactErrors.push(`Wave ${wave.wave_number}: ${wave.error}`);
  }
  artifactErrors.push(...verification.errors);
  if (grade.error) artifactErrors.push(grade.error);

  return {
    target_domain: targetDomain,
    session_dir: dir,
    state: {
      exists: stateRead.exists,
      phase: capString(state?.phase, 40),
      auth_status: capString(state?.auth_status, 40),
      hunt_wave: Number.isInteger(state?.hunt_wave) ? state.hunt_wave : 0,
      pending_wave: Number.isInteger(state?.pending_wave) ? state.pending_wave : null,
      total_findings: Number.isInteger(state?.total_findings) ? state.total_findings : findings.total,
      hold_count: Number.isInteger(state?.hold_count) ? state.hold_count : 0,
      mtime: stateRead.mtime,
      error: stateRead.error,
    },
    waves,
    findings,
    coverage,
    attack_surface_coverage: attackSurfaceCoverage,
    verification,
    grade,
    report: {
      present: fs.existsSync(reportPath),
      path: reportPath,
      mtime: reportMtime,
    },
    artifact_errors: artifactErrors,
    latest_artifact_ts: latestMtime,
  };
}

function buildBackfillEvents(targetDomain, artifacts) {
  const source = "artifact_backfill";
  const ts = artifacts.latest_artifact_ts || new Date().toISOString();
  const events = [];
  events.push(normalizePipelineEvent(targetDomain, "session_started", {
    ts: artifacts.state.mtime || ts,
    phase: "RECON",
    source,
  }));
  if (artifacts.state.phase && artifacts.state.phase !== "RECON") {
    events.push(normalizePipelineEvent(targetDomain, "phase_transitioned", {
      ts: artifacts.state.mtime || ts,
      to_phase: artifacts.state.phase,
      status: "current",
      source,
    }));
  }
  for (const wave of artifacts.waves) {
    events.push(normalizePipelineEvent(targetDomain, "wave_started", {
      ts,
      wave_number: wave.wave_number,
      status: wave.error ? "invalid" : "started",
      counts: { assignments: wave.assignments_total },
      source,
    }));
    if (artifacts.state.pending_wave === wave.wave_number) {
      events.push(normalizePipelineEvent(targetDomain, "wave_merge_pending", {
        ts,
        wave_number: wave.wave_number,
        status: "pending",
        counts: {
          assignments: wave.assignments_total,
          handoffs: wave.handoffs_total,
          missing_handoffs: wave.missing_agents.length,
          invalid_handoffs: wave.invalid_agents.length,
        },
        source,
      }));
    } else if (artifacts.state.hunt_wave >= wave.wave_number) {
      events.push(normalizePipelineEvent(targetDomain, "wave_merged", {
        ts,
        wave_number: wave.wave_number,
        status: "merged",
        counts: {
          assignments: wave.assignments_total,
          handoffs: wave.handoffs_total,
          invalid_handoffs: wave.invalid_agents.length,
        },
        source,
      }));
    }
  }
  if (artifacts.coverage.total_records > 0) {
    events.push(normalizePipelineEvent(targetDomain, "coverage_logged", {
      ts: artifacts.coverage.mtime || ts,
      status: "backfilled",
      counts: { records: artifacts.coverage.total_records, surfaces: artifacts.coverage.surface_count },
      source,
    }));
  }
  if (artifacts.findings.total > 0) {
    events.push(normalizePipelineEvent(targetDomain, "finding_recorded", {
      ts: artifacts.findings.mtime || ts,
      status: "backfilled",
      counts: { findings: artifacts.findings.total },
      source,
    }));
  }
  for (const round of VERIFICATION_ROUND_VALUES) {
    const summary = artifacts.verification.rounds[round];
    if (!summary.exists) continue;
    events.push(normalizePipelineEvent(targetDomain, "verification_written", {
      ts: summary.mtime || ts,
      status: round,
      counts: { results: summary.results_count, reportable: summary.reportable_count },
      source,
    }));
  }
  if (artifacts.grade.exists) {
    events.push(normalizePipelineEvent(targetDomain, "grade_written", {
      ts: artifacts.grade.mtime || ts,
      status: artifacts.grade.verdict || "unknown",
      counts: { findings: artifacts.grade.findings_count, total_score: artifacts.grade.total_score || 0 },
      source,
    }));
  }
  return events.sort((a, b) => timestampMs(a.ts) - timestampMs(b.ts));
}

function readPipelineEvents(targetDomain, { allowBackfill = true } = {}) {
  const filePath = pipelineEventsJsonlPath(targetDomain);
  const result = {
    enabled: pipelineAnalyticsEnabled(),
    events_path: filePath,
    exists: fs.existsSync(filePath),
    events: [],
    malformed_lines: 0,
    backfilled: false,
  };

  if (result.exists) {
    const read = readJsonlSafe(filePath, "pipeline-events.jsonl");
    result.malformed_lines = read.malformed_lines;
    for (const record of read.records) {
      const event = normalizePipelineEventForRead(record, targetDomain);
      if (event) {
        result.events.push(event);
      } else {
        result.malformed_lines += 1;
      }
    }
  }

  if (allowBackfill && result.events.length === 0) {
    result.events = buildBackfillEvents(targetDomain, readSessionArtifactSummary(targetDomain));
    result.backfilled = true;
  }

  result.events.sort((a, b) => timestampMs(a.ts) - timestampMs(b.ts));
  return result;
}

function latestEvent(events) {
  return events.length ? events[events.length - 1] : null;
}

function compactEvent(event) {
  if (!event) return null;
  const compact = {
    ts: event.ts,
    target_domain: event.target_domain,
    type: event.type,
  };
  for (const field of ["phase", "from_phase", "to_phase", "wave_number", "agent", "surface_id", "status", "block_code", "counts", "source", "force_merge", "override", "override_reason"]) {
    if (event[field] != null) compact[field] = event[field];
  }
  return compact;
}

function filterByWindow(events, cutoffMs) {
  if (!cutoffMs) return events;
  return events.filter((event) => timestampMs(event.ts) >= cutoffMs);
}

function slimToolHealth(readResult, events, limit) {
  const summary = summarizeToolTelemetryEvents(events, { limit });
  const topFailureTools = summary.tools
    .filter((tool) => tool.failures > 0)
    .sort((a, b) => b.failures - a.failures || b.calls - a.calls || a.tool.localeCompare(b.tool))
    .slice(0, limit)
    .map((tool) => ({
      tool: tool.tool,
      calls: tool.calls,
      failures: tool.failures,
      success_rate: tool.success_rate,
      error_codes: tool.error_codes,
    }));
  return {
    enabled: readResult.enabled,
    telemetry_path: readResult.telemetry_path,
    total_events: events.length,
    malformed_lines: readResult.malformed_lines,
    totals: {
      calls: summary.totals.calls,
      successes: summary.totals.successes,
      failures: summary.totals.failures,
      success_rate: summary.totals.success_rate,
      error_codes: summary.totals.error_codes,
    },
    top_failure_tools: topFailureTools,
    recent_failures: events
      .filter((event) => !event.ok)
      .slice(-limit)
      .reverse()
      .map((event) => ({
        ts: event.ts,
        tool: event.tool,
        error_code: event.error_code,
        target_domain: event.target_domain,
        wave: event.wave,
        agent: event.agent,
        surface_id: event.surface_id,
      })),
  };
}

function buildToolHealth({ targetDomain = null, cutoffMs = null, limit = DEFAULT_LIMIT, env = process.env } = {}) {
  const readResult = readToolTelemetryEvents({ target_domain: targetDomain, env });
  return slimToolHealth(readResult, filterByWindow(readResult.events, cutoffMs), limit);
}

function buildHunterHealth({ targetDomain = null, cutoffMs = null, limit = DEFAULT_LIMIT, env = process.env } = {}) {
  const readResult = readAgentRunTelemetryEvents({
    target_domain: targetDomain,
    agent_run_type: "hunter",
    env,
  });
  const events = filterByWindow(readResult.events, cutoffMs);
  const byStatus = { allowed: 0, blocked: 0 };
  const byBlockCode = {};
  for (const event of events) {
    byStatus[event.status] = (byStatus[event.status] || 0) + 1;
    if (event.status === "blocked" && event.block_code) {
      byBlockCode[event.block_code] = (byBlockCode[event.block_code] || 0) + 1;
    }
  }
  return {
    enabled: readResult.enabled,
    telemetry_path: readResult.telemetry_path,
    total_runs: events.length,
    malformed_lines: readResult.malformed_lines,
    totals: {
      by_status: byStatus,
      by_block_code: byBlockCode,
    },
    recent_blocked_runs: events
      .filter((event) => event.status === "blocked")
      .slice(-limit)
      .reverse()
      .map((event) => ({
        ts: event.ts,
        block_code: event.block_code,
        target_domain: event.target_domain,
        wave: event.wave,
        agent: event.agent,
        surface_id: event.surface_id,
        handoff: {
          present: event.handoff.present,
          valid: event.handoff.valid,
        },
        coverage: event.coverage,
        findings: event.findings,
      })),
  };
}

function phaseIndex(phase) {
  return PHASE_VALUES.indexOf(phase);
}

function phaseAtLeast(phase, requiredPhase) {
  const current = phaseIndex(phase);
  const required = phaseIndex(requiredPhase);
  return current >= 0 && required >= 0 && current >= required;
}

function issue(code, severity, message, evidence = {}) {
  return { code, severity, message, evidence };
}

function analyzeSession(targetDomain, { cutoffMs = null, limit = DEFAULT_LIMIT, env = process.env } = {}) {
  const artifacts = readSessionArtifactSummary(targetDomain);
  const eventRead = readPipelineEvents(targetDomain);
  const events = filterByWindow(eventRead.events, cutoffMs);
  const allEvents = eventRead.events;
  const toolHealth = buildToolHealth({ targetDomain, cutoffMs, limit, env });
  const hunterHealth = buildHunterHealth({ targetDomain, cutoffMs, limit, env });
  const issues = [];

  if (artifacts.artifact_errors.length > 0) {
    issues.push(issue("unreadable_artifacts", "blocked", "Session has missing or unreadable required artifacts.", {
      errors: artifacts.artifact_errors.slice(0, limit),
    }));
  }

  const pendingWave = artifacts.state.pending_wave;
  const pendingReadiness = pendingWave == null
    ? null
    : artifacts.waves.find((wave) => wave.wave_number === pendingWave) || null;
  if (pendingReadiness && (pendingReadiness.missing_agents.length > 0 || pendingReadiness.invalid_agents.length > 0)) {
    issues.push(issue("hunter_handoff_failures", "blocked", "Pending wave has missing or invalid hunter handoffs.", {
      wave_number: pendingWave,
      missing_handoffs: pendingReadiness.missing_agents.length,
      invalid_handoffs: pendingReadiness.invalid_agents.length,
    }));
  }

  const blockedHunterRuns = hunterHealth.totals.by_status.blocked || 0;
  if (blockedHunterRuns >= 2) {
    issues.push(issue("repeated_hunter_stops", "blocked", "Hunter SubagentStop blocks repeated for this session.", {
      blocked_runs: blockedHunterRuns,
      by_block_code: hunterHealth.totals.by_block_code,
    }));
  }

  if (phaseAtLeast(artifacts.state.phase, "GRADE") && !artifacts.verification.rounds.final.valid) {
    issues.push(issue("missing_verification", "blocked", "Session reached GRADE without a valid final verification artifact.", {
      phase: artifacts.state.phase,
    }));
  }

  if (phaseAtLeast(artifacts.state.phase, "REPORT") && !artifacts.grade.valid) {
    issues.push(issue("missing_grade", "blocked", "Session reached REPORT without a valid grade artifact.", {
      phase: artifacts.state.phase,
    }));
  }

  if (phaseAtLeast(artifacts.state.phase, "REPORT") && !artifacts.report.present) {
    issues.push(issue("missing_report", "needs_attention", "Session reached REPORT but report.md is not present.", {
      phase: artifacts.state.phase,
    }));
  }

  const toolCalls = toolHealth.totals.calls;
  const toolFailures = toolHealth.totals.failures;
  if (toolFailures >= HIGH_TOOL_FAILURE_MIN_FAILURES && toolCalls > 0 && toolFailures / toolCalls > HIGH_TOOL_FAILURE_RATE) {
    issues.push(issue("mcp_tool_failures", "needs_attention", "MCP tool failure rate is high.", {
      calls: toolCalls,
      failures: toolFailures,
      failure_rate: Number((toolFailures / toolCalls).toFixed(4)),
      top_failure_tools: toolHealth.top_failure_tools.slice(0, 5),
    }));
  }

  const authFailures = Object.entries(toolHealth.totals.error_codes || {})
    .filter(([code]) => /AUTH/i.test(code))
    .reduce((total, [, count]) => total + count, 0);
  if (authFailures > 0) {
    issues.push(issue("auth_failures", "needs_attention", "Auth-related MCP failures are present.", {
      failures: authFailures,
    }));
  }

  const coverage = artifacts.attack_surface_coverage;
  if (
    phaseAtLeast(artifacts.state.phase, "CHAIN") &&
    coverage.non_low_total > 0 &&
    Number.isFinite(coverage.coverage_pct) &&
    coverage.coverage_pct < 100
  ) {
    issues.push(issue("low_coverage", "needs_attention", "Non-low attack surface coverage is below the wave policy target.", {
      coverage_pct: coverage.coverage_pct,
      non_low_explored: coverage.non_low_explored,
      non_low_total: coverage.non_low_total,
      unexplored_high: coverage.unexplored_high,
    }));
  }

  if (
    artifacts.findings.total > 0 &&
    artifacts.verification.rounds.final.exists &&
    (artifacts.verification.final_results_count === 0 || artifacts.verification.final_reportable_count === 0)
  ) {
    issues.push(issue("verification_dropoff", "needs_attention", "Final verification dropped all recorded findings or reportable findings.", {
      findings: artifacts.findings.total,
      final_results: artifacts.verification.final_results_count,
      final_reportable: artifacts.verification.final_reportable_count,
    }));
  }

  if (artifacts.grade.verdict === "HOLD" || artifacts.grade.verdict === "SKIP") {
    issues.push(issue("grade_hold_skip", "needs_attention", "Grade verdict is not SUBMIT.", {
      verdict: artifacts.grade.verdict,
      total_score: artifacts.grade.total_score,
    }));
  }

  const latest = latestEvent(allEvents);
  if (pendingWave != null && latest && Date.now() - timestampMs(latest.ts) > STALE_PENDING_WAVE_MS) {
    issues.push(issue("stale_pending_wave", "needs_attention", "Pending wave has not advanced recently.", {
      wave_number: pendingWave,
      latest_event: compactEvent(latest),
    }));
  }

  const healthStatus = issues.some((item) => item.severity === "blocked")
    ? "blocked"
    : issues.some((item) => item.severity === "needs_attention")
      ? "needs_attention"
      : "healthy";

  const row = {
    target_domain: targetDomain,
    phase: artifacts.state.phase,
    auth_status: artifacts.state.auth_status,
    waves: {
      hunt_wave: artifacts.state.hunt_wave,
      pending_wave: artifacts.state.pending_wave,
      assignment_files: artifacts.waves.length,
      pending_handoffs_missing: pendingReadiness ? pendingReadiness.missing_agents.length : 0,
      pending_handoffs_invalid: pendingReadiness ? pendingReadiness.invalid_agents.length : 0,
    },
    findings: {
      total: artifacts.findings.total,
      by_severity: artifacts.findings.by_severity,
    },
    final_verification_count: artifacts.verification.final_results_count,
    final_reportable_count: artifacts.verification.final_reportable_count,
    grade_verdict: artifacts.grade.verdict,
    report_present: artifacts.report.present,
    latest_event: compactEvent(latest),
    health: {
      status: healthStatus,
      reasons: issues.map((item) => item.code),
    },
  };

  return {
    target_domain: targetDomain,
    row,
    artifacts,
    event_read: eventRead,
    events,
    issues,
    tool_health: toolHealth,
    hunter_health: hunterHealth,
  };
}

function sessionReachedPhase(analysis, phase) {
  if (phase === "REPORT" && analysis.artifacts.report.present) return true;
  if (phaseAtLeast(analysis.artifacts.state.phase, phase)) return true;
  return analysis.event_read.events.some((event) => event.to_phase === phase || event.phase === phase);
}

function buildFunnel(analyses) {
  const funnel = {
    sessions_total: analyses.length,
    reached: {
      AUTH: 0,
      HUNT: 0,
      CHAIN: 0,
      VERIFY: 0,
      GRADE: 0,
      REPORT: 0,
    },
    findings_total: 0,
    final_verification_total: 0,
    final_reportable_total: 0,
    grade_total: 0,
    report_total: 0,
  };

  for (const analysis of analyses) {
    for (const phase of Object.keys(funnel.reached)) {
      if (sessionReachedPhase(analysis, phase)) funnel.reached[phase] += 1;
    }
    funnel.findings_total += analysis.artifacts.findings.total;
    funnel.final_verification_total += analysis.artifacts.verification.final_results_count;
    funnel.final_reportable_total += analysis.artifacts.verification.final_reportable_count;
    if (analysis.artifacts.grade.exists) funnel.grade_total += 1;
    if (analysis.artifacts.report.present) funnel.report_total += 1;
  }

  return funnel;
}

function severityRank(severity) {
  if (severity === "blocked") return 2;
  if (severity === "needs_attention") return 1;
  return 0;
}

function buildBottlenecks(analyses, limit) {
  const grouped = new Map();
  for (const analysis of analyses) {
    for (const item of analysis.issues) {
      if (!grouped.has(item.code)) {
        grouped.set(item.code, {
          code: item.code,
          severity: item.severity,
          affected_targets: [],
          evidence: [],
        });
      }
      const group = grouped.get(item.code);
      if (severityRank(item.severity) > severityRank(group.severity)) {
        group.severity = item.severity;
      }
      group.affected_targets.push(analysis.target_domain);
      group.evidence.push({ target_domain: analysis.target_domain, ...item.evidence });
    }
  }

  return Array.from(grouped.values())
    .map((group) => ({
      code: group.code,
      severity: group.severity,
      affected_count: group.affected_targets.length,
      affected_targets: group.affected_targets.slice(0, limit),
      evidence: group.evidence.slice(0, limit),
    }))
    .sort((a, b) => (
      b.affected_count - a.affected_count ||
      severityRank(b.severity) - severityRank(a.severity) ||
      a.code.localeCompare(b.code)
    ))
    .slice(0, limit);
}

function actionForBottleneck(bottleneck) {
  const actionByCode = {
    unreadable_artifacts: "Repair or remove malformed session artifacts before resuming orchestration.",
    hunter_handoff_failures: "Resume the pending wave after missing hunters write valid structured handoffs, or force-merge intentionally.",
    repeated_hunter_stops: "Fix the hunter final-marker or handoff path that is repeatedly blocking SubagentStop.",
    mcp_tool_failures: "Inspect failing MCP tools and address the dominant error code before launching more agents.",
    auth_failures: "Refresh or recapture auth profiles before additional authenticated testing.",
    low_coverage: "Launch another wave for unexplored non-low surfaces before verification.",
    verification_dropoff: "Review final verification inputs because recorded findings are not surviving as reportable.",
    grade_hold_skip: "Use grader feedback to decide whether to return to HUNT or stop before report writing.",
    missing_verification: "Write a valid final verification round before grading or reporting.",
    missing_grade: "Write a valid grade verdict before report completion.",
    missing_report: "Write report.md or move the session out of REPORT if report writing is still pending.",
    stale_pending_wave: "Re-enter resume flow for the stale pending wave and reconcile handoffs.",
  };
  return {
    action: actionByCode[bottleneck.code] || "Inspect this bottleneck before continuing.",
    reason: `${bottleneck.affected_count} session(s) affected by ${bottleneck.code}.`,
    affected_targets: bottleneck.affected_targets,
    source_evidence: bottleneck.evidence,
  };
}

function buildNextActions(bottlenecks, limit) {
  return bottlenecks.slice(0, limit).map(actionForBottleneck);
}

function listSessionDomains() {
  const root = sessionsRoot();
  if (!fs.existsSync(root)) return [];
  return fs.readdirSync(root, { withFileTypes: true })
    .filter((entry) => entry.isDirectory())
    .map((entry) => entry.name)
    .filter((name) => {
      try {
        assertNonEmptyString(name, "target_domain");
        sessionDir(name);
        return true;
      } catch {
        return false;
      }
    })
    .sort();
}

function normalizeReadArgs(args = {}) {
  const targetDomain = args.target_domain == null ? null : assertNonEmptyString(args.target_domain, "target_domain");
  return {
    target_domain: targetDomain,
    window_days: normalizePositiveInteger(args.window_days, DEFAULT_WINDOW_DAYS, MAX_WINDOW_DAYS),
    limit: normalizePositiveInteger(args.limit, DEFAULT_LIMIT, MAX_LIMIT),
    include_events: args.include_events === true,
  };
}

function readPipelineAnalytics(args = {}, { env = process.env } = {}) {
  const options = normalizeReadArgs(args);
  const cutoffMs = Date.now() - options.window_days * 24 * 60 * 60 * 1000;

  if (options.target_domain) {
    const analysis = analyzeSession(options.target_domain, {
      cutoffMs: null,
      limit: options.limit,
      env,
    });
    const bottlenecks = buildBottlenecks([analysis], options.limit);
    const response = {
      version: PIPELINE_ANALYTICS_VERSION,
      mode: "session",
      target_domain: options.target_domain,
      filters: options,
      sessions: [analysis.row],
      funnel: buildFunnel([analysis]),
      bottlenecks,
      next_actions: buildNextActions(bottlenecks, options.limit),
      tool_health: analysis.tool_health,
      hunter_health: analysis.hunter_health,
      event_log: {
        enabled: analysis.event_read.enabled,
        path: analysis.event_read.events_path,
        exists: analysis.event_read.exists,
        malformed_lines: analysis.event_read.malformed_lines,
        backfilled: analysis.event_read.backfilled,
      },
    };
    if (options.include_events) {
      response.events = analysis.event_read.events.slice(-options.limit).map(compactEvent);
    }
    return JSON.stringify(response);
  }

  const analyses = listSessionDomains()
    .map((targetDomain) => analyzeSession(targetDomain, { cutoffMs, limit: options.limit, env }))
    .filter((analysis) => {
      const latest = latestEvent(analysis.event_read.events);
      const latestMs = Math.max(timestampMs(latest?.ts), timestampMs(analysis.artifacts.latest_artifact_ts));
      return latestMs >= cutoffMs;
    })
    .sort((a, b) => {
      const aLatest = Math.max(timestampMs(latestEvent(a.event_read.events)?.ts), timestampMs(a.artifacts.latest_artifact_ts));
      const bLatest = Math.max(timestampMs(latestEvent(b.event_read.events)?.ts), timestampMs(b.artifacts.latest_artifact_ts));
      return bLatest - aLatest || a.target_domain.localeCompare(b.target_domain);
    });

  const bottlenecks = buildBottlenecks(analyses, options.limit);
  const response = {
    version: PIPELINE_ANALYTICS_VERSION,
    mode: "cross_session",
    filters: options,
    sessions: analyses.map((analysis) => analysis.row),
    funnel: buildFunnel(analyses),
    bottlenecks,
    next_actions: buildNextActions(bottlenecks, options.limit),
    tool_health: buildToolHealth({ cutoffMs, limit: options.limit, env }),
    hunter_health: buildHunterHealth({ cutoffMs, limit: options.limit, env }),
  };
  if (options.include_events) {
    response.events = analyses
      .flatMap((analysis) => analysis.event_read.events)
      .sort((a, b) => timestampMs(b.ts) - timestampMs(a.ts))
      .slice(0, options.limit)
      .map(compactEvent);
  }
  return JSON.stringify(response);
}

module.exports = {
  PIPELINE_ANALYTICS_VERSION,
  PIPELINE_EVENT_TYPES,
  PIPELINE_EVENT_VERSION,
  appendPipelineEventDirect,
  buildBackfillEvents,
  listSessionDomains,
  normalizePipelineEvent,
  pipelineAnalyticsEnabled,
  readPipelineAnalytics,
  readPipelineEvents,
  readSessionArtifactSummary,
  safeAppendPipelineEventDirect,
  safeAppendPipelineEventWithSessionLock,
  safeRecordHunterStoppedPipelineEvent,
};
