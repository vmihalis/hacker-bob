"use strict";

const fs = require("fs");
const {
  COVERAGE_LOG_MAX_RECORDS,
  COVERAGE_STATUS_VALUES,
  COVERAGE_SUMMARY_MAX_ITEMS,
  COVERAGE_UNFINISHED_STATUS_VALUES,
} = require("./constants.js");
const {
  assertEnumValue,
  assertInteger,
  assertNonEmptyString,
  assertRequiredText,
  normalizeOptionalText,
  parseAgentId,
  parseWaveId,
} = require("./validation.js");
const {
  coverageJsonlPath,
} = require("./paths.js");
const {
  appendJsonlLines,
  withSessionLock,
} = require("./storage.js");
const {
  validateAssignedWaveAgentSurface,
} = require("./assignments.js");

function normalizeCoverageRecord(record, { expectedDomain = null, lineNumber = null } = {}) {
  if (record == null || typeof record !== "object" || Array.isArray(record)) {
    throw new Error(lineNumber == null
      ? "coverage record must be an object"
      : `Malformed coverage.jsonl at line ${lineNumber}: expected object`);
  }

  try {
    const coverage = {
      version: record.version == null
        ? 1
        : assertInteger(record.version, "version", { min: 1, max: 1 }),
      ts: assertNonEmptyString(record.ts, "ts"),
      target_domain: assertNonEmptyString(record.target_domain, "target_domain"),
      wave: parseWaveId(record.wave),
      agent: parseAgentId(record.agent),
      surface_id: assertNonEmptyString(record.surface_id, "surface_id"),
      endpoint: assertRequiredText(record.endpoint, "endpoint"),
      method: normalizeOptionalText(record.method, "method"),
      bug_class: assertRequiredText(record.bug_class, "bug_class").toLowerCase(),
      auth_profile: normalizeOptionalText(record.auth_profile, "auth_profile"),
      status: assertEnumValue(record.status, COVERAGE_STATUS_VALUES, "status"),
      evidence_summary: assertRequiredText(record.evidence_summary, "evidence_summary"),
      next_step: normalizeOptionalText(record.next_step, "next_step"),
    };

    if (coverage.method) {
      coverage.method = coverage.method.toUpperCase();
    }

    if (expectedDomain != null && coverage.target_domain !== expectedDomain) {
      throw new Error("target_domain mismatch");
    }

    return coverage;
  } catch (error) {
    if (lineNumber == null) {
      throw error;
    }
    throw new Error(`Malformed coverage.jsonl at line ${lineNumber}: ${error.message || String(error)}`);
  }
}

function normalizeCoverageEntryInput(entry, index) {
  if (entry == null || typeof entry !== "object" || Array.isArray(entry)) {
    throw new Error(`entries[${index}] must be an object`);
  }

  const normalized = {
    endpoint: assertRequiredText(entry.endpoint, `entries[${index}].endpoint`),
    method: normalizeOptionalText(entry.method, `entries[${index}].method`),
    bug_class: assertRequiredText(entry.bug_class, `entries[${index}].bug_class`).toLowerCase(),
    auth_profile: normalizeOptionalText(entry.auth_profile, `entries[${index}].auth_profile`),
    status: assertEnumValue(entry.status, COVERAGE_STATUS_VALUES, `entries[${index}].status`),
    evidence_summary: assertRequiredText(entry.evidence_summary, `entries[${index}].evidence_summary`),
    next_step: normalizeOptionalText(entry.next_step, `entries[${index}].next_step`),
  };

  if (normalized.method) {
    normalized.method = normalized.method.toUpperCase();
  }

  return normalized;
}

function readCoverageRecordsFromJsonl(domain) {
  const filePath = coverageJsonlPath(domain);
  if (!fs.existsSync(filePath)) {
    return [];
  }

  const content = fs.readFileSync(filePath, "utf8");
  if (!content.trim()) {
    return [];
  }

  const records = [];
  const lines = content.split("\n");
  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index];
    if (!line.trim()) continue;

    let parsed;
    try {
      parsed = JSON.parse(line);
    } catch (error) {
      throw new Error(`Malformed coverage.jsonl at line ${index + 1}: ${error.message || String(error)}`);
    }

    records.push(normalizeCoverageRecord(parsed, {
      expectedDomain: domain,
      lineNumber: index + 1,
    }));
  }

  return records;
}

function coverageRecordKey(record) {
  return JSON.stringify([
    record.surface_id,
    record.method || "",
    record.endpoint,
    record.bug_class,
    record.auth_profile || "",
  ]);
}

function latestCoverageRecordsByKey(records) {
  const latest = new Map();
  for (const record of records) {
    latest.set(coverageRecordKey(record), record);
  }
  return latest;
}

function isUnfinishedCoverageStatus(status) {
  return COVERAGE_UNFINISHED_STATUS_VALUES.includes(status);
}

function coverageSummaryItem(record) {
  const item = {
    endpoint: record.endpoint,
    bug_class: record.bug_class,
    status: record.status,
    evidence_summary: record.evidence_summary,
    wave: record.wave,
    agent: record.agent,
    ts: record.ts,
  };
  if (record.method) item.method = record.method;
  if (record.auth_profile) item.auth_profile = record.auth_profile;
  if (record.next_step) item.next_step = record.next_step;
  return item;
}

function buildCoverageSummaryForSurface(records, surfaceId, cap = COVERAGE_SUMMARY_MAX_ITEMS) {
  const latestRecords = Array.from(latestCoverageRecordsByKey(
    records.filter((record) => record.surface_id === surfaceId),
  ).values());

  const statusOrder = new Map([
    ["promising", 0],
    ["needs_auth", 1],
    ["requeue", 2],
    ["tested", 3],
    ["blocked", 4],
  ]);

  latestRecords.sort((a, b) => {
    const statusDelta = (statusOrder.get(a.status) ?? 99) - (statusOrder.get(b.status) ?? 99);
    if (statusDelta !== 0) return statusDelta;
    const timeDelta = Date.parse(b.ts) - Date.parse(a.ts);
    if (!Number.isNaN(timeDelta) && timeDelta !== 0) return timeDelta;
    return coverageRecordKey(a).localeCompare(coverageRecordKey(b));
  });

  const shownRecords = latestRecords.slice(0, cap);
  const grouped = COVERAGE_STATUS_VALUES.reduce((result, status) => {
    result[status] = [];
    return result;
  }, {});

  for (const record of shownRecords) {
    grouped[record.status].push(coverageSummaryItem(record));
  }

  return {
    surface_id: surfaceId,
    total: latestRecords.length,
    shown: shownRecords.length,
    omitted: Math.max(0, latestRecords.length - shownRecords.length),
    cap,
    ...grouped,
  };
}

function computeCoverageRequeueSurfaceIds(artifacts, coverageRecords) {
  const assignedSurfaceIds = new Set(artifacts.assignments.map((assignment) => assignment.surface_id));
  const assignedAgentSurfaces = new Map(
    artifacts.assignments.map((assignment) => [assignment.agent, assignment.surface_id]),
  );
  const latestCurrentWaveRecords = Array.from(latestCoverageRecordsByKey(
    coverageRecords.filter((record) => (
      record.wave === artifacts.wave &&
      assignedSurfaceIds.has(record.surface_id) &&
      assignedAgentSurfaces.get(record.agent) === record.surface_id
    )),
  ).values());

  const unfinishedSurfaceIds = new Set();
  for (const record of latestCurrentWaveRecords) {
    if (isUnfinishedCoverageStatus(record.status)) {
      unfinishedSurfaceIds.add(record.surface_id);
    }
  }

  return artifacts.assignments
    .map((assignment) => assignment.surface_id)
    .filter((surfaceId) => unfinishedSurfaceIds.has(surfaceId));
}

function logCoverage(args) {
  const domain = assertNonEmptyString(args.target_domain, "target_domain");
  const wave = parseWaveId(args.wave);
  const agent = parseAgentId(args.agent);
  const surfaceId = assertNonEmptyString(args.surface_id, "surface_id");

  validateAssignedWaveAgentSurface(domain, wave, agent, surfaceId);

  if (!Array.isArray(args.entries) || args.entries.length === 0) {
    throw new Error("entries must be a non-empty array");
  }

  const entries = args.entries.map((entry, index) => normalizeCoverageEntryInput(entry, index));
  const logPath = coverageJsonlPath(domain);
  const ts = new Date().toISOString();
  const records = entries.map((entry) => normalizeCoverageRecord({
    version: 1,
    ts,
    target_domain: domain,
    wave,
    agent,
    surface_id: surfaceId,
    ...entry,
  }, { expectedDomain: domain }));

  return withSessionLock(domain, () => {
    appendJsonlLines(logPath, records, { maxRecords: COVERAGE_LOG_MAX_RECORDS });

    return JSON.stringify({
      appended: records.length,
      log_path: logPath,
      statuses: COVERAGE_STATUS_VALUES.reduce((result, status) => {
        result[status] = records.filter((record) => record.status === status).length;
        return result;
      }, {}),
    });
  });
}

module.exports = {
  buildCoverageSummaryForSurface,
  computeCoverageRequeueSurfaceIds,
  coverageRecordKey,
  coverageSummaryItem,
  isUnfinishedCoverageStatus,
  latestCoverageRecordsByKey,
  logCoverage,
  normalizeCoverageEntryInput,
  normalizeCoverageRecord,
  readCoverageRecordsFromJsonl,
};
