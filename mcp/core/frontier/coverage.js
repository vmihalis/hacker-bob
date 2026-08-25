"use strict";

const fs = require("fs");
const {
  COVERAGE_LOG_MAX_RECORDS,
  COVERAGE_STATUS_VALUES,
  COVERAGE_SUMMARY_MAX_ITEMS,
  COVERAGE_UNFINISHED_STATUS_VALUES,
} = require("./coverage-vocabulary.js");
const {
  assertEnumValue,
  assertInteger,
  assertNonEmptyString,
  assertRequiredText,
  normalizeOptionalText,
  parseAgentId,
  parseWaveId,
} = require("../io/validation.js");
const {
  coverageJsonlPath,
} = require("../io/paths.js");
const {
  hashCanonicalJson,
} = require("../verification/verification-contracts.js");
const {
  isBugClassRegisteredForClosure,
} = require("../capability/capability-packs.js");
const {
  appendJsonlLines,
  readFileUtf8,
  withSessionLock,
} = require("../io/storage.js");
const {
  validateAssignedWaveAgentSurface,
} = require("../session/assignments.js");
const {
  safeAppendPipelineEventDirect,
} = require("../telemetry/pipeline-events.js");
const {
  safeGovernanceContextForDomain,
} = require("../governance/index.js");
const {
  appendClosureRecordedEvent,
} = require("./frontier-events.js");
const {
  scheduleMaterialization,
} = require("./frontier-materialize-debounce.js");

const CLASS_LATTICE_COVERAGE_STATUS_VALUES = Object.freeze([
  "tested",
  "not_tested",
  "blocked",
  "held",
  "non_reportable",
  "proof_closed",
]);

const COVERAGE_FRONTIER_ROW_LIMIT = 64;

const STRUCTURAL_CLASS_BUDGET_FLOORS = Object.freeze({
  confidentiality: Object.freeze({ min_cells: 1, reserved: true }),
  race: Object.freeze({ min_cells: 1, reserved: true }),
  lifecycle: Object.freeze({ min_cells: 1, reserved: true }),
  availability: Object.freeze({ min_cells: 1, reserved: true }),
  entropy: Object.freeze({ min_cells: 1, reserved: true }),
  semantic_oracle: Object.freeze({ min_cells: 1, reserved: true }),
});

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
      // wave/agent are null for graph-dispatched coverage cells (no wave
      // assignment); every requeue join self-excludes a null-keyed record.
      wave: record.wave == null ? null : parseWaveId(record.wave),
      agent: record.agent == null ? null : parseAgentId(record.agent),
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

  const content = readFileUtf8(filePath, { label: "coverage.jsonl" });
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

function coveragePlanningKey(bugClass, authProfile) {
  return JSON.stringify([String(bugClass || "").toLowerCase(), authProfile || ""]);
}

function structuralClassForBugClass(bugClass) {
  const key = String(bugClass || "").trim().toLowerCase().replace(/[\s-]+/g, "_");
  if (/(race|toctou|concurr|stale|replay|rollback|version)/.test(key)) return "race";
  if (/(lifecycle|state|workflow|ordering|sequence|transition|move|carryover)/.test(key)) return "lifecycle";
  if (/(dos|availability|exhaust|resource|rate|timeout|crash)/.test(key)) return "availability";
  if (/(entropy|token|nonce|random|rng|secret|session|predict)/.test(key)) return "entropy";
  if (/(canary|semantic|ai|llm|search|render|secondorder|second_order)/.test(key)) return "semantic_oracle";
  return "confidentiality";
}

function latestCoverageRowsByPlanningKey(records, surfaceId) {
  const latest = new Map();
  const safeRecords = Array.isArray(records) ? records : [];
  for (const record of safeRecords) {
    if (!record || typeof record !== "object" || Array.isArray(record)) continue;
    if (surfaceId != null && record.surface_id !== surfaceId) continue;
    if (typeof record.bug_class !== "string") continue;
    const status = typeof record.status === "string" ? record.status : "";
    if (!COVERAGE_STATUS_VALUES.includes(status)) continue;
    const key = coveragePlanningKey(record.bug_class, record.auth_profile || "");
    latest.set(key, {
      bug_class: record.bug_class.toLowerCase(),
      auth_profile: record.auth_profile || "",
      status,
      evidence_summary: typeof record.evidence_summary === "string" ? record.evidence_summary : null,
      next_step: typeof record.next_step === "string" ? record.next_step : null,
      ts: typeof record.ts === "string" ? record.ts : null,
      wave: record.wave == null ? null : record.wave,
      agent: record.agent == null ? null : record.agent,
    });
  }
  return latest;
}

function statusForCoverageProductCell(cell, latestByPlanningKey) {
  const bugClass = String(cell.bug_class || "").toLowerCase();
  if (cell.disposition === "hold" || !isBugClassRegisteredForClosure(bugClass)) {
    return {
      status: "held",
      reason: cell.hold_reason || `unknown control-validity class: ${bugClass}`,
      source: null,
    };
  }

  const planningKey = typeof cell.planning_key === "string"
    ? cell.planning_key
    : coveragePlanningKey(bugClass, cell.auth_profile || "");
  const latest = latestByPlanningKey.get(planningKey);
  if (!latest) {
    return { status: "not_tested", reason: "no coverage row recorded", source: null };
  }
  if (latest.status === "blocked") {
    return { status: "blocked", reason: latest.evidence_summary || "coverage blocked", source: latest };
  }
  if (latest.status === "tested") {
    return { status: "tested", reason: latest.evidence_summary || "coverage tested", source: latest };
  }
  return {
    status: "not_tested",
    reason: latest.next_step || latest.evidence_summary || `coverage still ${latest.status}`,
    source: latest,
  };
}

function summarizeCounts(rows, key) {
  const counts = {};
  for (const row of rows) {
    const value = row && row[key];
    if (typeof value !== "string" || value.length === 0) continue;
    counts[value] = (counts[value] || 0) + 1;
  }
  return counts;
}

function buildClassLatticeCoverageProduct({
  target_domain,
  surface_id,
  expected_cells,
  coverage_records,
  row_limit = COVERAGE_FRONTIER_ROW_LIMIT,
} = {}) {
  const domain = assertNonEmptyString(target_domain, "target_domain");
  const surfaceId = assertNonEmptyString(surface_id, "surface_id");
  const cells = Array.isArray(expected_cells) ? expected_cells : [];
  const limit = Number.isInteger(row_limit) && row_limit > 0
    ? Math.min(row_limit, COVERAGE_FRONTIER_ROW_LIMIT)
    : COVERAGE_FRONTIER_ROW_LIMIT;
  const latestByPlanningKey = latestCoverageRowsByPlanningKey(coverage_records, surfaceId);
  const rows = [];
  for (const cell of cells) {
    if (!cell || typeof cell !== "object" || Array.isArray(cell)) continue;
    if (typeof cell.bug_class !== "string" || cell.bug_class.length === 0) continue;
    const bugClass = cell.bug_class.toLowerCase();
    const authProfile = typeof cell.auth_profile === "string" ? cell.auth_profile : "";
    const structuralClass = structuralClassForBugClass(bugClass);
    const status = statusForCoverageProductCell({ ...cell, bug_class: bugClass, auth_profile: authProfile }, latestByPlanningKey);
    rows.push({
      row_kind: "class_lattice_coverage",
      surface_id: surfaceId,
      class_id: bugClass,
      binding_id: authProfile || "anonymous",
      auth_profile: authProfile,
      planning_key: typeof cell.planning_key === "string" ? cell.planning_key : coveragePlanningKey(bugClass, authProfile),
      structural_class: structuralClass,
      budget_floor: STRUCTURAL_CLASS_BUDGET_FLOORS[structuralClass] || null,
      status: status.status,
      reason: status.reason,
      source_record: status.source,
    });
  }

  rows.sort((a, b) => {
    const statusDelta = CLASS_LATTICE_COVERAGE_STATUS_VALUES.indexOf(a.status)
      - CLASS_LATTICE_COVERAGE_STATUS_VALUES.indexOf(b.status);
    if (statusDelta !== 0) return statusDelta;
    const structuralDelta = a.structural_class.localeCompare(b.structural_class);
    if (structuralDelta !== 0) return structuralDelta;
    return a.planning_key.localeCompare(b.planning_key);
  });

  const shownRows = rows.slice(0, limit);
  const coverageGaps = rows.filter((row) => (
    row.status === "not_tested"
    || row.status === "blocked"
    || row.status === "held"
    || row.status === "non_reportable"
  ));
  const product = {
    version: 1,
    target_domain: domain,
    surface_id: surfaceId,
    statuses: CLASS_LATTICE_COVERAGE_STATUS_VALUES,
    structural_class_budget_floors: STRUCTURAL_CLASS_BUDGET_FLOORS,
    total_rows: rows.length,
    shown_rows: shownRows.length,
    omitted_rows: Math.max(0, rows.length - shownRows.length),
    counts_by_status: summarizeCounts(rows, "status"),
    counts_by_structural_class: summarizeCounts(rows, "structural_class"),
    gap_count: coverageGaps.length,
    rows: shownRows,
    coverage_gaps: coverageGaps.slice(0, limit).map((row) => ({
      class_id: row.class_id,
      binding_id: row.binding_id,
      structural_class: row.structural_class,
      status: row.status,
      reason: row.reason,
    })),
  };
  return {
    ...product,
    coverage_product_hash: hashCanonicalJson(product),
  };
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
    // coverage.jsonl records per-endpoint coverage tests. After D.3,
    // surface-level explored/closed truth lives entirely in the frontier
    // ledger; coverage.jsonl is the per-endpoint per-wave history that
    // feeds wave-readiness and analytics.
    appendJsonlLines(logPath, records, { maxRecords: COVERAGE_LOG_MAX_RECORDS });
    const statuses = COVERAGE_STATUS_VALUES.reduce((result, status) => {
      result[status] = records.filter((record) => record.status === status).length;
      return result;
    }, {});
    safeAppendPipelineEventDirect(domain, "coverage_logged", {
      wave,
      agent,
      surface_id: surfaceId,
      status: "logged",
      source: "bob_log_coverage",
      counts: {
        records: records.length,
        ...statuses,
      },
    }, safeGovernanceContextForDomain(domain));

    // Dual-write per Pact P2: a coverage log entry is a closure signal for the
    // surface (the agent declares a probe path was exercised). Emit one
    // closure.recorded event capturing the batch; F.3 will fold these into
    // currentClosures(domain).
    try {
      appendClosureRecordedEvent({
        target_domain: domain,
        kind: "closure.recorded",
        surface_id: surfaceId,
        payload: {
          wave,
          agent,
          records: records.length,
          statuses,
          tested: records.filter((record) => record.status === "tested").length,
          blocked: records.filter((record) => record.status === "blocked").length,
          promising: records.filter((record) => record.status === "promising").length,
          requeue: records.filter((record) => record.status === "requeue").length,
          needs_auth: records.filter((record) => record.status === "needs_auth").length,
        },
        source: { artifact: "coverage.jsonl", tool: "bob_log_coverage" },
      });
      scheduleMaterialization(domain);
    } catch {
      // Frontier ledger is dual-write best-effort during the deprecation window.
    }

    return JSON.stringify({
      appended: records.length,
      log_path: logPath,
      statuses,
    });
  });
}

// Reconcile a finalized coverage cell into coverage.jsonl. Unlike logCoverage
// this is the orchestrator-authority graph-cell path: a cell is graph-dispatched
// (not wave-assigned), so it bypasses validateAssignedWaveAgentSurface and
// records wave/agent null (every requeue join self-excludes a null-keyed
// record). The coverage key is (surface_id, "", "cell:<surface_id>", bug_class,
// auth_profile); the floor-pruner keys on (bug_class, auth_profile), so the
// endpoint sentinel is inert. bob_finalize_node calls this ONLY when a cell node
// reaches finalized (its coverage witness verified), so coverage stays
// falsifiable: an unprobed cell fails verification and writes no coverage.
function logCellCoverage({ target_domain, surface_id, bug_class, auth_profile, status, evidence_summary }) {
  const domain = assertNonEmptyString(target_domain, "target_domain");
  const surfaceId = assertNonEmptyString(surface_id, "surface_id");
  const bugClass = assertNonEmptyString(bug_class, "bug_class");
  const logPath = coverageJsonlPath(domain);
  const ts = new Date().toISOString();
  const record = normalizeCoverageRecord({
    version: 1,
    ts,
    target_domain: domain,
    wave: null,
    agent: null,
    surface_id: surfaceId,
    endpoint: `cell:${surfaceId}`,
    bug_class: bugClass,
    auth_profile: auth_profile || undefined,
    status: status || "tested",
    evidence_summary: evidence_summary || `cell ${bugClass} probed (graph-dispatched)`,
  }, { expectedDomain: domain });

  return withSessionLock(domain, () => {
    appendJsonlLines(logPath, [record], { maxRecords: COVERAGE_LOG_MAX_RECORDS });
    return record;
  });
}

module.exports = {
  CLASS_LATTICE_COVERAGE_STATUS_VALUES,
  STRUCTURAL_CLASS_BUDGET_FLOORS,
  buildCoverageSummaryForSurface,
  buildClassLatticeCoverageProduct,
  computeCoverageRequeueSurfaceIds,
  logCellCoverage,
  coverageRecordKey,
  coverageSummaryItem,
  structuralClassForBugClass,
  isUnfinishedCoverageStatus,
  latestCoverageRecordsByKey,
  logCoverage,
  normalizeCoverageEntryInput,
  normalizeCoverageRecord,
  readCoverageRecordsFromJsonl,
};
