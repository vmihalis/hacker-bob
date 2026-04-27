"use strict";

const fs = require("fs");
const {
  CHAIN_ATTEMPT_OUTCOME_VALUES,
  CHAIN_ATTEMPT_TERMINAL_OUTCOME_VALUES,
} = require("./constants.js");
const {
  readAttackSurfaceStrict,
} = require("./attack-surface.js");
const {
  readFindingsFromJsonl,
} = require("./findings.js");
const {
  chainAttemptsJsonlPath,
} = require("./paths.js");
const {
  appendJsonlLine,
  withSessionLock,
} = require("./storage.js");
const {
  assertEnumValue,
  assertNonEmptyString,
  assertRequiredText,
  normalizeStringArray,
  parseFindingId,
} = require("./validation.js");

const CHAIN_ATTEMPT_VERSION = 1;

function isPlainObject(value) {
  return value != null && typeof value === "object" && !Array.isArray(value);
}

function capRequiredText(value, fieldName, maxChars) {
  const text = assertRequiredText(value, fieldName);
  if (text.length > maxChars) {
    throw new Error(`${fieldName} must be at most ${maxChars} characters`);
  }
  return text;
}

function normalizeOptionalStringArray(value, fieldName, maxItems, maxChars) {
  const strings = normalizeStringArray(value, fieldName);
  if (strings.length > maxItems) {
    throw new Error(`${fieldName} must contain at most ${maxItems} entries`);
  }
  for (const item of strings) {
    if (item.length > maxChars) {
      throw new Error(`${fieldName} entries must be at most ${maxChars} characters`);
    }
  }
  return strings;
}

function normalizeRequiredStringArray(value, fieldName, maxItems, maxChars) {
  const strings = normalizeOptionalStringArray(value, fieldName, maxItems, maxChars);
  if (strings.length === 0) {
    throw new Error(`${fieldName} must contain at least one entry`);
  }
  return strings;
}

function normalizeFindingIds(value, findingIdSet, outcome) {
  if (!Array.isArray(value)) {
    throw new Error("finding_ids must be an array of finding IDs");
  }

  const normalized = [];
  const seen = new Set();
  for (const item of value) {
    const findingId = parseFindingId(item, "finding_ids");
    if (findingIdSet && !findingIdSet.has(findingId)) {
      throw new Error(`unknown finding_id: ${findingId}`);
    }
    if (seen.has(findingId)) continue;
    seen.add(findingId);
    normalized.push(findingId);
  }

  if (normalized.length === 0 && outcome !== "not_applicable") {
    throw new Error("finding_ids must contain at least one finding ID unless outcome is not_applicable");
  }

  return normalized;
}

function normalizeSurfaceIds(value, surfaceIdSet) {
  if (!Array.isArray(value)) {
    throw new Error("surface_ids must be an array of surface IDs");
  }

  const normalized = normalizeOptionalStringArray(value, "surface_ids", 50, 200);
  if (surfaceIdSet) {
    for (const surfaceId of normalized) {
      if (!surfaceIdSet.has(surfaceId)) {
        throw new Error(`unknown surface_id: ${surfaceId}`);
      }
    }
  }
  return normalized;
}

function buildSurfaceIdSet(domain, requestedSurfaceIds) {
  if (!Array.isArray(requestedSurfaceIds) || requestedSurfaceIds.length === 0) {
    return null;
  }
  const attackSurface = readAttackSurfaceStrict(domain);
  return attackSurface.surface_id_set;
}

function normalizeIsoTimestamp(value, fallback = new Date()) {
  if (value instanceof Date && Number.isFinite(value.getTime())) {
    return value.toISOString();
  }
  if (typeof value === "string" && value.trim()) {
    const parsedMs = Date.parse(value);
    if (Number.isFinite(parsedMs)) return new Date(parsedMs).toISOString();
  }
  return fallback.toISOString();
}

function normalizeChainAttemptRecord(record, {
  expectedDomain = null,
  findingIdSet = null,
  surfaceIdSet = null,
  lineNumber = null,
  fallbackAttemptId = null,
} = {}) {
  const prefix = lineNumber == null
    ? "chain attempt"
    : `Malformed chain-attempts.jsonl at line ${lineNumber}`;
  if (!isPlainObject(record)) {
    throw new Error(`${prefix}: expected object`);
  }

  try {
    const targetDomain = assertNonEmptyString(record.target_domain, "target_domain");
    if (expectedDomain != null && targetDomain !== expectedDomain) {
      throw new Error("target_domain mismatch");
    }
    const outcome = assertEnumValue(record.outcome, CHAIN_ATTEMPT_OUTCOME_VALUES, "outcome");
    const attemptId = record.attempt_id == null
      ? fallbackAttemptId
      : assertNonEmptyString(record.attempt_id, "attempt_id");
    if (!attemptId) {
      throw new Error("attempt_id must be a non-empty string");
    }

    return {
      version: CHAIN_ATTEMPT_VERSION,
      ts: normalizeIsoTimestamp(record.ts),
      attempt_id: attemptId,
      target_domain: targetDomain,
      finding_ids: normalizeFindingIds(record.finding_ids, findingIdSet, outcome),
      surface_ids: normalizeSurfaceIds(record.surface_ids, surfaceIdSet),
      hypothesis: capRequiredText(record.hypothesis, "hypothesis", 2000),
      steps: normalizeRequiredStringArray(record.steps, "steps", 50, 1000),
      outcome,
      evidence_summary: capRequiredText(record.evidence_summary, "evidence_summary", 4000),
      request_refs: normalizeOptionalStringArray(record.request_refs, "request_refs", 100, 300),
      auth_profiles: normalizeOptionalStringArray(record.auth_profiles, "auth_profiles", 20, 120),
    };
  } catch (error) {
    if (lineNumber == null) throw error;
    throw new Error(`${prefix}: ${error.message || String(error)}`);
  }
}

function readChainAttemptsFromJsonl(domain) {
  const targetDomain = assertNonEmptyString(domain, "target_domain");
  const filePath = chainAttemptsJsonlPath(targetDomain);
  if (!fs.existsSync(filePath)) {
    return [];
  }

  const content = fs.readFileSync(filePath, "utf8");
  if (!content.trim()) {
    return [];
  }

  const attempts = [];
  const lines = content.split("\n");
  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index];
    if (!line.trim()) continue;

    let parsed;
    try {
      parsed = JSON.parse(line);
    } catch (error) {
      throw new Error(`Malformed chain-attempts.jsonl at line ${index + 1}: ${error.message || String(error)}`);
    }

    attempts.push(normalizeChainAttemptRecord(parsed, {
      expectedDomain: targetDomain,
      lineNumber: index + 1,
      fallbackAttemptId: `C-${attempts.length + 1}`,
    }));
  }

  return attempts;
}

function summarizeChainAttempts(attempts) {
  const byOutcome = CHAIN_ATTEMPT_OUTCOME_VALUES.reduce((summary, outcome) => {
    summary[outcome] = 0;
    return summary;
  }, {});
  for (const attempt of attempts) {
    if (Object.prototype.hasOwnProperty.call(byOutcome, attempt.outcome)) {
      byOutcome[attempt.outcome] += 1;
    }
  }
  const terminalCount = attempts.filter((attempt) => (
    CHAIN_ATTEMPT_TERMINAL_OUTCOME_VALUES.includes(attempt.outcome)
  )).length;
  return {
    total: attempts.length,
    by_outcome: byOutcome,
    terminal_count: terminalCount,
    has_terminal_attempt: terminalCount > 0,
  };
}

function writeChainAttempt(args) {
  const domain = assertNonEmptyString(args.target_domain, "target_domain");
  return withSessionLock(domain, () => {
    const existingAttempts = readChainAttemptsFromJsonl(domain);
    const findings = readFindingsFromJsonl(domain);
    const findingIdSet = new Set(findings.map((finding) => finding.id));
    const surfaceIdSet = buildSurfaceIdSet(domain, args.surface_ids);
    const attempt = normalizeChainAttemptRecord({
      version: CHAIN_ATTEMPT_VERSION,
      ts: new Date().toISOString(),
      attempt_id: `C-${existingAttempts.length + 1}`,
      target_domain: domain,
      finding_ids: args.finding_ids,
      surface_ids: args.surface_ids,
      hypothesis: args.hypothesis,
      steps: args.steps,
      outcome: args.outcome,
      evidence_summary: args.evidence_summary,
      request_refs: args.request_refs,
      auth_profiles: args.auth_profiles,
    }, {
      expectedDomain: domain,
      findingIdSet,
      surfaceIdSet,
    });

    const filePath = chainAttemptsJsonlPath(domain);
    appendJsonlLine(filePath, attempt);
    return JSON.stringify({
      version: 1,
      written: true,
      attempt_id: attempt.attempt_id,
      total: existingAttempts.length + 1,
      written_jsonl: filePath,
      attempt,
      summary: summarizeChainAttempts([...existingAttempts, attempt]),
    });
  });
}

function readChainAttempts(args) {
  const domain = assertNonEmptyString(args.target_domain, "target_domain");
  const attempts = readChainAttemptsFromJsonl(domain);
  return JSON.stringify({
    version: 1,
    target_domain: domain,
    attempts,
    summary: summarizeChainAttempts(attempts),
  });
}

module.exports = {
  CHAIN_ATTEMPT_VERSION,
  normalizeChainAttemptRecord,
  readChainAttempts,
  readChainAttemptsFromJsonl,
  summarizeChainAttempts,
  writeChainAttempt,
};
