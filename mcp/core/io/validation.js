"use strict";

const {
  AGENT_ID_RE,
  FINDING_ID_RE,
  WAVE_ID_RE,
} = require("./identifier-contracts.js");
const {
  canonicalizeCwe,
  assertValidCwe,
  isKnownCwe,
} = require("../scoring/cwe-catalog.js");
const {
  cloneJson,
  isPlainObject,
} = require("../verification/verification-contracts.js");
const {
  validateNoSensitiveMaterial,
} = require("../redaction/sensitive-material.js");

function assertNonEmptyString(value, fieldName) {
  if (typeof value !== "string" || !value.trim()) {
    throw new Error(`${fieldName} must be a non-empty string`);
  }
  return value.trim();
}

function parseWaveId(value, fieldName = "wave") {
  const wave = assertNonEmptyString(value, fieldName);
  if (!WAVE_ID_RE.test(wave)) {
    throw new Error(`${fieldName} must match wN`);
  }
  return wave;
}

function parseAgentId(value, fieldName = "agent") {
  const agent = assertNonEmptyString(value, fieldName);
  if (!AGENT_ID_RE.test(agent)) {
    throw new Error(`${fieldName} must match aN`);
  }
  return agent;
}

function parseWaveNumber(value, fieldName = "wave_number") {
  if (!Number.isInteger(value) || value < 1) {
    throw new Error(`${fieldName} must be a positive integer`);
  }
  return value;
}

function parseSurfaceStatus(value) {
  if (value !== "complete" && value !== "partial") {
    throw new Error(`surface_status must be "complete" or "partial"`);
  }
  return value;
}

function normalizeStringArray(value, fieldName) {
  if (value == null) return [];
  if (!Array.isArray(value)) {
    throw new Error(`${fieldName} must be an array of strings`);
  }

  const normalized = [];
  const seen = new Set();
  for (const item of value) {
    if (typeof item !== "string") {
      throw new Error(`${fieldName} must contain only strings`);
    }
    const trimmed = item.trim();
    if (!trimmed || seen.has(trimmed)) continue;
    seen.add(trimmed);
    normalized.push(trimmed);
  }
  return normalized;
}

function pushUnique(target, seen, values) {
  for (const value of values) {
    if (seen.has(value)) continue;
    seen.add(value);
    target.push(value);
  }
}

function compareAgentLabels(a, b) {
  const aMatch = typeof a === "string" && a.match(AGENT_ID_RE);
  const bMatch = typeof b === "string" && b.match(AGENT_ID_RE);

  if (aMatch && bMatch) {
    return Number(aMatch[1]) - Number(bMatch[1]);
  }
  if (aMatch) return -1;
  if (bMatch) return 1;
  return String(a).localeCompare(String(b));
}

function assertRequiredText(value, fieldName) {
  if (typeof value !== "string" || !value.trim()) {
    throw new Error(`${fieldName} must be a non-empty string`);
  }
  return value.trim();
}

function normalizeOptionalText(value, fieldName) {
  if (value == null) return null;
  if (typeof value !== "string") {
    throw new Error(`${fieldName} must be a string or null`);
  }
  const normalized = value.trim();
  return normalized ? normalized : null;
}

function assertBoolean(value, fieldName) {
  if (typeof value !== "boolean") {
    throw new Error(`${fieldName} must be a boolean`);
  }
  return value;
}

function assertInteger(value, fieldName, { min = undefined, max = undefined } = {}) {
  if (!Number.isInteger(value)) {
    throw new Error(`${fieldName} must be an integer`);
  }
  if (min != null && value < min) {
    throw new Error(`${fieldName} must be >= ${min}`);
  }
  if (max != null && value > max) {
    throw new Error(`${fieldName} must be <= ${max}`);
  }
  return value;
}

function normalizeOptionalInteger(value, fieldName, { min = undefined, max = undefined } = {}) {
  if (value == null) return null;
  return assertInteger(value, fieldName, { min, max });
}

function normalizeIsoTimestamp(value, fieldName = "ts", fallback = new Date()) {
  if (value == null) {
    if (fallback instanceof Date && Number.isFinite(fallback.getTime())) {
      return fallback.toISOString();
    }
    throw new Error(`${fieldName} must be an ISO timestamp`);
  }
  if (value instanceof Date && Number.isFinite(value.getTime())) {
    return value.toISOString();
  }
  if (typeof value !== "string" || !value.trim()) {
    throw new Error(`${fieldName} must be an ISO timestamp`);
  }
  const parsedMs = Date.parse(value.trim());
  if (!Number.isFinite(parsedMs)) {
    throw new Error(`${fieldName} must be an ISO timestamp`);
  }
  return new Date(parsedMs).toISOString();
}

function normalizePlainObject(value, fieldName, { defaultValue = undefined, maxTextChars, bypassValuePaths } = {}) {
  if (value == null && defaultValue !== undefined) {
    return cloneJson(defaultValue);
  }
  if (!isPlainObject(value)) {
    throw new Error(`${fieldName} must be an object`);
  }
  const cloned = cloneJson(value);
  const validatorOptions = {};
  if (maxTextChars != null) validatorOptions.maxTextChars = maxTextChars;
  if (bypassValuePaths != null) validatorOptions.bypassValuePaths = bypassValuePaths;
  validateNoSensitiveMaterial(
    cloned,
    fieldName,
    Object.keys(validatorOptions).length > 0 ? validatorOptions : undefined,
  );
  return cloned;
}

function normalizeOptionalObject(value, fieldName, options = {}) {
  if (value == null) return null;
  return normalizePlainObject(value, fieldName, options);
}

function normalizeReferenceArray(value, fieldName = "refs") {
  if (value == null) return [];
  if (!Array.isArray(value)) {
    throw new Error(`${fieldName} must be an array`);
  }
  return value.map((entry, index) =>
    normalizePlainObject(entry, `${fieldName}[${index}]`));
}

function normalizeOptionalTextArray(value, fieldName) {
  return normalizeStringArray(value, fieldName);
}

function normalizeId(value, fieldName, { maxLength = 200 } = {}) {
  const text = assertNonEmptyString(value, fieldName);
  if (text.length > maxLength) {
    throw new Error(`${fieldName} must be ${maxLength} characters or fewer`);
  }
  return text;
}

function normalizeOptionalId(value, fieldName, options = {}) {
  const text = normalizeOptionalText(value, fieldName);
  return text == null ? null : normalizeId(text, fieldName, options);
}

function normalizePositiveInteger(value, fieldName, { defaultValue = null, max = undefined } = {}) {
  if (value == null) return defaultValue;
  return assertInteger(value, fieldName, { min: 1, max });
}

function sortByTextField(fieldName) {
  return (a, b) => String(a[fieldName] || "").localeCompare(String(b[fieldName] || ""));
}

function assertEnumValue(value, allowedValues, fieldName) {
  if (!allowedValues.includes(value)) {
    throw new Error(`${fieldName} must be one of ${allowedValues.join(", ")}`);
  }
  return value;
}

function assertCwe(value, fieldName = "cwe", { required = false, strictPresent = true } = {}) {
  const empty = value == null || (typeof value === "string" && !value.trim());
  if (empty) {
    if (required) {
      throw new Error(`${fieldName} is required and must be a catalog CWE id (e.g. "CWE-79"); see mcp/core/scoring/cwe-catalog.js for the accepted set`);
    }
    return null;
  }
  if (!strictPresent) {
    // Tolerant read-back: a present-but-unparseable or non-catalog CWE is
    // degraded to null rather than throwing, so a legacy claim row whose
    // embedded CWE predates the curated catalog (or used free text) still
    // projects instead of being silently dropped by a caller's catch.
    return isKnownCwe(value) ? canonicalizeCwe(value) : null;
  }
  const canonical = canonicalizeCwe(value);
  if (canonical == null) {
    throw new Error(`${fieldName} must be a CWE identifier like "CWE-79"; got ${JSON.stringify(value)}`);
  }
  return assertValidCwe(canonical);
}

function parseFindingId(value, fieldName = "finding_id") {
  const findingId = assertNonEmptyString(value, fieldName);
  if (!FINDING_ID_RE.test(findingId)) {
    throw new Error(`${fieldName} must match F-N`);
  }
  return findingId;
}

module.exports = {
  assertBoolean,
  assertCwe,
  assertEnumValue,
  assertInteger,
  assertNonEmptyString,
  assertRequiredText,
  compareAgentLabels,
  normalizeId,
  normalizeIsoTimestamp,
  normalizeOptionalId,
  normalizeOptionalInteger,
  normalizeOptionalObject,
  normalizeOptionalText,
  normalizeOptionalTextArray,
  normalizePlainObject,
  normalizePositiveInteger,
  normalizeReferenceArray,
  normalizeStringArray,
  parseAgentId,
  parseFindingId,
  parseSurfaceStatus,
  parseWaveId,
  parseWaveNumber,
  pushUnique,
  sortByTextField,
};
