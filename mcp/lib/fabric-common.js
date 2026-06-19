"use strict";

const fs = require("fs");
const path = require("path");
const {
  assertInteger,
  assertNonEmptyString,
  normalizeOptionalText,
  normalizeStringArray,
} = require("./validation.js");
const {
  cloneJson,
  hashCanonicalJson,
  isPlainObject,
} = require("./verification-contracts.js");
const {
  readFileUtf8,
  writeFileAtomic,
} = require("./storage.js");
const {
  validateNoSensitiveMaterial,
} = require("./sensitive-material.js");

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

function hashDocumentExcluding(document, fields) {
  const copy = cloneJson(document);
  for (const field of fields) {
    delete copy[field];
  }
  return hashCanonicalJson(copy);
}

function withDocumentHash(document, fieldName) {
  const copy = cloneJson(document);
  copy[fieldName] = hashDocumentExcluding(copy, [fieldName]);
  return copy;
}

function readJsonlStrict(filePath, label, normalizeRecord) {
  if (!fs.existsSync(filePath)) return [];
  const raw = readFileUtf8(filePath, { label });
  const lines = raw.split(/\r?\n/).filter((line) => line.trim().length > 0);
  const records = [];
  for (let i = 0; i < lines.length; i++) {
    let parsed;
    try {
      parsed = JSON.parse(lines[i]);
    } catch (error) {
      throw new Error(`Malformed ${label} at line ${i + 1}: ${error.message || String(error)}`);
    }
    records.push(normalizeRecord ? normalizeRecord(parsed, i) : parsed);
  }
  return records;
}

function writeJsonDocument(filePath, document) {
  writeFileAtomic(filePath, `${JSON.stringify(document, null, 2)}\n`);
}

function sortByTextField(fieldName) {
  return (a, b) => String(a[fieldName] || "").localeCompare(String(b[fieldName] || ""));
}

function ensureParentDir(filePath) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
}

module.exports = {
  ensureParentDir,
  hashDocumentExcluding,
  normalizeId,
  normalizeIsoTimestamp,
  normalizeOptionalId,
  normalizeOptionalObject,
  normalizeOptionalTextArray,
  normalizePlainObject,
  normalizePositiveInteger,
  normalizeReferenceArray,
  readJsonlStrict,
  sortByTextField,
  withDocumentHash,
  writeJsonDocument,
};
