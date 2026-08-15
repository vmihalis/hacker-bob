"use strict";

// Session-owned fuzz-harness import store (bob_import_harness). Modeled on
// static-artifacts.js: content-only, redacted, capped, written under a session
// `harnesses/` dir with a `harnesses.jsonl` provenance ledger. MCP-write-only scratch
// (the agent Write tool is fenced from harnesses/ — provenance flows only through the
// tool). NOT audit-graded. Consumed by the OSS native-fuzz lane when the target repo
// ships no LLVMFuzzerTestOneInput harness of its own (the common case — harnesses live
// in OSS-Fuzz, not the project repo), so bob can build + fuzz it anyway.

const {
  HARNESS_LOG_MAX_RECORDS,
  HARNESS_MAX_CHARS,
} = require("../lib/constants.js");
const {
  assertEnumValue,
  assertInteger,
  assertNonEmptyString,
  assertRequiredText,
  normalizeOptionalText,
} = require("./io/validation.js");
const {
  assertHarnessId,
  harnessPath,
  harnessesJsonlPath,
} = require("./io/paths.js");
const {
  appendJsonlLine,
  withSessionLock,
  writeFileAtomic,
} = require("./io/storage.js");
const {
  readSessionStateStrict,
} = require("./session/session-state-store.js");
const {
  redactStaticArtifactContent,
  readJsonlRecords,
  shortSha256,
} = require("../domains/repo/static-artifacts.js");

const HARNESS_LANGUAGE_VALUES = ["c", "cpp"];
const HARNESS_SOURCE_VALUES = ["operator", "oss_fuzz_ingest", "llm_synth"];

function rejectPathImport(args) {
  for (const key of ["path", "file_path", "filename", "harness_path", "source_path"]) {
    if (Object.prototype.hasOwnProperty.call(args, key)) {
      throw new Error("Path imports are not supported. Pass harness content to bob_import_harness.");
    }
  }
}

function normalizeTargetIncludes(value) {
  if (value == null) return [];
  if (!Array.isArray(value)) throw new Error("target_includes must be an array of strings");
  const out = [];
  for (const entry of value) {
    const s = normalizeOptionalText(entry, "target_includes[]");
    if (s) out.push(s.replace(/[^A-Za-z0-9._/+-]/g, "_").slice(0, 200));
    if (out.length >= 32) break;
  }
  return out;
}

function normalizeHarnessRecord(record, lineNumber = null) {
  if (record == null || typeof record !== "object" || Array.isArray(record)) {
    throw new Error(lineNumber == null
      ? "harness record must be an object"
      : `Malformed harnesses.jsonl at line ${lineNumber}: expected object`);
  }
  try {
    return {
      version: record.version == null ? 1 : assertInteger(record.version, "version", { min: 1, max: 1 }),
      target_domain: assertNonEmptyString(record.target_domain, "target_domain"),
      harness_id: assertHarnessId(record.harness_id),
      language: assertEnumValue(record.language, HARNESS_LANGUAGE_VALUES, "language"),
      source: assertEnumValue(record.source, HARNESS_SOURCE_VALUES, "source"),
      source_url: normalizeOptionalText(record.source_url, "source_url"),
      imported_at: assertNonEmptyString(record.imported_at, "imported_at"),
      content_sha256: assertNonEmptyString(record.content_sha256, "content_sha256"),
      original_chars: assertInteger(record.original_chars, "original_chars", { min: 1 }),
      stored_chars: assertInteger(record.stored_chars, "stored_chars", { min: 1 }),
      redactions: assertInteger(record.redactions || 0, "redactions", { min: 0 }),
      target_includes: Array.isArray(record.target_includes)
        ? record.target_includes.map(String).slice(0, 32)
        : [],
      harness_path: normalizeOptionalText(record.harness_path, "harness_path"),
    };
  } catch (error) {
    if (lineNumber == null) throw error;
    throw new Error(`Malformed harnesses.jsonl at line ${lineNumber}: ${error.message || String(error)}`);
  }
}

function readHarnessRecordsFromJsonl(domain) {
  return readJsonlRecords(
    harnessesJsonlPath(domain),
    "harnesses.jsonl",
    (record, lineNumber) => normalizeHarnessRecord(record, lineNumber),
  ).filter((record) => record.target_domain === domain);
}

function nextHarnessId(records) {
  let max = 0;
  for (const record of records) {
    const match = String(record.harness_id || "").match(/^H-([1-9]\d*)$/);
    if (match) max = Math.max(max, Number(match[1]));
  }
  return `H-${max + 1}`;
}

// Read-side predicate used by the inventory to flip native_fuzz_shape on when the
// repo itself has no harness but one has been imported for the session.
function hasAcquiredHarness(domain) {
  try {
    return readHarnessRecordsFromJsonl(domain).length > 0;
  } catch {
    return false;
  }
}

function importHarness(args) {
  rejectPathImport(args || {});
  const domain = assertNonEmptyString(args.target_domain, "target_domain");
  const language = args.language == null
    ? "cpp"
    : assertEnumValue(args.language, HARNESS_LANGUAGE_VALUES, "language");
  const source = args.source == null
    ? "operator"
    : assertEnumValue(args.source, HARNESS_SOURCE_VALUES, "source");
  const sourceUrl = normalizeOptionalText(args.source_url, "source_url");
  const targetIncludes = normalizeTargetIncludes(args.target_includes);
  const originalContent = assertRequiredText(args.content, "content");
  if (originalContent.length > HARNESS_MAX_CHARS) {
    throw new Error(`content exceeds harness cap of ${HARNESS_MAX_CHARS} characters`);
  }
  // A usable libFuzzer entry point must define LLVMFuzzerTestOneInput. Reject at import
  // rather than discover the failure inside the docker build at fuzz time.
  if (!/LLVMFuzzerTestOneInput/.test(originalContent)) {
    throw new Error("harness content must define LLVMFuzzerTestOneInput");
  }
  readSessionStateStrict(domain);

  const redacted = redactStaticArtifactContent(originalContent);
  const importedAt = new Date().toISOString();

  return withSessionLock(domain, () => {
    const records = readHarnessRecordsFromJsonl(domain);
    const harnessId = nextHarnessId(records);
    const filePath = harnessPath(domain, harnessId);
    writeFileAtomic(filePath, redacted.content);

    const record = normalizeHarnessRecord({
      version: 1,
      target_domain: domain,
      harness_id: harnessId,
      language,
      source,
      source_url: sourceUrl,
      imported_at: importedAt,
      content_sha256: shortSha256(redacted.content),
      original_chars: originalContent.length,
      stored_chars: redacted.content.length,
      redactions: redacted.redactions,
      target_includes: targetIncludes,
      harness_path: filePath,
    });
    appendJsonlLine(harnessesJsonlPath(domain), record, { maxRecords: HARNESS_LOG_MAX_RECORDS });

    return {
      version: 1,
      target_domain: domain,
      harness_id: harnessId,
      language,
      source,
      content_sha256: record.content_sha256,
      original_chars: record.original_chars,
      stored_chars: record.stored_chars,
      redactions: record.redactions,
      target_includes: targetIncludes,
      harness_path: filePath,
    };
  });
}

module.exports = {
  importHarness,
  hasAcquiredHarness,
  normalizeHarnessRecord,
  readHarnessRecordsFromJsonl,
  HARNESS_LANGUAGE_VALUES,
  HARNESS_SOURCE_VALUES,
};
