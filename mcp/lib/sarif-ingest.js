"use strict";

const fs = require("fs");
const path = require("path");
const { redactUrlSensitiveValues } = require("../redaction.js");
const {
  assertInteger,
  assertNonEmptyString,
  normalizeOptionalText,
} = require("./validation.js");
const {
  repoRunsDir,
  repoWorkDir,
  staticAnalysisResultsJsonlPath,
} = require("./paths.js");
const {
  appendJsonlLine,
  withSessionLock,
} = require("./storage.js");
const {
  readSessionStateStrict,
} = require("./session-state-store.js");
const {
  readJsonlRecords,
  redactStaticArtifactContent,
  shortSha256,
} = require("./static-artifacts.js");

const MAX_RESULTS = 500;
const MAX_SARIF_BYTES = 10 * 1024 * 1024;
const STATIC_ANALYSIS_RESULTS_MAX_RECORDS = 5_000;
const TEXT_FIELD_MAX_CHARS = 500;
const TOOL_NAME_MAX_CHARS = 120;
const TOOL_VERSION_MAX_CHARS = 80;
const RULE_ID_MAX_CHARS = 160;
const ARTIFACT_URI_MAX_CHARS = 260;
const FINGERPRINT_MAX_CHARS = 180;
const SUMMARY_MESSAGE_MAX_CHARS = 160;
const SUMMARY_RECORD_LIMIT = 5;
const SUMMARY_WARNING_LIMIT = 10;
const SAFE_RUN_ID_RE = /^[A-Za-z0-9._-]+$/;

let staticAnalysisIndexer = null;

function registerStaticAnalysisIndexer(indexer) {
  staticAnalysisIndexer = typeof indexer === "function" ? indexer : null;
}

function isObject(value) {
  return value != null && typeof value === "object" && !Array.isArray(value);
}

function truncateText(value, maxChars = TEXT_FIELD_MAX_CHARS) {
  const text = String(value == null ? "" : value).replace(/\s+/g, " ").trim();
  return text.length > maxChars ? `${text.slice(0, maxChars - 3)}...` : text;
}

function optionalText(value) {
  if (typeof value !== "string") return null;
  const normalized = value.trim();
  return normalized ? normalized : null;
}

function redactSarifText(value) {
  if (value == null) return null;
  const redacted = redactStaticArtifactContent(String(value));
  const urlRedacted = redactUrlSensitiveValues(redacted.content);
  return truncateText(urlRedacted == null ? redacted.content : urlRedacted);
}

function safeDecode(value) {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}

function stripUriQueryAndFragment(value) {
  const marker = value.search(/[?#]/);
  return marker >= 0 ? value.slice(0, marker) : value;
}

function normalizeArtifactUri(rawUri) {
  if (typeof rawUri !== "string" || !rawUri.trim()) return null;
  let uri = rawUri.trim();
  if (/^[A-Za-z][A-Za-z0-9+.-]*:/.test(uri)) {
    try {
      const parsed = new URL(uri);
      if (parsed.protocol !== "file:") return null;
      uri = parsed.pathname;
    } catch {
      uri = uri.replace(/^file:\/+/, "/");
    }
  }
  uri = stripUriQueryAndFragment(safeDecode(uri)).replace(/\\/g, "/");
  uri = uri.replace(/^\/src\/+/, "");
  uri = uri.replace(/^\.\/+/, "");
  if (uri.startsWith("/")) return null;
  const normalized = path.posix.normalize(uri);
  if (!normalized || normalized === "." || normalized.startsWith("../") || normalized === "..") {
    return null;
  }
  return normalized;
}

function normalizeLine(value) {
  return Number.isInteger(value) && value >= 1 ? value : null;
}

function severitySignalForLevel(level) {
  if (level === "error" || level === "warning" || level === "note") return level;
  return null;
}

function driverForRun(run) {
  const driver = isObject(run.tool) && isObject(run.tool.driver) ? run.tool.driver : {};
  const rules = Array.isArray(driver.rules) ? driver.rules : [];
  return { driver, rules };
}

function ruleForResult(result, rules) {
  if (Number.isInteger(result.ruleIndex) && result.ruleIndex >= 0 && isObject(rules[result.ruleIndex])) {
    return rules[result.ruleIndex];
  }
  return null;
}

function ruleIdForResult(result, rules) {
  if (typeof result.ruleId === "string" && result.ruleId.trim()) return result.ruleId.trim();
  const rule = ruleForResult(result, rules);
  if (rule && typeof rule.id === "string" && rule.id.trim()) return rule.id.trim();
  if (isObject(result.rule) && typeof result.rule.id === "string" && result.rule.id.trim()) {
    return result.rule.id.trim();
  }
  return null;
}

function severitySignalForResult(result, rules) {
  const directLevel = severitySignalForLevel(result.level);
  if (directLevel) return directLevel;
  const rule = ruleForResult(result, rules);
  const defaultConfiguration = rule && isObject(rule.defaultConfiguration)
    ? rule.defaultConfiguration
    : {};
  return severitySignalForLevel(defaultConfiguration.level) || "warning";
}

function messageForResult(result) {
  if (isObject(result.message)) {
    if (typeof result.message.text === "string") return result.message.text;
    if (typeof result.message.markdown === "string") return result.message.markdown;
  }
  return "";
}

function firstLocation(result) {
  if (!Array.isArray(result.locations) || result.locations.length === 0) return null;
  for (const location of result.locations) {
    if (!isObject(location) || !isObject(location.physicalLocation)) continue;
    return location.physicalLocation;
  }
  return null;
}

function artifactUriForPhysicalLocation(physicalLocation) {
  const artifactLocation = isObject(physicalLocation.artifactLocation)
    ? physicalLocation.artifactLocation
    : {};
  return normalizeArtifactUri(artifactLocation.uri);
}

function regionForPhysicalLocation(physicalLocation) {
  return isObject(physicalLocation.region) ? physicalLocation.region : {};
}

function snippetForRegion(region) {
  if (isObject(region.snippet) && typeof region.snippet.text === "string") {
    return region.snippet.text;
  }
  return null;
}

function fingerprintForResult(result, dedupeMaterial) {
  if (isObject(result.partialFingerprints)) {
    const entries = Object.keys(result.partialFingerprints)
      .sort()
      .map((key) => [
        truncateText(redactSarifText(key) || "", FINGERPRINT_MAX_CHARS),
        truncateText(redactSarifText(result.partialFingerprints[key]) || "", FINGERPRINT_MAX_CHARS),
      ]);
    if (entries.length > 0) return shortSha256(JSON.stringify(["sarif-partial-fingerprints", entries]));
  }
  return shortSha256(JSON.stringify(["sarif-fingerprint", ...dedupeMaterial]));
}

function normalizeSarifResultInternal(result, run, ctx = {}) {
  if (!isObject(result)) {
    return { record: null, warning: "SARIF result is not an object" };
  }
  if (!isObject(run)) {
    return { record: null, warning: "SARIF run is not an object" };
  }

  const { driver, rules } = driverForRun(run);
  const toolName = truncateText(optionalText(ctx.tool_name)
    || optionalText(driver.name)
    || "unknown", TOOL_NAME_MAX_CHARS);
  const toolVersion = truncateText(
    optionalText(driver.semanticVersion) || optionalText(driver.version) || "",
    TOOL_VERSION_MAX_CHARS,
  ) || null;
  const ruleId = ruleIdForResult(result, rules);
  if (!ruleId) return { record: null, warning: "SARIF result missing ruleId" };
  const safeRuleId = truncateText(ruleId, RULE_ID_MAX_CHARS);

  const physicalLocation = firstLocation(result);
  if (!physicalLocation) return { record: null, warning: `SARIF result ${safeRuleId} missing physicalLocation` };
  const artifactUriRaw = artifactUriForPhysicalLocation(physicalLocation);
  const artifactUri = artifactUriRaw ? truncateText(artifactUriRaw, ARTIFACT_URI_MAX_CHARS) : null;
  if (!artifactUri) return { record: null, warning: `SARIF result ${safeRuleId} missing repo-relative artifact uri` };
  const region = regionForPhysicalLocation(physicalLocation);
  const startLine = normalizeLine(region.startLine);
  if (startLine == null) return { record: null, warning: `SARIF result ${safeRuleId} missing startLine` };
  const endLine = normalizeLine(region.endLine) || startLine;
  const message = redactSarifText(messageForResult(result)) || "";
  const snippet = redactSarifText(snippetForRegion(region));
  const dedupeMaterial = [toolName, safeRuleId, artifactUri, startLine, message];
  const resultSha256 = shortSha256(JSON.stringify(dedupeMaterial));

  return {
    record: {
      tool_name: toolName,
      tool_version: toolVersion,
      rule_id: safeRuleId,
      severity_signal: severitySignalForResult(result, rules),
      message,
      snippet,
      artifact_uri: artifactUri,
      start_line: startLine,
      end_line: endLine,
      fingerprint: fingerprintForResult(result, dedupeMaterial),
      result_sha256: resultSha256,
      source_run_id: optionalText(ctx.source_run_id),
    },
    warning: null,
  };
}

function normalizeSarifResult(result, run, ctx = {}) {
  return normalizeSarifResultInternal(result, run, ctx).record;
}

function parseSarif(jsonText, ctx = {}) {
  const warnings = [];
  let parsed;
  try {
    parsed = JSON.parse(String(jsonText || ""));
  } catch (error) {
    return {
      records: [],
      warnings: [`Malformed SARIF JSON: ${error.message || String(error)}`],
      total_results: 0,
      skipped_results: 0,
      truncated: false,
    };
  }

  if (!isObject(parsed)) {
    return {
      records: [],
      warnings: ["Malformed SARIF JSON: expected object document"],
      total_results: 0,
      skipped_results: 0,
      truncated: false,
    };
  }

  const runs = Array.isArray(parsed.runs) ? parsed.runs : [];
  const records = [];
  let totalResults = 0;
  let processedResults = 0;
  let skippedResults = 0;
  let truncated = false;

  for (let runIndex = 0; runIndex < runs.length; runIndex += 1) {
    const run = runs[runIndex];
    if (!isObject(run)) {
      warnings.push(`SARIF run ${runIndex} is not an object; skipped`);
      continue;
    }
    const results = Array.isArray(run.results) ? run.results : [];
    totalResults += results.length;
    if (processedResults >= MAX_RESULTS) {
      truncated = true;
      if (results.length > 0) {
        warnings.push(`SARIF result cap ${MAX_RESULTS} reached before run ${runIndex}; skipped ${results.length} result(s)`);
      }
      continue;
    }
    const remaining = MAX_RESULTS - processedResults;
    const limit = Math.min(results.length, remaining);
    if (results.length > limit) {
      truncated = true;
      warnings.push(`SARIF run ${runIndex} has ${results.length} results; processed first ${limit}`);
    }
    for (let resultIndex = 0; resultIndex < limit; resultIndex += 1) {
      processedResults += 1;
      let normalized;
      try {
        normalized = normalizeSarifResultInternal(results[resultIndex], run, ctx);
      } catch (error) {
        normalized = {
          record: null,
          warning: error.message || String(error),
        };
      }
      const { record, warning } = normalized;
      if (record) {
        records.push(record);
      } else {
        skippedResults += 1;
        warnings.push(`run ${runIndex} result ${resultIndex}: ${warning || "skipped"}`);
      }
    }
  }

  return {
    records,
    warnings,
    total_results: totalResults,
    skipped_results: skippedResults,
    truncated,
  };
}

function normalizeStaticAnalysisResultRecord(record, lineNumber = null) {
  if (!isObject(record)) {
    throw new Error(lineNumber == null
      ? "static analysis result must be an object"
      : `Malformed static-analysis-results.jsonl at line ${lineNumber}: expected object`);
  }
  try {
    return {
      version: record.version == null ? 1 : assertInteger(record.version, "version", { min: 1, max: 1 }),
      target_domain: assertNonEmptyString(record.target_domain, "target_domain"),
      created_at: assertNonEmptyString(record.created_at, "created_at"),
      tool_name: truncateText(assertNonEmptyString(record.tool_name, "tool_name"), TOOL_NAME_MAX_CHARS),
      tool_version: truncateText(normalizeOptionalText(record.tool_version, "tool_version") || "", TOOL_VERSION_MAX_CHARS) || null,
      rule_id: truncateText(assertNonEmptyString(record.rule_id, "rule_id"), RULE_ID_MAX_CHARS),
      severity_signal: assertNonEmptyString(record.severity_signal, "severity_signal"),
      message: typeof record.message === "string" ? truncateText(record.message) : "",
      snippet: record.snippet == null ? null : truncateText(record.snippet),
      artifact_uri: truncateText(assertNonEmptyString(record.artifact_uri, "artifact_uri"), ARTIFACT_URI_MAX_CHARS),
      start_line: assertInteger(record.start_line, "start_line", { min: 1 }),
      end_line: assertInteger(record.end_line, "end_line", { min: 1 }),
      fingerprint: truncateText(assertNonEmptyString(record.fingerprint, "fingerprint"), FINGERPRINT_MAX_CHARS),
      result_sha256: assertNonEmptyString(record.result_sha256, "result_sha256"),
      source_run_id: normalizeOptionalText(record.source_run_id, "source_run_id"),
    };
  } catch (error) {
    if (lineNumber == null) throw error;
    throw new Error(`Malformed static-analysis-results.jsonl at line ${lineNumber}: ${error.message || String(error)}`);
  }
}

function readStaticAnalysisResultsFromJsonl(domain, filters = {}) {
  const normalizedDomain = assertNonEmptyString(domain, "target_domain");
  const records = readJsonlRecords(
    staticAnalysisResultsJsonlPath(normalizedDomain),
    "static-analysis-results.jsonl",
    (record, lineNumber) => normalizeStaticAnalysisResultRecord(record, lineNumber),
  ).filter((record) => record.target_domain === normalizedDomain);
  return records.filter((record) => (
    (filters.tool_name == null || record.tool_name === filters.tool_name) &&
    (filters.rule_id == null || record.rule_id === filters.rule_id) &&
    (filters.artifact_uri == null || record.artifact_uri === filters.artifact_uri)
  ));
}

function assertWithinRoot(resolvedPath, rootPath, label) {
  const normalizedRoot = path.resolve(rootPath);
  const normalized = path.resolve(resolvedPath);
  if (normalized !== normalizedRoot && !normalized.startsWith(`${normalizedRoot}${path.sep}`)) {
    throw new Error(`${label} escapes allowed root`);
  }
  return normalized;
}

function assertExistingFileWithinRoot(filePath, rootPath, label) {
  const resolved = assertWithinRoot(filePath, rootPath, label);
  let rootReal;
  let fileReal;
  try {
    rootReal = fs.realpathSync(rootPath);
    fileReal = fs.realpathSync(resolved);
  } catch {
    throw new Error(`${label} is not readable`);
  }
  if (fileReal !== rootReal && !fileReal.startsWith(`${rootReal}${path.sep}`)) {
    throw new Error(`${label} escapes allowed root via symlink`);
  }
  let stat;
  try {
    stat = fs.statSync(fileReal);
  } catch {
    throw new Error(`${label} is not readable`);
  }
  if (!stat.isFile()) {
    throw new Error(`${label} must be a file`);
  }
  return fileReal;
}

function normalizeRunId(value) {
  const runId = assertNonEmptyString(value, "run_id");
  if (!SAFE_RUN_ID_RE.test(runId)) {
    throw new Error("run_id may only contain letters, numbers, dot, underscore, and dash");
  }
  return runId;
}

function resolveSarifSourcePath(domain, { run_id: runIdRaw = null, artifact_path: artifactPathRaw = null } = {}) {
  const hasRunId = runIdRaw != null;
  const hasArtifactPath = artifactPathRaw != null;
  if (hasRunId === hasArtifactPath) {
    throw new Error("Provide exactly one of run_id or artifact_path");
  }

  if (hasRunId) {
    const runId = normalizeRunId(runIdRaw);
    const runsRoot = repoRunsDir(domain);
    const stdoutPath = path.join(runsRoot, `${runId}.stdout`);
    return {
      source_run_id: runId,
      source_kind: "run_stdout",
      display_path: `repo-runs/${runId}.stdout`,
      absolute_path: assertExistingFileWithinRoot(stdoutPath, runsRoot, "run_id stdout path"),
    };
  }

  const artifactPath = assertNonEmptyString(artifactPathRaw, "artifact_path");
  const workRoot = repoWorkDir(domain);
  let resolved;
  if (artifactPath === "/work" || artifactPath === "/work/") {
    throw new Error("artifact_path must name a file under /work");
  } else if (artifactPath.startsWith("/work/")) {
    resolved = path.join(workRoot, artifactPath.slice("/work/".length));
  } else if (path.isAbsolute(artifactPath)) {
    resolved = artifactPath;
  } else {
    resolved = path.join(workRoot, artifactPath);
  }
  const absolutePath = assertExistingFileWithinRoot(resolved, workRoot, "artifact_path");
  return {
    source_run_id: null,
    source_kind: "work_artifact",
    display_path: artifactPath.startsWith("/work/") ? artifactPath : `/work/${path.relative(workRoot, absolutePath)}`,
    absolute_path: absolutePath,
  };
}

function compactRecordForResponse(record) {
  return {
    tool_name: truncateText(record.tool_name, TOOL_NAME_MAX_CHARS),
    rule_id: truncateText(record.rule_id, RULE_ID_MAX_CHARS),
    severity_signal: record.severity_signal,
    artifact_uri: truncateText(record.artifact_uri, ARTIFACT_URI_MAX_CHARS),
    start_line: record.start_line,
    result_sha256: record.result_sha256,
    message: truncateText(record.message, SUMMARY_MESSAGE_MAX_CHARS),
  };
}

function indexSourcePathForStaticAnalysis(source) {
  if (source.source_kind === "work_artifact" && source.display_path.startsWith("/work/")) {
    return `repo-work/${source.display_path.slice("/work/".length)}`;
  }
  return source.display_path;
}

function readSarifSourceUtf8(source) {
  let fd = null;
  try {
    fd = fs.openSync(source.absolute_path, "r");
    const stats = fs.fstatSync(fd);
    if (!stats.isFile()) {
      throw new Error(`${source.display_path} must be a file`);
    }
    if (stats.size > MAX_SARIF_BYTES) {
      throw new Error(`${source.display_path} exceeds SARIF read cap of ${MAX_SARIF_BYTES} bytes`);
    }
    return fs.readFileSync(fd, "utf8");
  } catch (error) {
    const message = error && error.message ? error.message : String(error);
    if (message.startsWith(`${source.display_path} must be a file`)
      || message.startsWith(`${source.display_path} exceeds SARIF read cap`)) {
      throw error;
    }
    throw new Error(`${source.display_path} could not be read`);
  } finally {
    if (fd != null) {
      try { fs.closeSync(fd); } catch {}
    }
  }
}

function ingestSarif(args = {}) {
  const domain = assertNonEmptyString(args.target_domain, "target_domain");
  const toolName = normalizeOptionalText(args.tool_name, "tool_name");
  readSessionStateStrict(domain);
  const source = resolveSarifSourcePath(domain, args);
  const jsonText = readSarifSourceUtf8(source);
  const parsed = parseSarif(jsonText, {
    source_run_id: source.source_run_id,
    tool_name: toolName,
  });
  const createdAt = new Date().toISOString();
  let duplicateResults = 0;
  const ingested = [];

  withSessionLock(domain, () => {
    const existingHashes = new Set(readStaticAnalysisResultsFromJsonl(domain).map((record) => record.result_sha256));
    for (const result of parsed.records) {
      if (existingHashes.has(result.result_sha256)) {
        duplicateResults += 1;
        continue;
      }
      const record = normalizeStaticAnalysisResultRecord({
        version: 1,
        target_domain: domain,
        created_at: createdAt,
        ...result,
      });
      appendJsonlLine(staticAnalysisResultsJsonlPath(domain), record, {
        maxRecords: STATIC_ANALYSIS_RESULTS_MAX_RECORDS,
      });
      existingHashes.add(record.result_sha256);
      ingested.push(record);
    }
  });

  let indexResponse = null;
  if (parsed.records.length > 0 && staticAnalysisIndexer) {
    indexResponse = staticAnalysisIndexer(domain, {
      run_id: source.source_run_id,
      stdout_path: indexSourcePathForStaticAnalysis(source),
      tool: toolName,
    });
  }

  return JSON.stringify({
    version: 1,
    target_domain: domain,
    source: {
      kind: source.source_kind,
      run_id: source.source_run_id,
      artifact_path: source.display_path,
    },
    results_seen: parsed.total_results,
    normalized_results: parsed.records.length,
    ingested_results: ingested.length,
    duplicate_results: duplicateResults,
    skipped_results: parsed.skipped_results,
    truncated: parsed.truncated,
    warning_count: parsed.warnings.length,
    warnings: parsed.warnings.slice(0, SUMMARY_WARNING_LIMIT),
    results_path: "static-analysis-results.jsonl",
    ...(indexResponse ? {
      index_path: "static-analysis-index.jsonl",
      static_analysis_index: {
        indexed_results: indexResponse.indexed_results,
        duplicate_results: indexResponse.duplicate_results,
        total_records: indexResponse.total_records,
        static_analysis_leads: indexResponse.static_analysis_leads,
      },
    } : {}),
    records: ingested.slice(0, SUMMARY_RECORD_LIMIT).map(compactRecordForResponse),
    records_omitted: Math.max(0, ingested.length - SUMMARY_RECORD_LIMIT),
    doctrine: "lead_seed_only_no_findings_or_skips",
  }, null, 2);
}

module.exports = {
  MAX_RESULTS,
  MAX_SARIF_BYTES,
  ingestSarif,
  normalizeSarifResult,
  normalizeStaticAnalysisResultRecord,
  parseSarif,
  readStaticAnalysisResultsFromJsonl,
  registerStaticAnalysisIndexer,
  resolveSarifSourcePath,
};
