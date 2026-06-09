"use strict";

const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const {
  ERROR_CODES,
  ToolError,
} = require("./envelope.js");
const {
  assertInteger,
  assertNonEmptyString,
  normalizeOptionalText,
} = require("./validation.js");
const {
  sessionDir,
  staticAnalysisIndexPath,
} = require("./paths.js");
const {
  parseSarif,
  normalizeSarifResult,
  readStaticAnalysisResultsFromJsonl,
  MAX_SARIF_BYTES,
} = require("./sarif-ingest.js");
const {
  normalizeSurfaceLead,
  SURFACE_LEAD_ITEM_MAX_CHARS,
} = require("./lead-intake.js");
const {
  readJsonlRecords,
  redactStaticArtifactContent,
} = require("./static-artifacts.js");
const {
  readFileUtf8,
  withSessionLock,
  writeFileAtomic,
} = require("./storage.js");
const {
  readSessionStateStrict,
} = require("./session-state-store.js");
const {
  redactTextSensitiveValues,
  validateNoSensitiveMaterial,
} = require("./sensitive-material.js");

const STATIC_ANALYSIS_INDEX_VERSION = 1;
const STATIC_ANALYSIS_INDEX_MAX_RECORDS = 500;
const STATIC_ANALYSIS_INDEX_DEFAULT_TOP_K = 20;
const STATIC_ANALYSIS_INDEX_MAX_TOP_K = 20;
const STATIC_ANALYSIS_INDEX_SUMMARY_RECORD_LIMIT = 5;
const STATIC_ANALYSIS_INDEX_WARNING_LIMIT = 10;
const STATIC_ANALYSIS_INDEX_MESSAGE_MAX_CHARS = SURFACE_LEAD_ITEM_MAX_CHARS;
const TOOL_MAX_CHARS = 120;
const RULE_ID_MAX_CHARS = 160;
const PATH_MAX_CHARS = 260;
const TAG_MAX_CHARS = 120;
const CWE_MAX_CHARS = 40;
const SEVERITY_RANK = Object.freeze({ error: 0, warning: 1, note: 2 });

function isObject(value) {
  return value != null && typeof value === "object" && !Array.isArray(value);
}

function sha256Hex(value) {
  return crypto.createHash("sha256").update(String(value), "utf8").digest("hex");
}

function truncateText(value, maxChars = STATIC_ANALYSIS_INDEX_MESSAGE_MAX_CHARS) {
  const text = String(value == null ? "" : value).replace(/\s+/g, " ").trim();
  return text.length > maxChars ? text.slice(0, maxChars) : text;
}

function scrubText(value, fieldName) {
  if (value == null) return null;
  const staticRedacted = redactStaticArtifactContent(String(value)).content;
  const redacted = redactTextSensitiveValues(staticRedacted);
  const truncated = truncateText(redacted);
  validateNoSensitiveMaterial(truncated, fieldName, {
    maxTextChars: STATIC_ANALYSIS_INDEX_MESSAGE_MAX_CHARS,
  });
  return truncated;
}

function optionalString(value, maxChars) {
  const text = normalizeOptionalText(value, "value");
  return text == null ? null : truncateText(text, maxChars);
}

function normalizeSeverity(value) {
  if (value === "error" || value === "warning" || value === "note") return value;
  const text = typeof value === "string" ? value.toLowerCase() : "";
  if (["critical", "high"].includes(text)) return "error";
  if (["medium", "moderate", "warning"].includes(text)) return "warning";
  return "note";
}

function normalizeTool(value) {
  return truncateText(value || "unknown", TOOL_MAX_CHARS) || "unknown";
}

function normalizeRuleId(value) {
  return truncateText(value || "unknown-rule", RULE_ID_MAX_CHARS) || "unknown-rule";
}

function normalizeRepoPath(value) {
  if (typeof value !== "string" || !value.trim()) return null;
  let uri = value.trim().replace(/\\/g, "/");
  uri = uri.replace(/[?#].*$/, "");
  uri = uri.replace(/^file:\/\/+/, "/");
  uri = uri.replace(/^\/src\/+/, "");
  uri = uri.replace(/^\.\/+/, "");
  if (uri.startsWith("/")) return null;
  const normalized = path.posix.normalize(uri);
  if (!normalized || normalized === "." || normalized === ".." || normalized.startsWith("../")) return null;
  return truncateText(normalized, PATH_MAX_CHARS);
}

function arrayFromUnknown(value) {
  if (value == null) return [];
  if (Array.isArray(value)) return value;
  return [value];
}

function pushUniqueString(target, seen, value, maxChars) {
  if (value == null) return;
  const text = truncateText(value, maxChars);
  if (!text || seen.has(text)) return;
  seen.add(text);
  target.push(text);
}

function collectStringArray(...values) {
  const result = [];
  const seen = new Set();
  for (const value of values) {
    for (const item of arrayFromUnknown(value)) {
      if (typeof item === "string" || typeof item === "number") {
        pushUniqueString(result, seen, item, TAG_MAX_CHARS);
      }
    }
  }
  return result;
}

function collectCwe(...values) {
  const result = [];
  const seen = new Set();
  const scan = (value) => {
    if (value == null) return;
    if (Array.isArray(value)) {
      value.forEach(scan);
      return;
    }
    const text = String(value);
    const direct = text.match(/^CWE[-_ ]?([0-9]{1,5})$/i);
    if (direct) {
      pushUniqueString(result, seen, `CWE-${direct[1]}`, CWE_MAX_CHARS);
      return;
    }
    const regexes = [
      /(?:^|[^A-Za-z0-9])cwe[-_/ ]?([0-9]{1,5})(?:$|[^A-Za-z0-9])/ig,
      /cwe\.mitre\.org\/data\/definitions\/([0-9]{1,5})\.html/ig,
    ];
    for (const regex of regexes) {
      let match;
      while ((match = regex.exec(text)) != null) {
        pushUniqueString(result, seen, `CWE-${match[1]}`, CWE_MAX_CHARS);
      }
    }
  };
  values.forEach(scan);
  return result;
}

function ruleForResult(result, rules) {
  if (Number.isInteger(result.ruleIndex) && result.ruleIndex >= 0 && isObject(rules[result.ruleIndex])) {
    return rules[result.ruleIndex];
  }
  if (typeof result.ruleId === "string") {
    return rules.find((rule) => isObject(rule) && rule.id === result.ruleId) || null;
  }
  return null;
}

function countCodeFlowSteps(result) {
  if (!Array.isArray(result.codeFlows)) return 0;
  let count = 0;
  for (const flow of result.codeFlows) {
    const threadFlows = isObject(flow) && Array.isArray(flow.threadFlows) ? flow.threadFlows : [];
    for (const threadFlow of threadFlows) {
      const locations = isObject(threadFlow) && Array.isArray(threadFlow.locations)
        ? threadFlow.locations
        : [];
      count += locations.length;
    }
  }
  return count;
}

function metadataForSarifResult(result, run) {
  const driver = isObject(run.tool) && isObject(run.tool.driver) ? run.tool.driver : {};
  const rules = Array.isArray(driver.rules) ? driver.rules : [];
  const rule = ruleForResult(result, rules) || {};
  const ruleProps = isObject(rule.properties) ? rule.properties : {};
  const resultProps = isObject(result.properties) ? result.properties : {};
  const tags = collectStringArray(ruleProps.tags, resultProps.tags);
  return {
    cwe: collectCwe(
      ruleProps.cwe,
      ruleProps.cwes,
      ruleProps.tags,
      rule.helpUri,
      resultProps.cwe,
      resultProps.cwes,
      resultProps.tags,
    ),
    tags,
    dataflow_steps: countCodeFlowSteps(result),
  };
}

function sarifMetadataByResultHash(jsonText, ctx = {}) {
  let document;
  try {
    document = JSON.parse(String(jsonText || ""));
  } catch {
    return new Map();
  }
  const result = new Map();
  const runs = isObject(document) && Array.isArray(document.runs) ? document.runs : [];
  for (const run of runs) {
    if (!isObject(run)) continue;
    const rows = Array.isArray(run.results) ? run.results : [];
    for (const row of rows) {
      if (!isObject(row)) continue;
      const normalized = normalizeSarifResult(row, run, ctx);
      if (!normalized || typeof normalized.result_sha256 !== "string") continue;
      result.set(normalized.result_sha256, metadataForSarifResult(row, run));
    }
  }
  return result;
}

function severityFromTrivy(value) {
  return normalizeSeverity(value || "note");
}

function firstTrivyCodeLine(item) {
  const code = isObject(item.Code) ? item.Code : {};
  const lines = Array.isArray(code.Lines) ? code.Lines : [];
  for (const line of lines) {
    if (isObject(line) && typeof line.Content === "string") return line.Content;
  }
  return null;
}

function trivyMessage(...parts) {
  return parts
    .map((part) => (typeof part === "string" ? part.trim() : ""))
    .filter(Boolean)
    .join(" - ");
}

function trivyRecord({
  tool = "trivy",
  target,
  ruleId,
  severity,
  message,
  startLine,
  endLine = null,
  snippet = null,
  cwe = [],
  tags = [],
  sourceRunId = null,
}) {
  const artifactUri = normalizeRepoPath(target);
  if (!artifactUri || !ruleId) return null;
  const line = Number.isInteger(startLine) && startLine >= 1 ? startLine : 1;
  const safeMessage = scrubText(message || ruleId, "static_analysis_index.trivy_message") || ruleId;
  const safeSnippet = snippet == null ? null : scrubText(snippet, "static_analysis_index.trivy_snippet");
  const dedupeMaterial = [tool, normalizeRuleId(ruleId), artifactUri, line, safeMessage];
  return {
    tool_name: tool,
    tool_version: null,
    rule_id: normalizeRuleId(ruleId),
    severity_signal: severityFromTrivy(severity),
    message: safeMessage,
    snippet: safeSnippet,
    artifact_uri: artifactUri,
    start_line: line,
    end_line: Number.isInteger(endLine) && endLine >= line ? endLine : line,
    fingerprint: sha256Hex(JSON.stringify(["trivy-native-fingerprint", ...dedupeMaterial])),
    result_sha256: sha256Hex(JSON.stringify(dedupeMaterial)),
    source_run_id: sourceRunId,
    __index_metadata: {
      cwe: collectCwe(cwe),
      tags: collectStringArray(tags),
      dataflow_steps: 0,
    },
  };
}

function parseTrivyJson(jsonText, ctx = {}) {
  let document;
  try {
    document = JSON.parse(String(jsonText || ""));
  } catch (error) {
    throw new ToolError(
      ERROR_CODES.INVALID_ARGUMENTS,
      `Malformed Trivy JSON: ${error.message || String(error)}`,
      { repo_error_code: "static_analysis_parse_failed" },
    );
  }
  if (!isObject(document) || !Array.isArray(document.Results)) {
    throw new ToolError(
      ERROR_CODES.INVALID_ARGUMENTS,
      "Malformed Trivy JSON: expected object with Results[]",
      { repo_error_code: "static_analysis_parse_failed" },
    );
  }

  const records = [];
  const warnings = [];
  let totalResults = 0;
  let skippedResults = 0;
  const sourceRunId = normalizeOptionalText(ctx.run_id || ctx.source_run_id, "run_id");

  for (const result of document.Results) {
    if (!isObject(result)) {
      skippedResults += 1;
      warnings.push("Trivy result entry is not an object");
      continue;
    }
    const target = result.Target || result.TargetPath || result.Name;
    const vulnerabilities = Array.isArray(result.Vulnerabilities) ? result.Vulnerabilities : [];
    const secrets = Array.isArray(result.Secrets) ? result.Secrets : [];
    const misconfigurations = Array.isArray(result.Misconfigurations) ? result.Misconfigurations : [];

    for (const vulnerability of vulnerabilities) {
      totalResults += 1;
      if (!isObject(vulnerability)) {
        skippedResults += 1;
        continue;
      }
      const record = trivyRecord({
        target,
        ruleId: vulnerability.VulnerabilityID || vulnerability.ID,
        severity: vulnerability.Severity,
        message: trivyMessage(vulnerability.Title, vulnerability.Description),
        startLine: 1,
        cwe: vulnerability.CweIDs || vulnerability.CWEIDs || vulnerability.CVSS,
        tags: ["vulnerability", vulnerability.PkgName],
        sourceRunId,
      });
      if (record) records.push(record);
      else skippedResults += 1;
    }

    for (const secret of secrets) {
      totalResults += 1;
      if (!isObject(secret)) {
        skippedResults += 1;
        continue;
      }
      const record = trivyRecord({
        target,
        ruleId: secret.RuleID || secret.ID || secret.Category,
        severity: secret.Severity,
        message: trivyMessage(secret.Title, secret.Category),
        startLine: secret.StartLine,
        endLine: secret.EndLine,
        snippet: firstTrivyCodeLine(secret),
        tags: ["secret", secret.Category],
        sourceRunId,
      });
      if (record) records.push(record);
      else skippedResults += 1;
    }

    for (const misconfiguration of misconfigurations) {
      totalResults += 1;
      if (!isObject(misconfiguration)) {
        skippedResults += 1;
        continue;
      }
      const cause = isObject(misconfiguration.CauseMetadata) ? misconfiguration.CauseMetadata : {};
      const record = trivyRecord({
        target,
        ruleId: misconfiguration.ID || misconfiguration.AVDID || misconfiguration.Type,
        severity: misconfiguration.Severity,
        message: trivyMessage(misconfiguration.Title, misconfiguration.Message, misconfiguration.Description),
        startLine: cause.StartLine,
        endLine: cause.EndLine,
        snippet: firstTrivyCodeLine(cause),
        tags: ["misconfiguration", misconfiguration.Type],
        sourceRunId,
      });
      if (record) records.push(record);
      else skippedResults += 1;
    }
  }

  return {
    records: records.slice(0, STATIC_ANALYSIS_INDEX_MAX_RECORDS),
    warnings,
    total_results: totalResults,
    skipped_results: skippedResults,
    truncated: records.length > STATIC_ANALYSIS_INDEX_MAX_RECORDS,
  };
}

function parseStaticAnalysisCapture(jsonText, ctx = {}) {
  let document;
  try {
    document = JSON.parse(String(jsonText || ""));
  } catch (error) {
    if (ctx.stdout_truncated === true) {
      return {
        records: [],
        warnings: [`Truncated static-analysis JSON could not be parsed: ${error.message || String(error)}`],
        total_results: 0,
        skipped_results: 0,
        truncated: true,
        metadata_by_result_sha256: new Map(),
      };
    }
    throw new ToolError(
      ERROR_CODES.INVALID_ARGUMENTS,
      `Malformed static-analysis JSON: ${error.message || String(error)}`,
      { repo_error_code: "static_analysis_parse_failed" },
    );
  }

  if (isObject(document) && Array.isArray(document.runs)) {
    const parsed = parseSarif(jsonText, {
      source_run_id: normalizeOptionalText(ctx.run_id, "run_id"),
      tool_name: normalizeOptionalText(ctx.tool, "tool"),
    });
    return {
      ...parsed,
      truncated: parsed.truncated || ctx.stdout_truncated === true,
      metadata_by_result_sha256: sarifMetadataByResultHash(jsonText, {
        source_run_id: normalizeOptionalText(ctx.run_id, "run_id"),
        tool_name: normalizeOptionalText(ctx.tool, "tool"),
      }),
    };
  }

  if (isObject(document) && Array.isArray(document.Results)) {
    const parsed = parseTrivyJson(jsonText, ctx);
    return {
      ...parsed,
      truncated: parsed.truncated || ctx.stdout_truncated === true,
      metadata_by_result_sha256: new Map(parsed.records.map((record) => [
        record.result_sha256,
        record.__index_metadata || { cwe: [], tags: [], dataflow_steps: 0 },
      ])),
    };
  }

  throw new ToolError(
    ERROR_CODES.INVALID_ARGUMENTS,
    "Unsupported static-analysis JSON: expected SARIF runs[] or Trivy Results[]",
    { repo_error_code: "static_analysis_parse_failed" },
  );
}

function findingHashFor({ tool, ruleId, artifactUri, startLine, message }) {
  return sha256Hex(JSON.stringify([
    normalizeTool(tool),
    normalizeRuleId(ruleId),
    artifactUri || "",
    Number.isInteger(startLine) ? startLine : null,
    message || "",
  ]));
}

function normalizeMetadata(metadata) {
  const safe = isObject(metadata) ? metadata : {};
  return {
    cwe: collectCwe(safe.cwe),
    tags: collectStringArray(safe.tags),
    dataflow_steps: Number.isInteger(safe.dataflow_steps) && safe.dataflow_steps >= 0
      ? safe.dataflow_steps
      : 0,
  };
}

function normalizeStaticAnalysisIndexRecord(record, lineNumber = null) {
  if (!isObject(record)) {
    throw new Error(lineNumber == null
      ? "static analysis index record must be an object"
      : `Malformed static-analysis-index.jsonl at line ${lineNumber}: expected object`);
  }
  try {
    const tool = normalizeTool(assertNonEmptyString(record.tool, "tool"));
    const ruleId = normalizeRuleId(assertNonEmptyString(record.rule_id, "rule_id"));
    const location = isObject(record.location) ? record.location : {};
    const artifactUri = truncateText(assertNonEmptyString(
      location.path || record.file || record.artifact_uri,
      "location.path",
    ), PATH_MAX_CHARS);
    const startLine = assertInteger(location.line || record.start_line, "location.line", { min: 1 });
    const message = scrubText(record.message || "", "static_analysis_index.message") || "";
    const metadata = normalizeMetadata(record);
    const normalized = {
      version: record.version == null
        ? STATIC_ANALYSIS_INDEX_VERSION
        : assertInteger(record.version, "version", { min: 1, max: 1 }),
      target_domain: assertNonEmptyString(record.target_domain, "target_domain"),
      indexed_at: assertNonEmptyString(record.indexed_at, "indexed_at"),
      finding_hash: assertNonEmptyString(record.finding_hash, "finding_hash"),
      tool,
      tool_version: optionalString(record.tool_version, 80),
      rule_id: ruleId,
      severity: normalizeSeverity(record.severity),
      location: {
        path: artifactUri,
        line: startLine,
        column: Number.isInteger(location.column) && location.column >= 1 ? location.column : null,
        end_line: Number.isInteger(location.end_line) && location.end_line >= startLine
          ? location.end_line
          : startLine,
      },
      file: artifactUri,
      start_line: startLine,
      message,
      snippet: record.snippet == null ? null : scrubText(record.snippet, "static_analysis_index.snippet"),
      cwe: metadata.cwe,
      tags: metadata.tags,
      dataflow_steps: metadata.dataflow_steps,
      run_id: normalizeOptionalText(record.run_id, "run_id"),
      stdout_hash: normalizeOptionalText(record.stdout_hash, "stdout_hash"),
      stdout_path: normalizeOptionalText(record.stdout_path, "stdout_path"),
      source_result_sha256: normalizeOptionalText(record.source_result_sha256, "source_result_sha256"),
      surface_id: normalizeOptionalText(record.surface_id, "surface_id"),
      truncated: record.truncated === true,
    };
    validateNoSensitiveMaterial(normalized, "static_analysis_index", { maxTextChars: 1000 });
    return normalized;
  } catch (error) {
    if (lineNumber == null) throw error;
    throw new Error(`Malformed static-analysis-index.jsonl at line ${lineNumber}: ${error.message || String(error)}`);
  }
}

function indexRecordFromNormalizedResult(domain, result, ctx = {}) {
  const metadata = normalizeMetadata(
    result.__index_metadata
      || (ctx.metadata_by_result_sha256 && ctx.metadata_by_result_sha256.get(result.result_sha256))
      || {},
  );
  const tool = normalizeTool(ctx.tool || result.tool_name);
  const ruleId = normalizeRuleId(result.rule_id);
  const artifactUri = truncateText(assertNonEmptyString(result.artifact_uri, "artifact_uri"), PATH_MAX_CHARS);
  const startLine = assertInteger(result.start_line, "start_line", { min: 1 });
  const message = scrubText(result.message || "", "static_analysis_index.message") || "";
  const row = {
    version: STATIC_ANALYSIS_INDEX_VERSION,
    target_domain: domain,
    indexed_at: ctx.indexed_at,
    finding_hash: findingHashFor({
      tool,
      ruleId,
      artifactUri,
      startLine,
      message,
    }),
    tool,
    tool_version: optionalString(result.tool_version, 80),
    rule_id: ruleId,
    severity: normalizeSeverity(result.severity_signal),
    location: {
      path: artifactUri,
      line: startLine,
      column: Number.isInteger(result.start_column) && result.start_column >= 1 ? result.start_column : null,
      end_line: Number.isInteger(result.end_line) && result.end_line >= startLine ? result.end_line : startLine,
    },
    file: artifactUri,
    start_line: startLine,
    message,
    snippet: result.snippet == null ? null : scrubText(result.snippet, "static_analysis_index.snippet"),
    cwe: metadata.cwe,
    tags: metadata.tags,
    dataflow_steps: metadata.dataflow_steps,
    run_id: normalizeOptionalText(ctx.run_id || result.source_run_id, "run_id"),
    stdout_hash: normalizeOptionalText(ctx.stdout_hash, "stdout_hash"),
    stdout_path: normalizeOptionalText(ctx.stdout_path, "stdout_path"),
    source_result_sha256: normalizeOptionalText(result.result_sha256, "source_result_sha256"),
    surface_id: normalizeOptionalText(ctx.surface_id, "surface_id"),
    truncated: ctx.truncated === true,
  };
  return normalizeStaticAnalysisIndexRecord(row);
}

function compareIndexRecords(a, b) {
  const severityDelta = (SEVERITY_RANK[a.severity] ?? 99) - (SEVERITY_RANK[b.severity] ?? 99);
  if (severityDelta !== 0) return severityDelta;
  const flowDelta = (b.dataflow_steps || 0) - (a.dataflow_steps || 0);
  if (flowDelta !== 0) return flowDelta;
  const pathDelta = a.location.path.localeCompare(b.location.path);
  if (pathDelta !== 0) return pathDelta;
  if (a.location.line !== b.location.line) return a.location.line - b.location.line;
  return a.finding_hash.localeCompare(b.finding_hash);
}

function readStaticAnalysisIndex(domain) {
  const normalizedDomain = assertNonEmptyString(domain, "target_domain");
  return readJsonlRecords(
    staticAnalysisIndexPath(normalizedDomain),
    "static-analysis-index.jsonl",
    (record, lineNumber) => normalizeStaticAnalysisIndexRecord(record, lineNumber),
  ).filter((record) => record.target_domain === normalizedDomain);
}

function writeStaticAnalysisIndex(domain, records) {
  const filePath = staticAnalysisIndexPath(domain);
  const bounded = records.slice(0, STATIC_ANALYSIS_INDEX_MAX_RECORDS);
  const content = bounded.length === 0
    ? ""
    : `${bounded.map((record) => JSON.stringify(normalizeStaticAnalysisIndexRecord(record))).join("\n")}\n`;
  writeFileAtomic(filePath, content);
}

function resolveSourcePath(domain, stdoutPathRaw) {
  const root = sessionDir(domain);
  const normalizedRoot = path.resolve(root);
  const raw = assertNonEmptyString(stdoutPathRaw, "stdout_path");
  const candidate = path.isAbsolute(raw) ? raw : path.join(root, raw);
  const resolved = path.resolve(candidate);
  if (resolved !== normalizedRoot && !resolved.startsWith(`${normalizedRoot}${path.sep}`)) {
    throw new ToolError(
      ERROR_CODES.INVALID_ARGUMENTS,
      "stdout_path escapes session directory",
      { repo_error_code: "static_analysis_source_outside_session" },
    );
  }
  let rootReal;
  let fileReal;
  try {
    rootReal = fs.realpathSync(root);
    fileReal = fs.realpathSync(resolved);
  } catch {
    throw new ToolError(
      ERROR_CODES.NOT_FOUND,
      "stdout_path is not readable",
      { repo_error_code: "static_analysis_source_missing" },
    );
  }
  if (fileReal !== rootReal && !fileReal.startsWith(`${rootReal}${path.sep}`)) {
    throw new ToolError(
      ERROR_CODES.INVALID_ARGUMENTS,
      "stdout_path escapes session directory via symlink",
      { repo_error_code: "static_analysis_source_outside_session" },
    );
  }
  const relativePath = path.relative(rootReal, fileReal).split(path.sep).join("/");
  return {
    absolute_path: fileReal,
    display_path: relativePath,
  };
}

function ip7RecordsForRun(domain, runId) {
  if (!runId) return [];
  return readStaticAnalysisResultsFromJsonl(domain)
    .filter((record) => record.source_run_id === runId);
}

function compactRecordForResponse(record) {
  return {
    finding_hash: record.finding_hash,
    tool: record.tool,
    rule_id: record.rule_id,
    severity: record.severity,
    location: `${record.location.path}:${record.location.line}`,
    message: truncateText(record.message, 160),
    cwe: record.cwe,
    dataflow_steps: record.dataflow_steps,
  };
}

function indexStaticResults(domainRaw, args = {}) {
  const domain = assertNonEmptyString(domainRaw, "target_domain");
  readSessionStateStrict(domain);
  const runId = normalizeOptionalText(args.run_id, "run_id");
  const tool = normalizeOptionalText(args.tool, "tool");
  const surfaceId = normalizeOptionalText(args.surface_id, "surface_id");
  const indexedAt = new Date().toISOString();
  let stdoutHash = normalizeOptionalText(args.stdout_hash, "stdout_hash");
  let displayPath = null;
  let parsed = null;
  let sourceRecords = [];

  if (args.stdout_path == null) {
    sourceRecords = ip7RecordsForRun(domain, runId);
    if (sourceRecords.length === 0) {
      return {
        version: STATIC_ANALYSIS_INDEX_VERSION,
        target_domain: domain,
        source: { run_id: runId, stdout_path: null },
        results_seen: 0,
        normalized_results: 0,
        indexed_results: 0,
        duplicate_results: 0,
        total_records: readStaticAnalysisIndex(domain).length,
        truncated: false,
        warning_count: 0,
        warnings: [],
        index_path: "static-analysis-index.jsonl",
        doctrine: "lead_seed_only_no_findings_or_skips",
      };
    }
  } else {
    const source = resolveSourcePath(domain, args.stdout_path);
    displayPath = source.display_path;
    const jsonText = readFileUtf8(source.absolute_path, {
      label: displayPath,
      maxBytes: MAX_SARIF_BYTES,
    });
    stdoutHash = stdoutHash || sha256Hex(jsonText);
    parsed = parseStaticAnalysisCapture(jsonText, {
      run_id: runId,
      tool,
      stdout_truncated: args.stdout_truncated === true,
    });
    sourceRecords = parsed.records;
    if (sourceRecords.length === 0 && runId) {
      sourceRecords = ip7RecordsForRun(domain, runId);
    }
  }

  const metadataByHash = parsed && parsed.metadata_by_result_sha256 instanceof Map
    ? parsed.metadata_by_result_sha256
    : new Map();
  const candidateRows = sourceRecords.map((record) => indexRecordFromNormalizedResult(domain, record, {
    indexed_at: indexedAt,
    run_id: runId,
    tool,
    stdout_hash: stdoutHash,
    stdout_path: displayPath,
    surface_id: surfaceId,
    truncated: parsed ? parsed.truncated === true : false,
    metadata_by_result_sha256: metadataByHash,
  }));

  let indexedResults = 0;
  let duplicateResults = 0;
  let totalRecords = 0;
  let responseRecords = [];

  withSessionLock(domain, () => {
    const existing = readStaticAnalysisIndex(domain);
    const byHash = new Map(existing.map((record) => [record.finding_hash, record]));
    const seenInput = new Set();
    for (const row of candidateRows) {
      const old = byHash.get(row.finding_hash);
      if (seenInput.has(row.finding_hash) || old) duplicateResults += 1;
      if (!seenInput.has(row.finding_hash) && !old) indexedResults += 1;
      seenInput.add(row.finding_hash);
      byHash.set(row.finding_hash, {
        ...(old || {}),
        ...row,
        indexed_at: old ? old.indexed_at : row.indexed_at,
      });
    }
    const merged = Array.from(byHash.values()).sort(compareIndexRecords)
      .slice(0, STATIC_ANALYSIS_INDEX_MAX_RECORDS);
    writeStaticAnalysisIndex(domain, merged);
    totalRecords = merged.length;
    responseRecords = candidateRows.sort(compareIndexRecords)
      .slice(0, STATIC_ANALYSIS_INDEX_SUMMARY_RECORD_LIMIT)
      .map(compactRecordForResponse);
  });

  return {
    version: STATIC_ANALYSIS_INDEX_VERSION,
    target_domain: domain,
    source: {
      run_id: runId,
      stdout_path: displayPath,
    },
    results_seen: parsed ? parsed.total_results : sourceRecords.length,
    normalized_results: sourceRecords.length,
    indexed_results: indexedResults,
    duplicate_results: duplicateResults,
    total_records: totalRecords,
    truncated: parsed ? parsed.truncated === true : false,
    warning_count: parsed ? parsed.warnings.length : 0,
    warnings: parsed ? parsed.warnings.slice(0, STATIC_ANALYSIS_INDEX_WARNING_LIMIT) : [],
    index_path: "static-analysis-index.jsonl",
    records: responseRecords,
    records_omitted: Math.max(0, candidateRows.length - responseRecords.length),
    doctrine: "lead_seed_only_no_findings_or_skips",
  };
}

function normalizeTopK(value) {
  if (value == null) return STATIC_ANALYSIS_INDEX_DEFAULT_TOP_K;
  return assertInteger(value, "top_k", { min: 1, max: STATIC_ANALYSIS_INDEX_MAX_TOP_K });
}

function queryStaticAnalysisIndex(domain, opts = {}) {
  const topK = normalizeTopK(opts.top_k);
  const minSeverity = opts.min_severity == null ? "note" : normalizeSeverity(opts.min_severity);
  const minRank = SEVERITY_RANK[minSeverity] ?? SEVERITY_RANK.note;
  const ruleId = normalizeOptionalText(opts.rule_id, "rule_id");
  const surfaceId = normalizeOptionalText(opts.surface_id, "surface_id");
  return readStaticAnalysisIndex(domain)
    .filter((record) => (
      (SEVERITY_RANK[record.severity] ?? 99) <= minRank
      && (ruleId == null || record.rule_id === ruleId)
      && (surfaceId == null || record.surface_id === surfaceId)
    ))
    .sort(compareIndexRecords)
    .slice(0, topK);
}

function readStaticAnalysisIndexTool(args = {}) {
  const domain = assertNonEmptyString(args.target_domain, "target_domain");
  readSessionStateStrict(domain);
  const records = queryStaticAnalysisIndex(domain, {
    top_k: args.top_k,
    min_severity: args.min_severity,
    rule_id: args.rule_id,
    surface_id: args.surface_id,
  });
  return JSON.stringify({
    version: STATIC_ANALYSIS_INDEX_VERSION,
    target_domain: domain,
    index_path: "static-analysis-index.jsonl",
    top_k: normalizeTopK(args.top_k),
    min_severity: args.min_severity == null ? "note" : normalizeSeverity(args.min_severity),
    total_records: readStaticAnalysisIndex(domain).length,
    returned_records: records.length,
    records: records.map(compactRecordForResponse),
    doctrine: "lead_seed_only_no_findings_or_skips",
  }, null, 2);
}

function mapSarifResultToSurfaceLead(rowRaw) {
  const row = normalizeStaticAnalysisIndexRecord({
    ...rowRaw,
    indexed_at: rowRaw.indexed_at || new Date(0).toISOString(),
    target_domain: rowRaw.target_domain || "static-analysis.local",
  });
  const evidence = `${row.location.path}:${row.location.line} - ${row.message}`;
  const bugClassHints = [
    row.rule_id,
    ...row.cwe,
    ...row.tags,
  ].filter(Boolean);
  return normalizeSurfaceLead({
    title: `${row.rule_id} in ${row.location.path}:${row.location.line}`,
    source: `static-analysis:${row.tool}`,
    source_surface_id: row.surface_id,
    status: "new",
    promote: false,
    confidence: row.severity === "error" ? "medium" : "low",
    surface_type: "repo",
    bug_class_hints: bugClassHints,
    evidence: [evidence],
    rationale:
      `Static analysis rule ${row.rule_id} surfaced an unverified repo location; live verification is required before promotion.`,
  });
}

module.exports = {
  STATIC_ANALYSIS_INDEX_DEFAULT_TOP_K,
  STATIC_ANALYSIS_INDEX_MAX_RECORDS,
  STATIC_ANALYSIS_INDEX_MAX_TOP_K,
  indexStaticResults,
  mapSarifResultToSurfaceLead,
  normalizeStaticAnalysisIndexRecord,
  parseStaticAnalysisCapture,
  parseTrivyJson,
  queryStaticAnalysisIndex,
  readStaticAnalysisIndex,
  readStaticAnalysisIndexTool,
};
