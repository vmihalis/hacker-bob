"use strict";

const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const { redactUrlSensitiveValues } = require("../redaction.js");
const {
  STATIC_ARTIFACT_LOG_MAX_RECORDS,
  STATIC_ARTIFACT_MAX_CHARS,
  STATIC_ARTIFACT_TYPE_VALUES,
  STATIC_SCAN_FINDING_MAX_ITEMS,
  STATIC_SCAN_HINT_MAX_ITEMS,
  STATIC_SCAN_RESULTS_MAX_RECORDS,
} = require("./constants.js");
const {
  assertEnumValue,
  assertInteger,
  assertNonEmptyString,
  assertRequiredText,
  normalizeOptionalText,
} = require("./validation.js");
const {
  assertStaticArtifactId,
  staticArtifactImportDir,
  staticArtifactPath,
  staticArtifactsJsonlPath,
  staticScanResultsJsonlPath,
} = require("./paths.js");
const {
  appendJsonlLine,
  withSessionLock,
  writeFileAtomic,
} = require("./storage.js");
const {
  readSessionStateStrict,
} = require("./session-state.js");
const {
  EVM_PATTERNS,
  RISK_ORDER,
  RISK_WEIGHTS,
  SOLANA_PATTERNS,
} = require("./token-scan-patterns.js");

function rejectPathImport(args) {
  for (const key of ["path", "file_path", "filename", "contract_path", "source_path"]) {
    if (Object.prototype.hasOwnProperty.call(args, key)) {
      throw new Error("Path imports are not supported. Pass artifact content to bounty_import_static_artifact.");
    }
  }
}

function normalizeDisplayName(value, fieldName) {
  const normalized = normalizeOptionalText(value, fieldName);
  if (!normalized) return null;
  return path.basename(normalized).replace(/[^A-Za-z0-9._ -]/g, "_").slice(0, 120) || null;
}

function countReplacement(text, regex, replacement) {
  let count = 0;
  const next = text.replace(regex, (...args) => {
    count += 1;
    if (typeof replacement === "function") return replacement(...args);
    return replacement;
  });
  return { text: next, count };
}

function redactStaticArtifactContent(content) {
  let text = String(content || "");
  let redactions = 0;

  let replaced = countReplacement(
    text,
    /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g,
    "REDACTED_PRIVATE_KEY",
  );
  text = replaced.text;
  redactions += replaced.count;

  replaced = countReplacement(text, /\bAKIA[0-9A-Z]{16}\b/g, "REDACTED_AWS_ACCESS_KEY");
  text = replaced.text;
  redactions += replaced.count;

  replaced = countReplacement(text, /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{20,}\b/g, "REDACTED_GITHUB_TOKEN");
  text = replaced.text;
  redactions += replaced.count;

  replaced = countReplacement(text, /\bgithub_pat_[A-Za-z0-9_]{20,}\b/g, "REDACTED_GITHUB_TOKEN");
  text = replaced.text;
  redactions += replaced.count;

  replaced = countReplacement(text, /\bxox[baprs]-[A-Za-z0-9-]{12,}\b/g, "REDACTED_SLACK_TOKEN");
  text = replaced.text;
  redactions += replaced.count;

  replaced = countReplacement(text, /\bBearer\s+[A-Za-z0-9._~+/=-]{16,}\b/g, "Bearer REDACTED");
  text = replaced.text;
  redactions += replaced.count;

  replaced = countReplacement(
    text,
    /\b(api[_-]?key|secret|token|password|passwd|client_secret|private_key)\b(\s*[:=]\s*)(["']?)([^"'\s;,)]{8,})\3/gi,
    (match, key, separator, quote) => `${key}${separator}${quote}REDACTED${quote}`,
  );
  text = replaced.text;
  redactions += replaced.count;

  replaced = countReplacement(text, /https?:\/\/[^\s"'<>]+/g, (url) => {
    const redacted = redactUrlSensitiveValues(url);
    if (redacted !== url) redactions += 1;
    return redacted;
  });
  text = replaced.text;

  return { content: text, redactions };
}

function shortSha256(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function readJsonlRecords(filePath, label, normalizer) {
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
      throw new Error(`Malformed ${label} at line ${index + 1}: ${error.message || String(error)}`);
    }
    records.push(normalizer(parsed, index + 1));
  }
  return records;
}

function normalizeStaticArtifactRecord(record, lineNumber = null) {
  if (record == null || typeof record !== "object" || Array.isArray(record)) {
    throw new Error(lineNumber == null
      ? "static artifact record must be an object"
      : `Malformed static-artifacts.jsonl at line ${lineNumber}: expected object`);
  }
  try {
    const artifactId = assertStaticArtifactId(record.artifact_id);
    return {
      version: record.version == null ? 1 : assertInteger(record.version, "version", { min: 1, max: 1 }),
      target_domain: assertNonEmptyString(record.target_domain, "target_domain"),
      artifact_id: artifactId,
      artifact_type: assertEnumValue(record.artifact_type, STATIC_ARTIFACT_TYPE_VALUES, "artifact_type"),
      label: normalizeOptionalText(record.label, "label"),
      source_name: normalizeOptionalText(record.source_name, "source_name"),
      surface_id: normalizeOptionalText(record.surface_id, "surface_id"),
      imported_at: assertNonEmptyString(record.imported_at, "imported_at"),
      content_sha256: assertNonEmptyString(record.content_sha256, "content_sha256"),
      original_chars: assertInteger(record.original_chars, "original_chars", { min: 1 }),
      stored_chars: assertInteger(record.stored_chars, "stored_chars", { min: 1 }),
      redactions: assertInteger(record.redactions || 0, "redactions", { min: 0 }),
      artifact_path: normalizeOptionalText(record.artifact_path, "artifact_path"),
    };
  } catch (error) {
    if (lineNumber == null) throw error;
    throw new Error(`Malformed static-artifacts.jsonl at line ${lineNumber}: ${error.message || String(error)}`);
  }
}

function readStaticArtifactRecordsFromJsonl(domain) {
  return readJsonlRecords(
    staticArtifactsJsonlPath(domain),
    "static-artifacts.jsonl",
    (record, lineNumber) => normalizeStaticArtifactRecord(record, lineNumber),
  ).filter((record) => record.target_domain === domain);
}

function nextStaticArtifactId(records) {
  let max = 0;
  for (const record of records) {
    const match = String(record.artifact_id || "").match(/^SA-([1-9]\d*)$/);
    if (match) max = Math.max(max, Number(match[1]));
  }
  return `SA-${max + 1}`;
}

function assertInitializedSession(domain) {
  readSessionStateStrict(domain);
}

function importStaticArtifact(args) {
  rejectPathImport(args || {});
  const domain = assertNonEmptyString(args.target_domain, "target_domain");
  const artifactType = assertEnumValue(args.artifact_type, STATIC_ARTIFACT_TYPE_VALUES, "artifact_type");
  const label = normalizeDisplayName(args.label, "label");
  const sourceName = normalizeDisplayName(args.source_name, "source_name");
  const surfaceId = normalizeOptionalText(args.surface_id, "surface_id");
  const originalContent = assertRequiredText(args.content, "content");
  if (originalContent.length > STATIC_ARTIFACT_MAX_CHARS) {
    throw new Error(`content exceeds static artifact cap of ${STATIC_ARTIFACT_MAX_CHARS} characters`);
  }
  assertInitializedSession(domain);

  const redacted = redactStaticArtifactContent(originalContent);
  const importedAt = new Date().toISOString();

  return withSessionLock(domain, () => {
    const records = readStaticArtifactRecordsFromJsonl(domain);
    const artifactId = nextStaticArtifactId(records);
    const artifactPath = staticArtifactPath(domain, artifactId);
    writeFileAtomic(artifactPath, redacted.content);

    const record = normalizeStaticArtifactRecord({
      version: 1,
      target_domain: domain,
      artifact_id: artifactId,
      artifact_type: artifactType,
      label,
      source_name: sourceName,
      surface_id: surfaceId,
      imported_at: importedAt,
      content_sha256: shortSha256(redacted.content),
      original_chars: originalContent.length,
      stored_chars: redacted.content.length,
      redactions: redacted.redactions,
      artifact_path: artifactPath,
    });
    appendJsonlLine(staticArtifactsJsonlPath(domain), record, { maxRecords: STATIC_ARTIFACT_LOG_MAX_RECORDS });

    return JSON.stringify({
      version: 1,
      target_domain: domain,
      artifact_id: artifactId,
      artifact_type: artifactType,
      label,
      source_name: sourceName,
      surface_id: surfaceId,
      imported_at: importedAt,
      original_chars: originalContent.length,
      stored_chars: redacted.content.length,
      redactions: redacted.redactions,
      artifact_path: artifactPath,
      manifest_path: staticArtifactsJsonlPath(domain),
    }, null, 2);
  });
}

function chainForArtifactType(artifactType) {
  return artifactType === "solana_token_contract" ? "solana" : "evm";
}

function compactEvidenceLine(line) {
  const redacted = redactStaticArtifactContent(line).content.replace(/\s+/g, " ").trim();
  return redacted.length > 180 ? `${redacted.slice(0, 177)}...` : redacted;
}

function dedupeFindings(findings) {
  const retained = [];
  for (const finding of findings) {
    const duplicate = retained.some((existing) => (
      existing.title === finding.title &&
      existing.artifact_id === finding.artifact_id &&
      Math.abs(existing.line_number - finding.line_number) <= 5
    ));
    if (!duplicate) retained.push(finding);
  }
  return retained;
}

function scanTokenContractContent(content, {
  artifactId,
  artifactType,
  label = null,
  sourceName = null,
  surfaceId = null,
} = {}) {
  const chain = chainForArtifactType(artifactType);
  const patterns = chain === "solana" ? SOLANA_PATTERNS : EVM_PATTERNS;
  const lines = String(content || "").split(/\r?\n/);
  const findings = [];

  for (const [category, categoryPatterns] of Object.entries(patterns)) {
    for (const pattern of categoryPatterns) {
      for (let index = 0; index < lines.length; index += 1) {
        const line = lines[index];
        if (!pattern.regex.test(line)) continue;
        findings.push({
          risk: pattern.risk,
          category,
          title: pattern.title,
          description: pattern.description,
          artifact_id: artifactId,
          label,
          source_name: sourceName,
          surface_id: surfaceId,
          line_number: index + 1,
          evidence: compactEvidenceLine(line),
          recommendation: pattern.recommendation,
        });
      }
    }
  }

  const dedupedFindings = dedupeFindings(findings);
  dedupedFindings.sort((a, b) => {
    const riskDelta = (RISK_ORDER[a.risk] ?? 99) - (RISK_ORDER[b.risk] ?? 99);
    if (riskDelta !== 0) return riskDelta;
    if (a.line_number !== b.line_number) return a.line_number - b.line_number;
    return a.title.localeCompare(b.title);
  });
  const returnedFindings = dedupedFindings.slice(0, STATIC_SCAN_FINDING_MAX_ITEMS);
  const riskScore = dedupedFindings.reduce((sum, finding) => sum + (RISK_WEIGHTS[finding.risk] || 0), 0);

  let verdict = "CLEAN - NO RED FLAGS DETECTED";
  if (riskScore >= 50) verdict = "CRITICAL RISK - DO NOT INTERACT";
  else if (riskScore >= 25) verdict = "HIGH RISK - LIKELY RUG VECTORS PRESENT";
  else if (riskScore >= 10) verdict = "MEDIUM RISK - MANUAL REVIEW NEEDED";
  else if (riskScore >= 5) verdict = "LOW RISK - MINOR CONCERNS";

  return {
    scan_type: "token_contract",
    chain,
    files_scanned: 1,
    findings_count: dedupedFindings.length,
    findings_returned: returnedFindings.length,
    findings_capped: dedupedFindings.length > returnedFindings.length,
    risk_score: riskScore,
    verdict,
    findings: returnedFindings,
  };
}

function normalizeStaticScanResultRecord(record, lineNumber = null) {
  if (record == null || typeof record !== "object" || Array.isArray(record)) {
    throw new Error(lineNumber == null
      ? "static scan result must be an object"
      : `Malformed static-scan-results.jsonl at line ${lineNumber}: expected object`);
  }
  try {
    const findings = Array.isArray(record.findings) ? record.findings : [];
    return {
      version: record.version == null ? 1 : assertInteger(record.version, "version", { min: 1, max: 1 }),
      target_domain: assertNonEmptyString(record.target_domain, "target_domain"),
      artifact_id: assertStaticArtifactId(record.artifact_id),
      artifact_type: assertEnumValue(record.artifact_type, STATIC_ARTIFACT_TYPE_VALUES, "artifact_type"),
      scan_type: assertEnumValue(record.scan_type, ["token_contract"], "scan_type"),
      chain: assertEnumValue(record.chain, ["evm", "solana"], "chain"),
      label: normalizeOptionalText(record.label, "label"),
      source_name: normalizeOptionalText(record.source_name, "source_name"),
      surface_id: normalizeOptionalText(record.surface_id, "surface_id"),
      scanned_at: assertNonEmptyString(record.scanned_at, "scanned_at"),
      files_scanned: assertInteger(record.files_scanned, "files_scanned", { min: 0 }),
      findings_count: assertInteger(record.findings_count, "findings_count", { min: 0 }),
      findings_returned: assertInteger(record.findings_returned, "findings_returned", { min: 0 }),
      findings_capped: !!record.findings_capped,
      risk_score: assertInteger(record.risk_score, "risk_score", { min: 0 }),
      verdict: assertNonEmptyString(record.verdict, "verdict"),
      findings: findings
        .filter((finding) => finding && typeof finding === "object" && !Array.isArray(finding))
        .slice(0, STATIC_SCAN_FINDING_MAX_ITEMS)
        .map((finding) => ({
          risk: assertEnumValue(finding.risk, Object.keys(RISK_WEIGHTS), "finding.risk"),
          category: assertNonEmptyString(finding.category, "finding.category"),
          title: assertNonEmptyString(finding.title, "finding.title"),
          description: assertNonEmptyString(finding.description, "finding.description"),
          artifact_id: assertStaticArtifactId(finding.artifact_id || record.artifact_id),
          label: normalizeOptionalText(finding.label, "finding.label"),
          source_name: normalizeOptionalText(finding.source_name, "finding.source_name"),
          surface_id: normalizeOptionalText(finding.surface_id, "finding.surface_id"),
          line_number: assertInteger(finding.line_number, "finding.line_number", { min: 1 }),
          evidence: normalizeOptionalText(finding.evidence, "finding.evidence"),
          recommendation: assertNonEmptyString(finding.recommendation, "finding.recommendation"),
        })),
    };
  } catch (error) {
    if (lineNumber == null) throw error;
    throw new Error(`Malformed static-scan-results.jsonl at line ${lineNumber}: ${error.message || String(error)}`);
  }
}

function readStaticScanResultsFromJsonl(domain) {
  return readJsonlRecords(
    staticScanResultsJsonlPath(domain),
    "static-scan-results.jsonl",
    (record, lineNumber) => normalizeStaticScanResultRecord(record, lineNumber),
  ).filter((record) => record.target_domain === domain);
}

function staticScan(args) {
  const domain = assertNonEmptyString(args.target_domain, "target_domain");
  const artifactId = assertStaticArtifactId(args.artifact_id);
  const scanType = args.scan_type == null
    ? "token_contract"
    : assertEnumValue(args.scan_type, ["token_contract"], "scan_type");
  const requestedLimit = args.limit == null
    ? STATIC_SCAN_FINDING_MAX_ITEMS
    : assertInteger(args.limit, "limit", { min: 1, max: STATIC_SCAN_FINDING_MAX_ITEMS });
  assertInitializedSession(domain);

  return withSessionLock(domain, () => {
    const artifact = readStaticArtifactRecordsFromJsonl(domain).find((record) => record.artifact_id === artifactId);
    if (!artifact) {
      throw new Error(`Static artifact ${artifactId} not found for ${domain}`);
    }
    const artifactPath = staticArtifactPath(domain, artifactId);
    if (!fs.existsSync(artifactPath)) {
      throw new Error(`Missing imported static artifact file: ${artifactPath}`);
    }
    const content = fs.readFileSync(artifactPath, "utf8");
    const scannedAt = new Date().toISOString();
    const scan = scanTokenContractContent(content, {
      artifactId,
      artifactType: artifact.artifact_type,
      label: artifact.label,
      sourceName: artifact.source_name,
      surfaceId: artifact.surface_id,
    });
    const record = normalizeStaticScanResultRecord({
      version: 1,
      target_domain: domain,
      artifact_id: artifactId,
      artifact_type: artifact.artifact_type,
      scan_type: scanType,
      chain: scan.chain,
      label: artifact.label,
      source_name: artifact.source_name,
      surface_id: artifact.surface_id,
      scanned_at: scannedAt,
      files_scanned: scan.files_scanned,
      findings_count: scan.findings_count,
      findings_returned: scan.findings_returned,
      findings_capped: scan.findings_capped,
      risk_score: scan.risk_score,
      verdict: scan.verdict,
      findings: scan.findings,
    });
    appendJsonlLine(staticScanResultsJsonlPath(domain), record, { maxRecords: STATIC_SCAN_RESULTS_MAX_RECORDS });

    const findingsShown = Math.min(record.findings.length, requestedLimit);
    return JSON.stringify({
      ...record,
      findings: record.findings.slice(0, requestedLimit),
      findings_shown: findingsShown,
      findings_omitted: Math.max(0, record.findings_count - findingsShown),
      results_path: staticScanResultsJsonlPath(domain),
    }, null, 2);
  });
}

function summarizeStaticScanHints(domain, { surface = null, limit = STATIC_SCAN_HINT_MAX_ITEMS } = {}) {
  const normalizedLimit = limit == null
    ? STATIC_SCAN_HINT_MAX_ITEMS
    : assertInteger(limit, "limit", { min: 0, max: STATIC_SCAN_HINT_MAX_ITEMS });
  const surfaceId = surface && surface.id ? String(surface.id) : null;
  const results = readStaticScanResultsFromJsonl(domain)
    .filter((result) => !surfaceId || !result.surface_id || result.surface_id === surfaceId)
    .sort((a, b) => Date.parse(b.scanned_at) - Date.parse(a.scanned_at));

  if (results.length === 0) {
    return {
      available: false,
      total_results: 0,
      shown: 0,
      omitted: 0,
      cap: normalizedLimit,
      max_risk_score: 0,
      artifacts: [],
      findings: [],
    };
  }

  const allFindings = [];
  for (const result of results) {
    for (const finding of result.findings) {
      allFindings.push({
        ...finding,
        artifact_type: result.artifact_type,
        chain: result.chain,
        scanned_at: result.scanned_at,
        result_risk_score: result.risk_score,
        verdict: result.verdict,
      });
    }
  }
  allFindings.sort((a, b) => {
    const riskDelta = (RISK_ORDER[a.risk] ?? 99) - (RISK_ORDER[b.risk] ?? 99);
    if (riskDelta !== 0) return riskDelta;
    return Date.parse(b.scanned_at) - Date.parse(a.scanned_at);
  });

  const shownFindings = allFindings.slice(0, normalizedLimit).map((finding) => ({
    artifact_id: finding.artifact_id,
    label: finding.label,
    source_name: finding.source_name,
    surface_id: finding.surface_id,
    chain: finding.chain,
    risk: finding.risk,
    category: finding.category,
    title: finding.title,
    line_number: finding.line_number,
    recommendation: finding.recommendation,
  }));

  return {
    available: true,
    total_results: results.length,
    shown: shownFindings.length,
    omitted: Math.max(0, allFindings.length - shownFindings.length),
    cap: normalizedLimit,
    max_risk_score: Math.max(...results.map((result) => result.risk_score)),
    artifacts: results.slice(0, normalizedLimit).map((result) => ({
      artifact_id: result.artifact_id,
      label: result.label,
      source_name: result.source_name,
      surface_id: result.surface_id,
      chain: result.chain,
      risk_score: result.risk_score,
      verdict: result.verdict,
      findings_count: result.findings_count,
      scanned_at: result.scanned_at,
    })),
    findings: shownFindings,
  };
}

module.exports = {
  compactEvidenceLine,
  importStaticArtifact,
  normalizeStaticArtifactRecord,
  normalizeStaticScanResultRecord,
  readStaticArtifactRecordsFromJsonl,
  readStaticScanResultsFromJsonl,
  redactStaticArtifactContent,
  scanTokenContractContent,
  staticScan,
  summarizeStaticScanHints,
};
