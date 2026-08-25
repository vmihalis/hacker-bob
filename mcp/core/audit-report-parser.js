"use strict";

const fs = require("fs");
const {
  assertSafeDomain,
  auditReportsJsonlPath,
  sessionDir,
} = require("./io/paths.js");
const {
  readFileUtf8,
} = require("./io/storage.js");
const { hashCanonicalJson } = require("./verification/verification-contracts.js");

const SEVERITY_VALUES = Object.freeze([
  "critical",
  "high",
  "medium",
  "low",
  "informational",
  "info",
  "unknown",
]);

const SEVERITY_INLINE = /(?:^|\W)(?:\*\*)?severity\s*[:\-]\s*(?:\*\*\s*)?(critical|high|medium|low|informational|info)\b/i;
const SEVERITY_HEADER = /^\s*###?\s*(?:\*\*)?severity(?:\*\*)?\s*[:\-]?\s*$/i;
const RECOMMENDATION_HEADER = /^\s*###?\s*(?:\*\*)?(?:recommendation|remediation|fix|mitigation)(?:\*\*)?\s*[:\-]?\s*$/i;
const DESCRIPTION_HEADER = /^\s*###?\s*(?:\*\*)?description(?:\*\*)?\s*[:\-]?\s*$/i;
const SCOPE_HEADER = /^\s*###?\s*(?:\*\*)?(?:scope|affected|location|target)(?:\*\*)?\s*[:\-]?\s*$/i;

function isPlainObject(value) {
  return value != null && typeof value === "object" && !Array.isArray(value);
}

function ensureSessionDir(domain) {
  const dir = sessionDir(domain);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  return dir;
}

function normalizeSeverity(rawSeverity) {
  if (typeof rawSeverity !== "string" || rawSeverity.length === 0) return "unknown";
  const lower = rawSeverity.toLowerCase().trim();
  if (lower === "informational") return "informational";
  if (SEVERITY_VALUES.includes(lower)) return lower;
  if (lower.startsWith("crit")) return "critical";
  if (lower.startsWith("hi")) return "high";
  if (lower.startsWith("med")) return "medium";
  if (lower.startsWith("lo")) return "low";
  if (lower.startsWith("info")) return "info";
  return "unknown";
}

function findInlineSeverity(text) {
  const match = text.match(SEVERITY_INLINE);
  if (!match) return null;
  return normalizeSeverity(match[1]);
}

function classifyVulnerability(text) {
  const lower = text.toLowerCase();
  if (/\breentran/.test(lower)) return "reentrancy";
  if (/access[\s-_]?control|missing[\s-_]?(?:auth|authoriz)/.test(lower)) return "access_control";
  if (/integer\s+overflow|underflow|arith(?:metic)?\s+overflow/.test(lower)) return "arithmetic_overflow";
  if (/oracle\s+manipulation|price\s+manipulation/.test(lower)) return "oracle_manipulation";
  if (/front[\s-]?running|sandwich/.test(lower)) return "front_running";
  if (/flash\s+loan/.test(lower)) return "flash_loan";
  if (/unchecked\s+(?:call|return|low[\s-]?level)/.test(lower)) return "unchecked_call";
  if (/storage\s+collision|delegatecall/.test(lower)) return "delegatecall_storage";
  if (/signature\s+(?:malleability|replay|verify)|ecrecover/.test(lower)) return "signature_validation";
  if (/idor|broken[\s-]?object[\s-]?level/.test(lower)) return "idor";
  if (/sql\s+injection|nosql\s+injection|injection\b/.test(lower)) return "injection";
  if (/xss|cross[\s-]?site\s+scripting/.test(lower)) return "xss";
  if (/race[\s-]?condition|toctou/.test(lower)) return "race_condition";
  return "unknown";
}

function trimEdgeBlankLines(lines) {
  let start = 0;
  let end = lines.length;
  while (start < end && lines[start].trim().length === 0) start++;
  while (end > start && lines[end - 1].trim().length === 0) end--;
  return lines.slice(start, end);
}

function parseAuditReportMarkdown(rawMarkdown) {
  const warnings = [];
  if (typeof rawMarkdown !== "string") {
    throw new TypeError("rawMarkdown must be a string");
  }
  const lines = rawMarkdown.split(/\r?\n/);
  let title = null;
  let summary = null;
  const findings = [];
  let currentFinding = null;
  let currentSection = null;
  let buffer = [];

  function flushSection() {
    if (currentSection == null) {
      buffer = [];
      return;
    }
    const text = trimEdgeBlankLines(buffer).join("\n");
    if (currentFinding != null) {
      if (currentSection === "description") {
        currentFinding.description = (currentFinding.description ? currentFinding.description + "\n\n" : "") + text;
      } else if (currentSection === "recommendation") {
        currentFinding.recommendation = (currentFinding.recommendation ? currentFinding.recommendation + "\n\n" : "") + text;
      } else if (currentSection === "scope") {
        currentFinding.scope_paths = parseScopePaths(text);
      } else if (currentSection === "severity") {
        const severity = findInlineSeverity(text) || normalizeSeverity(text.replace(/[\s*:]+/g, " ").trim());
        if (severity && severity !== "unknown") currentFinding.severity = severity;
      } else if (currentSection === "_default") {
        // Default body content from the H2 finding header itself.
        currentFinding.description = (currentFinding.description ? currentFinding.description + "\n\n" : "") + text;
      }
    } else if (currentSection === "_summary") {
      summary = (summary ? summary + "\n\n" : "") + text;
    }
    buffer = [];
    currentSection = null;
  }

  function startFinding(headingText) {
    flushSection();
    if (currentFinding != null) findings.push(currentFinding);
    const inlineSeverity = findInlineSeverity(headingText);
    const cleanedTitle = headingText
      .replace(/\(.*?severity.*?\)/gi, "")
      .replace(SEVERITY_INLINE, "")
      .trim();
    currentFinding = {
      title: cleanedTitle || headingText.trim(),
      severity: inlineSeverity || "unknown",
      description: null,
      recommendation: null,
      scope_paths: [],
      vulnerability_class: "unknown",
    };
    currentSection = "_default";
  }

  function startSection(name) {
    flushSection();
    currentSection = name;
  }

  for (const rawLine of lines) {
    const line = rawLine;
    if (/^# /.test(line) && currentFinding == null) {
      // First H1 -> title
      const candidate = line.replace(/^#\s+/, "").trim();
      if (title == null) {
        title = candidate;
        currentSection = "_summary";
      } else {
        // Second H1 starts a new finding section as a fallback.
        startFinding(candidate);
      }
      continue;
    }
    if (/^##\s+/.test(line)) {
      const headingText = line.replace(/^##\s+/, "").trim();
      // Treat H2 as a finding boundary unless it's a top-level summary keyword.
      if (currentFinding == null && /^(?:summary|overview|introduction|scope)\b/i.test(headingText)) {
        startSection("_summary");
        continue;
      }
      startFinding(headingText);
      continue;
    }
    if (/^###\s+/.test(line) && currentFinding != null) {
      const headingText = line.replace(/^###\s+/, "").trim();
      if (RECOMMENDATION_HEADER.test(line)) startSection("recommendation");
      else if (SEVERITY_HEADER.test(line)) startSection("severity");
      else if (DESCRIPTION_HEADER.test(line)) startSection("description");
      else if (SCOPE_HEADER.test(line)) startSection("scope");
      else {
        // Unknown H3 header -> treat as inline description content prefixed with the header text.
        buffer.push(headingText);
      }
      continue;
    }
    if (currentFinding != null && currentFinding.severity === "unknown") {
      const inlineSev = findInlineSeverity(line);
      if (inlineSev) currentFinding.severity = inlineSev;
    }
    buffer.push(line);
  }
  flushSection();
  if (currentFinding != null) findings.push(currentFinding);

  for (const finding of findings) {
    const corpus = `${finding.title}\n${finding.description || ""}\n${finding.recommendation || ""}`;
    finding.vulnerability_class = classifyVulnerability(corpus);
  }

  if (findings.length === 0) {
    warnings.push("no_findings_detected");
  }

  const rawSourceHash = hashCanonicalJson({ raw: rawMarkdown });
  const docHash = hashCanonicalJson({
    title,
    summary,
    findings: findings.map((f) => ({
      title: f.title,
      severity: f.severity,
      vulnerability_class: f.vulnerability_class,
      description: f.description,
      recommendation: f.recommendation,
      scope_paths: f.scope_paths,
    })),
  });
  return {
    schema_format: "markdown_audit",
    title,
    summary,
    findings: findings.map((finding, index) => ({
      ...finding,
      finding_index: index,
      finding_hash: hashCanonicalJson({
        title: finding.title,
        description: finding.description,
        recommendation: finding.recommendation,
        scope_paths: finding.scope_paths,
        vulnerability_class: finding.vulnerability_class,
      }),
    })),
    source_doc_hash: docHash,
    source_raw_hash: rawSourceHash,
    parser_warnings: warnings,
  };
}

function parseScopePaths(text) {
  if (typeof text !== "string" || text.length === 0) return [];
  const lines = text.split(/\r?\n/);
  const paths = new Set();
  for (const line of lines) {
    const trimmed = line.replace(/^[\s\-*+]+/, "").trim();
    if (trimmed.length === 0) continue;
    const match = trimmed.match(/`([^`]+)`/);
    if (match) {
      paths.add(match[1]);
      continue;
    }
    if (/[A-Za-z0-9_./-]+\.(?:sol|move|rs|cairo|fc|tact|ts|js|py|go|java|rb)\b/.test(trimmed)) {
      paths.add(trimmed.split(/\s+/)[0]);
    }
  }
  return Array.from(paths).sort();
}

function readJsonlAuditReports(filePath) {
  if (!fs.existsSync(filePath)) return [];
  const raw = readFileUtf8(filePath, { label: "audit-reports.jsonl" });
  const lines = raw.split(/\r?\n/).filter((line) => line.trim().length > 0);
  const records = [];
  for (let i = 0; i < lines.length; i++) {
    try {
      records.push(JSON.parse(lines[i]));
    } catch (err) {
      throw new Error(`Malformed audit-reports.jsonl at line ${i + 1}: ${err.message || String(err)}`);
    }
  }
  return records;
}

function writeJsonlAuditReports(filePath, records) {
  const sorted = records.slice().sort((a, b) => {
    const aHash = typeof a.source_doc_hash === "string" ? a.source_doc_hash : "";
    const bHash = typeof b.source_doc_hash === "string" ? b.source_doc_hash : "";
    return aHash.localeCompare(bHash);
  });
  const body = sorted.map((record) => JSON.stringify(record)).join("\n");
  fs.writeFileSync(filePath, body.length > 0 ? body + "\n" : "", "utf8");
}

function ingestAuditReport({ target_domain, raw_markdown, source_uri }) {
  const domain = assertSafeDomain(target_domain);
  if (typeof raw_markdown !== "string" || raw_markdown.length === 0) {
    throw new Error("raw_markdown must be a non-empty string");
  }
  const sourceUri = typeof source_uri === "string" && source_uri.length > 0 ? source_uri : null;
  const parsed = parseAuditReportMarkdown(raw_markdown);
  ensureSessionDir(domain);
  const filePath = auditReportsJsonlPath(domain);
  const existing = readJsonlAuditReports(filePath);
  const byHash = new Map();
  for (const record of existing) {
    if (record && typeof record.source_doc_hash === "string") {
      byHash.set(record.source_doc_hash, record);
    }
  }
  const previous = byHash.get(parsed.source_doc_hash) || null;
  const ingestedAt = new Date().toISOString();
  const record = {
    source_doc_hash: parsed.source_doc_hash,
    source_raw_hash: parsed.source_raw_hash,
    source_uri: sourceUri,
    title: parsed.title,
    summary: parsed.summary,
    finding_count: parsed.findings.length,
    findings: parsed.findings,
    parser_warnings: parsed.parser_warnings,
    ingested_at: ingestedAt,
  };
  byHash.set(parsed.source_doc_hash, record);
  writeJsonlAuditReports(filePath, Array.from(byHash.values()));
  return {
    target_domain: domain,
    source_doc_hash: parsed.source_doc_hash,
    source_uri: sourceUri,
    finding_count: parsed.findings.length,
    new_record: previous == null,
    total_in_corpus: byHash.size,
    parser_warnings: parsed.parser_warnings,
  };
}

function queryAuditReports({ target_domain, severity_filter, vulnerability_class_filter, limit }) {
  const domain = assertSafeDomain(target_domain);
  const filePath = auditReportsJsonlPath(domain);
  const reports = readJsonlAuditReports(filePath);
  if (reports.length === 0) {
    return { reports: [], total_in_corpus: 0, total_findings: 0, matched_finding_count: 0 };
  }
  let totalFindings = 0;
  const matched = [];
  for (const report of reports) {
    if (!isPlainObject(report)) continue;
    const findings = Array.isArray(report.findings) ? report.findings : [];
    totalFindings += findings.length;
    const filteredFindings = findings.filter((finding) => {
      if (!isPlainObject(finding)) return false;
      if (severity_filter && finding.severity !== severity_filter) return false;
      if (vulnerability_class_filter && finding.vulnerability_class !== vulnerability_class_filter) return false;
      return true;
    });
    if (filteredFindings.length === 0 && (severity_filter || vulnerability_class_filter)) continue;
    matched.push({
      source_doc_hash: report.source_doc_hash,
      source_uri: report.source_uri,
      title: report.title,
      finding_count: filteredFindings.length,
      findings: filteredFindings,
    });
  }
  const cap = Number.isInteger(limit) && limit > 0 ? Math.min(limit, 200) : 50;
  return {
    reports: matched.slice(0, cap),
    total_in_corpus: reports.length,
    total_findings: totalFindings,
    matched_finding_count: matched.reduce((acc, r) => acc + r.findings.length, 0),
  };
}

module.exports = {
  parseAuditReportMarkdown,
  ingestAuditReport,
  queryAuditReports,
  classifyVulnerability,
  normalizeSeverity,
  SEVERITY_VALUES,
};
