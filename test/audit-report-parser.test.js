"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const crypto = require("node:crypto");

const {
  parseAuditReportMarkdown,
  ingestAuditReport,
  queryAuditReports,
  classifyVulnerability,
  normalizeSeverity,
} = require("../mcp/lib/audit-report-parser.js");

function uniqueDomain(prefix = "bob-audit-test") {
  const suffix = crypto.randomBytes(4).toString("hex");
  return `${prefix}-${suffix}.local`;
}

function cleanupDomain(domain) {
  const dir = path.join(os.homedir(), "hacker-bob-sessions", domain);
  if (fs.existsSync(dir)) fs.rmSync(dir, { recursive: true, force: true });
}

const SAMPLE_AUDIT = `# Acme DeFi Protocol — Security Audit

## Summary

This audit covers the Acme lending protocol contracts.

## Reentrancy in withdraw function (Severity: High)

### Description
The \`withdraw\` function makes an external call to the borrower
before updating the internal balance state, allowing the borrower
to re-enter and drain the pool.

### Scope
- \`contracts/Pool.sol\`

### Recommendation
Apply the checks-effects-interactions pattern: update internal
state before any external call. Consider OpenZeppelin's
\`ReentrancyGuard\`.

## Missing access control on emergencyPause

**Severity:** Critical

The \`emergencyPause()\` function on \`Pool.sol\` has no role check,
so any address can pause the protocol.

### Recommendation
Restrict \`emergencyPause\` to the timelock-controlled admin role.

## Integer overflow in interest accrual

**Severity:** Medium

The interest accrual math in \`InterestRateModel.sol\` may overflow
for very large principal values.

### Recommendation
Use SafeMath or a Solidity 0.8+ checked math context.
`;

test("normalizeSeverity maps common spellings to canonical values", () => {
  assert.equal(normalizeSeverity("Critical"), "critical");
  assert.equal(normalizeSeverity("HIGH"), "high");
  assert.equal(normalizeSeverity("Med"), "medium");
  assert.equal(normalizeSeverity("low"), "low");
  assert.equal(normalizeSeverity("Informational"), "informational");
  assert.equal(normalizeSeverity("Info"), "info");
  assert.equal(normalizeSeverity("garbage"), "unknown");
  assert.equal(normalizeSeverity(null), "unknown");
});

test("classifyVulnerability detects common smart-contract bug classes", () => {
  assert.equal(classifyVulnerability("Reentrancy in withdraw"), "reentrancy");
  assert.equal(classifyVulnerability("Missing access control on admin"), "access_control");
  assert.equal(classifyVulnerability("Integer overflow in math"), "arithmetic_overflow");
  assert.equal(classifyVulnerability("Oracle manipulation via price"), "oracle_manipulation");
  assert.equal(classifyVulnerability("Front-running attack"), "front_running");
  assert.equal(classifyVulnerability("Flash loan abuse"), "flash_loan");
  assert.equal(classifyVulnerability("Unchecked call return"), "unchecked_call");
  assert.equal(classifyVulnerability("Storage collision via delegatecall"), "delegatecall_storage");
  assert.equal(classifyVulnerability("Signature replay attack"), "signature_validation");
  assert.equal(classifyVulnerability("IDOR on user profile"), "idor");
  assert.equal(classifyVulnerability("SQL injection in admin panel"), "injection");
  assert.equal(classifyVulnerability("XSS in search"), "xss");
  assert.equal(classifyVulnerability("Race condition in withdrawal"), "race_condition");
  assert.equal(classifyVulnerability("just some prose"), "unknown");
});

test("parseAuditReportMarkdown extracts title, summary, and three findings from a sample audit", () => {
  const result = parseAuditReportMarkdown(SAMPLE_AUDIT);
  assert.equal(result.schema_format, "markdown_audit");
  assert.equal(result.title, "Acme DeFi Protocol — Security Audit");
  assert.match(result.summary, /Acme lending protocol/);
  assert.equal(result.findings.length, 3);
  assert.deepEqual(result.findings.map((f) => f.title), [
    "Reentrancy in withdraw function",
    "Missing access control on emergencyPause",
    "Integer overflow in interest accrual",
  ]);
});

test("severity is parsed from the H2 heading inline form and the Severity: bold form", () => {
  const result = parseAuditReportMarkdown(SAMPLE_AUDIT);
  assert.equal(result.findings[0].severity, "high");
  assert.equal(result.findings[1].severity, "critical");
  assert.equal(result.findings[2].severity, "medium");
});

test("vulnerability_class classifies each finding from its prose", () => {
  const result = parseAuditReportMarkdown(SAMPLE_AUDIT);
  assert.equal(result.findings[0].vulnerability_class, "reentrancy");
  assert.equal(result.findings[1].vulnerability_class, "access_control");
  assert.equal(result.findings[2].vulnerability_class, "arithmetic_overflow");
});

test("scope_paths parses backtick-quoted contract paths from the Scope section", () => {
  const result = parseAuditReportMarkdown(SAMPLE_AUDIT);
  assert.deepEqual(result.findings[0].scope_paths, ["contracts/Pool.sol"]);
});

test("recommendation captures the Remediation/Recommendation body for each finding", () => {
  const result = parseAuditReportMarkdown(SAMPLE_AUDIT);
  assert.match(result.findings[0].recommendation, /checks-effects-interactions/);
  assert.match(result.findings[1].recommendation, /timelock/);
  assert.match(result.findings[2].recommendation, /SafeMath/);
});

test("finding_hash is stable across re-parsing of the same input", () => {
  const a = parseAuditReportMarkdown(SAMPLE_AUDIT);
  const b = parseAuditReportMarkdown(SAMPLE_AUDIT);
  assert.equal(a.source_doc_hash, b.source_doc_hash);
  for (let i = 0; i < a.findings.length; i++) {
    assert.equal(a.findings[i].finding_hash, b.findings[i].finding_hash);
  }
});

test("parseAuditReportMarkdown emits no_findings_detected on a body with no headings", () => {
  const result = parseAuditReportMarkdown("# Title\n\nNo findings sections at all.\n");
  assert.equal(result.findings.length, 0);
  assert.deepEqual(result.parser_warnings, ["no_findings_detected"]);
});

test("ingestAuditReport persists records and dedupes by source_doc_hash", () => {
  const domain = uniqueDomain();
  try {
    const first = ingestAuditReport({
      target_domain: domain,
      raw_markdown: SAMPLE_AUDIT,
      source_uri: "https://example.com/audit.md",
    });
    assert.equal(first.new_record, true);
    assert.equal(first.finding_count, 3);
    assert.equal(first.total_in_corpus, 1);
    const second = ingestAuditReport({
      target_domain: domain,
      raw_markdown: SAMPLE_AUDIT,
    });
    assert.equal(second.new_record, false);
    assert.equal(second.total_in_corpus, 1);
  } finally {
    cleanupDomain(domain);
  }
});

test("queryAuditReports returns reports and counts; severity filter narrows findings", () => {
  const domain = uniqueDomain();
  try {
    ingestAuditReport({ target_domain: domain, raw_markdown: SAMPLE_AUDIT });
    const all = queryAuditReports({ target_domain: domain });
    assert.equal(all.total_in_corpus, 1);
    assert.equal(all.total_findings, 3);
    assert.equal(all.matched_finding_count, 3);
    const criticalOnly = queryAuditReports({ target_domain: domain, severity_filter: "critical" });
    assert.equal(criticalOnly.matched_finding_count, 1);
    assert.equal(criticalOnly.reports[0].findings[0].severity, "critical");
  } finally {
    cleanupDomain(domain);
  }
});

test("queryAuditReports filters by vulnerability_class", () => {
  const domain = uniqueDomain();
  try {
    ingestAuditReport({ target_domain: domain, raw_markdown: SAMPLE_AUDIT });
    const reentrancyOnly = queryAuditReports({ target_domain: domain, vulnerability_class_filter: "reentrancy" });
    assert.equal(reentrancyOnly.matched_finding_count, 1);
    assert.equal(reentrancyOnly.reports[0].findings[0].vulnerability_class, "reentrancy");
  } finally {
    cleanupDomain(domain);
  }
});

test("queryAuditReports on missing corpus returns empty result", () => {
  const domain = uniqueDomain();
  try {
    const result = queryAuditReports({ target_domain: domain });
    assert.equal(result.reports.length, 0);
    assert.equal(result.total_in_corpus, 0);
  } finally {
    cleanupDomain(domain);
  }
});

test("ingestAuditReport rejects unsafe target_domain and empty input", () => {
  assert.throws(
    () => ingestAuditReport({ target_domain: "../escape", raw_markdown: SAMPLE_AUDIT }),
    /target_domain/,
  );
  assert.throws(
    () => ingestAuditReport({ target_domain: "ok.example", raw_markdown: "" }),
    /raw_markdown/,
  );
});
