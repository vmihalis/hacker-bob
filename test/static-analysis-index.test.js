"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const {
  indexStaticResults,
  mapSarifResultToSurfaceLead,
  parseStaticAnalysisCapture,
  parseTrivyJson,
  queryStaticAnalysisIndex,
  readStaticAnalysisIndex,
  readStaticAnalysisIndexTool,
  registerStaticAnalysisLeadRecorder,
} = require("../mcp/lib/static-analysis-index.js");
const {
  isAuditGradedPath,
  repoInventoryPath,
  repoRunsDir,
  staticAnalysisIndexPath,
} = require("../mcp/lib/paths.js");
const {
  readFrontierEvents,
} = require("../mcp/lib/frontier-events.js");
const {
  normalizeSurfaceLead,
  readSurfaceLeadsDocument,
} = require("../mcp/lib/lead-intake.js");
const {
  initSession,
} = require("../mcp/lib/session-state.js");
const {
  initRepoSession,
} = require("../mcp/lib/repo-target.js");

require("../mcp/lib/lead-promotion.js");

test.after(() => {
  registerStaticAnalysisLeadRecorder(null);
});

function fixture(name) {
  return fs.readFileSync(path.join(__dirname, "fixtures", "sarif", name), "utf8");
}

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-static-analysis-index-"));
  process.env.HOME = home;
  try {
    return fn(home);
  } finally {
    if (previousHome === undefined) delete process.env.HOME;
    else process.env.HOME = previousHome;
    fs.rmSync(home, { recursive: true, force: true });
  }
}

function initDomain(domain) {
  JSON.parse(initSession({ target_domain: domain, target_url: `https://${domain}` }));
}

function initRepoDomain(domain, home) {
  const repoRoot = fs.mkdtempSync(path.join(home, "repo-"));
  initRepoSession({ repo_path: repoRoot, target_domain: domain });
  return repoRoot;
}

function writeRunStdout(domain, runId, content) {
  fs.mkdirSync(repoRunsDir(domain), { recursive: true });
  const filePath = path.join(repoRunsDir(domain), `${runId}.stdout`);
  fs.writeFileSync(filePath, content, "utf8");
  return filePath;
}

function hasCwe22(row) {
  return row.cwe.some((entry) => /^CWE-0?22$/.test(entry));
}

test("parseStaticAnalysisCapture reuses IP7 SARIF records and extracts CodeQL CWE/dataflow metadata", () => {
  const semgrep = parseStaticAnalysisCapture(fixture("semgrep.sarif"), { run_id: "run-semgrep" });
  assert.equal(semgrep.records.length, 1);
  assert.equal(semgrep.records[0].tool_name, "semgrep");
  assert.equal(semgrep.records[0].rule_id, "javascript.lang.security.audit.detect-eval-with-expression.detect-eval-with-expression");

  const codeql = parseStaticAnalysisCapture(fixture("codeql-codeflows.sarif"), { run_id: "run-codeql" });
  assert.equal(codeql.records.length, 1);
  assert.equal(codeql.records[0].tool_name, "CodeQL");
  const metadata = codeql.metadata_by_result_sha256.get(codeql.records[0].result_sha256);
  assert.ok(metadata.cwe.some((entry) => /^CWE-0?22$/.test(entry)));
  assert.equal(metadata.dataflow_steps, 2);
});

test("parseTrivyJson adapts native Trivy secret JSON and scrubs planted secrets before records exist", () => {
  const parsed = parseTrivyJson(fixture("trivy-secret.json"), { run_id: "run-trivy" });
  assert.equal(parsed.records.length, 1);
  const record = parsed.records[0];
  assert.equal(record.tool_name, "trivy");
  assert.equal(record.rule_id, "aws-access-key-id");
  assert.equal(record.severity_signal, "error");
  assert.equal(record.artifact_uri, "config/settings.py");
  assert.equal(record.start_line, 4);
  assert.equal(JSON.stringify(record).includes("AKIA1234567890ABCDEF"), false);
  assert.match(JSON.stringify(record), /REDACTED_AWS_ACCESS_KEY/);
});

test("indexStaticResults dedupes by stable finding_hash and preserves CodeQL metadata", () => withTempHome((home) => {
  const domain = "static-index-codeql.example.com";
  const runId = "run-codeql";
  initRepoDomain(domain, home);
  const stdoutPath = writeRunStdout(domain, runId, fixture("codeql-codeflows.sarif"));

  const first = indexStaticResults(domain, {
    run_id: runId,
    stdout_path: stdoutPath,
    tool: "codeql",
    surface_id: "RS-1",
    reachability_index: {
      "RS-1": {
        attack_vector: "network",
        network_reachable: true,
        severity_ceiling: "critical",
      },
    },
  });
  assert.equal(first.indexed_results, 1);
  assert.equal(first.duplicate_results, 0);
  assert.equal(first.static_analysis_leads.mapped_leads, 1);
  assert.equal(first.static_analysis_leads.recorded, 1);

  const rowsAfterFirst = readStaticAnalysisIndex(domain);
  assert.equal(rowsAfterFirst.length, 1);
  const firstHash = rowsAfterFirst[0].finding_hash;
  assert.match(firstHash, /^[a-f0-9]{64}$/);
  assert.equal(rowsAfterFirst[0].tool, "codeql");
  assert.equal(rowsAfterFirst[0].severity, "error");
  assert.equal(rowsAfterFirst[0].location.path, "routes/download.js");
  assert.equal(rowsAfterFirst[0].dataflow_steps, 2);
  assert.ok(hasCwe22(rowsAfterFirst[0]));
  assert.equal(rowsAfterFirst[0].surface_id, "RS-1");
  assert.equal(isAuditGradedPath(staticAnalysisIndexPath(domain), domain), false);
  const leadsAfterFirst = readSurfaceLeadsDocument(domain).leads;
  assert.equal(leadsAfterFirst.length, 1);
  assert.equal(leadsAfterFirst[0].source, "bob_static_scan");
  assert.equal(leadsAfterFirst[0].surface_type, "oss_static_sink");
  assert.deepEqual(leadsAfterFirst[0].endpoints, ["routes/download.js:88"]);

  const second = indexStaticResults(domain, {
    run_id: runId,
    stdout_path: stdoutPath,
    tool: "codeql",
    surface_id: "RS-1",
  });
  assert.equal(second.indexed_results, 0);
  assert.equal(second.duplicate_results, 1);
  assert.equal(second.static_analysis_leads.mapped_leads, 0);
  assert.equal(second.static_analysis_leads.recorded, 0);
  assert.equal(
    readFrontierEvents(domain).filter((event) => event.kind === "frontier.enqueued").length,
    1,
    "duplicate static rows must not append another frontier.enqueued event",
  );

  const rowsAfterSecond = readStaticAnalysisIndex(domain);
  assert.equal(rowsAfterSecond.length, 1);
  assert.equal(rowsAfterSecond[0].finding_hash, firstHash);

  const queried = queryStaticAnalysisIndex(domain, {
    top_k: 5,
    min_severity: "error",
    rule_id: "js/path-injection",
    surface_id: "RS-1",
  });
  assert.equal(queried.length, 1);
  assert.equal(queried[0].finding_hash, firstHash);
}));

test("indexStaticResults re-scores duplicate static leads when reachability appears later", () => withTempHome((home) => {
  const domain = "static-index-late-reachability.example.com";
  const runId = "run-codeql";
  initRepoDomain(domain, home);
  const stdoutPath = writeRunStdout(domain, runId, fixture("codeql-codeflows.sarif"));

  const first = indexStaticResults(domain, {
    run_id: runId,
    stdout_path: stdoutPath,
    tool: "codeql",
    surface_id: "RS-1",
  });
  assert.equal(first.indexed_results, 1);
  assert.equal(first.static_analysis_leads.mapped_leads, 1);
  assert.equal(first.static_analysis_leads.recorded, 1);
  assert.equal(readSurfaceLeadsDocument(domain).leads[0].confidence, "medium");

  fs.writeFileSync(repoInventoryPath(domain), `${JSON.stringify({
    version: 1,
    target_domain: domain,
    reachability: {
      surface_ceilings: [
        {
          id: "RS-1",
          file_path: "routes/download.js",
          attack_vector: "network",
          network_reachable: true,
          severity_ceiling: "critical",
        },
      ],
    },
  })}\n`);

  const second = indexStaticResults(domain, {
    run_id: runId,
    stdout_path: stdoutPath,
    tool: "codeql",
    surface_id: "RS-1",
  });
  assert.equal(second.indexed_results, 0);
  assert.equal(second.duplicate_results, 1);
  assert.equal(second.static_analysis_leads.mapped_leads, 1);
  assert.equal(second.static_analysis_leads.recorded, 0);

  const leadsAfterRescore = readSurfaceLeadsDocument(domain).leads;
  assert.equal(leadsAfterRescore.length, 1);
  assert.equal(leadsAfterRescore[0].confidence, "high");
  assert.ok(leadsAfterRescore[0].high_value_flows.includes("attack_vector=network"));
  assert.ok(leadsAfterRescore[0].high_value_flows.includes("network_reachable=true"));
  assert.ok(leadsAfterRescore[0].high_value_flows.includes("severity_ceiling=critical"));
  assert.equal(
    readFrontierEvents(domain).filter((event) => event.kind === "frontier.enqueued").length,
    2,
    "late reachability re-score should emit a single merge event",
  );

  const third = indexStaticResults(domain, {
    run_id: runId,
    stdout_path: stdoutPath,
    tool: "codeql",
    surface_id: "RS-1",
  });
  assert.equal(third.static_analysis_leads.mapped_leads, 0);
  assert.equal(third.indexed_results, 0);
  assert.equal(third.duplicate_results, 1);
  assert.equal(
    readFrontierEvents(domain).filter((event) => event.kind === "frontier.enqueued").length,
    2,
    "unchanged duplicate rows must not append another frontier.enqueued event",
  );
}));

test("indexStaticResults scores static leads from persisted repo-inventory reachability", () => withTempHome((home) => {
  const domain = "static-index-inventory-reachability.example.com";
  const runId = "run-codeql";
  initRepoDomain(domain, home);
  fs.writeFileSync(repoInventoryPath(domain), `${JSON.stringify({
    version: 1,
    target_domain: domain,
    reachability: {
      network_reachable: true,
      max_credible_severity_ceiling: "critical",
      surface_ceilings: [
        {
          id: "RS-1",
          file_path: "routes/download.js",
          attack_vector: "network",
          network_reachable: true,
          severity_ceiling: "critical",
        },
      ],
    },
  })}\n`);
  const stdoutPath = writeRunStdout(domain, runId, fixture("codeql-codeflows.sarif"));

  const response = indexStaticResults(domain, {
    run_id: runId,
    stdout_path: stdoutPath,
    tool: "codeql",
    surface_id: "RS-1",
  });
  assert.equal(response.indexed_results, 1);
  assert.equal(response.static_analysis_leads.mapped_leads, 1);

  const leads = readSurfaceLeadsDocument(domain).leads;
  assert.equal(leads.length, 1);
  assert.equal(leads[0].confidence, "high");
  assert.deepEqual(leads[0].reachability_meta, {
    attack_vector: "network",
    network_reachable: true,
    severity_ceiling: "critical",
  });
  assert.ok(leads[0].high_value_flows.includes("attack_vector=network"));
  assert.ok(leads[0].high_value_flows.includes("network_reachable=true"));
  assert.ok(leads[0].high_value_flows.includes("severity_ceiling=critical"));
}));

test("indexStaticResults matches persisted reachability by file_path without surface_id", () => withTempHome((home) => {
  const domain = "static-index-inventory-filepath.example.com";
  const runId = "run-codeql";
  initRepoDomain(domain, home);
  fs.writeFileSync(repoInventoryPath(domain), `${JSON.stringify({
    version: 1,
    target_domain: domain,
    reachability: {
      network_reachable: true,
      max_credible_severity_ceiling: "critical",
      surface_ceilings: [
        {
          id: "RS-inventory",
          file_path: "routes/download.js",
          attack_vector: "network",
          network_reachable: true,
          severity_ceiling: "critical",
        },
      ],
    },
  })}\n`);
  const stdoutPath = writeRunStdout(domain, runId, fixture("codeql-codeflows.sarif"));

  const response = indexStaticResults(domain, {
    run_id: runId,
    stdout_path: stdoutPath,
    tool: "codeql",
  });
  assert.equal(response.indexed_results, 1);
  assert.equal(response.static_analysis_leads.mapped_leads, 1);

  const leads = readSurfaceLeadsDocument(domain).leads;
  assert.equal(leads.length, 1);
  assert.equal(leads[0].confidence, "high");
  assert.ok(leads[0].high_value_flows.includes("attack_vector=network"));
  assert.ok(leads[0].high_value_flows.includes("network_reachable=true"));
  assert.ok(leads[0].high_value_flows.includes("severity_ceiling=critical"));
}));

test("indexStaticResults backfills duplicate rows that have no recorded static lead", () => withTempHome((home) => {
  const domain = "static-index-backfill.example.com";
  const runId = "run-codeql";
  initRepoDomain(domain, home);
  const stdoutPath = writeRunStdout(domain, runId, fixture("codeql-codeflows.sarif"));

  const first = indexStaticResults(domain, {
    run_id: runId,
    stdout_path: stdoutPath,
    tool: "codeql",
    surface_id: "RS-1",
    record_static_leads: false,
  });
  assert.equal(first.indexed_results, 1);
  assert.equal(readSurfaceLeadsDocument(domain).leads.length, 0);

  const second = indexStaticResults(domain, {
    run_id: runId,
    stdout_path: stdoutPath,
    tool: "codeql",
    surface_id: "RS-1",
  });
  assert.equal(second.indexed_results, 0);
  assert.equal(second.duplicate_results, 1);
  assert.equal(second.static_analysis_leads.mapped_leads, 1);
  assert.equal(second.static_analysis_leads.recorded, 1);
  assert.equal(readSurfaceLeadsDocument(domain).leads.length, 1);
}));

test("indexStaticResults does not retry unchanged duplicate rows for unrelated reachability", () => withTempHome((home) => {
  const domain = "static-index-unmatched-reachability.example.com";
  const runId = "run-codeql";
  initRepoDomain(domain, home);
  const stdoutPath = writeRunStdout(domain, runId, fixture("codeql-codeflows.sarif"));

  const first = indexStaticResults(domain, {
    run_id: runId,
    stdout_path: stdoutPath,
    tool: "codeql",
    surface_id: "RS-1",
  });
  assert.equal(first.static_analysis_leads.mapped_leads, 1);
  assert.equal(readFrontierEvents(domain).filter((event) => event.kind === "frontier.enqueued").length, 1);

  fs.writeFileSync(repoInventoryPath(domain), `${JSON.stringify({
    version: 1,
    target_domain: domain,
    reachability: {
      surface_ceilings: [
        {
          id: "RS-other",
          file_path: "routes/other.js",
          attack_vector: "network",
          network_reachable: true,
          severity_ceiling: "critical",
        },
      ],
    },
  })}\n`);

  const second = indexStaticResults(domain, {
    run_id: runId,
    stdout_path: stdoutPath,
    tool: "codeql",
    surface_id: "RS-1",
  });
  assert.equal(second.indexed_results, 0);
  assert.equal(second.duplicate_results, 1);
  assert.equal(second.static_analysis_leads.mapped_leads, 0);
  assert.equal(readFrontierEvents(domain).filter((event) => event.kind === "frontier.enqueued").length, 1);
}));

test("indexStaticResults persists only scrubbed Trivy secret rows", () => withTempHome(() => {
  const domain = "static-index-trivy.example.com";
  const runId = "run-trivy";
  initDomain(domain);
  const stdoutPath = writeRunStdout(domain, runId, fixture("trivy-secret.json"));

  const response = indexStaticResults(domain, {
    run_id: runId,
    stdout_path: stdoutPath,
    tool: "trivy",
  });
  assert.equal(response.indexed_results, 1);

  const rawJsonl = fs.readFileSync(staticAnalysisIndexPath(domain), "utf8");
  assert.equal(rawJsonl.includes("AKIA1234567890ABCDEF"), false);
  assert.match(rawJsonl, /REDACTED_AWS_ACCESS_KEY/);

  const rows = readStaticAnalysisIndex(domain);
  assert.equal(rows.length, 1);
  assert.equal(rows[0].tool, "trivy");
  assert.match(rows[0].message, /REDACTED_AWS_ACCESS_KEY/);
  assert.match(rows[0].snippet, /REDACTED_AWS_ACCESS_KEY/);
}));

test("mapSarifResultToSurfaceLead returns unpromoted normalized leads only", () => withTempHome(() => {
  const domain = "static-index-lead.example.com";
  const runId = "run-codeql";
  initDomain(domain);
  const stdoutPath = writeRunStdout(domain, runId, fixture("codeql-codeflows.sarif"));
  indexStaticResults(domain, { run_id: runId, stdout_path: stdoutPath, tool: "codeql" });

  const row = readStaticAnalysisIndex(domain)[0];
  const lead = mapSarifResultToSurfaceLead(row);
  const normalized = normalizeSurfaceLead(lead);
  assert.equal(normalized.source, "static-analysis:codeql");
  assert.equal(normalized.surface_type, "repo");
  assert.equal(normalized.status, "new");
  assert.equal(normalized.promote, false);
  assert.equal(normalized.confidence, "medium");
  assert.ok(normalized.bug_class_hints.includes("js/path-injection"));
  assert.match(normalized.evidence[0], /routes\/download\.js:88/);
}));

test("indexStaticResults treats dry-run rows without stdout_path as no-op", () => withTempHome(() => {
  const domain = "static-index-dry.example.com";
  initDomain(domain);
  const response = indexStaticResults(domain, {
    run_id: "run-dry",
    stdout_path: null,
    tool: "semgrep",
  });
  assert.equal(response.normalized_results, 0);
  assert.equal(response.indexed_results, 0);
  assert.deepEqual(response.static_analysis_leads, {
    mapped_leads: 0,
    recorded: 0,
    skipped_findings: 0,
  });
  assert.equal(readStaticAnalysisIndex(domain).length, 0);
}));

test("readStaticAnalysisIndexTool requires an initialized session", () => withTempHome(() => {
  assert.throws(
    () => readStaticAnalysisIndexTool({ target_domain: "static-index-missing.example.com" }),
    /Missing session state:/,
  );
}));

test("indexStaticResults rejects malformed SARIF without partial index writes", () => withTempHome(() => {
  const domain = "static-index-malformed.example.com";
  const runId = "run-bad";
  initDomain(domain);
  const stdoutPath = writeRunStdout(domain, runId, "{not json");

  assert.throws(
    () => indexStaticResults(domain, { run_id: runId, stdout_path: stdoutPath, tool: "semgrep" }),
    (error) => {
      assert.equal(error.code, "INVALID_ARGUMENTS");
      assert.match(error.message, /Malformed static-analysis JSON/);
      return true;
    },
  );
  assert.equal(fs.existsSync(staticAnalysisIndexPath(domain)), false);
}));
