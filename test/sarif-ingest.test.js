"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const {
  MAX_RESULTS,
  MAX_SARIF_BYTES,
  ingestSarif,
  parseSarif,
  readStaticAnalysisResultsFromJsonl,
} = require("../mcp/lib/sarif-ingest.js");
const {
  isAuditGradedPath,
  repoRunsDir,
  repoWorkDir,
  staticAnalysisIndexPath,
  staticAnalysisResultsJsonlPath,
} = require("../mcp/lib/paths.js");
const {
  initSession,
} = require("../mcp/lib/session-state.js");
const {
  initRepoSession,
} = require("../mcp/lib/repo-target.js");
const {
  readSurfaceLeadsDocument,
} = require("../mcp/lib/lead-intake.js");

require("../mcp/lib/lead-promotion.js");

function fixture(name) {
  return fs.readFileSync(path.join(__dirname, "fixtures", "sarif", name), "utf8");
}

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-sarif-ingest-"));
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
  fs.writeFileSync(path.join(repoRunsDir(domain), `${runId}.stdout`), content, "utf8");
}

function writeWorkArtifact(domain, rel, content) {
  const filePath = path.join(repoWorkDir(domain), rel);
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, content, "utf8");
  return filePath;
}

function sarifResult({
  ruleId = "RULE-1",
  level = "warning",
  message = "fixture message",
  uri = "src/main.js",
  startLine = 1,
  snippet = "fixture();",
  partialFingerprints = null,
} = {}) {
  const result = {
    ruleId,
    level,
    message: { text: message },
    locations: [
      {
        physicalLocation: {
          artifactLocation: { uri },
          region: {
            startLine,
            endLine: startLine,
            snippet: { text: snippet },
          },
        },
      },
    ],
  };
  if (partialFingerprints) result.partialFingerprints = partialFingerprints;
  return result;
}

function sarifDocument(results, { toolName = "semgrep", version = "1.0.0" } = {}) {
  return JSON.stringify({
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: toolName,
            semanticVersion: version,
            rules: results
              .filter((result) => result && typeof result.ruleId === "string")
              .map((result) => ({ id: result.ruleId })),
          },
        },
        results,
      },
    ],
  });
}

test("parseSarif normalizes semgrep and trivy SARIF 2.1.0 fixtures", () => {
  const semgrep = parseSarif(fixture("semgrep.sarif"), { source_run_id: "run-semgrep" });
  assert.equal(semgrep.records.length, 1);
  assert.deepEqual({
    tool_name: semgrep.records[0].tool_name,
    tool_version: semgrep.records[0].tool_version,
    rule_id: semgrep.records[0].rule_id,
    severity_signal: semgrep.records[0].severity_signal,
    message: semgrep.records[0].message,
    snippet: semgrep.records[0].snippet,
    artifact_uri: semgrep.records[0].artifact_uri,
    start_line: semgrep.records[0].start_line,
    end_line: semgrep.records[0].end_line,
    source_run_id: semgrep.records[0].source_run_id,
  }, {
    tool_name: "semgrep",
    tool_version: "1.75.0",
    rule_id: "javascript.lang.security.audit.detect-eval-with-expression.detect-eval-with-expression",
    severity_signal: "warning",
    message: "Detected eval() with a non-literal argument.",
    snippet: "eval(userInput);",
    artifact_uri: "src/app.js",
    start_line: 42,
    end_line: 42,
    source_run_id: "run-semgrep",
  });
  assert.match(semgrep.records[0].result_sha256, /^[a-f0-9]{64}$/);

  const trivy = parseSarif(fixture("trivy.sarif"), { source_run_id: "run-trivy" });
  assert.equal(trivy.records.length, 1);
  assert.deepEqual({
    tool_name: trivy.records[0].tool_name,
    tool_version: trivy.records[0].tool_version,
    rule_id: trivy.records[0].rule_id,
    severity_signal: trivy.records[0].severity_signal,
    message: trivy.records[0].message,
    snippet: trivy.records[0].snippet,
    artifact_uri: trivy.records[0].artifact_uri,
    start_line: trivy.records[0].start_line,
    end_line: trivy.records[0].end_line,
    source_run_id: trivy.records[0].source_run_id,
  }, {
    tool_name: "trivy",
    tool_version: "0.52.2",
    rule_id: "CVE-2024-12345",
    severity_signal: "error",
    message: "package fixture-lib is affected by CVE-2024-12345",
    snippet: "\"fixture-lib\": \"1.0.0\"",
    artifact_uri: "package-lock.json",
    start_line: 7,
    end_line: 9,
    source_run_id: "run-trivy",
  });
  assert.match(trivy.records[0].result_sha256, /^[a-f0-9]{64}$/);
});

test("parseSarif is deterministic for identical SARIF bytes and stable hash inputs", () => {
  const sarif = fixture("semgrep.sarif");
  const first = parseSarif(sarif);
  const second = parseSarif(sarif);
  assert.deepEqual(first.records, second.records);

  const runA = parseSarif(sarif, { source_run_id: "run-a" }).records[0];
  const runB = parseSarif(sarif, { source_run_id: "run-b" }).records[0];
  assert.equal(runA.result_sha256, runB.result_sha256);
  assert.equal(runA.fingerprint, runB.fingerprint);
});

test("parseSarif preserves repo-relative paths that contain src directories", () => {
  const relative = parseSarif(sarifDocument([
    sarifResult({ uri: "packages/api/src/index.js" }),
  ]));
  assert.equal(relative.records[0].artifact_uri, "packages/api/src/index.js");

  const mounted = parseSarif(sarifDocument([
    sarifResult({ uri: "/src/packages/api/src/index.js" }),
  ]));
  assert.equal(mounted.records[0].artifact_uri, "packages/api/src/index.js");
});

test("parseSarif strips query and fragment data from artifact URIs", () => {
  const parsed = parseSarif(sarifDocument([
    sarifResult({
      ruleId: "QUERY",
      uri: "src/config.js?token=artifactsecret#fragment",
    }),
    sarifResult({
      ruleId: "ENCODED",
      uri: "src/encoded.js%3Fapi_key%3Dartifactsecret%23fragment",
      startLine: 2,
    }),
  ]));

  assert.equal(parsed.records[0].artifact_uri, "src/config.js");
  assert.equal(parsed.records[1].artifact_uri, "src/encoded.js");
  assert.equal(JSON.stringify(parsed.records).includes("artifactsecret"), false);
});

test("parseSarif honors rule default severity and SARIF warning default", () => {
  const defaulted = sarifResult({ ruleId: "RULE-DEFAULT", level: "warning" });
  delete defaulted.ruleId;
  delete defaulted.level;
  defaulted.ruleIndex = 0;

  const parsed = parseSarif(JSON.stringify({
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "semgrep",
            rules: [
              {
                id: "RULE-DEFAULT",
                defaultConfiguration: { level: "error" },
              },
            ],
          },
        },
        results: [defaulted],
      },
    ],
  }));
  assert.equal(parsed.records[0].rule_id, "RULE-DEFAULT");
  assert.equal(parsed.records[0].severity_signal, "error");

  const noLevel = sarifResult({ ruleId: "RULE-WARNING", level: "warning" });
  delete noLevel.level;
  const fallback = parseSarif(sarifDocument([noLevel]));
  assert.equal(fallback.records[0].severity_signal, "warning");
});

test("parseSarif warns and skips malformed, truncated, and missing-location rows without dropping valid rows", () => {
  assert.doesNotThrow(() => parseSarif("{not json"));
  const malformed = parseSarif("{not json");
  assert.deepEqual(malformed.records, []);
  assert.match(malformed.warnings[0], /Malformed SARIF JSON/);

  const mixed = parseSarif(sarifDocument([
    sarifResult({ ruleId: "VALID", startLine: 3 }),
    { ruleId: "NOLOC", level: "error", message: { text: "missing location" }, locations: [] },
    null,
  ]));
  assert.equal(mixed.records.length, 1);
  assert.equal(mixed.records[0].rule_id, "VALID");
  assert.equal(mixed.skipped_results, 2);
  assert.match(mixed.warnings.join("\n"), /missing physicalLocation/);
});

test("empty SARIF runs and results produce no index entry", () => withTempHome(() => {
  assert.deepEqual(parseSarif(JSON.stringify({ version: "2.1.0", runs: [] })).records, []);
  assert.deepEqual(parseSarif(sarifDocument([])).records, []);

  const domain = "sarif-empty.example.com";
  initDomain(domain);
  writeRunStdout(domain, "run-empty", JSON.stringify({ version: "2.1.0", runs: [] }));
  const response = JSON.parse(ingestSarif({ target_domain: domain, run_id: "run-empty" }));
  assert.equal(response.normalized_results, 0);
  assert.equal(response.ingested_results, 0);
  assert.equal(fs.existsSync(staticAnalysisResultsJsonlPath(domain)), false);
}));

test("parseSarif truncates over MAX_RESULTS deterministically per run", () => {
  const results = [];
  for (let i = 0; i < MAX_RESULTS + 2; i += 1) {
    results.push(sarifResult({
      ruleId: `RULE-${String(i).padStart(3, "0")}`,
      startLine: i + 1,
      message: `message ${i}`,
    }));
  }
  const parsed = parseSarif(sarifDocument(results));
  assert.equal(parsed.records.length, MAX_RESULTS);
  assert.equal(parsed.records[0].rule_id, "RULE-000");
  assert.equal(parsed.records[MAX_RESULTS - 1].rule_id, `RULE-${String(MAX_RESULTS - 1).padStart(3, "0")}`);
  assert.equal(parsed.truncated, true);
  assert.match(parsed.warnings.join("\n"), new RegExp(`processed first ${MAX_RESULTS}`));
});

test("parseSarif enforces MAX_RESULTS across multiple SARIF runs", () => {
  const first = [];
  const second = [];
  for (let i = 0; i < 300; i += 1) {
    first.push(sarifResult({
      ruleId: `A-${String(i).padStart(3, "0")}`,
      startLine: i + 1,
      message: `first ${i}`,
    }));
    second.push(sarifResult({
      ruleId: `B-${String(i).padStart(3, "0")}`,
      startLine: i + 1,
      message: `second ${i}`,
    }));
  }

  const parsed = parseSarif(JSON.stringify({
    version: "2.1.0",
    runs: [
      {
        tool: { driver: { name: "semgrep" } },
        results: first,
      },
      {
        tool: { driver: { name: "trivy" } },
        results: second,
      },
    ],
  }));
  assert.equal(parsed.total_results, 600);
  assert.equal(parsed.records.length, MAX_RESULTS);
  assert.equal(parsed.records[299].rule_id, "A-299");
  assert.equal(parsed.records[300].rule_id, "B-000");
  assert.equal(parsed.records[MAX_RESULTS - 1].rule_id, "B-199");
  assert.equal(parsed.truncated, true);
});

test("parseSarif bounds untrusted scalar fields before emitting records", () => {
  const parsed = parseSarif(sarifDocument([
    sarifResult({
      ruleId: `RULE-${"r".repeat(300)}`,
      uri: `packages/${"a".repeat(400)}.js`,
      message: "m".repeat(800),
      snippet: "s".repeat(800),
    }),
  ], {
    toolName: `tool-${"t".repeat(200)}`,
    version: `version-${"v".repeat(120)}`,
  }));
  const record = parsed.records[0];
  assert.equal(record.tool_name.length, 120);
  assert.equal(record.tool_version.length, 80);
  assert.equal(record.rule_id.length, 160);
  assert.equal(record.artifact_uri.length, 260);
  assert.equal(record.message.length, 500);
  assert.equal(record.snippet.length, 500);
});

test("ingestSarif redacts secrets before persistence and dedupes by result_sha256", () => withTempHome((home) => {
  const domain = "sarif-redact.example.com";
  const runId = "run-redact";
  initRepoDomain(domain, home);
  writeRunStdout(domain, runId, sarifDocument([
    sarifResult({
      ruleId: "SECRET-RULE",
      level: "error",
      message: "credential AKIA1234567890ABCDEF found at https://example.com/path?token=supersecret",
      snippet: "const url = \"https://example.com/download?api_key=supersecret\";",
      uri: "/src/config.js",
      startLine: 12,
      partialFingerprints: {
        "fingerprint-token": "AKIA9999999999999999",
        url: "https://example.com/path?token=fingerprintsecret",
      },
    }),
  ], { toolName: "trivy", version: "0.52.2" }));

  const response = JSON.parse(ingestSarif({ target_domain: domain, run_id: runId }));
  assert.equal(response.ingested_results, 1);
  assert.equal(response.duplicate_results, 0);
  assert.equal(response.results_path, "static-analysis-results.jsonl");
  assert.equal(response.index_path, "static-analysis-index.jsonl");
  assert.equal(response.static_analysis_index.indexed_results, 1);
  assert.equal(response.static_analysis_index.static_analysis_leads.mapped_leads, 1);
  assert.equal(response.static_analysis_index.static_analysis_leads.recorded, 1);
  assert.equal(JSON.stringify(response).includes(process.env.HOME), false);
  assert.ok(JSON.stringify(response).length < 8_000, "ingest response must stay bounded");

  const rawJsonl = fs.readFileSync(staticAnalysisResultsJsonlPath(domain), "utf8");
  assert.equal(rawJsonl.includes("AKIA1234567890ABCDEF"), false);
  assert.equal(rawJsonl.includes("AKIA9999999999999999"), false);
  assert.equal(rawJsonl.includes("supersecret"), false);
  assert.equal(rawJsonl.includes("fingerprintsecret"), false);
  assert.match(rawJsonl, /REDACTED_AWS_ACCESS_KEY/);
  assert.match(rawJsonl, /REDACTED/);

  const records = readStaticAnalysisResultsFromJsonl(domain);
  assert.equal(records.length, 1);
  assert.equal(records[0].source_run_id, runId);
  assert.match(records[0].message, /REDACTED_AWS_ACCESS_KEY/);
  assert.match(records[0].snippet, /REDACTED/);
  assert.match(records[0].fingerprint, /^[a-f0-9]{64}$/);
  assert.equal(isAuditGradedPath(staticAnalysisResultsJsonlPath(domain), domain), false);
  assert.equal(fs.existsSync(staticAnalysisIndexPath(domain)), true);
  const surfaceLeads = readSurfaceLeadsDocument(domain).leads;
  assert.equal(surfaceLeads.length, 1);
  assert.equal(surfaceLeads[0].source, "bob_static_scan");
  assert.equal(surfaceLeads[0].surface_type, "oss_static_sink");
  assert.equal(JSON.stringify(surfaceLeads).includes("AKIA1234567890ABCDEF"), false);
  assert.equal(JSON.stringify(surfaceLeads).includes("supersecret"), false);

  const second = JSON.parse(ingestSarif({ target_domain: domain, run_id: runId }));
  assert.equal(second.ingested_results, 0);
  assert.equal(second.duplicate_results, 1);
  assert.equal(second.static_analysis_index.duplicate_results, 1);
  assert.equal(readStaticAnalysisResultsFromJsonl(domain).length, 1);
}));

test("ingestSarif indexes but does not record OSS leads for non-repo sessions", () => withTempHome(() => {
  const domain = "sarif-url-session.example.com";
  const runId = "run-url";
  initDomain(domain);
  writeRunStdout(domain, runId, sarifDocument([
    sarifResult({
      ruleId: "URL-SESSION-RULE",
      level: "error",
      message: "bounded static lead seed",
      uri: "/src/config.js",
      startLine: 12,
    }),
  ], { toolName: "semgrep" }));

  const response = JSON.parse(ingestSarif({ target_domain: domain, run_id: runId }));
  assert.equal(response.ingested_results, 1);
  assert.equal(response.static_analysis_index.indexed_results, 1);
  assert.equal(response.static_analysis_index.static_analysis_leads.mapped_leads, 0);
  assert.equal(response.static_analysis_index.static_analysis_leads.recorded, 0);
  assert.equal(readSurfaceLeadsDocument(domain).leads.length, 0);
}));

test("ingestSarif reads explicit SARIF artifacts only under repo-work", () => withTempHome(() => {
  const domain = "sarif-work.example.com";
  initDomain(domain);
  writeWorkArtifact(domain, "trivy.sarif", fixture("trivy.sarif"));

  const response = JSON.parse(ingestSarif({
    target_domain: domain,
    artifact_path: "/work/trivy.sarif",
  }));
  assert.equal(response.source.kind, "work_artifact");
  assert.equal(response.ingested_results, 1);
  assert.equal(response.static_analysis_index.indexed_results, 1);
  assert.equal(readStaticAnalysisResultsFromJsonl(domain).length, 1);

  const outside = path.join(os.tmpdir(), "outside.sarif");
  fs.writeFileSync(outside, fixture("trivy.sarif"), "utf8");
  assert.throws(
    () => ingestSarif({ target_domain: domain, artifact_path: outside }),
    /artifact_path escapes allowed root/,
  );
  fs.rmSync(outside, { force: true });
}));

test("ingestSarif rejects oversized SARIF artifacts without leaking host paths", () => withTempHome(() => {
  const domain = "sarif-large.example.com";
  initDomain(domain);
  const filePath = writeWorkArtifact(domain, "large.sarif", " ".repeat(MAX_SARIF_BYTES + 1));

  assert.throws(
    () => ingestSarif({ target_domain: domain, artifact_path: "/work/large.sarif" }),
    (error) => {
      assert.match(error.message, /\/work\/large\.sarif exceeds SARIF read cap/);
      assert.equal(error.message.includes(filePath), false);
      return true;
    },
  );
}));
