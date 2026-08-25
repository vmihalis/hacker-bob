"use strict";

// runner-wiring: finding artifact + projection payload tests.
//
// Pure units (template/fingerprint/mappings) plus a fixture-session
// integration: a minimal sealed session (report.md, claim freeze, final
// verification round, evidence packs, grade verdict) assembles into a
// schema-valid artifact whose projection payload maps to the www shape.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const crypto = require("node:crypto");

const {
  assembleFindingArtifact,
  writeFindingArtifact,
} = require("../mcp/lib/finding-artifact.js");
const {
  buildProjectionPayload,
  fingerprintV1,
  projectionDisposition,
  projectionSeverity,
  projectionSurfaceType,
  templateEndpoint,
} = require("../mcp/lib/projection-payload.js");
const {
  postProjection,
} = require("../mcp/lib/projection-client.js");
const {
  sessionDir,
  reportMarkdownPath,
  evidencePackPaths,
  verificationRoundPaths,
  gradeArtifactPaths,
  claimFreezePath,
  findingArtifactPath,
  findingArtifactSidecarPath,
} = require("../mcp/lib/paths.js");

const DOMAIN = "example.com";
const HASH64 = "a".repeat(64);

const FINDING = {
  id: "F-1",
  title: "IDOR on the orders endpoint",
  summary: "An authenticated customer can read any order by id.",
  severity: "high",
  cwe: "CWE-639",
  endpoint: "https://example.com/api/orders/12345",
  auth_profile: "authenticated",
  surface_type: "api",
  response_evidence: "GET /api/orders/12345 -> 200 with a foreign order body",
  proof_of_concept: "swap the trailing id for another customer's order id",
};

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const tempHome = fs.mkdtempSync(path.join(os.tmpdir(), "bob-artifact-"));
  process.env.HOME = tempHome;
  try {
    return fn(tempHome);
  } finally {
    if (previousHome === undefined) delete process.env.HOME;
    else process.env.HOME = previousHome;
    fs.rmSync(tempHome, { recursive: true, force: true });
  }
}

function writeFixture(domain, { reportable = true } = {}) {
  const dir = sessionDir(domain);
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(reportMarkdownPath(domain), "# Sealed report\n\nFixture report content.\n");
  fs.writeFileSync(claimFreezePath(domain), JSON.stringify({
    freeze_id: "FZ-1",
    freeze_hash: HASH64,
    claims: [{ claim_id: "CL-1" }],
  }));
  fs.writeFileSync(verificationRoundPaths(domain, "final").json, JSON.stringify({
    version: 2,
    final_verification_hash: HASH64,
    results: [{
      finding_id: "F-1",
      disposition: reportable ? "confirmed" : "denied",
      severity: reportable ? "high" : "low",
      reportable,
      reasoning: reportable ? "Replay confirmed the cross-account read." : "Replay did not reproduce.",
    }],
  }));
  const packs = reportable
    ? [{
      finding_id: "F-1",
      sample_type: "request_response",
      sample_count: 1,
      aggregate_counts: {},
      representative_samples: [],
      sensitive_clusters: [],
      replay_summary: "Replayed the stored request and observed the foreign order body.",
      redaction_notes: null,
      report_snippet: "The endpoint returns another customer's order.",
    }]
    : [];
  fs.writeFileSync(evidencePackPaths(domain).json, JSON.stringify({
    version: 1,
    target_domain: domain,
    packs,
  }));
  fs.writeFileSync(gradeArtifactPaths(domain).json, JSON.stringify({
    target_domain: domain,
    verdict: reportable ? "SUBMIT" : "SKIP",
    total_score: reportable ? 60 : 0,
    findings: reportable
      ? [{
        finding_id: "F-1",
        impact: 20,
        proof_quality: 20,
        severity_accuracy: 10,
        chain_potential: 5,
        report_quality: 5,
        total_score: 60,
        graded_severity: "high",
        defender_disposition: "fix_now",
      }]
      : [],
    claim_freeze_id: null,
  }));
}

test("templateEndpoint generalizes ids, uuids, and hex segments and drops queries", () => {
  assert.equal(
    templateEndpoint("https://example.com/api/orders/12345?expand=items"),
    "example.com/api/orders/{param}",
  );
  assert.equal(
    templateEndpoint("https://example.com/api/users/550e8400-e29b-41d4-a716-446655440000"),
    "example.com/api/users/{param}",
  );
  assert.equal(
    templateEndpoint("https://example.com/api/tokens/0f577e9b2d6ba74b9cf"),
    "example.com/api/tokens/{param}",
  );
  assert.equal(
    templateEndpoint("https://example.com/api/health"),
    "example.com/api/health",
  );
  assert.equal(templateEndpoint("example.com/static/css/app.css"), "example.com/static/css/app.css");
});

test("fingerprint v1 is stable across concrete ids and changes on class change", () => {
  const base = { domain: DOMAIN, cwe: "CWE-639", authProfile: "authenticated", surfaceType: "api" };
  const first = fingerprintV1({ ...base, endpoint: "https://example.com/api/orders/12345" });
  const second = fingerprintV1({ ...base, endpoint: "https://example.com/api/orders/67890" });
  assert.equal(first, second);
  const otherClass = fingerprintV1({ ...base, endpoint: "https://example.com/api/orders/12345", cwe: "CWE-862" });
  assert.notEqual(first, otherClass);
  assert.match(first, /^[0-9a-f]{64}$/);
});

test("projection mappings follow the www vocabulary", () => {
  assert.equal(projectionSeverity("high"), "high");
  assert.equal(projectionSeverity("info"), null);
  assert.equal(projectionDisposition("fix_now"), "fix-now");
  assert.equal(projectionDisposition("worth_fixing"), "worth-fixing");
  assert.equal(projectionDisposition(undefined), "worth-fixing");
  assert.equal(projectionSurfaceType("auth"), "auth");
  assert.equal(projectionSurfaceType("smart_contract"), "smart_contract");
  assert.equal(projectionSurfaceType("weird_type"), "api");
});

test("sealed session assembles a schema-valid artifact and writes the sidecar", () => {
  withTempHome(() => {
    writeFixture(DOMAIN);
    const result = writeFindingArtifact(DOMAIN, { findings: [FINDING] });
    assert.equal(result.emitted, true);
    assert.equal(result.reportableCount, 1);
    const artifact = JSON.parse(fs.readFileSync(findingArtifactPath(DOMAIN), "utf8"));
    assert.equal(artifact.schemaVersion, 1);
    assert.equal(artifact.targetKind, "web");
    assert.equal(artifact.target.name, DOMAIN);
    assert.equal(artifact.findings.length, 1);
    assert.equal(artifact.findings[0].id, "F-1");
    assert.equal(artifact.findings[0].band, "high");
    assert.equal(artifact.receipt.evidenceHash, result.bundle.grade_verdict_hash);
    const sidecar = fs.readFileSync(findingArtifactSidecarPath(DOMAIN), "utf8").trim();
    const expected = crypto.createHash("sha256")
      .update(fs.readFileSync(findingArtifactPath(DOMAIN)))
      .digest("hex");
    assert.equal(sidecar, `${expected}  finding-artifact.json`);
  });
});

test("projection payload maps the sealed run into the www shape", () => {
  withTempHome(() => {
    writeFixture(DOMAIN);
    const { payload } = buildProjectionPayload(DOMAIN, {
      runSlug: "run-fixture",
      projectionKey: "projection-fixture",
      reportSlug: "report-fixture",
      kind: "assessment",
      retestOf: ["old-fingerprint"],
      findings: [FINDING],
    });
    assert.equal(payload.runSlug, "run-fixture");
    assert.equal(payload.projectionKey, "projection-fixture");
    assert.equal(payload.reportSlug, "report-fixture");
    assert.equal(payload.kind, "scan");
    assert.deepEqual(payload.retestOf, ["old-fingerprint"]);
    assert.equal(payload.freezeHash.length, 64);
    assert.equal(payload.findings.length, 1);
    const row = payload.findings[0];
    assert.match(row.fingerprint, /^[0-9a-f]{64}$/);
    assert.equal(row.fingerprintVersion, 1);
    assert.equal(row.refId, "F-1");
    assert.equal(row.severity, "high");
    assert.equal(row.disposition, "fix-now");
    assert.equal(row.reproduced, true);
    assert.equal(row.reachable, true);
    assert.equal(row.reportable, true);
    assert.equal(row.surfaceType, "api");
    assert.equal(row.open, true);
    assert.equal(row.cwe[0].id, "CWE-639");
    assert.equal(row.cwe[0].name, "Authorization Bypass Through User-Controlled Key");
  });
});

test("a clean scan emits no artifact and projects an empty findings array", () => {
  withTempHome(() => {
    writeFixture(DOMAIN, { reportable: false });
    const assembled = assembleFindingArtifact(DOMAIN, { findings: [FINDING] });
    assert.equal(assembled.emitted, false);
    assert.equal(assembled.reason, "no_reportable_findings");
    assert.equal(fs.existsSync(findingArtifactPath(DOMAIN)), false);
    const { payload } = buildProjectionPayload(DOMAIN, {
      runSlug: "run-clean",
      projectionKey: "projection-clean",
      kind: "assessment",
      findings: [FINDING],
    });
    assert.deepEqual(payload.findings, []);
  });
});

test("postProjection retries transient failures, fails fast on rejection, and honors retry caps", async () => {
  const calls = [];
  const flaky = async () => {
    calls.push(1);
    if (calls.length < 3) return new Response(null, { status: 503 });
    return new Response(JSON.stringify({ projected: 1 }), { status: 200 });
  };
  const recovered = await postProjection({
    url: "https://projection.invalid",
    secret: "secret",
    payload: { findings: [] },
    fetchImpl: flaky,
    initialDelayMs: 1,
  });
  assert.equal(recovered.ok, true);
  assert.equal(recovered.attempts, 3);

  const rejected = await postProjection({
    url: "https://projection.invalid",
    secret: "secret",
    payload: { findings: [] },
    fetchImpl: async () => new Response("bad capability", { status: 400 }),
    initialDelayMs: 1,
  });
  assert.equal(rejected.ok, false);
  assert.equal(rejected.status, 400);
  assert.equal(rejected.attempts, 1);

  await assert.rejects(
    () => postProjection({
      url: "https://projection.invalid",
      secret: "secret",
      payload: { findings: [] },
      fetchImpl: async () => new Response(null, { status: 500 }),
      maxAttempts: 2,
      initialDelayMs: 1,
    }),
    /after 2 attempts/,
  );
});
