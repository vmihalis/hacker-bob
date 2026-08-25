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
  buildArtifactFindings,
  writeFindingArtifact,
} = require("../mcp/finding-artifact.js");
const {
  normalizeEndpointForDedupe,
  normalizeFindingRecord,
} = require("../mcp/core/finding-contracts.js");
const recordCandidateClaimTool = require("../mcp/tools/record-candidate-claim.js");
const {
  CONSOLE_REPORT_MAX_BYTES,
  CONSOLE_REPORT_MAX_FINDINGS,
  assertConsoleReportBounds,
  buildProjectionPayload,
  fingerprintV1,
  projectionCwe,
  projectionDisposition,
  projectionSeverity,
  projectionSurfaceType,
  safeRouteTemplate,
} = require("../mcp/projection-payload.js");
const {
  postProjection,
} = require("../mcp/projection-client.js");
const {
  sessionDir,
  reportMarkdownPath,
  evidencePackPaths,
  verificationRoundPaths,
  gradeArtifactPaths,
  claimFreezePath,
  findingArtifactPath,
  findingArtifactSidecarPath,
} = require("../mcp/core/io/paths.js");

const DOMAIN = "example.com";
const HASH64 = "a".repeat(64);

const FINDING = {
  id: "F-1",
  title: "IDOR on the orders endpoint",
  summary: "An authenticated customer can read any order by id.",
  severity: "high",
  cwe: "CWE-639",
  endpoint: "https://example.com/api/orders/12345",
  request_method: "GET",
  injection_point: "path:order_id",
  auth_profile: "authenticated",
  surface_type: "web",
  source_surface_type: "api",
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

function writeFixture(
  domain,
  { reportable = true, gradeFindingOverrides = {}, findingIds = ["F-1"] } = {},
) {
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
    results: findingIds.map((findingId) => ({
      finding_id: findingId,
      disposition: reportable ? "confirmed" : "denied",
      severity: reportable ? "high" : "low",
      reportable,
      reasoning: reportable ? "Replay confirmed the cross-account read." : "Replay did not reproduce.",
    })),
  }));
  const packs = reportable
    ? findingIds.map((findingId) => ({
      finding_id: findingId,
      sample_type: "request_response",
      sample_count: 1,
      aggregate_counts: {},
      representative_samples: [],
      sensitive_clusters: [],
      replay_summary: "Replayed the stored request and observed the foreign order body.",
      redaction_notes: null,
      report_snippet: "The endpoint returns another customer's order.",
    }))
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
      ? findingIds.map((findingId) => ({
        finding_id: findingId,
        impact: 20,
        proof_quality: 20,
        severity_accuracy: 10,
        chain_potential: 5,
        report_quality: 5,
        total_score: 60,
        graded_severity: "high",
        defender_disposition: "fix_now",
        ...gradeFindingOverrides,
      }))
      : [],
    claim_freeze_id: null,
  }));
}

test("safeRouteTemplate generalizes path ids and preserves sorted query-key placeholders", () => {
  assert.equal(
    safeRouteTemplate("https://example.com/api/orders/12345?expand=items"),
    "example.com/api/orders/{param}?expand=*",
  );
  assert.equal(
    safeRouteTemplate("https://example.com/api/users/550e8400-e29b-41d4-a716-446655440000"),
    "example.com/api/users/{param}",
  );
  assert.equal(
    safeRouteTemplate("https://example.com/api/tokens/0f577e9b2d6ba74b9cf"),
    "example.com/api/tokens/{param}",
  );
  assert.equal(
    safeRouteTemplate("https://example.com/api/health"),
    "example.com/api/health",
  );
  assert.equal(
    safeRouteTemplate("example.com/orders/123?z=secret&a=private"),
    "example.com/orders/{param}?a=*&z=*",
  );
  assert.equal(
    normalizeEndpointForDedupe("HTTPS://Example.COM/api/orders/123/?z=secret&A=private#raw"),
    "https://example.com/api/orders/123?a=*&z=*",
  );
});

test("fingerprint v1 separates continuity tuples while correlating concrete path ids", () => {
  const web = {
    findingId: "F-web",
    domain: DOMAIN,
    endpoint: "https://example.com/api/orders/12345?expand=items",
    requestMethod: "GET",
    injectionPoint: "path:order_id",
    cwe: "CWE-639",
    authProfile: "authenticated",
    surfaceType: "web",
    sourceSurfaceType: "api",
  };
  const first = fingerprintV1(web);
  assert.equal(
    first,
    fingerprintV1({ ...web, endpoint: "https://example.com/api/orders/67890?expand=private" }),
  );
  assert.notEqual(first, fingerprintV1({ ...web, endpoint: "https://example.com/api/orders/12345?view=items" }));
  assert.notEqual(first, fingerprintV1({ ...web, requestMethod: "POST" }));
  assert.notEqual(first, fingerprintV1({ ...web, injectionPoint: "header:X-Order" }));

  const graphql = {
    ...web,
    findingId: "F-graphql",
    sourceSurfaceType: "graphql",
    graphqlOperation: "GetOrder",
    graphqlResolver: "Query.order",
    injectionPoint: "variable:id",
  };
  const graphqlHash = fingerprintV1(graphql);
  assert.notEqual(graphqlHash, fingerprintV1({ ...graphql, graphqlOperation: "UpdateOrder" }));
  assert.notEqual(graphqlHash, fingerprintV1({ ...graphql, graphqlResolver: "Mutation.updateOrder" }));

  const smartContract = {
    findingId: "F-contract",
    cwe: "CWE-284",
    surfaceType: "smart_contract",
    scEvidence: {
      chain_family: "evm",
      chain_id: 1,
      contract_address: `0x${"a".repeat(40)}`,
      function_signature: "withdraw(uint256)",
    },
  };
  const contractHash = fingerprintV1(smartContract);
  assert.notEqual(contractHash, fingerprintV1({
    ...smartContract,
    scEvidence: { ...smartContract.scEvidence, chain_id: 10 },
  }));
  assert.notEqual(contractHash, fingerprintV1({
    ...smartContract,
    scEvidence: { ...smartContract.scEvidence, contract_address: `0x${"b".repeat(40)}` },
  }));
  assert.notEqual(contractHash, fingerprintV1({
    ...smartContract,
    scEvidence: { ...smartContract.scEvidence, function_signature: "deposit(uint256)" },
  }));
  assert.throws(
    () => fingerprintV1({ ...web, authProfile: null }),
    /finding F-web lacks fingerprint input: auth_profile/,
  );
  assert.match(first, /^[0-9a-f]{64}$/);
});

test("projection mappings follow the www vocabulary", () => {
  assert.equal(projectionSeverity("high"), "high");
  assert.equal(projectionSeverity("info"), null);
  assert.equal(projectionDisposition("fix_now"), "fix-now");
  assert.equal(projectionDisposition("worth_fixing"), "worth-fixing");
  assert.throws(
    () => projectionDisposition(undefined, "F-missing"),
    /finding F-missing has missing or unsupported defender_disposition/,
  );
  assert.throws(
    () => projectionDisposition("later", "F-invalid"),
    /finding F-invalid has missing or unsupported defender_disposition/,
  );
  assert.equal(projectionSurfaceType("web"), "web");
  assert.equal(projectionSurfaceType("smart_contract"), "smart_contract");
  assert.throws(() => projectionSurfaceType("weird_type"), /unsupported projection surface_type/);
  assert.deepEqual(
    projectionCwe("CWE-639", "F-cwe"),
    [{ id: "CWE-639", name: "Authorization Bypass Through User-Controlled Key (IDOR)" }],
  );
  assert.throws(
    () => projectionCwe("CWE-999999", "F-unknown-cwe"),
    /finding F-unknown-cwe has missing or unsupported CWE/,
  );
});

test("console projection enforces the hosted report parser bounds", () => {
  assert.throws(
    () => assertConsoleReportBounds(DOMAIN, Array(CONSOLE_REPORT_MAX_FINDINGS + 1).fill({})),
    new RegExp(`at most ${CONSOLE_REPORT_MAX_FINDINGS} findings`, "u"),
  );
  assert.throws(
    () => assertConsoleReportBounds(DOMAIN, [{ plainRead: "x".repeat(CONSOLE_REPORT_MAX_BYTES) }]),
    new RegExp(`${CONSOLE_REPORT_MAX_BYTES} bytes or fewer`, "u"),
  );
});

test("artifact assembly rejects reportable findings without valid graded severity", () => {
  const result = { finding_id: "F-ungraded", reportable: true };
  const finding = { id: "F-ungraded", title: "Ungraded finding" };
  assert.throws(
    () => buildArtifactFindings(DOMAIN, [result], [finding], { findings: [] }),
    /reportable finding F-ungraded lacks a valid graded severity/,
  );
  assert.throws(
    () => buildArtifactFindings(
      DOMAIN,
      [{ ...result, severity: "urgent" }],
      [finding],
      { findings: [] },
    ),
    /reportable finding F-ungraded lacks a valid graded severity/,
  );
});

test("web and GraphQL continuity fields normalize and enforce bounded values", () => {
  const base = {
    ...FINDING,
    target_domain: DOMAIN,
    description: FINDING.summary,
    validated: true,
  };
  const normalized = normalizeFindingRecord({
    ...base,
    request_method: "patch",
    injection_point: "json:user.id",
    graphql_operation: "UpdateUser",
    graphql_resolver: "Mutation.updateUser",
    source_surface_type: "graphql",
  });
  assert.equal(normalized.request_method, "PATCH");
  assert.equal(normalized.injection_point, "json:user.id");
  assert.equal(normalized.graphql_operation, "UpdateUser");
  assert.equal(normalized.graphql_resolver, "Mutation.updateUser");

  assert.throws(
    () => normalizeFindingRecord({ ...base, request_method: "CONNECT" }),
    /request_method must be one of/,
  );
  assert.throws(
    () => normalizeFindingRecord({ ...base, injection_point: "query:id\u0000" }),
    /injection_point must not contain control characters/,
  );
  assert.throws(
    () => normalizeFindingRecord({ ...base, injection_point: "x".repeat(201) }),
    /injection_point must be at most 200 characters/,
  );
  assert.throws(
    () => normalizeFindingRecord({ ...base, graphql_operation: "x".repeat(129) }),
    /graphql_operation must be at most 128 characters/,
  );
  assert.throws(
    () => normalizeFindingRecord({ ...base, graphql_resolver: "x".repeat(257) }),
    /graphql_resolver must be at most 256 characters/,
  );

  const legacy = normalizeFindingRecord({
    ...base,
    request_method: undefined,
    injection_point: undefined,
  });
  assert.equal(legacy.request_method, null);
  assert.equal(legacy.injection_point, null);

  const properties = recordCandidateClaimTool.inputSchema.properties;
  assert.equal(properties.injection_point.maxLength, 200);
  assert.equal(properties.graphql_operation.maxLength, 128);
  assert.equal(properties.graphql_resolver.maxLength, 256);
  assert.match(recordCandidateClaimTool.description, /Reportable web findings must record/);
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
    const hostileFinding = {
      ...FINDING,
      title: "<script>alert('raw title')</script>",
      summary: "token=super-secret should never reach the browser",
      endpoint: "https://operator:password@example.com/api/orders/12345?token=super-secret&expand=items#raw",
      response_evidence: "Bearer raw-secret-response",
      proof_of_concept: "<script>raw-proof()</script>",
      remediation: "paste raw-secret-fix",
    };
    const { payload } = buildProjectionPayload(DOMAIN, {
      runSlug: "run-fixture",
      projectionKey: "projection-fixture",
      reportSlug: "report-fixture",
      kind: "assessment",
      retestOf: [],
      findings: [hostileFinding],
    });
    assert.equal(payload.runSlug, "run-fixture");
    assert.equal(payload.projectionKey, "projection-fixture");
    assert.equal(payload.reportSlug, "report-fixture");
    assert.equal(payload.kind, "scan");
    assert.equal(Object.prototype.hasOwnProperty.call(payload, "retestOf"), false);
    assert.equal(payload.freezeHash.length, 64);
    assert.equal(payload.findings.length, 1);
    const row = payload.findings[0];
    assert.match(row.fingerprint, /^[0-9a-f]{64}$/);
    assert.equal(row.fingerprintVersion, 1);
    assert.equal(row.refId, "F-1");
    assert.equal(row.severity, "high");
    assert.equal(row.disposition, "fix-now");
    assert.equal(row.score, 60);
    assert.deepEqual(row.scoreAxes, {
      impact: 20,
      proof: 20,
      severityAccuracy: 10,
      chain: 5,
      report: 5,
    });
    assert.equal(row.reproduced, true);
    assert.equal(row.reachable, true);
    assert.equal(row.reportable, true);
    assert.equal(row.surfaceType, "web");
    assert.equal(row.open, true);
    assert.equal(row.cwe[0].id, "CWE-639");
    assert.equal(row.cwe[0].name, "Authorization Bypass Through User-Controlled Key (IDOR)");
    assert.equal(row.title, "Authorization Bypass Through User-Controlled Key (IDOR) — Web API");
    assert.equal(
      row.plainRead,
      "Web API finding classified as CWE-639: Authorization Bypass Through User-Controlled Key (IDOR).",
    );
    assert.equal(row.endpoint, "example.com/api/orders/{param}?expand=*&token=*");
    assert.equal(Object.prototype.hasOwnProperty.call(row, "remediation"), false);
    const browserRow = JSON.stringify(row);
    for (const forbidden of ["<script>", "super-secret", "raw-secret", "password"]) {
      assert.equal(browserRow.includes(forbidden), false, `browser row leaked ${forbidden}`);
    }
  });
});

test("projection rejects distinct findings with the same continuity fingerprint", () => {
  withTempHome(() => {
    writeFixture(DOMAIN, { findingIds: ["F-1", "F-2"] });
    assert.throws(
      () => buildProjectionPayload(DOMAIN, {
        runSlug: "run-duplicate-continuity",
        projectionKey: "projection-duplicate-continuity",
        kind: "assessment",
        findings: [
          FINDING,
          { ...FINDING, id: "F-2" },
        ],
      }),
      /findings F-1 and F-2 resolve to duplicate projection fingerprint/u,
    );
  });
});

test("retest projection emits explicit closure markers for scoped findings not reproduced", () => {
  withTempHome(() => {
    writeFixture(DOMAIN);
    const baseline = buildProjectionPayload(DOMAIN, {
      runSlug: "baseline-run",
      projectionKey: "baseline-key",
      kind: "assessment",
      findings: [FINDING],
    });
    const reproducedFingerprint = baseline.payload.findings[0].fingerprint;
    const absentFingerprint = reproducedFingerprint === "f".repeat(64)
      ? "e".repeat(64)
      : "f".repeat(64);
    const { payload } = buildProjectionPayload(DOMAIN, {
      runSlug: "retest-run",
      projectionKey: "retest-key",
      kind: "retest",
      retestOf: [reproducedFingerprint, absentFingerprint],
      findings: [FINDING],
    });

    assert.equal(payload.kind, "retest");
    assert.deepEqual(payload.retestOf, [reproducedFingerprint, absentFingerprint]);
    assert.equal(payload.findings.length, 2);
    assert.equal(payload.findings[0].fingerprint, reproducedFingerprint);
    assert.equal(payload.findings[0].open, true);
    assert.deepEqual(payload.findings[1], {
      fingerprint: absentFingerprint,
      open: false,
    });
  });
});

test("projection rejects dispatch kind and retest scope mismatches", () => {
  assert.throws(
    () => buildProjectionPayload(DOMAIN, {
      kind: "assessment",
      retestOf: ["a".repeat(64)],
    }),
    /kind and retestOf do not match/,
  );
  assert.throws(
    () => buildProjectionPayload(DOMAIN, {
      kind: "retest",
      retestOf: [],
    }),
    /kind and retestOf do not match/,
  );
});

test("smart-contract projection carries normalized chain identity and no web endpoint", () => {
  withTempHome(() => {
    writeFixture(DOMAIN);
    const contractAddress = `0x${"a".repeat(40)}`;
    const smartFinding = {
      ...FINDING,
      cwe: "CWE-284",
      endpoint: `evm:1:${contractAddress}`,
      request_method: undefined,
      injection_point: undefined,
      auth_profile: undefined,
      surface_type: "smart_contract",
      source_surface_type: "smart_contract",
      sc_evidence: {
        chain_family: "evm",
        chain_id: 1,
        contract_address: contractAddress,
        harness_path: "/workspace/harnesses/F-1",
        match_test: "withdraw drains escrow",
        function_signature: "withdraw(uint256)",
      },
    };
    const { payload } = buildProjectionPayload(DOMAIN, {
      runSlug: "run-contract",
      projectionKey: "projection-contract",
      kind: "assessment",
      findings: [smartFinding],
    });
    const [row] = payload.findings;
    assert.equal(row.surfaceType, "smart_contract");
    assert.equal(row.chainFamily, "evm");
    assert.deepEqual(row.scEvidence, {
      chainId: "1",
      contractIdentity: contractAddress,
      functionSignature: "withdraw(uint256)",
    });
    assert.equal(Object.prototype.hasOwnProperty.call(row, "endpoint"), false);
    assert.equal(row.score, 60);
  });
});

test("dispatched projection fails closed when structured continuity fields are missing", () => {
  withTempHome(() => {
    writeFixture(DOMAIN);
    const options = {
      runSlug: "run-continuity",
      projectionKey: "projection-continuity",
      kind: "assessment",
    };
    assert.throws(
      () => buildProjectionPayload(DOMAIN, {
        ...options,
        findings: [{ ...FINDING, request_method: null }],
      }),
      /finding F-1 lacks dispatched web continuity fields: request_method/,
    );
    assert.throws(
      () => buildProjectionPayload(DOMAIN, {
        ...options,
        findings: [{
          ...FINDING,
          source_surface_type: "graphql",
          graphql_operation: "UpdateOrder",
        }],
      }),
      /finding F-1 lacks dispatched GraphQL continuity fields: graphql_resolver/,
    );
  });
});

test("dispatched projection rejects a missing defender disposition", () => {
  withTempHome(() => {
    writeFixture(DOMAIN, {
      gradeFindingOverrides: { defender_disposition: undefined },
    });
    assert.throws(
      () => buildProjectionPayload(DOMAIN, {
        runSlug: "run-ungraded-disposition",
        projectionKey: "projection-ungraded-disposition",
        kind: "assessment",
        findings: [FINDING],
      }),
      /finding F-1 has missing or unsupported defender_disposition/,
    );
  });
});

test("dispatched projection rejects incomplete grade axes", () => {
  withTempHome(() => {
    writeFixture(DOMAIN, {
      gradeFindingOverrides: { proof_quality: undefined },
    });
    assert.throws(
      () => buildProjectionPayload(DOMAIN, {
        runSlug: "run-incomplete-grade",
        projectionKey: "projection-incomplete-grade",
        kind: "assessment",
        findings: [FINDING],
      }),
      /finding F-1 lacks valid grade field: proof_quality/,
    );
  });
});

test("info-graded findings are excluded from retained projection", () => {
  withTempHome(() => {
    writeFixture(DOMAIN, {
      gradeFindingOverrides: { graded_severity: "info" },
    });
    const { payload } = buildProjectionPayload(DOMAIN, {
      runSlug: "run-info",
      projectionKey: "projection-info",
      kind: "assessment",
      findings: [FINDING],
    });
    assert.deepEqual(payload.findings, []);
  });
});

test("a clean scan emits no artifact and projects an empty findings array", () => {
  withTempHome(() => {
    writeFixture(DOMAIN, { reportable: false });
    const assembled = assembleFindingArtifact(DOMAIN, { findings: [FINDING] });
    assert.equal(assembled.emitted, false);
    assert.equal(assembled.reason, "no_reportable_findings");
    fs.writeFileSync(findingArtifactPath(DOMAIN), "stale artifact\n");
    fs.writeFileSync(findingArtifactSidecarPath(DOMAIN), "stale sidecar\n");
    const cleaned = writeFindingArtifact(DOMAIN, { findings: [FINDING] });
    assert.equal(cleaned.emitted, false);
    assert.equal(fs.existsSync(findingArtifactPath(DOMAIN)), false);
    assert.equal(fs.existsSync(findingArtifactSidecarPath(DOMAIN)), false);
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
    url: "https://projection.invalid/api/findings",
    secret: "secret",
    payload: { findings: [] },
    fetchImpl: flaky,
    initialDelayMs: 1,
  });
  assert.equal(recovered.ok, true);
  assert.equal(recovered.attempts, 3);

  const rejected = await postProjection({
    url: "https://projection.invalid/api/findings",
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
      url: "https://projection.invalid/api/findings",
      secret: "secret",
      payload: { findings: [] },
      fetchImpl: async () => new Response(null, { status: 500 }),
      maxAttempts: 2,
      initialDelayMs: 1,
    }),
    /after 2 attempts/,
  );

  await assert.rejects(
    () => postProjection({
      url: "https://projection.invalid/api/findings",
      secret: "secret",
      payload: { findings: [] },
      fetchImpl: async (_url, { signal }) => new Promise((_resolve, reject) => {
        signal.addEventListener("abort", () => reject(new Error("request aborted")), { once: true });
      }),
      maxAttempts: 1,
      requestTimeoutMs: 5,
    }),
    /request aborted/,
  );

  await assert.rejects(
    () => postProjection({
      url: "https://projection.invalid/api/findings",
      secret: "secret",
      payload: { findings: [] },
      fetchImpl: async (_url, { signal }) => ({
        ok: false,
        status: 500,
        text: () => new Promise((_resolve, reject) => {
          signal.addEventListener("abort", () => reject(new Error("response body aborted")), { once: true });
        }),
      }),
      maxAttempts: 1,
      requestTimeoutMs: 5,
    }),
    /response body aborted/,
  );

  await assert.rejects(
    () => postProjection({
      url: "https://projection.invalid/api/findings",
      secret: "secret",
      payload: { findings: [] },
      fetchImpl: async () => new Response("x".repeat(64 * 1024 + 1), { status: 200 }),
      maxAttempts: 1,
    }),
    /response exceeds 65536 bytes/,
  );

  let fetched = false;
  await assert.rejects(
    () => postProjection({
      url: "http://projection.invalid/api/findings",
      secret: "secret",
      payload: { findings: [] },
      fetchImpl: async () => {
        fetched = true;
        return new Response(null, { status: 200 });
      },
    }),
    /exact HTTPS/,
  );
  assert.equal(fetched, false);
});
