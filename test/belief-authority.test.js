"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");

const {
  BELIEF_PROVENANCE_VALUES,
  assertBeliefScratchWritePath,
  queryBeliefSignals,
  readBeliefSignals,
  writeBeliefSignalScratch,
} = require("../mcp/core/belief/authority.js");
const {
  beliefScratchDir,
  beliefSignalsJsonlPath,
  claimFreezePath,
  claimsJsonlPath,
  gradeArtifactPaths,
  reportMarkdownPath,
  sessionDir,
  verificationAdjudicationPath,
} = require("../mcp/core/io/paths.js");
const { TOOL_MANIFEST } = require("../mcp/tools/tool-registry.js");

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-belief-authority-"));
  process.env.HOME = home;
  try {
    return fn(home);
  } finally {
    process.env.HOME = previousHome;
    fs.rmSync(home, { recursive: true, force: true });
  }
}

test("belief scratch writes are confined to belief-scratch and refuse audit-graded artifacts", () => {
  withTempHome(() => {
    const domain = "belief.example";
    fs.mkdirSync(sessionDir(domain), { recursive: true });

    const allowed = beliefSignalsJsonlPath(domain);
    assert.equal(assertBeliefScratchWritePath({ target_domain: domain, file_path: allowed }), allowed);

    const forbidden = [
      claimsJsonlPath(domain),
      claimFreezePath(domain),
      verificationAdjudicationPath(domain),
      gradeArtifactPaths(domain).json,
      reportMarkdownPath(domain),
    ];
    for (const filePath of forbidden) {
      assert.throws(
        () => assertBeliefScratchWritePath({ target_domain: domain, file_path: filePath }),
        /audit-graded|belief-scratch/,
        `${filePath} must not be writable by belief output code`,
      );
    }

    assert.throws(
      () => assertBeliefScratchWritePath({
        target_domain: domain,
        file_path: path.join(sessionDir(domain), "mechanism-graph.json"),
      }),
      /belief-scratch/,
      "belief code must not create a parallel mechanism graph store",
    );
  });
});

test("belief signals are advisory derived scratch with stable content hashes", () => {
  withTempHome(() => {
    const domain = "belief.example";
    const first = writeBeliefSignalScratch({
      target_domain: domain,
      kind: "mechanism_projection",
      source: "CB-S1-test",
      provenance: "surface_graph",
      artifact_ref: "surface-graph.jsonl#edge:abc",
      payload: {
        projection_hash: "sha256:abc",
        surface_graph_hash: "sha256:def",
      },
    });
    const second = writeBeliefSignalScratch({
      target_domain: domain,
      kind: "mechanism_projection",
      source: "CB-S1-test",
      provenance: "surface_graph",
      artifact_ref: "surface-graph.jsonl#edge:abc",
      payload: {
        surface_graph_hash: "sha256:def",
        projection_hash: "sha256:abc",
      },
    });

    assert.equal(first.signal_hash, second.signal_hash);
    assert.equal(first.advisory, true);
    assert.equal(first.derived, true);
    assert.equal(first.scratch, true);
    assert.equal(path.dirname(first.artifact_path), beliefScratchDir(domain));

    const read = readBeliefSignals({ target_domain: domain });
    assert.equal(read.signals.length, 2);
    assert.equal(read.signals[0].advisory, true);
    assert.equal(read.signals[0].derived, true);
    assert.equal(read.signals[0].scratch, true);

    const queried = queryBeliefSignals({
      target_domain: domain,
      kind: "mechanism_projection",
      source: "CB-S1-test",
      provenance: "surface_graph",
      role: "evidence",
    });
    assert.equal(queried.signals.length, 2);
  });
});

test("belief provenance is closed and residual_anomaly is diagnostic-only", () => {
  assert.deepEqual(BELIEF_PROVENANCE_VALUES, [
    "observed_http",
    "observed_traffic",
    "declared_schema",
    "static_code",
    "surface_graph",
    "claim_ledger",
    "verification_result",
    "operator_asserted",
    "llm_inferred",
    "learned_prior",
    "verified_intervention",
    "residual_anomaly",
  ]);

  withTempHome(() => {
    const domain = "belief.example";
    assert.throws(
      () => writeBeliefSignalScratch({
        target_domain: domain,
        kind: "belief_signal",
        source: "CB-S2-test",
        provenance: "machine_invented_class",
        artifact_ref: "belief-window:test",
        payload: { mechanism_id: "object_authorization" },
      }),
      /invalid belief provenance/,
    );
    assert.throws(
      () => writeBeliefSignalScratch({
        target_domain: domain,
        kind: "belief_signal",
        source: "CB-S2-test",
        provenance: "residual_anomaly",
        artifact_ref: "belief-window:test",
        role: "evidence",
        payload: { residual_hash: "sha256:abc" },
      }),
      /diagnostic-only/,
    );

    writeBeliefSignalScratch({
      target_domain: domain,
      kind: "belief_signal",
      source: "CB-S2-test",
      provenance: "residual_anomaly",
      artifact_ref: "belief-window:test",
      role: "diagnostic",
      payload: { residual_hash: "sha256:abc" },
    });
    const queried = queryBeliefSignals({
      target_domain: domain,
      provenance: "residual_anomaly",
      role: "diagnostic",
    });
    assert.equal(queried.signals.length, 1);
  });
});

test("CB-B7: llm_inferred belief is advisory and cannot enter the window as evidence", () => {
  withTempHome(() => {
    const domain = "belief.example";
    // default role is "evidence" -> an llm_inferred signal must NOT silently land as evidence
    assert.throws(
      () => writeBeliefSignalScratch({
        target_domain: domain,
        kind: "belief_signal",
        source: "CB-B7-test",
        provenance: "llm_inferred",
        artifact_ref: "belief-window:test",
        payload: { latent: "effective_permission", distribution: { allowed: 0.7, blocked: 0.2, unknown: 0.1 } },
      }),
      /advisory and cannot enter the belief window as evidence/,
    );
    assert.throws(
      () => writeBeliefSignalScratch({
        target_domain: domain,
        kind: "belief_signal",
        source: "CB-B7-test",
        provenance: "llm_inferred",
        artifact_ref: "belief-window:test",
        role: "evidence",
        payload: { latent: "effective_permission" },
      }),
      /advisory and cannot enter the belief window as evidence/,
    );

    // role:prior is the honest home for an elicited belief
    writeBeliefSignalScratch({
      target_domain: domain,
      kind: "belief_signal",
      source: "CB-B7-test",
      provenance: "llm_inferred",
      artifact_ref: "belief-window:test",
      role: "prior",
      payload: { latent: "effective_permission", distribution: { allowed: 0.7, blocked: 0.2, unknown: 0.1 } },
    });
    const queried = queryBeliefSignals({ target_domain: domain, provenance: "llm_inferred", role: "prior" });
    assert.equal(queried.signals.length, 1);
    assert.equal(queried.signals[0].role, "prior");
    assert.equal(queried.signals[0].provenance, "llm_inferred");
  });
});

test("belief writer redacts string leaves before secret validation and rejects secret-shaped fields", () => {
  withTempHome(() => {
    const domain = "belief.example";
    assert.throws(
      () => writeBeliefSignalScratch({
        target_domain: domain,
        kind: "belief_signal",
        source: "CB-S2-test",
        provenance: "observed_http",
        artifact_ref: "http-audit:abc",
        payload: {
          endpoint: "/api/me",
          authorization_header: "Bearer should-not-land",
        },
      }),
      /secrets|auth headers|cookies|tokens/,
    );

    writeBeliefSignalScratch({
      target_domain: domain,
      kind: "belief_signal",
      source: "CB-S2-test",
      provenance: "observed_http",
      artifact_ref: "http-audit:abc",
      payload: {
        endpoint_name: "GET /api/me",
        auth_header_hash: "sha256:abc",
        cookie_name: "session",
      },
    });
    const read = readBeliefSignals({ target_domain: domain });
    assert.equal(read.signals.length, 1);
    assert.equal(read.signals[0].payload.cookie_name, "session");
  });
});

test("belief read/query tools are read-only offline registry entries with no artifact writes", () => {
  for (const toolName of ["bob_read_belief_signals", "bob_query_belief_signals"]) {
    const tool = TOOL_MANIFEST[toolName];
    assert.ok(tool, `${toolName} must be registered`);
    assert.equal(tool.mutating, false);
    assert.equal(tool.network_access, false);
    assert.equal(tool.browser_access, false);
    assert.deepEqual(tool.session_artifacts_written, []);
    assert.ok(tool.role_bundles.includes("orchestrator"));
  }
});
