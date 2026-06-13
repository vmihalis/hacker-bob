"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");

const {
  assertBeliefScratchWritePath,
  queryBeliefSignals,
  readBeliefSignals,
  writeBeliefSignalScratch,
} = require("../mcp/lib/belief/authority.js");
const {
  beliefScratchDir,
  beliefSignalsJsonlPath,
  claimFreezePath,
  claimsJsonlPath,
  gradeArtifactPaths,
  reportMarkdownPath,
  sessionDir,
  verificationAdjudicationPath,
} = require("../mcp/lib/paths.js");
const { TOOL_MANIFEST } = require("../mcp/lib/tool-registry.js");

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
      payload: {
        projection_hash: "sha256:abc",
        surface_graph_hash: "sha256:def",
      },
    });
    const second = writeBeliefSignalScratch({
      target_domain: domain,
      kind: "mechanism_projection",
      source: "CB-S1-test",
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
    });
    assert.equal(queried.signals.length, 2);
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
