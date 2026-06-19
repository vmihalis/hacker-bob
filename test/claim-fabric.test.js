const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");

const {
  appendAgentRun,
  readAgentRuns,
} = require("../mcp/lib/agent-runs.js");
const {
  appendCandidateClaim,
  readCandidateClaims,
} = require("../mcp/lib/claims.js");
const {
  appendClaimCluster,
  readClaimClusters,
} = require("../mcp/lib/claim-clusters.js");
const {
  buildClaimFreeze,
  readCurrentClaimFreeze,
  verificationSnapshotFromClaimFreeze,
} = require("../mcp/lib/claim-freeze.js");
const {
  appendReportSnapshot,
  readReportSnapshots,
} = require("../mcp/lib/report-snapshots.js");

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-claim-fabric-"));
  process.env.HOME = home;
  try {
    return fn(home);
  } finally {
    process.env.HOME = previousHome;
    fs.rmSync(home, { recursive: true, force: true });
  }
}

test("agent runs, claims, freeze, and report snapshots form a hash-bound chain", () => {
  withTempHome(() => {
    const domain = "claims.example.com";
    const run = appendAgentRun({
      target_domain: domain,
      task_id: "T-alpha",
      agent_id: "a1",
      status: "completed",
      started_at: "2026-05-26T01:00:00.000Z",
      ended_at: "2026-05-26T01:05:00.000Z",
      output_refs: [{ kind: "json", path: "evidence/account-boundary.json" }],
      metrics: { steps: 4 },
    });
    const claim = appendCandidateClaim({
      target_domain: domain,
      title: "Tenant boundary allows cross-account billing view",
      summary: "Changing the billing profile identifier returns another account view.",
      severity: "high",
      status: "candidate",
      created_at: "2026-05-26T01:06:00.000Z",
      surface_ids: ["surface:billing-profile"],
      lenses: ["control_check", "impact_correlation"],
      evidence_refs: [{ kind: "agent_run", agent_run_id: run.agent_run_id }],
      control_expectation: { expected: "Billing profile reads stay within the active account." },
      impact: "Account billing metadata can cross tenant boundaries.",
      confidence: 0.91,
    });
    const cluster = appendClaimCluster({
      target_domain: domain,
      claim_ids: [claim.claim_id],
      title: "Billing account boundary",
      control_area: "tenant-boundary",
      created_at: "2026-05-26T01:07:00.000Z",
    });

    assert.equal(readAgentRuns(domain)[0].agent_run_id, run.agent_run_id);
    assert.equal(readCandidateClaims(domain)[0].claim_id, claim.claim_id);
    assert.equal(readClaimClusters(domain)[0].cluster_id, cluster.cluster_id);

    const freeze = buildClaimFreeze(domain, {
      write: true,
      now: new Date("2026-05-26T01:08:00.000Z"),
    });
    const laterFreeze = buildClaimFreeze(domain, {
      now: new Date("2026-05-26T02:08:00.000Z"),
    });
    assert.equal(freeze.claim_count, 1);
    assert.equal(freeze.cluster_count, 1);
    assert.equal(freeze.freeze_hash, laterFreeze.freeze_hash);
    assert.equal(readCurrentClaimFreeze(domain).freeze_hash, freeze.freeze_hash);
    const verificationSnapshot = verificationSnapshotFromClaimFreeze(freeze, {
      now: new Date("2026-05-26T01:08:30.000Z"),
    });
    assert.equal(verificationSnapshot.claim_freeze_hash, freeze.freeze_hash);
    assert.equal(verificationSnapshot.claim_count, 1);

    const snapshot = appendReportSnapshot({
      target_domain: domain,
      status: "ready",
      created_at: "2026-05-26T01:09:00.000Z",
      claim_freeze_hash: freeze.freeze_hash,
      verification_snapshot_hash: verificationSnapshot.verification_snapshot_hash,
      final_verification_hash: "a".repeat(64),
      evidence_hash: "b".repeat(64),
      grade_verdict_hash: "c".repeat(64),
      claim_ids: [claim.claim_id],
      artifact_refs: [{ kind: "markdown", path: "report.md" }],
      summary: "Ready report snapshot.",
    });
    const snapshots = readReportSnapshots(domain);
    assert.equal(snapshots.length, 1);
    assert.equal(snapshots[0].snapshot_id, snapshot.snapshot_id);
    assert.equal(snapshots[0].claim_freeze_hash, freeze.freeze_hash);
    assert.equal(snapshots[0].final_verification_hash, "a".repeat(64));
    assert.equal(snapshots[0].evidence_hash, "b".repeat(64));
    assert.equal(snapshots[0].grade_verdict_hash, "c".repeat(64));
  });
});

test("report snapshots require verification, evidence, and grade hashes", () => {
  assert.throws(
    () => appendReportSnapshot({
      target_domain: "claims.example.com",
      status: "ready",
      claim_freeze_hash: "a".repeat(64),
      final_verification_hash: "b".repeat(64),
      grade_verdict_hash: "c".repeat(64),
    }),
    /evidence_hash must be a non-empty string/,
  );
});
