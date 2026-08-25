"use strict";

const test = require("node:test");
const assert = require("node:assert");
const fs = require("fs");
const os = require("os");
const path = require("path");

const {
  recordedBlockerPartialSurfaceIdSet,
} = require("../mcp/core/telemetry/pipeline-session-artifacts.js");
const {
  readSessionArtifactSummary,
  readPipelineAnalytics,
} = require("../mcp/core/telemetry/pipeline-analytics.js");
const {
  appendClosureRecordedEvent,
} = require("../mcp/core/frontier/frontier-events.js");
const { initSession } = require("../mcp/core/session/session-state.js");
const {
  readSessionStateStrict,
  writeSessionStateDocument,
} = require("../mcp/core/session/session-state-store.js");
const { attackSurfacePath, sessionDir } = require("../mcp/core/io/paths.js");

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-coverage-blocked-"));
  process.env.HOME = home;
  try {
    return fn(home);
  } finally {
    if (previousHome === undefined) delete process.env.HOME;
    else process.env.HOME = previousHome;
    fs.rmSync(home, { recursive: true, force: true });
  }
}

function seedCoverage(domain, { surfaces, blockedPrereqHistory = [] }) {
  // Real session (no unreadable_artifacts). Drive the legacy phase to VERIFY,
  // which the analytics lifecycle index maps to lifecycle VERIFY (>= CLAIM_FREEZE),
  // so the coverage gate (lifecycleAtLeast CLAIM_FREEZE) evaluates.
  initSession({ target_domain: domain, target_url: `https://${domain}/` });
  const { raw, state } = readSessionStateStrict(domain);
  writeSessionStateDocument(domain, raw, {
    ...state,
    phase: "VERIFY",
    blocked_prereq_history: blockedPrereqHistory,
  });
  fs.mkdirSync(sessionDir(domain), { recursive: true });
  fs.writeFileSync(attackSurfacePath(domain), `${JSON.stringify({ surfaces }, null, 2)}\n`, "utf8");
  // surface-explored is closed via the frontier ledger; the other non-low
  // surface stays OPEN so closed_pct < 100 and the coverage gate evaluates.
  appendClosureRecordedEvent({
    target_domain: domain,
    kind: "closure.recorded",
    surface_id: "surface-explored",
    payload: { surface_fully_explored: true, reason: "seeded_explored" },
    source: { artifact: "wave-merge", tool: "bob_apply_wave_merge" },
  });
}

test("recorded-blocker partial is recovered from blocked_prereq_history", () => {
  const state = {
    blocked_prereq_history: [
      { wave: 1, surface_id: "surface-key", kind: "key_material_missing", reason: "signer key not provisioned" },
      { wave: 1, surface_id: "surface-rpc", kind: "harness_unavailable", reason: "archive RPC depth limit" },
    ],
  };
  // Both blocked surfaces are still open to the frontier (first-wave block,
  // not yet promoted to terminally_blocked); surface-neglected has no blocker.
  const openNonLow = ["surface-key", "surface-rpc", "surface-neglected"];
  const blocked = recordedBlockerPartialSurfaceIdSet(state, openNonLow);
  assert.deepEqual([...blocked].sort(), ["surface-key", "surface-rpc"]);
  // The genuinely neglected surface is the real gap.
  const neglected = openNonLow.filter((id) => !blocked.has(id));
  assert.deepEqual(neglected, ["surface-neglected"]);
});

test("a recorded blocker for an already-closed surface is not double-counted", () => {
  const state = {
    blocked_prereq_history: [
      { wave: 1, surface_id: "surface-key", kind: "key_material_missing" },
    ],
  };
  // surface-key is NOT in the candidate (open) set because it is
  // explored/terminally_blocked; it must not appear in the recorded-blocker set.
  const blocked = recordedBlockerPartialSurfaceIdSet(state, new Set(["surface-other"]));
  assert.equal(blocked.size, 0);
});

test("empty or missing history yields an empty set (no behavior change)", () => {
  assert.equal(recordedBlockerPartialSurfaceIdSet({}, ["a", "b"]).size, 0);
  assert.equal(recordedBlockerPartialSurfaceIdSet(null, ["a"]).size, 0);
  assert.equal(recordedBlockerPartialSurfaceIdSet({ blocked_prereq_history: [] }, ["a"]).size, 0);
});

test("an open non-low surface with a recorded blocker downgrades low_coverage to coverage_blocked_pending", () => {
  withTempHome(() => {
    const domain = "coverage-blocked.example.com";
    seedCoverage(domain, {
      surfaces: [
        { id: "surface-blocked", priority: "HIGH" },
        { id: "surface-explored", priority: "HIGH" },
      ],
      blockedPrereqHistory: [
        { wave: 1, surface_id: "surface-blocked", kind: "key_material_missing", reason: "signer key not provisioned" },
      ],
    });

    // Summarize integration: the open recorded-blocker surface is handled, not a gap.
    const coverage = readSessionArtifactSummary(domain).attack_surface_coverage;
    assert.equal(coverage.non_low_total, 2);
    assert.equal(coverage.non_low_explored, 1);
    assert.equal(coverage.non_low_recorded_blocker_partial, 1);
    assert.equal(coverage.non_low_neglected, 0);

    // Gate downgrade: a healthy coverage_blocked_pending replaces low_coverage.
    const analytics = JSON.parse(readPipelineAnalytics({ target_domain: domain }));
    assert.ok(
      analytics.bottlenecks.some((b) => b.code === "coverage_blocked_pending"),
      "expected a coverage_blocked_pending bottleneck",
    );
    assert.ok(
      !analytics.bottlenecks.some((b) => b.code === "low_coverage"),
      "low_coverage must not fire when the only open non-low surface is recorded-blocker",
    );
  });
});

test("an open non-low surface with no recorded blocker still fires low_coverage", () => {
  withTempHome(() => {
    const domain = "coverage-neglected.example.com";
    seedCoverage(domain, {
      surfaces: [
        { id: "surface-neglected", priority: "HIGH" },
        { id: "surface-explored", priority: "HIGH" },
      ],
      blockedPrereqHistory: [],
    });

    const coverage = readSessionArtifactSummary(domain).attack_surface_coverage;
    assert.equal(coverage.non_low_recorded_blocker_partial, 0);
    assert.equal(coverage.non_low_neglected, 1);

    const analytics = JSON.parse(readPipelineAnalytics({ target_domain: domain }));
    assert.ok(
      analytics.bottlenecks.some((b) => b.code === "low_coverage"),
      "a genuinely neglected open non-low surface must still fire low_coverage",
    );
  });
});
