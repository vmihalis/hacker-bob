"use strict";

// CN (coverage-nesting) Step B — D6 nested-spawn-time dedup. A nested fan-out child
// and a closure-phase cell-floor cell must not double-probe the same (bug_class, auth)
// cell on a surface within one materialize window. The dedup is nesting-only (the
// always-on floor is untouched) and empty in the normal wave phase, so it closes the
// narrow re-materialize window without over-pruning.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");

const { appendCellProposal } = require("../mcp/lib/task-graph-events.js");
const { fanoutPlanningKey } = require("../mcp/lib/capability-pack-derivation.js");
const { writeQueuePolicy, normalizeQueuePolicy, DEFAULT_QUEUE_POLICY } = require("../mcp/lib/queue-policy.js");
const { cellFloorPlanningKeysForSurface, buildChildFanoutPlanForSurface } = require("../mcp/lib/assignment-brief.js");

function withTempHome(fn, host = "claude") {
  const prev = process.env.HOME;
  const prevClient = process.env.BOB_CLIENT;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-d6-"));
  process.env.HOME = home;
  // Nesting is claude-only (B3 host gate); pin the host so the plan emits deterministically.
  process.env.BOB_CLIENT = host;
  try {
    return fn(home);
  } finally {
    process.env.HOME = prev;
    if (prevClient === undefined) delete process.env.BOB_CLIENT;
    else process.env.BOB_CLIENT = prevClient;
    try { fs.rmSync(home, { recursive: true, force: true }); } catch {}
  }
}

function plantCell(domain, ts, surfaceId, bugClass, authProfile) {
  appendCellProposal({
    target_domain: domain,
    ts,
    surface_id: surfaceId,
    bug_class: bugClass,
    auth_profile: authProfile,
    cell_key: JSON.stringify([surfaceId, "", "", bugClass, authProfile]),
  });
}

test("D6: cellFloorPlanningKeysForSurface returns the planning_keys the floor proposed for THAT surface only", () => {
  withTempHome(() => {
    const domain = "d6-helper.example.com";
    plantCell(domain, "2026-06-21T00:00:00.000Z", "surface:api", "idor", "");
    plantCell(domain, "2026-06-21T00:00:01.000Z", "surface:other", "ssrf", "");
    const keys = cellFloorPlanningKeysForSurface(domain, "surface:api");
    assert.ok(keys.has(fanoutPlanningKey("idor", "")), "idor/anon cell on surface:api is in-flight");
    assert.ok(!keys.has(fanoutPlanningKey("ssrf", "")), "a different surface's cell is excluded");
  });
});

test("B3: nesting is claude-only and depth is clamped by the host ceiling", () => {
  // Non-claude host (unknown/codex/kimi MCP-side) => NO nested plan; the fan-out
  // degrades to flat wave assignments the orchestrator dispatches.
  withTempHome((home) => {
    void home;
    const domain = "b3-unknown.example.com";
    writeQueuePolicy(domain, normalizeQueuePolicy({ ...DEFAULT_QUEUE_POLICY, max_spawn_depth: 6, max_spawn_children: 8 }));
    const surfaceObj = { id: "surface:api", bug_class_hints: ["idor"] };
    const plan = buildChildFanoutPlanForSurface({ domain, surfaceObj, surfaceId: "surface:api", coverageSummary: {} });
    assert.equal(plan, null, "non-claude host => no nested plan (host gate)");
  }, "unknown");

  // claude => plan emitted, but depth clamped by the host ceiling (5), not the raw 6.
  withTempHome((home) => {
    void home;
    const domain = "b3-claude.example.com";
    writeQueuePolicy(domain, normalizeQueuePolicy({ ...DEFAULT_QUEUE_POLICY, max_spawn_depth: 6, max_spawn_children: 8 }));
    const surfaceObj = { id: "surface:api", bug_class_hints: ["idor"] };
    const plan = buildChildFanoutPlanForSurface({ domain, surfaceObj, surfaceId: "surface:api", coverageSummary: {} });
    assert.ok(plan, "claude => plan emitted");
    assert.equal(plan.remaining_depth, 4, "remaining_depth = min(6,5)-1 = 4 (clamped by the claude host ceiling)");
  }, "claude");
});

test("D6: a nested fan-out child is deduped when the cell floor already proposed that cell", () => {
  withTempHome(() => {
    const domain = "d6-dedup.example.com";
    writeQueuePolicy(domain, normalizeQueuePolicy({ ...DEFAULT_QUEUE_POLICY, max_spawn_depth: 2, max_spawn_children: 8 }));
    plantCell(domain, "2026-06-21T00:00:00.000Z", "surface:api", "idor", "");
    const surfaceObj = { id: "surface:api", bug_class_hints: ["idor", "ssrf"] };
    const plan = buildChildFanoutPlanForSurface({ domain, surfaceObj, surfaceId: "surface:api", coverageSummary: {} });
    assert.ok(plan, "nesting on (depth 2) => a plan is emitted");
    const keys = plan.children.map((c) => c.planning_key);
    assert.ok(!keys.includes(fanoutPlanningKey("idor", "")), "the idor child is deduped against the in-flight floor cell");
    assert.ok(keys.includes(fanoutPlanningKey("ssrf", "")), "the ssrf child (no floor cell) is still planned");
  });
});
