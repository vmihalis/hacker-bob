const test = require("node:test");
const assert = require("node:assert/strict");
const {
  isOpenForAssignment,
  planNextWave,
} = require("../mcp/lib/wave-planner.js");

function surface(id, priority, score = 0) {
  return {
    id,
    priority,
    ranking: { version: 1, score, priority, reasons: [] },
  };
}

test("planNextWave wave 1 orders buckets, fills to target, caps high-priority overflow, and labels after dedupe", () => {
  const state = { hunt_wave: 0, pending_wave: null, explored: [], terminally_blocked: [], lead_surface_ids: [] };
  const highOverflow = planNextWave({
    state,
    surfaces: [
      surface("h5", "HIGH", 10),
      surface("h1", "CRITICAL", 99),
      surface("h4", "HIGH", 20),
      surface("h3", "HIGH", 30),
      surface("h2", "CRITICAL", 80),
      surface("h6", "HIGH", 5),
      surface("h7", "HIGH", 1),
      surface("m1", "MEDIUM", 100),
    ],
  });
  assert.equal(highOverflow.decision, "start_wave");
  assert.deepEqual(highOverflow.assignments, [
    { agent: "a1", surface_id: "h1" },
    { agent: "a2", surface_id: "h2" },
    { agent: "a3", surface_id: "h3" },
    { agent: "a4", surface_id: "h4" },
    { agent: "a5", surface_id: "h5" },
    { agent: "a6", surface_id: "h6" },
    { agent: "a7", surface_id: "h7" },
  ]);

  const fill = planNextWave({
    state,
    surfaces: [
      surface("low-a", "LOW", 100),
      surface("high-a", "HIGH", 10),
      surface("med-b", "MEDIUM", 20),
      surface("high-b", "HIGH", 5),
      surface("med-a", "MEDIUM", 50),
    ],
  });
  assert.deepEqual(fill.assignments, [
    { agent: "a1", surface_id: "high-a" },
    { agent: "a2", surface_id: "high-b" },
    { agent: "a3", surface_id: "med-a" },
    { agent: "a4", surface_id: "med-b" },
    { agent: "a5", surface_id: "low-a" },
  ]);
});

test("planNextWave wave 2+ prioritizes open requeue, lead IDs, remaining priorities, and dedupes earlier buckets", () => {
  const state = {
    hunt_wave: 1,
    pending_wave: null,
    explored: ["done"],
    terminally_blocked: [{ surface_id: "blocked", blocked_at_wave: 1, blockers: [{ kind: "auth_missing" }] }],
    lead_surface_ids: ["lead-high", "requeue-high", "missing-lead"],
  };
  const surfaces = [
    surface("requeue-high", "HIGH", 20),
    surface("lead-high", "HIGH", 90),
    surface("critical", "CRITICAL", 50),
    surface("medium", "MEDIUM", 99),
    surface("low", "LOW", 99),
    surface("done", "CRITICAL", 100),
    surface("blocked", "CRITICAL", 100),
  ];
  const coverageRecords = [
    { surface_id: "requeue-high", status: "requeue", endpoint: "/a", bug_class: "idor" },
    { surface_id: "done", status: "needs_auth", endpoint: "/b", bug_class: "auth" },
    { surface_id: "blocked", status: "promising", endpoint: "/c", bug_class: "auth" },
  ];

  const plan = planNextWave({ state, surfaces, coverageRecords });
  assert.deepEqual(plan.buckets.map((bucket) => [bucket.name, bucket.surface_ids]), [
    ["open_requeue", ["requeue-high"]],
    ["lead_surface_ids", ["lead-high"]],
    ["critical_high", ["critical"]],
    ["medium", ["medium"]],
    ["low", ["low"]],
  ]);
  assert.deepEqual(plan.assignments, [
    { agent: "a1", surface_id: "requeue-high" },
    { agent: "a2", surface_id: "lead-high" },
    { agent: "a3", surface_id: "critical" },
    { agent: "a4", surface_id: "medium" },
    { agent: "a5", surface_id: "low" },
  ]);
});

test("isOpenForAssignment excludes invalid, explored, and terminally blocked surfaces only", () => {
  const state = {
    explored: ["done"],
    terminally_blocked: [{ surface_id: "blocked", blocked_at_wave: 1, blockers: [{ kind: "auth_missing" }] }],
    dead_ends: ["/closed-endpoint"],
    waf_blocked_endpoints: ["/waf"],
  };
  const surfaceIdSet = new Set(["open", "done", "blocked"]);
  assert.equal(isOpenForAssignment("open", state, { surfaceIdSet }), true);
  assert.equal(isOpenForAssignment("done", state, { surfaceIdSet }), false);
  assert.equal(isOpenForAssignment("blocked", state, { surfaceIdSet }), false);
  assert.equal(isOpenForAssignment("missing", state, { surfaceIdSet }), false);
  assert.equal(isOpenForAssignment("", state, { surfaceIdSet }), false);
});

test("planNextWave returns pending-wave reconcile before selecting candidates", () => {
  const plan = planNextWave({
    state: {
      hunt_wave: 2,
      pending_wave: 3,
      explored: [],
      terminally_blocked: [],
      lead_surface_ids: [],
    },
    surfaces: [surface("high", "CRITICAL", 100)],
  });
  assert.equal(plan.decision, "pending_wave_reconcile");
  assert.deepEqual(plan.assignments, []);
  assert.deepEqual(plan.buckets, []);
  assert.equal(plan.pending_wave, 3);
});
