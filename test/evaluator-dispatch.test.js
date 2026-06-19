"use strict";

/**
 * Tests for S5 — evaluator-dispatch.ts.
 *
 * Verifies acceptance criteria:
 *   1. One agent context per unique surface_id (deduplicated).
 *   2. Max concurrent evaluator agents capped at MAX_EVALUATOR_AGENTS.
 *   3. Each agent receives: session_id, surface_id, diff_hunks[], target_domain.
 *   4. Agent lifecycle helpers: initSpawnedAgent, markAgentCompleted,
 *      markAgentTimedOut, allAgentsExited.
 *   5. Coverage gap detection via findCoverageGaps.
 *   6. S6 readiness predicate allAgentsExited blocks until terminal.
 *   7. Surface priority order: smart_contract > auth > api-route > other.
 *   8. Empty impacted_entries -> is_empty plan with no agents.
 *   9. PATH A and PATH B surface_id namespaces both deduplicated correctly.
 *  10. formatS5FailureJson produces parseable JSON with step 'S5.evaluator_dispatch'.
 */

const test = require("node:test");
const assert = require("node:assert/strict");

const {
  MAX_EVALUATOR_AGENTS,
  AGENT_TIMEOUT_MS,
  deduplicateAndPrioritize,
  buildDiffHunksForSurface,
  buildAgentContexts,
  buildS5SpawnPlan,
  initSpawnedAgent,
  markAgentCompleted,
  markAgentTimedOut,
  allAgentsExited,
  findTimedOutAgents,
  findCoverageGaps,
  formatS5FailureJson,
} = require("../packages/bob-diff-review/dist/evaluator-dispatch.js");

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

function makeEntry(file, surface_ids, opts = {}) {
  return {
    file,
    line_start: opts.line_start ?? 1,
    line_end: opts.line_end ?? 10,
    surface_ids,
    hunk_summary: opts.hunk_summary ?? `change in ${file}`,
  };
}

const SAMPLE_ENTRIES = [
  makeEntry("src/auth/login.ts", ["auth:login-handler"], { line_start: 5, line_end: 20 }),
  makeEntry("contracts/Token.sol", ["smart_contract:token"], { line_start: 1, line_end: 50 }),
  makeEntry("src/routes/api.ts", ["api-route:users"], { line_start: 10, line_end: 30 }),
  makeEntry("src/auth/session.ts", ["auth:login-handler"], { line_start: 1, line_end: 15 }),
];

// ---------------------------------------------------------------------------
// Acceptance criterion 1: one agent per unique surface_id
// ---------------------------------------------------------------------------

test("deduplicateAndPrioritize produces one entry per unique surface_id", () => {
  // auth:login-handler appears in two entries but should produce one surface.
  const result = deduplicateAndPrioritize(SAMPLE_ENTRIES);
  const ids = result.surface_ids;
  // smart_contract:token, auth:login-handler, api-route:users — 3 unique
  assert.equal(result.total_unique, 3, "should find 3 unique surface_ids");
  // Each surface_id appears exactly once.
  const unique = new Set(ids);
  assert.equal(unique.size, ids.length, "output surface_ids must have no duplicates");
});

test("deduplicateAndPrioritize handles entries with multiple surface_ids", () => {
  const entries = [
    makeEntry("src/auth/api.ts", ["auth:handler", "api-route:auth-endpoint"]),
    makeEntry("src/auth/api.ts", ["auth:handler"]), // duplicate surface_id
  ];
  const result = deduplicateAndPrioritize(entries);
  assert.equal(result.total_unique, 2);
  assert.equal(result.surface_ids.length, 2);
});

test("deduplicateAndPrioritize skips empty surface_ids[]", () => {
  const entries = [
    makeEntry("src/misc.ts", []),
    makeEntry("src/auth/login.ts", ["auth:login"]),
  ];
  const result = deduplicateAndPrioritize(entries);
  assert.equal(result.total_unique, 1);
  assert.equal(result.surface_ids[0], "auth:login");
});

test("buildS5SpawnPlan deduplicates surface_ids across entries", () => {
  const plan = buildS5SpawnPlan(SAMPLE_ENTRIES, "gh-12345678", "sess-abc");
  assert.equal(plan.is_empty, false);
  const surfaceIds = plan.agents.map((a) => a.surface_id);
  const unique = new Set(surfaceIds);
  assert.equal(unique.size, surfaceIds.length, "no duplicate surface_ids in plan");
  assert.equal(plan.total_unique_surfaces, 3);
});

// ---------------------------------------------------------------------------
// Acceptance criterion 2: cap at MAX_EVALUATOR_AGENTS
// ---------------------------------------------------------------------------

test("MAX_EVALUATOR_AGENTS is 8", () => {
  assert.equal(MAX_EVALUATOR_AGENTS, 8);
});

test("deduplicateAndPrioritize caps at maxAgents", () => {
  // Generate 10 unique surface_ids.
  const entries = Array.from({ length: 10 }, (_, i) =>
    makeEntry(`src/service${i}.ts`, [`surface:service-${i}`])
  );
  const result = deduplicateAndPrioritize(entries, 8);
  assert.equal(result.surface_ids.length, 8);
  assert.equal(result.capped_count, 2);
  assert.equal(result.dropped_surfaces.length, 2);
  assert.equal(result.total_unique, 10);
});

test("buildS5SpawnPlan caps agents at MAX_EVALUATOR_AGENTS by default", () => {
  const entries = Array.from({ length: 12 }, (_, i) =>
    makeEntry(`src/file${i}.ts`, [`service:surface-${i}`])
  );
  const plan = buildS5SpawnPlan(entries, "gh-99999", "sess-xyz");
  assert.equal(plan.agents.length, MAX_EVALUATOR_AGENTS);
  assert.equal(plan.capped_count, 12 - MAX_EVALUATOR_AGENTS);
  assert.equal(plan.dropped_surfaces.length, 12 - MAX_EVALUATOR_AGENTS);
});

test("buildS5SpawnPlan respects custom maxAgents override", () => {
  const entries = Array.from({ length: 5 }, (_, i) =>
    makeEntry(`src/svc${i}.ts`, [`svc:surface-${i}`])
  );
  const plan = buildS5SpawnPlan(entries, "gh-12345", "sess-123", 3);
  assert.equal(plan.agents.length, 3);
  assert.equal(plan.capped_count, 2);
});

// ---------------------------------------------------------------------------
// Acceptance criterion 3: each agent receives session_id, surface_id,
// diff_hunks[], target_domain
// ---------------------------------------------------------------------------

test("buildS5SpawnPlan injects required fields into each agent context", () => {
  const plan = buildS5SpawnPlan(SAMPLE_ENTRIES, "gh-12345678", "sess-abc123");
  for (const agent of plan.agents) {
    assert.ok(typeof agent.target_domain === "string" && agent.target_domain.length > 0,
      "target_domain must be non-empty string");
    assert.ok(typeof agent.session_id === "string" && agent.session_id.length > 0,
      "session_id must be non-empty string");
    assert.ok(typeof agent.surface_id === "string" && agent.surface_id.length > 0,
      "surface_id must be non-empty string");
    assert.ok(Array.isArray(agent.diff_hunks),
      "diff_hunks must be an array");
    assert.equal(agent.target_domain, "gh-12345678");
    assert.equal(agent.session_id, "sess-abc123");
  }
});

test("buildDiffHunksForSurface returns only hunks belonging to the surface", () => {
  const hunks = buildDiffHunksForSurface("auth:login-handler", SAMPLE_ENTRIES);
  // Two entries carry auth:login-handler.
  assert.equal(hunks.length, 2);
  for (const hunk of hunks) {
    assert.ok(typeof hunk.file === "string", "file must be string");
    assert.ok(typeof hunk.line_start === "number", "line_start must be number");
    assert.ok(typeof hunk.line_end === "number", "line_end must be number");
    assert.ok(typeof hunk.hunk_text === "string", "hunk_text must be string");
  }
  const files = hunks.map((h) => h.file);
  assert.ok(files.includes("src/auth/login.ts"));
  assert.ok(files.includes("src/auth/session.ts"));
});

test("buildDiffHunksForSurface returns empty array for unknown surface_id", () => {
  const hunks = buildDiffHunksForSurface("unknown:surface", SAMPLE_ENTRIES);
  assert.equal(hunks.length, 0);
});

test("diff_hunks line range is preserved from the impacted_entry", () => {
  const entries = [
    makeEntry("src/auth/login.ts", ["auth:handler"], { line_start: 42, line_end: 99 }),
  ];
  const hunks = buildDiffHunksForSurface("auth:handler", entries);
  assert.equal(hunks.length, 1);
  assert.equal(hunks[0].line_start, 42);
  assert.equal(hunks[0].line_end, 99);
});

// ---------------------------------------------------------------------------
// Surface type priority ordering
// ---------------------------------------------------------------------------

test("deduplicateAndPrioritize puts smart_contract surfaces first", () => {
  const entries = [
    makeEntry("src/routes/api.ts", ["api-route:handler"]),
    makeEntry("src/misc.ts", ["heuristic:unknown"]),
    makeEntry("contracts/Token.sol", ["smart_contract:vault"]),
    makeEntry("src/auth/login.ts", ["auth:handler"]),
  ];
  const result = deduplicateAndPrioritize(entries);
  // smart_contract must appear before auth, which before api-route/unknown.
  const ids = result.surface_ids;
  const smartContractIdx = ids.findIndex((id) => id.includes("smart_contract"));
  const authIdx = ids.findIndex((id) => id.includes("auth"));
  const apiIdx = ids.findIndex((id) => id.includes("api-route"));
  assert.ok(smartContractIdx < authIdx, "smart_contract must precede auth in priority");
  assert.ok(authIdx < apiIdx, "auth must precede api-route in priority");
});

test("deduplicateAndPrioritize puts heuristic:smart-contract before heuristic:api-route", () => {
  const entries = [
    makeEntry("api/routes.ts", ["heuristic:api-route"]),
    makeEntry("contracts/Token.sol", ["heuristic:smart-contract"]),
  ];
  const result = deduplicateAndPrioritize(entries);
  const ids = result.surface_ids;
  const scIdx = ids.findIndex((id) => id.includes("smart-contract"));
  const apiIdx = ids.findIndex((id) => id.includes("api-route"));
  assert.ok(scIdx < apiIdx, "heuristic:smart-contract must have higher priority than heuristic:api-route");
});

// ---------------------------------------------------------------------------
// Empty impacted_entries handling
// ---------------------------------------------------------------------------

test("buildS5SpawnPlan returns is_empty:true for empty impacted_entries", () => {
  const plan = buildS5SpawnPlan([], "gh-12345678", "sess-abc");
  assert.equal(plan.is_empty, true);
  assert.deepEqual(plan.agents, []);
  assert.equal(plan.total_unique_surfaces, 0);
  assert.equal(plan.capped_count, 0);
});

test("buildS5SpawnPlan returns is_empty:true when all entries have empty surface_ids", () => {
  const entries = [
    makeEntry("src/misc.ts", []),
    makeEntry("src/other.ts", []),
  ];
  const plan = buildS5SpawnPlan(entries, "gh-12345678", "sess-abc");
  assert.equal(plan.is_empty, true);
  assert.deepEqual(plan.agents, []);
});

// ---------------------------------------------------------------------------
// PATH A and PATH B surface_id namespace deduplication
// ---------------------------------------------------------------------------

test("deduplicateAndPrioritize treats heuristic: and non-heuristic: IDs as distinct", () => {
  // "auth:login" (PATH A) and "heuristic:authentication" (PATH B) are different
  // surfaces and must each get their own agent.
  const entries = [
    makeEntry("src/auth/login.ts", ["auth:login"]),
    makeEntry("src/auth/session.ts", ["heuristic:authentication"]),
  ];
  const result = deduplicateAndPrioritize(entries);
  assert.equal(result.total_unique, 2);
  assert.ok(result.surface_ids.includes("auth:login"));
  assert.ok(result.surface_ids.includes("heuristic:authentication"));
});

test("deduplicateAndPrioritize trims whitespace when deduplicating surface_ids", () => {
  const entries = [
    makeEntry("a.ts", [" auth:login "]),
    makeEntry("b.ts", ["auth:login"]),
  ];
  // Trimmed IDs collide — only one surface spawned.
  const result = deduplicateAndPrioritize(entries);
  assert.equal(result.total_unique, 1);
});

// ---------------------------------------------------------------------------
// Agent lifecycle helpers
// ---------------------------------------------------------------------------

test("initSpawnedAgent creates a running agent record", () => {
  const context = {
    target_domain: "gh-123",
    session_id: "sess-1",
    surface_id: "auth:login",
    diff_hunks: [],
  };
  const agent = initSpawnedAgent(context);
  assert.equal(agent.status, "running");
  assert.equal(agent.surface_id, "auth:login");
  assert.equal(agent.exited_at, null);
  assert.ok(typeof agent.spawned_at === "number" && agent.spawned_at > 0);
});

test("markAgentCompleted sets status to completed and exited_at", () => {
  const context = {
    target_domain: "gh-123",
    session_id: "sess-1",
    surface_id: "auth:login",
    diff_hunks: [],
  };
  const running = initSpawnedAgent(context);
  const completed = markAgentCompleted(running);
  assert.equal(completed.status, "completed");
  assert.ok(typeof completed.exited_at === "number" && completed.exited_at > 0);
  // Original record must not be mutated.
  assert.equal(running.status, "running");
  assert.equal(running.exited_at, null);
});

test("markAgentTimedOut sets status to timed_out and exited_at", () => {
  const context = {
    target_domain: "gh-123",
    session_id: "sess-1",
    surface_id: "smart_contract:vault",
    diff_hunks: [],
  };
  const running = initSpawnedAgent(context);
  const timedOut = markAgentTimedOut(running);
  assert.equal(timedOut.status, "timed_out");
  assert.ok(typeof timedOut.exited_at === "number" && timedOut.exited_at > 0);
});

// ---------------------------------------------------------------------------
// Acceptance criterion 6: S6 readiness
// ---------------------------------------------------------------------------

test("allAgentsExited returns false while any agent is running", () => {
  const makeAgent = (status) => ({
    surface_id: "s",
    context: { target_domain: "t", session_id: "s", surface_id: "s", diff_hunks: [] },
    spawned_at: Date.now(),
    status,
    exited_at: status !== "running" ? Date.now() : null,
  });

  const agents = [
    makeAgent("completed"),
    makeAgent("running"),
    makeAgent("timed_out"),
  ];
  assert.equal(allAgentsExited(agents), false);
});

test("allAgentsExited returns true when all agents are in terminal states", () => {
  const makeAgent = (status) => ({
    surface_id: "s",
    context: { target_domain: "t", session_id: "s", surface_id: "s", diff_hunks: [] },
    spawned_at: Date.now(),
    status,
    exited_at: Date.now(),
  });

  const agents = [
    makeAgent("completed"),
    makeAgent("timed_out"),
    makeAgent("skipped"),
  ];
  assert.equal(allAgentsExited(agents), true);
});

test("allAgentsExited returns true for an empty agent array", () => {
  assert.equal(allAgentsExited([]), true);
});

// ---------------------------------------------------------------------------
// Timeout detection
// ---------------------------------------------------------------------------

test("AGENT_TIMEOUT_MS is 5 minutes (300000 ms)", () => {
  assert.equal(AGENT_TIMEOUT_MS, 300000);
});

test("findTimedOutAgents identifies agents past the timeout threshold", () => {
  const now = Date.now();
  const old = now - 400000; // 400 seconds ago — past the 5-minute threshold.
  const recent = now - 60000; // 60 seconds ago — within threshold.

  const agents = [
    {
      surface_id: "auth:login",
      context: {},
      spawned_at: old,
      status: "running",
      exited_at: null,
    },
    {
      surface_id: "api-route:users",
      context: {},
      spawned_at: recent,
      status: "running",
      exited_at: null,
    },
    {
      surface_id: "admin:dashboard",
      context: {},
      spawned_at: old,
      status: "completed", // already completed — not a timeout.
      exited_at: now - 10000,
    },
  ];

  const timedOut = findTimedOutAgents(agents, AGENT_TIMEOUT_MS, now);
  assert.equal(timedOut.length, 1);
  assert.equal(timedOut[0].surface_id, "auth:login");
});

test("findTimedOutAgents returns empty when no agents exceeded timeout", () => {
  const now = Date.now();
  const agents = [
    {
      surface_id: "auth:login",
      context: {},
      spawned_at: now - 60000,
      status: "running",
      exited_at: null,
    },
  ];
  const timedOut = findTimedOutAgents(agents, AGENT_TIMEOUT_MS, now);
  assert.equal(timedOut.length, 0);
});

// ---------------------------------------------------------------------------
// Acceptance criterion 5: coverage gap detection
// ---------------------------------------------------------------------------

test("findCoverageGaps identifies completed agents missing coverage log", () => {
  const agents = [
    { surface_id: "auth:login", status: "completed", context: {}, spawned_at: 0, exited_at: Date.now() },
    { surface_id: "api-route:users", status: "completed", context: {}, spawned_at: 0, exited_at: Date.now() },
    { surface_id: "admin:panel", status: "timed_out", context: {}, spawned_at: 0, exited_at: Date.now() },
    { surface_id: "smart_contract:vault", status: "running", context: {}, spawned_at: 0, exited_at: null },
  ];

  // Only auth:login logged coverage.
  const coveredSurfaces = new Set(["auth:login"]);
  const gaps = findCoverageGaps(agents, coveredSurfaces);

  // api-route:users (completed, no coverage) and admin:panel (timed_out, no coverage) are gaps.
  // smart_contract:vault (still running) is not a gap yet.
  assert.equal(gaps.length, 2);
  assert.ok(gaps.includes("api-route:users"));
  assert.ok(gaps.includes("admin:panel"));
  assert.ok(!gaps.includes("auth:login"), "covered surfaces must not appear as gaps");
  assert.ok(!gaps.includes("smart_contract:vault"), "running agents must not appear as gaps");
});

test("findCoverageGaps returns empty when all completed agents logged coverage", () => {
  const agents = [
    { surface_id: "auth:login", status: "completed", context: {}, spawned_at: 0, exited_at: Date.now() },
  ];
  const covered = new Set(["auth:login"]);
  const gaps = findCoverageGaps(agents, covered);
  assert.equal(gaps.length, 0);
});

// ---------------------------------------------------------------------------
// buildAgentContexts
// ---------------------------------------------------------------------------

test("buildAgentContexts returns one context per deduplicated surface_id", () => {
  const result = buildAgentContexts({
    impactedEntries: SAMPLE_ENTRIES,
    targetDomain: "gh-77777",
    sessionId: "sess-777",
  });
  // 3 unique surface_ids in SAMPLE_ENTRIES.
  assert.equal(result.contexts.length, 3);
  assert.equal(result.deduplication.total_unique, 3);
  assert.equal(result.deduplication.capped_count, 0);
});

test("buildAgentContexts aggregates diff_hunks for a surface spanning multiple entries", () => {
  const result = buildAgentContexts({
    impactedEntries: SAMPLE_ENTRIES,
    targetDomain: "gh-77777",
    sessionId: "sess-777",
  });
  const authCtx = result.contexts.find((c) => c.surface_id === "auth:login-handler");
  assert.ok(authCtx, "expected context for auth:login-handler");
  // Two entries carry auth:login-handler.
  assert.equal(authCtx.diff_hunks.length, 2);
});

// ---------------------------------------------------------------------------
// formatS5FailureJson
// ---------------------------------------------------------------------------

test("formatS5FailureJson returns parseable JSON with step S5.evaluator_dispatch", () => {
  const json = formatS5FailureJson({ code: "spawn_failed", message: "agent process exited" });
  const parsed = JSON.parse(json);
  assert.equal(parsed.step, "S5.evaluator_dispatch");
  assert.equal(parsed.ok, false);
  assert.equal(parsed.error.code, "spawn_failed");
  assert.equal(parsed.error.message, "agent process exited");
});

test("formatS5FailureJson produces pretty-printed JSON", () => {
  const json = formatS5FailureJson({ code: "timeout", message: "agent timed out" });
  assert.ok(json.includes("\n"), "should be pretty-printed with newlines");
});
