"use strict";

// CN (coverage-nesting) Step B — E2 honest e2e. node:test cannot spawn a real
// subagent, so this verifies the IN-PROCESS chain end to end: opt-in policy =>
// a host-clamped one-child-level plan is emitted from a real brief => the MCP width bound caps the
// fan-out so its worst-case tree fits the spawn budget (the governor) => an
// exhausted budget degrades the plan to flat (the breaker) => default-off emits
// nothing. The live recursion + the dispatch-side ledger write are the host's
// job and out of scope for an in-process test.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");

const { DEFAULT_QUEUE_POLICY, LEAN_PROFILE, normalizeQueuePolicy, writeQueuePolicy } = require("../mcp/lib/queue-policy.js");
const { FANOUT_ROLE_REGISTRY, worstCaseTreeSize } = require("../mcp/lib/nested-spawn.js");
const { buildChildFanoutPlanForSurface } = require("../mcp/lib/assignment-brief.js");

const SURFACE = { id: "surface:api", bug_class_hints: ["idor", "ssrf", "xss", "ssti", "auth_bypass"] };

function withClaudeHome(fn) {
  const ph = process.env.HOME;
  const pc = process.env.BOB_CLIENT;
  const pt = process.env.CLAUDE_CODE_EXPERIMENTAL_AGENT_TEAMS;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-e2-"));
  process.env.HOME = home;
  process.env.BOB_CLIENT = "claude"; // nesting is explicitly-enabled Claude-only (NS-3)
  process.env.CLAUDE_CODE_EXPERIMENTAL_AGENT_TEAMS = "1";
  try {
    return fn(home);
  } finally {
    process.env.HOME = ph;
    if (pc === undefined) delete process.env.BOB_CLIENT;
    else process.env.BOB_CLIENT = pc;
    if (pt === undefined) delete process.env.CLAUDE_CODE_EXPERIMENTAL_AGENT_TEAMS;
    else process.env.CLAUDE_CODE_EXPERIMENTAL_AGENT_TEAMS = pt;
    try { fs.rmSync(home, { recursive: true, force: true }); } catch {}
  }
}

function planFor(domain, policyOverride) {
  writeQueuePolicy(domain, normalizeQueuePolicy({ ...DEFAULT_QUEUE_POLICY, ...policyOverride }));
  return buildChildFanoutPlanForSurface({ domain, surfaceObj: SURFACE, surfaceId: SURFACE.id, coverageSummary: {} });
}

test("E2: Claude's one-level plan fits the spawn budget (governor caps the width)", () => {
  withClaudeHome(() => {
    // 5 bug-classes (1 anon auth) = 5 candidate cells; Claude clamps the policy's
    // depth 3 to depth 2 (remaining_depth 1). The lifetime budget reserves one
    // slot for the root itself, leaving descendant width 3.
    const plan = planFor("e2-cov.example.com", { max_spawn_depth: 3, max_spawn_children: 64, max_total_spawned_agents: 4 });
    assert.ok(plan, "nesting on => a plan is emitted");
    assert.equal(plan.remaining_depth, 1, "policy depth 3 => remaining_depth 1 under Claude's depth-2 ceiling");
    const width = plan.children.length;
    assert.ok(width <= 3, `the governor caps descendant width to <= 3 (got ${width})`);
    assert.ok(
      1 + worstCaseTreeSize(width, plan.remaining_depth) <= 4,
      "the root plus its worst-case descendants fit the lifetime budget",
    );
    assert.ok(plan.budget_pruned_count > 0, "the over-budget cell was capped (the governor bit)");
    // Every child carries the brain-pinned spawn role and is a non-recursive leaf.
    for (const child of plan.children) {
      assert.equal(child.subagent_type, FANOUT_ROLE_REGISTRY.child.subagent_type);
      assert.equal(child.remaining_depth, 0);
      assert.ok(!child.allowed_tools_for_node.includes("bob_write_wave_handoff"),
        "MCP-issued child contract excludes the root-owned handoff writer");
      assert.ok(!child.allowed_tools_for_node.includes("bob_finalize_agent_run"),
        "MCP-issued child contract excludes the root-owned finalizer");
    }
  });
});

test("E2: the breaker — an exhausted spawn budget degrades the plan to flat (no nested fan-out)", () => {
  withClaudeHome(() => {
    const domain = "e2-breaker.example.com";
    // Reserve the only lifetime slot first. The read path then sees zero remaining
    // budget, chooses branching 0, and emits no child plan.
    require("../mcp/lib/spawn-ledger.js").appendSpawnLedgerEntry(domain, {
      ts: "2026-01-01T00:00:00.000Z",
      wave: "w0",
      parent_agent: "a0",
      surface_id: "surface:prior",
      depth: 1,
      branching: 0,
      root_count: 1,
      descendant_tree: 0,
      worst_case_tree: 1,
    });
    const plan = planFor(domain, { max_spawn_depth: 3, max_spawn_children: 64, max_total_spawned_agents: 1 });
    assert.equal(plan, null, "exhausted budget => no nested plan (degrades to flat wave dispatch)");
  });
});

test("E2: a lean override emits no plan; enabled agent teams let the default policy emit one", () => {
  withClaudeHome(() => {
    // Off-path via a lean override: depth 1 => no nested plan (flat dispatch).
    const leanPlan = planFor("e2-off.example.com", LEAN_PROFILE);
    assert.equal(leanPlan, null, "lean override (max_spawn_depth 1, budget null) => no nested plan");

    // The policy default requests depth 3; this helper explicitly enables Claude
    // agent teams, so the runtime gate admits a host-clamped child plan.
    const onDefaultPlan = planFor("e2-on-default.example.com", {});
    assert.ok(onDefaultPlan, "the shipped depth-3 policy emits a nested plan on flag-enabled Claude");
    assert.equal(onDefaultPlan.remaining_depth, 1, "policy depth 3 => remaining_depth 1 under Claude's ceiling");
  });
});
