"use strict";

// CN (coverage-nesting) Step B — E2 honest e2e. node:test cannot spawn a real
// subagent, so this verifies the IN-PROCESS chain end to end: opt-in policy =>
// a depth-3 plan is emitted from a real brief => the MCP width bound caps the
// fan-out so its worst-case tree fits the spawn budget (the governor) => an
// exhausted budget degrades the plan to flat (the breaker) => default-off emits
// nothing. The live recursion + the dispatch-side ledger write are the host's
// job and out of scope for an in-process test.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");

const { DEFAULT_QUEUE_POLICY, normalizeQueuePolicy, writeQueuePolicy } = require("../mcp/lib/queue-policy.js");
const { worstCaseTreeSize } = require("../mcp/lib/nested-spawn.js");
const { buildChildFanoutPlanForSurface } = require("../mcp/lib/assignment-brief.js");

const SURFACE = { id: "surface:api", bug_class_hints: ["idor", "ssrf", "xss", "ssti", "auth_bypass"] };

function withClaudeHome(fn) {
  const ph = process.env.HOME;
  const pc = process.env.BOB_CLIENT;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-e2-"));
  process.env.HOME = home;
  process.env.BOB_CLIENT = "claude"; // nesting is claude-only (NS-3)
  try {
    return fn(home);
  } finally {
    process.env.HOME = ph;
    if (pc === undefined) delete process.env.BOB_CLIENT;
    else process.env.BOB_CLIENT = pc;
    try { fs.rmSync(home, { recursive: true, force: true }); } catch {}
  }
}

function planFor(domain, policyOverride) {
  writeQueuePolicy(domain, normalizeQueuePolicy({ ...DEFAULT_QUEUE_POLICY, ...policyOverride }));
  return buildChildFanoutPlanForSurface({ domain, surfaceObj: SURFACE, surfaceId: SURFACE.id, coverageSummary: {} });
}

test("E2: opt-in nesting emits a depth-3 plan whose worst-case tree fits the spawn budget (governor caps the width)", () => {
  withClaudeHome(() => {
    // 5 bug-classes (1 anon auth) = 5 candidate cells; budget 20 at depth-3
    // (remaining_depth 2) => maxBranching 4 (4 + 4^2 = 20), so the 5th cell is capped.
    const plan = planFor("e2-cov.example.com", { max_spawn_depth: 3, max_spawn_children: 64, max_total_spawned_agents: 20 });
    assert.ok(plan, "nesting on => a plan is emitted");
    assert.equal(plan.remaining_depth, 2, "depth 3 => remaining_depth 2 (within claude ceiling 5)");
    const width = plan.children.length;
    assert.ok(width <= 4, `the governor caps the width to <= 4 (got ${width})`);
    assert.ok(worstCaseTreeSize(width, plan.remaining_depth) <= 20, "the root's worst-case tree fits the budget");
    assert.ok(plan.budget_pruned_count > 0, "the over-budget cell was capped (the governor bit)");
    // Every child carries the brain-pinned spawn role + a one-smaller depth budget.
    for (const child of plan.children) {
      assert.equal(child.subagent_type, "evaluator-fanout");
      assert.equal(child.remaining_depth, 1);
    }
  });
});

test("E2: the breaker — an exhausted spawn budget degrades the plan to flat (no nested fan-out)", () => {
  withClaudeHome(() => {
    // budget 1 at depth-3: even branching 1 has worst-case tree 1+1=2 > 1 => maxBranching 0 => leaf.
    const plan = planFor("e2-breaker.example.com", { max_spawn_depth: 3, max_spawn_children: 64, max_total_spawned_agents: 1 });
    assert.equal(plan, null, "exhausted budget => no nested plan (degrades to flat wave dispatch)");
  });
});

test("E2: default-off is unchanged — no nested plan when nesting is off", () => {
  withClaudeHome(() => {
    const plan = planFor("e2-off.example.com", {});
    assert.equal(plan, null, "default (max_spawn_depth 1, budget null) => no nested plan");
  });
});
