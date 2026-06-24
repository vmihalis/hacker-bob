"use strict";

// CN (coverage-nesting) Step B — the nesting invariant-envelope capstone (E1).
// Registry-driven lock over NS-1..NS-5, each asserted via a REAL artifact (not a
// vacuous pure-function check): the rendered spawn role, the deny'd toolset, the
// LIVE host-clamped plan, the budget bound, and the default-off policy. Mirrors the
// G2 coverage-cell-invariant-envelope capstone.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");

const { REGISTRY } = require("../mcp/lib/invariant-registry.js");
const { spawnCapableAgentNames, CLAUDE_ROLE_SPECS } = require("../scripts/lib/claude-role-renderer.js");
const { mcpToolNamesForRole } = require("../mcp/lib/role-model.js");
const { DEFAULT_QUEUE_POLICY, LEAN_PROFILE, normalizeQueuePolicy, writeQueuePolicy } = require("../mcp/lib/queue-policy.js");
const { maxBranchingForBudget, validateSpawnFanout } = require("../mcp/lib/nested-spawn.js");
const { buildChildFanoutPlanForSurface } = require("../mcp/lib/assignment-brief.js");

const TOOLS_DIR = path.join(__dirname, "..", "mcp", "lib", "tools");
const CELL_MARKERS = ["appendCellProposal", "appendTransitionProposal", "appendNodeTransition", "materializeCellFloor", "selectNextExecutableNodes", "buildCellCoverageContract", "enumerateCandidatePaths", "verifyCompositionPath"];
function coverageCellToolNames() {
  const out = new Set();
  for (const f of fs.readdirSync(TOOLS_DIR).filter((x) => x.endsWith(".js") && !x.startsWith("_"))) {
    const src = fs.readFileSync(path.join(TOOLS_DIR, f), "utf8");
    if (!CELL_MARKERS.some((m) => src.includes(m))) continue;
    const spec = require(path.join(TOOLS_DIR, f));
    if (spec && typeof spec.name === "string") out.add(spec.name);
  }
  return out;
}

function withHost(host, fn) {
  const ph = process.env.HOME;
  const pc = process.env.BOB_CLIENT;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-e1-"));
  process.env.HOME = home;
  if (host === undefined) delete process.env.BOB_CLIENT;
  else process.env.BOB_CLIENT = host;
  try {
    return fn(home);
  } finally {
    process.env.HOME = ph;
    if (pc === undefined) delete process.env.BOB_CLIENT;
    else process.env.BOB_CLIENT = pc;
    try { fs.rmSync(home, { recursive: true, force: true }); } catch {}
  }
}

test("E1 capstone: NS-1..NS-5 are registry-declared nested_fanout invariants", () => {
  for (const tag of ["NS-1", "NS-2", "NS-3", "NS-4", "NS-5"]) {
    assert.ok(REGISTRY[tag], `${tag} is a registry entry`);
    assert.equal(REGISTRY[tag].kind, "invariant");
    assert.equal(REGISTRY[tag].class, "nested_fanout");
  }
});

test("E1 NS-1: exactly one declared spawner (real renderer registry)", () => {
  assert.deepEqual(spawnCapableAgentNames(), ["evaluator-fanout"]);
  assert.equal(CLAUDE_ROLE_SPECS["evaluator-fanout"].spawn_capable, true);
});

test("E1 NS-2: the spawn role's granted tools are disjoint from the coverage-cell tools (real render + deny)", () => {
  const cell = coverageCellToolNames();
  const leaked = mcpToolNamesForRole("evaluator-fanout").filter((t) => cell.has(t));
  assert.deepEqual(leaked, [], `spawn role leaks a cell tool: ${JSON.stringify(leaked)}`);
});

test("E1 NS-3: host-only nesting + depth clamp via the LIVE plan path", () => {
  withHost("claude", () => {
    const domain = "e1-host.example.com";
    writeQueuePolicy(domain, normalizeQueuePolicy({ ...DEFAULT_QUEUE_POLICY, max_spawn_depth: 6, max_spawn_children: 8 }));
    const plan = buildChildFanoutPlanForSurface({ domain, surfaceObj: { id: "s", bug_class_hints: ["idor"] }, surfaceId: "s", coverageSummary: {} });
    assert.ok(plan && plan.remaining_depth === 4, "claude depth-6 clamps to remaining_depth 4 (host ceiling 5)");
  });
  withHost(undefined, () => {
    const domain = "e1-unknown.example.com";
    writeQueuePolicy(domain, normalizeQueuePolicy({ ...DEFAULT_QUEUE_POLICY, max_spawn_depth: 6, max_spawn_children: 8 }));
    const plan = buildChildFanoutPlanForSurface({ domain, surfaceObj: { id: "s", bug_class_hints: ["idor"] }, surfaceId: "s", coverageSummary: {} });
    assert.equal(plan, null, "non-claude host => no nested plan (host gate)");
  });
});

test("E1 NS-4: bounded fan-out — preventive width cap + detective validateSpawnFanout", () => {
  // depth-3 (remaining_depth 2): worst-case b + b^2 <= 500 => b = 21.
  assert.equal(maxBranchingForBudget(2, 500, 64), 21);
  // Detective: an off-allowlist + over-session-budget child is flagged.
  const v = validateSpawnFanout(
    [{ subagent_type: "evaluator-rogue" }],
    { remaining_depth: 1, max_children: 8, total_spawned: 0, max_total_spawned_agents: 0, child_type_allowlist: ["evaluator-fanout"] },
  );
  assert.equal(v.ok, false);
});

test("E1 NS-5: the cross-role fan-out default nests (depth 3) but keeps the governor null (unbounded fixpoint)", () => {
  // The default now drives cross-role fan-out: depth 3 lets a per-surface
  // evaluator-fanout nest one level of child cells. The lifetime governor stays
  // null — the crux invariant: width is RAISED without a COVERAGE CAP. The
  // shipped default is exempt from the auto-fill, so normalization keeps it null.
  assert.equal(DEFAULT_QUEUE_POLICY.max_spawn_depth, 3);
  assert.equal(DEFAULT_QUEUE_POLICY.max_total_spawned_agents, null);
  assert.equal(normalizeQueuePolicy(DEFAULT_QUEUE_POLICY).max_total_spawned_agents, null);
  // The off-path floor is one override away: LEAN_PROFILE restores depth 1.
  const lean = normalizeQueuePolicy(LEAN_PROFILE);
  assert.equal(lean.max_spawn_depth, 1, "depth-1 (no nesting) is reachable via an explicit lean override");
  assert.equal(lean.max_total_spawned_agents, null, "the lean override stays governor-null too");
});
