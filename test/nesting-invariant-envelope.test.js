"use strict";

// CN (coverage-nesting) Step B — the nesting invariant-envelope capstone (E1).
// Registry-driven lock over NS-1..NS-7, each asserted via a REAL artifact (not a
// vacuous pure-function check): the rendered spawn role, the deny'd toolset, the
// LIVE host-clamped plan, the budget bound, and the default-off policy. Mirrors the
// G2 coverage-cell-invariant-envelope capstone.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");

const { REGISTRY } = require("../mcp/lib/invariant-registry.js");
const {
  CLAUDE_ROLE_SPECS,
  claudeAllowedToolsForRole,
  fanoutChildAgentNames,
  spawnCapableAgentNames,
} = require("../scripts/lib/claude-role-renderer.js");
const { mcpToolNamesForRole } = require("../mcp/lib/role-model.js");
const { DEFAULT_QUEUE_POLICY, LEAN_PROFILE, normalizeQueuePolicy, writeQueuePolicy } = require("../mcp/lib/queue-policy.js");
const {
  FANOUT_ROLE_REGISTRY,
  maxBranchingForBudget,
  validateSpawnFanout,
} = require("../mcp/lib/nested-spawn.js");
const { buildChildFanoutPlanForSurface } = require("../mcp/lib/assignment-brief.js");
const { techniqueCompatibilityPackId } = require("../mcp/lib/capability-packs.js");
const { loadTechniqueRegistry, techniquePackSupportsCapability } = require("../mcp/lib/technique-packs.js");

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

function withHost(host, fn, { agentTeams = host === "claude" } = {}) {
  const ph = process.env.HOME;
  const pc = process.env.BOB_CLIENT;
  const pt = process.env.CLAUDE_CODE_EXPERIMENTAL_AGENT_TEAMS;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-e1-"));
  process.env.HOME = home;
  if (host === undefined) delete process.env.BOB_CLIENT;
  else process.env.BOB_CLIENT = host;
  if (agentTeams) process.env.CLAUDE_CODE_EXPERIMENTAL_AGENT_TEAMS = "1";
  else delete process.env.CLAUDE_CODE_EXPERIMENTAL_AGENT_TEAMS;
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

test("E1 capstone: NS-1..NS-7 are registry-declared nested_fanout invariants", () => {
  for (const tag of ["NS-1", "NS-2", "NS-3", "NS-4", "NS-5", "NS-6", "NS-7"]) {
    assert.ok(REGISTRY[tag], `${tag} is a registry entry`);
    assert.equal(REGISTRY[tag].kind, "invariant");
    assert.equal(REGISTRY[tag].class, "nested_fanout");
  }
});

test("E1 NS-1: exactly one declared spawner (real renderer registry)", () => {
  assert.deepEqual(spawnCapableAgentNames(), [FANOUT_ROLE_REGISTRY.root.subagent_type]);
  assert.deepEqual(fanoutChildAgentNames(), [FANOUT_ROLE_REGISTRY.child.subagent_type]);
  assert.equal(CLAUDE_ROLE_SPECS[FANOUT_ROLE_REGISTRY.root.role_id].spawn_capable, true);
  assert.notEqual(CLAUDE_ROLE_SPECS[FANOUT_ROLE_REGISTRY.child.role_id].spawn_capable, true,
    "the distinct child must remain a leaf");
  assert.notEqual(CLAUDE_ROLE_SPECS[FANOUT_ROLE_REGISTRY.child.role_id].background, true,
    "fanout children must remain eligible for anonymous synchronous invocation");
});

test("E1 NS-2: the spawn role's granted tools are disjoint from the coverage-cell tools (real render + deny)", () => {
  const cell = coverageCellToolNames();
  const leaked = mcpToolNamesForRole("evaluator-fanout").filter((t) => cell.has(t));
  assert.deepEqual(leaked, [], `spawn role leaks a cell tool: ${JSON.stringify(leaked)}`);
});

test("E1 NS-7: child frontmatter subtracts recursion and root settlement before spawn", () => {
  const childTools = new Set(claudeAllowedToolsForRole(FANOUT_ROLE_REGISTRY.child.role_id));
  for (const denied of ["Agent", "Task"]) assert.equal(childTools.has(denied), false);
  for (const denied of ["bob_write_wave_handoff", "bob_finalize_agent_run"]) {
    assert.equal(childTools.has(`mcp__hacker-bob__${denied}`), false);
  }
  for (const retained of ["bob_read_assignment_brief", "bob_record_candidate_claim", "bob_log_coverage", "bob_read_technique_pack", "bob_log_technique_attempt"]) {
    assert.equal(childTools.has(`mcp__hacker-bob__${retained}`), true, `child lost ${retained}`);
  }
});

test("E1 NS-3: host-only nesting + depth clamp via the LIVE plan path", () => {
  withHost("claude", () => {
    const domain = "e1-claude-default.example.com";
    writeQueuePolicy(domain, normalizeQueuePolicy({ ...DEFAULT_QUEUE_POLICY, max_spawn_depth: 6, max_spawn_children: 8 }));
    const plan = buildChildFanoutPlanForSurface({ domain, surfaceObj: { id: "s", bug_class_hints: ["idor"] }, surfaceId: "s", coverageSummary: {} });
    assert.equal(plan, null, "default Claude stays flat while experimental agent teams are disabled");
  }, { agentTeams: false });
  withHost("claude", () => {
    const domain = "e1-host.example.com";
    writeQueuePolicy(domain, normalizeQueuePolicy({ ...DEFAULT_QUEUE_POLICY, max_spawn_depth: 6, max_spawn_children: 8 }));
    const plan = buildChildFanoutPlanForSurface({ domain, surfaceObj: { id: "s", bug_class_hints: ["idor"] }, surfaceId: "s", coverageSummary: {} });
    assert.ok(plan && plan.remaining_depth === 1, "claude depth-6 clamps to remaining_depth 1 (host ceiling 2)");
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
    { remaining_depth: 1, max_children: 8, total_spawned: 0, max_total_spawned_agents: 0, child_type_allowlist: [FANOUT_ROLE_REGISTRY.child.subagent_type] },
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

test("E1 NS-6: web_fanout resolves to web for every technique compatibility predicate", () => {
  assert.equal(techniqueCompatibilityPackId("web_fanout"), "web");
  const genericWeb = loadTechniqueRegistry().packs.find((pack) => pack.id === "generic-rest-api");
  assert.ok(genericWeb, "the real web technique registry contains generic-rest-api");
  assert.equal(techniquePackSupportsCapability(genericWeb, "web_fanout"), true);
  assert.equal(techniquePackSupportsCapability(genericWeb, "smart_contract_evm"), false);
});

test("E1 NS-7: rendered child contract and stop hook share the cell-bound root-owned marker", () => {
  const prompt = fs.readFileSync(path.join(__dirname, "..", "prompts", "roles", "evaluator-fanout.md"), "utf8");
  const childPrompt = fs.readFileSync(path.join(__dirname, "..", "prompts", "roles", "evaluator-fanout-child.md"), "utf8");
  const hook = fs.readFileSync(path.join(__dirname, "..", ".claude", "hooks", "agent-run-stop.js"), "utf8");
  assert.match(prompt, /BOB_CHILD_CELL_DONE/);
  assert.match(prompt, /evaluator-fanout-child/);
  assert.match(childPrompt, /cell_key/);
  assert.match(childPrompt, /planning_key/);
  assert.match(childPrompt, /BOB_CHILD_CELL_DONE/);
  assert.match(hook, /BOB_CHILD_CELL_DONE/);
  assert.match(hook, /evaluateNestedChildCompletion/);
  assert.match(childPrompt, /Do NOT call `bob_write_wave_handoff`/);
  assert.match(childPrompt, /Do NOT call `bob_finalize_agent_run`/);
});
