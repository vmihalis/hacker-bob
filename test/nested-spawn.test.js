const test = require("node:test");
const assert = require("node:assert/strict");

const {
  FANOUT_ROLE_REGISTRY,
  HOST_NESTING_CAPABILITIES,
  nestingCapabilityForHost,
  runtimeNestingEnabledForHost,
  hostPoolCeiling,
  effectiveConcurrencyCap,
  effectiveSpawnDepth,
  worstCaseTreeSize,
  maxBranchingForBudget,
  validateSpawnFanout,
} = require("../mcp/core/session/nested-spawn.js");

const {
  normalizeQueuePolicy,
  DEFAULT_QUEUE_POLICY,
  LEAN_PROFILE,
} = require("../mcp/core/io/queue-policy.js");

// ─── queue-policy spawn budget (A1) ──────────────────────────────────────

test("the cross-role fan-out default turns nesting ON (depth 3, 64 children); a lean override restores depth 1", () => {
  // The default drives cross-role fan-out: depth 3 + 64-wide cells.
  assert.equal(DEFAULT_QUEUE_POLICY.max_spawn_depth, 3);
  assert.equal(DEFAULT_QUEUE_POLICY.max_spawn_children, 64);
  const p = normalizeQueuePolicy(DEFAULT_QUEUE_POLICY);
  assert.equal(p.max_spawn_depth, 3);
  assert.equal(p.max_spawn_children, 64);
  // The off-path floor is reachable: an explicit lean override restores depth 1.
  const lean = normalizeQueuePolicy(LEAN_PROFILE);
  assert.equal(lean.max_spawn_depth, 1);
  assert.equal(lean.max_spawn_children, 8);
});

test("queue policy accepts opt-in depth/children and clamps to ceiling", () => {
  const p = normalizeQueuePolicy({ max_spawn_depth: 3, max_spawn_children: 16 });
  assert.equal(p.max_spawn_depth, 3);
  assert.equal(p.max_spawn_children, 16);
  assert.throws(() => normalizeQueuePolicy({ max_spawn_depth: 99 }), /max_spawn_depth must be <= 8/);
  assert.throws(() => normalizeQueuePolicy({ max_spawn_depth: 0 }), /max_spawn_depth must be >= 1/);
  assert.throws(() => normalizeQueuePolicy({ max_spawn_children: 999 }), /max_spawn_children must be <= 64/);
});

// ─── host capability registry (A4) ───────────────────────────────────────

test("host capability registry matches the per-CLI research", () => {
  assert.equal(HOST_NESTING_CAPABILITIES.claude.supports_nesting, true);
  assert.equal(HOST_NESTING_CAPABILITIES.claude.nesting_mechanism, "agent_team_sync_subagent");
  assert.equal(HOST_NESTING_CAPABILITIES.claude.max_native_depth, 2);
  assert.equal(HOST_NESTING_CAPABILITIES.claude.minimum_host_version, "2.1.172");
  assert.deepEqual(HOST_NESTING_CAPABILITIES.claude.runtime_enablement, {
    env_var: "CLAUDE_CODE_EXPERIMENTAL_AGENT_TEAMS",
    enabled_value: "1",
  });
  assert.equal(HOST_NESTING_CAPABILITIES.codex.supports_nesting, true);
  assert.equal(HOST_NESTING_CAPABILITIES.codex.max_native_depth, null);
  assert.equal(HOST_NESTING_CAPABILITIES.kimi.supports_nesting, false);
  assert.equal(HOST_NESTING_CAPABILITIES["generic-mcp"].supports_nesting, false);
});

test("Claude nesting is runtime-gated by the exact experimental agent-teams flag", () => {
  assert.equal(runtimeNestingEnabledForHost("claude", {}), false, "agent teams are off by default");
  assert.equal(runtimeNestingEnabledForHost("claude", { CLAUDE_CODE_EXPERIMENTAL_AGENT_TEAMS: "0" }), false);
  assert.equal(runtimeNestingEnabledForHost("claude", { CLAUDE_CODE_EXPERIMENTAL_AGENT_TEAMS: "true" }), false);
  assert.equal(runtimeNestingEnabledForHost("claude", { CLAUDE_CODE_EXPERIMENTAL_AGENT_TEAMS: " 1 " }), true);
  assert.equal(runtimeNestingEnabledForHost("codex", {}), true, "Codex has no registry-declared env gate");
  assert.equal(runtimeNestingEnabledForHost("unknown", { CLAUDE_CODE_EXPERIMENTAL_AGENT_TEAMS: "1" }), false);
});

test("unknown / empty host fails closed to no-nesting", () => {
  assert.equal(nestingCapabilityForHost("nope").supports_nesting, false);
  assert.equal(nestingCapabilityForHost("").supports_nesting, false);
  assert.equal(nestingCapabilityForHost(undefined).supports_nesting, false);
});

test("effectiveSpawnDepth clamps by host and never drops below 1", () => {
  const agentTeamsEnabled = { CLAUDE_CODE_EXPERIMENTAL_AGENT_TEAMS: "1" };
  // claude: flat by default; an explicitly enabled named teammate may spawn
  // one anonymous synchronous child level.
  assert.equal(effectiveSpawnDepth(8, "claude", {}), 1);
  assert.equal(effectiveSpawnDepth(8, "claude", agentTeamsEnabled), 2);
  assert.equal(effectiveSpawnDepth(3, "claude", agentTeamsEnabled), 2);
  // codex: operator-set ceiling (null) -> honor policy depth
  assert.equal(effectiveSpawnDepth(4, "codex"), 4);
  // kimi/generic/unknown: no nesting -> always 1
  assert.equal(effectiveSpawnDepth(4, "kimi"), 1);
  assert.equal(effectiveSpawnDepth(4, "generic-mcp"), 1);
  assert.equal(effectiveSpawnDepth(4, "unknown-host"), 1);
  // degenerate policy depth -> floored to 1
  assert.equal(effectiveSpawnDepth(0, "claude", agentTeamsEnabled), 1);
  assert.equal(effectiveSpawnDepth(undefined, "codex"), 1);
});

// ─── spawn-fanout detective enforcement primitive (A5) ───────────────────

test("validateSpawnFanout passes a within-budget fan-out", () => {
  const r = validateSpawnFanout(
    [{ subagent_type: "evaluator-agent" }, { subagent_type: "evaluator-agent" }],
    { remaining_depth: 1, max_children: 4, child_type_allowlist: ["evaluator-agent"] },
  );
  assert.equal(r.ok, true);
  assert.deepEqual(r.violations, []);
});

test("validateSpawnFanout flags a leaf that fanned out (depth budget 0)", () => {
  const r = validateSpawnFanout([{ subagent_type: "evaluator-agent" }], { remaining_depth: 0, max_children: 8 });
  assert.equal(r.ok, false);
  assert.match(r.violations.join(" "), /leaf evaluator must not fan out/);
});

test("validateSpawnFanout flags exceeding max_children", () => {
  const r = validateSpawnFanout(
    [1, 2, 3, 4, 5].map(() => ({ subagent_type: "evaluator-agent" })),
    { remaining_depth: 1, max_children: 3 },
  );
  assert.equal(r.ok, false);
  assert.match(r.violations.join(" "), /exceeds max_children budget 3/);
});

test("validateSpawnFanout flags a child type outside the allowlist", () => {
  const r = validateSpawnFanout(
    [{ subagent_type: "orchestrator" }],
    { remaining_depth: 1, max_children: 4, child_type_allowlist: ["evaluator-agent"] },
  );
  assert.equal(r.ok, false);
  assert.match(r.violations.join(" "), /"orchestrator" is not in the child_type_allowlist/);
});

test("validateSpawnFanout: no allowlist means any child type is allowed (count/depth still bound)", () => {
  const r = validateSpawnFanout(
    [{ subagent_type: "anything" }],
    { remaining_depth: 1, max_children: 4 },
  );
  assert.equal(r.ok, true);
});

// ─── D3: host concurrent-subagent pool ceiling ───────────────────────────

test("hostPoolCeiling: nesting hosts self-manage (null), non-nesting/unknown fail-closed to 1", () => {
  assert.equal(hostPoolCeiling("claude"), null, "claude self-manages a bounded pool (null)");
  assert.equal(hostPoolCeiling("codex"), null, "codex self-manages (operator-config)");
  assert.equal(hostPoolCeiling("kimi"), 1, "no nesting => 1");
  assert.equal(hostPoolCeiling("generic-mcp"), 1);
  assert.equal(hostPoolCeiling("nonsense-host"), 1, "unknown host fail-closes to 1");
  assert.equal(hostPoolCeiling(""), 1);
  // The descriptor is present on every capability entry.
  for (const cap of Object.values(HOST_NESTING_CAPABILITIES)) {
    assert.ok("max_concurrent_subagents" in cap, `${cap.host} carries the pool descriptor`);
  }
});

// ─── D4: shared in-flight concurrency cap ────────────────────────────────

test("effectiveConcurrencyCap: host-managed pools honor the operator's request; finite hosts fail-closed", () => {
  // claude self-manages (null ceiling) => the operator's request governs.
  assert.equal(effectiveConcurrencyCap(500, "claude"), 500, "claude honors the operator's 500");
  assert.equal(effectiveConcurrencyCap(null, "claude"), null, "null request stays null (wave-planner default)");
  // A finite-ceiling host caps the request (never oversubscribe a pool it can't drain).
  assert.equal(effectiveConcurrencyCap(500, "kimi"), 1, "kimi (ceiling 1) caps a 500 request to 1");
  assert.equal(effectiveConcurrencyCap(null, "generic-mcp"), 1, "finite host with no request uses its ceiling");
  assert.equal(effectiveConcurrencyCap(500, "unknown-host"), 1, "unknown host fail-closes to 1");
});

// ─── C5: worst-case-tree budget bound ────────────────────────────────────

test("worstCaseTreeSize sums the geometric fan-out (branching + branching^2 + ...)", () => {
  assert.equal(worstCaseTreeSize(8, 1), 8, "one level = branching");
  assert.equal(worstCaseTreeSize(8, 2), 8 + 64, "two levels = b + b^2");
  assert.equal(worstCaseTreeSize(5, 3), 5 + 25 + 125);
  assert.equal(worstCaseTreeSize(8, 0), 0, "no fan-out levels => leaf, zero descendants");
  assert.equal(worstCaseTreeSize(0, 3), 0, "no branching => zero");
});

test("maxBranchingForBudget caps branching so the worst-case tree fits the budget", () => {
  // depth-3 (remaining_depth 2): worstCaseTree(b,2) = b + b^2. budget 500 => b=21
  // (462 <= 500 < 506), capped under the hardCap of 64.
  assert.equal(maxBranchingForBudget(2, 500, 64), 21);
  // depth-2 (remaining_depth 1): worstCaseTree(b,1) = b. budget 500, hardCap 64 => 64.
  assert.equal(maxBranchingForBudget(1, 500, 64), 64);
  // budget below a single child => leaf (breaker).
  assert.equal(maxBranchingForBudget(2, 0, 64), 0);
});

test("maxBranchingForBudget is default-off: null/Infinity budget leaves the hardCap unchanged", () => {
  assert.equal(maxBranchingForBudget(2, null, 64), 64, "null budget => no governor");
  assert.equal(maxBranchingForBudget(2, Infinity, 64), 64);
  assert.equal(maxBranchingForBudget(0, 500, 64), 64, "remaining_depth 0 => width irrelevant");
});

test("validateSpawnFanout 4th leg: the session spawn budget bounds the running total", () => {
  // total_spawned already at 6, this plan adds 4 => 10 > max 8 is a violation.
  const over = validateSpawnFanout(
    Array.from({ length: 4 }, () => ({ subagent_type: FANOUT_ROLE_REGISTRY.child.subagent_type })),
    { remaining_depth: 1, max_children: 8, total_spawned: 6, max_total_spawned_agents: 8 },
  );
  assert.equal(over.ok, false);
  assert.ok(over.violations.some((v) => /max_total_spawned_agents/.test(v)));
  // Within budget passes.
  const ok = validateSpawnFanout(
    [{ subagent_type: FANOUT_ROLE_REGISTRY.child.subagent_type }],
    { remaining_depth: 1, max_children: 8, total_spawned: 6, max_total_spawned_agents: 8 },
  );
  assert.equal(ok.ok, true);
  // Default-off: null max_total => no session-budget leg.
  const off = validateSpawnFanout(
    [{ subagent_type: FANOUT_ROLE_REGISTRY.child.subagent_type }],
    { remaining_depth: 1, max_children: 8, total_spawned: 9999 },
  );
  assert.equal(off.ok, true);
});
