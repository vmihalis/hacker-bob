"use strict";

// CN (coverage-nesting) — nested-subagent host-capability registry + spawn
// budget + a detective enforcement primitive.
//
// Bob's brain (the MCP server) owns the (bug_class x auth_role) fan-out
// DECISION and its depth/count budget (see capability-pack-derivation.js
// deriveChildFanoutPlan + queue-policy max_spawn_depth/max_spawn_children).
// The host CLI is the muscle that ACTUATES it. Hosts differ in whether a
// spawned worker may itself spawn children:
//   - claude: one supported nesting edge through agent teams: the wave root is
//     a named background teammate, which may spawn anonymous SYNCHRONOUS
//     subagents. Agent teams are experimental and off by default, so this edge
//     runtime environment on Claude Code >=2.1.172 (the documented minimum for
//     nested subagents; Bob
//     does not probe the CLI version at runtime). Current Claude releases can
//     support deeper generic nesting, but Bob deliberately fixes this topology
//     at depth 2: the generated child has no Agent grant and the host hook denies
//     recursion (wave root + one child level).
//   - codex:  opt-in nesting via ~/.codex/config.toml `[agents] max_depth`
//     (default 1 = workers are leaves). The brain cannot read the operator's
//     config.toml, so max_native_depth is null = "honor the queue-policy depth,
//     gated by the operator's own config".
//   - kimi / generic-mcp: NO nesting. A worker cannot spawn; the fan-out plan
//     is actuated as flat extra wave assignments by the orchestrator.
//
// Unknown host -> fail-closed to no-nesting (the portable flat-wave fallback).
//
// The registry and budget functions are pure. runtimeNestingEnabledForHost and
// effectiveSpawnDepth receive an injectable env object (default process.env) so
// the one host-owned feature gate remains deterministic in tests.

// max_concurrent_subagents (D3) — the host's simultaneous-live-subagent pool
// ceiling. null = the host SELF-MANAGES a bounded pool (claude/codex queue and
// drain excess spawns at their own rate), so the in-flight bound is the operator's
// max_concurrent_evaluators plus C5's spawn budget, not a brain-imposed number.
// A finite value (non-nesting/unknown hosts: 1) is the hard host ceiling and
// fail-closes so the orchestrator never emits a nested plan such a host can't drain.
// NS-7 — one registry-owned identity pair for the Claude nesting edge. The
// wave root is the only spawn-capable role; every emitted leaf is dispatched
// as the distinct child role so its generated frontmatter can subtract spawn
// and settlement authority before the child starts. All plan, handoff, hook,
// and completion consumers import these identities instead of maintaining
// string aliases.
const FANOUT_ROLE_REGISTRY = Object.freeze({
  root: Object.freeze({
    role_id: "evaluator-fanout",
    subagent_type: "evaluator-fanout",
    spawn_capable: true,
  }),
  child: Object.freeze({
    role_id: "evaluator-fanout-child",
    subagent_type: "evaluator-fanout-child",
    spawn_capable: false,
    remaining_depth: 0,
  }),
});

const HOST_NESTING_CAPABILITIES = Object.freeze({
  claude: Object.freeze({
    host: "claude",
    supports_nesting: true,
    nesting_mechanism: "agent_team_sync_subagent",
    max_native_depth: 2,
    max_concurrent_subagents: null,
    minimum_host_version: "2.1.172",
    runtime_enablement: Object.freeze({
      env_var: "CLAUDE_CODE_EXPERIMENTAL_AGENT_TEAMS",
      enabled_value: "1",
    }),
  }),
  codex: Object.freeze({
    host: "codex",
    supports_nesting: true,
    nesting_mechanism: "codex_agents_max_depth",
    max_native_depth: null,
    max_concurrent_subagents: null,
    minimum_host_version: null,
    runtime_enablement: null,
  }),
  kimi: Object.freeze({
    host: "kimi",
    supports_nesting: false,
    nesting_mechanism: "none",
    max_native_depth: 1,
    max_concurrent_subagents: 1,
    minimum_host_version: null,
    runtime_enablement: null,
  }),
  "generic-mcp": Object.freeze({
    host: "generic-mcp",
    supports_nesting: false,
    nesting_mechanism: "none",
    max_native_depth: 1,
    max_concurrent_subagents: 1,
    minimum_host_version: null,
    runtime_enablement: null,
  }),
});

const FALLBACK_CAPABILITY = Object.freeze({
  host: "unknown",
  supports_nesting: false,
  nesting_mechanism: "none",
  max_native_depth: 1,
  max_concurrent_subagents: 1,
  minimum_host_version: null,
  runtime_enablement: null,
});

function nestingCapabilityForHost(hostId) {
  if (typeof hostId !== "string" || hostId.length === 0) return FALLBACK_CAPABILITY;
  return HOST_NESTING_CAPABILITIES[hostId] || FALLBACK_CAPABILITY;
}

// NS-3 — runtimeNestingEnabledForHost is the registry-driven host feature gate. A host may
// advertise a supported topology while still requiring an explicit runtime
// opt-in. Unknown/non-nesting hosts fail closed. Values are exact after trimming:
// Claude's documented gate is `=1`; truthy aliases such as `true` do not enable it.
function runtimeNestingEnabledForHost(hostId, env = process.env) {
  const capability = nestingCapabilityForHost(hostId);
  if (!capability.supports_nesting) return false;
  const gate = capability.runtime_enablement;
  if (!gate) return true;
  const rawValue = env && env[gate.env_var];
  return typeof rawValue === "string" && rawValue.trim() === gate.enabled_value;
}

// hostPoolCeiling (D3) — the host's concurrent-subagent pool ceiling, or null when
// the host self-manages a bounded pool (claude/codex). A finite value (1 for
// non-nesting/unknown hosts) fail-closes the in-flight accounting (D4) so the
// orchestrator never emits more concurrent nested work than the host can drain.
function hostPoolCeiling(hostId) {
  return nestingCapabilityForHost(hostId).max_concurrent_subagents ?? null;
}

// effectiveConcurrencyCap (D4) — the in-flight cap the orchestrator may run across
// BOTH the wave-phase nested fan-out AND the closure-phase cell floor. They share
// ONE host pool through the single max_concurrent_evaluators knob (D2 routes the
// cell-floor capacity through it), so the in-flight total is bounded by this one
// number. A host that self-manages its pool (null ceiling: claude/codex) queues and
// drains excess, so the operator's request governs unbounded by a brain number
// (null request => null, the wave-planner's existing default). A finite-ceiling host
// caps the request so the orchestrator never oversubscribes a pool it cannot drain.
function effectiveConcurrencyCap(maxConcurrentEvaluators, hostId) {
  const requested = Number.isInteger(maxConcurrentEvaluators) && maxConcurrentEvaluators >= 1
    ? maxConcurrentEvaluators
    : null;
  const ceiling = hostPoolCeiling(hostId);
  if (ceiling == null) return requested;
  return requested == null ? ceiling : Math.min(requested, ceiling);
}

// effectiveSpawnDepth — clamp the operator's queue-policy max_spawn_depth by
// what the host actually supports. Returns an integer >= 1.
//   - host doesn't support nesting          -> 1 (leaf workers; fan-out flat).
//   - host runtime gate is disabled         -> 1 (Claude agent teams default).
//   - host has a fixed ceiling (claude: 2)  -> min(policyDepth, ceiling).
//   - host ceiling unknown/null (codex)     -> policyDepth as given.
function effectiveSpawnDepth(policyDepth, hostId, env = process.env) {
  const cap = nestingCapabilityForHost(hostId);
  const depth = Number.isInteger(policyDepth) && policyDepth >= 1 ? policyDepth : 1;
  if (!runtimeNestingEnabledForHost(hostId, env)) return 1;
  if (Number.isInteger(cap.max_native_depth) && cap.max_native_depth >= 1) {
    return Math.min(depth, cap.max_native_depth);
  }
  return depth;
}

// worstCaseTreeSize — the worst-case number of descendants a single root spawns
// when it fans out `branching` children per level for `remainingDepth` levels:
// branching + branching^2 + ... + branching^remainingDepth. This is the depth-1
// budget-ALLOCATION heuristic (per CN Step B): the share of the session spawn
// budget a single root may consume. It is NOT an enforced tree cap — the deeper
// levels are detective (validateSpawnFanout at finalize + the host pool). PURE.
function worstCaseTreeSize(branching, remainingDepth) {
  const b = Number.isInteger(branching) && branching > 0 ? branching : 0;
  const R = Number.isInteger(remainingDepth) && remainingDepth > 0 ? remainingDepth : 0;
  if (b === 0 || R === 0) return 0;
  let total = 0;
  let level = 1;
  for (let k = 1; k <= R; k++) {
    level *= b;
    total += level;
    if (total > Number.MAX_SAFE_INTEGER) return Number.MAX_SAFE_INTEGER;
  }
  return total;
}

// maxBranchingForBudget — the largest branching factor <= hardCap whose worst-case
// tree fits `budget`. Returns hardCap when budget is null/Infinity (default-off, no
// governor) or remainingDepth is 0 (a leaf — no fan-out levels). Returns 0 when even
// branching=1 overflows the budget (the root degrades to a leaf — the preventive
// breaker). This is the read-path width bound: the depth-1 plan's worst-case
// allocation is held within the remaining session spawn budget. PURE.
function maxBranchingForBudget(remainingDepth, budget, hardCap) {
  const cap = Number.isInteger(hardCap) && hardCap > 0 ? hardCap : 0;
  if (cap === 0) return 0;
  const R = Number.isInteger(remainingDepth) && remainingDepth > 0 ? remainingDepth : 0;
  if (R === 0) return cap;
  if (budget == null || !Number.isFinite(budget)) return cap;
  let best = 0;
  for (let b = 1; b <= cap; b++) {
    if (worstCaseTreeSize(b, R) <= budget) best = b;
    else break;
  }
  return best;
}

// NS-4 — validateSpawnFanout — detective bound on actuated fan-out. Given the children
// an agent reports it spawned and the budget it was handed, return
// { ok, violations[] }. PURE. This mirrors the existing finalize-node
// `tool_constraint_violation` pattern: a witness check over SELF-REPORTED data,
// so it bounds an honest agent, not a malicious one. Hard prevention (a
// PreToolUse intercept on the host Agent/Task tool) is a separate, host-side
// control. Step B wires this into the TaskGraph finalize path and the
// evaluator SubagentStop validator.
//
// budget: { remaining_depth, max_children, child_type_allowlist?,
//           total_spawned?, max_total_spawned_agents? }
// reportedChildren: array of { subagent_type } (or bare subagent_type strings).
function validateSpawnFanout(reportedChildren, budget) {
  const violations = [];
  const children = Array.isArray(reportedChildren) ? reportedChildren : [];
  const b = budget && typeof budget === "object" ? budget : {};
  const maxChildren = Number.isInteger(b.max_children) ? b.max_children : 0;
  const remainingDepth = Number.isInteger(b.remaining_depth) ? b.remaining_depth : 0;
  const allowlist = Array.isArray(b.child_type_allowlist) ? new Set(b.child_type_allowlist) : null;

  if (remainingDepth <= 0 && children.length > 0) {
    violations.push(
      `spawned ${children.length} child(ren) at depth budget 0 — a leaf evaluator must not fan out`,
    );
  }
  if (children.length > maxChildren) {
    violations.push(
      `spawned ${children.length} children exceeds max_children budget ${maxChildren}`,
    );
  }
  // 4th leg (CN Step B) — the session-wide spawn budget. total_spawned is the
  // ledger count already handed out; a plan that would push the running total past
  // max_total_spawned_agents is a budget violation. Null max => no governor (default-off).
  const totalSpawned = Number.isInteger(b.total_spawned) ? b.total_spawned : 0;
  const maxTotal = Number.isInteger(b.max_total_spawned_agents) ? b.max_total_spawned_agents : null;
  if (maxTotal != null && totalSpawned + children.length > maxTotal) {
    violations.push(
      `session spawn total ${totalSpawned + children.length} exceeds max_total_spawned_agents ${maxTotal}`,
    );
  }
  if (allowlist) {
    for (const child of children) {
      const type = child && typeof child === "object" ? child.subagent_type : child;
      if (typeof type === "string" && type.length > 0 && !allowlist.has(type)) {
        violations.push(`child subagent_type "${type}" is not in the child_type_allowlist`);
      }
    }
  }
  return { ok: violations.length === 0, violations };
}

module.exports = {
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
};
