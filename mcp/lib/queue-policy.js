"use strict";

const fs = require("fs");
const {
  assertBoolean,
  assertEnumValue,
  assertInteger,
  assertNonEmptyString,
} = require("./validation.js");
const {
  normalizePositiveInteger,
  writeJsonDocument,
} = require("./fabric-common.js");
const {
  normalizeTaskLens,
} = require("./task-lenses.js");
const {
  TARGET_CLASS_VALUES,
} = require("./target-classes.js");
const {
  DEFAULT_MAX_TOTAL_SEED_PRODUCERS,
  DEFAULT_SEED_PRODUCER_PER_PASS_CAP,
  DEFAULT_PER_EXPANDER_LINKED_ADDRESS_CAP,
} = require("./constants.js");

const TASK_PRIORITY_VALUES = Object.freeze(["critical", "high", "medium", "low"]);
const QUEUE_STATUS_VALUES = Object.freeze(["queued", "assigned", "running", "blocked", "closed", "dismissed"]);

const DEFAULT_WAVE_TASK_BUDGET = Object.freeze({
  max_steps: 6,
  max_context_tokens: 24000,
});

const DEFAULT_QUEUE_POLICY = Object.freeze({
  version: 1,
  // WIDTH/PARALLELISM knobs below are CAPS, not targets: the actual wave is
  // min(candidate surfaces, cap), so on a small target the run stays small. The
  // cross-role fan-out default RAISES these caps so width reaches the real
  // surface/cell count without an artificial throttle; the in-flight host-pool
  // cap (max_concurrent_evaluators) is the sized peak-load safety knob, and the
  // lifetime governor (max_total_spawned_agents) stays null = unbounded fixpoint
  // so coverage is never bounded. An operator restores the old conservative
  // profile in one bob_set_queue_policy call via LEAN_PROFILE below.
  max_parallel_tasks: 128,
  priority_order: ["critical", "high", "medium", "low"],
  stale_after_ms: 24 * 60 * 60 * 1000,
  close_blocked_on_freeze: false,
  // Route high-value (id-bearing) web surfaces to the spawn-capable web_fanout variant so the
  // (bug_class × auth) child fan-out fires (default ON; operators set false to keep flat routing).
  route_high_value_to_fanout: true,
  // Also route HIGH-priority (non-id-bearing) web surfaces to fanout — opt-in, since priority is
  // an agent-writable RANK not a depth signal.
  web_fanout_on_high_priority: false,
  standard_wave_target: 64,
  standard_wave_max: 128,
  deep_wave_target: 64,
  deep_wave_max: 128,
  // IN-FLIGHT axis. The bounded-concurrency cap on the number of evaluators
  // running AT ONCE, independent of per-wave target/max. This is the real safety
  // knob for lifting width: it bounds peak concurrent load on the host pool, not
  // the lifetime total. When set, planNextWave clamps BOTH the effective target
  // and the effective max to this value before selecting assignments, so the cap
  // is enforced regardless of bucket overflow rules; the per-wave clamp plus
  // sequential wave settle bind concurrency across waves. It does NOT bound the
  // cumulative number of agents a session may ever spawn — that LIFETIME axis is
  // max_total_spawned_agents below. Sized to 128: the in-flight pool is shared by
  // wave nesting and the cell floor, and effectiveConcurrencyCap re-clamps it per
  // host (claude/codex self-manage; finite-pool hosts cap to their ceiling).
  max_concurrent_evaluators: 128,
  default_wave_task_lens: "surface_scout",
  default_wave_task_budget: { ...DEFAULT_WAVE_TASK_BUDGET },
  // Y.3 (D16) — operator-extensible friction scanners. Default empty;
  // bob_set_friction_scanners persists additions here. Default registry of
  // closed-prefix scanners lives in `mcp/lib/friction-scanners.js` (Y.6) and
  // is unioned with this list at scan time. Order-preserving.
  friction_scanners: [],
  // Y.6 (Y-D5 + Y-D9) — Friction-to-Hypothesis promotion threshold.
  // bob_propose_friction_promotion uses this as the default
  // min_frictions when the caller does not pass min_frictions. Per-call
  // override is allowed; the policy is the operator-tunable floor.
  friction_promotion_threshold: 2,
  // Y.6 (Y-D9 rev 4) — default target_class threaded into Surface/Claim
  // brief derivation by Y.5 wave-scheduler when the session metadata
  // does not declare one. null leaves derivation target-class-agnostic.
  target_class_default: null,
  // Y.6 (Y-D9 rev 4) — subdomain-enumeration circuit-breaker threshold
  // placeholder. The Y.7 scanner family will consume this when an
  // operator dials in a per-target ceiling on synthetic subdomain
  // enumeration.
  subdomain_enum_circuit_breaker_threshold: null,
  // Y.6 (Y-D9 rev 4.1 defect 1) — producer-side rationale enforcement
  // toggle. When TRUE, bob_record_surface_leads (Y.12) requires a
  // rationale per lead AND the Y.7 silent_lead_threshold_drop scanner
  // sets rationale_required_but_missing: true on missing-rationale
  // leads. Default FALSE preserves Y.2-shipped surface-leads recording
  // behavior; operator opt-in via bob_set_queue_policy.
  lead_rationale_required_when_below_threshold: false,
  // CB-C1 — belief-assisted scheduler scoring is default-ON and advisory-when-on.
  // The wave planner reads advisory belief rankings and residual priority hints,
  // then feeds their score through the existing priority/ranking path. The mode
  // only ever REORDERS candidates within a single priority band — it never crosses
  // a band, never drops or adds a node, and never gates closure, verdict, or claim.
  // When no belief signals are fed, the belief map is empty and the ordering is
  // byte-identical to the no-belief path, so the advisory engages only once executed
  // outcomes feed signals. An explicit `false` from an operator disables it per
  // session (the assertBoolean fallback only applies to null inputs).
  belief_assisted_priority_enabled: true,
  belief_assisted_priority_seed: "belief-scheduler-priority",
  belief_assisted_priority_rank_limit: 25,
  // E2 — residual-anomaly depth trigger is default-ON. The cell-floor producer
  // re-proposes covered cells on residual-flagged surfaces as Tier-2 depth
  // re-probes (advisory deepening dispatched after all Tier-1 breadth). Default-ON:
  // residual flags advisory Tier-2 re-probes dispatched after all Tier-1 breadth;
  // a Tier-2 re-probe never blocks closure (the gate counts only the Tier-1 floor).
  residual_depth_reprobe_enabled: true,
  // CN (coverage-nesting) — MCP-owned bound on evaluator fan-out. The brain
  // owns the decomposition decision (which
  // (bug_class x auth_role) child cells to probe) and the budget; the host
  // CLI is the muscle (one teammate->subagent level on current Claude, host-
  // configured nesting on Codex, flat extra wave assignments on Kimi/generic).
  // `max_spawn_depth` counts evaluator spawn
  // levels below the orchestrator: 1 = flat topology (per-surface evaluators
  // are leaves, NO fan-out); 2 lets a per-surface evaluator spawn one level of
  // child sub-evaluators; etc. The cross-role fan-out default requests depth 3;
  // Claude's current flat-team adapter clamps that to depth 2 only when its
  // experimental agent-teams runtime flag is explicitly enabled, so a per-surface
  // evaluator-fanout can spawn one level of (bug_class x auth_role) child cells.
  // Default Claude (flag absent) clamps to depth 1 and stays flat.
  // The per-host nesting ceiling
  // further clamps this via the adapter capability descriptor. Default Claude
  // (agent-teams flag absent) and non-nesting hosts degrade depth to 1, so the
  // requested default fans deep only on an explicitly enabled capable host.
  // `max_spawn_children` caps the child cells a single fan-out plan may
  // mint (64 = the normalizeQueuePolicy max, so an operator can't be throttled
  // below the real cell count). LEAN_PROFILE below restores depth 1 / children 8.
  max_spawn_depth: 3,
  max_spawn_children: 64,
  // LIFETIME axis. The session-wide COST ceiling on the cumulative number of
  // agents a session may EVER spawn — wave-evaluator roots, their nested
  // descendants, AND closure cells all draw down this one budget through the
  // spawn-ledger, so it binds ACROSS waves, nesting levels, and drain cycles (not
  // per-wave). This is the operator's total-cost limit, distinct from the
  // in-flight peak cap (max_concurrent_evaluators above). When the budget is fully
  // reserved but open surfaces or cells remain, the scheduler STOPS and reports a
  // coverage gap naming the uncovered work (decision spawn_budget_exhausted /
  // selection coverage_gap) — RANK != BOUND: it never silently drops a surface and
  // never over-spawns past the ceiling. null = unbounded = fixpoint; when set, the
  // MCP plan emission also bounds each root's worst-case fan-out tree so nested
  // spawns stay within budget. Detective backstop is validateSpawnFanout at
  // finalize + the host concurrent-subagent pool.
  // CROSS-ROLE FAN-OUT default keeps this null on purpose: the default RAISES
  // WIDTH (depth, wave caps, in-flight cap above) WITHOUT a COVERAGE CAP. A finite
  // lifetime default would BOUND coverage on a big target — a bounded-away surface
  // is a severed chain link — so the default drains the cell floor to fixpoint and
  // the in-flight cap is the only sized default safety knob (it bounds PEAK load,
  // never TOTAL coverage). An operator who wants a lifetime cost ceiling sets this
  // explicitly; the scheduler then STOPS+reports the coverage gap on exhaustion.
  // normalizeQueuePolicy does NOT auto-fill a coverage-bounding governor for this
  // shipped default (the auto-fill compares against CONSERVATIVE_WIDTH_BASELINE and
  // exempts the byte-equal default); raising a knob ABOVE the default re-arms it.
  // NS-5 — RANK != BOUND: the shipped default keeps this null (unbounded fixpoint,
  // no coverage cap); the off-path floor is one lean override away.
  max_total_spawned_agents: null,
  // Y.10 (Y-D12 / Y-P12 / D6 + D14) — operator attestation that the
  // listed partial surfaces are acknowledged and may pass the
  // OPEN_FRONTIER -> CLAIM_FREEZE runtime gate. Each entry is a
  // {surface_id, attestation_token, rationale?} object. The runtime
  // gate consults the latest merged wave's partial_surface_ids
  // (via mcp/lib/scheduler-preconditions.js partial_surfaces_drained)
  // and intersects them with the surface_ids in this list; a surface
  // is gated until acknowledged. The attestation_token is matched
  // against the operator nonce at ~/.bob/session-cap when that file
  // exists (mode 0600 enforced); when the file is absent the token
  // must still be a non-empty string and is recorded for audit.
  partial_surface_advance_acknowledgements: [],
  // OD1 seed-producer governors. The per-pass cap and the per-expander
  // linked-address cap are the LOAD-BEARING, MCP-enforced, NON-null fan-out
  // bounds: they cap how many seed producers a single pass may mint and how many
  // linked addresses one expander may follow, so they are the primary throttle on
  // the cell-floor materializer's seed expansion. The 1024 max_total_seed_producers
  // is an OD1 lifetime BACKSTOP only — a last-resort cumulative ceiling, never the
  // primary throttle. These fields are DECLARED here for sibling nodes to consume;
  // this node does not wire them into any producer.
  max_total_seed_producers: DEFAULT_MAX_TOTAL_SEED_PRODUCERS,
  seed_producer_per_pass_cap: DEFAULT_SEED_PRODUCER_PER_PASS_CAP,
  per_expander_linked_address_cap: DEFAULT_PER_EXPANDER_LINKED_ADDRESS_CAP,
  // OD4 linked-contract recursion depth governor. Bounds how deep the emergent
  // sc_address_expander recursion descends a contract lineage: a producer_key
  // whose proposed depth exceeds this value is NOT proposed and is REPORTED as a
  // linked_contract_depth_capped gap (RANK != BOUND — named by contract, never a
  // silent drop), so the cap is non-blocking. depth 0 = no recursion is
  // representable. The literal 3 mirrors the seed-side default in
  // init-contract-session.js (duplicated rather than shared because constants.js
  // is outside this field's wiring scope).
  linked_contract_depth: 3,
});

const FRICTION_KIND_VALUES = Object.freeze(["tool_absent", "tool_inadequate"]);

function normalizeFrictionScanner(value, fieldName) {
  if (value == null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${fieldName} must be an object`);
  }
  const name = typeof value.name === "string" ? value.name.trim() : "";
  if (!name) throw new Error(`${fieldName}.name must be a non-empty string`);
  if (name.length > 64) throw new Error(`${fieldName}.name must be at most 64 characters`);
  if (!/^[a-z][a-z0-9_]*$/.test(name)) {
    throw new Error(`${fieldName}.name must match ^[a-z][a-z0-9_]*$`);
  }
  const pattern = typeof value.pattern === "string" ? value.pattern : "";
  if (!pattern) throw new Error(`${fieldName}.pattern must be a non-empty string`);
  if (pattern.length > 256) throw new Error(`${fieldName}.pattern must be at most 256 characters`);
  try {
    // Validate the regex compiles. Stored as string so it survives JSON
    // round-trips; consumed via `new RegExp(stored)`.
    new RegExp(pattern);
  } catch (error) {
    throw new Error(`${fieldName}.pattern must be a valid regex: ${error.message || String(error)}`);
  }
  const fallbackUsed = typeof value.fallback_used === "string" ? value.fallback_used.trim() : "";
  if (!fallbackUsed) throw new Error(`${fieldName}.fallback_used must be a non-empty string`);
  if (fallbackUsed.length > 64) throw new Error(`${fieldName}.fallback_used must be at most 64 characters`);
  const frictionKind = typeof value.friction_kind === "string" ? value.friction_kind : "tool_absent";
  if (!FRICTION_KIND_VALUES.includes(frictionKind)) {
    throw new Error(`${fieldName}.friction_kind must be one of ${FRICTION_KIND_VALUES.join(", ")}`);
  }
  return Object.freeze({ name, pattern, fallback_used: fallbackUsed, friction_kind: frictionKind });
}

function normalizePartialSurfaceAcknowledgement(value, fieldName) {
  if (value == null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${fieldName} must be an object`);
  }
  const surfaceId = typeof value.surface_id === "string" ? value.surface_id.trim() : "";
  if (!surfaceId) throw new Error(`${fieldName}.surface_id must be a non-empty string`);
  if (surfaceId.length > 128) throw new Error(`${fieldName}.surface_id must be at most 128 characters`);
  const attestationToken = typeof value.attestation_token === "string" ? value.attestation_token.trim() : "";
  if (!attestationToken) throw new Error(`${fieldName}.attestation_token must be a non-empty string`);
  if (attestationToken.length > 256) throw new Error(`${fieldName}.attestation_token must be at most 256 characters`);
  const result = { surface_id: surfaceId, attestation_token: attestationToken };
  if (value.rationale != null) {
    if (typeof value.rationale !== "string") {
      throw new Error(`${fieldName}.rationale must be a string when provided`);
    }
    const rationale = value.rationale.trim();
    if (rationale.length > 512) throw new Error(`${fieldName}.rationale must be at most 512 characters`);
    if (rationale) result.rationale = rationale;
  }
  return Object.freeze(result);
}

function normalizePartialSurfaceAcknowledgements(value, fieldName = "partial_surface_advance_acknowledgements") {
  if (value == null) return [];
  if (!Array.isArray(value)) throw new Error(`${fieldName} must be an array`);
  if (value.length > 64) throw new Error(`${fieldName} must contain at most 64 entries`);
  const seen = new Set();
  const out = [];
  for (let i = 0; i < value.length; i += 1) {
    const entry = normalizePartialSurfaceAcknowledgement(value[i], `${fieldName}[${i}]`);
    if (seen.has(entry.surface_id)) {
      throw new Error(`${fieldName} contains duplicate surface_id ${entry.surface_id}`);
    }
    seen.add(entry.surface_id);
    out.push(entry);
  }
  return out;
}

function normalizeFrictionScanners(value, fieldName = "friction_scanners") {
  if (value == null) return [];
  if (!Array.isArray(value)) throw new Error(`${fieldName} must be an array`);
  if (value.length > 32) throw new Error(`${fieldName} must contain at most 32 entries`);
  const seen = new Set();
  const out = [];
  for (let i = 0; i < value.length; i += 1) {
    const scanner = normalizeFrictionScanner(value[i], `${fieldName}[${i}]`);
    if (seen.has(scanner.name)) {
      throw new Error(`${fieldName} contains duplicate scanner name ${scanner.name}`);
    }
    seen.add(scanner.name);
    out.push(scanner);
  }
  return out;
}

function normalizeTaskPriority(value, fieldName = "priority") {
  return assertEnumValue(value == null ? "medium" : value, TASK_PRIORITY_VALUES, fieldName);
}

function normalizeQueueStatus(value, fieldName = "status") {
  return assertEnumValue(value == null ? "queued" : value, QUEUE_STATUS_VALUES, fieldName);
}

function normalizeWaveTaskBudget(value, fieldName = "default_wave_task_budget") {
  if (value == null) {
    return { ...DEFAULT_WAVE_TASK_BUDGET };
  }
  if (typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${fieldName} must be an object`);
  }
  const maxSteps = normalizePositiveInteger(value.max_steps, `${fieldName}.max_steps`, {
    defaultValue: DEFAULT_WAVE_TASK_BUDGET.max_steps,
  });
  const maxContextTokens = normalizePositiveInteger(value.max_context_tokens, `${fieldName}.max_context_tokens`, {
    defaultValue: DEFAULT_WAVE_TASK_BUDGET.max_context_tokens,
  });
  return { max_steps: maxSteps, max_context_tokens: maxContextTokens };
}

// CN (coverage-nesting) Step B — the generous finite ceiling for the wave-size and
// dispatch-capacity knobs, lifted from the former hard 128. The operator sets the
// width; the REAL governor is the host concurrent-subagent pool plus the spawn
// budget (max_total_spawned_agents), not this clamp. Kept finite (not Infinity) so a
// NaN/garbage override is still rejected. Shared by graph-scheduler.js (cell-floor
// dispatch capacity) and scheduler-decisions.js (max_assignments / capacity_limit).
const CLAMP_CEILING = 4096;

// CN (coverage-nesting) Step B — the safe session spawn budget applied automatically
// when an operator opts into nesting (max_spawn_depth > 1) without naming one. The
// lifted CLAMP_CEILING governs only WIDTH knobs; the spawn TREE is bounded by
// max_total_spawned_agents. Leaving it null with nesting on would make the fan-out
// ungoverned, so normalizeQueuePolicy fills it here. Matches MAX_COVERAGE_PROFILE's
// budget. depth<=1 (default-off) keeps it null => byte-identical.
const DEFAULT_NESTING_SPAWN_BUDGET = 512;

// The FROZEN conservative width/depth baseline — the old shipped-lean values the
// auto-fill governor compares against. DEFAULT_QUEUE_POLICY now ships the
// cross-role fan-out profile (depth 3, wave caps 64/128, in-flight cap 128) with
// a null lifetime governor, so the auto-fill can no longer reference the live
// default to decide "is this raised?" (the default IS raised). This frozen
// snapshot is the fixed reference: a normalized policy whose width/depth knobs
// EXCEED this baseline arms the safety governor; a policy AT OR BELOW it (the
// lean override) keeps the governor null. The shipped default exceeds this
// baseline but is exempted separately (see normalizeQueuePolicy) so its null
// governor — the unbounded fixpoint, the no-coverage-cap invariant — survives.
const CONSERVATIVE_WIDTH_BASELINE = Object.freeze({
  max_spawn_depth: 1,
  standard_wave_target: 4,
  standard_wave_max: 6,
  deep_wave_target: 6,
  deep_wave_max: 8,
  max_concurrent_evaluators: 8,
});

// CN (coverage-nesting) — the named cost-CEILINGED coverage profile. An operator
// opts into the full nested + maxed-cell-floor regime WITH a finite lifetime cost
// ceiling in ONE bob_set_queue_policy call by passing this as the policy. depth 3 +
// 64-wide fan-out, the cell floor + waves scaled past the old 128 clamp, all
// bounded by max_total_spawned_agents:512 (the governor) so the worst-case spawn
// tree fits a budget. Cross-guards (wave_max >= wave_target) are pre-satisfied.
// It differs from the shipped DEFAULT_QUEUE_POLICY ONLY by setting the lifetime
// governor to 512: the default is byte-identical on width/depth/concurrency but
// keeps the governor null (unbounded fixpoint, no coverage cap). Choose this
// profile when a total-cost ceiling is wanted; the default fans out without one.
const MAX_COVERAGE_PROFILE = Object.freeze({
  max_spawn_depth: 3,
  max_spawn_children: 64,
  max_concurrent_evaluators: 128,
  max_parallel_tasks: 128,
  max_total_spawned_agents: 512,
  standard_wave_target: 64,
  standard_wave_max: 128,
  deep_wave_target: 64,
  deep_wave_max: 128,
});

// The named LEAN profile — the inverse of MAX_COVERAGE_PROFILE. An operator opts
// OUT of cross-role fan-out in ONE bob_set_queue_policy call, restoring the old
// conservative single-recon / flat-evaluator profile: depth 1 (no nesting), the
// 4/6 standard and 6/8 deep wave caps, in-flight cap unset, and a null lifetime
// governor. normalizeQueuePolicy(LEAN_PROFILE) is byte-identical on width/depth to
// the old shipped conservative run and keeps the governor null (the lean width is
// at/below CONSERVATIVE_WIDTH_BASELINE, so the auto-fill does not arm). The flip
// changed the DEFAULT, not the FLOOR — lean mode is one override away.
const LEAN_PROFILE = Object.freeze({
  max_spawn_depth: 1,
  max_spawn_children: 8,
  max_concurrent_evaluators: null,
  max_parallel_tasks: 4,
  max_total_spawned_agents: null,
  standard_wave_target: 4,
  standard_wave_max: 6,
  deep_wave_target: 6,
  deep_wave_max: 8,
});

// True when a normalized policy's width/depth knobs are byte-equal to the shipped
// DEFAULT_QUEUE_POLICY — i.e. the operator passed NO width/depth override and is
// running the cross-role fan-out default as shipped. This is the auto-fill exempt
// case: the shipped default's raised width is deliberate and stays governor-null
// (the unbounded fixpoint). Any single knob differing from the default falls
// through to the baseline comparison, so an operator who raises a knob ABOVE the
// default still arms the safety governor.
function widthDepthMatchesShippedDefault(policy) {
  return (
    policy.max_spawn_depth === DEFAULT_QUEUE_POLICY.max_spawn_depth &&
    policy.standard_wave_target === DEFAULT_QUEUE_POLICY.standard_wave_target &&
    policy.standard_wave_max === DEFAULT_QUEUE_POLICY.standard_wave_max &&
    policy.deep_wave_target === DEFAULT_QUEUE_POLICY.deep_wave_target &&
    policy.deep_wave_max === DEFAULT_QUEUE_POLICY.deep_wave_max &&
    policy.max_concurrent_evaluators === DEFAULT_QUEUE_POLICY.max_concurrent_evaluators
  );
}

function normalizeQueuePolicy(input = {}) {
  const policy = {
    version: 1,
    max_parallel_tasks: normalizePositiveInteger(input.max_parallel_tasks, "max_parallel_tasks", {
      defaultValue: DEFAULT_QUEUE_POLICY.max_parallel_tasks,
      max: CLAMP_CEILING,
    }),
    priority_order: Array.isArray(input.priority_order) && input.priority_order.length > 0
      ? input.priority_order.map((priority, index) => normalizeTaskPriority(priority, `priority_order[${index}]`))
      : DEFAULT_QUEUE_POLICY.priority_order.slice(),
    stale_after_ms: normalizePositiveInteger(input.stale_after_ms, "stale_after_ms", {
      defaultValue: DEFAULT_QUEUE_POLICY.stale_after_ms,
    }),
    close_blocked_on_freeze: input.close_blocked_on_freeze == null
      ? DEFAULT_QUEUE_POLICY.close_blocked_on_freeze
      : assertBoolean(input.close_blocked_on_freeze, "close_blocked_on_freeze"),
    route_high_value_to_fanout: input.route_high_value_to_fanout == null
      ? DEFAULT_QUEUE_POLICY.route_high_value_to_fanout
      : assertBoolean(input.route_high_value_to_fanout, "route_high_value_to_fanout"),
    web_fanout_on_high_priority: input.web_fanout_on_high_priority == null
      ? DEFAULT_QUEUE_POLICY.web_fanout_on_high_priority
      : assertBoolean(input.web_fanout_on_high_priority, "web_fanout_on_high_priority"),
    standard_wave_target: normalizePositiveInteger(input.standard_wave_target, "standard_wave_target", {
      defaultValue: DEFAULT_QUEUE_POLICY.standard_wave_target,
      max: CLAMP_CEILING,
    }),
    standard_wave_max: normalizePositiveInteger(input.standard_wave_max, "standard_wave_max", {
      defaultValue: DEFAULT_QUEUE_POLICY.standard_wave_max,
      max: CLAMP_CEILING,
    }),
    deep_wave_target: normalizePositiveInteger(input.deep_wave_target, "deep_wave_target", {
      defaultValue: DEFAULT_QUEUE_POLICY.deep_wave_target,
      max: CLAMP_CEILING,
    }),
    deep_wave_max: normalizePositiveInteger(input.deep_wave_max, "deep_wave_max", {
      defaultValue: DEFAULT_QUEUE_POLICY.deep_wave_max,
      max: CLAMP_CEILING,
    }),
    default_wave_task_lens: input.default_wave_task_lens == null
      ? DEFAULT_QUEUE_POLICY.default_wave_task_lens
      : normalizeTaskLens(input.default_wave_task_lens, "default_wave_task_lens"),
    default_wave_task_budget: normalizeWaveTaskBudget(input.default_wave_task_budget),
    friction_scanners: normalizeFrictionScanners(input.friction_scanners),
    friction_promotion_threshold: normalizePositiveInteger(
      input.friction_promotion_threshold,
      "friction_promotion_threshold",
      {
        defaultValue: DEFAULT_QUEUE_POLICY.friction_promotion_threshold,
        max: 128,
      },
    ),
    target_class_default: input.target_class_default == null
      ? DEFAULT_QUEUE_POLICY.target_class_default
      : assertEnumValue(input.target_class_default, TARGET_CLASS_VALUES, "target_class_default"),
    subdomain_enum_circuit_breaker_threshold:
      input.subdomain_enum_circuit_breaker_threshold == null
        ? DEFAULT_QUEUE_POLICY.subdomain_enum_circuit_breaker_threshold
        : normalizePositiveInteger(
          input.subdomain_enum_circuit_breaker_threshold,
          "subdomain_enum_circuit_breaker_threshold",
          { max: 65536 },
        ),
    // The in-flight cap can be EXPLICITLY cleared to null. Now that the shipped
    // default is a sized 128, an operator (e.g. LEAN_PROFILE) restoring the old
    // conservative "no in-flight cap, waves governed solely by the wave caps" must
    // be able to request null and get null back, distinct from omitting the key
    // (which inherits the sized default). An explicitly-present null key resolves
    // to null; an absent key inherits the default; any other value is normalized.
    max_concurrent_evaluators:
      input.max_concurrent_evaluators == null
        ? (Object.prototype.hasOwnProperty.call(input, "max_concurrent_evaluators")
          ? null
          : DEFAULT_QUEUE_POLICY.max_concurrent_evaluators)
        : normalizePositiveInteger(
          input.max_concurrent_evaluators,
          "max_concurrent_evaluators",
          { max: CLAMP_CEILING },
        ),
    lead_rationale_required_when_below_threshold:
      input.lead_rationale_required_when_below_threshold == null
        ? DEFAULT_QUEUE_POLICY.lead_rationale_required_when_below_threshold
        : assertBoolean(
          input.lead_rationale_required_when_below_threshold,
          "lead_rationale_required_when_below_threshold",
        ),
    belief_assisted_priority_enabled:
      input.belief_assisted_priority_enabled == null
        ? DEFAULT_QUEUE_POLICY.belief_assisted_priority_enabled
        : assertBoolean(
          input.belief_assisted_priority_enabled,
          "belief_assisted_priority_enabled",
        ),
    residual_depth_reprobe_enabled:
      input.residual_depth_reprobe_enabled == null
        ? DEFAULT_QUEUE_POLICY.residual_depth_reprobe_enabled
        : assertBoolean(
          input.residual_depth_reprobe_enabled,
          "residual_depth_reprobe_enabled",
        ),
    belief_assisted_priority_seed:
      input.belief_assisted_priority_seed == null
        ? DEFAULT_QUEUE_POLICY.belief_assisted_priority_seed
        : assertNonEmptyString(input.belief_assisted_priority_seed, "belief_assisted_priority_seed"),
    belief_assisted_priority_rank_limit:
      input.belief_assisted_priority_rank_limit == null
        ? DEFAULT_QUEUE_POLICY.belief_assisted_priority_rank_limit
        : normalizePositiveInteger(
          input.belief_assisted_priority_rank_limit,
          "belief_assisted_priority_rank_limit",
          { max: 100 },
        ),
    max_spawn_depth:
      input.max_spawn_depth == null
        ? DEFAULT_QUEUE_POLICY.max_spawn_depth
        : normalizePositiveInteger(input.max_spawn_depth, "max_spawn_depth", { max: 8 }),
    max_spawn_children:
      input.max_spawn_children == null
        ? DEFAULT_QUEUE_POLICY.max_spawn_children
        : normalizePositiveInteger(input.max_spawn_children, "max_spawn_children", { max: 64 }),
    max_total_spawned_agents:
      input.max_total_spawned_agents == null
        ? DEFAULT_QUEUE_POLICY.max_total_spawned_agents
        : normalizePositiveInteger(input.max_total_spawned_agents, "max_total_spawned_agents", { max: 4096 }),
    partial_surface_advance_acknowledgements:
      normalizePartialSurfaceAcknowledgements(input.partial_surface_advance_acknowledgements),
    // OD1 seed-producer governors. The per-pass + per-expander linked-address
    // caps use the NON-clearable `== null ? default` idiom (no explicit-null ->
    // null branch), so an explicit null falls back to the default and they can
    // never be cleared to null — they are the real MCP-enforced fan-out bounds.
    // The lifetime total is the same shape but is only a backstop, never the
    // primary throttle. All three MUST be rebuilt here: normalize does not spread
    // DEFAULT_QUEUE_POLICY, so a default-only field would be silently dropped.
    max_total_seed_producers:
      input.max_total_seed_producers == null
        ? DEFAULT_QUEUE_POLICY.max_total_seed_producers
        : normalizePositiveInteger(input.max_total_seed_producers, "max_total_seed_producers", { max: CLAMP_CEILING }),
    seed_producer_per_pass_cap:
      input.seed_producer_per_pass_cap == null
        ? DEFAULT_QUEUE_POLICY.seed_producer_per_pass_cap
        : normalizePositiveInteger(input.seed_producer_per_pass_cap, "seed_producer_per_pass_cap", { max: CLAMP_CEILING }),
    per_expander_linked_address_cap:
      input.per_expander_linked_address_cap == null
        ? DEFAULT_QUEUE_POLICY.per_expander_linked_address_cap
        : normalizePositiveInteger(input.per_expander_linked_address_cap, "per_expander_linked_address_cap", { max: CLAMP_CEILING }),
    // OD4 depth governor. Rebuilt here alongside the OD1 seed governors so a
    // default-only field is not silently dropped (normalize does not spread
    // DEFAULT_QUEUE_POLICY). assertInteger (not normalizePositiveInteger) is used
    // directly because depth 0 = no recursion must be representable; the field is
    // NON-clearable (an explicit null falls back to the default and it can never
    // resolve to null), exactly like the OD1 seed governors above.
    linked_contract_depth:
      input.linked_contract_depth == null
        ? DEFAULT_QUEUE_POLICY.linked_contract_depth
        : assertInteger(input.linked_contract_depth, "linked_contract_depth", { min: 0, max: 32 }),
  };
  policy.priority_order = Array.from(new Set(policy.priority_order));
  // The auto-fill safety governor — RANK != BOUND. Lifting WIDTH (wave size,
  // concurrency) or DEPTH (nesting) without a sized lifetime governor would expose
  // the large CLAMP_CEILING width with no binding total ceiling, so an unset
  // governor is filled with a safe budget WHENEVER the normalized width/depth knobs
  // EXCEED the frozen CONSERVATIVE_WIDTH_BASELINE. Two carve-outs keep the contract:
  //
  //   (a) The SHIPPED cross-role fan-out DEFAULT is exempt. Its width/depth knobs
  //       exceed the baseline, but when they are byte-equal to DEFAULT_QUEUE_POLICY
  //       (i.e. the operator passed NO width/depth override) the governor stays null
  //       — the unbounded fixpoint, the no-coverage-cap invariant. The default
  //       RAISES width WITHOUT a coverage cap, by design; the in-flight cap is its
  //       only sized default safety knob. Compared against the frozen baseline (NOT
  //       the live, now-raised default) so the comparison can't self-reference away.
  //
  //   (b) An EXPLICIT max_total_spawned_agents is never overridden (the field's
  //       input!=null branch above already honored it; this only fills a null one).
  //
  // Net: the shipped default keeps governor null (fixpoint); an operator who raises
  // a knob ABOVE the default gets the safety auto-fill; the lean override (width at
  // or below the baseline) stays governor-null and byte-identical to the old
  // shipped conservative run.
  if (policy.max_total_spawned_agents == null && !widthDepthMatchesShippedDefault(policy)) {
    const widthDepthRaised = (
      policy.max_spawn_depth > CONSERVATIVE_WIDTH_BASELINE.max_spawn_depth ||
      policy.standard_wave_max > CONSERVATIVE_WIDTH_BASELINE.standard_wave_max ||
      policy.standard_wave_target > CONSERVATIVE_WIDTH_BASELINE.standard_wave_target ||
      policy.deep_wave_max > CONSERVATIVE_WIDTH_BASELINE.deep_wave_max ||
      policy.deep_wave_target > CONSERVATIVE_WIDTH_BASELINE.deep_wave_target ||
      (Number.isInteger(policy.max_concurrent_evaluators) &&
        policy.max_concurrent_evaluators > CONSERVATIVE_WIDTH_BASELINE.max_concurrent_evaluators)
    );
    if (widthDepthRaised) {
      policy.max_total_spawned_agents = DEFAULT_NESTING_SPAWN_BUDGET;
    }
  }
  if (policy.standard_wave_max < policy.standard_wave_target) {
    throw new Error("standard_wave_max must be >= standard_wave_target");
  }
  if (policy.deep_wave_max < policy.deep_wave_target) {
    throw new Error("deep_wave_max must be >= deep_wave_target");
  }
  return policy;
}

// PATCH semantics for bob_set_queue_policy: read-modify-write the WHOLE persisted
// policy. normalizeQueuePolicy rebuilds a policy from its input, so writing the raw
// operator override would reset EVERY field the operator omitted
// (max_parallel_tasks, priority_order, stale_after_ms, close_blocked_on_freeze, the
// wave targets/budgets/lens, and the init-owned OD governors) back to
// DEFAULT_QUEUE_POLICY — a silent loss of the operator's persisted config. Start
// from the normalized `existing` policy and overlay ONLY the operator-supplied
// fields, so a one-field update preserves every OTHER field at its persisted value.
// An operator resets a field by setting it explicitly (least-surprise: omission
// keeps, explicit value overwrites). A field PRESENT in `input` with an explicit
// null (e.g. LEAN_PROFILE clearing max_concurrent_evaluators) is overlaid and
// normalizeQueuePolicy resolves it, so deliberate clears still work.
function mergePersistedPolicyFields(input, existing) {
  if (input == null || typeof input !== "object" || Array.isArray(input)) {
    throw new Error("policy must be an object");
  }
  if (existing == null || typeof existing !== "object" || Array.isArray(existing)) {
    return { ...input };
  }
  return { ...existing, ...input };
}

function compareQueuedTasks(a, b, policy = DEFAULT_QUEUE_POLICY) {
  const normalizedPolicy = normalizeQueuePolicy(policy);
  const priorityRank = new Map(normalizedPolicy.priority_order.map((priority, index) => [priority, index]));
  const aPriority = priorityRank.get(a.priority) ?? normalizedPolicy.priority_order.length;
  const bPriority = priorityRank.get(b.priority) ?? normalizedPolicy.priority_order.length;
  if (aPriority !== bPriority) return aPriority - bPriority;
  const aCreated = Date.parse(a.created_at || "") || 0;
  const bCreated = Date.parse(b.created_at || "") || 0;
  if (aCreated !== bCreated) return aCreated - bCreated;
  return String(a.task_id || "").localeCompare(String(b.task_id || ""));
}

function loadQueuePolicy(domain) {
  assertNonEmptyString(domain, "target_domain");
  // Require paths lazily to avoid a load-time cycle (paths.js → validation.js).
  const { queuePolicyPath } = require("./paths.js");
  const filePath = queuePolicyPath(domain);
  if (!fs.existsSync(filePath)) {
    return normalizeQueuePolicy(DEFAULT_QUEUE_POLICY);
  }
  let raw;
  try {
    raw = fs.readFileSync(filePath, "utf8");
  } catch (error) {
    throw new Error(`Failed to read queue-policy.json: ${error.message || String(error)}`);
  }
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch (error) {
    throw new Error(`Malformed queue-policy.json at ${filePath}: ${error.message || String(error)}`);
  }
  return normalizeQueuePolicy(parsed);
}

function writeQueuePolicy(domain, policy) {
  assertNonEmptyString(domain, "target_domain");
  const normalized = normalizeQueuePolicy(policy);
  const { queuePolicyPath } = require("./paths.js");
  writeJsonDocument(queuePolicyPath(domain), normalized);
  return normalized;
}

module.exports = {
  CLAMP_CEILING,
  CONSERVATIVE_WIDTH_BASELINE,
  DEFAULT_NESTING_SPAWN_BUDGET,
  LEAN_PROFILE,
  MAX_COVERAGE_PROFILE,
  DEFAULT_QUEUE_POLICY,
  DEFAULT_WAVE_TASK_BUDGET,
  FRICTION_KIND_VALUES,
  QUEUE_STATUS_VALUES,
  TASK_PRIORITY_VALUES,
  compareQueuedTasks,
  loadQueuePolicy,
  mergePersistedPolicyFields,
  normalizeFrictionScanner,
  normalizeFrictionScanners,
  normalizePartialSurfaceAcknowledgement,
  normalizePartialSurfaceAcknowledgements,
  normalizeQueuePolicy,
  normalizeQueueStatus,
  normalizeTaskPriority,
  writeQueuePolicy,
};
