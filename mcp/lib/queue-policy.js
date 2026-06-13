"use strict";

const fs = require("fs");
const {
  assertBoolean,
  assertEnumValue,
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

const TASK_PRIORITY_VALUES = Object.freeze(["critical", "high", "medium", "low"]);
const QUEUE_STATUS_VALUES = Object.freeze(["queued", "assigned", "running", "blocked", "closed", "dismissed"]);

const DEFAULT_WAVE_TASK_BUDGET = Object.freeze({
  max_steps: 6,
  max_context_tokens: 24000,
});

const DEFAULT_QUEUE_POLICY = Object.freeze({
  version: 1,
  max_parallel_tasks: 4,
  priority_order: ["critical", "high", "medium", "low"],
  stale_after_ms: 24 * 60 * 60 * 1000,
  close_blocked_on_freeze: false,
  standard_wave_target: 4,
  standard_wave_max: 6,
  deep_wave_target: 6,
  deep_wave_max: 8,
  // First-class bounded-concurrency cap on the number of evaluators in flight
  // at once, independent of per-wave target/max. When set, planNextWave clamps
  // BOTH the effective target and the effective max to this value before
  // selecting assignments, so the cap is enforced regardless of bucket overflow
  // rules. null leaves wave fan-out governed solely by the *_wave_target/max
  // fields (backward compatible — behavior is unchanged when unset).
  max_concurrent_evaluators: null,
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
  // CB-C1 — opt-in belief-assisted scheduler scoring. When enabled, the wave
  // planner reads advisory belief rankings and residual priority hints, then
  // feeds their score through the existing priority/ranking path. Default false
  // preserves the current scheduler and makes the mode disableable per session.
  belief_assisted_priority_enabled: false,
  belief_assisted_priority_seed: "belief-scheduler-priority",
  belief_assisted_priority_rank_limit: 25,
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

function normalizeQueuePolicy(input = {}) {
  const policy = {
    version: 1,
    max_parallel_tasks: normalizePositiveInteger(input.max_parallel_tasks, "max_parallel_tasks", {
      defaultValue: DEFAULT_QUEUE_POLICY.max_parallel_tasks,
      max: 128,
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
    standard_wave_target: normalizePositiveInteger(input.standard_wave_target, "standard_wave_target", {
      defaultValue: DEFAULT_QUEUE_POLICY.standard_wave_target,
      max: 128,
    }),
    standard_wave_max: normalizePositiveInteger(input.standard_wave_max, "standard_wave_max", {
      defaultValue: DEFAULT_QUEUE_POLICY.standard_wave_max,
      max: 128,
    }),
    deep_wave_target: normalizePositiveInteger(input.deep_wave_target, "deep_wave_target", {
      defaultValue: DEFAULT_QUEUE_POLICY.deep_wave_target,
      max: 128,
    }),
    deep_wave_max: normalizePositiveInteger(input.deep_wave_max, "deep_wave_max", {
      defaultValue: DEFAULT_QUEUE_POLICY.deep_wave_max,
      max: 128,
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
    max_concurrent_evaluators:
      input.max_concurrent_evaluators == null
        ? DEFAULT_QUEUE_POLICY.max_concurrent_evaluators
        : normalizePositiveInteger(
          input.max_concurrent_evaluators,
          "max_concurrent_evaluators",
          { max: 128 },
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
    partial_surface_advance_acknowledgements:
      normalizePartialSurfaceAcknowledgements(input.partial_surface_advance_acknowledgements),
  };
  policy.priority_order = Array.from(new Set(policy.priority_order));
  if (policy.standard_wave_max < policy.standard_wave_target) {
    throw new Error("standard_wave_max must be >= standard_wave_target");
  }
  if (policy.deep_wave_max < policy.deep_wave_target) {
    throw new Error("deep_wave_max must be >= deep_wave_target");
  }
  return policy;
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
  DEFAULT_QUEUE_POLICY,
  DEFAULT_WAVE_TASK_BUDGET,
  FRICTION_KIND_VALUES,
  QUEUE_STATUS_VALUES,
  TASK_PRIORITY_VALUES,
  compareQueuedTasks,
  loadQueuePolicy,
  normalizeFrictionScanner,
  normalizeFrictionScanners,
  normalizePartialSurfaceAcknowledgement,
  normalizePartialSurfaceAcknowledgements,
  normalizeQueuePolicy,
  normalizeQueueStatus,
  normalizeTaskPriority,
  writeQueuePolicy,
};
