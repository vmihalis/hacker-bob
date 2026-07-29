"use strict";

const {
  assertNonEmptyString,
} = require("../validation.js");
const {
  withSessionLock,
} = require("../storage.js");
const {
  CLAMP_CEILING,
  loadQueuePolicy,
  mergePersistedPolicyFields,
  normalizeQueuePolicy,
  writeQueuePolicy,
} = require("../queue-policy.js");

function handler(args) {
  const domain = assertNonEmptyString(args.target_domain, "target_domain");
  const policyInput = args.policy == null ? {} : args.policy;
  if (typeof policyInput !== "object" || Array.isArray(policyInput)) {
    throw new Error("policy must be an object");
  }
  // Validate the EFFECTIVE (merged) policy eagerly so a malformed policy fails
  // before the session lock is taken. Validating the raw partial in isolation is
  // WRONG for a PATCH: normalizeQueuePolicy fills every omitted field with its
  // DEFAULT, so the cross-field wave guards (standard/deep wave_max >= wave_target)
  // would see a default cross-guard partner instead of the persisted one and
  // falsely reject a legitimate one-field wave-cap update — e.g. after LEAN_PROFILE
  // persists standard_wave_target=4/standard_wave_max=6, a `{standard_wave_max: 5}`
  // partial would trip against the default target 64. Validate the same MERGE the
  // in-lock writeQueuePolicy normalizes so the pre-check accepts exactly what the
  // authoritative write accepts. This is fail-fast only; the fail-closed gate is
  // writeQueuePolicy inside the lock, which re-merges + re-normalizes under the lock
  // (an out-of-bounds field still throws here AND there).
  normalizeQueuePolicy(mergePersistedPolicyFields(policyInput, loadQueuePolicy(domain)));
  // bob_set_queue_policy is a PARTIAL update (PATCH): read-modify-write the WHOLE
  // persisted policy so a one-field update preserves every OTHER field. Without this
  // the writer's normalizeQueuePolicy would rebuild the policy from the raw operator
  // override and reset every omitted field (max_parallel_tasks, priority_order,
  // stale_after_ms, close_blocked_on_freeze, the wave targets/budgets/lens, and the
  // init-owned OD governors) back to DEFAULT_QUEUE_POLICY — a silent loss of the
  // operator's config. Load the persisted policy under the lock, overlay ONLY the
  // operator-supplied fields, and keep each unspecified field at its persisted
  // value; an operator resets a field by setting it explicitly.
  const persisted = withSessionLock(domain, () => {
    const existing = loadQueuePolicy(domain);
    const merged = mergePersistedPolicyFields(policyInput, existing);
    return writeQueuePolicy(domain, merged);
  });
  return JSON.stringify({
    version: 1,
    target_domain: domain,
    queue_policy: persisted,
  });
}

module.exports = Object.freeze({
  name: "bob_set_queue_policy",
  description:
    "Apply a PARTIAL (PATCH) QueuePolicy update for a target_domain, persisted to " +
    "~/hacker-bob-sessions/<domain>/queue-policy.json. Read-modify-writes the WHOLE " +
    "persisted policy: only the fields the operator supplies are changed, and every " +
    "omitted field keeps its persisted value (reset a field to its default by setting " +
    "it explicitly). The result is normalized via normalizeQueuePolicy and consumed by " +
    "the wave planner and scheduler. Fields include max_parallel_tasks, priority_order, " +
    "stale_after_ms, close_blocked_on_freeze, the wave targets/budgets/lens, and the " +
    "init-owned OD governors (linked_contract_depth plus the OD1 seed caps " +
    "seed_producer_per_pass_cap, per_expander_linked_address_cap, " +
    "max_total_seed_producers).",
  inputSchema: {
    type: "object",
    properties: {
      target_domain: {
        type: "string",
      },
      policy: {
        type: "object",
        description:
          "Partial or full QueuePolicy. Only the fields present here are updated; every " +
          "field the operator omits keeps its persisted value, because a partial update " +
          "read-modify-writes the WHOLE persisted policy (custom wave targets/budgets/" +
          "priority AND the init-owned OD governors all survive a one-field update). " +
          "Reset a field to its default by setting it explicitly.",
        properties: {
          max_parallel_tasks: { type: "integer" },
          priority_order: {
            type: "array",
            items: { type: "string", enum: ["critical", "high", "medium", "low"] },
          },
          stale_after_ms: { type: "integer" },
          close_blocked_on_freeze: { type: "boolean" },
          standard_wave_target: { type: "integer" },
          standard_wave_max: { type: "integer" },
          deep_wave_target: { type: "integer" },
          deep_wave_max: { type: "integer" },
          default_wave_task_lens: { type: "string" },
          default_wave_task_budget: {
            type: "object",
            properties: {
              max_steps: { type: "integer" },
              max_context_tokens: { type: "integer" },
            },
          },
          // Y.6 (Y-D5 + Y-D9) — operator-tunable knobs for the
          // friction-to-Hypothesis promotion path AND the rev-4 / rev-4.1
          // target-class + lead-rationale extensions.
          friction_promotion_threshold: { type: "integer" },
          target_class_default: {
            type: "string",
            enum: [
              "web_application",
              "smart_contract",
              "phishing_fraud",
              "mobile_app",
              "infrastructure",
              "other",
            ],
          },
          subdomain_enum_circuit_breaker_threshold: { type: "integer" },
          lead_rationale_required_when_below_threshold: { type: "boolean" },
          belief_assisted_priority_enabled: { type: "boolean" },
          belief_assisted_priority_seed: { type: "string" },
          belief_assisted_priority_rank_limit: { type: "integer" },
          // CN (coverage-nesting) — MCP-owned bounded-recursive-fan-out budget.
          // max_spawn_depth: evaluator spawn levels below the orchestrator
          // (1 = flat/no-nesting default); max_spawn_children: child cells a
          // single fan-out plan may mint. Per-host nesting ceiling clamps depth.
          max_spawn_depth: { type: "integer" },
          max_spawn_children: { type: "integer" },
          // CN Step B — max_concurrent_evaluators: the shared in-flight cap for the
          // wave path AND the cell floor (default null = unset). max_total_spawned_agents:
          // the session-wide spawn budget governor (default null = unbounded) bounding the
          // nested fan-out's worst-case tree — the REAL governor that makes a lifted
          // wave/concurrency clamp safe.
          //
          // NULLABLE: an operator must be able to pass the literal null these fields
          // default to (e.g. the LEAN_PROFILE's no-in-flight-cap / null-governor
          // conservative profile). normalizeQueuePolicy already disambiguates explicit
          // null (-> null) from an absent key (-> sized default); the schema gate was the
          // only thing rejecting null at the boundary. The width-at-baseline LEAN profile
          // stays governor-null (the auto-fill arms only when width/depth is RAISED), so
          // the RANK != BOUND / unbounded-fixpoint invariants are untouched.
          max_concurrent_evaluators: { type: ["integer", "null"] },
          max_total_spawned_agents: { type: ["integer", "null"] },
          // Y.10 (Y-D12 / Y-P12 / D6 + D14) — operator attestation that
          // listed partial surfaces are acknowledged for the
          // OPEN_FRONTIER -> CLAIM_FREEZE runtime gate.
          partial_surface_advance_acknowledgements: {
            type: "array",
            items: {
              type: "object",
              properties: {
                surface_id: { type: "string" },
                attestation_token: { type: "string" },
                rationale: { type: "string" },
              },
              required: ["surface_id", "attestation_token"],
            },
          },
          // OD1 seed-producer governors + OD4 linked-contract depth governor.
          // These are the init-owned, MCP-enforced fan-out bounds normalizeQueuePolicy
          // rebuilds and the partial-update merge read-modify-writes; declaring them
          // here (additionalProperties defaults false) makes the operator-update path
          // reachable instead of rejecting the field at the tool boundary. Bounds are
          // the AUTHORITATIVE normalizeQueuePolicy clamps: the seed caps are positive
          // integers <= CLAMP_CEILING; linked_contract_depth allows 0 (no recursion)
          // up to 32. An out-of-bounds value fails closed at the schema boundary and
          // again in the normalizer.
          seed_producer_per_pass_cap: { type: "integer", minimum: 1, maximum: CLAMP_CEILING },
          per_expander_linked_address_cap: { type: "integer", minimum: 1, maximum: CLAMP_CEILING },
          max_total_seed_producers: { type: "integer", minimum: 1, maximum: CLAMP_CEILING },
          linked_contract_depth: { type: "integer", minimum: 0, maximum: 32 },
        },
      },
    },
    required: ["target_domain", "policy"],
  },
  handler,
  role_bundles: ["orchestrator"],
  mutating: true,
  global_preapproval: false,
  network_access: false,
  browser_access: false,
  scope_required: false,
  sensitive_output: false,
  session_artifacts_written: ["queue-policy.json"],
});
