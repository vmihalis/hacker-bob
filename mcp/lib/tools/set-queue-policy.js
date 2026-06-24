"use strict";

const {
  assertNonEmptyString,
} = require("../validation.js");
const {
  withSessionLock,
} = require("../storage.js");
const {
  normalizeQueuePolicy,
  writeQueuePolicy,
} = require("../queue-policy.js");

function handler(args) {
  const domain = assertNonEmptyString(args.target_domain, "target_domain");
  const policyInput = args.policy == null ? {} : args.policy;
  if (typeof policyInput !== "object" || Array.isArray(policyInput)) {
    throw new Error("policy must be an object");
  }
  const normalized = normalizeQueuePolicy(policyInput);
  const persisted = withSessionLock(domain, () => writeQueuePolicy(domain, normalized));
  return JSON.stringify({
    version: 1,
    target_domain: domain,
    queue_policy: persisted,
  });
}

module.exports = Object.freeze({
  name: "bob_set_queue_policy",
  description:
    "Persist an operator-supplied QueuePolicy override for a target_domain to " +
    "~/hacker-bob-sessions/<domain>/queue-policy.json. The policy is normalized via " +
    "normalizeQueuePolicy and consumed by the wave planner and scheduler. Carries " +
    "max_parallel_tasks, priority_order, stale_after_ms, close_blocked_on_freeze, " +
    "and the wave targets/budgets/lens.",
  inputSchema: {
    type: "object",
    properties: {
      target_domain: {
        type: "string",
      },
      policy: {
        type: "object",
        description:
          "Partial or full QueuePolicy. Unspecified fields fall back to DEFAULT_QUEUE_POLICY.",
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
