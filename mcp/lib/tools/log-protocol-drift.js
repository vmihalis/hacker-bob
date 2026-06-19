"use strict";

// chain+evaluator-shared justified: protocol-drift logging is a
// cross-cutting telemetry channel — every agent role (chain-builder,
// evaluator-shared subagents, surface-discovery, orchestrator) may emit
// drift records on write-arg INVALID_ARGUMENTS retries, wrong-mode tool
// calls, or hook denials. The wide role_bundles[] grant is the Y-P7
// advisory-channel discipline (Y.9 chain-bundle audit rev 4.1 defect 3
// absorption); single-spawner topology preserved.

// Cycle Y.2 — bob_log_protocol_drift.
//
// Thin wrapper over bob_append_frontier_event for protocol_drift_observed.
// Drift records are ADVISORY telemetry only (Y-P7) — the runtime never
// decides "skill is wrong, MCP is right". Resolution lives in the CI gates
// (Y.7 lifecycle / write-tool-schema / runtime-constraint dimensions).
//
// Idempotency key: ${run_id}:${skill_path}:${drift_signature}. CI-emitted
// drifts always carry a skill_path; runtime emitters MAY omit it (the source
// of drift is the live tool call, not a markdown file) — in that case the
// idempotency key uses the literal "<runtime>" sentinel so multiple
// CI-derived drifts on different skill paths and runtime-emit drifts coexist
// without collapsing into one record.

const {
  appendFrontierEvent,
  readFrontierEvents,
} = require("../frontier-events.js");
const {
  scheduleMaterialization,
} = require("../frontier-materialize-debounce.js");
const {
  assertProtocolDriftPayload,
} = require("../capability-observations.js");
const {
  assertSafeDomain,
} = require("../paths.js");
const {
  withSessionLock,
} = require("../storage.js");
const { ERROR_CODES, ToolError } = require("../envelope.js");

const SKILL_PATH_SENTINEL_RUNTIME = "<runtime>";

function idempotencyKeyFromPayload(payload) {
  const skillPath = typeof payload.skill_path === "string" && payload.skill_path
    ? payload.skill_path
    : SKILL_PATH_SENTINEL_RUNTIME;
  return [payload.run_id, skillPath, payload.drift_signature].join("");
}

function idempotencyKeyFromEvent(event) {
  if (!event || event.kind !== "observation.recorded") return null;
  const payload = event.payload;
  if (!payload || payload.observation_kind !== "protocol_drift_observed") return null;
  if (typeof payload.run_id !== "string"
    || typeof payload.drift_signature !== "string"
  ) {
    return null;
  }
  const skillPath = typeof payload.skill_path === "string" && payload.skill_path
    ? payload.skill_path
    : SKILL_PATH_SENTINEL_RUNTIME;
  return [payload.run_id, skillPath, payload.drift_signature].join("");
}

function findExistingDriftByKey(domain, key) {
  const events = readFrontierEvents(domain);
  for (const event of events) {
    if (idempotencyKeyFromEvent(event) === key) {
      return event;
    }
  }
  return null;
}

function handler(args) {
  if (args == null || typeof args !== "object" || Array.isArray(args)) {
    throw new ToolError(
      ERROR_CODES.INVALID_ARGUMENTS,
      "bob_log_protocol_drift args must be a plain object",
    );
  }
  const domain = assertSafeDomain(args.target_domain);
  const normalized = assertProtocolDriftPayload(args);

  return withSessionLock(domain, () => {
    const key = idempotencyKeyFromPayload(normalized);
    const existing = findExistingDriftByKey(domain, key);
    if (existing) {
      return JSON.stringify({
        version: 1,
        appended: false,
        idempotent: true,
        event_id: existing.event_id,
        event_hash: existing.event_hash,
        observation_kind: "protocol_drift_observed",
        idempotency_key_components: {
          run_id: normalized.run_id,
          skill_path: normalized.skill_path == null ? SKILL_PATH_SENTINEL_RUNTIME : normalized.skill_path,
          drift_signature: normalized.drift_signature,
        },
      });
    }

    const event = appendFrontierEvent({
      target_domain: domain,
      kind: "observation.recorded",
      payload: normalized,
      source: {
        artifact: "frontier-events.jsonl",
        tool: "bob_log_protocol_drift",
      },
    });
    try {
      scheduleMaterialization(domain);
    } catch {
      // Best-effort.
    }
    return JSON.stringify({
      version: 1,
      appended: true,
      idempotent: false,
      event_id: event.event_id,
      event_hash: event.event_hash,
      observation_kind: "protocol_drift_observed",
      idempotency_key_components: {
        run_id: normalized.run_id,
        skill_path: normalized.skill_path == null ? SKILL_PATH_SENTINEL_RUNTIME : normalized.skill_path,
        drift_signature: normalized.drift_signature,
      },
    });
  });
}

module.exports = Object.freeze({
  name: "bob_log_protocol_drift",
  description:
    "Append a protocol_drift_observed observation to frontier-events.jsonl. Drift records are advisory telemetry only (Y-P7); the runtime NEVER decides skill-vs-MCP rightness. CI dimensions (Y.7 lifecycle / write-tool-schema / runtime-constraint) and operators resolve drift. Per-(run_id, skill_path, drift_signature) idempotent — runtime-emitted records without a skill_path collapse onto a <runtime> sentinel so multiple CI drifts on the same run coexist.",
  inputSchema: {
    type: "object",
    properties: {
      target_domain: {
        type: "string",
      },
      run_id: {
        type: "string",
      },
      drift_signature: {
        type: "string",
        enum: [
          "write_arg_schema_mismatch_recovered",
          "wrong_mode_tool_call",
          "partial_advance_acknowledged",
          "hook_denial",
          "lifecycle_transition_invalid",
          "unknown_tool_token",
          "missing_schema_ref",
          "write_arg_schema_mismatch",
          "runtime_constraint_collision",
          "producer_trace_dropped",
          "silent_lead_threshold_drop",
        ],
      },
      detected_by: {
        type: "string",
        enum: [
          "agent_self_report",
          "adversarial_transcript_scan",
          "mcp_runtime_auto_emit",
        ],
      },
      rationale: {
        type: "string",
        maxLength: 512,
      },
      skill_path: {
        type: "string",
        description: "Required for CI-emitted drifts; runtime emitters MAY omit (the source of drift is the live tool call, not a markdown file).",
      },
      details: {
        type: "object",
        description: "Optional structured payload (tool, session_mode, ajv_path, etc.) so operators can grep telemetry.",
      },
    },
    required: ["target_domain", "run_id", "drift_signature", "detected_by", "rationale"],
  },
  handler,
  role_bundles: [
    "chain",
    "evaluator-shared",
    "evaluator-spawn",
    "orchestrator",
    "surface-discovery",
  ],
  capability_id: "Y_self_reporting",
  mutating: true,
  global_preapproval: true,
  network_access: false,
  browser_access: false,
  scope_required: false,
  sensitive_output: false,
  session_artifacts_written: ["frontier-events.jsonl"],
});
