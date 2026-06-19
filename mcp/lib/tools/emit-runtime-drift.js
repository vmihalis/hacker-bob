"use strict";

// Cycle Y.2 — bob_emit_runtime_drift (Y-D13).
//
// Orchestrator-facing entry for runtime-channel drift telemetry. Runtime
// channels emit protocol_drift_observed defensively when the live tool call
// disagrees with the agent's expectation (write-arg INVALID_ARGUMENTS retries
// that subsequently succeed, wrong-mode tool calls, hook denials on Bob-owned
// hooks, queue-policy partial-surface advance acknowledgements).
//
// Per Y-P7 these are ADVISORY telemetry only — never auto-correctors.
//
// Per Y-R20: idempotent on (run_id, drift_signature, tool). Same triplet
// inside a single run is silently de-duped so a stuck retry loop cannot bury
// the ledger. The 5-tuple discipline of bob_log_capability_friction does not
// apply here — runtime drift records have no node_id / purpose semantics.
//
// Rev 3 Y-D13 explicitly states the write-tool auto-emit path goes through
// a SERVER-INTERNAL caller bundle constructed inside _write-base.js (which
// ships atomically in Y.3); the `mcp_server_internal` bundle is NOT
// grantable to any agent role and is CI-asserted absent from
// mcp/lib/role-bundles.js exports. This Y.2 cycle ships ONLY the
// orchestrator-facing entry; the internal caller context lands in Y.3.

const {
  appendFrontierEvent,
  readFrontierEvents,
} = require("../frontier-events.js");
const {
  scheduleMaterialization,
} = require("../frontier-materialize-debounce.js");
const {
  assertProtocolDriftPayload,
  DRIFT_SIGNATURE_VALUES,
  DETECTED_BY_VALUES,
} = require("../capability-observations.js");
const {
  assertSafeDomain,
} = require("../paths.js");
const {
  withSessionLock,
} = require("../storage.js");
const { ERROR_CODES, ToolError } = require("../envelope.js");

// Runtime channels emit ONLY this subset of the closed drift_signature enum
// (the CI-emitted dimensions in Y.7 land via bob_log_protocol_drift). Y-D13
// names these four explicitly; we encode them as a frozen array so the
// schema enum and the runtime contract stay in lockstep.
const RUNTIME_EMIT_DRIFT_SIGNATURES = Object.freeze([
  "write_arg_schema_mismatch_recovered",
  "wrong_mode_tool_call",
  "partial_advance_acknowledged",
  "hook_denial",
]);

for (const sig of RUNTIME_EMIT_DRIFT_SIGNATURES) {
  if (!DRIFT_SIGNATURE_VALUES.includes(sig)) {
    throw new Error(
      `bob_emit_runtime_drift declared runtime drift signature ${sig} that is not in DRIFT_SIGNATURE_VALUES`,
    );
  }
}

function idempotencyKeyFromPayload(payload) {
  const tool = payload.details && typeof payload.details.tool === "string"
    ? payload.details.tool
    : "<no-tool>";
  return [payload.run_id, payload.drift_signature, tool].join("");
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
  if (payload.detected_by !== "mcp_runtime_auto_emit") return null;
  const tool = payload.details && typeof payload.details.tool === "string"
    ? payload.details.tool
    : "<no-tool>";
  return [payload.run_id, payload.drift_signature, tool].join("");
}

function findExistingRuntimeDriftByKey(domain, key) {
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
      "bob_emit_runtime_drift args must be a plain object",
    );
  }
  const domain = assertSafeDomain(args.target_domain);

  if (typeof args.drift_signature !== "string"
    || !RUNTIME_EMIT_DRIFT_SIGNATURES.includes(args.drift_signature)
  ) {
    throw new ToolError(
      ERROR_CODES.INVALID_ARGUMENTS,
      `drift_signature must be one of ${RUNTIME_EMIT_DRIFT_SIGNATURES.join(", ")} for runtime emission`,
    );
  }

  // detected_by is FORCED to "mcp_runtime_auto_emit" — this tool's contract
  // is the runtime emit channel; voluntary agent emissions go through
  // bob_log_protocol_drift. We do not let callers spoof detected_by.
  const driftPayload = {
    run_id: args.run_id,
    drift_signature: args.drift_signature,
    detected_by: "mcp_runtime_auto_emit",
    rationale: args.rationale,
  };
  if (args.skill_path != null) driftPayload.skill_path = args.skill_path;
  if (args.details != null) driftPayload.details = args.details;

  const normalized = assertProtocolDriftPayload(driftPayload);
  // Defensive sanity-check: assertProtocolDriftPayload accepts every
  // DETECTED_BY enum; we additionally REQUIRE mcp_runtime_auto_emit here.
  if (normalized.detected_by !== "mcp_runtime_auto_emit") {
    throw new ToolError(
      ERROR_CODES.INTERNAL_ERROR,
      "bob_emit_runtime_drift must stamp detected_by=mcp_runtime_auto_emit",
    );
  }

  return withSessionLock(domain, () => {
    const key = idempotencyKeyFromPayload(normalized);
    const existing = findExistingRuntimeDriftByKey(domain, key);
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
          drift_signature: normalized.drift_signature,
          tool: normalized.details && typeof normalized.details.tool === "string"
            ? normalized.details.tool
            : null,
        },
      });
    }

    const event = appendFrontierEvent({
      target_domain: domain,
      kind: "observation.recorded",
      payload: normalized,
      source: {
        artifact: "frontier-events.jsonl",
        tool: "bob_emit_runtime_drift",
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
        drift_signature: normalized.drift_signature,
        tool: normalized.details && typeof normalized.details.tool === "string"
          ? normalized.details.tool
          : null,
      },
    });
  });
}

// Sanity guard: ensure the closed runtime-emit set is a subset of the
// general DETECTED_BY enum (defensive — DETECTED_BY_VALUES is closed and
// this would catch any silent rename of the runtime-emit token).
if (!DETECTED_BY_VALUES.includes("mcp_runtime_auto_emit")) {
  throw new Error(
    "DETECTED_BY_VALUES must include mcp_runtime_auto_emit for bob_emit_runtime_drift",
  );
}

module.exports = Object.freeze({
  name: "bob_emit_runtime_drift",
  description:
    "Orchestrator-facing entry for runtime-channel protocol drift telemetry (Y-D13). The runtime emits defensively when the live tool call disagrees with the agent's expectation (write-arg INVALID_ARGUMENTS retries that succeed, wrong-mode tool calls, hook denials on Bob-owned hooks, partial-surface advance acknowledgements). Y-P7: ADVISORY telemetry only — the runtime never decides skill-vs-MCP rightness. detected_by is ALWAYS stamped 'mcp_runtime_auto_emit'; voluntary agent emissions go through bob_log_protocol_drift. Per Y-R20: idempotent on (run_id, drift_signature, details.tool).",
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
        ],
        description: "Runtime channels emit only the Y-D13 quartet; CI dimensions land via bob_log_protocol_drift.",
      },
      rationale: {
        type: "string",
        maxLength: 512,
      },
      skill_path: {
        type: "string",
        description: "Optional — runtime drifts often have no skill_path because the source is the live tool call.",
      },
      details: {
        type: "object",
        description: "Structured payload — typically {tool, session_mode, ajv_path, attempts, ...} so operators can grep telemetry. The `tool` field participates in the idempotency key.",
      },
    },
    required: ["target_domain", "run_id", "drift_signature", "rationale"],
  },
  handler,
  // Y-D13: orchestrator-only at the role-bundle layer. The
  // mcp_server_internal synthetic caller context that lets _write-base.js
  // auto-emit on INVALID_ARGUMENTS retry success lands in Y.3 and is
  // explicitly NOT a grantable role bundle. CI guard in Y.8 asserts
  // mcp_server_internal is not exported from mcp/lib/role-bundles.js.
  role_bundles: ["orchestrator"],
  capability_id: "Y_self_reporting",
  mutating: true,
  // Orchestrator-only mutators NEVER carry global_preapproval — the host
  // adapter's permission generator gates that combination. Mirrors the
  // contract on bob_append_frontier_event (orchestrator-only + mutating).
  global_preapproval: false,
  network_access: false,
  browser_access: false,
  scope_required: false,
  sensitive_output: false,
  session_artifacts_written: ["frontier-events.jsonl"],
  // Exposed for Y.3 + Y.8 + tests so the runtime-emit drift signature set
  // stays a single source of truth.
  RUNTIME_EMIT_DRIFT_SIGNATURES,
});
