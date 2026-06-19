"use strict";

// Cycle Y.1 — Capability observation kinds + payload validators.
//
// Two new `observation_kind` values that ride the existing
// `observation.recorded` top-level FRONTIER_EVENT_KIND (Y-P1: zero new
// top-level kinds). Pack-surfacing and friction-aware derivation read
// these from the observation feed the same way OSS observation kinds and
// the T.5 jwt_observed precedent do.
//
// Records are summary-grade by SHAPE (Y-P2): closed enums on every
// classifier field, a 512-character cap on `rationale`, and `wanted_tool`
// must exist in TOOL_REGISTRY. Full transcript fragments stay pull-only via
// `bob_resolve_body`.
//
// `tool_inadequate` carries an additional `inadequacy_mode` (closed enum)
// AND an `inadequate_invocation_ref` of the form
// `frontier_event:<event_id>` (Y-P10 mechanical witness). The witness MUST
// point to a recorded MCP invocation in the same `run_id` whose `tool`
// matches `wanted_tool` and whose outcome was non-success. `tool_absent`
// MUST NOT carry `inadequacy_mode` or `inadequate_invocation_ref`.
//
// Protocol drift records carry a closed `drift_signature` enum plus an
// optional structured `details` object. Y-P7 — runtime never decides
// skill-vs-MCP rightness; drift is advisory telemetry the CI dimensions
// resolve.

const { ERROR_CODES, ToolError } = require("./envelope.js");
// tool-registry.js loads every tool module, several of which require
// repo-target.js, which re-exports the capability-observation enums from
// this module. Eager-loading tool-registry here therefore creates a
// require cycle that strands repo-target's full export surface. Resolve
// it lazily at call time — the validator only needs the registry on the
// hot path, not at module load.
let registryModule = null;
function lookupRegisteredTool(name) {
  if (registryModule === null) {
    registryModule = require("./tool-registry.js");
  }
  return registryModule.getRegisteredTool(name);
}

const RATIONALE_MAX_CHARS = 512;
const FRONTIER_EVENT_REF_RE = /^frontier_event:[A-Za-z0-9_-]+$/;

// Two new observation_kind values. They ride observation.recorded, so the
// top-level FRONTIER_EVENT_KIND set is UNCHANGED (Y-P1 / X-P8 honored).
const CAPABILITY_OBSERVATION_KIND_VALUES = Object.freeze([
  "capability_friction_observed",
  "protocol_drift_observed",
]);

// Closed-prefix `purpose` enum (Y-P2). These name what the agent was
// trying to accomplish when it discovered the friction; downstream
// derivation reads `purpose` to widen capability packs for the specific
// goal, not just the named wanted_tool.
const PURPOSE_VALUES = Object.freeze([
  "http_probe",
  "auth_replay",
  "schema_fetch",
  "body_resolve",
  "static_scan",
  "chain_walk",
  "evidence_pull",
  "report_compose",
  "other",
]);

// Bounded `fallback_used` enum (Y-P2). Closed-prefix Bash side-channels
// the agent reached for. `bash_other` is the catch-all for operator-
// extended scanners that have not yet been classified. The `none` value
// covers protocol-drift records where the agent did not actually fall
// back — it just observed runtime/skill disagreement.
const FALLBACK_USED_VALUES = Object.freeze([
  "bash_curl",
  "bash_wget",
  "bash_raw_http",
  "bash_cat_ledger",
  "bash_grep",
  "bash_other",
  "none",
]);

// Closed `friction_kind` enum. Y-P3 5-tuple keeps `tool_absent` and
// `tool_inadequate` records for the same wanted_tool DISTINCT (they must
// not collapse — see Y-P11). Y-P10 mechanical witness is REQUIRED on
// `tool_inadequate` and FORBIDDEN on `tool_absent`.
const FRICTION_KIND_VALUES = Object.freeze([
  "tool_absent",
  "tool_inadequate",
]);

// Closed `inadequacy_mode` enum (Y-P2). REQUIRED on tool_inadequate,
// FORBIDDEN on tool_absent. Cf. Y-D5 — promotion of an inadequacy group
// surfaces the majority-vote mode as `tool_evolution_request` Contract
// hint.
const INADEQUACY_MODE_VALUES = Object.freeze([
  "body_truncated",
  "response_timeout",
  "missing_parameter",
  "missing_auth_mode",
  "output_format_unsuitable",
  "rate_limited",
  "other",
]);

// Closed `detected_by` enum. Voluntary emissions carry "agent_self_report";
// the Y.6 adversarial scanner carries "adversarial_transcript_scan" so the
// 5-tuple keeps voluntary + synthetic records distinct (Y-P11 coexistence
// signal). The runtime / dispatch-layer auto-emit path uses
// "mcp_runtime_auto_emit" so operators can grep telemetry by source.
const DETECTED_BY_VALUES = Object.freeze([
  "agent_self_report",
  "adversarial_transcript_scan",
  "mcp_runtime_auto_emit",
]);

// Closed `drift_signature` enum for protocol_drift_observed records.
// Runtime channels emit defensively: write-arg INVALID_ARGUMENTS retries,
// wrong-mode tool calls, hook denials on Bob-owned hooks, partial-surface
// advance acknowledgements. CI dimensions (Y.7 a/b/c) emit static-drift
// signatures so a single observation feed unifies all coherence telemetry.
// Cycle Y.7 (rev 4 W2 + rev 4.1 defect 1) adds two scanner-synthesized
// signatures emitted by `bob_scan_transcript_for_friction`:
//   * `producer_trace_dropped` — handoff summary asserts ranked_leads but
//     the run made zero `bob_record_surface_leads` calls (Y-P14a producer
//     trace dropped).
//   * `silent_lead_threshold_drop` — handoff summary asserts N ranked_leads
//     while surface-leads.json records M < N entries for the same run
//     (rev-4.1 producer-side runtime tripwire complement).
const DRIFT_SIGNATURE_VALUES = Object.freeze([
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
]);

function isCapabilityObservationKind(value) {
  return typeof value === "string"
    && CAPABILITY_OBSERVATION_KIND_VALUES.includes(value);
}

function invalid(message, details) {
  return new ToolError(ERROR_CODES.INVALID_ARGUMENTS, message, details || null);
}

function assertPlainObject(payload, label) {
  if (payload == null || typeof payload !== "object" || Array.isArray(payload)) {
    throw invalid(`${label} payload must be a plain object`);
  }
}

function assertNonEmptyString(value, fieldName) {
  if (typeof value !== "string" || !value.trim()) {
    throw invalid(`${fieldName} must be a non-empty string`);
  }
  return value.trim();
}

function assertEnumMembership(value, allowed, fieldName) {
  if (!allowed.includes(value)) {
    throw invalid(`${fieldName} must be one of ${allowed.join(", ")}`);
  }
  return value;
}

function assertRationale(value) {
  const text = assertNonEmptyString(value, "rationale");
  if (text.length > RATIONALE_MAX_CHARS) {
    throw invalid(
      `rationale must be <= ${RATIONALE_MAX_CHARS} characters (got ${text.length})`,
    );
  }
  return text;
}

function assertKnownTool(value) {
  const name = assertNonEmptyString(value, "wanted_tool");
  if (!lookupRegisteredTool(name)) {
    throw invalid(`wanted_tool must exist in TOOL_REGISTRY (got ${name})`);
  }
  return name;
}

function assertFrontierEventRef(value, fieldName) {
  const ref = assertNonEmptyString(value, fieldName);
  if (!FRONTIER_EVENT_REF_RE.test(ref)) {
    throw invalid(
      `${fieldName} must match ^frontier_event:[A-Za-z0-9_-]+$ (got ${ref})`,
    );
  }
  return ref;
}

function frontierEventIdFromRef(ref) {
  return ref.slice("frontier_event:".length);
}

// Optional witness lookup. When supplied, the validator enforces Y-P10
// end-to-end: referenced event must exist in the SAME run_id and its tool
// must match wanted_tool. When omitted (e.g. validator called in isolation
// without session context), the validator still enforces the shape but
// defers existence + tool-match verification to the appender (Y.2).
function assertWitnessConsistency(ref, runId, wantedTool, lookupFrontierEvent) {
  if (typeof lookupFrontierEvent !== "function") return;
  const eventId = frontierEventIdFromRef(ref);
  const event = lookupFrontierEvent(eventId);
  if (!event) {
    throw invalid(
      `inadequate_invocation_ref ${ref} not found in session frontier events`,
    );
  }
  const eventRunId = event.run_id
    || (event.payload && event.payload.run_id)
    || (event.source && event.source.run_id);
  if (runId && eventRunId && eventRunId !== runId) {
    throw invalid(
      `inadequate_invocation_ref ${ref} run_id ${eventRunId} does not match record run_id ${runId}`,
    );
  }
  const eventTool = event.tool
    || (event.payload && event.payload.tool)
    || (event.source && event.source.tool);
  if (eventTool && eventTool !== wantedTool) {
    throw invalid(
      `inadequate_invocation_ref ${ref} tool ${eventTool} does not match wanted_tool ${wantedTool}`,
    );
  }
}

// Validate a capability_friction_observed payload (Y-P2 + Y-P10).
// `lookupFrontierEvent(event_id) -> event | null` is optional and lets
// callers wire session context for the witness existence + tool-match
// check. The validator returns the normalized payload object (deep-copied
// + canonical field order) so producers can append it verbatim.
function assertCapabilityFrictionPayload(payload, options = {}) {
  assertPlainObject(payload, "capability_friction_observed");

  const runId = assertNonEmptyString(payload.run_id, "run_id");
  const nodeId = assertNonEmptyString(payload.node_id, "node_id");
  const wantedTool = assertKnownTool(payload.wanted_tool);
  const purpose = assertEnumMembership(payload.purpose, PURPOSE_VALUES, "purpose");
  const fallbackUsed = assertEnumMembership(
    payload.fallback_used,
    FALLBACK_USED_VALUES,
    "fallback_used",
  );
  const frictionKind = assertEnumMembership(
    payload.friction_kind,
    FRICTION_KIND_VALUES,
    "friction_kind",
  );
  const detectedBy = assertEnumMembership(
    payload.detected_by,
    DETECTED_BY_VALUES,
    "detected_by",
  );
  const rationale = assertRationale(payload.rationale);
  const surfaceId = payload.surface_id == null
    ? null
    : assertNonEmptyString(payload.surface_id, "surface_id");

  const normalized = {
    observation_kind: "capability_friction_observed",
    run_id: runId,
    node_id: nodeId,
    wanted_tool: wantedTool,
    purpose,
    fallback_used: fallbackUsed,
    friction_kind: frictionKind,
    detected_by: detectedBy,
    rationale,
  };
  if (surfaceId) normalized.surface_id = surfaceId;

  if (frictionKind === "tool_inadequate") {
    if (payload.inadequacy_mode == null) {
      throw invalid("inadequacy_mode is required when friction_kind is tool_inadequate");
    }
    const inadequacyMode = assertEnumMembership(
      payload.inadequacy_mode,
      INADEQUACY_MODE_VALUES,
      "inadequacy_mode",
    );
    if (payload.inadequate_invocation_ref == null) {
      throw invalid(
        "inadequate_invocation_ref is required when friction_kind is tool_inadequate (Y-P10 mechanical witness)",
      );
    }
    const witnessRef = assertFrontierEventRef(
      payload.inadequate_invocation_ref,
      "inadequate_invocation_ref",
    );
    assertWitnessConsistency(witnessRef, runId, wantedTool, options.lookupFrontierEvent);
    normalized.inadequacy_mode = inadequacyMode;
    normalized.inadequate_invocation_ref = witnessRef;
  } else {
    // friction_kind === "tool_absent"
    if (payload.inadequacy_mode != null) {
      throw invalid(
        "inadequacy_mode must be absent when friction_kind is tool_absent",
      );
    }
    if (payload.inadequate_invocation_ref != null) {
      throw invalid(
        "inadequate_invocation_ref must be absent when friction_kind is tool_absent",
      );
    }
  }

  return normalized;
}

// Validate a protocol_drift_observed payload (Y-P2 + Y-P7).
// drift_signature is the closed enum; details is an optional plain object
// the dispatch-layer / CI emitter supplies so operators can grep
// telemetry. `skill_path` is required for CI-emitted drifts; runtime
// emitters MAY omit it (the source of drift is the live tool call, not a
// markdown file).
function assertProtocolDriftPayload(payload) {
  assertPlainObject(payload, "protocol_drift_observed");

  const runId = assertNonEmptyString(payload.run_id, "run_id");
  const driftSignature = assertEnumMembership(
    payload.drift_signature,
    DRIFT_SIGNATURE_VALUES,
    "drift_signature",
  );
  const detectedBy = assertEnumMembership(
    payload.detected_by,
    DETECTED_BY_VALUES,
    "detected_by",
  );
  const rationale = assertRationale(payload.rationale);
  const skillPath = payload.skill_path == null
    ? null
    : assertNonEmptyString(payload.skill_path, "skill_path");

  let details = null;
  if (payload.details != null) {
    if (typeof payload.details !== "object" || Array.isArray(payload.details)) {
      throw invalid("details must be a plain object when provided");
    }
    details = payload.details;
  }

  const normalized = {
    observation_kind: "protocol_drift_observed",
    run_id: runId,
    drift_signature: driftSignature,
    detected_by: detectedBy,
    rationale,
  };
  if (skillPath) normalized.skill_path = skillPath;
  if (details) normalized.details = details;
  return normalized;
}

module.exports = {
  CAPABILITY_OBSERVATION_KIND_VALUES,
  PURPOSE_VALUES,
  FALLBACK_USED_VALUES,
  FRICTION_KIND_VALUES,
  INADEQUACY_MODE_VALUES,
  DETECTED_BY_VALUES,
  DRIFT_SIGNATURE_VALUES,
  RATIONALE_MAX_CHARS,
  isCapabilityObservationKind,
  assertCapabilityFrictionPayload,
  assertProtocolDriftPayload,
  frontierEventIdFromRef,
};
