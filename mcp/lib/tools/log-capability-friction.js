"use strict";

// chain+evaluator-shared justified: friction logging is a cross-cutting
// telemetry channel — every agent role (chain-builder, evaluator-shared
// subagents, surface-discovery, orchestrator) emits capability friction
// at recognized inadequacy points. The wide role_bundles[] grant is the
// Y-P9 voluntary-emission discipline (Y.9 chain-bundle audit rev 4.1
// defect 3 absorption); single-spawner topology preserved.

// Cycle Y.2 — bob_log_capability_friction.
//
// Thin wrapper over bob_append_frontier_event that:
//   * Validates the payload via assertCapabilityFrictionPayload (Y-P2 + Y-P10
//     mechanical-witness wired with a session-context frontier-event lookup).
//   * Stamps a per-(run_id, node_id, wanted_tool, purpose, detected_by)
//     idempotency key (Y-P3 5-tuple) and SILENTLY short-circuits the second
//     emission rather than appending a duplicate observation.
//   * Appends an `observation.recorded` frontier event with
//     payload.observation_kind = "capability_friction_observed" — siblings
//     of OSS observation kinds; ZERO new top-level FRONTIER_EVENT_KIND
//     (Y-P1 / X-P8 honoured).
//
// Voluntary `tool_inadequate` and synthetic adversarial scans for the same
// wanted_tool must COEXIST per Y-P11. The 5-tuple includes `detected_by`,
// so a voluntary "agent_self_report" record and an "adversarial_transcript_scan"
// record for the same wanted_tool resolve to different idempotency keys.

const {
  appendFrontierEvent,
  readFrontierEvents,
} = require("../frontier-events.js");
const {
  scheduleMaterialization,
} = require("../frontier-materialize-debounce.js");
const {
  assertCapabilityFrictionPayload,
} = require("../capability-observations.js");
const {
  assertSafeDomain,
} = require("../paths.js");
const {
  withSessionLock,
} = require("../storage.js");
const { ERROR_CODES, ToolError } = require("../envelope.js");

function idempotencyKeyFromPayload(payload) {
  return [
    payload.run_id,
    payload.node_id,
    payload.wanted_tool,
    payload.purpose,
    payload.detected_by,
  ].join("");
}

function idempotencyKeyFromEvent(event) {
  if (!event || event.kind !== "observation.recorded") return null;
  const payload = event.payload;
  if (!payload || payload.observation_kind !== "capability_friction_observed") return null;
  if (typeof payload.run_id !== "string"
    || typeof payload.node_id !== "string"
    || typeof payload.wanted_tool !== "string"
    || typeof payload.purpose !== "string"
    || typeof payload.detected_by !== "string"
  ) {
    return null;
  }
  return [
    payload.run_id,
    payload.node_id,
    payload.wanted_tool,
    payload.purpose,
    payload.detected_by,
  ].join("");
}

function frictionEventLookup(domain) {
  // The lookup is consumed by assertCapabilityFrictionPayload to verify the
  // Y-P10 mechanical witness exists in the same run_id and its `tool` matches
  // the wanted_tool. We index by event_id so the validator can resolve a
  // `frontier_event:<event_id>` ref in O(1).
  const events = readFrontierEvents(domain);
  const byId = new Map();
  for (const event of events) {
    if (event && typeof event.event_id === "string") {
      byId.set(event.event_id, event);
    }
  }
  return (eventId) => byId.get(eventId) || null;
}

function findExistingFrictionByKey(domain, key) {
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
      "bob_log_capability_friction args must be a plain object",
    );
  }
  const domain = assertSafeDomain(args.target_domain);

  return withSessionLock(domain, () => {
    const lookup = frictionEventLookup(domain);
    const normalized = assertCapabilityFrictionPayload(args, {
      lookupFrontierEvent: lookup,
    });
    const key = idempotencyKeyFromPayload(normalized);

    const existing = findExistingFrictionByKey(domain, key);
    if (existing) {
      return JSON.stringify({
        version: 1,
        appended: false,
        idempotent: true,
        event_id: existing.event_id,
        event_hash: existing.event_hash,
        observation_kind: "capability_friction_observed",
        idempotency_key_components: {
          run_id: normalized.run_id,
          node_id: normalized.node_id,
          wanted_tool: normalized.wanted_tool,
          purpose: normalized.purpose,
          detected_by: normalized.detected_by,
        },
      });
    }

    const event = appendFrontierEvent({
      target_domain: domain,
      kind: "observation.recorded",
      surface_id: normalized.surface_id == null ? null : normalized.surface_id,
      payload: normalized,
      source: {
        artifact: "frontier-events.jsonl",
        tool: "bob_log_capability_friction",
      },
    });
    try {
      scheduleMaterialization(domain);
    } catch {
      // Best-effort materialization debounce; the append is authoritative.
    }
    return JSON.stringify({
      version: 1,
      appended: true,
      idempotent: false,
      event_id: event.event_id,
      event_hash: event.event_hash,
      observation_kind: "capability_friction_observed",
      idempotency_key_components: {
        run_id: normalized.run_id,
        node_id: normalized.node_id,
        wanted_tool: normalized.wanted_tool,
        purpose: normalized.purpose,
        detected_by: normalized.detected_by,
      },
    });
  });
}

module.exports = Object.freeze({
  name: "bob_log_capability_friction",
  description:
    "Append a capability_friction_observed observation to frontier-events.jsonl. The agent declares the MCP tool it wanted (wanted_tool MUST exist in TOOL_REGISTRY), the closed-enum purpose, the Bash fallback it reached for, and the friction_kind (tool_absent vs tool_inadequate). tool_inadequate REQUIRES inadequate_invocation_ref pointing at a recorded MCP invocation in the same run_id (Y-P10 mechanical witness). Per-(run_id, node_id, wanted_tool, purpose, detected_by) idempotent (Y-P3) — second emission with the same 5-tuple is silently de-duped.",
  inputSchema: {
    type: "object",
    properties: {
      target_domain: {
        type: "string",
        description: "Session target domain — the same value passed to bob_init_session.",
      },
      run_id: {
        type: "string",
        description: "Agent run identifier; the witness lookup matches by run_id.",
      },
      node_id: {
        type: "string",
        description: "TaskGraph node identifier the agent was executing when the friction surfaced.",
      },
      wanted_tool: {
        type: "string",
        description: "MCP tool the agent declares it needed; MUST exist in TOOL_REGISTRY.",
      },
      purpose: {
        type: "string",
        enum: [
          "http_probe",
          "auth_replay",
          "schema_fetch",
          "body_resolve",
          "static_scan",
          "chain_walk",
          "evidence_pull",
          "report_compose",
          "other",
        ],
        description: "Closed-prefix purpose enum (Y-P2).",
      },
      fallback_used: {
        type: "string",
        enum: [
          "bash_curl",
          "bash_wget",
          "bash_raw_http",
          "bash_cat_ledger",
          "bash_grep",
          "bash_other",
          "none",
        ],
        description: "Bash side-channel the agent reached for; `none` is reserved for protocol-drift records.",
      },
      friction_kind: {
        type: "string",
        enum: ["tool_absent", "tool_inadequate"],
        description: "Closed enum. tool_absent: tool not in pack. tool_inadequate: tool present but inadequate (REQUIRES inadequate_invocation_ref + inadequacy_mode per Y-P10).",
      },
      detected_by: {
        type: "string",
        enum: [
          "agent_self_report",
          "adversarial_transcript_scan",
          "mcp_runtime_auto_emit",
        ],
        description: "Voluntary vs synthetic vs runtime-emit attribution. Affects the 5-tuple so voluntary + synthetic coexist (Y-P11).",
      },
      rationale: {
        type: "string",
        maxLength: 512,
        description: "Free-text rationale capped at 512 chars at append (Y-P2). Full transcript fragments stay pull-only via bob_resolve_body.",
      },
      surface_id: {
        type: "string",
        description: "Optional surface this friction relates to; threaded into wave-scoped friction-history (Y-P5).",
      },
      inadequacy_mode: {
        type: "string",
        enum: [
          "body_truncated",
          "response_timeout",
          "missing_parameter",
          "missing_auth_mode",
          "output_format_unsuitable",
          "rate_limited",
          "other",
        ],
        description: "REQUIRED when friction_kind=tool_inadequate; FORBIDDEN when friction_kind=tool_absent (Y-P11 disjointness).",
      },
      inadequate_invocation_ref: {
        type: "string",
        pattern: "^frontier_event:[A-Za-z0-9_-]+$",
        description: "Y-P10 mechanical witness. REQUIRED on tool_inadequate. MUST point to a recorded MCP invocation in the same run_id whose tool matches wanted_tool and whose outcome was non-success. FORBIDDEN on tool_absent.",
      },
    },
    required: [
      "target_domain",
      "run_id",
      "node_id",
      "wanted_tool",
      "purpose",
      "fallback_used",
      "friction_kind",
      "detected_by",
      "rationale",
    ],
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
