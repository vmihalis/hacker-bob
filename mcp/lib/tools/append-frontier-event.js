"use strict";

const {
  FRONTIER_EVENT_KINDS,
  appendFrontierEvent,
} = require("../frontier-events.js");
const {
  scheduleMaterialization,
} = require("../frontier-materialize-debounce.js");

function handler(args) {
  const event = appendFrontierEvent(args || {});
  try {
    scheduleMaterialization(event.target_domain);
  } catch {
    // Materialization debounce is best-effort; do not regress the event append.
  }
  return JSON.stringify({
    version: 1,
    appended: true,
    event_id: event.event_id,
    event_hash: event.event_hash,
    kind: event.kind,
    target_domain: event.target_domain,
  });
}

module.exports = Object.freeze({
  name: "bob_append_frontier_event",
  description:
    "Append a frontier event to frontier-events.jsonl. Append-only authority. " +
    "Each event is normalized, content-hashed, and bounded by FRONTIER_EVENTS_MAX_RECORDS. " +
    "Most producers append events implicitly via init/leads/routes/http/static/coverage/dead-ends; " +
    "this tool is for rare direct operator use and internal tooling.",
  inputSchema: {
    type: "object",
    properties: {
      target_domain: {
        type: "string",
      },
      kind: {
        type: "string",
        enum: [...FRONTIER_EVENT_KINDS],
        description:
          "Frontier event kind. Must be one of the enumerated kinds; the materializer folds " +
          "kinds into the surface index and task queue projections.",
      },
      ts: {
        type: "string",
        description: "ISO-8601 timestamp. Defaults to the current time.",
      },
      payload: {
        type: "object",
        description: "Kind-specific event payload. Stored verbatim under .payload on the event.",
      },
      source: {
        type: "object",
        description: "Optional producer attribution (artifact, ref, tool).",
      },
      surface_id: {
        type: "string",
      },
      frontier_item_id: {
        type: "string",
      },
      task_id: {
        type: "string",
      },
      claim_id: {
        type: "string",
      },
      actor: {
        type: "string",
      },
      tags: {
        type: "array",
        items: { type: "string" },
      },
      event_id: {
        type: "string",
        description: "Optional explicit event_id; auto-generated from canonical hash when omitted.",
      },
    },
    required: ["target_domain", "kind"],
  },
  handler,
  role_bundles: ["orchestrator"],
  mutating: true,
  global_preapproval: false,
  network_access: false,
  browser_access: false,
  scope_required: false,
  sensitive_output: false,
  session_artifacts_written: ["frontier-events.jsonl"],
});
