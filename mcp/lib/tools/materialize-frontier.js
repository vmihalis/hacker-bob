"use strict";

const {
  assertNonEmptyString,
} = require("../validation.js");
const {
  materializeFrontier,
} = require("../frontier-materializer.js");

function handler(args) {
  const domain = assertNonEmptyString(args.target_domain, "target_domain");
  const views = materializeFrontier(domain, { write: true });
  return JSON.stringify({
    version: 1,
    target_domain: domain,
    surface_index_hash: views.surface_index.surface_index_hash,
    task_queue_hash: views.task_queue.task_queue_hash,
    surface_count: views.surface_index.surface_count,
    task_count: views.task_queue.task_count,
    source_event_count: views.surface_index.source_event_count,
  });
}

module.exports = Object.freeze({
  name: "bob_materialize_frontier",
  description:
    "Fold frontier-events.jsonl into the surface-index.json and task-queue.json " +
    "materialized views and write both to disk under the session root. Producers " +
    "trigger a debounced auto-materialization; this tool is for rare direct " +
    "operator use or recovery after an external mutation of the event log.",
  inputSchema: {
    type: "object",
    properties: {
      target_domain: {
        type: "string",
      },
    },
    required: ["target_domain"],
  },
  handler,
  role_bundles: ["orchestrator"],
  mutating: true,
  global_preapproval: false,
  network_access: false,
  browser_access: false,
  scope_required: false,
  sensitive_output: false,
  session_artifacts_written: ["surface-index.json", "task-queue.json"],
});
