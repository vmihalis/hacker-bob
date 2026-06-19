"use strict";

// Plane X Cycle X.2 — bob_materialize_task_graph.
//
// Orchestrator-only force-flush of task-graph.json (the wave-debounce hook
// already triggers materialization on producer-event release). This tool is
// for rare direct operator use or recovery after an external mutation of
// frontier-events.jsonl. It mirrors the role/authority shape of
// bob_materialize_frontier so the surface-index and task-graph stay aligned.

const {
  assertNonEmptyString,
} = require("../validation.js");
const {
  materializeTaskGraph,
} = require("../task-graph-materializer.js");

function handler(args) {
  const domain = assertNonEmptyString(args.target_domain, "target_domain");
  const result = materializeTaskGraph(domain, { write: true });
  const out = {
    version: 1,
    target_domain: domain,
    materialized_at: result.document.materialized_at,
    source_event_count: result.document.source_event_count,
    node_count: result.document.node_count,
    edge_count: result.document.edge_count,
    hashes: result.document.hashes,
  };
  if (result.ledgerPressureWarning) {
    out.warnings = [result.ledgerPressureWarning];
  }
  return JSON.stringify(out);
}

module.exports = Object.freeze({
  name: "bob_materialize_task_graph",
  description:
    "Fold frontier-events.jsonl into the deterministic task-graph.json materialized view "
    + "and write it under the session root. Producers already trigger a debounced "
    + "auto-materialization; this tool is for rare direct operator use or recovery after "
    + "an external mutation of the event log. Refuses materialization when the ledger "
    + "exceeds 18,000 events (per X-R1 ledger-pressure guardrail).",
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
  // Orchestrator-only per X.2 Do step 4: materialization is an authority call
  // (it folds the ledger into a canonical view). The X.5 capability-pack
  // derivation reads the view through the read tool, not this one.
  role_bundles: ["orchestrator"],
  mutating: true,
  global_preapproval: false,
  network_access: false,
  browser_access: false,
  scope_required: false,
  sensitive_output: false,
  session_artifacts_written: ["task-graph.json"],
});
