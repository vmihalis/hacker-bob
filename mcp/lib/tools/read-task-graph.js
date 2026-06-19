"use strict";

// Plane X Cycle X.2 — bob_read_task_graph.
//
// Returns the materialized task-graph.json view. Per Do step 3 the view
// modes are:
//
//   - "raw"      → the full document {nodes[], edges[], hashes, warnings?}
//                  with optional {kind, state, node_id} filters
//   - "summary"  → folded counts + top-N ready nodes + open Hypotheses +
//                  recent finalizations + cross-stack Transitions + the most
//                  recent structured failure_reason per failed node
//
// The summary mode keeps the read surface at one entry point for the
// X.5 / X.8 / X.11 cycles that consume it.

const {
  assertNonEmptyString,
} = require("../validation.js");
const {
  readTaskGraph,
  summarizeTaskGraph,
} = require("../task-graph-materializer.js");

const VIEW_VALUES = Object.freeze(["raw", "summary"]);

function handler(args) {
  const domain = assertNonEmptyString(args.target_domain, "target_domain");
  const view = typeof args.view === "string" && args.view.trim() ? args.view.trim() : "raw";
  if (!VIEW_VALUES.includes(view)) {
    throw new Error(`view must be one of ${VIEW_VALUES.join(", ")}`);
  }
  const filters = args.filters && typeof args.filters === "object" && !Array.isArray(args.filters)
    ? args.filters
    : undefined;
  if (view === "summary") {
    const summary = summarizeTaskGraph(domain);
    return JSON.stringify(summary);
  }
  const document = readTaskGraph(domain, { filters });
  return JSON.stringify(document);
}

module.exports = Object.freeze({
  name: "bob_read_task_graph",
  description:
    "Read the materialized task-graph.json view. view: \"raw\" returns the full "
    + "node + edge document with optional {kind, state, node_id} filters; view: "
    + "\"summary\" returns per-state counts + top-10 ready nodes + open "
    + "Hypotheses + recent finalizations + cross-stack Transitions + the most "
    + "recent structured failure_reason per failed node. Reads bound to the "
    + "session root.",
  inputSchema: {
    type: "object",
    properties: {
      target_domain: {
        type: "string",
      },
      view: {
        type: "string",
        enum: [...VIEW_VALUES],
        description: "raw (default) returns the full document; summary folds counts + top-N slices.",
      },
      filters: {
        type: "object",
        properties: {
          kind: {
            type: "string",
            description: "Filter raw nodes by kind (surface, hypothesis, transition, claim).",
          },
          state: {
            type: "string",
            description: "Filter raw nodes by state from the X.1 frozen state-transition table.",
          },
          node_id: {
            type: "string",
            description: "Filter to a single node id (e.g. TG-T-<...>).",
          },
        },
        additionalProperties: false,
      },
    },
    required: ["target_domain"],
  },
  handler,
  // Read access for orchestrator (which drives bob_schedule_graph_nodes) +
  // evaluator-shared (which renders briefs in X.5/X.8) + verifier (which
  // resolves the graph_context_hash for adjudication grounding).
  role_bundles: ["orchestrator", "evaluator-shared", "verifier"],
  mutating: false,
  global_preapproval: false,
  network_access: false,
  browser_access: false,
  scope_required: false,
  sensitive_output: false,
  session_artifacts_written: [],
});
