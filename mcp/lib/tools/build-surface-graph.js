"use strict";

const { buildSurfaceGraph } = require("../surface-graph-builder.js");

function buildSurfaceGraphHandler(args) {
  return buildSurfaceGraph({
    target_domain: args.target_domain,
    sources: args.sources,
  });
}

module.exports = Object.freeze({
  name: "bob_build_surface_graph",
  capability_id: "I1_surface_graph",
  description:
    "Build (or refresh) the surface graph for a target by reading attack_surface.json, schema contracts, auth-differential results, optional evm-role-table results, and chain-tree outcomes and emitting canonical edges. Idempotent via edge_hash; later builds upsert in place. Pass sources to limit which artifact paths feed the graph (default: ['attack_surface', 'schema_corpus', 'auth_differential', 'evm_role_table', 'chain_tree']).",
  inputSchema: {
    type: "object",
    properties: {
      target_domain: { type: "string" },
      sources: {
        type: "array",
        items: { type: "string" },
        description: "Optional subset of source artifact pipelines to read. Known values: attack_surface, schema_corpus, auth_differential, evm_role_table, chain_tree.",
      },
    },
    required: ["target_domain"],
  },
  handler: buildSurfaceGraphHandler,
  role_bundles: ["orchestrator"],
  mutating: true,
  global_preapproval: false,
  network_access: false,
  browser_access: false,
  scope_required: false,
  sensitive_output: false,
  session_artifacts_written: ["surface-graph.jsonl"],
});
