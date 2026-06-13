"use strict";

const { queryEdges, queryMechanismView, neighbors } = require("../surface-graph.js");

function querySurfaceGraphHandler(args) {
  if (args.mode === "mechanism") {
    return queryMechanismView({
      target_domain: args.target_domain,
      principal_id: args.principal_id,
      effect_id: args.effect_id,
      limit: args.limit,
    });
  }
  if (args.mode === "neighbors") {
    return neighbors({
      target_domain: args.target_domain,
      node_type: args.node_type,
      node_id: args.node_id,
      direction: args.direction,
      limit: args.limit,
    });
  }
  return queryEdges({
    target_domain: args.target_domain,
    source_type: args.source_type,
    target_type: args.target_type,
    edge_type: args.edge_type,
    source_id: args.source_id,
    target_id: args.target_id,
    limit: args.limit,
  });
}

module.exports = Object.freeze({
  name: "bob_query_surface_graph",
  aliases: ["bounty_query_surface_graph"],
  capability_id: "I1_surface_graph",
  description:
    "Query the surface graph. Default mode filters edges by source/target type, source/target id, and edge_type. Pass mode: 'neighbors' with node_type and node_id to walk adjacency, or mode: 'mechanism' for bounded principal/credential/policy_gate/effect/intervention projection edges from the same graph store.",
  inputSchema: {
    type: "object",
    properties: {
      target_domain: { type: "string" },
      mode: { type: "string", enum: ["edges", "neighbors", "mechanism"], description: "Default 'edges' filters edges; 'neighbors' walks adjacency; 'mechanism' returns mechanism projection edges from surface-graph.jsonl." },
      source_type: { type: "string" },
      target_type: { type: "string" },
      edge_type: { type: "string" },
      source_id: { type: "string" },
      target_id: { type: "string" },
      node_type: { type: "string" },
      node_id: { type: "string" },
      principal_id: { type: "string" },
      effect_id: { type: "string" },
      direction: { type: "string", enum: ["incoming", "outgoing", "both"] },
      limit: { type: "integer", minimum: 1, maximum: 1000 },
    },
    required: ["target_domain"],
  },
  handler: querySurfaceGraphHandler,
  role_bundles: ["orchestrator"],
  mutating: false,
  global_preapproval: false,
  network_access: false,
  browser_access: false,
  scope_required: false,
  sensitive_output: false,
  session_artifacts_written: [],
});
