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
  if (args.mode === "covered_paths") {
    // F1: the mechanism chain substrate — bounded principal->effect path space
    // over the covered mechanism graph, plus the covered A2 transition hops, that
    // the chain phase (F2) traverses. Read-only projection over the same store.
    const { enumerateCandidatePaths } = require("../mechanism-coverage.js");
    return enumerateCandidatePaths(args.target_domain, {
      max_paths: args.limit,
      max_hops: args.max_hops,
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
    "Query the surface graph. Default mode filters edges by source/target type, source/target id, and edge_type. Pass mode: 'neighbors' with node_type and node_id to walk adjacency, mode: 'mechanism' for bounded principal/credential/policy_gate/effect/intervention projection edges, or mode: 'covered_paths' for the F1 chain substrate (bounded principal->effect candidate paths over the covered mechanism graph + covered cross-surface transition hops) the chain phase traverses.",
  inputSchema: {
    type: "object",
    properties: {
      target_domain: { type: "string" },
      mode: { type: "string", enum: ["edges", "neighbors", "mechanism", "covered_paths"], description: "Default 'edges' filters edges; 'neighbors' walks adjacency; 'mechanism' returns mechanism projection edges; 'covered_paths' enumerates the principal->effect candidate-path space + covered transition hops for the chain phase." },
      max_hops: { type: "integer", minimum: 1, maximum: 8, description: "covered_paths mode: max hops per enumerated path (default 4)." },
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
