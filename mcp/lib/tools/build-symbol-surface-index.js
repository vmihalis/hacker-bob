"use strict";

const { buildSymbolSurfaceIndex } = require("../symbol-surface-index.js");

function buildSymbolSurfaceIndexHandler(args) {
  return buildSymbolSurfaceIndex({
    target_domain: args.target_domain,
    route_records: args.route_records,
    surfaces: args.surfaces,
  });
}

module.exports = Object.freeze({
  name: "bob_build_symbol_surface_index",
  aliases: ["bounty_build_symbol_surface_index"],
  description:
    "Persist a per-target symbol-surface index from bob_extract_routes output and (optionally) attack_surface.json surfaces. Produces three lookup maps (by_file_line, by_file, by_surface) plus a content-addressed index_hash. The index drives bob_summarize_diff_impact for diff-aware regression evaluating.",
  inputSchema: {
    type: "object",
    properties: {
      target_domain: { type: "string" },
      route_records: {
        type: "array",
        description: "Routes from bob_extract_routes.routes, or any equivalent (file, line, framework, method, path, handler_hint?, edge_kind?) records.",
      },
      surfaces: {
        type: "array",
        description: "Optional. Surfaces from attack_surface.json. When omitted, the tool reads them from the target's attack_surface.json.",
      },
    },
    required: ["target_domain", "route_records"],
  },
  handler: buildSymbolSurfaceIndexHandler,
  role_bundles: ["orchestrator"],
  mutating: true,
  global_preapproval: false,
  network_access: false,
  browser_access: false,
  scope_required: false,
  sensitive_output: false,
  session_artifacts_written: ["symbol-surface-index.json"],
});
