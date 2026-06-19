"use strict";

const {
  readSurfaceRoutesStrict,
  countRoutesByCapabilityPack,
} = require("../surface-router.js");
const { assertNonEmptyString } = require("../validation.js");

function readSurfaceRoutes(args) {
  const domain = assertNonEmptyString(args.target_domain, "target_domain");
  const routed = readSurfaceRoutesStrict(domain);
  const document = routed.document;
  return JSON.stringify({
    target_domain: domain,
    surface_routes_path: routed.path,
    version: document.version,
    route_version: document.route_version,
    surface_count: document.routes.length,
    counts: countRoutesByCapabilityPack(document.routes),
    routes: document.routes,
  });
}

module.exports = Object.freeze({
  name: "bob_read_surface_routes",
  aliases: ["bounty_read_surface_routes"],
  description:
    "Read the MCP-owned surface-routes.json: per-surface capability_pack, evaluator_agent, brief_profile, confidence, and reasons. Use to dispatch verifier/chain/evidence/reporter prompts on assignment.capability_pack without re-deriving from surface_type or chain_family.",
  inputSchema: {
    type: "object",
    properties: {
      target_domain: { type: "string" },
    },
    required: ["target_domain"],
  },
  handler: readSurfaceRoutes,
  // Surface-router-agent (role bundle "router") writes routes via
  // bob_route_surfaces and exits — it does not need to re-read its own
  // writes. Downstream consumers (orchestrator + verifier/chain/evidence/
  // reporter) read via this tool.
  role_bundles: ["orchestrator", "verifier", "chain", "evidence", "reporter"],
  mutating: false,
  global_preapproval: true,
  network_access: false,
  browser_access: false,
  scope_required: false,
  sensitive_output: false,
  session_artifacts_written: [],
});
