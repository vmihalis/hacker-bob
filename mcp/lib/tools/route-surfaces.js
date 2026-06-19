"use strict";

const { routeSurfaces } = require("../surface-router.js");

module.exports = Object.freeze({
  name: "bob_route_surfaces",
  aliases: ["bounty_route_surfaces"],
  description: "Classify attack_surface.json entries into MCP-owned capability packs and write surface-routes.json.",
  inputSchema: {
    type: "object",
    properties: {
      target_domain: { type: "string" },
    },
    required: ["target_domain"],
  },
  handler: routeSurfaces,
  role_bundles: ["orchestrator", "router"],
  mutating: true,
  global_preapproval: false,
  network_access: false,
  browser_access: false,
  scope_required: false,
  sensitive_output: false,
  session_artifacts_written: ["surface-routes.json"],
});
