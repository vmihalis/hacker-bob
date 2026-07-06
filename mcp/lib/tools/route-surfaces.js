"use strict";

const { routeSurfaces } = require("../surface-router.js");
// S1: the id-bearing detector is required HERE (a tool handler, outside the
// lead-closure) and injected into routeSurfaces, so surface-router.js never
// takes a require edge to the alias-require-reaching offensive module.
const { surfaceExposesIdBearingCollection, surfaceIdBearingEndpoints } = require("../offensive-idor-producer.js");

module.exports = Object.freeze({
  name: "bob_route_surfaces",
  description: "Classify attack_surface.json entries into MCP-owned capability packs and write surface-routes.json.",
  inputSchema: {
    type: "object",
    properties: {
      target_domain: { type: "string" },
    },
    required: ["target_domain"],
  },
  handler: (args) => routeSurfaces(args, {
    idBearingDetector: surfaceExposesIdBearingCollection,
    idBearingEndpoints: surfaceIdBearingEndpoints,
  }),
  role_bundles: ["orchestrator", "router"],
  mutating: true,
  global_preapproval: false,
  network_access: false,
  browser_access: false,
  scope_required: false,
  sensitive_output: false,
  session_artifacts_written: ["surface-routes.json"],
});
