"use strict";

const { readSurfaceLeads } = require("../surface-leads.js");

module.exports = Object.freeze({
  name: "bob_read_surface_leads",
  aliases: ["bounty_read_surface_leads"],
  description:
    "Read compact ranked surface leads from session-owned surface-leads.json, including high-confidence unpromoted lead debt.",
  inputSchema: {
    type: "object",
    properties: {
      target_domain: { type: "string" },
      limit: { type: "integer", minimum: 1, maximum: 200 },
    },
    required: ["target_domain"],
  },
  handler: readSurfaceLeads,
  role_bundles: ["evaluator-web", "orchestrator"],
  mutating: false,
  global_preapproval: true,
  network_access: false,
  browser_access: false,
  scope_required: false,
  sensitive_output: false,
  session_artifacts_written: [],
});
