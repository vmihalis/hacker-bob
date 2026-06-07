"use strict";

const { promoteSurfaceLeads } = require("../surface-leads.js");

module.exports = Object.freeze({
  name: "bob_promote_surface_leads",
  aliases: ["bounty_promote_surface_leads"],
  description:
    "Promote top-ranked entries from surface-leads.json into frontier surface events so later waves can assign them from surface-index.json.",
  inputSchema: {
    type: "object",
    properties: {
      target_domain: { type: "string" },
      limit: { type: "integer", minimum: 1, maximum: 50 },
      min_score: { type: "integer", minimum: 0, maximum: 100 },
      include_medium: { type: "boolean" },
      update_state: { type: "boolean" },
    },
    required: ["target_domain"],
  },
  handler: promoteSurfaceLeads,
  role_bundles: ["orchestrator"],
  mutating: true,
  global_preapproval: false,
  network_access: false,
  browser_access: false,
  scope_required: false,
  sensitive_output: false,
  session_artifacts_written: ["surface-leads.json", "frontier-events.jsonl", "surface-index.json", "task-queue.json", "task-graph.json"],
});
