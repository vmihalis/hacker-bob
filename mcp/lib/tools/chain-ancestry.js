"use strict";

const { ancestry } = require("../chain-state-tree.js");

function chainAncestryHandler(args) {
  return ancestry({
    target_domain: args.target_domain,
    state_hash: args.state_hash,
    limit: args.limit,
  });
}

module.exports = Object.freeze({
  name: "bob_chain_ancestry",
  aliases: ["bounty_chain_ancestry"],
  capability_id: "I7_chain_state_tree",
  description:
    "Walk parent_state_hash links from a state_hash back to the chain tree root. Returns the lineage in newest-first order, capped at 25 by default (max 100). Use when explaining how a leaf state was reached or when rebuilding a chain for evidence.",
  inputSchema: {
    type: "object",
    properties: {
      target_domain: { type: "string" },
      state_hash: { type: "string" },
      limit: { type: "integer", minimum: 1, maximum: 100 },
    },
    required: ["target_domain", "state_hash"],
  },
  handler: chainAncestryHandler,
  role_bundles: ["orchestrator"],
  mutating: false,
  global_preapproval: false,
  network_access: false,
  browser_access: false,
  scope_required: false,
  sensitive_output: false,
  session_artifacts_written: [],
});
