"use strict";

const { frontier } = require("../chain-state-tree.js");

function chainFrontierHandler(args) {
  return frontier({
    target_domain: args.target_domain,
    include_pruned: args.include_pruned,
    limit: args.limit,
  });
}

module.exports = Object.freeze({
  name: "bob_chain_frontier",
  aliases: ["bounty_chain_frontier"],
  capability_id: "I7_chain_state_tree",
  description:
    "Return the leaf nodes of the chain state tree (the live exploration frontier). Default excludes pruned leaves so dead branches don't pollute the next-action search; pass include_pruned: true to recover pruned tips for diagnostics.",
  inputSchema: {
    type: "object",
    properties: {
      target_domain: { type: "string" },
      include_pruned: { type: "boolean" },
      limit: { type: "integer", minimum: 1, maximum: 500 },
    },
    required: ["target_domain"],
  },
  handler: chainFrontierHandler,
  role_bundles: ["orchestrator"],
  mutating: false,
  global_preapproval: false,
  network_access: false,
  browser_access: false,
  scope_required: false,
  sensitive_output: false,
  session_artifacts_written: [],
});
