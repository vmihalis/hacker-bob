"use strict";

// chain+evaluator-shared justified: chain-builder needs graph mutation/query authority via the chain bundle (rev 4.1 defect 3 absorption); single-spawner topology preserved per Y.9 chain-bundle audit. This tool only grants `chain` + `orchestrator` (no evaluator-shared); the justification comment is recorded here for the Y.11 chain-bundle authority absorption audit trail.

const { appendChainNode } = require("../chain-state-tree.js");

function appendChainNodeHandler(args) {
  return appendChainNode({
    target_domain: args.target_domain,
    parent_state_hash: args.parent_state_hash,
    action: args.action,
    observed: args.observed,
    verdict: args.verdict,
    replay_budget: args.replay_budget,
    notes: args.notes,
  });
}

module.exports = Object.freeze({
  name: "bob_append_chain_node",
  aliases: ["bounty_append_chain_node"],
  capability_id: "I7_chain_state_tree",
  description:
    "Record one node in the content-addressed chain state tree. node_hash is computed from (parent_state_hash, action_canonical) so re-recording the same attempt is idempotent. state_hash is computed from (node_hash, observed_canonical) so a child can pin to it for backtracking. Pass parent_state_hash from a prior node's state_hash to extend a branch; omit to anchor at the root.",
  inputSchema: {
    type: "object",
    properties: {
      target_domain: { type: "string" },
      parent_state_hash: {
        type: "string",
        description: "state_hash from a prior chain node, or omit to anchor at the tree root.",
      },
      action: {
        type: "object",
        description: "Canonical action descriptor. kind is required; target/payload/description are optional.",
        properties: {
          kind: { type: "string" },
          target: { type: "string" },
          payload: {},
          description: { type: "string" },
        },
        required: ["kind"],
      },
      observed: {
        type: "object",
        description: "Optional observed outcome. When present, state_hash is computed from (node_hash, observed_canonical).",
      },
      verdict: {
        type: "string",
        enum: ["pending", "success", "failure", "pruned", "branched"],
      },
      replay_budget: { type: "number" },
      notes: { type: "string" },
    },
    required: ["target_domain", "action"],
  },
  handler: appendChainNodeHandler,
  // Y.11 (rev 4.1 defect 3): "chain" added so chain-builder can append
  // chain-state-tree nodes via the graph apparatus rather than
  // hand-writing chain-tree.jsonl. Y-P8 single-spawner topology
  // preserved — the chain bundle grants tool access, not dispatch
  // authority.
  role_bundles: ["orchestrator", "chain"],
  mutating: true,
  global_preapproval: false,
  network_access: false,
  browser_access: false,
  scope_required: false,
  sensitive_output: false,
  session_artifacts_written: ["chain-tree.jsonl"],
});
