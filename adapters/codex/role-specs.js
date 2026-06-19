"use strict";

const { evaluatorRoleSpecs } = require("../../mcp/lib/capability-packs.js");

const CODEX_ROLE_SPECS = Object.freeze({
  "surface-discovery": Object.freeze({
    bob_role: "surface-discovery-agent",
    agent_type: "worker",
    lifecycle: "wait",
  }),
  "deep-surface-discovery": Object.freeze({
    bob_role: "deep-surface-discovery-agent",
    agent_type: "worker",
    lifecycle: "wait",
  }),
  "surface-router": Object.freeze({
    bob_role: "surface-router-agent",
    agent_type: "worker",
    lifecycle: "wait",
  }),
  evaluator: Object.freeze({
    bob_role: "evaluator-agent",
    agent_type: "worker",
    lifecycle: "async_wave",
    bob_agent_id_source: "wave-start result.data.assignments[].agent",
  }),
  // Per-chain evaluator Codex role specs derived from EVALUATOR_ROLES. Multiple
  // capability packs that share a role_id collapse to a single codex spec —
  // matching the role-model.js + Claude-role-renderer.js dedup. Adding a
  // new evaluator role auto-extends this object.
  ...Object.fromEntries(
    evaluatorRoleSpecs().map((role) => [
      role.role_id,
      Object.freeze({
        bob_role: role.name,
        agent_type: "worker",
        lifecycle: "async_wave",
        bob_agent_id_source: "wave-start result.data.assignments[].agent",
      }),
    ]),
  ),
  // Plane X Cycle X.10 — generic TaskGraph evaluator shell. Spawned by
  // the orchestrator via bob_prepare_node when graph-scheduled dispatch
  // hands off a Transition or Hypothesis node. The bob_agent_id_source
  // is the node_id returned by bob_prepare_node (the wave-scheduler's
  // assignment id is not used here — graph dispatch carries its own
  // node_id and prep_token).
  "evaluator-spawn": Object.freeze({
    bob_role: "evaluator-spawn",
    agent_type: "worker",
    lifecycle: "async_wave",
    bob_agent_id_source: "bob_prepare_node result.data.node_id",
  }),
  chain: Object.freeze({
    bob_role: "chain-builder",
    agent_type: "worker",
    lifecycle: "wait",
  }),
  "brutalist-verifier": Object.freeze({
    bob_role: "brutalist-verifier",
    agent_type: "worker",
    lifecycle: "wait",
  }),
  "balanced-verifier": Object.freeze({
    bob_role: "balanced-verifier",
    agent_type: "worker",
    lifecycle: "wait",
  }),
  "final-verifier": Object.freeze({
    bob_role: "final-verifier",
    agent_type: "worker",
    lifecycle: "wait",
  }),
  evidence: Object.freeze({
    bob_role: "evidence-agent",
    agent_type: "worker",
    lifecycle: "wait",
  }),
  grader: Object.freeze({
    bob_role: "grader",
    agent_type: "worker",
    lifecycle: "wait",
  }),
  reporter: Object.freeze({
    bob_role: "report-writer",
    agent_type: "worker",
    lifecycle: "wait",
  }),
});

function codexRoleSpec(roleId) {
  const spec = CODEX_ROLE_SPECS[roleId];
  if (!spec) throw new Error(`Missing Codex role spec for ${roleId}`);
  return spec;
}

module.exports = {
  CODEX_ROLE_SPECS,
  codexRoleSpec,
};
