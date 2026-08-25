"use strict";

const { normalizeElicitation } = require("../core/belief/elicitation.js");
const { writeBeliefSignalScratch } = require("../core/belief/authority.js");

// CB-B7: the host coding agent records its evidence-conditioned belief over one
// latent during the turn it is already taking. Advisory scratch only -- forced
// llm_inferred / role:prior, so the authority guard keeps it out of the belief
// window as evidence. Cites the evidence it reasoned over.
function elicitBeliefHandler(args) {
  const elicitation = normalizeElicitation(args || {});
  const written = writeBeliefSignalScratch({
    target_domain: (args || {}).target_domain,
    kind: "belief_signal",
    source: "CB-B7-elicitation",
    provenance: "llm_inferred",
    artifact_ref: `belief-window:${elicitation.latent_id}`,
    role: "prior",
    payload: {
      latent_id: elicitation.latent_id,
      latent_type: elicitation.latent_type,
      states: elicitation.states,
      distribution: elicitation.distribution,
      evidence_refs: elicitation.evidence_refs,
      rationale: elicitation.rationale,
      model_id: elicitation.model_id,
      elicitation_hash: elicitation.elicitation_hash,
    },
  });
  return {
    target_domain: written.target_domain,
    elicitation_hash: elicitation.elicitation_hash,
    signal_hash: written.signal_hash,
    latent_id: elicitation.latent_id,
    distribution: elicitation.distribution,
    provenance: "llm_inferred",
    role: "prior",
    advisory: true,
    derived: true,
  };
}

module.exports = Object.freeze({
  name: "bob_elicit_belief",
  capability_id: "CB-B7_belief_elicitation",
  description:
    "Record the host agent's evidence-conditioned belief over one latent's declared states as advisory belief scratch (llm_inferred, role:prior). Must cite evidence_refs. Non-gating: cannot enter the belief window as evidence, record claims, schedule work, or promote templates.",
  inputSchema: {
    type: "object",
    properties: {
      target_domain: { type: "string" },
      latent_id: { type: "string" },
      latent_type: { type: "string" },
      states: { type: "array", items: { type: "string" }, minItems: 2, maxItems: 16 },
      distribution: { type: "object" },
      evidence_refs: { type: "array", items: { type: "string" }, minItems: 1, maxItems: 32 },
      rationale: { type: "string" },
      model_id: { type: "string" },
    },
    required: ["target_domain", "latent_id", "latent_type", "states", "distribution", "evidence_refs", "rationale"],
  },
  handler: elicitBeliefHandler,
  role_bundles: ["orchestrator"],
  mutating: true,
  global_preapproval: false,
  network_access: false,
  browser_access: false,
  scope_required: false,
  sensitive_output: false,
  session_artifacts_written: ["belief-scratch/belief-signals.jsonl"],
});
