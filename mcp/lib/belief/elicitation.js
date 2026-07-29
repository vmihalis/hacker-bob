"use strict";

// CB-B7 -- evidence-conditioned belief elicitation primitive.
//
// Bob runs inside a host coding-agent session tasked with a target, so the host
// agent IS the estimator. Elicitation is the agent emitting, during the turn it is
// already taking, a distribution over one latent's declared states with cited
// evidence_refs. There is no separate model or inference budget: the agent records
// its belief via a tool call. This module is the deterministic shell around that
// judgment -- it validates the distribution, forces advisory provenance, and
// provides the evidence-sensitivity gate. It never makes an LLM call itself.

const { hashCanonicalJson } = require("../verification-contracts.js");

const ELICITATION_MODEL_VERSION = "belief-elicitation.v1";
// An elicited belief is advisory: llm_inferred provenance, prior role. The
// authority.js guard refuses llm_inferred at role:evidence; this module never
// emits anything else.
const ELICITATION_PROVENANCE = "llm_inferred";
const ELICITATION_ROLE = "prior";
const PROB_SUM_TOLERANCE = 1e-6;
const MAX_STATES = 16;
const MAX_EVIDENCE_REFS = 32;
const DEFAULT_SENSITIVITY_THRESHOLD = 0.15;

function boundedString(value, name, max) {
  if (typeof value !== "string" || value.trim().length === 0) {
    throw new Error(`${name} is required`);
  }
  const trimmed = value.trim();
  if (trimmed.length > max) throw new Error(`${name} exceeds ${max} chars`);
  return trimmed;
}

// Validate + normalize an agent-elicited distribution over declared states.
function normalizeElicitation(input) {
  if (input == null || typeof input !== "object") {
    throw new Error("elicitation must be an object");
  }
  const latentId = boundedString(input.latent_id, "latent_id", 200);
  const latentType = boundedString(input.latent_type, "latent_type", 80);

  if (!Array.isArray(input.states) || input.states.length < 2 || input.states.length > MAX_STATES) {
    throw new Error(`states must be an array of 2..${MAX_STATES} declared state names`);
  }
  const states = input.states.map((s, i) => boundedString(s, `states[${i}]`, 80));
  const stateSet = new Set(states);
  if (stateSet.size !== states.length) throw new Error("states must be unique");

  const dist = input.distribution;
  if (dist == null || typeof dist !== "object" || Array.isArray(dist)) {
    throw new Error("distribution must be an object { state: probability }");
  }
  const keys = Object.keys(dist);
  if (keys.length !== states.length) {
    throw new Error("distribution must assign a probability to exactly the declared states");
  }
  let sum = 0;
  const normalized = {};
  for (const state of states) {
    if (!(state in dist)) throw new Error(`distribution missing declared state: ${state}`);
    const p = dist[state];
    if (typeof p !== "number" || !Number.isFinite(p) || p < 0 || p > 1) {
      throw new Error(`distribution[${state}] must be a probability in [0,1]`);
    }
    normalized[state] = p;
    sum += p;
  }
  if (Math.abs(sum - 1) > PROB_SUM_TOLERANCE) {
    throw new Error(`distribution must sum to 1 (got ${sum})`);
  }

  if (!Array.isArray(input.evidence_refs) || input.evidence_refs.length === 0) {
    throw new Error("evidence_refs is required (an elicited belief must cite the evidence it reasoned over)");
  }
  if (input.evidence_refs.length > MAX_EVIDENCE_REFS) {
    throw new Error(`evidence_refs exceeds ${MAX_EVIDENCE_REFS} entries`);
  }
  const evidenceRefs = input.evidence_refs
    .map((r, i) => boundedString(r, `evidence_refs[${i}]`, 500))
    .slice()
    .sort();

  const rationale = boundedString(input.rationale, "rationale", 2000);
  const modelId = input.model_id == null ? "host_agent" : boundedString(input.model_id, "model_id", 120);

  const body = {
    model_version: ELICITATION_MODEL_VERSION,
    latent_id: latentId,
    latent_type: latentType,
    states,
    distribution: normalized,
    evidence_refs: evidenceRefs,
    rationale,
    model_id: modelId,
    provenance: ELICITATION_PROVENANCE,
    role: ELICITATION_ROLE,
    advisory: true,
    derived: true,
  };
  return Object.freeze({ ...body, elicitation_hash: hashCanonicalJson(body) });
}

function l1Distance(before, after) {
  const states = new Set([...Object.keys(before), ...Object.keys(after)]);
  let total = 0;
  for (const s of states) total += Math.abs((after[s] || 0) - (before[s] || 0));
  return Number(total.toFixed(6));
}

// The evidence-sensitivity gate. Two elicitations on the same latent differing by
// exactly one cited evidence_ref. A `relevant` change must move the belief past a
// threshold (toward expected_shift_state if given); an irrelevant change must leave
// it flat. A belief invariant to relevant evidence is the regex with a model_id.
function evidenceSensitivity({ before, after, relevant, expected_shift_state, threshold = DEFAULT_SENSITIVITY_THRESHOLD }) {
  if (!before || !after || typeof before.distribution !== "object" || typeof after.distribution !== "object") {
    throw new Error("before/after must be normalized elicitations");
  }
  if (before.latent_id !== after.latent_id) {
    throw new Error("evidence sensitivity compares the same latent");
  }
  const l1 = l1Distance(before.distribution, after.distribution);
  const moved = l1 >= threshold;
  let towardExpected = true;
  if (expected_shift_state != null) {
    const b = before.distribution[expected_shift_state] || 0;
    const a = after.distribution[expected_shift_state] || 0;
    towardExpected = a > b;
  }
  const pass = relevant ? (moved && towardExpected) : !moved;
  return Object.freeze({
    l1_distance: l1,
    threshold,
    relevant: Boolean(relevant),
    moved,
    toward_expected: towardExpected,
    pass,
  });
}

module.exports = {
  ELICITATION_MODEL_VERSION,
  ELICITATION_PROVENANCE,
  ELICITATION_ROLE,
  DEFAULT_SENSITIVITY_THRESHOLD,
  normalizeElicitation,
  evidenceSensitivity,
};
