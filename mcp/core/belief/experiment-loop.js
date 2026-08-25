"use strict";

const crypto = require("crypto");
const {
  appendHypothesisProposal,
} = require("../waves/task-graph-events.js");
const {
  scheduleMaterialization,
} = require("../frontier/frontier-materialize-debounce.js");
const {
  rankInterventions,
} = require("./intervention-calculus.js");
const {
  _internals,
} = require("./authority.js");

const EXPERIMENT_LOOP_MODEL_VERSION = "belief-experiment-loop.v1";
const DEFAULT_MAX_ITERATIONS = 1;
const MAX_ITERATIONS = 5;

function sha256Hex(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function normalizePositiveInteger(value, fallback, max) {
  if (!Number.isInteger(value) || value <= 0) return fallback;
  return Math.min(value, max);
}

function surfaceRefForCandidate(candidate) {
  return `surface:belief-${sha256Hex(candidate.variable_id).slice(0, 12)}`;
}

function hypothesisStatement(candidate) {
  if (candidate.intervention === "public_object_check") {
    return "Check whether the selected object is intentionally public before treating authorization divergence as IDOR.";
  }
  if (candidate.intervention === "principal_fixed_object_swap") {
    return "Test whether a fixed attacker principal can access a victim object by changing only the object selector.";
  }
  return `Run ${candidate.intervention} as a discriminating object-authorization control.`;
}

function suggestedContractForCandidate(candidate, calculus) {
  return Object.freeze({
    version: 1,
    source: "belief_experiment_loop",
    model_version: EXPERIMENT_LOOP_MODEL_VERSION,
    calculus_hash: calculus.calculus_hash,
    window_hash: calculus.window_hash,
    production_paths: Object.freeze([
      candidate.do_operation.assignment,
    ]),
    witnesses: Object.freeze([
      Object.freeze({
        kind: "relational_value_match",
        variable_id: candidate.variable_id,
        control: candidate.intervention,
        expected_state: candidate.predicted_effect.expected_state,
      }),
    ]),
    intervention: Object.freeze({
      intervention: candidate.intervention,
      do_operation: candidate.do_operation,
      predicted_effect: candidate.predicted_effect,
      expected_information_gain_bits: candidate.expected_information_gain_bits,
    }),
    controls: candidate.controls,
    confounders_discriminated: candidate.confounders_discriminated,
    advisory: true,
  });
}

function planBeliefExperiment({ target_domain, seed, rank_limit, max_iterations, dry_run = false } = {}) {
  const iterationLimit = normalizePositiveInteger(max_iterations, DEFAULT_MAX_ITERATIONS, MAX_ITERATIONS);
  const calculus = rankInterventions({ target_domain, seed, rank_limit });
  const selected = calculus.ranking.slice(0, iterationLimit);
  const proposals = [];
  for (const [index, candidate] of selected.entries()) {
    const proposal = {
      target_domain: calculus.target_domain,
      hypothesis_statement: hypothesisStatement(candidate),
      surface_refs: [surfaceRefForCandidate(candidate)],
      proposal_id: `HP-CB-B3-${sha256Hex(`${calculus.calculus_hash}:${candidate.candidate_id}:${index}`).slice(0, 16)}`,
      suggested_contract: suggestedContractForCandidate(candidate, calculus),
      source: {
        kind: "belief_experiment_loop",
        calculus_hash: calculus.calculus_hash,
        candidate_id: candidate.candidate_id,
      },
      actor: "belief-experiment-loop",
    };
    if (dry_run) {
      proposals.push(Object.freeze({
        appended: false,
        event_id: null,
        proposal,
        candidate,
      }));
      continue;
    }
    const event = appendHypothesisProposal(proposal);
    try {
      scheduleMaterialization(event.target_domain);
    } catch {
      // Materialization debounce is best-effort; the proposal event is the authority.
    }
    proposals.push(Object.freeze({
      appended: true,
      event_id: event.event_id,
      event_hash: event.event_hash,
      proposal,
      candidate,
    }));
  }
  const body = {
    model_version: EXPERIMENT_LOOP_MODEL_VERSION,
    target_domain: calculus.target_domain,
    window_hash: calculus.window_hash,
    calculus_hash: calculus.calculus_hash,
    seed: calculus.seed,
    max_iterations: iterationLimit,
    dry_run: Boolean(dry_run),
    proposals: Object.freeze(proposals),
    loop_bound_reached: selected.length >= iterationLimit,
    advisory: true,
    derived: true,
    dispatch_authority: false,
    claim_authority: false,
    writer_authority: "bob_propose_hypothesis",
  };
  return Object.freeze({
    ...body,
    loop_hash: sha256Hex(_internals.canonicalJson(body)),
  });
}

module.exports = {
  EXPERIMENT_LOOP_MODEL_VERSION,
  MAX_ITERATIONS,
  planBeliefExperiment,
};
