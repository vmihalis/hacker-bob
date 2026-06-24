"use strict";

const crypto = require("crypto");
const {
  buildFactorGraphSample,
} = require("./factor-graph.js");
const {
  buildBeliefWindow,
} = require("./belief-window.js");
const {
  queryFrontierTypedFacts,
} = require("./frontier-facts.js");
const {
  writeBeliefSignalScratch,
  _internals,
} = require("./authority.js");

const RESIDUAL_MODEL_VERSION = "belief-residual.v1";
const DEFAULT_DECOMPOSITION_LIMIT = 25;
const MAX_DECOMPOSITION_LIMIT = 100;
const MAX_EXECUTED_PROVENANCE = 25;
const MAX_UNMAPPED_FACTS = 25;

// An observed frontier fact is "modeled" when some window latent was built from
// it — i.e. a latent's scope.source_event_id equals the fact's source_event_id.
// All three fact-sourced builders (object_ownership, request_equivalence, and the
// open-vocab unknown-mechanism mint) stamp source_event_id onto the latent scope,
// so a fact whose source_event_id is absent from every latent scope produced NO
// latent: it mapped to no home. This is the closed-world vanish — a real
// observation the modeled vocabulary, even with the open-vocab catch-all, had no
// shape for. The reason below NOTICES that vanish instead of silently dropping it.
const UNMAPPED_FACT_REASON = "observed_fact_maps_to_no_latent";

// Circularity guard: a residual is built by SAMPLING the window's own
// marginals (buildFactorGraphSample/inferMarginals), so on its own it is
// self-generated belief — admitting it to the scheduler would let belief reorder
// dispatch from belief. The ONLY outcomes that may move dispatch order are
// EXECUTED ones, so a residual hint is scheduler-admissible only when its
// provenance chain cites at least one executed outcome: a verified_intervention
// belief signal, a realized dead-end (bob_log_dead_ends), or a realized-vs-predicted
// coverage delta. Each citation is {kind, artifact_ref}; a residual built purely
// from self-sampling cites nothing and is recorded but NOT admissible.
const EXECUTED_PROVENANCE_KINDS = Object.freeze([
  "verified_intervention",
  "dead_end",
  "coverage_delta",
]);

function normalizeExecutedProvenance(value) {
  if (!Array.isArray(value)) return [];
  const seen = new Set();
  const out = [];
  for (const entry of value) {
    if (!entry || typeof entry !== "object" || Array.isArray(entry)) continue;
    const kind = typeof entry.kind === "string" ? entry.kind.trim() : "";
    const artifactRef = typeof entry.artifact_ref === "string" ? entry.artifact_ref.trim() : "";
    if (!EXECUTED_PROVENANCE_KINDS.includes(kind)) continue;
    if (!artifactRef) continue;
    const dedupeKey = `${kind}:${artifactRef}`;
    if (seen.has(dedupeKey)) continue;
    seen.add(dedupeKey);
    out.push(Object.freeze({ kind, artifact_ref: artifactRef }));
    if (out.length >= MAX_EXECUTED_PROVENANCE) break;
  }
  return out;
}

function sha256Hex(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function normalizePositiveInteger(value, fallback, max) {
  if (!Number.isInteger(value) || value <= 0) return fallback;
  return Math.min(value, max);
}

function maxMass(distribution) {
  let max = 0;
  for (const value of Object.values(distribution || {})) {
    const number = Number(value) || 0;
    if (number > max) max = number;
  }
  return max;
}

function negativeLog2Likelihood(probability) {
  const p = Math.max(Number(probability) || 0, 1e-9);
  return Number((-Math.log2(p)).toFixed(6));
}

function decomposeMarginal(marginal) {
  const likelihood = maxMass(marginal.marginal);
  const surprise = negativeLog2Likelihood(likelihood);
  const score = Number((surprise + marginal.entropy_bits).toFixed(6));
  return Object.freeze({
    variable_id: marginal.variable_id,
    variable_type: marginal.type,
    scope: marginal.scope,
    likelihood,
    negative_log2_likelihood: surprise,
    entropy_bits: marginal.entropy_bits,
    residual_score: score,
    reason: "low_max_marginal_mass_plus_entropy",
  });
}

function classifyResidual(score) {
  if (score >= 1.5) return "high";
  if (score >= 0.75) return "medium";
  return "low";
}

// Collect the set of source_event_ids that DID produce a latent this window.
function modeledSourceEventIds(window) {
  const ids = new Set();
  for (const variable of (window && window.variables) || []) {
    const scope = variable && variable.scope;
    const sourceEventId = scope && typeof scope.source_event_id === "string"
      ? scope.source_event_id.trim()
      : "";
    if (sourceEventId) ids.add(sourceEventId);
  }
  return ids;
}

// Find observed frontier facts that mapped to NO latent. A fact is unmapped when
// its source_event_id is absent from the set of latent-producing source_event_ids
// AND the fact actually carries a usable source_event_id (a fact with none can
// never be matched to its mint, so it is conservatively treated as unmapped — it
// still vanished from the modeled set). Deterministic order: by source_event_id.
function findUnmappedFacts(window, facts) {
  const modeled = modeledSourceEventIds(window);
  const seen = new Set();
  const unmapped = [];
  for (const fact of facts || []) {
    const sourceEventId = typeof fact.source_event_id === "string" ? fact.source_event_id.trim() : "";
    if (sourceEventId && modeled.has(sourceEventId)) continue;
    const dedupeKey = fact.fact_id || sourceEventId || fact.artifact_ref || "";
    if (!dedupeKey || seen.has(dedupeKey)) continue;
    seen.add(dedupeKey);
    unmapped.push(Object.freeze({
      fact_id: fact.fact_id,
      source_event_id: sourceEventId || null,
      surface_id: fact.surface_id || null,
      observation_kind: fact.observation_kind || null,
      provenance: fact.provenance || null,
      artifact_ref: fact.artifact_ref || null,
      // A free-form statement the orchestrator can hand to bob_propose_hypothesis
      // verbatim. It is a CONJECTURE to investigate, never an assertion of impact.
      mint_hypothesis_statement:
        `Observed ${fact.observation_kind || "frontier"} fact on ${fact.surface_id || "an unknown surface"} `
        + "maps to no modeled belief latent; investigate whether it exposes a security-relevant mechanism.",
      mint_surface_refs: fact.surface_id ? [fact.surface_id] : [],
      reason: UNMAPPED_FACT_REASON,
    }));
    if (unmapped.length >= MAX_UNMAPPED_FACTS) break;
  }
  return unmapped
    .slice()
    .sort((a, b) => String(a.source_event_id || a.fact_id || "").localeCompare(String(b.source_event_id || b.fact_id || "")));
}

// High band for the unmapped residual is an ORDERING threshold, not a filter. The
// fraction of observed facts that vanished is the expectation-violation strength:
// a window where most observations have no modeled home is a stronger signal that
// the modeled vocabulary is missing a mechanism than one stray fact. RANK != BOUND:
// the band only RAISES dispatch priority of investigating the no-home facts; it
// never drops, bounds, or filters any fact — every unmapped fact is surfaced, the
// band only decides which the orchestrator should seed FIRST.
function classifyUnmappedBand(unmappedCount, totalFactCount) {
  if (unmappedCount === 0) return "none";
  const fraction = totalFactCount > 0 ? unmappedCount / totalFactCount : 1;
  if (fraction >= 0.5 || unmappedCount >= 5) return "high";
  if (fraction >= 0.2 || unmappedCount >= 2) return "medium";
  return "low";
}

function buildResidualDiagnostic({
  sample,
  target_domain,
  seed,
  sample_count,
  rank_limit,
  chain_depth,
  decomposition_limit,
  executed_provenance,
} = {}) {
  // Build the window once and thread it into the factor sample so the unmapped-fact
  // detection sees EXACTLY the latents the sample was drawn from (same window_hash).
  const beliefWindow = buildBeliefWindow({ target_domain });
  const factorSample = sample || buildFactorGraphSample({
    window: beliefWindow,
    target_domain,
    seed,
    sample_count,
    rank_limit,
    chain_depth,
  });
  // The observed frontier facts, compared against the window's latents, expose the
  // closed-world vanish: facts that produced no latent (no home). Surfacing them is
  // ADVISORY/SEEDING only — it MINTS nothing and CONFIRMS nothing.
  const observedFacts = queryFrontierTypedFacts({ target_domain }).facts || [];
  const unmappedFacts = findUnmappedFacts(beliefWindow, observedFacts);
  const unmappedBand = classifyUnmappedBand(unmappedFacts.length, observedFacts.length);
  const executedProvenance = normalizeExecutedProvenance(executed_provenance);
  // The hint is scheduler-admissible only when the residual cites an executed
  // outcome. Self-sampled-only residuals stay diagnostic/human-router but never move
  // dispatch order.
  const schedulerAdmissible = executedProvenance.length > 0;
  const limit = normalizePositiveInteger(
    decomposition_limit,
    DEFAULT_DECOMPOSITION_LIMIT,
    MAX_DECOMPOSITION_LIMIT,
  );
  const decomposition = Object.freeze((factorSample.marginals || [])
    .map(decomposeMarginal)
    .sort((a, b) => b.residual_score - a.residual_score || a.variable_id.localeCompare(b.variable_id))
    .slice(0, limit));
  const residualScore = decomposition.length
    ? Number((decomposition.reduce((sum, item) => sum + item.residual_score, 0) / decomposition.length).toFixed(6))
    : 0;
  const body = {
    model_version: RESIDUAL_MODEL_VERSION,
    target_domain: factorSample.target_domain,
    window_hash: factorSample.window_hash,
    sample_hash: factorSample.sample_hash,
    seed: factorSample.seed,
    sample_count: factorSample.sample_count,
    residual_score: residualScore,
    residual_band: classifyResidual(residualScore),
    provenance: "residual_anomaly",
    role: "diagnostic",
    decomposition,
    executed_provenance: Object.freeze(executedProvenance),
    scheduler_admissible: schedulerAdmissible,
    priority_hint: Object.freeze({
      sink: "CB-C1",
      score: residualScore,
      band: classifyResidual(residualScore),
      non_gating: true,
      dispatch_authority: false,
      // The scheduler reads ONLY this provenance chain (not the raw
      // self-sampled score) to decide admissibility — executed outcome or nothing.
      scheduler_admissible: schedulerAdmissible,
      executed_provenance: Object.freeze(executedProvenance),
    }),
    human_router_record: Object.freeze({
      route: "human_review",
      summary: `Residual ${classifyResidual(residualScore)}: modeled templates explain the top marginals with score ${residualScore}`,
      decomposition_count: decomposition.length,
      non_gating: true,
    }),
    // Closed-world vanish notice. The decomposition above ranks KNOWN-but-uncertain
    // latents; this block names observed facts that mapped to no latent at all. It is
    // a SEED, not a verdict: each unmapped fact carries a free-form statement the
    // orchestrator may pass verbatim to bob_propose_hypothesis to mint an ADVISORY
    // candidate (claim_authority:false). That candidate stays merely BELIEVED until an
    // executed differential confirms it; seeding proves nothing. RANK != BOUND: a
    // high band raises which no-home fact to investigate first; it drops no fact and
    // bounds no other coverage.
    unmapped_facts: Object.freeze({
      reason: UNMAPPED_FACT_REASON,
      band: unmappedBand,
      // ordering only — a high band reorders investigation priority of the no-home
      // facts; it is NOT a filter and removes nothing from the full list below.
      dispatch_priority_hint: unmappedBand === "high" ? "investigate_first" : "investigate_after_known",
      observed_fact_count: observedFacts.length,
      unmapped_count: unmappedFacts.length,
      facts: Object.freeze(unmappedFacts),
      // The advisory mint reuses the EXISTING free-form path; the residual builds no
      // tool of its own and asserts no authority.
      mint_tool: "bob_propose_hypothesis",
      claim_authority: false,
      dispatch_authority: false,
      template_promotion_authority: false,
      non_gating: true,
    }),
    advisory: true,
    derived: true,
    scratch: true,
    claim_authority: false,
    dispatch_authority: false,
    template_promotion_authority: false,
  };
  return Object.freeze({
    ...body,
    residual_hash: sha256Hex(_internals.canonicalJson(body)),
  });
}

function runBeliefResidual({ target_domain, seed, sample_count, rank_limit, chain_depth, decomposition_limit, executed_provenance } = {}) {
  const diagnostic = buildResidualDiagnostic({
    target_domain,
    seed,
    sample_count,
    rank_limit,
    chain_depth,
    decomposition_limit,
    executed_provenance,
  });
  const signal = writeBeliefSignalScratch({
    target_domain: diagnostic.target_domain,
    kind: "belief_signal",
    source: "mcp/lib/belief/residual.js#runBeliefResidual",
    provenance: "residual_anomaly",
    artifact_ref: `belief_sample:${diagnostic.sample_hash}`,
    role: "diagnostic",
    payload: {
      model_version: diagnostic.model_version,
      residual_hash: diagnostic.residual_hash,
      window_hash: diagnostic.window_hash,
      sample_hash: diagnostic.sample_hash,
      residual_score: diagnostic.residual_score,
      residual_band: diagnostic.residual_band,
      decomposition: diagnostic.decomposition,
      unmapped_facts: diagnostic.unmapped_facts,
      executed_provenance: diagnostic.executed_provenance,
      scheduler_admissible: diagnostic.scheduler_admissible,
      priority_hint: diagnostic.priority_hint,
      human_router_record: diagnostic.human_router_record,
      claim_authority: false,
      dispatch_authority: false,
      template_promotion_authority: false,
    },
  });
  return Object.freeze({
    ...diagnostic,
    signal_hash: signal.signal_hash,
    artifact_path: signal.artifact_path,
  });
}

module.exports = {
  RESIDUAL_MODEL_VERSION,
  EXECUTED_PROVENANCE_KINDS,
  UNMAPPED_FACT_REASON,
  findUnmappedFacts,
  classifyUnmappedBand,
  buildResidualDiagnostic,
  runBeliefResidual,
};
