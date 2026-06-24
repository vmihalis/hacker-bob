"use strict";

const crypto = require("crypto");
const {
  queryMechanismView,
} = require("../surface-graph.js");
const {
  getMechanismTemplate,
} = require("../invariant-template-corpus.js");
const {
  queryFrontierTypedFacts,
} = require("./frontier-facts.js");
const {
  queryBeliefSignals,
} = require("./authority.js");

const BELIEF_WINDOW_MODEL_VERSION = "belief-window.v1";

// Factor-mediated sibling propagation. A verified_intervention sharpens the exact-id
// latent (verifiedIndex, ~0.9); a SECOND pass then raises the priors of structural
// SIBLINGS — request_equivalence latents sharing the same {endpoint, method}
// structure as a verified latent — through the existing factor machinery. The raise
// is bounded so a sibling NEVER resolves and NEVER alone crosses a priority/severity
// band: it is capped well below the principal_policy_effect_path factor weight (0.5)
// and below the sharpen mass, and the absolute posterior delta is hard-capped.
const SIBLING_PROPAGATION_WEIGHT = 0.15;
const SIBLING_RAISE_CAP = 0.15;
// A latent is "resolved" only by an executed outcome (verifiedIndex ~0.9). The
// sibling raise, additive from the uniform 1/3 and capped at +0.15, reaches at most
// ~0.483 equivalent — strictly below this threshold, so a sibling is auditably never
// resolved by propagation.
const RESOLUTION_THRESHOLD = 0.7;

const DEFAULT_VARIABLE_LIMIT = 64;
const DEFAULT_FACTOR_LIMIT = 128;
const DEFAULT_FACT_LIMIT = 200;
const DEFAULT_SIZE_LIMIT_BYTES = 65536;

// The CURATED, KNOWN variable types — the four mechanism shapes the window knows
// how to derive structurally from the surface graph and typed facts. This is the
// known SUBSET, not the closed universe: an observed fact that carries a mechanism
// token outside this set is no longer dropped, it mints an open `unknown`-typed
// latent (see UNKNOWN_VARIABLE_TYPE / openTypeVariables). BELIEF_VARIABLE_TYPES
// stays exported for back-compat; the window emits BOTH known and observed-open
// types in variable_types.
const BELIEF_VARIABLE_TYPES = Object.freeze([
  "effective_permission",
  "object_ownership",
  "request_equivalence",
  "gate_effectiveness",
]);

// The catch-all open type. An untyped/open-mechanism fact mints a latent of this
// type with a generic ternary so it still gets an honest uniform prior rather than
// vanishing. Opening the vocab does NOT relax the confirm contract: an open-vocab
// latent's posterior comes only from uniformPrior or an elicited/verified index,
// so minting alone never raises it past RESOLUTION_THRESHOLD — it stays merely
// BELIEVED until an executed differential crosses the bar.
const UNKNOWN_VARIABLE_TYPE = "unknown";

// The known-plus-unknown set: the curated four plus the open catch-all. This is
// the type vocabulary the window may emit; an observed-open mechanism token is
// carried as an `unknown`-typed latent within this set.
const KNOWN_PLUS_UNKNOWN_VARIABLE_TYPES = Object.freeze([
  ...BELIEF_VARIABLE_TYPES,
  UNKNOWN_VARIABLE_TYPE,
]);

function canonicalJson(value) {
  if (Array.isArray(value)) {
    return `[${value.map(canonicalJson).join(",")}]`;
  }
  if (value && typeof value === "object") {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

function sha256Hex(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function stableId(prefix, body) {
  return `${prefix}-${sha256Hex(canonicalJson(body)).slice(0, 24)}`;
}

function beliefWindowTooLarge(message, details) {
  const err = new Error(message);
  err.code = "belief_window_too_large";
  err.details = details;
  return err;
}

function normalizeLimit(value, fallback, max) {
  if (!Number.isInteger(value) || value <= 0) return fallback;
  return Math.min(value, max);
}

function sortedEdges(edges) {
  return edges.slice().sort((a, b) => String(a.edge_hash || "").localeCompare(String(b.edge_hash || "")));
}

function sortedFacts(facts) {
  return facts.slice().sort((a, b) => String(a.fact_id || "").localeCompare(String(b.fact_id || "")));
}

function nodeKey(node) {
  return `${node.type}:${node.id}`;
}

// CB-B1: latent priors are the host agent's elicited belief (CB-B7) if it cited one
// for this exact latent, else an honest uniform over the declared states. No regex,
// no hardcoded guess -- the prior is evidence-derived or maximally uncertain.
const CANONICAL_STATES = Object.freeze({
  effective_permission: Object.freeze(["allowed", "blocked", "unknown"]),
  object_ownership: Object.freeze(["owned", "not_owned", "unknown"]),
  request_equivalence: Object.freeze(["equivalent", "distinct", "unknown"]),
  gate_effectiveness: Object.freeze(["effective", "ineffective", "unknown"]),
  // Generic ternary for an open/untyped fact: present / absent / unknown. A fact
  // we cannot map onto a curated mechanism shape still gets an honest uniform
  // prior over this set instead of being dropped.
  [UNKNOWN_VARIABLE_TYPE]: Object.freeze(["present", "absent", "unknown"]),
});

function uniformPrior(states) {
  const mass = Number((1 / states.length).toFixed(6));
  const dist = {};
  for (const state of states) dist[state] = mass;
  return Object.freeze(dist);
}

// Index host-agent elicited priors by latent_id (== the window variable_id).
function elicitedPriorIndex(targetDomain) {
  const index = new Map();
  let signals = [];
  try {
    signals = (queryBeliefSignals({ target_domain: targetDomain, provenance: "llm_inferred", role: "prior" }) || {}).signals || [];
  } catch {
    signals = [];
  }
  for (const signal of signals) {
    const payload = signal && signal.payload;
    if (payload && typeof payload.latent_id === "string" && payload.distribution && typeof payload.distribution === "object") {
      index.set(payload.latent_id, payload.distribution);
    }
  }
  return index;
}

// Index executed-outcome posteriors by latent_id (== the window variable_id).
// These come from outcome-bridge.js after a live verified_pass: provenance
// verified_intervention, role evidence. Only request_equivalence signals whose
// distribution names exactly the 3 canonical states (each a number) are admitted, so
// a malformed payload silently falls back to the prior (never a blanket shift).
function verifiedPosteriorIndex(targetDomain) {
  const index = new Map();
  const states = CANONICAL_STATES.request_equivalence;
  let signals = [];
  try {
    signals = (queryBeliefSignals({ target_domain: targetDomain, provenance: "verified_intervention", role: "evidence" }) || {}).signals || [];
  } catch {
    signals = [];
  }
  for (const signal of signals) {
    const payload = signal && signal.payload;
    if (!payload || typeof payload.latent_id !== "string") continue;
    if (payload.type && payload.type !== "request_equivalence") continue;
    const dist = payload.distribution;
    if (!dist || typeof dist !== "object") continue;
    if (Object.keys(dist).length !== states.length) continue;
    if (!states.every((s) => typeof dist[s] === "number")) continue;
    const distribution = {};
    for (const state of states) distribution[state] = dist[state];
    // Last writer wins (most recent verified_pass for the same latent).
    index.set(payload.latent_id, {
      distribution: Object.freeze(distribution),
      artifact_ref: typeof signal.artifact_ref === "string" ? signal.artifact_ref : null,
    });
  }
  return index;
}

function priorForLatent(type, scope, elicitedIndex) {
  const states = CANONICAL_STATES[type];
  const variableId = stableId("BV", { type, scope });
  const elicited = elicitedIndex && elicitedIndex.get(variableId);
  if (elicited && typeof elicited === "object"
    && Object.keys(elicited).length === states.length
    && states.every((s) => typeof elicited[s] === "number")) {
    const dist = {};
    for (const state of states) dist[state] = elicited[state];
    return { distribution: Object.freeze(dist), source: "elicited" };
  }
  return { distribution: uniformPrior(states), source: "uniform" };
}

// Shared request_equivalence scope normalizer. Producer (outcome-bridge) and
// consumer (requestEquivalenceVariables) MUST derive byte-identical scope so the
// verified-intervention signal keys to the exact window variable by construction.
//
// endpoint: a top-level observation selector (payload.endpoint/path) wins, then the
// recorded request's own selector (request.endpoint/path), else the request URL's
// pathname (joined onto base_url so a relative leaf url resolves). method: top-level
// method, else the recorded request.method, else UNKNOWN. source_event_id is the
// frontier observation event id (== typed-fact source_event_id == leaf evidence id).
function requestEquivalenceScope(payload, sourceEventId, baseUrl) {
  const body = payload && typeof payload === "object" ? payload : {};
  const request = body.request && typeof body.request === "object" ? body.request : {};
  let endpoint = body.endpoint || body.path || request.endpoint || request.path || null;
  if (!endpoint && typeof request.url === "string" && request.url) {
    const rawUrl = request.url;
    let joined = rawUrl;
    if (!/^https?:\/\//i.test(rawUrl) && typeof baseUrl === "string" && baseUrl) {
      const trimmedBase = baseUrl.replace(/\/+$/, "");
      joined = `${trimmedBase}${rawUrl.startsWith("/") ? "" : "/"}${rawUrl}`;
    }
    try {
      endpoint = new URL(joined).pathname;
    } catch {
      const qIndex = rawUrl.indexOf("?");
      endpoint = qIndex === -1 ? rawUrl : rawUrl.slice(0, qIndex);
    }
  }
  const method = body.method || request.method || null;
  return {
    endpoint: String(endpoint || "unknown"),
    method: String(method || "UNKNOWN"),
    source_event_id: sourceEventId,
  };
}

// The structural key of a request_equivalence scope: the {endpoint, method} of the
// observed request, EXCLUDING source_event_id (the per-observation identity). Two
// latents are structural SIBLINGS iff they share this key — i.e. they probe the same
// endpoint+method (the structure of the verified flip), differing only by observation.
function structureKey(scope) {
  return canonicalJson({
    endpoint: scope && scope.endpoint,
    method: scope && scope.method,
  });
}

// Does this observation payload carry anything the request_equivalence latent can key
// on (a top-level selector/method, or a recorded request)?
function hasRequestEquivalenceSignal(payload) {
  const body = payload && typeof payload === "object" ? payload : {};
  if (body.endpoint || body.path || body.method) return true;
  const request = body.request && typeof body.request === "object" ? body.request : null;
  return !!(request && (request.url || request.endpoint || request.path || request.method));
}

// Build a window variable. The vocab is OPEN: `type` may be any non-empty string
// (a curated known type or an observed-open mechanism token), so this validates
// the SHAPE rather than asserting a closed enum. A minted variable of an open type
// is frozen identically and carries prior_source. The shape contract:
//   - type is a non-empty string;
//   - states is a non-empty array of distinct non-empty strings;
//   - posterior is a distribution over EXACTLY those states (each a number);
//   - scope is an object.
// A malformed shape is refused so opening the vocab cannot smuggle in a degenerate
// latent.
function makeVariable(type, scope, posterior, evidenceRefs, priorSource = "uniform") {
  if (typeof type !== "string" || !type.trim()) {
    throw new Error("belief variable type must be a non-empty string");
  }
  if (!scope || typeof scope !== "object" || Array.isArray(scope)) {
    throw new Error(`belief variable ${type} scope must be an object`);
  }
  if (!posterior || typeof posterior !== "object" || Array.isArray(posterior)) {
    throw new Error(`belief variable ${type} posterior must be a distribution object`);
  }
  const states = Object.keys(posterior);
  if (states.length === 0
    || states.some((s) => typeof s !== "string" || !s.trim())
    || new Set(states).size !== states.length) {
    throw new Error(`belief variable ${type} states must be a non-empty array of distinct non-empty strings`);
  }
  if (states.some((s) => typeof posterior[s] !== "number")) {
    throw new Error(`belief variable ${type} posterior must be a number over exactly its states`);
  }
  return Object.freeze({
    variable_id: stableId("BV", { type, scope }),
    type,
    states: Object.freeze(states),
    scope: Object.freeze(scope),
    posterior,
    prior_source: priorSource,
    evidence_refs: Object.freeze(Array.from(new Set(evidenceRefs)).sort()),
  });
}

function makeFactor(kind, variableIds, provenance, artifactRefs, weight) {
  return Object.freeze({
    factor_id: stableId("BF", { kind, variableIds, artifactRefs }),
    kind,
    variable_ids: Object.freeze(variableIds.slice().sort()),
    provenance,
    artifact_refs: Object.freeze(Array.from(new Set(artifactRefs)).sort()),
    weight,
  });
}

function principalPolicyEdges(edges) {
  return edges.filter((edge) => (
    edge.source && edge.source.type === "principal"
    && edge.target && edge.target.type === "policy_gate"
  ));
}

function policyEffectEdges(edges) {
  return edges.filter((edge) => (
    edge.source && edge.source.type === "policy_gate"
    && edge.target && edge.target.type === "effect"
  ));
}

function objectOwnershipVariables(facts, elicitedIndex) {
  const variables = [];
  for (const fact of facts) {
    const payload = fact.payload || {};
    const principal = payload.principal || payload.owner || payload.owner_id;
    const object = payload.object || payload.object_id || payload.object_selector;
    if (!principal || !object) continue;
    const scope = { principal: String(principal), object: String(object), source_event_id: fact.source_event_id };
    const prior = priorForLatent("object_ownership", scope, elicitedIndex);
    variables.push(makeVariable("object_ownership", scope, prior.distribution, [fact.artifact_ref], prior.source));
  }
  return variables;
}

// Does this typed fact carry an explicit mechanism/type token, and is that token
// OUTSIDE the curated known set? Such a fact names a mechanism the window has no
// curated shape for. Today it would vanish (no known-shape builder fires); the
// open-vocab path mints an `unknown`-typed latent from it instead of dropping it.
// The token is read from a small set of payload fields a producer may use to
// declare a mechanism class; only a token NOT in the known set qualifies (a known
// token is already covered by its structural builder).
function openMechanismToken(payload) {
  const body = payload && typeof payload === "object" ? payload : {};
  const raw = body.mechanism_type || body.belief_type || body.mechanism_class;
  if (typeof raw !== "string" || !raw.trim()) return null;
  const token = raw.trim();
  if (BELIEF_VARIABLE_TYPES.includes(token)) return null;
  return token;
}

// Mint an `unknown`-typed latent for every fact carrying an open mechanism token.
// The latent's posterior is an honest uniform over the generic ternary (or an
// elicited prior if the host cited one) — there is NO path where minting raises it
// past RESOLUTION_THRESHOLD, so an open-vocab latent stays merely BELIEVED until
// an executed differential confirms it. The observed token is preserved on the
// scope so two distinct open mechanisms key to distinct latents (rank, don't drop).
function openTypeVariables(facts, elicitedIndex) {
  const variables = [];
  for (const fact of facts) {
    const payload = fact.payload || {};
    const token = openMechanismToken(payload);
    if (!token) continue;
    const scope = {
      mechanism_token: token,
      source_event_id: fact.source_event_id,
    };
    const prior = priorForLatent(UNKNOWN_VARIABLE_TYPE, scope, elicitedIndex);
    variables.push(makeVariable(UNKNOWN_VARIABLE_TYPE, scope, prior.distribution, [fact.artifact_ref], prior.source));
  }
  return variables;
}

function requestEquivalenceVariables(facts, elicitedIndex, verifiedIndex, baseUrl) {
  const variables = [];
  for (const fact of facts) {
    const payload = fact.payload || {};
    if (!hasRequestEquivalenceSignal(payload)) continue;
    const scope = requestEquivalenceScope(payload, fact.source_event_id, baseUrl);
    const variableId = stableId("BV", { type: "request_equivalence", scope });
    // Executed-outcome evidence (a live verified_pass) sharpens this exact latent.
    // ONLY request_equivalence consults the verified index, and only by exact id, so
    // a verified_pass moves the matching latent and nothing else; an absent match
    // falls back to the elicited/uniform prior untouched.
    const verified = verifiedIndex && verifiedIndex.get(variableId);
    if (verified) {
      const states = CANONICAL_STATES.request_equivalence;
      const posterior = {};
      for (const state of states) posterior[state] = verified.distribution[state];
      const evidenceRefs = [fact.artifact_ref];
      if (verified.artifact_ref) evidenceRefs.push(verified.artifact_ref);
      variables.push(makeVariable(
        "request_equivalence",
        scope,
        Object.freeze(posterior),
        evidenceRefs,
        "verified_intervention",
      ));
      continue;
    }
    const prior = priorForLatent("request_equivalence", scope, elicitedIndex);
    variables.push(makeVariable("request_equivalence", scope, prior.distribution, [fact.artifact_ref], prior.source));
  }
  return variables;
}

// Factor-mediated sibling propagation. Runs ONLY when at least one verified_intervention
// latent exists (verifiedIndex non-empty produced one). For each structural group keyed
// by {endpoint, method}, a verified latent V raises the priors of its still-present,
// non-verified request_equivalence SIBLINGS S (same structureKey, different variable_id)
// by a bounded, capped nudge toward `equivalent`, and emits one factor per (V, S) pair.
//
// Returns { variables, factors }: the variables array is the SAME set with raised
// siblings rebuilt in place (never added/dropped — covered-set-at-fixpoint), and factors
// are the new verified_sibling_equivalence carriers. The raise per sibling is computed
// ONCE from the structure group (deduped by structureKey), so N verified siblings of the
// same structure produce ONE capped raise — additive, idempotent, hard-ceilinged.
function propagateVerifiedSiblings(variables) {
  const requestEquivalence = variables.filter((v) => v.type === "request_equivalence");
  if (requestEquivalence.length === 0) return { variables, factors: [] };

  // Group request_equivalence latents by structure, partitioning verified vs. siblings.
  const groups = new Map();
  for (const v of requestEquivalence) {
    const key = structureKey(v.scope);
    if (!groups.has(key)) groups.set(key, { verified: [], siblings: [] });
    const bucket = groups.get(key);
    if (v.prior_source === "verified_intervention") bucket.verified.push(v);
    else bucket.siblings.push(v);
  }

  // raisedById maps a sibling variable_id to its rebuilt (raised) variable.
  const raisedById = new Map();
  const factors = [];
  // Canonical, deterministic iteration: sorted structureKey, then sorted variable_id.
  for (const key of [...groups.keys()].sort()) {
    const group = groups.get(key);
    if (group.verified.length === 0 || group.siblings.length === 0) continue;
    const verified = group.verified.slice().sort((a, b) => a.variable_id.localeCompare(b.variable_id));
    const siblings = group.siblings.slice().sort((a, b) => a.variable_id.localeCompare(b.variable_id));
    // The verified target equivalent mass is the sharpened distribution of the verified
    // anchor (~0.9, the VERIFIED_EQUIVALENT_DISTRIBUTION produced by the exact-id
    // sharpen). Deterministic: max over the group's verified latents.
    const verifiedEquivalent = Math.max(...verified.map((v) => v.posterior.equivalent));
    for (const sibling of siblings) {
      const current = sibling.posterior.equivalent;
      // Bounded nudge toward equivalent, computed ONCE from S's current prior; the
      // absolute delta is hard-capped at SIBLING_RAISE_CAP so a sibling can move at
      // most +0.15 toward equivalent regardless of how many verified siblings point
      // at it. The raise mass is removed proportionally from the other two states so
      // the distribution stays normalized to 1.0 (toFixed(6) like uniformPrior).
      const raise = Math.min(
        SIBLING_RAISE_CAP,
        SIBLING_PROPAGATION_WEIGHT * (verifiedEquivalent - current),
      );
      const raisedSibling = raise > 0
        ? rebuildSiblingRaised(sibling, raise)
        : sibling;
      raisedById.set(sibling.variable_id, raisedSibling);
      // One factor per (V, S) pair through the EXISTING makeFactor path. The factor
      // is the auditable carrier; the prior raise above is the bounded effect.
      for (const v of verified) {
        const artifactRefs = v.evidence_refs.filter((ref) => typeof ref === "string");
        factors.push(makeFactor(
          "verified_sibling_equivalence",
          [v.variable_id, sibling.variable_id],
          "verified_intervention_propagation",
          artifactRefs,
          SIBLING_PROPAGATION_WEIGHT,
        ));
      }
    }
  }

  if (raisedById.size === 0) return { variables, factors: [] };
  const rebuilt = variables.map((v) => raisedById.get(v.variable_id) || v);
  return { variables: rebuilt, factors };
}

// Rebuild a sibling latent with a bounded raise toward `equivalent`, removing the raise
// mass proportionally from the other two states so the distribution sums to 1.0, and
// marking prior_source "sibling_propagated" (auditably NOT a resolved latent). The raise
// is additive and capped, so equivalent can never reach the resolution threshold.
function rebuildSiblingRaised(sibling, raise) {
  const states = CANONICAL_STATES.request_equivalence; // [equivalent, distinct, unknown]
  const before = sibling.posterior;
  const otherMass = before.distinct + before.unknown;
  const posterior = {};
  posterior.equivalent = Number((before.equivalent + raise).toFixed(6));
  if (otherMass > 0) {
    // Proportional removal keeps the relative shape of (distinct, unknown).
    posterior.distinct = Number((before.distinct - raise * (before.distinct / otherMass)).toFixed(6));
    posterior.unknown = Number((before.unknown - raise * (before.unknown / otherMass)).toFixed(6));
  } else {
    posterior.distinct = before.distinct;
    posterior.unknown = before.unknown;
  }
  // Order keys canonically (equivalent, distinct, unknown) to match makeVariable shape.
  const ordered = {};
  for (const state of states) ordered[state] = posterior[state];
  return makeVariable(
    "request_equivalence",
    sibling.scope,
    Object.freeze(ordered),
    sibling.evidence_refs,
    "sibling_propagated",
  );
}

function buildBeliefWindow({
  target_domain,
  template_id = "object_authorization",
  variable_limit,
  factor_limit,
  fact_limit,
  size_limit_bytes,
  base_url,
} = {}) {
  const variableLimit = normalizeLimit(variable_limit, DEFAULT_VARIABLE_LIMIT, DEFAULT_VARIABLE_LIMIT);
  const factorLimit = normalizeLimit(factor_limit, DEFAULT_FACTOR_LIMIT, DEFAULT_FACTOR_LIMIT);
  const factLimit = normalizeLimit(fact_limit, DEFAULT_FACT_LIMIT, DEFAULT_FACT_LIMIT);
  const sizeLimit = normalizeLimit(size_limit_bytes, DEFAULT_SIZE_LIMIT_BYTES, DEFAULT_SIZE_LIMIT_BYTES);
  // Pass target_domain so a registered tier-3 candidate is resolvable alongside
  // the frozen tier-2 corpus base. The window body emits the template's tier so a
  // downstream consumer treats a tier-3 template as advisory-only.
  const template = getMechanismTemplate(template_id, target_domain);
  if (!template) {
    throw new Error(`unknown mechanism template: ${template_id}`);
  }
  const mechanism = queryMechanismView({ target_domain, limit: 1000 });
  const edges = sortedEdges(mechanism.edges || []);
  const typedFacts = sortedFacts(queryFrontierTypedFacts({ target_domain, limit: factLimit }).facts);
  const variables = [];
  const factors = [];
  const elicitedIndex = elicitedPriorIndex(target_domain);
  const verifiedIndex = verifiedPosteriorIndex(target_domain);

  const policyToEffects = new Map();
  for (const edge of policyEffectEdges(edges)) {
    const key = nodeKey(edge.source);
    if (!policyToEffects.has(key)) policyToEffects.set(key, []);
    policyToEffects.get(key).push(edge);
  }

  for (const principalEdge of principalPolicyEdges(edges)) {
    const effects = policyToEffects.get(nodeKey(principalEdge.target)) || [];
    for (const effectEdge of effects) {
      const evidenceRefs = [
        `surface_graph:${principalEdge.edge_hash}`,
        `surface_graph:${effectEdge.edge_hash}`,
      ];
      const epScope = {
        principal_id: principalEdge.source.id,
        policy_gate_id: principalEdge.target.id,
        effect_id: effectEdge.target.id,
      };
      const epPrior = priorForLatent("effective_permission", epScope, elicitedIndex);
      const variable = makeVariable("effective_permission", epScope, epPrior.distribution, evidenceRefs, epPrior.source);
      variables.push(variable);
      factors.push(makeFactor(
        "principal_policy_effect_path",
        [variable.variable_id],
        "surface_graph",
        evidenceRefs,
        0.5,
      ));
    }
  }

  variables.push(...objectOwnershipVariables(typedFacts, elicitedIndex));
  variables.push(...requestEquivalenceVariables(typedFacts, elicitedIndex, verifiedIndex, base_url));
  // Open-vocab: a typed fact carrying a mechanism token outside the curated known
  // set mints an `unknown`-typed latent instead of vanishing. The mint is honest-
  // uniform; it never self-resolves.
  variables.push(...openTypeVariables(typedFacts, elicitedIndex));

  for (const edge of edges.filter((item) => item.edge_type === "requires" || item.edge_type === "blocks_effect" || item.edge_type === "permits_effect")) {
    const artifact = `surface_graph:${edge.edge_hash}`;
    const geScope = {
      source_id: edge.source.id,
      target_id: edge.target.id,
      edge_type: edge.edge_type,
    };
    const gePrior = priorForLatent("gate_effectiveness", geScope, elicitedIndex);
    const variable = makeVariable("gate_effectiveness", geScope, gePrior.distribution, [artifact], gePrior.source);
    variables.push(variable);
  }

  // Factor-mediated sibling propagation: a SECOND pass that runs ONLY when at least
  // one verified_intervention latent exists. It raises (bounded, capped) the priors of
  // structural siblings of a verified latent and adds verified_sibling_equivalence
  // factors. ONE-WAY/GROUNDED: if verifiedIndex is empty no verified-sourced latent was
  // produced, the pass is a no-op, and the window is byte-identical to today.
  // COMPLETENESS: the pass only RAISES existing siblings and ADDS factors — never
  // adds/drops a variable, so the covered set is unchanged.
  let propagatedVariables = variables;
  if (verifiedIndex.size > 0) {
    const propagation = propagateVerifiedSiblings(variables);
    propagatedVariables = propagation.variables;
    factors.push(...propagation.factors);
  }

  const cappedVariables = propagatedVariables.slice(0, variableLimit);
  if (variables.length > variableLimit) {
    throw beliefWindowTooLarge("belief window variable cap exceeded", {
      variable_count: variables.length,
      variable_limit: variableLimit,
    });
  }
  if (factors.length > factorLimit) {
    throw beliefWindowTooLarge("belief window factor cap exceeded", {
      factor_count: factors.length,
      factor_limit: factorLimit,
    });
  }

  // Emit BOTH the curated known types and any observed-open types actually minted
  // this window. The known four lead in their canonical order, then observed-open
  // types are appended sorted. When NO open type was observed the array equals
  // BELIEF_VARIABLE_TYPES exactly, so the known-4 path stays byte-identical
  // (window_hash unchanged).
  const observedOpenTypes = Array.from(new Set(
    cappedVariables
      .map((variable) => variable.type)
      .filter((type) => !BELIEF_VARIABLE_TYPES.includes(type)),
  )).sort();
  const variableTypes = observedOpenTypes.length > 0
    ? [...BELIEF_VARIABLE_TYPES, ...observedOpenTypes]
    : BELIEF_VARIABLE_TYPES;

  const body = {
    model_version: BELIEF_WINDOW_MODEL_VERSION,
    target_domain,
    template_id: template.id,
    mechanism_id: template.mechanism_id,
    variable_types: variableTypes,
    variables: cappedVariables,
    factors,
    evidence_summary: {
      mechanism_edge_count: edges.length,
      typed_fact_count: typedFacts.length,
      template_required_entities: template.required_entities,
      template_interventions: template.interventions,
    },
    advisory: true,
    derived: true,
    writes_artifacts: false,
  };
  const serialized = canonicalJson(body);
  if (Buffer.byteLength(serialized, "utf8") > sizeLimit) {
    throw beliefWindowTooLarge("belief window serialized size cap exceeded", {
      size_bytes: Buffer.byteLength(serialized, "utf8"),
      size_limit_bytes: sizeLimit,
    });
  }
  return Object.freeze({
    ...body,
    window_hash: sha256Hex(serialized),
    limits: Object.freeze({
      variable_limit: variableLimit,
      factor_limit: factorLimit,
      fact_limit: factLimit,
      size_limit_bytes: sizeLimit,
    }),
  });
}

module.exports = {
  BELIEF_VARIABLE_TYPES,
  UNKNOWN_VARIABLE_TYPE,
  KNOWN_PLUS_UNKNOWN_VARIABLE_TYPES,
  BELIEF_WINDOW_MODEL_VERSION,
  SIBLING_PROPAGATION_WEIGHT,
  SIBLING_RAISE_CAP,
  RESOLUTION_THRESHOLD,
  buildBeliefWindow,
  makeVariable,
  stableId,
  requestEquivalenceScope,
  structureKey,
};
