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
const DEFAULT_VARIABLE_LIMIT = 64;
const DEFAULT_FACTOR_LIMIT = 128;
const DEFAULT_FACT_LIMIT = 200;
const DEFAULT_SIZE_LIMIT_BYTES = 65536;

const BELIEF_VARIABLE_TYPES = Object.freeze([
  "effective_permission",
  "object_ownership",
  "request_equivalence",
  "gate_effectiveness",
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

function makeVariable(type, scope, posterior, evidenceRefs, priorSource = "uniform") {
  return Object.freeze({
    variable_id: stableId("BV", { type, scope }),
    type,
    states: Object.freeze(Object.keys(posterior)),
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

function requestEquivalenceVariables(facts, elicitedIndex) {
  const variables = [];
  for (const fact of facts) {
    const payload = fact.payload || {};
    if (!payload.endpoint && !payload.path && !payload.method) continue;
    const scope = {
      endpoint: String(payload.endpoint || payload.path || "unknown"),
      method: String(payload.method || "UNKNOWN"),
      source_event_id: fact.source_event_id,
    };
    const prior = priorForLatent("request_equivalence", scope, elicitedIndex);
    variables.push(makeVariable("request_equivalence", scope, prior.distribution, [fact.artifact_ref], prior.source));
  }
  return variables;
}

function buildBeliefWindow({
  target_domain,
  template_id = "object_authorization",
  variable_limit,
  factor_limit,
  fact_limit,
  size_limit_bytes,
} = {}) {
  const variableLimit = normalizeLimit(variable_limit, DEFAULT_VARIABLE_LIMIT, DEFAULT_VARIABLE_LIMIT);
  const factorLimit = normalizeLimit(factor_limit, DEFAULT_FACTOR_LIMIT, DEFAULT_FACTOR_LIMIT);
  const factLimit = normalizeLimit(fact_limit, DEFAULT_FACT_LIMIT, DEFAULT_FACT_LIMIT);
  const sizeLimit = normalizeLimit(size_limit_bytes, DEFAULT_SIZE_LIMIT_BYTES, DEFAULT_SIZE_LIMIT_BYTES);
  const template = getMechanismTemplate(template_id);
  if (!template) {
    throw new Error(`unknown mechanism template: ${template_id}`);
  }
  const mechanism = queryMechanismView({ target_domain, limit: 1000 });
  const edges = sortedEdges(mechanism.edges || []);
  const typedFacts = sortedFacts(queryFrontierTypedFacts({ target_domain, limit: factLimit }).facts);
  const variables = [];
  const factors = [];
  const elicitedIndex = elicitedPriorIndex(target_domain);

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
  variables.push(...requestEquivalenceVariables(typedFacts, elicitedIndex));

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

  const cappedVariables = variables.slice(0, variableLimit);
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

  const body = {
    model_version: BELIEF_WINDOW_MODEL_VERSION,
    target_domain,
    template_id: template.id,
    mechanism_id: template.mechanism_id,
    variable_types: BELIEF_VARIABLE_TYPES,
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
  BELIEF_WINDOW_MODEL_VERSION,
  buildBeliefWindow,
};
