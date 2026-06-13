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

function idorLikeEffect(effectId) {
  return /unauth_succeeds_where_auth_blocked|idor|object_authorization|victim/i.test(String(effectId || ""));
}

function publicObjectEffect(effectId) {
  return /public[_:-]?object|public/i.test(String(effectId || ""));
}

function posteriorForEffectivePermission({ principalEdge, effectEdge }) {
  const effectId = effectEdge.target.id;
  if (idorLikeEffect(effectId)) {
    return Object.freeze({ allowed: 0.88, blocked: 0.07, unknown: 0.05 });
  }
  if (publicObjectEffect(effectId)) {
    return Object.freeze({ allowed: 0.52, blocked: 0.18, unknown: 0.30 });
  }
  if (effectEdge.edge_type === "blocks_effect") {
    return Object.freeze({ allowed: 0.10, blocked: 0.78, unknown: 0.12 });
  }
  return Object.freeze({ allowed: 0.42, blocked: 0.28, unknown: 0.30 });
}

function makeVariable(type, scope, posterior, evidenceRefs) {
  return Object.freeze({
    variable_id: stableId("BV", { type, scope }),
    type,
    states: Object.freeze(Object.keys(posterior)),
    scope: Object.freeze(scope),
    posterior,
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

function objectOwnershipVariables(facts) {
  const variables = [];
  for (const fact of facts) {
    const payload = fact.payload || {};
    const principal = payload.principal || payload.owner || payload.owner_id;
    const object = payload.object || payload.object_id || payload.object_selector;
    if (!principal || !object) continue;
    variables.push(makeVariable(
      "object_ownership",
      { principal: String(principal), object: String(object), source_event_id: fact.source_event_id },
      Object.freeze({ owned: 0.70, not_owned: 0.15, unknown: 0.15 }),
      [fact.artifact_ref],
    ));
  }
  return variables;
}

function requestEquivalenceVariables(facts) {
  const variables = [];
  for (const fact of facts) {
    const payload = fact.payload || {};
    if (!payload.endpoint && !payload.path && !payload.method) continue;
    variables.push(makeVariable(
      "request_equivalence",
      {
        endpoint: String(payload.endpoint || payload.path || "unknown"),
        method: String(payload.method || "UNKNOWN"),
        source_event_id: fact.source_event_id,
      },
      Object.freeze({ equivalent: 0.55, distinct: 0.20, unknown: 0.25 }),
      [fact.artifact_ref],
    ));
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
      const variable = makeVariable(
        "effective_permission",
        {
          principal_id: principalEdge.source.id,
          policy_gate_id: principalEdge.target.id,
          effect_id: effectEdge.target.id,
        },
        posteriorForEffectivePermission({ principalEdge, effectEdge }),
        evidenceRefs,
      );
      variables.push(variable);
      factors.push(makeFactor(
        "principal_policy_effect_path",
        [variable.variable_id],
        "surface_graph",
        evidenceRefs,
        idorLikeEffect(effectEdge.target.id) ? 0.88 : 0.45,
      ));
    }
  }

  variables.push(...objectOwnershipVariables(typedFacts));
  variables.push(...requestEquivalenceVariables(typedFacts));

  for (const edge of edges.filter((item) => item.edge_type === "requires" || item.edge_type === "blocks_effect" || item.edge_type === "permits_effect")) {
    const artifact = `surface_graph:${edge.edge_hash}`;
    const variable = makeVariable(
      "gate_effectiveness",
      {
        source_id: edge.source.id,
        target_id: edge.target.id,
        edge_type: edge.edge_type,
      },
      edge.edge_type === "blocks_effect"
        ? Object.freeze({ effective: 0.78, ineffective: 0.10, unknown: 0.12 })
        : Object.freeze({ effective: 0.60, ineffective: 0.15, unknown: 0.25 }),
      [artifact],
    );
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
