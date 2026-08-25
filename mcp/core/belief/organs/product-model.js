"use strict";

const crypto = require("crypto");
const {
  queryEdges,
} = require("../../frontier/surface-graph.js");
const {
  FRONTIER_TYPED_FACT_KIND,
  queryFrontierTypedFacts,
} = require("../frontier-facts.js");
const authority = require("../authority.js");

const PRODUCT_MODEL_VERSION = "product-model.v1";
const PRODUCT_MODEL_SOURCE = "mcp/core/belief/organs/product-model.js#runProductModel";
const DEFAULT_INPUT_LIMIT = 1000;
const MAX_INPUT_LIMIT = 1000;

const PRODUCT_NODE_TYPES = Object.freeze([
  "surface",
  "endpoint",
  "principal",
  "credential",
  "policy_gate",
  "effect",
  "intervention",
  "auth_scheme",
  "tech",
  "openapi_spec",
]);

const PRODUCT_RELATION_EDGE_TYPES = Object.freeze([
  "contains",
  "documents",
  "claims_auth",
  "uses_credential",
  "requires",
  "tests_gate",
  "produces_effect",
  "permits_effect",
  "blocks_effect",
  "observes_effect",
]);

const OPERATION_OBSERVATION_KINDS = Object.freeze([
  "http_record_observed",
  "http_route",
  "openapi_endpoint",
  "graphql_endpoint",
  "route_extraction",
  "schema_field",
  "schema_contract",
]);

const AUTH_OBSERVATION_KINDS = Object.freeze([
  "auth_redirect",
  "jwt_observed",
]);

const HARD_CAPTURE_PROVENANCE = Object.freeze([
  "observed_http",
  "observed_traffic",
  "declared_schema",
  "static_code",
  "surface_graph",
  "verified_intervention",
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

function deepFreeze(value) {
  if (!value || typeof value !== "object" || Object.isFrozen(value)) return value;
  for (const child of Object.values(value)) deepFreeze(child);
  return Object.freeze(value);
}

function isPlainObject(value) {
  return value != null && typeof value === "object" && !Array.isArray(value);
}

function normalizeLimit(limit) {
  if (!Number.isInteger(limit) || limit <= 0) return DEFAULT_INPUT_LIMIT;
  return Math.min(limit, MAX_INPUT_LIMIT);
}

function sortedById(values, idField) {
  return values.slice().sort((left, right) => String(left[idField]).localeCompare(String(right[idField])));
}

function pushUnique(map, item, idField) {
  if (!item || typeof item[idField] !== "string" || !item[idField]) return;
  if (!map.has(item[idField])) map.set(item[idField], item);
}

function safeString(value, fallback = "unknown") {
  if (typeof value !== "string" || !value.trim()) return fallback;
  return value.trim();
}

function nodeEntity(node, evidenceRef) {
  if (!isPlainObject(node) || !PRODUCT_NODE_TYPES.includes(node.type) || typeof node.id !== "string" || !node.id) {
    return null;
  }
  return {
    entity_id: stableId("PME", { type: node.type, id: node.id }),
    entity_type: node.type,
    external_id: node.id,
    evidence_refs: [evidenceRef],
  };
}

function surfaceEdgeEvidenceRef(edge) {
  if (!isPlainObject(edge) || typeof edge.edge_hash !== "string" || !/^[0-9a-f]{64}$/.test(edge.edge_hash)) {
    return null;
  }
  return `surface_graph:edge:${edge.edge_hash}`;
}

function factEvidenceRef(fact) {
  if (!isPlainObject(fact)) return null;
  if (fact.fact_kind !== FRONTIER_TYPED_FACT_KIND) return null;
  if (typeof fact.fact_id !== "string" || !/^BFF-[0-9a-f]{24}$/.test(fact.fact_id)) return null;
  if (typeof fact.source_event_id !== "string" || !fact.source_event_id.trim()) return null;
  return `frontier_fact:${fact.fact_id}`;
}

function holdGap({ gap_kind, reason, evidence_refs = [], input_digest = null }) {
  const body = {
    gap_id: stableId("PMG", { gap_kind, reason, evidence_refs, input_digest }),
    gap_kind,
    reason,
    disposition: "HOLD",
    hold_for_adjudication: true,
    evidence_refs: evidence_refs.slice().sort(),
  };
  if (input_digest) body.input_digest = input_digest;
  return body;
}

function surfaceRelation(edge, evidenceRef) {
  if (!isPlainObject(edge) || !PRODUCT_RELATION_EDGE_TYPES.includes(edge.edge_type)) return null;
  if (!PRODUCT_NODE_TYPES.includes(edge.source && edge.source.type)) return null;
  if (!PRODUCT_NODE_TYPES.includes(edge.target && edge.target.type)) return null;
  const body = {
    source: edge.source,
    target: edge.target,
    relation_type: edge.edge_type,
  };
  return {
    relation_id: stableId("PMR", body),
    ...body,
    evidence_refs: [evidenceRef],
    inert: true,
    closure_authority: false,
  };
}

function predicateFromSurfaceEdge(edge, evidenceRef) {
  if (!isPlainObject(edge)) return null;
  if (!["claims_auth", "requires", "tests_gate", "permits_effect", "blocks_effect"].includes(edge.edge_type)) {
    return null;
  }
  const predicateType = edge.edge_type === "claims_auth"
    ? "claimed_auth_scheme"
    : edge.edge_type === "requires"
      ? "requires_capability_or_gate"
      : edge.edge_type === "tests_gate"
        ? "principal_tests_gate"
        : edge.edge_type === "permits_effect"
          ? "gate_permits_effect"
          : "gate_blocks_effect";
  const body = {
    predicate_type: predicateType,
    source: edge.source,
    target: edge.target,
  };
  return {
    predicate_id: stableId("PMP", body),
    ...body,
    evidence_refs: [evidenceRef],
    inert: true,
    closure_authority: false,
  };
}

function operationFromFact(fact, evidenceRef) {
  if (!OPERATION_OBSERVATION_KINDS.includes(fact.observation_kind)) return null;
  const payload = isPlainObject(fact.payload) ? fact.payload : {};
  const request = isPlainObject(payload.request) ? payload.request : {};
  const endpoint = safeString(payload.endpoint || payload.path || request.endpoint || request.path || request.url, null);
  if (!endpoint) return null;
  const method = safeString(payload.method || request.method, "UNKNOWN").toUpperCase();
  const body = {
    operation_kind: fact.observation_kind,
    surface_id: safeString(fact.surface_id, "surface:unknown"),
    endpoint,
    method,
  };
  return {
    operation_id: stableId("PMO", body),
    ...body,
    evidence_refs: [evidenceRef],
    observed: true,
    inert: true,
    closure_authority: false,
  };
}

function predicateFromFact(fact, evidenceRef) {
  const payload = isPlainObject(fact.payload) ? fact.payload : {};
  if (OPERATION_OBSERVATION_KINDS.includes(fact.observation_kind) && typeof payload.claimed_auth === "string") {
    const body = {
      predicate_type: "operation_claimed_auth",
      surface_id: safeString(fact.surface_id, "surface:unknown"),
      endpoint: safeString(payload.endpoint || payload.path, "unknown"),
      auth_scheme: payload.claimed_auth,
    };
    return {
      predicate_id: stableId("PMP", body),
      ...body,
      evidence_refs: [evidenceRef],
      inert: true,
      closure_authority: false,
    };
  }
  if (AUTH_OBSERVATION_KINDS.includes(fact.observation_kind)) {
    const body = {
      predicate_type: fact.observation_kind,
      surface_id: safeString(fact.surface_id, "surface:unknown"),
      artifact_ref: safeString(fact.artifact_ref, "frontier_event:unknown"),
    };
    return {
      predicate_id: stableId("PMP", body),
      ...body,
      evidence_refs: [evidenceRef],
      inert: true,
      closure_authority: false,
    };
  }
  return null;
}

function classifyFrontierFact(fact) {
  const evidenceRef = factEvidenceRef(fact);
  if (!evidenceRef) {
    return {
      accepted: false,
      gap: holdGap({
        gap_kind: "forged_or_unsigned_capture",
        reason: "frontier fact is missing the typed fact identity or source event binding",
        input_digest: sha256Hex(canonicalJson(fact)),
      }),
    };
  }
  if (!HARD_CAPTURE_PROVENANCE.includes(fact.provenance)) {
    return {
      accepted: false,
      gap: holdGap({
        gap_kind: "soft_input_refused",
        reason: "product model consumes verified capture rows, not operator or model assertions",
        evidence_refs: [evidenceRef],
      }),
    };
  }
  const known = OPERATION_OBSERVATION_KINDS.includes(fact.observation_kind)
    || AUTH_OBSERVATION_KINDS.includes(fact.observation_kind);
  if (!known) {
    return {
      accepted: false,
      gap: holdGap({
        gap_kind: "unknown_observation_class",
        reason: `no product-model extractor is registered for ${safeString(fact.observation_kind)}`,
        evidence_refs: [evidenceRef],
      }),
    };
  }
  return { accepted: true, evidenceRef };
}

function classifySurfaceEdge(edge) {
  const evidenceRef = surfaceEdgeEvidenceRef(edge);
  if (!evidenceRef) {
    return {
      accepted: false,
      gap: holdGap({
        gap_kind: "forged_or_unsigned_surface_edge",
        reason: "surface graph edge is missing its canonical edge hash",
        input_digest: sha256Hex(canonicalJson(edge)),
      }),
    };
  }
  if (!PRODUCT_RELATION_EDGE_TYPES.includes(edge.edge_type)) {
    return {
      accepted: false,
      gap: holdGap({
        gap_kind: "unknown_surface_relation",
        reason: `no product-model relation extractor is registered for ${safeString(edge.edge_type)}`,
        evidence_refs: [evidenceRef],
      }),
    };
  }
  return { accepted: true, evidenceRef };
}

function gapForUnobservedEffect(edge, evidenceRef, operationsById) {
  if (!isPlainObject(edge) || edge.edge_type !== "permits_effect") return null;
  const effectId = edge.target && edge.target.type === "effect" ? edge.target.id : null;
  if (!effectId) return null;
  for (const operation of operationsById.values()) {
    if (operation.endpoint !== "unknown" && effectId.includes(operation.endpoint)) return null;
  }
  return holdGap({
    gap_kind: "unobserved_operation",
    reason: `effect ${effectId} has no observed operation binding`,
    evidence_refs: [evidenceRef],
  });
}

function buildProductModelFromInputs({
  target_domain,
  surface_edges = [],
  frontier_facts = [],
  belief_signals = [],
} = {}) {
  const targetDomain = safeString(target_domain, null);
  if (!targetDomain) throw new Error("target_domain is required");
  const entitiesById = new Map();
  const relationsById = new Map();
  const operationsById = new Map();
  const predicatesById = new Map();
  const gapsById = new Map();
  const rejectedInputs = [];
  const admittedEvidenceRefs = new Set();

  for (const signal of Array.isArray(belief_signals) ? belief_signals : []) {
    const gap = holdGap({
      gap_kind: "soft_input_refused",
      reason: "belief signals and generated hypotheses are inert outputs, never product-model capture inputs",
      input_digest: sha256Hex(canonicalJson(signal)),
    });
    pushUnique(gapsById, gap, "gap_id");
    rejectedInputs.push({ reason: "soft_input_refused", input_digest: gap.input_digest });
  }

  for (const edge of Array.isArray(surface_edges) ? surface_edges : []) {
    const classified = classifySurfaceEdge(edge);
    if (!classified.accepted) {
      pushUnique(gapsById, classified.gap, "gap_id");
      rejectedInputs.push({ reason: classified.gap.gap_kind, input_digest: classified.gap.input_digest || null });
      continue;
    }
    admittedEvidenceRefs.add(classified.evidenceRef);
    pushUnique(entitiesById, nodeEntity(edge.source, classified.evidenceRef), "entity_id");
    pushUnique(entitiesById, nodeEntity(edge.target, classified.evidenceRef), "entity_id");
    pushUnique(relationsById, surfaceRelation(edge, classified.evidenceRef), "relation_id");
    pushUnique(predicatesById, predicateFromSurfaceEdge(edge, classified.evidenceRef), "predicate_id");
  }

  for (const fact of Array.isArray(frontier_facts) ? frontier_facts : []) {
    const classified = classifyFrontierFact(fact);
    if (!classified.accepted) {
      pushUnique(gapsById, classified.gap, "gap_id");
      rejectedInputs.push({ reason: classified.gap.gap_kind, input_digest: classified.gap.input_digest || null });
      continue;
    }
    admittedEvidenceRefs.add(classified.evidenceRef);
    const operation = operationFromFact(fact, classified.evidenceRef);
    pushUnique(operationsById, operation, "operation_id");
    if (operation) {
      pushUnique(entitiesById, {
        entity_id: stableId("PME", { type: "endpoint", id: operation.endpoint }),
        entity_type: "endpoint",
        external_id: operation.endpoint,
        evidence_refs: [classified.evidenceRef],
      }, "entity_id");
    }
    pushUnique(predicatesById, predicateFromFact(fact, classified.evidenceRef), "predicate_id");
  }

  for (const edge of Array.isArray(surface_edges) ? surface_edges : []) {
    const evidenceRef = surfaceEdgeEvidenceRef(edge);
    if (!evidenceRef) continue;
    const gap = gapForUnobservedEffect(edge, evidenceRef, operationsById);
    pushUnique(gapsById, gap, "gap_id");
  }

  const body = {
    model_version: PRODUCT_MODEL_VERSION,
    target_domain: targetDomain,
    advisory: true,
    inert: true,
    derived: true,
    scratch: true,
    closure_authority: false,
    evidence_authority: false,
    dispatch_authority: false,
    model_authority: "nomination_only",
    admission: {
      status: rejectedInputs.length > 0 ? "HOLD" : "ACCEPTED",
      unknown_class_disposition: "HOLD",
      no_generic_web_fallback: true,
      rejected_input_count: rejectedInputs.length,
    },
    entities: sortedById([...entitiesById.values()], "entity_id"),
    relations: sortedById([...relationsById.values()], "relation_id"),
    operations: sortedById([...operationsById.values()], "operation_id"),
    permission_predicates: sortedById([...predicatesById.values()], "predicate_id"),
    coverage_gaps: sortedById([...gapsById.values()], "gap_id"),
    evidence_refs: [...admittedEvidenceRefs].sort(),
    rejected_inputs: rejectedInputs.sort((a, b) => canonicalJson(a).localeCompare(canonicalJson(b))),
  };
  return deepFreeze({
    ...body,
    model_hash: sha256Hex(canonicalJson(body)),
  });
}

function buildProductModel({ target_domain, limit } = {}) {
  const cap = normalizeLimit(limit);
  const surface = queryEdges({ target_domain, limit: cap });
  const facts = queryFrontierTypedFacts({ target_domain, limit: cap });
  return buildProductModelFromInputs({
    target_domain,
    surface_edges: surface.edges,
    frontier_facts: facts.facts,
  });
}

function writeProductModelSignal({ target_domain, model } = {}) {
  const productModel = model || buildProductModel({ target_domain });
  return authority.writeBeliefSignalScratch({
    target_domain: productModel.target_domain,
    kind: "mechanism_projection",
    source: PRODUCT_MODEL_SOURCE,
    provenance: "surface_graph",
    role: "diagnostic",
    artifact_ref: `product_model:${productModel.model_hash}`,
    payload: productModel,
  });
}

function runProductModel({ target_domain, limit } = {}) {
  const model = buildProductModel({ target_domain, limit });
  const written = writeProductModelSignal({ target_domain, model });
  return deepFreeze({
    ...written,
    model_hash: model.model_hash,
    admission: model.admission,
    entity_count: model.entities.length,
    relation_count: model.relations.length,
    operation_count: model.operations.length,
    permission_predicate_count: model.permission_predicates.length,
    coverage_gap_count: model.coverage_gaps.length,
    advisory: true,
    inert: true,
    closure_authority: false,
  });
}

module.exports = {
  PRODUCT_MODEL_VERSION,
  PRODUCT_MODEL_SOURCE,
  buildProductModel,
  buildProductModelFromInputs,
  runProductModel,
  writeProductModelSignal,
  _internals: {
    classifyFrontierFact,
    classifySurfaceEdge,
    canonicalJson,
    stableId,
  },
};
