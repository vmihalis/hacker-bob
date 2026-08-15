"use strict";

const crypto = require("crypto");
const {
  redactTextSensitiveValues,
  validateNoSensitiveMaterial,
} = require("../redaction/sensitive-material.js");
const {
  readFrontierEvents,
} = require("../frontier/frontier-events.js");
const {
  compareObservationEvents,
  normalizeObservationEvent,
} = require("../frontier/frontier-projections.js");

const FRONTIER_TYPED_FACT_KIND = "frontier_observation";
const DEFAULT_FACT_LIMIT = 100;
const MAX_FACT_LIMIT = 1000;
const REDACTED_VALUE = "REDACTED";

const OBSERVATION_PROVENANCE_BY_KIND = Object.freeze({
  auth_redirect: "observed_http",
  graphql_endpoint: "observed_http",
  http_record_observed: "observed_http",
  http_route: "observed_http",
  jwt_observed: "observed_http",
  openapi_endpoint: "observed_http",
  route_extraction: "observed_http",

  schema_field: "declared_schema",
  schema_contract: "declared_schema",

  config_misuse_observed: "static_code",
  crash_observed: "static_code",
  dependency_observed: "static_code",
  static_artifact_imported: "static_code",
  unsafe_sink_observed: "static_code",

  capability_friction_observed: "operator_asserted",
  protocol_drift_observed: "operator_asserted",
});

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

function redactStringLeaves(value) {
  if (typeof value === "string") {
    const redacted = redactTextSensitiveValues(value);
    return redacted === value ? value : REDACTED_VALUE;
  }
  if (Array.isArray(value)) {
    return value.map(redactStringLeaves);
  }
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value).map(([key, child]) => [key, redactStringLeaves(child)]),
    );
  }
  return value;
}

function normalizeLimit(limit) {
  if (!Number.isInteger(limit) || limit <= 0) return DEFAULT_FACT_LIMIT;
  return Math.min(limit, MAX_FACT_LIMIT);
}

function provenanceForObservationKind(observationKind) {
  if (typeof observationKind !== "string" || !observationKind.trim()) {
    return "operator_asserted";
  }
  return OBSERVATION_PROVENANCE_BY_KIND[observationKind.trim()] || "operator_asserted";
}

function artifactRefForObservation(observation) {
  const payload = observation.payload && typeof observation.payload === "object" && !Array.isArray(observation.payload)
    ? observation.payload
    : {};
  if (typeof payload.artifact_ref === "string" && payload.artifact_ref.trim()) {
    return payload.artifact_ref.trim();
  }
  if (typeof observation.event_id === "string" && observation.event_id.trim()) {
    return `frontier_event:${observation.event_id.trim()}`;
  }
  return "frontier_event:unknown";
}

function frontierEventToTypedFact(event) {
  if (!event || event.kind !== "observation.recorded") return null;
  const observation = normalizeObservationEvent(event);
  const observationKind = typeof observation.kind === "string" && observation.kind.trim()
    ? observation.kind.trim()
    : "unknown";
  const payload = redactStringLeaves(observation.payload || {});
  const artifactRef = redactTextSensitiveValues(artifactRefForObservation(observation));
  const source = redactStringLeaves(observation.source || {});
  const body = {
    target_domain: event.target_domain,
    source_event_id: observation.event_id,
    surface_id: observation.surface_id,
    ts: observation.ts,
    fact_kind: FRONTIER_TYPED_FACT_KIND,
    observation_kind: observationKind,
    provenance: provenanceForObservationKind(observationKind),
    artifact_ref: artifactRef,
    source,
    payload,
  };
  validateNoSensitiveMaterial(body, "frontier_typed_fact");
  const factId = `BFF-${sha256Hex(canonicalJson(body)).slice(0, 24)}`;
  return Object.freeze({
    fact_id: factId,
    ...body,
  });
}

function queryFrontierTypedFacts({
  target_domain,
  surface_id,
  observation_kind,
  provenance,
  limit,
} = {}) {
  const max = normalizeLimit(limit);
  const facts = readFrontierEvents(target_domain)
    .filter((event) => event.kind === "observation.recorded")
    .sort((left, right) => compareObservationEvents(
      normalizeObservationEvent(left),
      normalizeObservationEvent(right),
    ))
    .map(frontierEventToTypedFact)
    .filter(Boolean)
    .filter((fact) => {
      if (surface_id && fact.surface_id !== surface_id) return false;
      if (observation_kind && fact.observation_kind !== observation_kind) return false;
      if (provenance && fact.provenance !== provenance) return false;
      return true;
    });
  const start = Math.max(0, facts.length - max);
  return Object.freeze({
    target_domain,
    facts: Object.freeze(facts.slice(start)),
    limit: max,
    returned: Math.min(facts.length, max),
    total_matching: facts.length,
    source_artifact: "frontier-events.jsonl",
    writes_artifacts: false,
  });
}

module.exports = {
  FRONTIER_TYPED_FACT_KIND,
  OBSERVATION_PROVENANCE_BY_KIND,
  artifactRefForObservation,
  frontierEventToTypedFact,
  provenanceForObservationKind,
  queryFrontierTypedFacts,
};
