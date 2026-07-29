"use strict";

const fs = require("fs");
const path = require("path");
const crypto = require("node:crypto");
const {
  assertSafeDomain,
  sessionDir,
  sessionsRoot,
  surfaceGraphJsonlPath,
} = require("./paths.js");
const {
  assertSafeSessionDirectoryIdentity,
  readFileUtf8,
  withSessionLock,
} = require("./storage.js");
const { hashCanonicalJson } = require("./verification-contracts.js");
const { readVerifiedSessionNucleus } = require("./governance-store.js");
const {
  assertDurableReceiptTrustRegistry,
  normalizeAndVerifyPhysicalSurfaceLiveRevalidationReceipt,
  normalizeAndVerifyPhysicalSurfaceTransitionReceipt,
} = require("./executed-evidence-registry.js");
const {
  PHYSICAL_SURFACE_GRAPH_SCHEMA_VERSION,
  PHYSICAL_SURFACE_NODE_TYPES,
  PHYSICAL_TRANSITION_PARTICIPANT_ROLES,
  normalizePhysicalSurfaceTransitionPayload,
  physicalSurfaceTransitionProjectionDigests,
} = require("./physical-surface-transition.js");

const SURFACE_GRAPH_RECORD_VERSION = PHYSICAL_SURFACE_GRAPH_SCHEMA_VERSION;
const SURFACE_GRAPH_RECORD_KINDS = Object.freeze([
  "edge",
  "verified_transition_arc",
]);
const PARTICIPANT_ROLES = PHYSICAL_TRANSITION_PARTICIPANT_ROLES;
const PARTICIPANT_ROLE_SET = new Set(PARTICIPANT_ROLES);

const PHYSICAL_NODE_TYPES = Object.freeze([...PHYSICAL_SURFACE_NODE_TYPES]);

const PHYSICAL_RELATIONSHIP_EDGE_TYPES = Object.freeze([
  "represented_by",
  "staged_in",
  "presents_to",
  "verified_by",
  "controls",
  "guards",
  "grants_transition",
  "located_in",
  "exposes",
  "connects_to",
  "administers",
  "communicates_over",
  "emits_into",
  "injects_into",
  "actuates",
  "observes_outcome",
  "corroborates",
]);

const NODE_TYPES = Object.freeze([
  "surface",
  "subdomain",
  "hostname",
  "endpoint",
  "js_file",
  "tech",
  "openapi_spec",
  "archived_url",
  "secret_marker",
  "auth_scheme",
  "static_artifact",
  "principal",
  "credential",
  "policy_gate",
  "effect",
  "intervention",
  ...PHYSICAL_NODE_TYPES,
]);

const EDGE_TYPES = Object.freeze([
  "references",
  "contains",
  "hosts",
  "imports",
  "documents",
  "claims_auth",
  "leaks",
  "uses_credential",
  "requires",
  "tests_gate",
  "produces_effect",
  "permits_effect",
  "blocks_effect",
  "observes_effect",
  "demonstrated_transition",
  ...PHYSICAL_RELATIONSHIP_EDGE_TYPES,
]);

const PHYSICAL_SURFACE_GRAPH_ONTOLOGY = deepFreeze({
  schema_version: SURFACE_GRAPH_RECORD_VERSION,
  node_types: PHYSICAL_NODE_TYPES,
  participant_roles: PARTICIPANT_ROLES,
  relationship_edge_types: PHYSICAL_RELATIONSHIP_EDGE_TYPES,
  demonstrated_edge_types: Object.freeze(["demonstrated_transition"]),
});

const NODE_TYPE_SET = new Set(NODE_TYPES);
const EDGE_TYPE_SET = new Set(EDGE_TYPES);
const PHYSICAL_NODE_TYPE_SET = new Set(PHYSICAL_NODE_TYPES);

const DEMONSTRATED_TRANSITION_BINDING_REQUIRED_FIELDS = Object.freeze([
  "session_nucleus_hash",
  "plan_hash",
  "execution_request_digest",
  "claim_predicate_digest",
  "verdict_ref",
  "verdict_hash",
  "verified_claim_projection_digest",
  "verdict_signer_principal_ref",
  "verifier_template_id",
  "verifier_template_version",
  "verifier_template_digest",
  "decision_rule_digest",
  "verifier_execution_receipt_ref",
  "verifier_execution_receipt_digest",
  "executed_evidence_registry_digest",
  "verdict_signer_key_id",
  "trust_root_epoch",
  "verdict_trust_domain_ref",
  "verdict_independence_domain_ref",
  "verdict_trust_registry_digest",
  "verdict_signer_enrollment_digest",
  "verdict_authorization_context_digest",
  "transition_signer_key_id",
  "transition_trust_root_epoch",
  "upstream_execution_identities",
  "upstream_context_digest",
  "transition_state_epoch",
  "transition_state_digest",
  "validity_kind",
  "valid_from",
  "transition_instance_ref",
  "transition_receipt_digest",
  "participants_digest",
  "source_participant_role",
  "target_participant_role",
]);

const DEMONSTRATED_TRANSITION_BINDING_OPTIONAL_FIELDS = Object.freeze([
  "expires_at",
  "capability_instance_ref",
  "custody_state_digest",
  "external_observer_independence_domain_count",
  "external_observer_independence_domain_digest",
  "high_impact_corroboration_satisfied",
]);

const DEMONSTRATED_TRANSITION_BINDING_FIELDS = new Set([
  ...DEMONSTRATED_TRANSITION_BINDING_REQUIRED_FIELDS,
  ...DEMONSTRATED_TRANSITION_BINDING_OPTIONAL_FIELDS,
]);

const DEMONSTRATED_TRANSITION_VALIDITY_KINDS = Object.freeze([
  "historical_event",
  "live_capability",
]);
const DEMONSTRATED_TRANSITION_VALIDITY_KIND_SET = new Set(
  DEMONSTRATED_TRANSITION_VALIDITY_KINDS,
);
const SHA256_HEX_RE = /^[0-9a-f]{64}$/;

const DEFAULT_QUERY_LIMIT = 200;
const MAX_QUERY_LIMIT = 1000;
const PHYSICAL_SURFACE_GRAPH_SERVER_SERVICE_VERSION = 1;
const SURFACE_GRAPH_QUARANTINE_VERSION = 1;
const LIVE_REVALIDATION_MAX_AGE_MS = 30_000;
const LIVE_REVALIDATION_MAX_TTL_MS = 60_000;
const PHYSICAL_SURFACE_GRAPH_SERVER_SERVICES = new WeakSet();
const PHYSICAL_SURFACE_GRAPH_SERVER_SERVICE_STATE = new WeakMap();

function isPlainObject(value) {
  if (value == null || typeof value !== "object" || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function assertClosedObject(value, label, required, optional = []) {
  if (!isPlainObject(value)) throw new Error(`${label} must be an object`);
  const allowed = new Set([...required, ...optional]);
  const unknown = Object.keys(value).filter((field) => !allowed.has(field)).sort();
  if (unknown.length > 0) throw new Error(`${label} contains unknown fields: ${unknown.join(", ")}`);
  const missing = required.filter((field) => !Object.prototype.hasOwnProperty.call(value, field));
  if (missing.length > 0) throw new Error(`${label} is missing fields: ${missing.join(", ")}`);
  return value;
}

function deepFreeze(value) {
  if (!value || typeof value !== "object" || Object.isFrozen(value)) return value;
  for (const child of Object.values(value)) deepFreeze(child);
  return Object.freeze(value);
}

function requireDigest(value, label) {
  if (typeof value !== "string" || !SHA256_HEX_RE.test(value)) {
    throw new Error(`${label} must be a lowercase SHA-256 hex digest`);
  }
  return value;
}

function requireBoundedString(value, label, { max = 2048 } = {}) {
  if (typeof value !== "string" || value.length === 0 || value.length > max) {
    throw new Error(`${label} must be a non-empty string of at most ${max} characters`);
  }
  return value;
}

function requireCanonicalTimestamp(value, label) {
  if (typeof value !== "string" || Number.isNaN(Date.parse(value)) || new Date(value).toISOString() !== value) {
    throw new Error(`${label} must be a canonical UTC ISO-8601 timestamp`);
  }
  return value;
}

function assertSafeSurfaceGraphRoot({ create = false } = {}) {
  const root = sessionsRoot();
  if (!fs.existsSync(root)) {
    if (!create) return null;
    fs.mkdirSync(root, { mode: 0o700 });
  }
  const stats = fs.lstatSync(root);
  if (!stats.isDirectory() || stats.isSymbolicLink()) {
    throw new Error("Hacker Bob sessions root must be a real directory, not a symlink");
  }
  return Object.freeze({ dev: stats.dev, ino: stats.ino, root });
}

function assertSurfaceGraphRootIdentity(identity) {
  if (!identity) return;
  const stats = fs.lstatSync(identity.root);
  if (
    !stats.isDirectory()
    || stats.isSymbolicLink()
    || stats.dev !== identity.dev
    || stats.ino !== identity.ino
  ) throw new Error("Hacker Bob sessions root changed during surface graph operation");
}

function normalizeNode(node, label) {
  assertClosedObject(node, label, ["type", "id"]);
  if (typeof node.type !== "string" || node.type.length === 0) {
    throw new Error(`${label}.type must be a non-empty string`);
  }
  if (!NODE_TYPE_SET.has(node.type)) {
    throw new Error(`${label}.type is not in the surface-graph node vocabulary: ${node.type}`);
  }
  return { type: node.type, id: requireBoundedString(node.id, `${label}.id`) };
}

function requireBindingString(binding, field) {
  const value = binding[field];
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(`edge.demonstrated_transition_binding.${field} must be a non-empty string`);
  }
  return value;
}

function requireBindingDigest(binding, field) {
  const value = requireBindingString(binding, field);
  if (!SHA256_HEX_RE.test(value)) {
    throw new Error(`edge.demonstrated_transition_binding.${field} must be a lowercase SHA-256 hex digest`);
  }
  return value;
}

function normalizeBindingEpoch(binding, field) {
  const value = binding[field];
  if (Number.isSafeInteger(value) && value >= 0) return value;
  if (typeof value === "string" && value.length > 0) return value;
  throw new Error(
    `edge.demonstrated_transition_binding.${field} must be a non-negative safe integer or non-empty string`,
  );
}

function normalizeBindingVersion(binding) {
  const value = binding.verifier_template_version;
  if (Number.isSafeInteger(value) && value >= 0) return value;
  if (typeof value === "string" && value.length > 0) return value;
  throw new Error(
    "edge.demonstrated_transition_binding.verifier_template_version must be a non-negative safe integer or non-empty string",
  );
}

function normalizeBindingTimestamp(binding, field, { required = true } = {}) {
  const value = binding[field];
  if (!required && value == null) return null;
  return requireCanonicalTimestamp(value, `edge.demonstrated_transition_binding.${field}`);
}

function normalizeDemonstratedTransitionBinding(binding) {
  if (!isPlainObject(binding)) {
    throw new Error("edge.demonstrated_transition_binding must be an object");
  }
  for (const field of Object.keys(binding)) {
    if (!DEMONSTRATED_TRANSITION_BINDING_FIELDS.has(field)) {
      throw new Error(`edge.demonstrated_transition_binding contains unknown field: ${field}`);
    }
  }
  for (const field of DEMONSTRATED_TRANSITION_BINDING_REQUIRED_FIELDS) {
    if (!Object.prototype.hasOwnProperty.call(binding, field)) {
      throw new Error(`edge.demonstrated_transition_binding.${field} is required`);
    }
  }

  const validityKind = requireBindingString(binding, "validity_kind");
  if (!DEMONSTRATED_TRANSITION_VALIDITY_KIND_SET.has(validityKind)) {
    throw new Error(
      `edge.demonstrated_transition_binding.validity_kind must be one of: ${DEMONSTRATED_TRANSITION_VALIDITY_KINDS.join(", ")}`,
    );
  }

  const validFrom = normalizeBindingTimestamp(binding, "valid_from");
  const expiresAt = normalizeBindingTimestamp(binding, "expires_at", { required: false });
  if (expiresAt != null && Date.parse(expiresAt) <= Date.parse(validFrom)) {
    throw new Error("edge.demonstrated_transition_binding.expires_at must be after valid_from");
  }
  if (validityKind === "live_capability") {
    for (const field of ["expires_at", "capability_instance_ref", "custody_state_digest"]) {
      if (!Object.prototype.hasOwnProperty.call(binding, field)) {
        throw new Error(
          `edge.demonstrated_transition_binding.${field} is required for live_capability`,
        );
      }
    }
  }

  const normalized = {
    session_nucleus_hash: requireBindingDigest(binding, "session_nucleus_hash"),
    plan_hash: requireBindingDigest(binding, "plan_hash"),
    execution_request_digest: requireBindingDigest(binding, "execution_request_digest"),
    claim_predicate_digest: requireBindingDigest(binding, "claim_predicate_digest"),
    verdict_ref: requireBindingString(binding, "verdict_ref"),
    verdict_hash: requireBindingDigest(binding, "verdict_hash"),
    verified_claim_projection_digest: requireBindingDigest(binding, "verified_claim_projection_digest"),
    verdict_signer_principal_ref: requireBindingString(binding, "verdict_signer_principal_ref"),
    verifier_template_id: requireBindingString(binding, "verifier_template_id"),
    verifier_template_version: normalizeBindingVersion(binding),
    verifier_template_digest: requireBindingDigest(binding, "verifier_template_digest"),
    decision_rule_digest: requireBindingDigest(binding, "decision_rule_digest"),
    verifier_execution_receipt_ref: requireBindingString(binding, "verifier_execution_receipt_ref"),
    verifier_execution_receipt_digest: requireBindingDigest(binding, "verifier_execution_receipt_digest"),
    executed_evidence_registry_digest: requireBindingDigest(binding, "executed_evidence_registry_digest"),
    verdict_signer_key_id: requireBindingString(binding, "verdict_signer_key_id"),
    trust_root_epoch: normalizeBindingEpoch(binding, "trust_root_epoch"),
    verdict_trust_domain_ref: requireBindingString(binding, "verdict_trust_domain_ref"),
    verdict_independence_domain_ref: requireBindingString(binding, "verdict_independence_domain_ref"),
    verdict_trust_registry_digest: requireBindingDigest(binding, "verdict_trust_registry_digest"),
    verdict_signer_enrollment_digest: requireBindingDigest(binding, "verdict_signer_enrollment_digest"),
    verdict_authorization_context_digest: requireBindingDigest(
      binding,
      "verdict_authorization_context_digest",
    ),
    transition_signer_key_id: requireBindingString(binding, "transition_signer_key_id"),
    transition_trust_root_epoch: normalizeBindingEpoch(binding, "transition_trust_root_epoch"),
    upstream_execution_identities: (() => {
      if (!Array.isArray(binding.upstream_execution_identities) || binding.upstream_execution_identities.length === 0) {
        throw new Error("edge.demonstrated_transition_binding.upstream_execution_identities must be a non-empty array");
      }
      const values = binding.upstream_execution_identities.map((value, index) => (
        requireBoundedString(
          value,
          `edge.demonstrated_transition_binding.upstream_execution_identities[${index}]`,
          { max: 256 },
        )
      )).sort();
      if (new Set(values).size !== values.length) {
        throw new Error("edge.demonstrated_transition_binding.upstream_execution_identities must be unique");
      }
      return values;
    })(),
    upstream_context_digest: requireBindingDigest(binding, "upstream_context_digest"),
    transition_state_epoch: normalizeBindingEpoch(binding, "transition_state_epoch"),
    transition_state_digest: requireBindingDigest(binding, "transition_state_digest"),
    validity_kind: validityKind,
    valid_from: validFrom,
    transition_instance_ref: requireBindingString(binding, "transition_instance_ref"),
    transition_receipt_digest: requireBindingDigest(binding, "transition_receipt_digest"),
    participants_digest: requireBindingDigest(binding, "participants_digest"),
    source_participant_role: requireBindingString(binding, "source_participant_role"),
    target_participant_role: requireBindingString(binding, "target_participant_role"),
  };
  if (
    !PARTICIPANT_ROLE_SET.has(normalized.source_participant_role)
    || !PARTICIPANT_ROLE_SET.has(normalized.target_participant_role)
  ) {
    throw new Error(
      `edge.demonstrated_transition_binding participant roles must be one of: ${PARTICIPANT_ROLES.join(", ")}`,
    );
  }
  if (expiresAt != null) normalized.expires_at = expiresAt;
  if (validityKind === "live_capability" || binding.capability_instance_ref != null) {
    normalized.capability_instance_ref = requireBindingString(binding, "capability_instance_ref");
  }
  if (validityKind === "live_capability" || binding.custody_state_digest != null) {
    normalized.custody_state_digest = requireBindingDigest(binding, "custody_state_digest");
  }
  const observerAssuranceFields = [
    "external_observer_independence_domain_count",
    "external_observer_independence_domain_digest",
    "high_impact_corroboration_satisfied",
  ];
  const observerAssurancePresent = observerAssuranceFields.filter((field) => (
    Object.prototype.hasOwnProperty.call(binding, field)
  ));
  if (observerAssurancePresent.length !== 0
      && observerAssurancePresent.length !== observerAssuranceFields.length) {
    throw new Error(
      "edge.demonstrated_transition_binding external-observer assurance fields must be all present or all absent",
    );
  }
  if (observerAssurancePresent.length === observerAssuranceFields.length) {
    const count = binding.external_observer_independence_domain_count;
    if (!Number.isSafeInteger(count) || count < 0 || count > 256) {
      throw new Error(
        "edge.demonstrated_transition_binding.external_observer_independence_domain_count must be between 0 and 256",
      );
    }
    if (typeof binding.high_impact_corroboration_satisfied !== "boolean"
        || binding.high_impact_corroboration_satisfied !== (count >= 2)) {
      throw new Error(
        "edge.demonstrated_transition_binding.high_impact_corroboration_satisfied must exactly reflect two independent observer domains",
      );
    }
    normalized.external_observer_independence_domain_count = count;
    normalized.external_observer_independence_domain_digest = requireBindingDigest(
      binding,
      "external_observer_independence_domain_digest",
    );
    normalized.high_impact_corroboration_satisfied =
      binding.high_impact_corroboration_satisfied;
  }
  return normalized;
}

function normalizeEdgeInternal(edge, { verifiedTransition = false } = {}) {
  assertClosedObject(
    edge,
    "edge",
    ["source", "target", "edge_type"],
    ["confidence", "source_artifact", "observed_at", "demonstrated_transition_binding"],
  );
  const source = normalizeNode(edge.source, "edge.source");
  const target = normalizeNode(edge.target, "edge.target");
  const edgeType = edge.edge_type;
  if (typeof edgeType !== "string" || edgeType.length === 0) {
    throw new Error("edge.edge_type must be a non-empty string");
  }
  if (!EDGE_TYPE_SET.has(edgeType)) {
    throw new Error(`edge.edge_type is not in the surface-graph edge vocabulary: ${edgeType}`);
  }
  let demonstratedTransitionBinding = null;
  if (edgeType === "demonstrated_transition") {
    if (!verifiedTransition) {
      throw new Error(
        "demonstrated_transition edges can only be derived from a signed verified N-ary transition receipt",
      );
    }
    if (!PHYSICAL_NODE_TYPE_SET.has(source.type) || !PHYSICAL_NODE_TYPE_SET.has(target.type)) {
      throw new Error("demonstrated_transition endpoints must use physical surface-graph node types");
    }
    demonstratedTransitionBinding = normalizeDemonstratedTransitionBinding(
      edge.demonstrated_transition_binding,
    );
  } else if (edge.demonstrated_transition_binding != null) {
    throw new Error(
      "edge.demonstrated_transition_binding is only valid for demonstrated_transition edges",
    );
  }
  const confidence = edge.confidence == null ? 1 : edge.confidence;
  if (typeof confidence !== "number" || !Number.isFinite(confidence) || confidence < 0 || confidence > 1) {
    throw new Error("edge.confidence must be a finite number between 0 and 1");
  }
  const sourceArtifact = edge.source_artifact == null
    ? null
    : requireBoundedString(edge.source_artifact, "edge.source_artifact", { max: 4096 });
  const observedAt = edge.observed_at == null
    ? new Date().toISOString()
    : requireCanonicalTimestamp(edge.observed_at, "edge.observed_at");
  const canonical = {
    source,
    target,
    edge_type: edgeType,
    source_artifact: sourceArtifact,
  };
  if (demonstratedTransitionBinding != null) {
    canonical.demonstrated_transition_binding = demonstratedTransitionBinding;
  }
  const edgeHash = hashCanonicalJson(canonical);
  const normalized = {
    edge_hash: edgeHash,
    source,
    target,
    edge_type: edgeType,
    confidence,
    source_artifact: sourceArtifact,
    observed_at: observedAt,
  };
  if (demonstratedTransitionBinding != null) {
    normalized.demonstrated_transition_binding = demonstratedTransitionBinding;
  }
  return normalized;
}

function normalizeEdge(edge) {
  return normalizeEdgeInternal(edge, { verifiedTransition: false });
}

function edgeRecord(normalizedEdge) {
  const body = {
    schema_version: SURFACE_GRAPH_RECORD_VERSION,
    record_kind: "edge",
    ...normalizedEdge,
  };
  return deepFreeze({ ...body, record_digest: hashCanonicalJson(body) });
}

function assertRecordDigest(record, body, label) {
  const expected = hashCanonicalJson(body);
  if (requireDigest(record.record_digest, `${label}.record_digest`) !== expected) {
    throw new Error(`${label}.record_digest does not match the canonical record`);
  }
  return expected;
}

function normalizeCurrentEdgeRecord(record, label) {
  assertClosedObject(record, label, [
    "schema_version",
    "record_kind",
    "record_digest",
    "edge_hash",
    "source",
    "target",
    "edge_type",
    "confidence",
    "source_artifact",
    "observed_at",
  ]);
  if (record.schema_version !== SURFACE_GRAPH_RECORD_VERSION || record.record_kind !== "edge") {
    throw new Error(`${label} is not a version ${SURFACE_GRAPH_RECORD_VERSION} edge record`);
  }
  const normalized = normalizeEdge({
    source: record.source,
    target: record.target,
    edge_type: record.edge_type,
    confidence: record.confidence,
    source_artifact: record.source_artifact,
    observed_at: record.observed_at,
  });
  if (record.edge_hash !== normalized.edge_hash) throw new Error(`${label}.edge_hash does not match its edge`);
  const expected = edgeRecord(normalized);
  const { record_digest: _digest, ...body } = expected;
  assertRecordDigest(record, body, label);
  return expected;
}

function normalizeLegacyOrdinaryEdgeRecord(record, label) {
  if (!isPlainObject(record) || record.edge_type === "demonstrated_transition") {
    throw new Error("legacy_unsigned_demonstrated_transition");
  }
  assertClosedObject(record, label, [
    "edge_hash",
    "source",
    "target",
    "edge_type",
    "confidence",
    "source_artifact",
    "observed_at",
  ]);
  const normalized = normalizeEdge({
    source: record.source,
    target: record.target,
    edge_type: record.edge_type,
    confidence: record.confidence,
    source_artifact: record.source_artifact,
    observed_at: record.observed_at,
  });
  if (record.edge_hash !== normalized.edge_hash) throw new Error("legacy_edge_hash_mismatch");
  return edgeRecord(normalized);
}

function normalizeTransitionArcRecord(record, label) {
  assertClosedObject(record, label, [
    "schema_version",
    "record_kind",
    "record_digest",
    "edge_hash",
    "source",
    "target",
    "edge_type",
    "confidence",
    "source_artifact",
    "observed_at",
    "transition_receipt_ref",
    "transition_receipt_digest",
    "arc_id",
  ]);
  if (
    record.schema_version !== SURFACE_GRAPH_RECORD_VERSION
    || record.record_kind !== "verified_transition_arc"
  ) {
    throw new Error(`${label} is not a version ${SURFACE_GRAPH_RECORD_VERSION} transition arc`);
  }
  if (record.edge_type !== "demonstrated_transition" || record.confidence !== 1) {
    throw new Error(`${label} verified transition arcs have fixed kind and confidence`);
  }
  const body = {
    schema_version: SURFACE_GRAPH_RECORD_VERSION,
    record_kind: "verified_transition_arc",
    edge_hash: requireDigest(record.edge_hash, `${label}.edge_hash`),
    source: normalizeNode(record.source, `${label}.source`),
    target: normalizeNode(record.target, `${label}.target`),
    edge_type: "demonstrated_transition",
    confidence: 1,
    source_artifact: requireBoundedString(record.source_artifact, `${label}.source_artifact`, { max: 4096 }),
    observed_at: requireCanonicalTimestamp(record.observed_at, `${label}.observed_at`),
    transition_receipt_ref: requireBoundedString(
      record.transition_receipt_ref,
      `${label}.transition_receipt_ref`,
      { max: 512 },
    ),
    transition_receipt_digest: requireDigest(
      record.transition_receipt_digest,
      `${label}.transition_receipt_digest`,
    ),
    arc_id: requireBoundedString(record.arc_id, `${label}.arc_id`, { max: 128 }),
  };
  if (body.source_artifact !== body.transition_receipt_ref) {
    throw new Error(`${label}.source_artifact must be the transition receipt ref`);
  }
  assertRecordDigest(record, body, label);
  return deepFreeze({ ...body, record_digest: record.record_digest });
}

function readSurfaceRecords(filePath) {
  if (!fs.existsSync(filePath)) return { records: [], quarantined: [] };
  const stats = fs.lstatSync(filePath);
  if (!stats.isFile() || stats.isSymbolicLink() || stats.nlink !== 1) {
    throw new Error("surface-graph.jsonl must be a single-link regular file");
  }
  const raw = readFileUtf8(filePath, { label: "surface-graph.jsonl" });
  const lines = raw.split(/\r?\n/);
  const records = [];
  const quarantined = [];
  for (let i = 0; i < lines.length; i++) {
    if (lines[i].trim().length === 0) continue;
    let parsed;
    try {
      parsed = JSON.parse(lines[i]);
    } catch (error) {
      quarantined.push({
        source_line: i + 1,
        raw_record_digest: hashCanonicalJson({ raw: lines[i] }),
        reason_code: "malformed_json",
      });
      continue;
    }
    try {
      if (parsed && parsed.schema_version === SURFACE_GRAPH_RECORD_VERSION) {
        if (!SURFACE_GRAPH_RECORD_KINDS.includes(parsed.record_kind)) {
          throw new Error("unknown_record_kind");
        }
        records.push(parsed.record_kind === "edge"
          ? normalizeCurrentEdgeRecord(parsed, `surface-graph.jsonl line ${i + 1}`)
          : normalizeTransitionArcRecord(parsed, `surface-graph.jsonl line ${i + 1}`));
      } else {
        records.push(normalizeLegacyOrdinaryEdgeRecord(parsed, `surface-graph.jsonl line ${i + 1}`));
      }
    } catch {
      quarantined.push({
        source_line: i + 1,
        raw_record_digest: hashCanonicalJson(parsed),
        // Never persist parser input or attacker-controlled values in the
        // quarantine ledger. The content digest supports later correlation.
        reason_code: "invalid_or_untrusted_record",
      });
    }
  }
  return { records, quarantined };
}

function recordKey(record) {
  return record.record_kind === "verified_transition_arc"
    ? `transition:${record.transition_receipt_digest}:${record.arc_id}`
    : `edge:${record.edge_hash}`;
}

function recordSortKey(record) {
  return record.record_kind === "verified_transition_arc"
    ? `1:${record.transition_receipt_digest}:${record.arc_id}`
    : `0:${record.edge_hash}`;
}

function cleanupOrphanTemps(filePath) {
  const dirPath = path.dirname(filePath);
  const base = path.basename(filePath).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const pattern = new RegExp(`^\\.${base}\\.pending-[0-9]+-[a-f0-9]{24}$`);
  for (const name of fs.readdirSync(dirPath)) {
    if (!pattern.test(name)) continue;
    const candidate = path.join(dirPath, name);
    let stats;
    try { stats = fs.lstatSync(candidate); } catch { continue; }
    if (stats.isFile() && !stats.isSymbolicLink()) fs.unlinkSync(candidate);
  }
}

function fsyncDirectory(dirPath) {
  const descriptor = fs.openSync(dirPath, fs.constants.O_RDONLY);
  try { fs.fsyncSync(descriptor); } finally { fs.closeSync(descriptor); }
}

function writeJsonlAtomic(filePath, records, { sortKey, label, sessionDirectoryIdentity }) {
  assertSafeSessionDirectoryIdentity(sessionDirectoryIdentity);
  if (path.dirname(filePath) !== sessionDirectoryIdentity.directory.path) {
    throw new Error(`${label} path is not anchored in the verified session directory`);
  }
  const sorted = records.slice().sort((left, right) => sortKey(left).localeCompare(sortKey(right)));
  const body = sorted.map((record) => JSON.stringify(record)).join("\n");
  const content = body.length > 0 ? `${body}\n` : "";
  let mode = 0o600;
  try {
    const stats = fs.lstatSync(filePath);
    if (!stats.isFile() || stats.isSymbolicLink() || stats.nlink !== 1) {
      throw new Error(`${label} must be a single-link regular file`);
    }
    mode = stats.mode & 0o777;
  } catch (error) {
    if (!error || error.code !== "ENOENT") throw error;
  }
  assertSafeSessionDirectoryIdentity(sessionDirectoryIdentity);
  cleanupOrphanTemps(filePath);
  const tempPath = path.join(
    path.dirname(filePath),
    `.${path.basename(filePath)}.pending-${process.pid}-${crypto.randomBytes(12).toString("hex")}`,
  );
  let descriptor;
  try {
    const flags = fs.constants.O_CREAT
      | fs.constants.O_EXCL
      | fs.constants.O_WRONLY
      | (fs.constants.O_NOFOLLOW || 0);
    descriptor = fs.openSync(tempPath, flags, mode);
    fs.writeFileSync(descriptor, content, { encoding: "utf8" });
    fs.fsyncSync(descriptor);
    fs.closeSync(descriptor);
    descriptor = null;
    assertSafeSessionDirectoryIdentity(sessionDirectoryIdentity);
    fs.renameSync(tempPath, filePath);
    assertSafeSessionDirectoryIdentity(sessionDirectoryIdentity);
    fsyncDirectory(path.dirname(filePath));
  } finally {
    if (descriptor != null) fs.closeSync(descriptor);
    try { fs.unlinkSync(tempPath); } catch {}
  }
}

function writeRecordsToJsonl(filePath, records, sessionDirectoryIdentity) {
  return writeJsonlAtomic(filePath, records, {
    sortKey: recordSortKey,
    label: "surface-graph.jsonl",
    sessionDirectoryIdentity,
  });
}

function surfaceGraphQuarantinePath(domain) {
  return path.join(sessionDir(domain), "surface-graph-quarantine.jsonl");
}

function normalizeQuarantineRecord(input, label = "surface_graph_quarantine_record") {
  assertClosedObject(input, label, [
    "version",
    "record_kind",
    "target_domain",
    "source_store",
    "source_line",
    "raw_record_digest",
    "reason_code",
    "quarantined_at",
    "quarantine_digest",
  ]);
  if (input.version !== SURFACE_GRAPH_QUARANTINE_VERSION
      || input.record_kind !== "surface_graph_quarantine") {
    throw new Error(`${label} has an unsupported version or record kind`);
  }
  if (!Number.isSafeInteger(input.source_line) || input.source_line < 1) {
    throw new Error(`${label}.source_line must be a positive safe integer`);
  }
  const body = {
    version: SURFACE_GRAPH_QUARANTINE_VERSION,
    record_kind: "surface_graph_quarantine",
    target_domain: assertSafeDomain(input.target_domain),
    source_store: input.source_store === "surface-graph.jsonl"
      ? "surface-graph.jsonl"
      : (() => { throw new Error(`${label}.source_store must be surface-graph.jsonl`); })(),
    source_line: input.source_line,
    raw_record_digest: requireDigest(input.raw_record_digest, `${label}.raw_record_digest`),
    reason_code: requireBoundedString(input.reason_code, `${label}.reason_code`, { max: 256 }),
    quarantined_at: requireCanonicalTimestamp(input.quarantined_at, `${label}.quarantined_at`),
  };
  const quarantineDigest = hashCanonicalJson(body);
  if (requireDigest(input.quarantine_digest, `${label}.quarantine_digest`) !== quarantineDigest) {
    throw new Error(`${label}.quarantine_digest does not match the canonical record`);
  }
  return deepFreeze({ ...body, quarantine_digest: quarantineDigest });
}

function readQuarantineRecords(filePath) {
  if (!fs.existsSync(filePath)) return [];
  const stats = fs.lstatSync(filePath);
  if (!stats.isFile() || stats.isSymbolicLink() || stats.nlink !== 1) {
    throw new Error("surface-graph-quarantine.jsonl must be a single-link regular file");
  }
  const raw = readFileUtf8(filePath, { label: "surface-graph-quarantine.jsonl" });
  return raw.split(/\r?\n/).filter((line) => line.trim().length > 0).map((line, index) => {
    let parsed;
    try { parsed = JSON.parse(line); } catch {
      throw new Error(`surface-graph-quarantine.jsonl line ${index + 1} is malformed JSON`);
    }
    return normalizeQuarantineRecord(parsed, `surface-graph-quarantine.jsonl line ${index + 1}`);
  });
}

function writeQuarantineRecords(filePath, records, sessionDirectoryIdentity) {
  return writeJsonlAtomic(filePath, records, {
    sortKey: (record) => record.quarantine_digest,
    label: "surface-graph-quarantine.jsonl",
    sessionDirectoryIdentity,
  });
}

function appendEdges({ target_domain, edges }) {
  const domain = assertSafeDomain(target_domain);
  const rootIdentity = assertSafeSurfaceGraphRoot({ create: true });
  if (!Array.isArray(edges)) {
    throw new Error("edges must be an array");
  }
  const normalizedEdges = edges.map((edge) => edgeRecord(normalizeEdge(edge)));
  return withSessionLock(domain, (sessionDirectoryIdentity) => {
    assertSurfaceGraphRootIdentity(rootIdentity);
    assertSafeSessionDirectoryIdentity(sessionDirectoryIdentity);
    const filePath = surfaceGraphJsonlPath(domain);
    const { records: existing, quarantined } = readSurfaceRecords(filePath);
    if (quarantined.length > 0) {
      throw new Error("surface graph contains quarantined rows; explicit migration is required before append");
    }
    const byHash = new Map(existing.map((record) => [recordKey(record), record]));
    let newCount = 0;
    let replacedCount = 0;
    for (const normalized of normalizedEdges) {
      const key = recordKey(normalized);
      if (byHash.has(key)) {
        replacedCount += 1;
      } else {
        newCount += 1;
      }
      byHash.set(key, normalized);
    }
    const merged = Array.from(byHash.values());
    assertSurfaceGraphRootIdentity(rootIdentity);
    assertSafeSessionDirectoryIdentity(sessionDirectoryIdentity);
    writeRecordsToJsonl(filePath, merged, sessionDirectoryIdentity);
    return {
      target_domain: domain,
      new_count: newCount,
      replaced_count: replacedCount,
      total_in_graph: merged.length,
    };
  });
}

function assertSyncResolverResult(value, label) {
  if (value && typeof value.then === "function") throw new Error(`${label} must resolve synchronously`);
  if (value == null) throw new Error(`${label} is unavailable`);
  return value;
}

// The service accepts content resolvers only. Session authority, trust-root
// pinning, and time are resolved here from Bob's canonical on-disk session;
// callers cannot provide a nucleus, clock, or Boolean authorization predicate.
function createPhysicalSurfaceGraphServerService(input = {}) {
  assertClosedObject(input, "physical surface graph server service", [
    "target_domain",
    "resolve_receipt",
    "resolve_trust_registry",
  ], ["resolve_live_revalidation_receipt"]);
  const targetDomain = assertSafeDomain(input.target_domain);
  for (const field of ["resolve_receipt", "resolve_trust_registry"]) {
    if (typeof input[field] !== "function") {
      throw new Error(`physical surface graph server service.${field} must be a function`);
    }
  }
  if (input.resolve_live_revalidation_receipt != null
      && typeof input.resolve_live_revalidation_receipt !== "function") {
    throw new Error(
      "physical surface graph server service.resolve_live_revalidation_receipt must be a function",
    );
  }
  const state = {
    targetDomain,
    resolveReceipt: input.resolve_receipt,
    resolveTrustRegistry: input.resolve_trust_registry,
    resolveLiveRevalidationReceipt: input.resolve_live_revalidation_receipt || null,
    clockFloorMs: null,
  };
  // Fail at composition time if the bound session is absent, corrupt, legacy
  // physical-disabled, or lacks an authenticated transition trust-root pin.
  assertSafeSurfaceGraphRoot({ create: false });
  resolvePhysicalSurfaceGraphServerContext(state, targetDomain);
  const service = Object.freeze({
    version: PHYSICAL_SURFACE_GRAPH_SERVER_SERVICE_VERSION,
    service_kind: "physical_surface_graph_server",
    appendVerifiedTransition(request) {
      return appendVerifiedTransition(state, request);
    },
    queryVerifiedTransitionEdges(request = {}) {
      return queryVerifiedTransitionEdges(state, request);
    },
    migrateSurfaceGraph(request = {}) {
      return migrateSurfaceGraph(state, request);
    },
  });
  PHYSICAL_SURFACE_GRAPH_SERVER_SERVICES.add(service);
  PHYSICAL_SURFACE_GRAPH_SERVER_SERVICE_STATE.set(service, state);
  return service;
}

// Composition consumers must not accept a duck-typed object whose query
// method returns caller-authored "verified" edges.  This brand says only that
// the service was constructed by the Bob-owned SurfaceGraph implementation;
// its resolver callbacks remain content lookup seams, never attestations.  A
// branded service still rereads the canonical nucleus/trust pin and verifies
// every signed receipt on every append/query.
function assertPhysicalSurfaceGraphServerService(value, expectedTargetDomain = null) {
  if (!value || !PHYSICAL_SURFACE_GRAPH_SERVER_SERVICES.has(value)) {
    throw new Error("physical SurfaceGraph composition requires a Bob-owned server service");
  }
  const state = PHYSICAL_SURFACE_GRAPH_SERVER_SERVICE_STATE.get(value);
  if (!state || state.targetDomain == null) {
    throw new Error("physical SurfaceGraph server service state is unavailable");
  }
  if (expectedTargetDomain != null
      && state.targetDomain !== assertSafeDomain(expectedTargetDomain)) {
    throw new Error("physical SurfaceGraph server service target_domain drift");
  }
  // Re-resolve the canonical session at each trust-boundary crossing.  The
  // returned service identity is descriptive only; successful resolution is
  // the authority/freshness check.
  resolvePhysicalSurfaceGraphServerContext(state, state.targetDomain);
  return value;
}

function describePhysicalSurfaceGraphServerService(value) {
  const service = assertPhysicalSurfaceGraphServerService(value);
  const state = PHYSICAL_SURFACE_GRAPH_SERVER_SERVICE_STATE.get(service);
  return deepFreeze({
    version: PHYSICAL_SURFACE_GRAPH_SERVER_SERVICE_VERSION,
    service_kind: "physical_surface_graph_server",
    target_domain: state.targetDomain,
  });
}

function resolvePhysicalSurfaceGraphServerContext(state, targetDomain) {
  if (!state || state.targetDomain !== targetDomain) {
    throw new Error("physical surface graph service is not bound to this target domain");
  }
  const nucleus = readVerifiedSessionNucleus(targetDomain);
  const physicalScope = nucleus.physical_scope;
  if (!physicalScope || physicalScope.physical_enabled !== true) {
    throw new Error("current canonical session has physical operations disabled");
  }
  const context = deepFreeze({
    version: PHYSICAL_SURFACE_GRAPH_SERVER_SERVICE_VERSION,
    target_domain: targetDomain,
    session_nucleus_hash: requireDigest(nucleus.nucleus_hash, "current physical session nucleus_hash"),
    physical_enabled: true,
    physical_scope_projection_digest: requireDigest(
      physicalScope.projection_digest,
      "current physical session context.physical_scope_projection_digest",
    ),
    authority_epoch: physicalScope.authority_epoch,
    revocation_generation: physicalScope.revocation_generation,
    transition_receipt_registry_digest: requireDigest(
      physicalScope.transition_receipt_registry_digest,
      "current physical session context.transition_receipt_registry_digest",
    ),
  });
  return { state, context };
}

function resolveAuthorityTrustedNow(state) {
  const nowMs = Date.now();
  if (!Number.isFinite(nowMs)) throw new Error("physical surface system clock is unavailable");
  if (state.clockFloorMs != null && nowMs < state.clockFloorMs) {
    throw new Error("physical surface system clock moved backwards");
  }
  state.clockFloorMs = nowMs;
  return new Date(nowMs).toISOString();
}

function quarantineIdentity(record) {
  return hashCanonicalJson({
    domain: "hacker-bob/surface-graph-quarantine-identity/v1",
    target_domain: record.target_domain,
    source_store: record.source_store,
    source_line: record.source_line,
    raw_record_digest: record.raw_record_digest,
    reason_code: record.reason_code,
  });
}

function buildQuarantineRecord(domain, row, quarantinedAt) {
  const body = {
    version: SURFACE_GRAPH_QUARANTINE_VERSION,
    record_kind: "surface_graph_quarantine",
    target_domain: domain,
    source_store: "surface-graph.jsonl",
    source_line: row.source_line,
    raw_record_digest: row.raw_record_digest,
    reason_code: row.reason_code,
    quarantined_at: quarantinedAt,
  };
  return normalizeQuarantineRecord({
    ...body,
    quarantine_digest: hashCanonicalJson(body),
  });
}

// Migration is deliberately exposed only through the target-bound service.
// Quarantine evidence lands durably before the source graph is replaced, so a
// crash can leave redundant evidence but can never erase the rejected rows.
function migrateSurfaceGraph(state, input = {}) {
  assertClosedObject(input, "surface graph migration request", []);
  const domain = state.targetDomain;
  const rootIdentity = assertSafeSurfaceGraphRoot({ create: true });
  return withSessionLock(domain, (sessionDirectoryIdentity) => {
    assertSurfaceGraphRootIdentity(rootIdentity);
    assertSafeSessionDirectoryIdentity(sessionDirectoryIdentity);
    resolvePhysicalSurfaceGraphServerContext(state, domain);
    const quarantinedAt = resolveAuthorityTrustedNow(state);
    const graphPath = surfaceGraphJsonlPath(domain);
    const quarantinePath = surfaceGraphQuarantinePath(domain);
    const { records, quarantined } = readSurfaceRecords(graphPath);
    const existingQuarantine = readQuarantineRecords(quarantinePath);
    const quarantineByIdentity = new Map(
      existingQuarantine.map((record) => [quarantineIdentity(record), record]),
    );
    let newQuarantineCount = 0;
    for (const row of quarantined) {
      const candidate = buildQuarantineRecord(domain, row, quarantinedAt);
      const identity = quarantineIdentity(candidate);
      if (quarantineByIdentity.has(identity)) continue;
      quarantineByIdentity.set(identity, candidate);
      newQuarantineCount += 1;
    }
    const quarantineRecords = [...quarantineByIdentity.values()];
    if (quarantined.length > 0) {
      assertSurfaceGraphRootIdentity(rootIdentity);
      assertSafeSessionDirectoryIdentity(sessionDirectoryIdentity);
      writeQuarantineRecords(quarantinePath, quarantineRecords, sessionDirectoryIdentity);
    }

    const canonicalByKey = new Map();
    for (const record of records) {
      const key = recordKey(record);
      const prior = canonicalByKey.get(key);
      if (prior && prior.record_digest !== record.record_digest) {
        throw new Error(`surface graph migration encountered a conflicting canonical record for ${key}`);
      }
      canonicalByKey.set(key, record);
    }
    const canonicalRecords = [...canonicalByKey.values()];
    if (fs.existsSync(graphPath)) {
      assertSurfaceGraphRootIdentity(rootIdentity);
      assertSafeSessionDirectoryIdentity(sessionDirectoryIdentity);
      writeRecordsToJsonl(graphPath, canonicalRecords, sessionDirectoryIdentity);
    }
    return deepFreeze({
      version: 1,
      target_domain: domain,
      migration_complete: true,
      canonical_record_count: canonicalRecords.length,
      rejected_source_record_count: quarantined.length,
      new_quarantine_record_count: newQuarantineCount,
      total_quarantine_record_count: quarantineRecords.length,
    });
  });
}

function resolveVerifiedTransitionReceipt({
  receiptRef,
  receiptDigest,
  state,
  context,
  mode,
  trustedNow,
}) {
  const rawReceipt = assertSyncResolverResult(
    state.resolveReceipt({
      session_context: context,
      receipt_ref: receiptRef,
      receipt_digest: receiptDigest,
    }),
    "physical surface transition receipt",
  );
  if (rawReceipt.receipt_ref !== receiptRef || rawReceipt.receipt_digest !== receiptDigest) {
    throw new Error("resolved physical surface transition receipt ref/digest drift");
  }
  const registryDigest = requireDigest(
    rawReceipt.issuer_registry_digest,
    "physical surface transition receipt.issuer_registry_digest",
  );
  if (registryDigest !== context.transition_receipt_registry_digest) {
    throw new Error("physical surface transition receipt registry is not authorized by the current session");
  }
  const trustRegistry = assertSyncResolverResult(
    state.resolveTrustRegistry({
      session_context: context,
      issuer_registry_digest: registryDigest,
    }),
    "physical surface transition trust registry",
  );
  assertDurableReceiptTrustRegistry(trustRegistry);
  if (trustRegistry.registry_digest !== registryDigest) {
    throw new Error("resolved physical surface transition trust-registry digest drift");
  }
  const receipt = normalizeAndVerifyPhysicalSurfaceTransitionReceipt(rawReceipt, trustRegistry, {
    mode,
    trusted_now: mode === "admission" ? trustedNow : null,
  });
  if (receipt.receipt_ref !== receiptRef || receipt.receipt_digest !== receiptDigest) {
    throw new Error("verified physical surface transition receipt ref/digest drift");
  }
  return { receipt, trustRegistry };
}

function physicalSurfaceAuthorityContextDigest(context) {
  return hashCanonicalJson({
    domain: "hacker-bob/physical-surface-live-authority-context/v1",
    service_version: PHYSICAL_SURFACE_GRAPH_SERVER_SERVICE_VERSION,
    target_domain: context.target_domain,
    session_nucleus_hash: context.session_nucleus_hash,
    physical_scope_projection_digest: context.physical_scope_projection_digest,
    authority_epoch: context.authority_epoch,
    revocation_generation: context.revocation_generation,
    transition_receipt_registry_digest: context.transition_receipt_registry_digest,
  });
}

function liveRevalidationComparable(payload) {
  return {
    target_domain: payload.target_domain,
    session_nucleus_hash: payload.session_nucleus_hash,
    claim_verdict_ref: payload.claim_verdict_ref,
    claim_verdict_hash: payload.claim_verdict_hash,
    verified_claim_projection_digest: payload.verified_claim_projection_digest,
    claim_verdict_signer_key_id: payload.claim_verdict_signer_key_id,
    claim_verdict_trust_root_epoch: payload.claim_verdict_trust_root_epoch,
    verifier_template_id: payload.verifier_template_id,
    verifier_template_version: payload.verifier_template_version,
    verifier_template_digest: payload.verifier_template_digest,
    decision_rule_digest: payload.decision_rule_digest,
    upstream_execution_identities: payload.upstream_execution_identities,
    upstream_context_digest: payload.upstream_context_digest,
    physical_state_epoch: payload.physical_state_epoch,
    physical_state_digest: payload.physical_state_digest,
    validity_kind: payload.validity_kind,
    valid_from: payload.valid_from,
    expires_at: payload.expires_at,
    capability_instance_ref: payload.capability_instance_ref,
    custody_state_digest: payload.custody_state_digest,
  };
}

function revalidateLiveTransition({ state, context, receipt, trustRegistry }) {
  if (state.resolveLiveRevalidationReceipt == null) {
    return deepFreeze({ eligible: false, reason: "live_revalidation_unavailable" });
  }
  const payload = receipt.payload;
  const challengeNonce = crypto.randomBytes(32).toString("base64url");
  const authorityContextDigest = physicalSurfaceAuthorityContextDigest(context);
  const transitionPayloadDigest = hashCanonicalJson(payload);
  try {
    const raw = assertSyncResolverResult(
      state.resolveLiveRevalidationReceipt(deepFreeze({
        version: 1,
        target_domain: context.target_domain,
        session_context: context,
        transition_receipt_ref: receipt.receipt_ref,
        transition_receipt_digest: receipt.receipt_digest,
        transition_payload_digest: transitionPayloadDigest,
        authority_context_digest: authorityContextDigest,
        challenge_nonce: challengeNonce,
      })),
      "physical surface live-revalidation receipt",
    );
    if (raw.issuer_registry_digest !== context.transition_receipt_registry_digest) {
      return deepFreeze({ eligible: false, reason: "live_revalidation_registry_drift" });
    }
    const resolvedRegistry = assertSyncResolverResult(
      state.resolveTrustRegistry({
        session_context: context,
        issuer_registry_digest: raw.issuer_registry_digest,
      }),
      "physical surface live-revalidation trust registry",
    );
    assertDurableReceiptTrustRegistry(resolvedRegistry);
    if (resolvedRegistry !== trustRegistry
        && resolvedRegistry.registry_digest !== trustRegistry.registry_digest) {
      return deepFreeze({ eligible: false, reason: "live_revalidation_registry_drift" });
    }
    // Sample trusted time after the challenge response is signed. Sampling
    // before invoking a synchronous signer would make every freshly signed
    // response appear microscopically future-dated.
    const verificationNow = resolveAuthorityTrustedNow(state);
    const liveReceipt = normalizeAndVerifyPhysicalSurfaceLiveRevalidationReceipt(
      raw,
      resolvedRegistry,
      { mode: "admission", trusted_now: verificationNow },
    );
    const live = liveReceipt.payload;
    if (
      live.challenge_nonce !== challengeNonce
      || live.authority_context_digest !== authorityContextDigest
      || live.transition_receipt_ref !== receipt.receipt_ref
      || live.transition_receipt_digest !== receipt.receipt_digest
      || live.transition_payload_digest !== transitionPayloadDigest
      || hashCanonicalJson(liveRevalidationComparable(live))
        !== hashCanonicalJson(liveRevalidationComparable(payload))
    ) {
      return deepFreeze({ eligible: false, reason: "live_revalidation_binding_drift" });
    }
    const nowMs = Date.parse(verificationNow);
    const revalidatedAtMs = Date.parse(live.revalidated_at);
    const revalidationExpiresAtMs = Date.parse(live.revalidation_expires_at);
    if (
      revalidatedAtMs > nowMs
      || nowMs - revalidatedAtMs > LIVE_REVALIDATION_MAX_AGE_MS
      || revalidationExpiresAtMs <= nowMs
      || revalidationExpiresAtMs - revalidatedAtMs > LIVE_REVALIDATION_MAX_TTL_MS
    ) {
      return deepFreeze({ eligible: false, reason: "live_revalidation_stale" });
    }
    return deepFreeze({
      eligible: true,
      reason: "live_capability_current",
      receipt_ref: liveReceipt.receipt_ref,
      receipt_digest: liveReceipt.receipt_digest,
      signer_key_id: liveReceipt.issuer_key_id,
      trust_root_epoch: liveReceipt.issuer_epoch,
      revalidated_at: live.revalidated_at,
      revalidation_expires_at: live.revalidation_expires_at,
    });
  } catch {
    return deepFreeze({ eligible: false, reason: "live_revalidation_invalid" });
  }
}

function transitionArcRecords(receipt) {
  const payload = normalizePhysicalSurfaceTransitionPayload(receipt.payload);
  const participantById = new Map(payload.participants.map((entry) => [entry.participant_id, entry]));
  return payload.arcs.map((arc) => {
    const source = participantById.get(arc.source_participant_id).node;
    const target = participantById.get(arc.target_participant_id).node;
    const edgeHash = hashCanonicalJson({
      domain: "hacker-bob/surface-graph/verified-transition-arc/v2",
      transition_receipt_digest: receipt.receipt_digest,
      arc_id: arc.arc_id,
      source,
      target,
      edge_type: "demonstrated_transition",
    });
    const body = {
      schema_version: SURFACE_GRAPH_RECORD_VERSION,
      record_kind: "verified_transition_arc",
      edge_hash: edgeHash,
      source,
      target,
      edge_type: "demonstrated_transition",
      confidence: 1,
      source_artifact: receipt.receipt_ref,
      observed_at: payload.decided_at,
      transition_receipt_ref: receipt.receipt_ref,
      transition_receipt_digest: receipt.receipt_digest,
      arc_id: arc.arc_id,
    };
    return deepFreeze({ ...body, record_digest: hashCanonicalJson(body) });
  });
}

function appendVerifiedTransition(state, input = {}) {
  const domain = state.targetDomain;
  const rootIdentity = assertSafeSurfaceGraphRoot({ create: true });
  assertClosedObject(input, "verified transition append request", [
    "receipt_ref",
    "receipt_digest",
  ]);
  const receiptRef = requireBoundedString(input.receipt_ref, "receipt_ref", { max: 512 });
  const receiptDigest = requireDigest(input.receipt_digest, "receipt_digest");
  return withSessionLock(domain, (sessionDirectoryIdentity) => {
    assertSurfaceGraphRootIdentity(rootIdentity);
    assertSafeSessionDirectoryIdentity(sessionDirectoryIdentity);
    // All mutable authority and admission inputs are resolved after acquiring
    // the same session lock that serializes persistence. Canonical input shape
    // checks above are authority-independent and intentionally remain outside.
    const { context } = resolvePhysicalSurfaceGraphServerContext(state, domain);
    const trustedNow = resolveAuthorityTrustedNow(state);
    const { receipt } = resolveVerifiedTransitionReceipt({
      receiptRef,
      receiptDigest,
      state,
      context,
      mode: "admission",
      trustedNow,
    });
    const payload = receipt.payload;
    if (payload.target_domain !== domain) throw new Error("physical surface transition target_domain drift");
    if (payload.session_nucleus_hash !== context.session_nucleus_hash) {
      throw new Error("physical surface transition session nucleus drift");
    }
    if (payload.validity_kind === "live_capability") {
      if (Date.parse(trustedNow) < Date.parse(payload.valid_from) || Date.parse(trustedNow) >= Date.parse(payload.expires_at)) {
        throw new Error("physical surface transition live capability is outside its validity window");
      }
    }
    const derived = transitionArcRecords(receipt);
    const filePath = surfaceGraphJsonlPath(domain);
    const { records: existing, quarantined } = readSurfaceRecords(filePath);
    if (quarantined.length > 0) {
      throw new Error("surface graph contains quarantined rows; explicit migration is required before append");
    }
    const byKey = new Map(existing.map((record) => [recordKey(record), record]));
    let newCount = 0;
    let replacedCount = 0;
    for (const record of derived) {
      const key = recordKey(record);
      const prior = byKey.get(key);
      if (prior) {
        if (prior.record_digest !== record.record_digest) {
          throw new Error(`physical surface transition arc collision for ${record.arc_id}`);
        }
        replacedCount += 1;
      } else {
        newCount += 1;
      }
      byKey.set(key, record);
    }
    const merged = [...byKey.values()];
    assertSurfaceGraphRootIdentity(rootIdentity);
    assertSafeSessionDirectoryIdentity(sessionDirectoryIdentity);
    writeRecordsToJsonl(filePath, merged, sessionDirectoryIdentity);
    return {
      target_domain: domain,
      transition_receipt_ref: receipt.receipt_ref,
      transition_receipt_digest: receipt.receipt_digest,
      derived_arc_count: derived.length,
      new_count: newCount,
      replaced_count: replacedCount,
      total_in_graph: merged.length,
    };
  });
}

function transitionBinding(receipt, arc) {
  const payload = receipt.payload;
  const participantById = new Map(payload.participants.map((entry) => [entry.participant_id, entry]));
  const digests = physicalSurfaceTransitionProjectionDigests(payload);
  const binding = {
    session_nucleus_hash: payload.session_nucleus_hash,
    plan_hash: payload.plan_hash,
    execution_request_digest: payload.execution_request_digest,
    claim_predicate_digest: payload.claim_predicate_digest,
    verdict_ref: payload.claim_verdict_ref,
    verdict_hash: payload.claim_verdict_hash,
    verified_claim_projection_digest: payload.verified_claim_projection_digest,
    verdict_signer_principal_ref: payload.claim_verdict_signer_principal_ref,
    verifier_template_id: payload.verifier_template_id,
    verifier_template_version: payload.verifier_template_version,
    verifier_template_digest: payload.verifier_template_digest,
    decision_rule_digest: payload.decision_rule_digest,
    verifier_execution_receipt_ref: payload.verifier_execution_receipt_ref,
    verifier_execution_receipt_digest: payload.verifier_execution_receipt_digest,
    executed_evidence_registry_digest: payload.executed_evidence_registry_digest,
    verdict_signer_key_id: payload.claim_verdict_signer_key_id,
    trust_root_epoch: payload.claim_verdict_trust_root_epoch,
    verdict_trust_domain_ref: payload.claim_verdict_trust_domain_ref,
    verdict_independence_domain_ref: payload.claim_verdict_independence_domain_ref,
    verdict_trust_registry_digest: payload.claim_verdict_trust_registry_digest,
    verdict_signer_enrollment_digest: payload.claim_verdict_signer_enrollment_digest,
    verdict_authorization_context_digest: payload.claim_verdict_authorization_context_digest,
    transition_signer_key_id: receipt.issuer_key_id,
    transition_trust_root_epoch: receipt.issuer_epoch,
    upstream_execution_identities: payload.upstream_execution_identities,
    upstream_context_digest: payload.upstream_context_digest,
    transition_state_epoch: payload.physical_state_epoch,
    transition_state_digest: payload.physical_state_digest,
    validity_kind: payload.validity_kind,
    valid_from: payload.valid_from,
    transition_instance_ref: receipt.receipt_ref,
    transition_receipt_digest: receipt.receipt_digest,
    participants_digest: digests.participants_digest,
    source_participant_role: participantById.get(arc.source_participant_id).role,
    target_participant_role: participantById.get(arc.target_participant_id).role,
  };
  if (payload.validity_kind === "live_capability") {
    binding.expires_at = payload.expires_at;
    binding.capability_instance_ref = payload.capability_instance_ref;
    binding.custody_state_digest = payload.custody_state_digest;
  }
  if (Object.prototype.hasOwnProperty.call(
    payload,
    "external_observer_independence_domain_count",
  )) {
    binding.external_observer_independence_domain_count =
      payload.external_observer_independence_domain_count;
    binding.external_observer_independence_domain_digest =
      payload.external_observer_independence_domain_digest;
    binding.high_impact_corroboration_satisfied =
      payload.high_impact_corroboration_satisfied;
  }
  return normalizeDemonstratedTransitionBinding(binding);
}

function queryVerifiedTransitionEdgesUnderLock(state, input = {}) {
  const domain = state.targetDomain;
  assertClosedObject(input, "verified transition query request", [], [
    "source_type",
    "target_type",
    "source_id",
    "target_id",
    "verdict_ref",
    "verified_claim_projection_digest",
    "limit",
  ]);
  const {
    source_type: sourceType,
    target_type: targetType,
    source_id: sourceId,
    target_id: targetId,
    verdict_ref: verdictRef,
    verified_claim_projection_digest: verifiedClaimProjectionDigest,
    limit,
  } = input;
  for (const [field, value] of [["source_type", sourceType], ["target_type", targetType]]) {
    if (value != null && !NODE_TYPE_SET.has(value)) {
      throw new Error(`verified transition query request.${field} is not in the surface-graph node vocabulary`);
    }
  }
  if (sourceId != null) requireBoundedString(sourceId, "verified transition query request.source_id");
  if (targetId != null) requireBoundedString(targetId, "verified transition query request.target_id");
  if ((verdictRef == null) !== (verifiedClaimProjectionDigest == null)) {
    throw new Error(
      "verified transition query verdict_ref and verified_claim_projection_digest must be supplied together",
    );
  }
  if (verdictRef != null) {
    requireBoundedString(verdictRef, "verified transition query request.verdict_ref");
    requireDigest(
      verifiedClaimProjectionDigest,
      "verified transition query request.verified_claim_projection_digest",
    );
  }
  const { context } = resolvePhysicalSurfaceGraphServerContext(state, domain);
  const now = resolveAuthorityTrustedNow(state);
  const { records, quarantined } = readSurfaceRecords(surfaceGraphJsonlPath(domain));
  const groups = new Map();
  for (const record of records) {
    if (record.record_kind !== "verified_transition_arc") continue;
    const list = groups.get(record.transition_receipt_digest) || [];
    list.push(record);
    groups.set(record.transition_receipt_digest, list);
  }
  const edges = [];
  let historicalOnly = 0;
  for (const group of groups.values()) {
    const first = group[0];
    const { receipt, trustRegistry } = resolveVerifiedTransitionReceipt({
      receiptRef: first.transition_receipt_ref,
      receiptDigest: first.transition_receipt_digest,
      state,
      context,
      mode: "historical",
      trustedNow: null,
    });
    if (receipt.payload.target_domain !== domain
        || receipt.payload.session_nucleus_hash !== context.session_nucleus_hash) {
      throw new Error("stored physical surface transition domain/session nucleus drift");
    }
    const expected = transitionArcRecords(receipt);
    const actualByKey = new Map(group.map((record) => [recordKey(record), record]));
    if (actualByKey.size !== group.length || expected.length !== group.length) {
      throw new Error("stored physical surface transition arc set is incomplete or duplicated");
    }
    for (const record of expected) {
      const actual = actualByKey.get(recordKey(record));
      if (!actual || actual.record_digest !== record.record_digest) {
        throw new Error("stored physical surface transition arc drift");
      }
    }
    if (verdictRef != null
        && (receipt.payload.claim_verdict_ref !== verdictRef
          || receipt.payload.verified_claim_projection_digest
            !== verifiedClaimProjectionDigest)) {
      continue;
    }
    let liveRevalidation = deepFreeze({
      eligible: false,
      reason: "historical_event_only",
    });
    const payload = receipt.payload;
    if (payload.validity_kind === "live_capability") {
      if (Date.parse(now) < Date.parse(payload.valid_from)
          || Date.parse(now) >= Date.parse(payload.expires_at)) {
        liveRevalidation = deepFreeze({
          eligible: false,
          reason: "live_capability_expired_or_not_yet_valid",
        });
      } else {
        try {
          normalizeAndVerifyPhysicalSurfaceTransitionReceipt(receipt, trustRegistry, {
            mode: "admission",
            trusted_now: now,
          });
          liveRevalidation = revalidateLiveTransition({
            state,
            context,
            receipt,
            trustRegistry,
          });
        } catch {
          liveRevalidation = deepFreeze({ eligible: false, reason: "issuer_not_current" });
        }
      }
    }
    if (liveRevalidation.eligible && quarantined.length > 0) {
      liveRevalidation = deepFreeze({
        eligible: false,
        reason: "surface_graph_quarantine_present",
      });
    }
    if (!liveRevalidation.eligible) historicalOnly += expected.length;
    const arcById = new Map(payload.arcs.map((arc) => [arc.arc_id, arc]));
    for (const record of expected) {
      if (sourceType && record.source.type !== sourceType) continue;
      if (targetType && record.target.type !== targetType) continue;
      if (sourceId && record.source.id !== sourceId) continue;
      if (targetId && record.target.id !== targetId) continue;
      const arc = arcById.get(record.arc_id);
      const projected = {
        edge_hash: record.edge_hash,
        source: record.source,
        target: record.target,
        edge_type: record.edge_type,
        confidence: 1,
        source_artifact: record.source_artifact,
        observed_at: record.observed_at,
        demonstrated_transition_binding: transitionBinding(receipt, arc),
        prerequisite_eligible: liveRevalidation.eligible,
        eligibility_reason: liveRevalidation.reason,
      };
      if (liveRevalidation.eligible) {
        projected.live_revalidation = deepFreeze({
          receipt_ref: liveRevalidation.receipt_ref,
          receipt_digest: liveRevalidation.receipt_digest,
          signer_key_id: liveRevalidation.signer_key_id,
          trust_root_epoch: liveRevalidation.trust_root_epoch,
          revalidated_at: liveRevalidation.revalidated_at,
          revalidation_expires_at: liveRevalidation.revalidation_expires_at,
        });
      }
      edges.push(deepFreeze(projected));
    }
  }
  const cap = Number.isInteger(limit) && limit > 0 ? Math.min(limit, MAX_QUERY_LIMIT) : DEFAULT_QUERY_LIMIT;
  return {
    edges: edges.slice(0, cap),
    total_matched: edges.length,
    verified_transition_record_count: [...groups.values()].reduce((sum, group) => sum + group.length, 0),
    historical_only_count: historicalOnly,
    out_of_scope_count: 0,
    quarantined_count: quarantined.length,
  };
}

function queryVerifiedTransitionEdges(state, input = {}) {
  const domain = state.targetDomain;
  const rootIdentity = assertSafeSurfaceGraphRoot({ create: false });
  return withSessionLock(domain, (sessionDirectoryIdentity) => {
    assertSurfaceGraphRootIdentity(rootIdentity);
    assertSafeSessionDirectoryIdentity(sessionDirectoryIdentity);
    const result = queryVerifiedTransitionEdgesUnderLock(state, input);
    assertSurfaceGraphRootIdentity(rootIdentity);
    assertSafeSessionDirectoryIdentity(sessionDirectoryIdentity);
    return result;
  });
}

function queryEdges({
  target_domain,
  source_type,
  target_type,
  edge_type,
  source_id,
  target_id,
  limit,
}) {
  const domain = assertSafeDomain(target_domain);
  assertSafeSurfaceGraphRoot({ create: false });
  for (const [field, value] of [["source_type", source_type], ["target_type", target_type]]) {
    if (value != null && !NODE_TYPE_SET.has(value)) {
      throw new Error(`surface graph query ${field} is not in the node vocabulary`);
    }
  }
  if (edge_type != null && !EDGE_TYPE_SET.has(edge_type)) {
    throw new Error("surface graph query edge_type is not in the edge vocabulary");
  }
  if (source_id != null) requireBoundedString(source_id, "surface graph query source_id");
  if (target_id != null) requireBoundedString(target_id, "surface graph query target_id");
  if (edge_type === "demonstrated_transition") {
    throw new Error("demonstrated transitions require queryVerifiedTransitionEdges with receipt revalidation");
  }
  const filePath = surfaceGraphJsonlPath(domain);
  const { records, quarantined } = readSurfaceRecords(filePath);
  if (records.length === 0) {
    return {
      edges: [],
      total_in_graph: 0,
      total_matched: 0,
      verified_transition_records_withheld: 0,
      quarantined_count: quarantined.length,
    };
  }
  const matched = [];
  let withheld = 0;
  for (const record of records) {
    if (record.record_kind === "verified_transition_arc") {
      withheld += 1;
      continue;
    }
    if (source_type && record.source.type !== source_type) continue;
    if (target_type && record.target.type !== target_type) continue;
    if (edge_type && record.edge_type !== edge_type) continue;
    if (source_id && record.source.id !== source_id) continue;
    if (target_id && record.target.id !== target_id) continue;
    matched.push(record);
  }
  const cap = Number.isInteger(limit) && limit > 0
    ? Math.min(limit, MAX_QUERY_LIMIT)
    : DEFAULT_QUERY_LIMIT;
  return {
    edges: matched.slice(0, cap).map(({ schema_version, record_kind, record_digest, ...edge }) => edge),
    total_in_graph: records.length,
    total_matched: matched.length,
    verified_transition_records_withheld: withheld,
    quarantined_count: quarantined.length,
  };
}

function neighbors({ target_domain, node_type, node_id, direction, limit }) {
  if (typeof node_type !== "string" || node_type.length === 0) {
    throw new Error("neighbors node_type must be a non-empty string");
  }
  if (typeof node_id !== "string" || node_id.length === 0) {
    throw new Error("neighbors node_id must be a non-empty string");
  }
  const dir = direction === "incoming" ? "incoming" : direction === "outgoing" ? "outgoing" : "both";
  const result = { incoming: [], outgoing: [] };
  if (dir === "outgoing" || dir === "both") {
    const out = queryEdges({ target_domain, source_type: node_type, source_id: node_id, limit });
    result.outgoing = out.edges;
  }
  if (dir === "incoming" || dir === "both") {
    const inc = queryEdges({ target_domain, target_type: node_type, target_id: node_id, limit });
    result.incoming = inc.edges;
  }
  return result;
}

const MECHANISM_NODE_TYPES = Object.freeze([
  "principal",
  "credential",
  "policy_gate",
  "effect",
  "intervention",
]);

function queryMechanismView({ target_domain, principal_id, effect_id, limit }) {
  const cap = Number.isInteger(limit) && limit > 0
    ? Math.min(limit, MAX_QUERY_LIMIT)
    : DEFAULT_QUERY_LIMIT;
  const edges = queryEdges({ target_domain, limit: MAX_QUERY_LIMIT }).edges
    .filter((edge) => MECHANISM_NODE_TYPES.includes(edge.source.type)
      || MECHANISM_NODE_TYPES.includes(edge.target.type));
  const filtered = edges.filter((edge) => {
    if (principal_id && edge.source.id !== principal_id && edge.target.id !== principal_id) return false;
    if (effect_id && edge.source.id !== effect_id && edge.target.id !== effect_id) return false;
    return true;
  });
  return {
    edges: filtered.slice(0, cap),
    total_matched: filtered.length,
    total_mechanism_edges: edges.length,
    total_in_graph: queryEdges({ target_domain, limit: 1 }).total_in_graph,
    node_types: MECHANISM_NODE_TYPES,
  };
}

const SURFACE_SLICE_DEFAULT_LIMIT = 5;
const SURFACE_SLICE_MAX_LIMIT = 25;

function topByCount(map, limit) {
  return Array.from(map.entries())
    .map(([id, count]) => ({ id, count }))
    .sort((a, b) => {
      if (b.count !== a.count) return b.count - a.count;
      return a.id.localeCompare(b.id);
    })
    .slice(0, limit);
}

function summarizeSurfaceGraphForSurface(domain, surfaceObj, options) {
  if (surfaceObj == null || typeof surfaceObj !== "object") return null;
  const surfaceId = typeof surfaceObj.id === "string" ? surfaceObj.id : null;
  if (!surfaceId) return null;
  const opts = options || {};
  const requestedLimit = Number.isInteger(opts.limit) && opts.limit > 0
    ? opts.limit
    : SURFACE_SLICE_DEFAULT_LIMIT;
  const limit = Math.min(requestedLimit, SURFACE_SLICE_MAX_LIMIT);
  let outgoing;
  try {
    outgoing = queryEdges({
      target_domain: domain,
      source_type: "surface",
      source_id: surfaceId,
      limit: MAX_QUERY_LIMIT,
    });
  } catch (_err) {
    return null;
  }
  if (outgoing.total_in_graph === 0) return null;
  const endpointHits = new Map();
  const jsFileHits = new Map();
  const techHits = new Map();
  const subdomainHits = new Map();
  const secretHits = new Map();
  for (const edge of outgoing.edges) {
    const targetType = edge.target && edge.target.type;
    const targetId = edge.target && edge.target.id;
    if (typeof targetId !== "string" || targetId.length === 0) continue;
    const map = targetType === "endpoint" ? endpointHits
      : targetType === "js_file" ? jsFileHits
      : targetType === "tech" ? techHits
      : targetType === "subdomain" ? subdomainHits
      : targetType === "secret_marker" ? secretHits
      : null;
    if (map == null) continue;
    map.set(targetId, (map.get(targetId) || 0) + 1);
  }
  let claimedAuthHits = new Map();
  for (const [endpoint] of endpointHits) {
    let authEdges;
    try {
      authEdges = queryEdges({
        target_domain: domain,
        source_type: "endpoint",
        source_id: endpoint,
        edge_type: "claims_auth",
        limit: 50,
      });
    } catch (_err) {
      continue;
    }
    for (const edge of authEdges.edges) {
      const scheme = edge.target && edge.target.id;
      if (typeof scheme !== "string" || scheme.length === 0) continue;
      claimedAuthHits.set(scheme, (claimedAuthHits.get(scheme) || 0) + 1);
    }
  }
  return {
    total_in_graph: outgoing.total_in_graph,
    edges_summarized: outgoing.total_matched,
    related_endpoints: topByCount(endpointHits, limit),
    related_js_files: topByCount(jsFileHits, limit),
    related_subdomains: topByCount(subdomainHits, limit),
    related_tech: topByCount(techHits, limit),
    leaked_secret_markers: topByCount(secretHits, limit),
    claimed_auth_schemes: topByCount(claimedAuthHits, limit),
    truncated: outgoing.total_matched > outgoing.edges.length,
    limit,
  };
}

module.exports = {
  appendEdges,
  assertPhysicalSurfaceGraphServerService,
  createPhysicalSurfaceGraphServerService,
  describePhysicalSurfaceGraphServerService,
  queryEdges,
  queryMechanismView,
  neighbors,
  normalizeEdge,
  summarizeSurfaceGraphForSurface,
  PHYSICAL_NODE_TYPES,
  PHYSICAL_RELATIONSHIP_EDGE_TYPES,
  PHYSICAL_SURFACE_GRAPH_ONTOLOGY,
  NODE_TYPES,
  EDGE_TYPES,
  DEMONSTRATED_TRANSITION_VALIDITY_KINDS,
  SURFACE_GRAPH_RECORD_VERSION,
  PHYSICAL_SURFACE_GRAPH_SERVER_SERVICE_VERSION,
  LIVE_REVALIDATION_MAX_AGE_MS,
  LIVE_REVALIDATION_MAX_TTL_MS,
  DEFAULT_QUERY_LIMIT,
  MAX_QUERY_LIMIT,
};
