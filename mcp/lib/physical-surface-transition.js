"use strict";

const { assertSafeDomain } = require("./paths.js");
const { hashCanonicalJson, isPlainObject } = require("./verification-contracts.js");

const PHYSICAL_SURFACE_TRANSITION_VERSION = 1;
const PHYSICAL_SURFACE_LIVE_REVALIDATION_VERSION = 1;
const PHYSICAL_SURFACE_GRAPH_SCHEMA_VERSION = 2;
const MAX_TRANSITION_PARTICIPANTS = 64;
const MAX_TRANSITION_ARCS = 128;

const PHYSICAL_SURFACE_NODE_TYPES = Object.freeze([
  "interface",
  "medium",
  "signal_source",
  "actuator",
  "control_point",
  "verifier",
  "enclosure",
  "zone",
  "representation",
  "instrument",
  "asset",
  "physical_barrier",
  "physical_zone",
  "network_attachment",
  "sensor",
  "alarm",
  "workspace",
]);

const PHYSICAL_TRANSITION_PARTICIPANT_ROLES = Object.freeze([
  "subject",
  "source_state",
  "target_state",
  "stimulus_source",
  "medium",
  "actuator",
  "control",
  "observer",
  "verifier",
  "enclosure",
  "zone",
  "instrument",
  "context",
  "outcome",
]);

const VALIDITY_KINDS = Object.freeze(["historical_event", "live_capability"]);
const VERIFIED_TRANSITION_REASON_CODE = "differential_verified";
const PHYSICAL_CLAIM_VERDICT_REF_PREFIX = "physical-claim-verdict";
const NODE_TYPE_SET = new Set(PHYSICAL_SURFACE_NODE_TYPES);
const ROLE_SET = new Set(PHYSICAL_TRANSITION_PARTICIPANT_ROLES);
const VALIDITY_KIND_SET = new Set(VALIDITY_KINDS);
const DIGEST_RE = /^[a-f0-9]{64}$/;
const ID_RE = /^[a-z][a-z0-9._-]{0,127}$/;
const TOKEN_RE = /^[A-Za-z0-9][A-Za-z0-9._:@-]{0,190}$/;
const OPAQUE_REF_RE = /^[a-z][a-z0-9._-]{0,63}:[A-Za-z0-9][A-Za-z0-9._:-]{0,190}$/;
const CHALLENGE_NONCE_RE = /^[A-Za-z0-9_-]{43}$/;

function deepFreeze(value) {
  if (!value || typeof value !== "object" || Object.isFrozen(value)) return value;
  for (const child of Object.values(value)) deepFreeze(child);
  return Object.freeze(value);
}

function assertClosedObject(value, label, required, optional = []) {
  if (!isPlainObject(value)) throw new Error(`${label} must be an object`);
  const allowed = new Set([...required, ...optional]);
  const unknown = Object.keys(value).filter((field) => !allowed.has(field)).sort();
  if (unknown.length > 0) throw new Error(`${label} has unknown fields: ${unknown.join(", ")}`);
  const missing = required.filter((field) => !Object.prototype.hasOwnProperty.call(value, field));
  if (missing.length > 0) throw new Error(`${label} is missing fields: ${missing.join(", ")}`);
}

function assertDigest(value, label) {
  if (typeof value !== "string" || !DIGEST_RE.test(value)) {
    throw new Error(`${label} must be a lowercase SHA-256 digest`);
  }
  return value;
}

function assertId(value, label) {
  if (typeof value !== "string" || !ID_RE.test(value)) {
    throw new Error(`${label} must be a lowercase identifier`);
  }
  return value;
}

function assertToken(value, label) {
  if (typeof value !== "string" || !TOKEN_RE.test(value)) {
    throw new Error(`${label} must be a bounded opaque token`);
  }
  return value;
}

function assertOpaqueRef(value, label, prefix = null) {
  if (typeof value !== "string" || !OPAQUE_REF_RE.test(value)) {
    throw new Error(`${label} must be a namespaced opaque reference`);
  }
  if (prefix != null && !value.startsWith(`${prefix}:`)) {
    throw new Error(`${label} must use the ${prefix}: namespace`);
  }
  return value;
}

function assertTimestamp(value, label) {
  if (typeof value !== "string" || Number.isNaN(Date.parse(value)) || new Date(value).toISOString() !== value) {
    throw new Error(`${label} must be a canonical UTC ISO-8601 timestamp`);
  }
  return value;
}

function assertInteger(value, label, min = 0) {
  if (!Number.isSafeInteger(value) || value < min) throw new Error(`${label} must be a safe integer >= ${min}`);
  return value;
}

function normalizeEpoch(value, label) {
  if (Number.isSafeInteger(value) && value >= 0) return value;
  if (typeof value === "string" && value.length > 0 && value.length <= 128) return value;
  throw new Error(`${label} must be a non-negative safe integer or bounded non-empty string`);
}

function normalizeNode(value, label) {
  assertClosedObject(value, label, ["type", "id"]);
  if (!NODE_TYPE_SET.has(value.type)) {
    throw new Error(`${label}.type is not in the physical surface vocabulary: ${value.type}`);
  }
  if (typeof value.id !== "string" || value.id.length === 0 || value.id.length > 2048) {
    throw new Error(`${label}.id must be a non-empty string of at most 2048 characters`);
  }
  return deepFreeze({ type: value.type, id: value.id });
}

function normalizeParticipants(value, label) {
  if (!Array.isArray(value) || value.length < 2 || value.length > MAX_TRANSITION_PARTICIPANTS) {
    throw new Error(`${label} must contain 2 to ${MAX_TRANSITION_PARTICIPANTS} participants`);
  }
  const participants = value.map((entry, index) => {
    const entryLabel = `${label}[${index}]`;
    assertClosedObject(entry, entryLabel, ["participant_id", "role", "node"]);
    const role = entry.role;
    if (!ROLE_SET.has(role)) {
      throw new Error(`${entryLabel}.role must be one of: ${PHYSICAL_TRANSITION_PARTICIPANT_ROLES.join(", ")}`);
    }
    return {
      participant_id: assertId(entry.participant_id, `${entryLabel}.participant_id`),
      role,
      node: normalizeNode(entry.node, `${entryLabel}.node`),
    };
  }).sort((left, right) => left.participant_id.localeCompare(right.participant_id));
  if (new Set(participants.map((entry) => entry.participant_id)).size !== participants.length) {
    throw new Error(`${label} participant_id values must be unique`);
  }
  const semanticParticipants = participants.map((entry) => (
    `${entry.role}\u0000${entry.node.type}\u0000${entry.node.id}`
  ));
  if (new Set(semanticParticipants).size !== semanticParticipants.length) {
    throw new Error(`${label} must not contain duplicate role/node projections under different aliases`);
  }
  return deepFreeze(participants);
}

function normalizeArcs(value, participants, label) {
  if (!Array.isArray(value) || value.length === 0 || value.length > MAX_TRANSITION_ARCS) {
    throw new Error(`${label} must contain 1 to ${MAX_TRANSITION_ARCS} arcs`);
  }
  const participantIds = new Set(participants.map((entry) => entry.participant_id));
  const used = new Set();
  const arcs = value.map((entry, index) => {
    const entryLabel = `${label}[${index}]`;
    assertClosedObject(entry, entryLabel, [
      "arc_id",
      "source_participant_id",
      "target_participant_id",
      "edge_type",
    ]);
    const source = assertId(entry.source_participant_id, `${entryLabel}.source_participant_id`);
    const target = assertId(entry.target_participant_id, `${entryLabel}.target_participant_id`);
    if (!participantIds.has(source) || !participantIds.has(target)) {
      throw new Error(`${entryLabel} endpoints must resolve to declared participants`);
    }
    if (source === target) throw new Error(`${entryLabel} may not be a self-loop`);
    if (entry.edge_type !== "demonstrated_transition") {
      throw new Error(`${entryLabel}.edge_type must be demonstrated_transition`);
    }
    used.add(source);
    used.add(target);
    return {
      arc_id: assertId(entry.arc_id, `${entryLabel}.arc_id`),
      source_participant_id: source,
      target_participant_id: target,
      edge_type: "demonstrated_transition",
    };
  }).sort((left, right) => left.arc_id.localeCompare(right.arc_id));
  if (new Set(arcs.map((entry) => entry.arc_id)).size !== arcs.length) {
    throw new Error(`${label} arc_id values must be unique`);
  }
  const semanticArcs = arcs.map((entry) => (
    `${entry.source_participant_id}\u0000${entry.target_participant_id}\u0000${entry.edge_type}`
  ));
  if (new Set(semanticArcs).size !== semanticArcs.length) {
    throw new Error(`${label} must not contain duplicate semantic arcs under different IDs`);
  }
  if (used.size !== participants.length) throw new Error(`${label} must use every declared participant`);
  return deepFreeze(arcs);
}

function normalizeExecutionIdentities(value, label) {
  if (!Array.isArray(value) || value.length === 0 || value.length > 64) {
    throw new Error(`${label} must be a non-empty array with at most 64 entries`);
  }
  const normalized = value.map((entry, index) => (
    assertOpaqueRef(entry, `${label}[${index}]`, "execution")
  )).sort();
  if (new Set(normalized).size !== normalized.length) throw new Error(`${label} must not contain duplicates`);
  return deepFreeze(normalized);
}

function normalizePhysicalSurfaceTransitionTopology(input, label = "physical_surface_transition_topology") {
  assertClosedObject(input, label, ["target_domain", "participants", "arcs"]);
  const participants = normalizeParticipants(input.participants, `${label}.participants`);
  const arcs = normalizeArcs(input.arcs, participants, `${label}.arcs`);
  return deepFreeze({
    target_domain: assertSafeDomain(input.target_domain),
    participants,
    arcs,
  });
}

function physicalSurfaceTransitionClaimPredicateDigest(input) {
  const topology = normalizePhysicalSurfaceTransitionTopology(input);
  return hashCanonicalJson({
    domain: "hacker-bob/physical-surface-transition-claim-predicate/v1",
    surface_graph_schema_version: PHYSICAL_SURFACE_GRAPH_SCHEMA_VERSION,
    ...topology,
  });
}

function normalizePhysicalSurfaceTransitionPayload(input, label = "physical_surface_transition") {
  const required = [
    "version",
    "surface_graph_schema_version",
    "target_domain",
    "session_nucleus_hash",
    "experiment_id",
    "task_id",
    "attempt_id",
    "plan_hash",
    "execution_request_digest",
    "claim_predicate_digest",
    "claim_verdict_ref",
    "claim_verdict_hash",
    "claim_verdict_signer_key_id",
    "claim_verdict_signer_principal_ref",
    "claim_verdict_trust_root_epoch",
    "claim_verdict_trust_domain_ref",
    "claim_verdict_independence_domain_ref",
    "claim_verdict_trust_registry_digest",
    "claim_verdict_signer_enrollment_digest",
    "claim_verdict_authorization_context_digest",
    "verified_claim_projection_digest",
    "verifier_execution_receipt_ref",
    "verifier_execution_receipt_digest",
    "executed_evidence_registry_digest",
    "verifier_template_id",
    "verifier_template_version",
    "verifier_template_digest",
    "decision_rule_digest",
    "outcome",
    "reason_code",
    "decided_at",
    "upstream_execution_identities",
    "upstream_context_digest",
    "physical_state_epoch",
    "physical_state_digest",
    "validity_kind",
    "valid_from",
    "participants",
    "arcs",
  ];
  const liveCapabilityFields = ["expires_at", "capability_instance_ref", "custody_state_digest"];
  const observerAssuranceFields = [
    "external_observer_independence_domain_count",
    "external_observer_independence_domain_digest",
    "high_impact_corroboration_satisfied",
  ];
  const optional = [...liveCapabilityFields, ...observerAssuranceFields];
  assertClosedObject(input, label, required, optional);
  if (input.version !== PHYSICAL_SURFACE_TRANSITION_VERSION) {
    throw new Error(`${label}.version must be ${PHYSICAL_SURFACE_TRANSITION_VERSION}`);
  }
  if (input.surface_graph_schema_version !== PHYSICAL_SURFACE_GRAPH_SCHEMA_VERSION) {
    throw new Error(`${label}.surface_graph_schema_version must be ${PHYSICAL_SURFACE_GRAPH_SCHEMA_VERSION}`);
  }
  if (input.outcome !== "verified") throw new Error(`${label}.outcome must be verified`);
  if (input.reason_code !== VERIFIED_TRANSITION_REASON_CODE) {
    throw new Error(`${label}.reason_code must be ${VERIFIED_TRANSITION_REASON_CODE}`);
  }
  if (!VALIDITY_KIND_SET.has(input.validity_kind)) {
    throw new Error(`${label}.validity_kind must be one of: ${VALIDITY_KINDS.join(", ")}`);
  }
  const decidedAt = assertTimestamp(input.decided_at, `${label}.decided_at`);
  const validFrom = assertTimestamp(input.valid_from, `${label}.valid_from`);
  if (Date.parse(validFrom) < Date.parse(decidedAt)) throw new Error(`${label}.valid_from must not predate decided_at`);
  const participants = normalizeParticipants(input.participants, `${label}.participants`);
  const arcs = normalizeArcs(input.arcs, participants, `${label}.arcs`);
  const body = {
    version: PHYSICAL_SURFACE_TRANSITION_VERSION,
    surface_graph_schema_version: PHYSICAL_SURFACE_GRAPH_SCHEMA_VERSION,
    target_domain: assertSafeDomain(input.target_domain),
    session_nucleus_hash: assertDigest(input.session_nucleus_hash, `${label}.session_nucleus_hash`),
    experiment_id: assertId(input.experiment_id, `${label}.experiment_id`),
    task_id: assertToken(input.task_id, `${label}.task_id`),
    attempt_id: assertToken(input.attempt_id, `${label}.attempt_id`),
    plan_hash: assertDigest(input.plan_hash, `${label}.plan_hash`),
    execution_request_digest: assertDigest(input.execution_request_digest, `${label}.execution_request_digest`),
    claim_predicate_digest: assertDigest(input.claim_predicate_digest, `${label}.claim_predicate_digest`),
    claim_verdict_ref: assertOpaqueRef(
      input.claim_verdict_ref,
      `${label}.claim_verdict_ref`,
      PHYSICAL_CLAIM_VERDICT_REF_PREFIX,
    ),
    claim_verdict_hash: assertDigest(input.claim_verdict_hash, `${label}.claim_verdict_hash`),
    claim_verdict_signer_key_id: assertOpaqueRef(
      input.claim_verdict_signer_key_id,
      `${label}.claim_verdict_signer_key_id`,
      "signer-key",
    ),
    claim_verdict_signer_principal_ref: assertOpaqueRef(
      input.claim_verdict_signer_principal_ref,
      `${label}.claim_verdict_signer_principal_ref`,
      "principal",
    ),
    claim_verdict_trust_root_epoch: assertInteger(
      input.claim_verdict_trust_root_epoch,
      `${label}.claim_verdict_trust_root_epoch`,
      1,
    ),
    claim_verdict_trust_domain_ref: assertOpaqueRef(
      input.claim_verdict_trust_domain_ref,
      `${label}.claim_verdict_trust_domain_ref`,
      "trust-domain",
    ),
    claim_verdict_independence_domain_ref: assertOpaqueRef(
      input.claim_verdict_independence_domain_ref,
      `${label}.claim_verdict_independence_domain_ref`,
      "independence-domain",
    ),
    claim_verdict_trust_registry_digest: assertDigest(
      input.claim_verdict_trust_registry_digest,
      `${label}.claim_verdict_trust_registry_digest`,
    ),
    claim_verdict_signer_enrollment_digest: assertDigest(
      input.claim_verdict_signer_enrollment_digest,
      `${label}.claim_verdict_signer_enrollment_digest`,
    ),
    claim_verdict_authorization_context_digest: assertDigest(
      input.claim_verdict_authorization_context_digest,
      `${label}.claim_verdict_authorization_context_digest`,
    ),
    verified_claim_projection_digest: assertDigest(
      input.verified_claim_projection_digest,
      `${label}.verified_claim_projection_digest`,
    ),
    verifier_execution_receipt_ref: assertOpaqueRef(
      input.verifier_execution_receipt_ref,
      `${label}.verifier_execution_receipt_ref`,
      "verifier-execution",
    ),
    verifier_execution_receipt_digest: assertDigest(
      input.verifier_execution_receipt_digest,
      `${label}.verifier_execution_receipt_digest`,
    ),
    executed_evidence_registry_digest: assertDigest(
      input.executed_evidence_registry_digest,
      `${label}.executed_evidence_registry_digest`,
    ),
    verifier_template_id: assertId(input.verifier_template_id, `${label}.verifier_template_id`),
    verifier_template_version: assertInteger(
      input.verifier_template_version,
      `${label}.verifier_template_version`,
      1,
    ),
    verifier_template_digest: assertDigest(
      input.verifier_template_digest,
      `${label}.verifier_template_digest`,
    ),
    decision_rule_digest: assertDigest(input.decision_rule_digest, `${label}.decision_rule_digest`),
    outcome: "verified",
    reason_code: VERIFIED_TRANSITION_REASON_CODE,
    decided_at: decidedAt,
    upstream_execution_identities: normalizeExecutionIdentities(
      input.upstream_execution_identities,
      `${label}.upstream_execution_identities`,
    ),
    upstream_context_digest: assertDigest(input.upstream_context_digest, `${label}.upstream_context_digest`),
    physical_state_epoch: normalizeEpoch(input.physical_state_epoch, `${label}.physical_state_epoch`),
    physical_state_digest: assertDigest(input.physical_state_digest, `${label}.physical_state_digest`),
    validity_kind: input.validity_kind,
    valid_from: validFrom,
    participants,
    arcs,
  };
  const observerAssurancePresent = observerAssuranceFields.filter((field) => (
    Object.prototype.hasOwnProperty.call(input, field)
  ));
  if (observerAssurancePresent.length !== 0
      && observerAssurancePresent.length !== observerAssuranceFields.length) {
    throw new Error(`${label} external-observer assurance fields must be all present or all absent`);
  }
  if (observerAssurancePresent.length === observerAssuranceFields.length) {
    const observerDomainCount = assertInteger(
      input.external_observer_independence_domain_count,
      `${label}.external_observer_independence_domain_count`,
      0,
    );
    if (observerDomainCount > 256) {
      throw new Error(`${label}.external_observer_independence_domain_count must not exceed 256`);
    }
    if (typeof input.high_impact_corroboration_satisfied !== "boolean"
        || input.high_impact_corroboration_satisfied !== (observerDomainCount >= 2)) {
      throw new Error(
        `${label}.high_impact_corroboration_satisfied must exactly reflect two independent observer domains`,
      );
    }
    body.external_observer_independence_domain_count = observerDomainCount;
    body.external_observer_independence_domain_digest = assertDigest(
      input.external_observer_independence_domain_digest,
      `${label}.external_observer_independence_domain_digest`,
    );
    body.high_impact_corroboration_satisfied = input.high_impact_corroboration_satisfied;
  }
  if (input.validity_kind === "live_capability") {
    for (const field of liveCapabilityFields) {
      if (!Object.prototype.hasOwnProperty.call(input, field)) throw new Error(`${label}.${field} is required for live_capability`);
    }
    body.expires_at = assertTimestamp(input.expires_at, `${label}.expires_at`);
    if (Date.parse(body.expires_at) <= Date.parse(validFrom)) {
      throw new Error(`${label}.expires_at must be after valid_from`);
    }
    body.capability_instance_ref = assertOpaqueRef(
      input.capability_instance_ref,
      `${label}.capability_instance_ref`,
    );
    body.custody_state_digest = assertDigest(input.custody_state_digest, `${label}.custody_state_digest`);
  } else if (liveCapabilityFields.some((field) => Object.prototype.hasOwnProperty.call(input, field))) {
    throw new Error(`${label} historical_event must not carry live-capability fields`);
  }
  return deepFreeze(body);
}

function physicalSurfaceTransitionProjectionDigests(payloadInput) {
  const payload = normalizePhysicalSurfaceTransitionPayload(payloadInput);
  const participantsDigest = hashCanonicalJson(payload.participants);
  const arcsDigest = hashCanonicalJson(payload.arcs);
  return deepFreeze({
    participants_digest: participantsDigest,
    arcs_digest: arcsDigest,
    projection_digest: hashCanonicalJson({ payload, participants_digest: participantsDigest, arcs_digest: arcsDigest }),
  });
}

// A live transition can satisfy a capability prerequisite only when a current,
// challenge-bound authority attests that the exact state/custody projection
// signed into the transition still holds. This payload is intentionally
// provider-neutral: the authority may be backed by a broker, controller,
// observer, or another registered physical-state verifier.
function normalizePhysicalSurfaceLiveRevalidationPayload(
  input,
  label = "physical_surface_live_revalidation",
) {
  assertClosedObject(input, label, [
    "version",
    "surface_graph_schema_version",
    "target_domain",
    "session_nucleus_hash",
    "authority_context_digest",
    "transition_receipt_ref",
    "transition_receipt_digest",
    "transition_payload_digest",
    "challenge_nonce",
    "claim_verdict_ref",
    "claim_verdict_hash",
    "verified_claim_projection_digest",
    "claim_verdict_signer_key_id",
    "claim_verdict_trust_root_epoch",
    "verifier_template_id",
    "verifier_template_version",
    "verifier_template_digest",
    "decision_rule_digest",
    "upstream_execution_identities",
    "upstream_context_digest",
    "physical_state_epoch",
    "physical_state_digest",
    "validity_kind",
    "valid_from",
    "expires_at",
    "capability_instance_ref",
    "custody_state_digest",
    "status",
    "revalidated_at",
    "revalidation_expires_at",
  ]);
  if (input.version !== PHYSICAL_SURFACE_LIVE_REVALIDATION_VERSION) {
    throw new Error(`${label}.version must be ${PHYSICAL_SURFACE_LIVE_REVALIDATION_VERSION}`);
  }
  if (input.surface_graph_schema_version !== PHYSICAL_SURFACE_GRAPH_SCHEMA_VERSION) {
    throw new Error(`${label}.surface_graph_schema_version must be ${PHYSICAL_SURFACE_GRAPH_SCHEMA_VERSION}`);
  }
  if (input.validity_kind !== "live_capability") {
    throw new Error(`${label}.validity_kind must be live_capability`);
  }
  if (input.status !== "current") throw new Error(`${label}.status must be current`);
  if (typeof input.challenge_nonce !== "string" || !CHALLENGE_NONCE_RE.test(input.challenge_nonce)) {
    throw new Error(`${label}.challenge_nonce must be a canonical 256-bit base64url nonce`);
  }
  const validFrom = assertTimestamp(input.valid_from, `${label}.valid_from`);
  const expiresAt = assertTimestamp(input.expires_at, `${label}.expires_at`);
  const revalidatedAt = assertTimestamp(input.revalidated_at, `${label}.revalidated_at`);
  const revalidationExpiresAt = assertTimestamp(
    input.revalidation_expires_at,
    `${label}.revalidation_expires_at`,
  );
  if (Date.parse(expiresAt) <= Date.parse(validFrom)) {
    throw new Error(`${label}.expires_at must be after valid_from`);
  }
  if (Date.parse(revalidatedAt) < Date.parse(validFrom)
      || Date.parse(revalidatedAt) >= Date.parse(expiresAt)) {
    throw new Error(`${label}.revalidated_at must fall inside the capability validity window`);
  }
  if (Date.parse(revalidationExpiresAt) <= Date.parse(revalidatedAt)
      || Date.parse(revalidationExpiresAt) > Date.parse(expiresAt)) {
    throw new Error(
      `${label}.revalidation_expires_at must follow revalidated_at and not exceed capability expiry`,
    );
  }
  return deepFreeze({
    version: PHYSICAL_SURFACE_LIVE_REVALIDATION_VERSION,
    surface_graph_schema_version: PHYSICAL_SURFACE_GRAPH_SCHEMA_VERSION,
    target_domain: assertSafeDomain(input.target_domain),
    session_nucleus_hash: assertDigest(input.session_nucleus_hash, `${label}.session_nucleus_hash`),
    authority_context_digest: assertDigest(
      input.authority_context_digest,
      `${label}.authority_context_digest`,
    ),
    transition_receipt_ref: assertOpaqueRef(
      input.transition_receipt_ref,
      `${label}.transition_receipt_ref`,
      "surface-transition",
    ),
    transition_receipt_digest: assertDigest(
      input.transition_receipt_digest,
      `${label}.transition_receipt_digest`,
    ),
    transition_payload_digest: assertDigest(
      input.transition_payload_digest,
      `${label}.transition_payload_digest`,
    ),
    challenge_nonce: input.challenge_nonce,
    claim_verdict_ref: assertOpaqueRef(
      input.claim_verdict_ref,
      `${label}.claim_verdict_ref`,
      PHYSICAL_CLAIM_VERDICT_REF_PREFIX,
    ),
    claim_verdict_hash: assertDigest(input.claim_verdict_hash, `${label}.claim_verdict_hash`),
    verified_claim_projection_digest: assertDigest(
      input.verified_claim_projection_digest,
      `${label}.verified_claim_projection_digest`,
    ),
    claim_verdict_signer_key_id: assertOpaqueRef(
      input.claim_verdict_signer_key_id,
      `${label}.claim_verdict_signer_key_id`,
      "signer-key",
    ),
    claim_verdict_trust_root_epoch: assertInteger(
      input.claim_verdict_trust_root_epoch,
      `${label}.claim_verdict_trust_root_epoch`,
      1,
    ),
    verifier_template_id: assertId(input.verifier_template_id, `${label}.verifier_template_id`),
    verifier_template_version: assertInteger(
      input.verifier_template_version,
      `${label}.verifier_template_version`,
      1,
    ),
    verifier_template_digest: assertDigest(
      input.verifier_template_digest,
      `${label}.verifier_template_digest`,
    ),
    decision_rule_digest: assertDigest(input.decision_rule_digest, `${label}.decision_rule_digest`),
    upstream_execution_identities: normalizeExecutionIdentities(
      input.upstream_execution_identities,
      `${label}.upstream_execution_identities`,
    ),
    upstream_context_digest: assertDigest(
      input.upstream_context_digest,
      `${label}.upstream_context_digest`,
    ),
    physical_state_epoch: normalizeEpoch(input.physical_state_epoch, `${label}.physical_state_epoch`),
    physical_state_digest: assertDigest(input.physical_state_digest, `${label}.physical_state_digest`),
    validity_kind: "live_capability",
    valid_from: validFrom,
    expires_at: expiresAt,
    capability_instance_ref: assertOpaqueRef(
      input.capability_instance_ref,
      `${label}.capability_instance_ref`,
    ),
    custody_state_digest: assertDigest(input.custody_state_digest, `${label}.custody_state_digest`),
    status: "current",
    revalidated_at: revalidatedAt,
    revalidation_expires_at: revalidationExpiresAt,
  });
}

module.exports = {
  MAX_TRANSITION_ARCS,
  MAX_TRANSITION_PARTICIPANTS,
  PHYSICAL_SURFACE_GRAPH_SCHEMA_VERSION,
  PHYSICAL_SURFACE_LIVE_REVALIDATION_VERSION,
  PHYSICAL_SURFACE_NODE_TYPES,
  PHYSICAL_SURFACE_TRANSITION_VERSION,
  PHYSICAL_TRANSITION_PARTICIPANT_ROLES,
  VALIDITY_KINDS,
  normalizePhysicalSurfaceTransitionPayload,
  normalizePhysicalSurfaceLiveRevalidationPayload,
  normalizePhysicalSurfaceTransitionTopology,
  physicalSurfaceTransitionClaimPredicateDigest,
  physicalSurfaceTransitionProjectionDigests,
};
