"use strict";

// Plane-PH PH-S11 provider-neutral resource contract nucleus. This module is
// deliberately pure: it closes and hashes atomic resource requirements and
// broker reservation records, but it does not select a device, mint a fencing
// credential, read an inventory, acquire a lock, or dispatch an effect.

const {
  normalizeOpaqueRef,
  normalizeQuantityBound,
} = require("./physical-quantities.js");
const {
  hashCanonicalJson,
} = require("./verification-contracts.js");

const PHYSICAL_RESOURCE_BUNDLE_VERSION = 1;
const PHYSICAL_RESOURCE_BUNDLE_BINDING_VERSION = 1;
const PHYSICAL_RESERVATION_REQUEST_VERSION = 1;
const PHYSICAL_RESERVATION_RECEIPT_VERSION = 1;
const PHYSICAL_RESERVATION_PROJECTION_VERSION = 1;

const RESOURCE_KIND_VALUES = Object.freeze([
  "battery",
  "consumable",
  "control",
  "instrument",
  "observer",
  "operator_presence",
  "power_source",
  "rf_band",
  "rf_zone",
  "target_media",
  "thermal_zone",
  "workspace",
]);
const RESOURCE_OWNERSHIP_VALUES = Object.freeze(["exclusive", "shared"]);
const RESOURCE_PREEMPTION_VALUES = Object.freeze(["never", "before_effect_only"]);
const RESERVATION_STATE_VALUES = Object.freeze([
  "held",
  "cleanup_pending",
  "released",
  "fenced",
  "quarantined",
]);
const RESERVATION_TERMINAL_STATES = Object.freeze(["released", "fenced", "quarantined"]);
const RESERVATION_DISPOSITION_VALUES = Object.freeze([
  "cancelled_before_effect",
  "cleanup_confirmed",
  "expired_before_effect",
  "preempted_before_effect",
  "quarantined",
  "unknown_effect",
]);

const RESOURCE_REF_PREFIX = Object.freeze({
  battery: "battery",
  consumable: "consumable",
  control: "control",
  instrument: "instrument",
  observer: "observer",
  operator_presence: "principal",
  power_source: "power-source",
  rf_band: "rf-band",
  rf_zone: "rf-zone",
  target_media: "media",
  thermal_zone: "thermal-zone",
  workspace: "workspace",
});

// The constraint name carries scheduling semantics; the quantity registry
// carries canonical units and numeric limits. New constraints therefore need a
// Bob review instead of being provider-authored strings with implicit units.
const RESOURCE_CONSTRAINT_QUANTITY = Object.freeze({
  attempt_budget: "count",
  battery_floor: "battery_state",
  consumable_budget: "count",
  cooldown_duration: "duration",
  current_budget: "current",
  energy_budget: "energy",
  power_budget: "power",
  rf_bandwidth: "bandwidth",
  rf_frequency: "frequency",
  rf_power_ceiling: "rf_power",
  thermal_ceiling: "temperature",
  voltage_range: "voltage",
});

const RESOURCE_KIND_CONSTRAINTS = Object.freeze({
  battery: Object.freeze(["battery_floor", "energy_budget"]),
  consumable: Object.freeze(["consumable_budget"]),
  control: Object.freeze(["attempt_budget"]),
  instrument: Object.freeze([
    "attempt_budget",
    "cooldown_duration",
    "current_budget",
    "energy_budget",
    "power_budget",
    "thermal_ceiling",
    "voltage_range",
  ]),
  observer: Object.freeze([]),
  operator_presence: Object.freeze([]),
  power_source: Object.freeze(["current_budget", "energy_budget", "power_budget", "voltage_range"]),
  rf_band: Object.freeze(["rf_bandwidth", "rf_frequency", "rf_power_ceiling"]),
  rf_zone: Object.freeze(["rf_bandwidth", "rf_frequency", "rf_power_ceiling"]),
  target_media: Object.freeze(["attempt_budget"]),
  thermal_zone: Object.freeze(["cooldown_duration", "thermal_ceiling"]),
  workspace: Object.freeze(["attempt_budget"]),
});

const HASH_PATTERN = /^[a-f0-9]{64}$/;
const IDENTIFIER_PATTERN = /^[a-z][a-z0-9._-]{0,127}$/;
const TOKEN_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:@-]{0,190}$/;
const TASK_NODE_PATTERN = /^TG-[A-Za-z0-9][A-Za-z0-9._:@-]{0,190}$/;

function isPlainObject(value) {
  if (value == null || typeof value !== "object" || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function assertClosedObject(value, label, required, optional = []) {
  if (!isPlainObject(value)) throw new Error(`${label} must be an object`);
  const keys = Reflect.ownKeys(value);
  if (keys.some((key) => typeof key !== "string")) {
    throw new Error(`${label} cannot contain symbol fields`);
  }
  const allowed = new Set([...required, ...optional]);
  const unknown = keys.filter((key) => !allowed.has(key)).sort();
  if (unknown.length > 0) throw new Error(`${label} has unknown fields: ${unknown.join(", ")}`);
  const missing = required.filter((key) => !Object.prototype.hasOwnProperty.call(value, key));
  if (missing.length > 0) throw new Error(`${label} is missing fields: ${missing.join(", ")}`);
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || !("value" in descriptor) || !descriptor.enumerable) {
      throw new Error(`${label}.${key} must be an enumerable data field`);
    }
  }
  return value;
}

function assertDenseDataArray(value, label, minimum, maximum) {
  if (!Array.isArray(value) || value.length < minimum || value.length > maximum) {
    throw new Error(`${label} must be an array with ${minimum}-${maximum} entries`);
  }
  const keys = Reflect.ownKeys(value);
  if (keys.some((key) => typeof key !== "string")) {
    throw new Error(`${label} cannot contain symbol fields`);
  }
  const allowed = new Set([
    "length",
    ...Array.from({ length: value.length }, (_, index) => String(index)),
  ]);
  const unknown = keys.filter((key) => !allowed.has(key)).sort();
  if (unknown.length > 0) throw new Error(`${label} has adorned fields: ${unknown.join(", ")}`);
  for (let index = 0; index < value.length; index += 1) {
    const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
    if (!descriptor || !("value" in descriptor) || !descriptor.enumerable) {
      throw new Error(`${label}[${index}] must be an enumerable data field`);
    }
  }
  return value;
}

function deepFreeze(value) {
  if (!value || typeof value !== "object" || Object.isFrozen(value)) return value;
  for (const child of Object.values(value)) deepFreeze(child);
  return Object.freeze(value);
}

function assertEnum(value, values, label) {
  if (!values.includes(value)) throw new Error(`${label} must be one of ${values.join(", ")}`);
  return value;
}

function assertDigest(value, label) {
  if (typeof value !== "string" || !HASH_PATTERN.test(value)) {
    throw new Error(`${label} must be a lowercase SHA-256 digest`);
  }
  return value;
}

function assertIdentifier(value, label) {
  if (typeof value !== "string" || !IDENTIFIER_PATTERN.test(value)) {
    throw new Error(`${label} must be a lowercase identifier`);
  }
  return value;
}

function assertToken(value, label) {
  if (typeof value !== "string" || !TOKEN_PATTERN.test(value)) {
    throw new Error(`${label} must be a bounded opaque token`);
  }
  return value;
}

function assertTaskNodeId(value, label) {
  if (typeof value !== "string" || !TASK_NODE_PATTERN.test(value)) {
    throw new Error(`${label} must be a TaskGraph node ID`);
  }
  return value;
}

function assertInteger(value, label, minimum, maximum) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw new Error(`${label} must be a safe integer from ${minimum} through ${maximum}`);
  }
  return value;
}

function assertTimestamp(value, label) {
  if (typeof value !== "string") throw new Error(`${label} must be a canonical UTC timestamp`);
  const milliseconds = Date.parse(value);
  if (!Number.isFinite(milliseconds) || new Date(milliseconds).toISOString() !== value) {
    throw new Error(`${label} must be a canonical UTC timestamp`);
  }
  return value;
}

function comparePhysicalResourceProtocolStrings(left, right) {
  if (left === right) return 0;
  return left < right ? -1 : 1;
}

function normalizeSortedUnique(value, label, normalize, { minimum = 0, maximum = 64 } = {}) {
  assertDenseDataArray(value, label, minimum, maximum);
  const entries = value.map((entry, index) => normalize(entry, `${label}[${index}]`));
  const identities = entries.map((entry) => (
    typeof entry === "string" ? entry : hashCanonicalJson(entry)
  ));
  if (new Set(identities).size !== identities.length) {
    throw new Error(`${label} must not contain duplicates`);
  }
  return Object.freeze(entries
    .map((entry, index) => ({ entry, identity: identities[index] }))
    .sort((left, right) => comparePhysicalResourceProtocolStrings(left.identity, right.identity))
    .map(({ entry }) => entry));
}

function normalizeConstraint(input, label, resourceKind) {
  assertClosedObject(input, label, ["constraint_id", "bound"]);
  const constraintId = assertIdentifier(input.constraint_id, `${label}.constraint_id`);
  const allowed = RESOURCE_KIND_CONSTRAINTS[resourceKind];
  if (!allowed.includes(constraintId)) {
    throw new Error(`${label}.constraint_id is not valid for ${resourceKind}`);
  }
  // physical-quantities is shared with older contracts whose object checks
  // predate the closed data-field rule used by Plane-PH. Close the nested
  // quantity object here before handing it across that boundary so accessors
  // and symbol fields cannot be evaluated or silently omitted from the hash.
  assertClosedObject(input.bound, `${label}.bound`, ["quantity_id", "unit"], [
    "value",
    "min",
    "max",
    "uncertainty",
    "measurement_method_ref",
  ]);
  if (Object.prototype.hasOwnProperty.call(input.bound, "uncertainty")) {
    assertClosedObject(
      input.bound.uncertainty,
      `${label}.bound.uncertainty`,
      ["value", "unit"],
    );
  }
  const expectedQuantityId = RESOURCE_CONSTRAINT_QUANTITY[constraintId];
  return deepFreeze({
    constraint_id: constraintId,
    bound: normalizeQuantityBound(input.bound, `${label}.bound`, {
      expectedQuantityId,
      requireUsefulBound: true,
    }),
  });
}

function normalizeResourceRequirement(input, label = "resource_requirement") {
  assertClosedObject(input, label, [
    "alias",
    "resource_kind",
    "candidate_resource_refs",
    "ownership",
    "capacity_units",
    "capability_refs",
    "requested_effect_digests",
    "constraints",
  ], [
    "required_state_epoch_digest",
    "mode_ref",
    "workspace_ref",
    "custody_principal_ref",
    "independence_domain_ref",
    "containment_ref",
    "compatibility_ref",
  ]);
  const resourceKind = assertEnum(input.resource_kind, RESOURCE_KIND_VALUES, `${label}.resource_kind`);
  const prefix = RESOURCE_REF_PREFIX[resourceKind];
  const requirement = {
    alias: assertIdentifier(input.alias, `${label}.alias`),
    resource_kind: resourceKind,
    candidate_resource_refs: normalizeSortedUnique(
      input.candidate_resource_refs,
      `${label}.candidate_resource_refs`,
      (value, field) => normalizeOpaqueRef(value, field, { prefix }),
      { minimum: 1, maximum: 64 },
    ),
    ownership: assertEnum(input.ownership, RESOURCE_OWNERSHIP_VALUES, `${label}.ownership`),
    capacity_units: assertInteger(input.capacity_units, `${label}.capacity_units`, 1, 1_000_000),
    capability_refs: normalizeSortedUnique(
      input.capability_refs,
      `${label}.capability_refs`,
      (value, field) => normalizeOpaqueRef(value, field, { prefix: "capability" }),
    ),
    requested_effect_digests: normalizeSortedUnique(
      input.requested_effect_digests,
      `${label}.requested_effect_digests`,
      assertDigest,
    ),
    constraints: normalizeSortedUnique(
      input.constraints,
      `${label}.constraints`,
      (value, field) => normalizeConstraint(value, field, resourceKind),
      { maximum: 16 },
    ),
  };
  const constraintIds = requirement.constraints.map((entry) => entry.constraint_id);
  if (new Set(constraintIds).size !== constraintIds.length) {
    throw new Error(`${label}.constraints must not repeat a constraint_id`);
  }

  if (resourceKind !== "instrument"
      && (requirement.capability_refs.length > 0 || requirement.requested_effect_digests.length > 0)) {
    throw new Error(`${label} only instrument requirements may carry capabilities or requested effects`);
  }
  if (resourceKind === "instrument" && requirement.capability_refs.length === 0) {
    throw new Error(`${label}.instrument requires at least one capability_ref`);
  }
  if (requirement.ownership === "shared" && input.compatibility_ref == null) {
    throw new Error(`${label}.shared ownership requires an explicit compatibility_ref`);
  }
  if (resourceKind === "target_media" && input.custody_principal_ref == null) {
    throw new Error(`${label}.target_media requires custody_principal_ref`);
  }
  if (resourceKind === "target_media" && input.required_state_epoch_digest == null) {
    throw new Error(`${label}.target_media requires required_state_epoch_digest`);
  }
  if (resourceKind === "observer" && input.independence_domain_ref == null) {
    throw new Error(`${label}.observer requires independence_domain_ref`);
  }
  if (resourceKind === "operator_presence" && input.custody_principal_ref == null) {
    throw new Error(`${label}.operator_presence requires custody_principal_ref`);
  }
  if (resourceKind === "rf_zone" && input.containment_ref == null) {
    throw new Error(`${label}.rf_zone requires containment_ref`);
  }
  if (resourceKind === "workspace" && input.workspace_ref == null) {
    throw new Error(`${label}.workspace requires workspace_ref`);
  }

  if (input.required_state_epoch_digest != null) {
    requirement.required_state_epoch_digest = assertDigest(
      input.required_state_epoch_digest,
      `${label}.required_state_epoch_digest`,
    );
  }
  if (input.mode_ref != null) {
    if (!["instrument", "workspace"].includes(resourceKind)) {
      throw new Error(`${label}.mode_ref is invalid for ${resourceKind}`);
    }
    requirement.mode_ref = normalizeOpaqueRef(input.mode_ref, `${label}.mode_ref`, { prefix: "mode" });
  }
  if (input.workspace_ref != null) {
    if (!["instrument", "workspace"].includes(resourceKind)) {
      throw new Error(`${label}.workspace_ref is invalid for ${resourceKind}`);
    }
    requirement.workspace_ref = normalizeOpaqueRef(
      input.workspace_ref,
      `${label}.workspace_ref`,
      { prefix: "workspace" },
    );
  }
  if (input.custody_principal_ref != null) {
    if (!["target_media", "operator_presence"].includes(resourceKind)) {
      throw new Error(`${label}.custody_principal_ref is invalid for ${resourceKind}`);
    }
    requirement.custody_principal_ref = normalizeOpaqueRef(
      input.custody_principal_ref,
      `${label}.custody_principal_ref`,
      { prefix: "principal" },
    );
  }
  if (input.independence_domain_ref != null) {
    if (!["observer", "control"].includes(resourceKind)) {
      throw new Error(`${label}.independence_domain_ref is invalid for ${resourceKind}`);
    }
    requirement.independence_domain_ref = normalizeOpaqueRef(
      input.independence_domain_ref,
      `${label}.independence_domain_ref`,
      { prefix: "independence-domain" },
    );
  }
  if (input.containment_ref != null) {
    if (resourceKind !== "rf_zone") throw new Error(`${label}.containment_ref is invalid for ${resourceKind}`);
    requirement.containment_ref = normalizeOpaqueRef(
      input.containment_ref,
      `${label}.containment_ref`,
      { prefix: "containment" },
    );
  }
  if (input.compatibility_ref != null) {
    requirement.compatibility_ref = normalizeOpaqueRef(
      input.compatibility_ref,
      `${label}.compatibility_ref`,
      { prefix: "compatibility" },
    );
  }
  return deepFreeze(requirement);
}

function normalizePhysicalResourceBundle(input, label = "physical_resource_bundle") {
  assertClosedObject(input, label, [
    "version",
    "bundle_id",
    "requirements",
    "attempt_budget",
    "duration_ms",
    "reservation_ttl_ms",
    "cooldown_ms",
    "preemption_policy",
    "fairness_class",
    "batch_key",
    "setup_cost_units",
  ], [
    "spatial_envelope_ref",
    "spatial_envelope_digest",
    "stimulus_sequence_ref",
    "stimulus_sequence_digest",
    "resource_bundle_digest",
  ]);
  if (input.version !== PHYSICAL_RESOURCE_BUNDLE_VERSION) {
    throw new Error(`${label}.version must be ${PHYSICAL_RESOURCE_BUNDLE_VERSION}`);
  }
  const requirements = normalizeSortedUnique(
    input.requirements,
    `${label}.requirements`,
    normalizeResourceRequirement,
    { minimum: 1, maximum: 64 },
  );
  const aliases = requirements.map((entry) => entry.alias);
  if (new Set(aliases).size !== aliases.length) throw new Error(`${label}.requirements aliases must be unique`);
  const durationMs = assertInteger(input.duration_ms, `${label}.duration_ms`, 1, 86_400_000);
  const cooldownMs = assertInteger(input.cooldown_ms, `${label}.cooldown_ms`, 0, 86_400_000);
  const reservationTtlMs = assertInteger(
    input.reservation_ttl_ms,
    `${label}.reservation_ttl_ms`,
    1,
    86_400_000,
  );
  if (reservationTtlMs < durationMs + cooldownMs) {
    throw new Error(`${label}.reservation_ttl_ms must cover duration_ms plus cooldown_ms`);
  }
  const normalized = {
    version: PHYSICAL_RESOURCE_BUNDLE_VERSION,
    bundle_id: assertIdentifier(input.bundle_id, `${label}.bundle_id`),
    requirements,
    attempt_budget: assertInteger(input.attempt_budget, `${label}.attempt_budget`, 1, 1_000_000),
    duration_ms: durationMs,
    reservation_ttl_ms: reservationTtlMs,
    cooldown_ms: cooldownMs,
    preemption_policy: assertEnum(
      input.preemption_policy,
      RESOURCE_PREEMPTION_VALUES,
      `${label}.preemption_policy`,
    ),
    fairness_class: assertIdentifier(input.fairness_class, `${label}.fairness_class`),
    batch_key: assertToken(input.batch_key, `${label}.batch_key`),
    setup_cost_units: assertInteger(input.setup_cost_units, `${label}.setup_cost_units`, 0, 1_000_000),
  };
  const envelopePairs = [
    ["spatial_envelope_ref", "spatial_envelope_digest", "spatial-envelope"],
    ["stimulus_sequence_ref", "stimulus_sequence_digest", "stimulus-sequence"],
  ];
  for (const [refField, digestField, prefix] of envelopePairs) {
    const hasRef = Object.prototype.hasOwnProperty.call(input, refField);
    const hasDigest = Object.prototype.hasOwnProperty.call(input, digestField);
    if (hasRef !== hasDigest) throw new Error(`${label}.${refField} and ${digestField} must appear together`);
    if (hasRef) {
      normalized[refField] = normalizeOpaqueRef(input[refField], `${label}.${refField}`, { prefix });
      normalized[digestField] = assertDigest(input[digestField], `${label}.${digestField}`);
    }
  }
  const digest = hashCanonicalJson(normalized);
  if (input.resource_bundle_digest != null
      && assertDigest(input.resource_bundle_digest, `${label}.resource_bundle_digest`) !== digest) {
    throw new Error(`${label}.resource_bundle_digest does not match normalized content`);
  }
  return deepFreeze({ ...normalized, resource_bundle_digest: digest });
}

function normalizePhysicalResourceBundleBinding(input, label = "physical_resource_bundle_binding") {
  assertClosedObject(input, label, [
    "version",
    "resource_bundle_ref",
    "resource_bundle_digest",
  ]);
  if (input.version !== PHYSICAL_RESOURCE_BUNDLE_BINDING_VERSION) {
    throw new Error(`${label}.version must be ${PHYSICAL_RESOURCE_BUNDLE_BINDING_VERSION}`);
  }
  return deepFreeze({
    version: PHYSICAL_RESOURCE_BUNDLE_BINDING_VERSION,
    resource_bundle_ref: normalizeOpaqueRef(
      input.resource_bundle_ref,
      `${label}.resource_bundle_ref`,
      { prefix: "resource-bundle" },
    ),
    resource_bundle_digest: assertDigest(
      input.resource_bundle_digest,
      `${label}.resource_bundle_digest`,
    ),
  });
}

function bindPhysicalResourceBundle(bundleInput, resourceBundleRef) {
  const bundle = normalizePhysicalResourceBundle(bundleInput);
  return normalizePhysicalResourceBundleBinding({
    version: PHYSICAL_RESOURCE_BUNDLE_BINDING_VERSION,
    resource_bundle_ref: resourceBundleRef,
    resource_bundle_digest: bundle.resource_bundle_digest,
  });
}

function normalizePhysicalReservationRequest(input, label = "physical_reservation_request") {
  assertClosedObject(input, label, [
    "version",
    "reservation_request_id",
    "node_id",
    "contract_hash",
    "source_graph_hash",
    "session_nucleus_hash",
    "experiment_ref",
    "attempt_ref",
    "owner_principal_ref",
    "execution_principal_ref",
    "resource_bundle_digest",
    "requested_at",
    "effect_not_before",
    "effect_deadline",
  ], ["reservation_request_digest"]);
  if (input.version !== PHYSICAL_RESERVATION_REQUEST_VERSION) {
    throw new Error(`${label}.version must be ${PHYSICAL_RESERVATION_REQUEST_VERSION}`);
  }
  const requestedAt = assertTimestamp(input.requested_at, `${label}.requested_at`);
  const effectNotBefore = assertTimestamp(input.effect_not_before, `${label}.effect_not_before`);
  const effectDeadline = assertTimestamp(input.effect_deadline, `${label}.effect_deadline`);
  if (Date.parse(effectNotBefore) < Date.parse(requestedAt)) {
    throw new Error(`${label}.effect_not_before cannot predate requested_at`);
  }
  if (Date.parse(effectDeadline) <= Date.parse(effectNotBefore)) {
    throw new Error(`${label}.effect_deadline must be after effect_not_before`);
  }
  const normalized = {
    version: PHYSICAL_RESERVATION_REQUEST_VERSION,
    reservation_request_id: assertToken(input.reservation_request_id, `${label}.reservation_request_id`),
    node_id: assertTaskNodeId(input.node_id, `${label}.node_id`),
    contract_hash: assertDigest(input.contract_hash, `${label}.contract_hash`),
    source_graph_hash: assertDigest(input.source_graph_hash, `${label}.source_graph_hash`),
    session_nucleus_hash: assertDigest(input.session_nucleus_hash, `${label}.session_nucleus_hash`),
    experiment_ref: normalizeOpaqueRef(input.experiment_ref, `${label}.experiment_ref`, { prefix: "experiment" }),
    attempt_ref: normalizeOpaqueRef(input.attempt_ref, `${label}.attempt_ref`, { prefix: "attempt" }),
    owner_principal_ref: normalizeOpaqueRef(
      input.owner_principal_ref,
      `${label}.owner_principal_ref`,
      { prefix: "principal" },
    ),
    execution_principal_ref: normalizeOpaqueRef(
      input.execution_principal_ref,
      `${label}.execution_principal_ref`,
      { prefix: "principal" },
    ),
    resource_bundle_digest: assertDigest(input.resource_bundle_digest, `${label}.resource_bundle_digest`),
    requested_at: requestedAt,
    effect_not_before: effectNotBefore,
    effect_deadline: effectDeadline,
  };
  const digest = hashCanonicalJson(normalized);
  if (input.reservation_request_digest != null
      && assertDigest(input.reservation_request_digest, `${label}.reservation_request_digest`) !== digest) {
    throw new Error(`${label}.reservation_request_digest does not match normalized content`);
  }
  return deepFreeze({ ...normalized, reservation_request_digest: digest });
}

function normalizeResourceAllocation(input, label = "physical_resource_allocation") {
  assertClosedObject(input, label, [
    "alias",
    "resource_kind",
    "resource_ref",
    "ownership",
    "capacity_units",
    "state_epoch_digest",
    "fencing_generation",
    "fencing_token_hash",
  ]);
  const resourceKind = assertEnum(input.resource_kind, RESOURCE_KIND_VALUES, `${label}.resource_kind`);
  return deepFreeze({
    alias: assertIdentifier(input.alias, `${label}.alias`),
    resource_kind: resourceKind,
    resource_ref: normalizeOpaqueRef(
      input.resource_ref,
      `${label}.resource_ref`,
      { prefix: RESOURCE_REF_PREFIX[resourceKind] },
    ),
    ownership: assertEnum(input.ownership, RESOURCE_OWNERSHIP_VALUES, `${label}.ownership`),
    capacity_units: assertInteger(input.capacity_units, `${label}.capacity_units`, 1, 1_000_000),
    state_epoch_digest: assertDigest(input.state_epoch_digest, `${label}.state_epoch_digest`),
    fencing_generation: assertInteger(input.fencing_generation, `${label}.fencing_generation`, 1, Number.MAX_SAFE_INTEGER),
    fencing_token_hash: assertDigest(input.fencing_token_hash, `${label}.fencing_token_hash`),
  });
}

function normalizePhysicalReservationReceipt(input, label = "physical_reservation_receipt") {
  assertClosedObject(input, label, [
    "version",
    "reservation_ref",
    "broker_ref",
    "broker_epoch",
    "reservation_request_digest",
    "node_id",
    "contract_hash",
    "source_graph_hash",
    "session_nucleus_hash",
    "experiment_ref",
    "attempt_ref",
    "owner_principal_ref",
    "execution_principal_ref",
    "resource_bundle_digest",
    "inventory_digest",
    "state",
    "sequence",
    "issued_at",
    "updated_at",
    "expires_at",
    "allocations",
  ], [
    "closed_at",
    "terminal_disposition",
    "cleanup_handoff_ref",
    "receipt_digest",
  ]);
  if (input.version !== PHYSICAL_RESERVATION_RECEIPT_VERSION) {
    throw new Error(`${label}.version must be ${PHYSICAL_RESERVATION_RECEIPT_VERSION}`);
  }
  const state = assertEnum(input.state, RESERVATION_STATE_VALUES, `${label}.state`);
  const issuedAt = assertTimestamp(input.issued_at, `${label}.issued_at`);
  const updatedAt = assertTimestamp(input.updated_at, `${label}.updated_at`);
  const expiresAt = assertTimestamp(input.expires_at, `${label}.expires_at`);
  if (Date.parse(updatedAt) < Date.parse(issuedAt) || Date.parse(expiresAt) <= Date.parse(issuedAt)) {
    throw new Error(`${label} has invalid issuance/update/expiry order`);
  }
  const allocations = normalizeSortedUnique(
    input.allocations,
    `${label}.allocations`,
    normalizeResourceAllocation,
    { minimum: 1, maximum: 64 },
  );
  const aliases = allocations.map((allocation) => allocation.alias);
  if (new Set(aliases).size !== aliases.length) throw new Error(`${label}.allocations aliases must be unique`);
  const normalized = {
    version: PHYSICAL_RESERVATION_RECEIPT_VERSION,
    reservation_ref: normalizeOpaqueRef(input.reservation_ref, `${label}.reservation_ref`, { prefix: "reservation" }),
    broker_ref: normalizeOpaqueRef(input.broker_ref, `${label}.broker_ref`, { prefix: "broker" }),
    broker_epoch: assertInteger(input.broker_epoch, `${label}.broker_epoch`, 1, Number.MAX_SAFE_INTEGER),
    reservation_request_digest: assertDigest(
      input.reservation_request_digest,
      `${label}.reservation_request_digest`,
    ),
    node_id: assertTaskNodeId(input.node_id, `${label}.node_id`),
    contract_hash: assertDigest(input.contract_hash, `${label}.contract_hash`),
    source_graph_hash: assertDigest(input.source_graph_hash, `${label}.source_graph_hash`),
    session_nucleus_hash: assertDigest(input.session_nucleus_hash, `${label}.session_nucleus_hash`),
    experiment_ref: normalizeOpaqueRef(input.experiment_ref, `${label}.experiment_ref`, { prefix: "experiment" }),
    attempt_ref: normalizeOpaqueRef(input.attempt_ref, `${label}.attempt_ref`, { prefix: "attempt" }),
    owner_principal_ref: normalizeOpaqueRef(
      input.owner_principal_ref,
      `${label}.owner_principal_ref`,
      { prefix: "principal" },
    ),
    execution_principal_ref: normalizeOpaqueRef(
      input.execution_principal_ref,
      `${label}.execution_principal_ref`,
      { prefix: "principal" },
    ),
    resource_bundle_digest: assertDigest(input.resource_bundle_digest, `${label}.resource_bundle_digest`),
    inventory_digest: assertDigest(input.inventory_digest, `${label}.inventory_digest`),
    state,
    sequence: assertInteger(input.sequence, `${label}.sequence`, 0, Number.MAX_SAFE_INTEGER),
    issued_at: issuedAt,
    updated_at: updatedAt,
    expires_at: expiresAt,
    allocations,
  };
  const terminal = RESERVATION_TERMINAL_STATES.includes(state);
  if (terminal) {
    normalized.closed_at = assertTimestamp(input.closed_at, `${label}.closed_at`);
    if (normalized.closed_at !== updatedAt) throw new Error(`${label}.closed_at must equal updated_at`);
    normalized.terminal_disposition = assertEnum(
      input.terminal_disposition,
      RESERVATION_DISPOSITION_VALUES,
      `${label}.terminal_disposition`,
    );
  } else if (input.closed_at != null || input.terminal_disposition != null) {
    throw new Error(`${label}.${state} cannot carry terminal closure fields`);
  }
  if (state === "cleanup_pending") {
    normalized.cleanup_handoff_ref = normalizeOpaqueRef(
      input.cleanup_handoff_ref,
      `${label}.cleanup_handoff_ref`,
      { prefix: "cleanup-handoff" },
    );
  } else if (input.cleanup_handoff_ref != null) {
    throw new Error(`${label}.${state} cannot carry cleanup_handoff_ref`);
  }
  const digest = hashCanonicalJson(normalized);
  if (input.receipt_digest != null
      && assertDigest(input.receipt_digest, `${label}.receipt_digest`) !== digest) {
    throw new Error(`${label}.receipt_digest does not match normalized content`);
  }
  return deepFreeze({ ...normalized, receipt_digest: digest });
}

function assertReservationBindings(receiptInput, requestInput, bundleInput) {
  const receipt = normalizePhysicalReservationReceipt(receiptInput);
  const request = normalizePhysicalReservationRequest(requestInput);
  const bundle = normalizePhysicalResourceBundle(bundleInput);
  const bindings = [
    "node_id",
    "contract_hash",
    "source_graph_hash",
    "session_nucleus_hash",
    "experiment_ref",
    "attempt_ref",
    "owner_principal_ref",
    "execution_principal_ref",
    "resource_bundle_digest",
  ];
  if (receipt.reservation_request_digest !== request.reservation_request_digest) {
    throw new Error("physical reservation receipt request digest binding drift");
  }
  if (request.resource_bundle_digest !== bundle.resource_bundle_digest) {
    throw new Error("physical reservation request bundle digest binding drift");
  }
  const effectWindowMs = Date.parse(request.effect_deadline) - Date.parse(request.effect_not_before);
  if (effectWindowMs > bundle.duration_ms) {
    throw new Error("physical reservation request effect window exceeds the resource bundle duration");
  }
  if (Date.parse(receipt.issued_at) < Date.parse(request.requested_at)) {
    throw new Error("physical reservation receipt predates its request");
  }
  if (Date.parse(receipt.expires_at) < Date.parse(request.effect_deadline) + bundle.cooldown_ms) {
    throw new Error("physical reservation receipt does not cover the effect window and cooldown");
  }
  if (Date.parse(receipt.expires_at) > Date.parse(receipt.issued_at) + bundle.reservation_ttl_ms) {
    throw new Error("physical reservation receipt exceeds the resource bundle TTL");
  }
  for (const field of bindings) {
    if (receipt[field] !== request[field]) {
      throw new Error(`physical reservation receipt ${field} binding drift`);
    }
  }
  if (receipt.allocations.length !== bundle.requirements.length) {
    throw new Error("physical reservation receipt must allocate every requirement exactly once");
  }
  const requirements = new Map(bundle.requirements.map((entry) => [entry.alias, entry]));
  const allocationsByResource = new Map();
  const tokenResource = new Map();
  for (const allocation of receipt.allocations) {
    const requirement = requirements.get(allocation.alias);
    if (!requirement) throw new Error(`physical reservation allocation has unknown alias ${allocation.alias}`);
    if (allocation.resource_kind !== requirement.resource_kind
        || allocation.ownership !== requirement.ownership
        || allocation.capacity_units !== requirement.capacity_units
        || !requirement.candidate_resource_refs.includes(allocation.resource_ref)) {
      throw new Error(`physical reservation allocation ${allocation.alias} does not satisfy its exact requirement`);
    }
    if (requirement.required_state_epoch_digest != null
        && allocation.state_epoch_digest !== requirement.required_state_epoch_digest) {
      throw new Error(`physical reservation allocation ${allocation.alias} state epoch drift`);
    }
    if (!allocationsByResource.has(allocation.resource_ref)) {
      allocationsByResource.set(allocation.resource_ref, []);
    }
    allocationsByResource.get(allocation.resource_ref).push(allocation);
    const priorTokenResource = tokenResource.get(allocation.fencing_token_hash);
    if (priorTokenResource != null && priorTokenResource !== allocation.resource_ref) {
      throw new Error("physical reservation fencing token hash was reused across resources");
    }
    tokenResource.set(allocation.fencing_token_hash, allocation.resource_ref);
  }
  for (const [resourceRef, allocations] of allocationsByResource) {
    if (allocations.length <= 1) continue;
    if (allocations.some((allocation) => allocation.ownership === "exclusive")) {
      throw new Error(`physical reservation resource ${resourceRef} was allocated more than once with exclusive ownership`);
    }
    const compatibilityRefs = new Set(allocations.map((allocation) => (
      requirements.get(allocation.alias).compatibility_ref
    )));
    if (compatibilityRefs.size !== 1) {
      throw new Error(`physical reservation shared resource ${resourceRef} has incompatible requirements`);
    }
    for (const field of ["mode_ref", "workspace_ref"]) {
      const requiredValues = new Set(allocations
        .map((allocation) => requirements.get(allocation.alias)[field])
        .filter((value) => value != null));
      if (requiredValues.size > 1) {
        throw new Error(`physical reservation shared resource ${resourceRef} has conflicting ${field} requirements`);
      }
    }
    const first = allocations[0];
    for (const allocation of allocations.slice(1)) {
      if (allocation.fencing_generation !== first.fencing_generation
          || allocation.fencing_token_hash !== first.fencing_token_hash
          || allocation.state_epoch_digest !== first.state_epoch_digest) {
        throw new Error(`physical reservation shared resource ${resourceRef} has inconsistent fencing state`);
      }
    }
  }
  return receipt;
}

function projectPhysicalReservationState(receiptInput) {
  const receipt = normalizePhysicalReservationReceipt(receiptInput);
  return deepFreeze({
    version: PHYSICAL_RESERVATION_PROJECTION_VERSION,
    reservation_ref: receipt.reservation_ref,
    broker_ref: receipt.broker_ref,
    broker_epoch: receipt.broker_epoch,
    reservation_request_digest: receipt.reservation_request_digest,
    resource_bundle_digest: receipt.resource_bundle_digest,
    source_graph_hash: receipt.source_graph_hash,
    state: receipt.state,
    sequence: receipt.sequence,
    expires_at: receipt.expires_at,
    allocation_count: receipt.allocations.length,
    allocation_digest: hashCanonicalJson(receipt.allocations),
    receipt_digest: receipt.receipt_digest,
  });
}

module.exports = {
  PHYSICAL_RESOURCE_BUNDLE_BINDING_VERSION,
  PHYSICAL_RESERVATION_PROJECTION_VERSION,
  PHYSICAL_RESERVATION_RECEIPT_VERSION,
  PHYSICAL_RESERVATION_REQUEST_VERSION,
  PHYSICAL_RESOURCE_BUNDLE_VERSION,
  RESERVATION_DISPOSITION_VALUES,
  RESERVATION_STATE_VALUES,
  RESOURCE_CONSTRAINT_QUANTITY,
  RESOURCE_KIND_CONSTRAINTS,
  RESOURCE_KIND_VALUES,
  RESOURCE_OWNERSHIP_VALUES,
  RESOURCE_PREEMPTION_VALUES,
  RESOURCE_REF_PREFIX,
  assertReservationBindings,
  bindPhysicalResourceBundle,
  normalizePhysicalReservationReceipt,
  normalizePhysicalReservationRequest,
  normalizePhysicalResourceBundle,
  normalizePhysicalResourceBundleBinding,
  normalizeResourceAllocation,
  normalizeResourceRequirement,
  projectPhysicalReservationState,
};
