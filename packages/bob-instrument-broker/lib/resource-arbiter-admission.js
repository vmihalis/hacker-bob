"use strict";

// Plane-PH PH-S11 broker-private resource-arbiter admission. Public workflow
// inputs provide only an exact reservation request. The bundle-derived
// fairness class, setup cost, and batch compatibility digest are resolved and
// minted behind a same-isolate branded port, then committed as one blocked
// ticket through the durable arbiter store. Eligibility remains a separate
// broker decision; admission never marks a ticket ready or dispatches work.

const {
  MAX_ARBITER_GENERATION,
  PHYSICAL_RESOURCE_ARBITER_COMMAND_VERSION,
  PHYSICAL_RESOURCE_QUEUE_TICKET_VERSION,
  normalizePhysicalResourceArbiterCommand,
  normalizePhysicalResourceArbiterConfig,
  normalizePhysicalResourceQueueTicket,
} = require("../../../mcp/domains/physical/physical-resource-arbiter.js");
const {
  normalizePhysicalReservationRequest,
  normalizePhysicalResourceBundle,
} = require("../../../mcp/lib/physical-resource-contract.js");
const {
  hashCanonicalJson,
} = require("../../../mcp/core/verification/verification-contracts.js");
const {
  assertPhysicalResourceArbiterStore,
  commitPhysicalResourceArbiterTransition,
  physicalResourceArbiterStoreReadiness,
  projectPhysicalResourceArbiterStore,
} = require("./resource-arbiter-store.js");
const {
  assertPhysicalResourceBundleResolverPort,
  resolvePhysicalResourceBundleForAdmission,
} = require("./resource-reservations.js");

const RESOURCE_ARBITER_ADMISSION_PORT_VERSION = 1;
const RESOURCE_ARBITER_ADMISSION_VERSION = 1;
const RESOURCE_ARBITER_ADMISSION_BINDING_VERSION = 1;
const RESOURCE_ARBITER_ADMISSION_COMMIT_BINDING_VERSION = 1;
const RESOURCE_ARBITER_BATCH_SEMANTICS_VERSION = 1;
const RESOURCE_ARBITER_ADMISSION_READINESS_VERSION = 1;
const RESOURCE_ARBITER_ADMISSION_CONTRACT =
  "bundle-derived-blocked-physical-resource-arbiter-admission-v1";
const RESOURCE_ARBITER_BATCH_DERIVATION_CONTRACT =
  "canonical-resource-bundle-setup-compatibility-sha256-v1";
const RESOURCE_ARBITER_ADMISSION_ISOLATION = "same_isolate_weak_brand_only";

const HASH_PATTERN = /^[a-f0-9]{64}$/;
const IDENTIFIER_PATTERN = /^[a-z][a-z0-9._-]{0,127}$/;

const ADMISSION_PORTS = new WeakSet();
const ADMISSION_PRIVATE = new WeakMap();
const ACTIVE_ADMISSIONS = new WeakSet();

function compareProtocolStrings(left, right) {
  if (left === right) return 0;
  return left < right ? -1 : 1;
}

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
  const unknown = keys
    .filter((key) => !allowed.has(key))
    .sort(compareProtocolStrings);
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

function deepFreeze(value) {
  if (!value || typeof value !== "object" || Object.isFrozen(value)) return value;
  for (const child of Object.values(value)) deepFreeze(child);
  return Object.freeze(value);
}

function assertIdentifier(value, label) {
  if (typeof value !== "string" || !IDENTIFIER_PATTERN.test(value)) {
    throw new Error(`${label} must be a lowercase identifier`);
  }
  return value;
}

function assertDigest(value, label) {
  if (typeof value !== "string" || !HASH_PATTERN.test(value)) {
    throw new Error(`${label} must be a lowercase SHA-256 digest`);
  }
  return value;
}

function assertInteger(value, label, minimum = 0, maximum = Number.MAX_SAFE_INTEGER) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw new Error(`${label} must be a safe integer from ${minimum} through ${maximum}`);
  }
  return value;
}

function admissionError(code, message, cause = null) {
  const error = new Error(message, cause == null ? undefined : { cause });
  Object.defineProperty(error, "code", { value: code, enumerable: true });
  return error;
}

function assertSyncResult(value, label) {
  if (value && (typeof value === "object" || typeof value === "function")) {
    let then;
    try {
      then = value.then;
    } catch (cause) {
      throw admissionError(
        "resource_arbiter_admission_async_forbidden",
        `${label} returned a hostile thenable`,
        cause,
      );
    }
    if (typeof then === "function") {
      throw admissionError("resource_arbiter_admission_async_forbidden", `${label} must be synchronous`);
    }
  }
  return value;
}

function canonicalBatchRequirement(requirement) {
  const value = {
    alias: requirement.alias,
    resource_kind: requirement.resource_kind,
    candidate_resource_refs: Object.freeze(
      requirement.candidate_resource_refs.slice().sort(compareProtocolStrings),
    ),
    ownership: requirement.ownership,
    capacity_units: requirement.capacity_units,
    capability_refs: Object.freeze(requirement.capability_refs.slice().sort(compareProtocolStrings)),
    requested_effect_digests: Object.freeze(
      requirement.requested_effect_digests.slice().sort(compareProtocolStrings),
    ),
    constraints: Object.freeze(requirement.constraints
      .map((constraint) => ({ constraint, digest: hashCanonicalJson(constraint) }))
      .sort((left, right) => compareProtocolStrings(left.digest, right.digest))
      .map((entry) => entry.constraint)),
  };
  for (const field of [
    "required_state_epoch_digest",
    "mode_ref",
    "workspace_ref",
    "custody_principal_ref",
    "independence_domain_ref",
    "containment_ref",
    "compatibility_ref",
  ]) {
    if (Object.prototype.hasOwnProperty.call(requirement, field)) value[field] = requirement[field];
  }
  return deepFreeze(value);
}

function sortedBatchRequirements(bundle) {
  return Object.freeze(bundle.requirements
    .map((requirement) => {
      const canonical = canonicalBatchRequirement(requirement);
      return {
        requirement: canonical,
        requirement_digest: hashCanonicalJson(canonical),
      };
    })
    .sort((left, right) => compareProtocolStrings(
      left.requirement_digest,
      right.requirement_digest,
    ))
    .map((entry) => entry.requirement));
}

function projectPhysicalResourceArbiterBatchSemantics(
  input,
  label = "physical_resource_arbiter_batch_semantics_bundle",
) {
  const bundle = normalizePhysicalResourceBundle(input, label);
  // Full normalized requirements deliberately participate: candidate resource
  // sets, ownership/capacity, constraints, state epochs, capabilities/effects,
  // custody/independence/containment, and especially mode_ref, workspace_ref,
  // and compatibility_ref all affect whether retaining setup is sound. Fields
  // concerned only with queue fairness, TTL, attempts, or preemption do not.
  const value = {
    version: RESOURCE_ARBITER_BATCH_SEMANTICS_VERSION,
    derivation_contract: RESOURCE_ARBITER_BATCH_DERIVATION_CONTRACT,
    bundle_batch_key: bundle.batch_key,
    setup_cost_units: bundle.setup_cost_units,
    requirements: sortedBatchRequirements(bundle),
    spatial_envelope: bundle.spatial_envelope_ref == null
      ? null
      : deepFreeze({
        ref: bundle.spatial_envelope_ref,
        digest: bundle.spatial_envelope_digest,
      }),
    stimulus_sequence: bundle.stimulus_sequence_ref == null
      ? null
      : deepFreeze({
        ref: bundle.stimulus_sequence_ref,
        digest: bundle.stimulus_sequence_digest,
      }),
  };
  return deepFreeze({ ...value, batch_semantics_digest: hashCanonicalJson(value) });
}

function derivePhysicalResourceArbiterBatchKey(bundle) {
  return projectPhysicalResourceArbiterBatchSemantics(bundle).batch_semantics_digest;
}

function createPhysicalResourceArbiterAdmissionPort(input = {}) {
  assertClosedObject(input, "physical_resource_arbiter_admission_port", [
    "port_id",
    "bundle_resolver_port",
    "arbiter_store",
    "arbiter_config",
    "source_graph_hash",
    "session_nucleus_hash",
  ]);
  const bundleResolverPort = assertPhysicalResourceBundleResolverPort(input.bundle_resolver_port);
  const arbiterStore = assertPhysicalResourceArbiterStore(input.arbiter_store);
  const arbiterConfig = normalizePhysicalResourceArbiterConfig(
    input.arbiter_config,
    "physical_resource_arbiter_admission_port.arbiter_config",
  );
  if (arbiterConfig.config_digest !== arbiterStore.config_digest) {
    throw admissionError(
      "resource_arbiter_admission_config_drift",
      "physical resource arbiter admission config does not match the branded store",
    );
  }
  const port = deepFreeze({
    version: RESOURCE_ARBITER_ADMISSION_PORT_VERSION,
    port_id: assertIdentifier(input.port_id, "physical_resource_arbiter_admission_port.port_id"),
    contract: RESOURCE_ARBITER_ADMISSION_CONTRACT,
    batch_derivation_contract: RESOURCE_ARBITER_BATCH_DERIVATION_CONTRACT,
    bundle_resolver_port_id: bundleResolverPort.port_id,
    journal_domain_digest: arbiterStore.journal_domain_digest,
    arbiter_config_digest: arbiterConfig.config_digest,
    source_graph_hash: assertDigest(
      input.source_graph_hash,
      "physical_resource_arbiter_admission_port.source_graph_hash",
    ),
    session_nucleus_hash: assertDigest(
      input.session_nucleus_hash,
      "physical_resource_arbiter_admission_port.session_nucleus_hash",
    ),
    ticket_state_on_admission: "blocked",
    isolation_assurance: RESOURCE_ARBITER_ADMISSION_ISOLATION,
    resolver_assurance: bundleResolverPort.resolver_assurance,
    durability_assurance: arbiterStore.durability_assurance,
    production_attested: false,
  });
  ADMISSION_PORTS.add(port);
  ADMISSION_PRIVATE.set(port, Object.freeze({
    bundle_resolver_port: bundleResolverPort,
    arbiter_store: arbiterStore,
    arbiter_config: arbiterConfig,
  }));
  return port;
}

function assertPhysicalResourceArbiterAdmissionPort(port) {
  if (!port || !Object.isFrozen(port) || !ADMISSION_PORTS.has(port)
      || !ADMISSION_PRIVATE.has(port)) {
    throw new Error("physical resource arbiter admission port must be created by Bob's private factory");
  }
  return port;
}

function normalizeAdmissionCommitBinding(
  input,
  label = "physical_resource_arbiter_admission_commit_binding",
) {
  assertClosedObject(input, label, [
    "version",
    "generation",
    "head_digest",
    "prior_head_digest",
    "state_digest",
    "queue_digest",
    "transition_digest",
  ]);
  if (input.version !== RESOURCE_ARBITER_ADMISSION_COMMIT_BINDING_VERSION) {
    throw new Error(`${label}.version must be ${RESOURCE_ARBITER_ADMISSION_COMMIT_BINDING_VERSION}`);
  }
  return deepFreeze({
    version: RESOURCE_ARBITER_ADMISSION_COMMIT_BINDING_VERSION,
    generation: assertInteger(input.generation, `${label}.generation`, 1, MAX_ARBITER_GENERATION),
    head_digest: assertDigest(input.head_digest, `${label}.head_digest`),
    prior_head_digest: assertDigest(input.prior_head_digest, `${label}.prior_head_digest`),
    state_digest: assertDigest(input.state_digest, `${label}.state_digest`),
    queue_digest: assertDigest(input.queue_digest, `${label}.queue_digest`),
    transition_digest: assertDigest(input.transition_digest, `${label}.transition_digest`),
  });
}

function projectAdmissionCommitBinding(commitReceipt) {
  return normalizeAdmissionCommitBinding({
    version: RESOURCE_ARBITER_ADMISSION_COMMIT_BINDING_VERSION,
    generation: commitReceipt.generation,
    head_digest: commitReceipt.head_digest,
    prior_head_digest: commitReceipt.prior_head_digest,
    state_digest: commitReceipt.state_digest,
    queue_digest: commitReceipt.queue_digest,
    transition_digest: commitReceipt.transition_digest,
  });
}

function makeAdmissionBinding(
  port,
  request,
  ticket,
  batchSemantics,
  commandDigest,
  commitBinding,
) {
  const privateState = ADMISSION_PRIVATE.get(port);
  const value = {
    version: RESOURCE_ARBITER_ADMISSION_BINDING_VERSION,
    admission_port_id: port.port_id,
    journal_domain_digest: port.journal_domain_digest,
    arbiter_config_digest: privateState.arbiter_config.config_digest,
    reservation_request_id: request.reservation_request_id,
    reservation_request_digest: request.reservation_request_digest,
    node_id: request.node_id,
    contract_hash: request.contract_hash,
    source_graph_hash: request.source_graph_hash,
    session_nucleus_hash: request.session_nucleus_hash,
    resource_bundle_digest: request.resource_bundle_digest,
    batch_semantics_digest: batchSemantics.batch_semantics_digest,
    ticket_digest: ticket.ticket_digest,
    enqueue_command_digest: commandDigest,
    commit_generation: commitBinding.generation,
    commit_head_digest: commitBinding.head_digest,
    commit_prior_head_digest: commitBinding.prior_head_digest,
    commit_state_digest: commitBinding.state_digest,
    commit_queue_digest: commitBinding.queue_digest,
    commit_transition_digest: commitBinding.transition_digest,
  };
  return deepFreeze({ ...value, binding_digest: hashCanonicalJson(value) });
}

function admitPhysicalResourceArbiterRequest(port, input = {}) {
  assertPhysicalResourceArbiterAdmissionPort(port);
  assertClosedObject(input, "physical_resource_arbiter_admission", ["reservation_request"]);
  if (ACTIVE_ADMISSIONS.has(port)) {
    throw admissionError(
      "resource_arbiter_admission_reentrant",
      "physical resource arbiter admission cannot re-enter its broker-private port",
    );
  }
  ACTIVE_ADMISSIONS.add(port);
  try {
    const privateState = ADMISSION_PRIVATE.get(port);
    const request = normalizePhysicalReservationRequest(
      input.reservation_request,
      "physical_resource_arbiter_admission.reservation_request",
    );
    if (request.source_graph_hash !== port.source_graph_hash
        || request.session_nucleus_hash !== port.session_nucleus_hash) {
      throw admissionError(
        "resource_arbiter_admission_session_drift",
        "physical resource reservation request is outside the admission port graph/session domain",
      );
    }
    const bundle = assertSyncResult(
      resolvePhysicalResourceBundleForAdmission(privateState.bundle_resolver_port, {
        reservation_request: request,
      }),
      "physical resource bundle admission resolution",
    );
    if (bundle.resource_bundle_digest !== request.resource_bundle_digest) {
      throw admissionError(
        "resource_arbiter_admission_bundle_drift",
        "resolved physical resource bundle does not match the reservation request",
      );
    }
    if (!privateState.arbiter_config.fairness_classes.includes(bundle.fairness_class)) {
      throw admissionError(
        "resource_arbiter_admission_fairness_forbidden",
        `resolved physical resource fairness class ${bundle.fairness_class} is not configured`,
      );
    }

    const projection = projectPhysicalResourceArbiterStore(privateState.arbiter_store);
    if (projection.config_digest !== privateState.arbiter_config.config_digest
        || projection.journal_domain_digest !== port.journal_domain_digest) {
      throw admissionError(
        "resource_arbiter_admission_store_drift",
        "physical resource arbiter store binding drifted before admission",
      );
    }
    if (projection.generation >= MAX_ARBITER_GENERATION) {
      throw admissionError(
        "resource_arbiter_admission_generation_exhausted",
        "physical resource arbiter generation is exhausted",
      );
    }
    const batchSemantics = projectPhysicalResourceArbiterBatchSemantics(bundle);
    const ticket = normalizePhysicalResourceQueueTicket({
      version: PHYSICAL_RESOURCE_QUEUE_TICKET_VERSION,
      reservation_request_digest: request.reservation_request_digest,
      resource_bundle_digest: bundle.resource_bundle_digest,
      fairness_class: bundle.fairness_class,
      batch_key: batchSemantics.batch_semantics_digest,
      setup_cost_units: bundle.setup_cost_units,
      enqueue_generation: projection.generation + 1,
      deferral_count: 0,
      ticket_state: "blocked",
    }, "physical_resource_arbiter_admission.ticket");
    if (ticket.fairness_class !== bundle.fairness_class
        || ticket.setup_cost_units !== bundle.setup_cost_units
        || ticket.resource_bundle_digest !== bundle.resource_bundle_digest) {
      throw admissionError(
        "resource_arbiter_admission_metadata_drift",
        "normalized physical resource arbiter ticket drifted from its resolved bundle",
      );
    }
    const command = normalizePhysicalResourceArbiterCommand({
      version: PHYSICAL_RESOURCE_ARBITER_COMMAND_VERSION,
      command_kind: "enqueue",
      ticket,
    }, "physical_resource_arbiter_admission.command");
    const commitReceipt = assertSyncResult(commitPhysicalResourceArbiterTransition(
      privateState.arbiter_store,
      {
        expected_generation: projection.generation,
        expected_head_digest: projection.head_digest,
        expected_state_digest: projection.state_digest,
        expected_queue_digest: projection.queue_digest,
        commands: [command],
      },
    ), "physical resource arbiter admission commit");
    if (commitReceipt.generation !== projection.generation + 1
        || commitReceipt.prior_head_digest !== projection.head_digest) {
      throw admissionError(
        "resource_arbiter_admission_commit_drift",
        "physical resource arbiter admission commit does not bind its exact predecessor",
      );
    }
    const arbiterCommit = projectAdmissionCommitBinding(commitReceipt);
    const binding = makeAdmissionBinding(
      port,
      request,
      ticket,
      batchSemantics,
      command.command_digest,
      arbiterCommit,
    );
    const value = {
      version: RESOURCE_ARBITER_ADMISSION_VERSION,
      production_attested: false,
      isolation_assurance: RESOURCE_ARBITER_ADMISSION_ISOLATION,
      binding,
      ticket,
      arbiter_commit: arbiterCommit,
      command_digest: command.command_digest,
      commit_receipt: commitReceipt,
    };
    return deepFreeze({ ...value, admission_digest: hashCanonicalJson(value) });
  } finally {
    ACTIVE_ADMISSIONS.delete(port);
  }
}

// Exact, non-authorizing join verifier for a caller-owned durable request
// registry. The binding carries the arbiter head coordinates produced by the
// enqueue commit, while the request and full bundle re-derive every ticket
// field. This verifies canonical consistency; because the binding is not
// signed here, the registry must authenticate and retain it alongside the
// corresponding durable arbiter journal entry.
function verifyPhysicalResourceArbiterAdmissionBinding(port, input = {}) {
  assertPhysicalResourceArbiterAdmissionPort(port);
  assertClosedObject(input, "physical_resource_arbiter_admission_verification", [
    "binding",
    "reservation_request",
    "resource_bundle",
    "ticket",
    "arbiter_commit",
  ]);
  const request = normalizePhysicalReservationRequest(
    input.reservation_request,
    "physical_resource_arbiter_admission_verification.reservation_request",
  );
  const bundle = normalizePhysicalResourceBundle(
    input.resource_bundle,
    "physical_resource_arbiter_admission_verification.resource_bundle",
  );
  const ticket = normalizePhysicalResourceQueueTicket(
    input.ticket,
    "physical_resource_arbiter_admission_verification.ticket",
  );
  const commitBinding = normalizeAdmissionCommitBinding(
    input.arbiter_commit,
    "physical_resource_arbiter_admission_verification.arbiter_commit",
  );
  assertClosedObject(input.binding, "physical_resource_arbiter_admission_verification.binding", [
    "version",
    "admission_port_id",
    "journal_domain_digest",
    "arbiter_config_digest",
    "reservation_request_id",
    "reservation_request_digest",
    "node_id",
    "contract_hash",
    "source_graph_hash",
    "session_nucleus_hash",
    "resource_bundle_digest",
    "batch_semantics_digest",
    "ticket_digest",
    "enqueue_command_digest",
    "commit_generation",
    "commit_head_digest",
    "commit_prior_head_digest",
    "commit_state_digest",
    "commit_queue_digest",
    "commit_transition_digest",
    "binding_digest",
  ]);
  assertDigest(
    input.binding.binding_digest,
    "physical_resource_arbiter_admission_verification.binding.binding_digest",
  );
  if (request.source_graph_hash !== port.source_graph_hash
      || request.session_nucleus_hash !== port.session_nucleus_hash) {
    throw admissionError(
      "resource_arbiter_admission_session_drift",
      "physical resource admission binding is outside the port graph/session domain",
    );
  }
  const privateState = ADMISSION_PRIVATE.get(port);
  const batchSemantics = projectPhysicalResourceArbiterBatchSemantics(bundle);
  const command = normalizePhysicalResourceArbiterCommand({
    version: PHYSICAL_RESOURCE_ARBITER_COMMAND_VERSION,
    command_kind: "enqueue",
    ticket,
  }, "physical_resource_arbiter_admission_verification.command");
  const metadataMatches = request.resource_bundle_digest === bundle.resource_bundle_digest
    && ticket.reservation_request_digest === request.reservation_request_digest
    && ticket.resource_bundle_digest === bundle.resource_bundle_digest
    && ticket.fairness_class === bundle.fairness_class
    && ticket.setup_cost_units === bundle.setup_cost_units
    && ticket.batch_key === batchSemantics.batch_semantics_digest
    && ticket.ticket_state === "blocked"
    && ticket.deferral_count === 0
    && ticket.enqueue_generation === commitBinding.generation
    && privateState.arbiter_config.fairness_classes.includes(bundle.fairness_class);
  if (!metadataMatches) {
    throw admissionError(
      "resource_arbiter_admission_binding_invalid",
      "physical resource admission ticket/request/bundle/commit metadata does not join exactly",
    );
  }
  const expected = makeAdmissionBinding(
    port,
    request,
    ticket,
    batchSemantics,
    command.command_digest,
    commitBinding,
  );
  if (hashCanonicalJson(input.binding) !== hashCanonicalJson(expected)) {
    throw admissionError(
      "resource_arbiter_admission_binding_invalid",
      "physical resource admission binding does not match its exact canonical join",
    );
  }
  return expected;
}

function physicalResourceArbiterAdmissionReadiness(port) {
  assertPhysicalResourceArbiterAdmissionPort(port);
  const privateState = ADMISSION_PRIVATE.get(port);
  const projection = projectPhysicalResourceArbiterStore(privateState.arbiter_store);
  const storeReadiness = physicalResourceArbiterStoreReadiness(privateState.arbiter_store);
  return deepFreeze({
    version: RESOURCE_ARBITER_ADMISSION_READINESS_VERSION,
    production_ready: false,
    production_attested: false,
    admission_contract: RESOURCE_ARBITER_ADMISSION_CONTRACT,
    isolation_assurance: RESOURCE_ARBITER_ADMISSION_ISOLATION,
    resolver_assurance: port.resolver_assurance,
    durability_assurance: port.durability_assurance,
    mutation_state: storeReadiness.mutation_state,
    capacity_state: projection.capacity.capacity_state,
    generation: projection.generation,
    head_digest: projection.head_digest,
    blockers: Object.freeze([
      "bundle_resolver_callback_is_caller_asserted_and_unattested",
      "arbiter_state_callback_durability_is_unattested",
      "admission_brand_is_not_a_process_or_os_security_boundary",
      "admission_binding_is_not_authenticated_or_retained_by_a_durable_request_registry",
    ]),
  });
}

module.exports = {
  RESOURCE_ARBITER_ADMISSION_BINDING_VERSION,
  RESOURCE_ARBITER_ADMISSION_COMMIT_BINDING_VERSION,
  RESOURCE_ARBITER_ADMISSION_CONTRACT,
  RESOURCE_ARBITER_ADMISSION_ISOLATION,
  RESOURCE_ARBITER_ADMISSION_PORT_VERSION,
  RESOURCE_ARBITER_ADMISSION_READINESS_VERSION,
  RESOURCE_ARBITER_ADMISSION_VERSION,
  RESOURCE_ARBITER_BATCH_DERIVATION_CONTRACT,
  RESOURCE_ARBITER_BATCH_SEMANTICS_VERSION,
  admitPhysicalResourceArbiterRequest,
  assertPhysicalResourceArbiterAdmissionPort,
  createPhysicalResourceArbiterAdmissionPort,
  derivePhysicalResourceArbiterBatchKey,
  physicalResourceArbiterAdmissionReadiness,
  projectPhysicalResourceArbiterBatchSemantics,
  verifyPhysicalResourceArbiterAdmissionBinding,
};
