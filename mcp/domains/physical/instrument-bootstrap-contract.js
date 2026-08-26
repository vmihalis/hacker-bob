"use strict";

// Provider-neutral ABI-v3 durable bootstrap records. This module is pure: it
// neither persists events nor opens a transport. Provider ABI digests are
// intentionally identical to instrument-provider-contract.js; store-only
// hashes use distinct durable_* names and domains.

const {
  PROVIDER_BOOTSTRAP_ABI_VERSION,
  PROVIDER_BOOTSTRAP_CALL_VERSION,
  PROVIDER_BOOTSTRAP_INTENT_FIELDS,
  PROVIDER_BOOTSTRAP_OPERATION_IDS,
  PROVIDER_BOOTSTRAP_OUTCOME_VALUES,
  PROVIDER_BOOTSTRAP_REPORT_FIELDS,
} = require("./instrument-provider-contract.js");
const {
  normalizeOpaqueRef,
} = require("./physical-quantities.js");
const {
  hashCanonicalJson,
} = require("../../core/verification/verification-contracts.js");

const INSTRUMENT_BOOTSTRAP_PROVIDER_ABI_VERSION = PROVIDER_BOOTSTRAP_ABI_VERSION;
const INSTRUMENT_BOOTSTRAP_STORE_VERSION = 1;
const INSTRUMENT_BOOTSTRAP_REPORT_OUTCOMES = PROVIDER_BOOTSTRAP_OUTCOME_VALUES;
const HASH_PATTERN = /^[a-f0-9]{64}$/;
const IDENTIFIER_PATTERN = /^[a-z][a-z0-9._-]{0,127}$/;

const INSTRUMENT_BOOTSTRAP_STATE_VALUES = Object.freeze([
  "precommitted",
  "dispatch_committed",
  "redeemed",
  "succeeded",
  "refused_no_effect",
  "ambiguous",
]);
const INSTRUMENT_BOOTSTRAP_TERMINAL_STATES = Object.freeze([
  "succeeded",
  "refused_no_effect",
  "ambiguous",
]);
const INSTRUMENT_BOOTSTRAP_EVENT_KINDS = Object.freeze([
  "bootstrap_attempt_precommitted",
  "bootstrap_dispatch_committed",
  "bootstrap_dispatch_redeemed",
  "bootstrap_attempt_completed",
  "bootstrap_attempt_ambiguous",
]);
const INSTRUMENT_BOOTSTRAP_RECOVERY_DISPOSITIONS = Object.freeze([
  "safe_precommit_retry",
  "in_flight_fail_closed",
  "terminal_replay",
  "sticky_ambiguity",
]);

const INTENT_FIELDS = PROVIDER_BOOTSTRAP_INTENT_FIELDS;
const AUTHORITY_FIELDS = Object.freeze([
  "authority_resolution_digest",
  "signed_grant_digest",
  "replay_claim_digest",
  "replay_reservation_receipt_digest",
  "grant_not_before",
  "grant_expires_at",
]);
const PRECOMMIT_REQUIRED_FIELDS = Object.freeze([
  "provider_abi_version",
  ...INTENT_FIELDS,
  "bootstrap_intent_digest",
  "bootstrap_grant_projection_digest",
  "custody_binding_digest",
]);
const REQUEST_BINDING_REQUIRED_FIELDS = Object.freeze([
  ...INTENT_FIELDS,
  "bootstrap_intent_digest",
  "dispatch_record_digest",
]);
const REDEMPTION_EXPECTED_REQUIRED_FIELDS = Object.freeze([
  "version",
  ...PRECOMMIT_REQUIRED_FIELDS,
  "durable_attempt_binding_digest",
  "dispatch_record_digest",
  "bootstrap_request_digest",
]);
const PROVIDER_REDEMPTION_REQUEST_REQUIRED_FIELDS = Object.freeze([
  ...INTENT_FIELDS,
  "bootstrap_intent_digest",
  "dispatch_record_digest",
  "bootstrap_request_digest",
]);
const TERMINAL_BINDING_REQUIRED_FIELDS = Object.freeze([
  "version",
  "attempt_ref",
  "terminal_state",
  "durable_attempt_binding_digest",
  "custody_binding_digest",
  "dispatch_record_digest",
  "dispatch_redemption_digest",
  "provider_report_digest",
  "terminal_recorded_at",
]);

function deepFreeze(value) {
  if (!value || typeof value !== "object" || Object.isFrozen(value)) return value;
  for (const child of Object.values(value)) deepFreeze(child);
  return Object.freeze(value);
}

function isPlainObject(value) {
  if (value == null || typeof value !== "object" || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function closedDataValues(input, label, requiredFields, optionalFields = []) {
  if (!isPlainObject(input)) throw new Error(`${label} must be a plain data object`);
  const keys = Reflect.ownKeys(input);
  if (keys.some((field) => typeof field !== "string")) {
    throw new Error(`${label} cannot contain symbol fields`);
  }
  const allowed = new Set([...requiredFields, ...optionalFields]);
  const unknown = keys.filter((field) => !allowed.has(field)).sort();
  if (unknown.length > 0) throw new Error(`${label} has unknown fields: ${unknown.join(", ")}`);
  const missing = requiredFields.filter((field) => !keys.includes(field));
  if (missing.length > 0) throw new Error(`${label} is missing fields: ${missing.join(", ")}`);
  const descriptors = Object.getOwnPropertyDescriptors(input);
  const values = Object.create(null);
  for (const field of keys) {
    const descriptor = descriptors[field];
    if (!descriptor || descriptor.enumerable !== true
        || !Object.prototype.hasOwnProperty.call(descriptor, "value")) {
      throw new Error(`${label}.${field} must be an enumerable data field`);
    }
    values[field] = descriptor.value;
  }
  return values;
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

function assertInteger(value, label, min = 0) {
  if (!Number.isSafeInteger(value) || value < min) {
    throw new Error(`${label} must be a safe integer >= ${min}`);
  }
  return value;
}

function assertCanonicalTimestamp(value, label) {
  if (typeof value !== "string" || Number.isNaN(Date.parse(value))
      || new Date(value).toISOString() !== value) {
    throw new Error(`${label} must be a canonical UTC ISO-8601 timestamp`);
  }
  return value;
}

function normalizeProviderIntentBasis(input, label) {
  const values = closedDataValues(input, label, INTENT_FIELDS);
  if (values.version !== PROVIDER_BOOTSTRAP_CALL_VERSION) {
    throw new Error(`${label}.version must be ${PROVIDER_BOOTSTRAP_CALL_VERSION}`);
  }
  if (values.call_kind !== "bootstrap") throw new Error(`${label}.call_kind must be bootstrap`);
  if (!PROVIDER_BOOTSTRAP_OPERATION_IDS.includes(values.operation_id)) {
    throw new Error(
      `${label}.operation_id must be one of ${PROVIDER_BOOTSTRAP_OPERATION_IDS.join(", ")}`,
    );
  }
  const grantNotBefore = assertCanonicalTimestamp(
    values.grant_not_before,
    `${label}.grant_not_before`,
  );
  const grantExpiresAt = assertCanonicalTimestamp(
    values.grant_expires_at,
    `${label}.grant_expires_at`,
  );
  if (Date.parse(grantExpiresAt) <= Date.parse(grantNotBefore)) {
    throw new Error(`${label}.grant_expires_at must be after grant_not_before`);
  }
  return deepFreeze({
    version: PROVIDER_BOOTSTRAP_CALL_VERSION,
    call_kind: "bootstrap",
    attempt_ref: normalizeOpaqueRef(values.attempt_ref, `${label}.attempt_ref`, {
      prefix: "bootstrap-attempt",
    }),
    session_nucleus_hash: assertDigest(
      values.session_nucleus_hash,
      `${label}.session_nucleus_hash`,
    ),
    physical_scope_axis_digest: assertDigest(
      values.physical_scope_axis_digest,
      `${label}.physical_scope_axis_digest`,
    ),
    execution_principal_id: normalizeOpaqueRef(
      values.execution_principal_id,
      `${label}.execution_principal_id`,
      { prefix: "principal" },
    ),
    instrument_ref: normalizeOpaqueRef(values.instrument_ref, `${label}.instrument_ref`, {
      prefix: "instrument",
    }),
    enrollment_candidate_ref: normalizeOpaqueRef(
      values.enrollment_candidate_ref,
      `${label}.enrollment_candidate_ref`,
      { prefix: "enrollment-candidate" },
    ),
    provider_id: assertIdentifier(values.provider_id, `${label}.provider_id`),
    provider_descriptor_digest: assertDigest(
      values.provider_descriptor_digest,
      `${label}.provider_descriptor_digest`,
    ),
    provider_binary_digest: assertDigest(
      values.provider_binary_digest,
      `${label}.provider_binary_digest`,
    ),
    transport_digest: assertDigest(values.transport_digest, `${label}.transport_digest`),
    bootstrap_manifest_digest: assertDigest(
      values.bootstrap_manifest_digest,
      `${label}.bootstrap_manifest_digest`,
    ),
    bootstrap_invariants_digest: assertDigest(
      values.bootstrap_invariants_digest,
      `${label}.bootstrap_invariants_digest`,
    ),
    operation_id: values.operation_id,
    operation_digest: assertDigest(values.operation_digest, `${label}.operation_digest`),
    execution_request_digest: assertDigest(
      values.execution_request_digest,
      `${label}.execution_request_digest`,
    ),
    authority_resolution_digest: assertDigest(
      values.authority_resolution_digest,
      `${label}.authority_resolution_digest`,
    ),
    signed_grant_digest: assertDigest(
      values.signed_grant_digest,
      `${label}.signed_grant_digest`,
    ),
    replay_claim_digest: assertDigest(
      values.replay_claim_digest,
      `${label}.replay_claim_digest`,
    ),
    replay_reservation_receipt_digest: assertDigest(
      values.replay_reservation_receipt_digest,
      `${label}.replay_reservation_receipt_digest`,
    ),
    connection_ref: normalizeOpaqueRef(values.connection_ref, `${label}.connection_ref`, {
      prefix: "instrument-connection",
    }),
    connection_generation: assertInteger(
      values.connection_generation,
      `${label}.connection_generation`,
      1,
    ),
    grant_not_before: grantNotBefore,
    grant_expires_at: grantExpiresAt,
  });
}

function providerIntentInputFrom(values) {
  return Object.fromEntries(INTENT_FIELDS.map((field) => [field, values[field]]));
}

function instrumentBootstrapIntentDigest(input, label = "instrument_bootstrap_intent") {
  return hashCanonicalJson(normalizeProviderIntentBasis(input, label));
}

function durableAttemptBindingDigest(precommit) {
  const basis = { ...precommit };
  delete basis.durable_attempt_binding_digest;
  return hashCanonicalJson({
    domain: "hacker-bob/instrument-bootstrap-durable-attempt/v1",
    ...basis,
  });
}

function normalizeInstrumentBootstrapPrecommitRequest(
  input,
  label = "instrument_bootstrap_precommit_request",
) {
  const values = closedDataValues(input, label, PRECOMMIT_REQUIRED_FIELDS, [
    "durable_attempt_binding_digest",
  ]);
  if (values.provider_abi_version !== INSTRUMENT_BOOTSTRAP_PROVIDER_ABI_VERSION) {
    throw new Error(
      `${label}.provider_abi_version must be ${INSTRUMENT_BOOTSTRAP_PROVIDER_ABI_VERSION}`,
    );
  }
  const intent = normalizeProviderIntentBasis(providerIntentInputFrom(values), `${label}.intent`);
  const intentDigest = hashCanonicalJson(intent);
  if (assertDigest(values.bootstrap_intent_digest, `${label}.bootstrap_intent_digest`)
      !== intentDigest) {
    throw new Error(`${label}.bootstrap_intent_digest does not match the provider ABI-v3 intent`);
  }
  const precommit = {
    provider_abi_version: INSTRUMENT_BOOTSTRAP_PROVIDER_ABI_VERSION,
    ...intent,
    bootstrap_intent_digest: intentDigest,
    bootstrap_grant_projection_digest: assertDigest(
      values.bootstrap_grant_projection_digest,
      `${label}.bootstrap_grant_projection_digest`,
    ),
    custody_binding_digest: assertDigest(
      values.custody_binding_digest,
      `${label}.custody_binding_digest`,
    ),
  };
  const digest = durableAttemptBindingDigest(precommit);
  if (values.durable_attempt_binding_digest != null
      && assertDigest(
        values.durable_attempt_binding_digest,
        `${label}.durable_attempt_binding_digest`,
      ) !== digest) {
    throw new Error(`${label}.durable_attempt_binding_digest does not match the durable precommit`);
  }
  return deepFreeze({ ...precommit, durable_attempt_binding_digest: digest });
}

function instrumentBootstrapRequestDigest(input, label = "instrument_bootstrap_request") {
  const values = closedDataValues(input, label, REQUEST_BINDING_REQUIRED_FIELDS);
  const intent = normalizeProviderIntentBasis(providerIntentInputFrom(values), `${label}.intent`);
  const intentDigest = hashCanonicalJson(intent);
  if (assertDigest(values.bootstrap_intent_digest, `${label}.bootstrap_intent_digest`)
      !== intentDigest) {
    throw new Error(`${label}.bootstrap_intent_digest does not match the provider ABI-v3 intent`);
  }
  return hashCanonicalJson({
    ...intent,
    bootstrap_intent_digest: intentDigest,
    dispatch_record_digest: assertDigest(
      values.dispatch_record_digest,
      `${label}.dispatch_record_digest`,
    ),
  });
}

function normalizeInstrumentBootstrapCommitRequest(
  input,
  label = "instrument_bootstrap_commit_request",
) {
  const values = closedDataValues(input, label, [
    "version",
    "attempt_ref",
    "expected_durable_attempt_binding_digest",
  ]);
  if (values.version !== INSTRUMENT_BOOTSTRAP_STORE_VERSION) {
    throw new Error(`${label}.version must be ${INSTRUMENT_BOOTSTRAP_STORE_VERSION}`);
  }
  return deepFreeze({
    version: INSTRUMENT_BOOTSTRAP_STORE_VERSION,
    attempt_ref: normalizeOpaqueRef(values.attempt_ref, `${label}.attempt_ref`, {
      prefix: "bootstrap-attempt",
    }),
    expected_durable_attempt_binding_digest: assertDigest(
      values.expected_durable_attempt_binding_digest,
      `${label}.expected_durable_attempt_binding_digest`,
    ),
  });
}

function normalizeInstrumentBootstrapRedemptionExpected(
  input,
  label = "instrument_bootstrap_redemption_expected",
) {
  const values = closedDataValues(input, label, REDEMPTION_EXPECTED_REQUIRED_FIELDS);
  if (values.version !== INSTRUMENT_BOOTSTRAP_STORE_VERSION) {
    throw new Error(`${label}.version must be ${INSTRUMENT_BOOTSTRAP_STORE_VERSION}`);
  }
  const precommit = normalizeInstrumentBootstrapPrecommitRequest(
    Object.fromEntries(PRECOMMIT_REQUIRED_FIELDS.map((field) => [field, values[field]])),
    `${label}.precommit`,
  );
  if (assertDigest(
    values.durable_attempt_binding_digest,
    `${label}.durable_attempt_binding_digest`,
  ) !== precommit.durable_attempt_binding_digest) {
    throw new Error(`${label}.durable_attempt_binding_digest drifted`);
  }
  const dispatchRecordDigest = assertDigest(
    values.dispatch_record_digest,
    `${label}.dispatch_record_digest`,
  );
  const requestDigest = instrumentBootstrapRequestDigest({
    ...providerIntentInputFrom(precommit),
    bootstrap_intent_digest: precommit.bootstrap_intent_digest,
    dispatch_record_digest: dispatchRecordDigest,
  }, `${label}.request`);
  if (assertDigest(values.bootstrap_request_digest, `${label}.bootstrap_request_digest`)
      !== requestDigest) {
    throw new Error(`${label}.bootstrap_request_digest does not match the provider ABI-v3 request`);
  }
  return deepFreeze({
    version: INSTRUMENT_BOOTSTRAP_STORE_VERSION,
    ...precommit,
    dispatch_record_digest: dispatchRecordDigest,
    bootstrap_request_digest: requestDigest,
  });
}

// Provider-facing redemption carries only the serializable ABI-v3 request
// binding. Durable grant/attempt digests remain store-private and are joined
// from the credential's live attempt inside the durable store. An exact core
// provider request may retain its non-enumerable credential; the credential is
// deliberately omitted from this normalized projection.
function normalizeInstrumentBootstrapProviderRedemptionRequest(
  input,
  label = "instrument_bootstrap_provider_redemption_request",
) {
  if (!isPlainObject(input)) throw new Error(`${label} must be a plain data object`);
  const keys = Reflect.ownKeys(input);
  if (keys.some((field) => typeof field !== "string")) {
    throw new Error(`${label} cannot contain symbol fields`);
  }
  const allowed = new Set([
    ...PROVIDER_REDEMPTION_REQUEST_REQUIRED_FIELDS,
    "dispatch_credential",
  ]);
  const unknown = keys.filter((field) => !allowed.has(field)).sort();
  if (unknown.length > 0) throw new Error(`${label} has unknown fields: ${unknown.join(", ")}`);
  const missing = PROVIDER_REDEMPTION_REQUEST_REQUIRED_FIELDS.filter(
    (field) => !keys.includes(field),
  );
  if (missing.length > 0) throw new Error(`${label} is missing fields: ${missing.join(", ")}`);
  const descriptors = Object.getOwnPropertyDescriptors(input);
  const values = Object.create(null);
  for (const field of PROVIDER_REDEMPTION_REQUEST_REQUIRED_FIELDS) {
    const descriptor = descriptors[field];
    if (!descriptor || descriptor.enumerable !== true
        || !Object.prototype.hasOwnProperty.call(descriptor, "value")) {
      throw new Error(`${label}.${field} must be an enumerable data field`);
    }
    values[field] = descriptor.value;
  }
  if (descriptors.dispatch_credential) {
    const descriptor = descriptors.dispatch_credential;
    if (descriptor.enumerable !== false
        || !Object.prototype.hasOwnProperty.call(descriptor, "value")
        || !isPlainObject(descriptor.value)
        || !Object.isFrozen(descriptor.value)) {
      throw new Error(`${label}.dispatch_credential must be a non-enumerable frozen opaque object`);
    }
  }
  const intent = normalizeProviderIntentBasis(providerIntentInputFrom(values), `${label}.intent`);
  const intentDigest = hashCanonicalJson(intent);
  if (assertDigest(values.bootstrap_intent_digest, `${label}.bootstrap_intent_digest`)
      !== intentDigest) {
    throw new Error(`${label}.bootstrap_intent_digest does not match the provider ABI-v3 intent`);
  }
  const dispatchRecordDigest = assertDigest(
    values.dispatch_record_digest,
    `${label}.dispatch_record_digest`,
  );
  const requestDigest = instrumentBootstrapRequestDigest({
    ...intent,
    bootstrap_intent_digest: intentDigest,
    dispatch_record_digest: dispatchRecordDigest,
  }, `${label}.request`);
  if (assertDigest(values.bootstrap_request_digest, `${label}.bootstrap_request_digest`)
      !== requestDigest) {
    throw new Error(`${label}.bootstrap_request_digest does not match the provider ABI-v3 request`);
  }
  return deepFreeze({
    ...intent,
    bootstrap_intent_digest: intentDigest,
    dispatch_record_digest: dispatchRecordDigest,
    bootstrap_request_digest: requestDigest,
  });
}

function normalizeOptionalRef(value, label) {
  return value == null ? null : normalizeOpaqueRef(value, label);
}

function normalizeOptionalDigest(value, label) {
  return value == null ? null : assertDigest(value, label);
}

function normalizeInstrumentBootstrapProviderReport(
  input,
  requestInput,
  label = "instrument_bootstrap_provider_report",
) {
  const values = closedDataValues(input, label, PROVIDER_BOOTSTRAP_REPORT_FIELDS);
  const request = normalizeInstrumentBootstrapRedemptionExpected(
    requestInput,
    `${label}.request`,
  );
  if (values.version !== PROVIDER_BOOTSTRAP_CALL_VERSION) {
    throw new Error(`${label}.version must be ${PROVIDER_BOOTSTRAP_CALL_VERSION}`);
  }
  for (const field of [
    "attempt_ref",
    "operation_id",
    "bootstrap_intent_digest",
    "bootstrap_request_digest",
    "signed_grant_digest",
    "replay_reservation_receipt_digest",
    "dispatch_record_digest",
    "connection_generation",
  ]) {
    if (values[field] !== request[field]) {
      throw new Error(`${label}.${field} drifted from the durable bootstrap request`);
    }
  }
  if (!PROVIDER_BOOTSTRAP_OUTCOME_VALUES.includes(values.outcome)) {
    throw new Error(
      `${label}.outcome must be one of ${PROVIDER_BOOTSTRAP_OUTCOME_VALUES.join(", ")}`,
    );
  }
  const observedAt = assertCanonicalTimestamp(values.observed_at, `${label}.observed_at`);
  const evidenceFields = [
    "observation_ref",
    "observation_digest",
    "response_digest",
    "assurance_claims_digest",
    "invariant_witness_digest",
  ];
  if (values.outcome === "succeeded") {
    const missing = evidenceFields.filter((field) => values[field] == null);
    if (missing.length > 0) {
      throw new Error(`${label} succeeded without evidence fields: ${missing.join(", ")}`);
    }
    if (Date.parse(observedAt) < Date.parse(request.grant_not_before)
        || Date.parse(observedAt) >= Date.parse(request.grant_expires_at)) {
      throw new Error(`${label}.observed_at is outside the bootstrap grant window`);
    }
  } else {
    const fabricated = evidenceFields.filter((field) => values[field] !== null);
    if (fabricated.length > 0) {
      throw new Error(
        `${label} ${values.outcome} must not fabricate evidence fields: ${fabricated.join(", ")}`,
      );
    }
  }
  return deepFreeze({
    version: PROVIDER_BOOTSTRAP_CALL_VERSION,
    attempt_ref: request.attempt_ref,
    operation_id: request.operation_id,
    bootstrap_intent_digest: request.bootstrap_intent_digest,
    bootstrap_request_digest: request.bootstrap_request_digest,
    signed_grant_digest: request.signed_grant_digest,
    replay_reservation_receipt_digest: request.replay_reservation_receipt_digest,
    dispatch_record_digest: request.dispatch_record_digest,
    dispatch_redemption_digest: assertDigest(
      values.dispatch_redemption_digest,
      `${label}.dispatch_redemption_digest`,
    ),
    connection_generation: request.connection_generation,
    outcome: values.outcome,
    observation_ref: normalizeOptionalRef(values.observation_ref, `${label}.observation_ref`),
    observation_digest: normalizeOptionalDigest(
      values.observation_digest,
      `${label}.observation_digest`,
    ),
    receipt_ref: normalizeOpaqueRef(values.receipt_ref, `${label}.receipt_ref`),
    receipt_digest: assertDigest(values.receipt_digest, `${label}.receipt_digest`),
    response_digest: normalizeOptionalDigest(values.response_digest, `${label}.response_digest`),
    observed_at: observedAt,
    assurance_claims_digest: normalizeOptionalDigest(
      values.assurance_claims_digest,
      `${label}.assurance_claims_digest`,
    ),
    invariant_witness_digest: normalizeOptionalDigest(
      values.invariant_witness_digest,
      `${label}.invariant_witness_digest`,
    ),
  });
}

function instrumentBootstrapProviderReportDigest(reportInput, requestInput) {
  const report = normalizeInstrumentBootstrapProviderReport(reportInput, requestInput);
  return hashCanonicalJson({
    domain: "hacker-bob/instrument-bootstrap-durable-provider-report/v1",
    report,
  });
}

function normalizeInstrumentBootstrapTerminalBinding(
  input,
  reportInput,
  requestInput,
  label = "instrument_bootstrap_terminal_binding",
) {
  const values = closedDataValues(input, label, TERMINAL_BINDING_REQUIRED_FIELDS, [
    "durable_terminal_binding_digest",
  ]);
  if (values.version !== INSTRUMENT_BOOTSTRAP_STORE_VERSION) {
    throw new Error(`${label}.version must be ${INSTRUMENT_BOOTSTRAP_STORE_VERSION}`);
  }
  if (!INSTRUMENT_BOOTSTRAP_TERMINAL_STATES.includes(values.terminal_state)) {
    throw new Error(
      `${label}.terminal_state must be one of ${INSTRUMENT_BOOTSTRAP_TERMINAL_STATES.join(", ")}`,
    );
  }
  const request = normalizeInstrumentBootstrapRedemptionExpected(
    requestInput,
    `${label}.request`,
  );
  const report = normalizeInstrumentBootstrapProviderReport(
    reportInput,
    request,
    `${label}.report`,
  );
  if (values.attempt_ref !== request.attempt_ref || values.attempt_ref !== report.attempt_ref) {
    throw new Error(`${label}.attempt_ref drifted from the request/report`);
  }
  if (values.terminal_state !== report.outcome) {
    throw new Error(`${label}.terminal_state drifted from the provider report outcome`);
  }
  for (const [field, expected] of [
    ["durable_attempt_binding_digest", request.durable_attempt_binding_digest],
    ["custody_binding_digest", request.custody_binding_digest],
    ["dispatch_record_digest", report.dispatch_record_digest],
    ["dispatch_redemption_digest", report.dispatch_redemption_digest],
  ]) {
    if (assertDigest(values[field], `${label}.${field}`) !== expected) {
      throw new Error(`${label}.${field} drifted from durable report lineage`);
    }
  }
  const providerReportDigest = instrumentBootstrapProviderReportDigest(report, request);
  if (assertDigest(values.provider_report_digest, `${label}.provider_report_digest`)
      !== providerReportDigest) {
    throw new Error(`${label}.provider_report_digest does not match the provider report`);
  }
  const basis = {
    version: INSTRUMENT_BOOTSTRAP_STORE_VERSION,
    attempt_ref: request.attempt_ref,
    terminal_state: report.outcome,
    durable_attempt_binding_digest: request.durable_attempt_binding_digest,
    custody_binding_digest: request.custody_binding_digest,
    dispatch_record_digest: report.dispatch_record_digest,
    dispatch_redemption_digest: report.dispatch_redemption_digest,
    provider_report_digest: providerReportDigest,
    terminal_recorded_at: assertCanonicalTimestamp(
      values.terminal_recorded_at,
      `${label}.terminal_recorded_at`,
    ),
  };
  const durableTerminalBindingDigest = hashCanonicalJson({
    domain: "hacker-bob/instrument-bootstrap-durable-terminal/v1",
    ...basis,
  });
  if (values.durable_terminal_binding_digest != null
      && assertDigest(
        values.durable_terminal_binding_digest,
        `${label}.durable_terminal_binding_digest`,
      ) !== durableTerminalBindingDigest) {
    throw new Error(`${label}.durable_terminal_binding_digest does not match terminal lineage`);
  }
  return deepFreeze({
    ...basis,
    durable_terminal_binding_digest: durableTerminalBindingDigest,
  });
}

function normalizeInstrumentBootstrapMarkAmbiguousRequest(
  input,
  label = "instrument_bootstrap_mark_ambiguous_request",
) {
  const values = closedDataValues(input, label, [
    "version",
    "attempt_ref",
    "expected_attempt_digest",
    "reason_code",
  ]);
  if (values.version !== INSTRUMENT_BOOTSTRAP_STORE_VERSION) {
    throw new Error(`${label}.version must be ${INSTRUMENT_BOOTSTRAP_STORE_VERSION}`);
  }
  return deepFreeze({
    version: INSTRUMENT_BOOTSTRAP_STORE_VERSION,
    attempt_ref: normalizeOpaqueRef(values.attempt_ref, `${label}.attempt_ref`, {
      prefix: "bootstrap-attempt",
    }),
    expected_attempt_digest: assertDigest(
      values.expected_attempt_digest,
      `${label}.expected_attempt_digest`,
    ),
    reason_code: assertIdentifier(values.reason_code, `${label}.reason_code`),
  });
}

function normalizeInstrumentBootstrapDurableAmbiguity(
  input,
  label = "instrument_bootstrap_durable_ambiguity",
) {
  const values = closedDataValues(input, label, [
    "version",
    "attempt_ref",
    "durable_attempt_binding_digest",
    "custody_binding_digest",
    "dispatch_record_digest",
    "dispatch_redemption_digest",
    "reason_code",
    "ambiguity_receipt_ref",
    "ambiguity_receipt_digest",
    "terminal_recorded_at",
  ], ["terminal_state", "durable_terminal_binding_digest"]);
  if (values.version !== INSTRUMENT_BOOTSTRAP_STORE_VERSION) {
    throw new Error(`${label}.version must be ${INSTRUMENT_BOOTSTRAP_STORE_VERSION}`);
  }
  if (values.terminal_state != null && values.terminal_state !== "ambiguous") {
    throw new Error(`${label}.terminal_state must be ambiguous`);
  }
  const basis = {
    version: INSTRUMENT_BOOTSTRAP_STORE_VERSION,
    attempt_ref: normalizeOpaqueRef(values.attempt_ref, `${label}.attempt_ref`, {
      prefix: "bootstrap-attempt",
    }),
    terminal_state: "ambiguous",
    durable_attempt_binding_digest: assertDigest(
      values.durable_attempt_binding_digest,
      `${label}.durable_attempt_binding_digest`,
    ),
    custody_binding_digest: assertDigest(
      values.custody_binding_digest,
      `${label}.custody_binding_digest`,
    ),
    dispatch_record_digest: assertDigest(
      values.dispatch_record_digest,
      `${label}.dispatch_record_digest`,
    ),
    dispatch_redemption_digest: values.dispatch_redemption_digest == null
      ? null
      : assertDigest(
        values.dispatch_redemption_digest,
        `${label}.dispatch_redemption_digest`,
      ),
    reason_code: assertIdentifier(values.reason_code, `${label}.reason_code`),
    ambiguity_receipt_ref: normalizeOpaqueRef(
      values.ambiguity_receipt_ref,
      `${label}.ambiguity_receipt_ref`,
      { prefix: "bootstrap-ambiguity-receipt" },
    ),
    ambiguity_receipt_digest: assertDigest(
      values.ambiguity_receipt_digest,
      `${label}.ambiguity_receipt_digest`,
    ),
    terminal_recorded_at: assertCanonicalTimestamp(
      values.terminal_recorded_at,
      `${label}.terminal_recorded_at`,
    ),
  };
  const durableTerminalBindingDigest = hashCanonicalJson({
    domain: "hacker-bob/instrument-bootstrap-durable-ambiguity/v1",
    ...basis,
  });
  if (values.durable_terminal_binding_digest != null
      && assertDigest(
        values.durable_terminal_binding_digest,
        `${label}.durable_terminal_binding_digest`,
      ) !== durableTerminalBindingDigest) {
    throw new Error(`${label}.durable_terminal_binding_digest does not match ambiguity lineage`);
  }
  return deepFreeze({
    ...basis,
    durable_terminal_binding_digest: durableTerminalBindingDigest,
  });
}

function recoveryDispositionForState(state) {
  if (!INSTRUMENT_BOOTSTRAP_STATE_VALUES.includes(state)) {
    throw new Error(
      `instrument bootstrap state must be one of ${INSTRUMENT_BOOTSTRAP_STATE_VALUES.join(", ")}`,
    );
  }
  if (state === "precommitted") return "safe_precommit_retry";
  if (state === "dispatch_committed" || state === "redeemed") return "in_flight_fail_closed";
  if (state === "ambiguous") return "sticky_ambiguity";
  return "terminal_replay";
}

module.exports = {
  AUTHORITY_FIELDS,
  INSTRUMENT_BOOTSTRAP_EVENT_KINDS,
  INSTRUMENT_BOOTSTRAP_PROVIDER_ABI_VERSION,
  INSTRUMENT_BOOTSTRAP_RECOVERY_DISPOSITIONS,
  INSTRUMENT_BOOTSTRAP_REPORT_OUTCOMES,
  INSTRUMENT_BOOTSTRAP_STATE_VALUES,
  INSTRUMENT_BOOTSTRAP_STORE_VERSION,
  INSTRUMENT_BOOTSTRAP_TERMINAL_STATES,
  INTENT_FIELDS,
  durableAttemptBindingDigest,
  instrumentBootstrapIntentDigest,
  instrumentBootstrapProviderReportDigest,
  instrumentBootstrapRequestDigest,
  normalizeInstrumentBootstrapCommitRequest,
  normalizeInstrumentBootstrapDurableAmbiguity,
  normalizeInstrumentBootstrapMarkAmbiguousRequest,
  normalizeInstrumentBootstrapPrecommitRequest,
  normalizeInstrumentBootstrapProviderRedemptionRequest,
  normalizeInstrumentBootstrapProviderReport,
  normalizeInstrumentBootstrapRedemptionExpected,
  normalizeInstrumentBootstrapTerminalBinding,
  recoveryDispositionForState,
};
