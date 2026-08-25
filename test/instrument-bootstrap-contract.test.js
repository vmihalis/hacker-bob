"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");

const {
  defineProviderDescriptor,
  normalizeProviderBootstrapIntent,
  normalizeProviderBootstrapReport,
  normalizeProviderBootstrapRequest,
} = require("../mcp/domains/physical/instrument-provider-contract.js");
const {
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
} = require("../mcp/domains/physical/instrument-bootstrap-contract.js");
const {
  createDeterministicProviderFixture,
} = require("../packages/bob-instrument-deterministic/lib/fixtures.js");
const {
  hashCanonicalJson,
} = require("../mcp/core/verification/verification-contracts.js");

function digest(label) {
  return hashCanonicalJson({ label });
}

function fixture() {
  const base = createDeterministicProviderFixture();
  const descriptorInput = structuredClone(base.descriptor);
  delete descriptorInput.capabilities_digest;
  delete descriptorInput.descriptor_digest;
  descriptorInput.abi_version = 3;
  const descriptor = defineProviderDescriptor(
    descriptorInput,
    base.operationRegistry,
    base.effectRegistry,
  );
  const capability = descriptor.capabilities.find(
    (entry) => entry.operation_id === "instrument.inventory",
  );
  const intentInput = {
    version: 1,
    call_kind: "bootstrap",
    attempt_ref: "bootstrap-attempt:durable-contract-0001",
    session_nucleus_hash: digest("session-nucleus"),
    physical_scope_axis_digest: digest("physical-axis"),
    execution_principal_id: "principal:bootstrap-worker",
    instrument_ref: "instrument:mock-owned-fixture-0001",
    enrollment_candidate_ref: "enrollment-candidate:mock-owned-fixture-0001",
    provider_id: descriptor.provider_id,
    provider_descriptor_digest: descriptor.descriptor_digest,
    provider_binary_digest: digest("provider-binary"),
    transport_digest: digest("transport"),
    bootstrap_manifest_digest: digest("manifest"),
    bootstrap_invariants_digest: digest("invariants"),
    operation_id: capability.operation_id,
    operation_digest: capability.operation_digest,
    execution_request_digest: digest("execution-request"),
    authority_resolution_digest: digest("authority-resolution"),
    signed_grant_digest: digest("signed-grant"),
    replay_claim_digest: digest("replay-claim"),
    replay_reservation_receipt_digest: digest("replay-receipt"),
    connection_ref: "instrument-connection:mock-owned-fixture-0001",
    connection_generation: 7,
    grant_not_before: "2026-07-18T00:00:00.000Z",
    grant_expires_at: "2026-07-18T00:30:00.000Z",
  };
  const coreIntent = normalizeProviderBootstrapIntent(intentInput, descriptor);
  const precommitInput = {
    provider_abi_version: 3,
    ...intentInput,
    bootstrap_intent_digest: coreIntent.bootstrap_intent_digest,
    bootstrap_grant_projection_digest: digest("grant-projection"),
    custody_binding_digest: digest("custody-binding"),
  };
  const precommit = normalizeInstrumentBootstrapPrecommitRequest(precommitInput);
  const dispatchRecordDigest = digest("dispatch-record");
  const credential = Object.freeze({ private_fixture: true });
  const coreRequest = normalizeProviderBootstrapRequest({
    ...coreIntent,
    dispatch_record_digest: dispatchRecordDigest,
    dispatch_credential: credential,
  }, descriptor);
  const redemptionExpected = normalizeInstrumentBootstrapRedemptionExpected({
    version: 1,
    ...precommit,
    dispatch_record_digest: dispatchRecordDigest,
    bootstrap_request_digest: coreRequest.bootstrap_request_digest,
  });
  return {
    coreIntent,
    coreRequest,
    descriptor,
    dispatchRecordDigest,
    intentInput,
    precommit,
    precommitInput,
    redemptionExpected,
  };
}

function successReport(f, overrides = {}) {
  return {
    version: 1,
    attempt_ref: f.coreRequest.attempt_ref,
    operation_id: f.coreRequest.operation_id,
    bootstrap_intent_digest: f.coreRequest.bootstrap_intent_digest,
    bootstrap_request_digest: f.coreRequest.bootstrap_request_digest,
    signed_grant_digest: f.coreRequest.signed_grant_digest,
    replay_reservation_receipt_digest: f.coreRequest.replay_reservation_receipt_digest,
    dispatch_record_digest: f.coreRequest.dispatch_record_digest,
    dispatch_redemption_digest: digest("dispatch-redemption"),
    connection_generation: f.coreRequest.connection_generation,
    outcome: "succeeded",
    observation_ref: "bootstrap-observation:mock-inventory-0001",
    observation_digest: digest("observation"),
    receipt_ref: "bootstrap-receipt:mock-inventory-0001",
    receipt_digest: digest("receipt"),
    response_digest: digest("response"),
    observed_at: "2026-07-18T00:10:00.000Z",
    assurance_claims_digest: digest("assurance"),
    invariant_witness_digest: digest("witness"),
    ...overrides,
  };
}

test("durable precommit recomputes the exact provider ABI-v3 intent digest", () => {
  const f = fixture();
  assert.equal(
    instrumentBootstrapIntentDigest(f.intentInput),
    f.coreIntent.bootstrap_intent_digest,
  );
  assert.equal(f.precommit.bootstrap_intent_digest, f.coreIntent.bootstrap_intent_digest);
  assert.notEqual(f.precommit.durable_attempt_binding_digest, f.coreIntent.bootstrap_intent_digest);
  assert.match(f.precommit.durable_attempt_binding_digest, /^[a-f0-9]{64}$/);
  assert.notEqual(
    normalizeInstrumentBootstrapPrecommitRequest({
      ...f.precommitInput,
      custody_binding_digest: digest("other-custody-binding"),
    }).durable_attempt_binding_digest,
    f.precommit.durable_attempt_binding_digest,
  );

  for (const [field, replacement] of [
    ["bootstrap_invariants_digest", digest("other-invariants")],
    ["connection_ref", "instrument-connection:other"],
    ["connection_generation", 8],
    ["signed_grant_digest", digest("other-grant")],
  ]) {
    assert.throws(
      () => normalizeInstrumentBootstrapPrecommitRequest({
        ...f.precommitInput,
        [field]: replacement,
      }),
      /bootstrap_intent_digest does not match/,
    );
  }
});

test("provider request digest is derived only after the durable dispatch record", () => {
  const f = fixture();
  assert.equal(
    instrumentBootstrapRequestDigest({
      ...f.coreIntent,
      dispatch_record_digest: f.dispatchRecordDigest,
    }),
    f.coreRequest.bootstrap_request_digest,
  );
  assert.equal(
    f.redemptionExpected.bootstrap_request_digest,
    f.coreRequest.bootstrap_request_digest,
  );
  assert.throws(
    () => normalizeInstrumentBootstrapRedemptionExpected({
      ...f.redemptionExpected,
      dispatch_record_digest: digest("other-dispatch"),
    }),
    /bootstrap_request_digest does not match/,
  );
});

test("provider redemption accepts only the public ABI-v3 request binding", () => {
  const f = fixture();
  const projected = normalizeInstrumentBootstrapProviderRedemptionRequest({
    ...f.coreRequest,
  });
  assert.equal(projected.bootstrap_request_digest, f.coreRequest.bootstrap_request_digest);
  assert.equal(projected.bootstrap_intent_digest, f.coreRequest.bootstrap_intent_digest);
  assert.equal(projected.dispatch_record_digest, f.coreRequest.dispatch_record_digest);
  assert.equal(Object.hasOwn(projected, "dispatch_credential"), false);
  assert.equal(Object.hasOwn(projected, "durable_attempt_binding_digest"), false);
  assert.deepEqual(
    normalizeInstrumentBootstrapProviderRedemptionRequest(f.coreRequest),
    projected,
  );
  for (const privateField of [
    "bootstrap_grant_projection_digest",
    "custody_binding_digest",
    "durable_attempt_binding_digest",
  ]) {
    assert.throws(
      () => normalizeInstrumentBootstrapProviderRedemptionRequest({
        ...f.coreRequest,
        [privateField]: digest(privateField),
      }),
      /unknown fields/,
    );
  }
  assert.throws(
    () => normalizeInstrumentBootstrapProviderRedemptionRequest({
      ...f.coreRequest,
      bootstrap_request_digest: digest("detached-request"),
    }),
    /bootstrap_request_digest does not match/,
  );
});

test("durable report normalization is losslessly identical to the provider ABI report", () => {
  const f = fixture();
  const reportInput = successReport(f);
  const core = normalizeProviderBootstrapReport(reportInput, f.coreRequest);
  const durable = normalizeInstrumentBootstrapProviderReport(
    reportInput,
    f.redemptionExpected,
  );
  assert.deepEqual(durable, core);
  assert.match(
    instrumentBootstrapProviderReportDigest(reportInput, f.redemptionExpected),
    /^[a-f0-9]{64}$/,
  );
  const providerReportDigest = instrumentBootstrapProviderReportDigest(
    reportInput,
    f.redemptionExpected,
  );
  const terminal = normalizeInstrumentBootstrapTerminalBinding({
    version: 1,
    attempt_ref: f.coreRequest.attempt_ref,
    terminal_state: "succeeded",
    durable_attempt_binding_digest: f.precommit.durable_attempt_binding_digest,
    custody_binding_digest: f.precommit.custody_binding_digest,
    dispatch_record_digest: f.coreRequest.dispatch_record_digest,
    dispatch_redemption_digest: reportInput.dispatch_redemption_digest,
    provider_report_digest: providerReportDigest,
    terminal_recorded_at: "2026-07-18T00:10:01.000Z",
  }, reportInput, f.redemptionExpected);
  assert.match(terminal.durable_terminal_binding_digest, /^[a-f0-9]{64}$/);
  assert.notEqual(
    terminal.durable_terminal_binding_digest,
    f.precommit.durable_attempt_binding_digest,
  );
  assert.throws(
    () => normalizeInstrumentBootstrapTerminalBinding({
      ...terminal,
      terminal_state: "refused_no_effect",
    }, reportInput, f.redemptionExpected),
    /terminal_state drifted/,
  );

  const ambiguousInput = successReport(f, {
    outcome: "ambiguous",
    observation_ref: null,
    observation_digest: null,
    response_digest: null,
    observed_at: "2026-07-18T00:31:00.000Z",
    assurance_claims_digest: null,
    invariant_witness_digest: null,
  });
  assert.deepEqual(
    normalizeInstrumentBootstrapProviderReport(ambiguousInput, f.redemptionExpected),
    normalizeProviderBootstrapReport(ambiguousInput, f.coreRequest),
  );
  assert.throws(
    () => normalizeInstrumentBootstrapProviderReport(
      successReport(f, { bootstrap_request_digest: digest("detached-request") }),
      f.redemptionExpected,
    ),
    /bootstrap_request_digest drifted/,
  );
});

test("commit and broker ambiguity requests are closed and digest-bound", () => {
  const f = fixture();
  assert.deepEqual(normalizeInstrumentBootstrapCommitRequest({
    version: 1,
    attempt_ref: f.precommit.attempt_ref,
    expected_durable_attempt_binding_digest: f.precommit.durable_attempt_binding_digest,
  }), {
    version: 1,
    attempt_ref: f.precommit.attempt_ref,
    expected_durable_attempt_binding_digest: f.precommit.durable_attempt_binding_digest,
  });
  assert.deepEqual(normalizeInstrumentBootstrapMarkAmbiguousRequest({
    version: 1,
    attempt_ref: f.precommit.attempt_ref,
    expected_attempt_digest: digest("in-flight-head"),
    reason_code: "provider_timeout",
  }), {
    version: 1,
    attempt_ref: f.precommit.attempt_ref,
    expected_attempt_digest: digest("in-flight-head"),
    reason_code: "provider_timeout",
  });
  assert.throws(
    () => normalizeInstrumentBootstrapMarkAmbiguousRequest({
      version: 1,
      attempt_ref: f.precommit.attempt_ref,
      expected_attempt_digest: digest("in-flight-head"),
      reason_code: "provider_timeout",
      lease_id: "lease:fabricated",
    }),
    /unknown fields: lease_id/,
  );
  const ambiguity = normalizeInstrumentBootstrapDurableAmbiguity({
    version: 1,
    attempt_ref: f.precommit.attempt_ref,
    durable_attempt_binding_digest: f.precommit.durable_attempt_binding_digest,
    custody_binding_digest: f.precommit.custody_binding_digest,
    dispatch_record_digest: f.coreRequest.dispatch_record_digest,
    dispatch_redemption_digest: null,
    reason_code: "provider_timeout",
    ambiguity_receipt_ref: "bootstrap-ambiguity-receipt:timeout-0001",
    ambiguity_receipt_digest: digest("ambiguity-receipt"),
    terminal_recorded_at: "2026-07-18T00:11:00.000Z",
  });
  assert.equal(ambiguity.terminal_state, "ambiguous");
  assert.equal(ambiguity.dispatch_redemption_digest, null);
  assert.match(ambiguity.durable_terminal_binding_digest, /^[a-f0-9]{64}$/);
});

test("recovery dispositions distinguish safe retry, in-flight refusal, replay, and ambiguity", () => {
  assert.equal(recoveryDispositionForState("precommitted"), "safe_precommit_retry");
  assert.equal(recoveryDispositionForState("dispatch_committed"), "in_flight_fail_closed");
  assert.equal(recoveryDispositionForState("redeemed"), "in_flight_fail_closed");
  assert.equal(recoveryDispositionForState("succeeded"), "terminal_replay");
  assert.equal(recoveryDispositionForState("refused_no_effect"), "terminal_replay");
  assert.equal(recoveryDispositionForState("ambiguous"), "sticky_ambiguity");
});
