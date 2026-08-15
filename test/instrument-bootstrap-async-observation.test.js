"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const {
  instrumentBootstrapIntentDigest,
  normalizeInstrumentBootstrapPrecommitRequest,
  normalizeInstrumentBootstrapProviderRedemptionRequest,
} = require("../mcp/domains/physical/instrument-bootstrap-contract.js");
const {
  createDurableInstrumentBootstrapStore,
  createInstrumentBootstrapCustodyBinding,
  createInstrumentBootstrapProviderRedemptionPort,
  readInstrumentBootstrapCustodyProjection,
} = require("../mcp/domains/physical/instrument-bootstrap-store.js");
const {
  hashCanonicalJson,
} = require("../mcp/core/verification/verification-contracts.js");

function digest(label) {
  return hashCanonicalJson({ label });
}

const CUSTODY_FOR_PRECOMMIT = new WeakMap();

function clone(value) {
  return value == null ? null : structuredClone(value);
}

class MemoryStateAnchor {
  constructor() {
    this.state = null;
  }

  readState() {
    return clone(this.state);
  }

  compareAndSet(request) {
    const generation = this.state == null ? null : this.state.generation;
    const head = this.state == null ? null : this.state.head_event_digest;
    if (request.expected_generation !== generation
        || request.expected_head_event_digest !== head) return false;
    this.state = clone(request.next_state);
    return true;
  }
}

function makeClock(start = "2026-07-18T00:10:00.000Z") {
  let current = Date.parse(start);
  const clock = () => {
    const result = new Date(current);
    current += 1;
    return result;
  };
  clock.set = (timestamp) => { current = Date.parse(timestamp); };
  return clock;
}

function fixture(t, label) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "bob-bootstrap-async-"));
  fs.chmodSync(root, 0o700);
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const anchor = new MemoryStateAnchor();
  const clock = makeClock();
  const masterKey = crypto.createHash("sha256").update(`async-key:${label}`).digest();
  const runtimeId = `physical-runtime:v1:${digest(`runtime:${label}`).slice(0, 32)}`;
  const sessionNucleusHash = digest(`nucleus:${label}`);
  let currentStore = null;
  const open = () => {
    currentStore = createDurableInstrumentBootstrapStore({
      root,
      runtimeId,
      sessionNucleusHash,
      masterKey,
      stateAnchor: anchor,
      now: clock,
    });
    return currentStore;
  };
  return {
    anchor,
    clock,
    masterKey,
    open,
    root,
    runtimeId,
    sessionNucleusHash,
    get currentStore() { return currentStore; },
  };
}

function precommitFor(f, seed, overrides = {}) {
  const intent = {
    version: 1,
    call_kind: "bootstrap",
    attempt_ref: `bootstrap-attempt:${seed}`,
    session_nucleus_hash: f.sessionNucleusHash,
    physical_scope_axis_digest: digest(`axis:${seed}`),
    execution_principal_id: `principal:bootstrap-worker-${seed}`,
    instrument_ref: `instrument:owned-reader-${seed}`,
    enrollment_candidate_ref: `enrollment-candidate:owned-reader-${seed}`,
    provider_id: "deterministic_async_test",
    provider_descriptor_digest: digest(`descriptor:${seed}`),
    provider_binary_digest: digest(`binary:${seed}`),
    transport_digest: digest(`transport:${seed}`),
    bootstrap_manifest_digest: digest(`manifest:${seed}`),
    bootstrap_invariants_digest: digest(`invariants:${seed}`),
    operation_id: "instrument.inventory",
    operation_digest: digest(`operation:${seed}`),
    execution_request_digest: digest(`request:${seed}`),
    authority_resolution_digest: digest(`authority:${seed}`),
    signed_grant_digest: digest(`grant:${seed}`),
    replay_claim_digest: digest(`claim:${seed}`),
    replay_reservation_receipt_digest: digest(`reservation:${seed}`),
    connection_ref: `instrument-connection:owned-reader-${seed}`,
    connection_generation: 7,
    grant_not_before: "2026-07-18T00:00:00.000Z",
    grant_expires_at: "2026-07-18T00:30:00.000Z",
    ...overrides,
  };
  if (!f.currentStore) throw new Error("fixture store must be open before creating custody");
  const custodyState = { control: {} };
  const custodyBinding = createInstrumentBootstrapCustodyBinding(f.currentStore, {
    custody_authority: Object.freeze(Object.create(null)),
    read_connection_generation() {
      const control = custodyState.control;
      control.connectionCalls = (control.connectionCalls || 0) + 1;
      return {
        connection_ref: control.connectionRef || intent.connection_ref,
        connection_generation: control.connectionGeneration || intent.connection_generation,
        connected: control.connected !== false,
      };
    },
  });
  const custodyProjection = readInstrumentBootstrapCustodyProjection(custodyBinding);
  const precommit = normalizeInstrumentBootstrapPrecommitRequest({
    provider_abi_version: 3,
    ...intent,
    bootstrap_intent_digest: instrumentBootstrapIntentDigest(intent),
    bootstrap_grant_projection_digest: digest(`projection:${seed}`),
    custody_binding_digest: custodyProjection.custody_binding_digest,
  });
  CUSTODY_FOR_PRECOMMIT.set(precommit, {
    binding: custodyBinding,
    control_state: custodyState,
    projection: custodyProjection,
  });
  return precommit;
}

function custodyFor(precommit) {
  const custody = CUSTODY_FOR_PRECOMMIT.get(precommit);
  if (!custody) throw new Error("precommit fixture lost its custody capability");
  return custody;
}

function providerRequestFor(precommit, dispatch) {
  return normalizeInstrumentBootstrapProviderRedemptionRequest({
    ...Object.fromEntries(
      Object.entries(precommit).filter(([field]) => ![
        "provider_abi_version",
        "bootstrap_grant_projection_digest",
        "custody_binding_digest",
        "durable_attempt_binding_digest",
      ].includes(field)),
    ),
    dispatch_record_digest: dispatch.dispatch_record_digest,
    bootstrap_request_digest: dispatch.bootstrap_request_digest,
  });
}

function enrollmentFor(precommit, control = {}) {
  const custody = custodyFor(precommit);
  custody.control_state.control = control;
  control.authorityCalls = 0;
  control.connectionCalls = 0;
  return {
    provider_id: precommit.provider_id,
    provider_descriptor_digest: precommit.provider_descriptor_digest,
    provider_binary_digest: precommit.provider_binary_digest,
    transport_digest: precommit.transport_digest,
    bootstrap_manifest_digest: precommit.bootstrap_manifest_digest,
    bootstrap_invariants_digest: precommit.bootstrap_invariants_digest,
    execution_principal_id: precommit.execution_principal_id,
    instrument_ref: precommit.instrument_ref,
    enrollment_candidate_ref: precommit.enrollment_candidate_ref,
    custody_binding: custody.binding,
    revalidateBootstrapAuthority() {
      control.authorityCalls += 1;
      return control.authority !== false;
    },
  };
}

function dispatchAndRedeem(store, precommit, control = {}, options = {}) {
  const custody = custodyFor(precommit);
  store.precommitAttempt(precommit, custody.projection);
  const committed = store.commitDispatch({
    version: 1,
    attempt_ref: precommit.attempt_ref,
    expected_durable_attempt_binding_digest: precommit.durable_attempt_binding_digest,
  }, custody.projection);
  const provider = createInstrumentBootstrapProviderRedemptionPort(
    store,
    enrollmentFor(precommit, control),
    options,
  );
  const request = providerRequestFor(precommit, committed.dispatch);
  const redemption = provider.redeem(committed.dispatch_credential, request);
  return { committed, control, provider, redemption, request };
}

function successReport(request, redemption, seed) {
  return {
    version: 1,
    attempt_ref: request.attempt_ref,
    operation_id: request.operation_id,
    bootstrap_intent_digest: request.bootstrap_intent_digest,
    bootstrap_request_digest: request.bootstrap_request_digest,
    signed_grant_digest: request.signed_grant_digest,
    replay_reservation_receipt_digest: request.replay_reservation_receipt_digest,
    dispatch_record_digest: request.dispatch_record_digest,
    dispatch_redemption_digest: redemption.dispatch_redemption_digest,
    connection_generation: request.connection_generation,
    outcome: "succeeded",
    observation_ref: `bootstrap-observation:${seed}`,
    observation_digest: digest(`observation:${seed}`),
    receipt_ref: `bootstrap-receipt:${seed}`,
    receipt_digest: digest(`receipt:${seed}`),
    response_digest: digest(`response:${seed}`),
    observed_at: "2026-07-18T00:10:01.000Z",
    assurance_claims_digest: digest(`assurance:${seed}`),
    invariant_witness_digest: digest(`witness:${seed}`),
  };
}

async function waitForState(store, attemptRef, state, timeoutMs = 1_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const attempt = store.readAttempt(attemptRef);
    if (attempt && attempt.state === state) return attempt;
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
  assert.fail(`attempt ${attemptRef} did not reach ${state}`);
}

test("split-phase observation releases the store lock and accepts one exact late report", async (t) => {
  const f = fixture(t, "success");
  const store = f.open();
  const precommit = precommitFor(f, "success");
  const { provider, redemption, request, control } = dispatchAndRedeem(
    store,
    precommit,
    {},
    { observation_timeout_ms: 1_000 },
  );
  const begun = provider.beginBootstrapObservation(redemption.permit);
  assert.equal(begun.started, true);
  assert.equal(begun.provider_report, null);
  assert.equal(begun.redemption_projection, redemption.redemption_projection);
  assert.ok(Object.isFrozen(begun));
  assert.ok(Object.isFrozen(begun.completion_capability));
  assert.deepEqual(Object.keys(begun.completion_capability), []);
  assert.throws(() => JSON.stringify(begun.completion_capability), /not serializable/);
  assert.equal(control.authorityCalls, 2);
  assert.equal(control.connectionCalls, 2);

  // A pending device promise exists entirely outside the store mutation lock.
  let resolveDevice;
  const deviceIo = new Promise((resolve) => { resolveDevice = resolve; });
  assert.equal(store.snapshot().attempts[0].state, "redeemed");
  const unrelated = precommitFor(f, "unrelated");
  assert.equal(
    store.precommitAttempt(unrelated, custodyFor(unrelated).projection).state,
    "precommitted",
  );
  resolveDevice(successReport(request, begun.redemption_projection, "success"));
  const report = await deviceIo;
  const terminal = provider.completeBootstrapObservation(
    begun.completion_capability,
    report,
  );
  assert.equal(terminal.outcome, "succeeded");
  assert.equal(store.readAttempt(precommit.attempt_ref).state, "succeeded");
  assert.throws(
    () => provider.completeBootstrapObservation(begun.completion_capability, report),
    /was not issued to this provider port/,
  );
  assert.throws(
    () => provider.beginBootstrapObservation(redemption.permit),
    /permit was not issued to this provider port/,
  );
});

for (const drift of ["authority", "generation", "window"]) {
  test(`async begin ${drift} refusal terminalizes without completion authority or device I/O`, (t) => {
    const f = fixture(t, `refuse-${drift}`);
    const store = f.open();
    const precommit = precommitFor(f, `refuse-${drift}`);
    const control = {};
    const { provider, redemption } = dispatchAndRedeem(store, precommit, control);
    if (drift === "authority") control.authority = false;
    if (drift === "generation") {
      control.connectionGeneration = precommit.connection_generation + 1;
    }
    if (drift === "window") f.clock.set(precommit.grant_expires_at);

    let deviceCalls = 0;
    const begun = provider.beginBootstrapObservation(redemption.permit);
    if (begun.started) deviceCalls += 1;
    assert.equal(deviceCalls, 0);
    assert.equal(begun.started, false);
    assert.equal(begun.completion_capability, null);
    assert.equal(begun.provider_report.outcome, "refused_no_effect");
    assert.equal(store.readAttempt(precommit.attempt_ref).state, "refused_no_effect");
    assert.throws(
      () => provider.beginBootstrapObservation(redemption.permit),
      /permit was not issued to this provider port/,
    );
  });
}

test("timeout destroys completion authority, records sticky ambiguity, and rejects late output", async (t) => {
  const f = fixture(t, "timeout");
  const store = f.open();
  const precommit = precommitFor(f, "timeout");
  const { provider, redemption, request } = dispatchAndRedeem(
    store,
    precommit,
    {},
    { observation_timeout_ms: 15 },
  );
  const begun = provider.beginBootstrapObservation(redemption.permit);
  const terminal = await waitForState(store, precommit.attempt_ref, "ambiguous");
  assert.equal(terminal.terminal_reason_code, "observation_timeout");
  assert.equal(terminal.provider_report.outcome, "ambiguous");
  assert.throws(
    () => provider.completeBootstrapObservation(
      begun.completion_capability,
      successReport(request, begun.redemption_projection, "late"),
    ),
    /was not issued to this provider port/,
  );
  assert.equal(store.snapshot().generation, 4);
});

test("broker ambiguity wins the durable head and a late provider result cannot reclassify it", (t) => {
  const f = fixture(t, "broker-ambiguity");
  const store = f.open();
  const precommit = precommitFor(f, "broker-ambiguity");
  const { provider, redemption, request } = dispatchAndRedeem(store, precommit);
  const begun = provider.beginBootstrapObservation(redemption.permit);
  const redeemed = store.readAttempt(precommit.attempt_ref);
  const ambiguous = store.markAmbiguous({
    version: 1,
    attempt_ref: precommit.attempt_ref,
    expected_attempt_digest: redeemed.attempt_digest,
    reason_code: "broker_response_lost",
  });
  assert.equal(ambiguous.state, "ambiguous");
  assert.equal(ambiguous.provider_report, null);
  assert.throws(
    () => provider.completeBootstrapObservation(
      begun.completion_capability,
      successReport(request, begun.redemption_projection, "broker-late"),
    ),
    /lost its exact redeemed record/,
  );
  assert.equal(store.readAttempt(precommit.attempt_ref).terminal_reason_code, "broker_response_lost");
  assert.throws(
    () => provider.completeBootstrapObservation(
      begun.completion_capability,
      successReport(request, begun.redemption_projection, "broker-replay"),
    ),
    /was not issued to this provider port/,
  );
});

test("restart invalidates the live capability and recovery makes the redeemed head sticky ambiguous", (t) => {
  const f = fixture(t, "restart");
  let store = f.open();
  const precommit = precommitFor(f, "restart");
  const { provider, redemption, request } = dispatchAndRedeem(store, precommit);
  const begun = provider.beginBootstrapObservation(redemption.permit);
  store.close();
  assert.throws(
    () => provider.completeBootstrapObservation(
      begun.completion_capability,
      successReport(request, begun.redemption_projection, "old-process"),
    ),
    /store is closed|was not issued to this provider port/,
  );
  store = f.open();
  const terminal = store.readAttempt(precommit.attempt_ref);
  assert.equal(terminal.state, "ambiguous");
  assert.equal(terminal.terminal_reason_code, "restart_in_flight");
  assert.equal(terminal.provider_report, null);
});

test("completion capabilities reject clones, cross-wiring, wrong ports, and wrong stores", (t) => {
  const f = fixture(t, "confusion");
  const store = f.open();
  const first = precommitFor(f, "confusion-a");
  const a = dispatchAndRedeem(store, first);
  const begun = a.provider.beginBootstrapObservation(a.redemption.permit);
  const sibling = createInstrumentBootstrapProviderRedemptionPort(
    store,
    enrollmentFor(first, {}),
  );
  const cloneCapability = { ...begun.completion_capability };
  const report = successReport(a.request, begun.redemption_projection, "confusion-a");
  assert.throws(
    () => a.provider.completeBootstrapObservation(cloneCapability, report),
    /was not issued to this provider port/,
  );
  assert.throws(
    () => sibling.completeBootstrapObservation(begun.completion_capability, report),
    /was not issued to this provider port/,
  );

  const other = fixture(t, "confusion-other");
  const otherStore = other.open();
  const otherPrecommit = precommitFor(other, "confusion-other");
  const otherPort = createInstrumentBootstrapProviderRedemptionPort(
    otherStore,
    enrollmentFor(otherPrecommit, {}),
  );
  assert.throws(
    () => otherPort.completeBootstrapObservation(begun.completion_capability, report),
    /was not issued to this provider port/,
  );

  const second = precommitFor(f, "confusion-b", {
    provider_id: first.provider_id,
    provider_descriptor_digest: first.provider_descriptor_digest,
    provider_binary_digest: first.provider_binary_digest,
    transport_digest: first.transport_digest,
    bootstrap_manifest_digest: first.bootstrap_manifest_digest,
    bootstrap_invariants_digest: first.bootstrap_invariants_digest,
    execution_principal_id: first.execution_principal_id,
    instrument_ref: first.instrument_ref,
    enrollment_candidate_ref: first.enrollment_candidate_ref,
    connection_ref: first.connection_ref,
  });
  const b = dispatchAndRedeem(store, second);
  const bBegun = b.provider.beginBootstrapObservation(b.redemption.permit);
  const crosswiredReport = successReport(
    b.request,
    bBegun.redemption_projection,
    "confusion-b",
  );
  const failClosed = a.provider.completeBootstrapObservation(
    begun.completion_capability,
    crosswiredReport,
  );
  assert.equal(failClosed.outcome, "ambiguous");
  assert.equal(store.readAttempt(first.attempt_ref).terminal_reason_code, "provider_report_invalid");
  assert.throws(
    () => a.provider.completeBootstrapObservation(bBegun.completion_capability, crosswiredReport),
    /was not issued to this provider port/,
  );
  const bTerminal = b.provider.completeBootstrapObservation(
    bBegun.completion_capability,
    crosswiredReport,
  );
  assert.equal(bTerminal.outcome, "succeeded");
});

test("provider port timeout policy is closed and bounded", (t) => {
  const f = fixture(t, "options");
  const store = f.open();
  const precommit = precommitFor(f, "options");
  const enrollment = enrollmentFor(precommit, {});
  for (const observation_timeout_ms of [0, -1, 1.5, Number.MAX_SAFE_INTEGER]) {
    assert.throws(
      () => createInstrumentBootstrapProviderRedemptionPort(
        store,
        enrollment,
        { observation_timeout_ms },
      ),
      /observation_timeout_ms/,
    );
  }
  assert.throws(
    () => createInstrumentBootstrapProviderRedemptionPort(
      store,
      enrollment,
      { observation_timeout_ms: 10, unexpected: true },
    ),
    /unknown fields/,
  );
});
