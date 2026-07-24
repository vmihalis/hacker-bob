"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const {
  instrumentBootstrapIntentDigest,
  instrumentBootstrapProviderReportDigest,
  normalizeInstrumentBootstrapPrecommitRequest,
  normalizeInstrumentBootstrapProviderRedemptionRequest,
  normalizeInstrumentBootstrapRedemptionExpected,
} = require("../mcp/lib/instrument-bootstrap-contract.js");
const {
  assertDurableInstrumentBootstrapStore,
  assertInstrumentBootstrapBrokerPort,
  assertInstrumentBootstrapCustodyBinding,
  assertInstrumentBootstrapCustodyProjection,
  assertInstrumentBootstrapProviderRedemptionPort,
  createDurableInstrumentBootstrapStore,
  createInstrumentBootstrapCustodyBinding,
  createInstrumentBootstrapBrokerPort,
  createInstrumentBootstrapProviderRedemptionPort,
  readInstrumentBootstrapCustodyProjection,
} = require("../mcp/lib/instrument-bootstrap-store.js");
const {
  hashCanonicalJson,
} = require("../mcp/lib/verification-contracts.js");

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
    this.rejectNext = false;
    this.throwAfterCommit = false;
    this.hiddenReads = 0;
  }

  readState() {
    if (this.hiddenReads > 0) {
      this.hiddenReads -= 1;
      throw new Error("injected bootstrap anchor read outage");
    }
    return clone(this.state);
  }

  compareAndSet(request) {
    const generation = this.state == null ? null : this.state.generation;
    const head = this.state == null ? null : this.state.head_event_digest;
    if (request.expected_generation !== generation
        || request.expected_head_event_digest !== head) return false;
    if (this.rejectNext) {
      this.rejectNext = false;
      return false;
    }
    this.state = clone(request.next_state);
    if (this.throwAfterCommit) {
      this.throwAfterCommit = false;
      this.hiddenReads = 1;
      throw new Error("injected bootstrap anchor commit response loss");
    }
    return true;
  }

  armReject() {
    this.rejectNext = true;
  }

  armAmbiguousCommit() {
    this.throwAfterCommit = true;
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
  clock.peek = () => new Date(current).toISOString();
  return clock;
}

function fixture(t, label = "default") {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "bob-bootstrap-store-"));
  fs.chmodSync(root, 0o700);
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const anchor = new MemoryStateAnchor();
  const clock = makeClock();
  const masterKey = crypto.createHash("sha256").update(`bootstrap-key:${label}`).digest();
  const runtimeId = `physical-runtime:v1:${digest(`runtime:${label}`).slice(0, 32)}`;
  const sessionNucleusHash = digest(`session-nucleus:${label}`);
  let currentStore = null;
  const open = (overrides = {}) => {
    currentStore = createDurableInstrumentBootstrapStore({
      root,
      runtimeId,
      sessionNucleusHash,
      masterKey,
      stateAnchor: anchor,
      now: clock,
      ...overrides,
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

function precommitFor(f, seed = "attempt-1", overrides = {}) {
  const intent = {
    version: 1,
    call_kind: "bootstrap",
    attempt_ref: `bootstrap-attempt:${seed}`,
    session_nucleus_hash: f.sessionNucleusHash,
    physical_scope_axis_digest: digest(`physical-axis:${seed}`),
    execution_principal_id: `principal:bootstrap-worker-${seed}`,
    instrument_ref: `instrument:owned-reader-${seed}`,
    enrollment_candidate_ref: `enrollment-candidate:owned-reader-${seed}`,
    provider_id: "deterministic_bootstrap_test",
    provider_descriptor_digest: digest(`provider-descriptor:${seed}`),
    provider_binary_digest: digest(`provider-binary:${seed}`),
    transport_digest: digest(`transport:${seed}`),
    bootstrap_manifest_digest: digest(`bootstrap-manifest:${seed}`),
    bootstrap_invariants_digest: digest(`bootstrap-invariants:${seed}`),
    operation_id: "instrument.inventory",
    operation_digest: digest(`operation:${seed}`),
    execution_request_digest: digest(`execution-request:${seed}`),
    authority_resolution_digest: digest(`authority-resolution:${seed}`),
    signed_grant_digest: digest(`signed-grant:${seed}`),
    replay_claim_digest: digest(`replay-claim:${seed}`),
    replay_reservation_receipt_digest: digest(`replay-receipt:${seed}`),
    connection_ref: `instrument-connection:owned-reader-${seed}`,
    connection_generation: 7,
    grant_not_before: "2026-07-18T00:00:00.000Z",
    grant_expires_at: "2026-07-18T00:30:00.000Z",
    ...overrides,
  };
  if (!f.currentStore) throw new Error("fixture store must be open before creating custody");
  const custodyState = { control: {} };
  const custodyAuthority = Object.freeze(Object.create(null));
  const custodyBinding = createInstrumentBootstrapCustodyBinding(f.currentStore, {
    custody_authority: custodyAuthority,
    read_connection_generation() {
      const control = custodyState.control;
      control.connectionCalls = (control.connectionCalls || 0) + 1;
      if (control.connectionError) throw control.connectionError;
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
    bootstrap_grant_projection_digest: digest(`grant-projection:${seed}`),
    custody_binding_digest: custodyProjection.custody_binding_digest,
  });
  CUSTODY_FOR_PRECOMMIT.set(precommit, {
    binding: custodyBinding,
    authority: custodyAuthority,
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

function precommitAttempt(store, precommit, custodySource = precommit) {
  return store.precommitAttempt(precommit, custodyFor(custodySource).projection);
}

function commitAttempt(store, precommit) {
  const custody = custodyFor(precommit);
  const durable = store.precommitAttempt(precommit, custody.projection);
  const committed = store.commitDispatch({
    version: 1,
    attempt_ref: precommit.attempt_ref,
    expected_durable_attempt_binding_digest: precommit.durable_attempt_binding_digest,
  }, custody.projection);
  const expected = normalizeInstrumentBootstrapRedemptionExpected({
    version: 1,
    ...precommit,
    dispatch_record_digest: committed.dispatch.dispatch_record_digest,
    bootstrap_request_digest: committed.dispatch.bootstrap_request_digest,
  });
  const providerRequest = providerRequestFor(expected);
  return { committed, durable, expected, providerRequest };
}

function providerRequestFor(expected) {
  const providerRequestInput = { ...expected };
  delete providerRequestInput.provider_abi_version;
  delete providerRequestInput.bootstrap_grant_projection_digest;
  delete providerRequestInput.custody_binding_digest;
  delete providerRequestInput.durable_attempt_binding_digest;
  return normalizeInstrumentBootstrapProviderRedemptionRequest(providerRequestInput);
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
    revalidateBootstrapAuthority(request) {
      control.authorityCalls += 1;
      assert.ok(Object.isFrozen(request));
      if (control.authorityError) throw control.authorityError;
      return control.authority !== false;
    },
  };
}

function successReport(expected, redemption, seed = "success") {
  assert.ok(redemption && redemption.dispatch_redemption_digest,
    "the observation callback must receive the store-created redemption binding");
  return {
    version: 1,
    attempt_ref: expected.attempt_ref,
    operation_id: expected.operation_id,
    bootstrap_intent_digest: expected.bootstrap_intent_digest,
    bootstrap_request_digest: expected.bootstrap_request_digest,
    signed_grant_digest: expected.signed_grant_digest,
    replay_reservation_receipt_digest: expected.replay_reservation_receipt_digest,
    dispatch_record_digest: expected.dispatch_record_digest,
    dispatch_redemption_digest: redemption.dispatch_redemption_digest,
    connection_generation: expected.connection_generation,
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

function redeemCommitted(store, precommit, committed, expected, control = {}) {
  const provider = createInstrumentBootstrapProviderRedemptionPort(
    store,
    enrollmentFor(precommit, control),
  );
  const redemption = provider.redeem(
    committed.dispatch_credential,
    providerRequestFor(expected),
  );
  return {
    control,
    permit: redemption.permit,
    provider,
    redemptionProjection: redemption.redemption_projection,
  };
}

function eventPath(f, generation = 1) {
  return path.join(
    f.root,
    "bootstrap-events",
    `${String(generation).padStart(12, "0")}.bootstrap-event.json`,
  );
}

test("secure create/reopen encrypts the append-only attempt and binds root, key, runtime, and nucleus", (t) => {
  const f = fixture(t, "secure-reopen");
  let store = f.open();
  assert.equal(assertDurableInstrumentBootstrapStore(store), store);
  const precommit = precommitFor(f, "secure-reopen");
  const attempt = precommitAttempt(store, precommit);
  assert.equal(attempt.state, "precommitted");

  const metadataPath = path.join(f.root, "bootstrap-runtime.json");
  const eventsRoot = path.join(f.root, "bootstrap-events");
  for (const candidate of [f.root, eventsRoot]) {
    assert.equal(fs.statSync(candidate).mode & 0o077, 0);
  }
  for (const candidate of [metadataPath, eventPath(f)]) {
    const stat = fs.lstatSync(candidate);
    assert.ok(stat.isFile());
    assert.equal(stat.nlink, 1);
    assert.equal(stat.mode & 0o077, 0);
  }
  const envelopeText = fs.readFileSync(eventPath(f), "utf8");
  assert.doesNotMatch(envelopeText, new RegExp(precommit.attempt_ref));
  assert.doesNotMatch(envelopeText, new RegExp(precommit.signed_grant_digest));

  store.close();
  store = f.open();
  assert.deepEqual(store.readAttempt(precommit.attempt_ref), attempt);
  store.close();

  assert.throws(
    () => f.open({ masterKey: crypto.randomBytes(32) }),
    /authenticate|authentic|decrypt|Unsupported state/i,
  );
  assert.throws(
    () => f.open({ runtimeId: `physical-runtime:v1:${digest("other-runtime").slice(0, 32)}` }),
    /metadata binding drift/,
  );
  assert.throws(
    () => f.open({ sessionNucleusHash: digest("other-nucleus") }),
    /metadata binding drift/,
  );
});

test("exact precommit, dispatch, redemption, and observation success preserves ABI-v3 lineage", (t) => {
  const f = fixture(t, "exact-success");
  const store = f.open();
  const precommit = precommitFor(f, "exact-success");
  const { committed, durable, expected } = commitAttempt(store, precommit);
  assert.equal(durable.state, "precommitted");
  assert.equal(durable.sequence, 1);
  assert.equal(committed.attempt.state, "dispatch_committed");
  assert.equal(committed.attempt.sequence, 2);
  assert.equal(committed.already_committed, false);
  assert.ok(Object.isFrozen(committed));
  assert.ok(Object.isFrozen(committed.dispatch_credential));
  assert.throws(() => JSON.stringify(committed.dispatch_credential), /not serializable/);

  const {
    permit,
    provider,
    redemptionProjection,
  } = redeemCommitted(store, precommit, committed, expected);
  assert.ok(Object.isFrozen(redemptionProjection));
  assert.deepEqual(Object.keys(redemptionProjection).sort(), [
    "attempt_ref",
    "bootstrap_request_digest",
    "connection_generation",
    "connection_ref",
    "custody_binding_digest",
    "dispatch_record_digest",
    "dispatch_redemption_digest",
    "redeemed_at",
  ]);
  const redeemed = store.readAttempt(precommit.attempt_ref);
  assert.equal(redeemed.state, "redeemed");
  assert.equal(redeemed.sequence, 3);
  assert.deepEqual(redemptionProjection, {
    attempt_ref: redeemed.redemption.attempt_ref,
    dispatch_record_digest: redeemed.redemption.dispatch_record_digest,
    bootstrap_request_digest: redeemed.redemption.bootstrap_request_digest,
    custody_binding_digest: redeemed.redemption.custody_binding_digest,
    connection_ref: redeemed.redemption.connection_ref,
    connection_generation: redeemed.redemption.connection_generation,
    redeemed_at: redeemed.redemption.redeemed_at,
    dispatch_redemption_digest: redeemed.redemption.dispatch_redemption_digest,
  });
  let callbackCalls = 0;
  const returned = provider.consumeBootstrapObservation(permit, (redemption) => {
    callbackCalls += 1;
    assert.ok(Object.isFrozen(redemption));
    assert.deepEqual(redemption, redemptionProjection);
    return successReport(expected, redemption, "exact-success");
  });
  assert.equal(callbackCalls, 1);
  assert.equal(returned.outcome, "succeeded");

  const terminal = store.readAttempt(precommit.attempt_ref);
  assert.equal(terminal.state, "succeeded");
  assert.equal(terminal.sequence, 4);
  assert.equal(store.snapshot().generation, 4);
  assert.equal(terminal.recovery_disposition, "terminal_replay");
  assert.deepEqual(terminal.provider_report, returned);
  assert.equal(
    terminal.provider_report_digest,
    instrumentBootstrapProviderReportDigest(returned, expected),
  );
  assert.equal(
    terminal.terminal_binding.dispatch_redemption_digest,
    terminal.redemption.dispatch_redemption_digest,
  );
  assert.equal(
    terminal.terminal_binding.custody_binding_digest,
    terminal.redemption.custody_binding_digest,
  );
});

test("custody capabilities reject serialization, clones, cross-wiring, duplicate issuance, and drift", (t) => {
  const f = fixture(t, "custody-capabilities");
  const store = f.open();
  const first = precommitFor(f, "custody-capability-a");
  const second = precommitFor(f, "custody-capability-b");
  const a = custodyFor(first);
  const b = custodyFor(second);

  assert.equal(assertInstrumentBootstrapCustodyBinding(a.binding), a.binding);
  assert.equal(assertInstrumentBootstrapCustodyProjection(a.projection), a.projection);
  assert.throws(() => JSON.stringify(a.binding), /not serializable/);
  assert.throws(() => JSON.stringify(a.projection), /not serializable/);
  assert.throws(
    () => assertInstrumentBootstrapCustodyBinding(Object.freeze({ ...a.binding })),
    /private store-issued capability/,
  );
  assert.throws(
    () => assertInstrumentBootstrapCustodyProjection(Object.freeze({ ...a.projection })),
    /private store-issued capability/,
  );
  assert.throws(
    () => createInstrumentBootstrapCustodyBinding(store, {
      custody_authority: a.authority,
      read_connection_generation: () => ({
        connection_ref: first.connection_ref,
        connection_generation: first.connection_generation,
        connected: true,
      }),
    }),
    /already bound by this store/,
  );

  precommitAttempt(store, first);
  assert.throws(
    () => store.commitDispatch({
      version: 1,
      attempt_ref: first.attempt_ref,
      expected_durable_attempt_binding_digest: first.durable_attempt_binding_digest,
    }, b.projection),
    /lost its exact live custody instance/,
  );
  assert.equal(store.readAttempt(first.attempt_ref).state, "precommitted");
  assert.throws(
    () => store.precommitAttempt(second, Object.freeze({ ...b.projection })),
    /not issued by this live store/,
  );

  a.control_state.control.connectionGeneration = first.connection_generation + 1;
  const drifted = readInstrumentBootstrapCustodyProjection(a.binding);
  assert.notEqual(drifted.custody_binding_digest, first.custody_binding_digest);
  assert.throws(
    () => store.commitDispatch({
      version: 1,
      attempt_ref: first.attempt_ref,
      expected_durable_attempt_binding_digest: first.durable_attempt_binding_digest,
    }, a.projection),
    /connection_generation drifted/,
  );
  assert.equal(store.readAttempt(first.attempt_ref).state, "precommitted");
});

test("attempt, grant, execution-request, and replay-receipt reuse cannot fork durable lineage", (t) => {
  const f = fixture(t, "semantic-replay");
  const store = f.open();
  const original = precommitFor(f, "semantic-replay-original");
  const durable = precommitAttempt(store, original);
  assert.deepEqual(precommitAttempt(store, { ...original }, original), durable);
  assert.equal(store.snapshot().generation, 1);

  assert.throws(
    () => {
      const candidate = precommitFor(f, "same-ref-drift", {
        attempt_ref: original.attempt_ref,
      });
      return precommitAttempt(store, candidate);
    },
    /crosswired to another live custody instance/,
  );
  assert.throws(
    () => {
      const candidate = precommitFor(f, "grant-replay", {
        signed_grant_digest: original.signed_grant_digest,
      });
      return precommitAttempt(store, candidate);
    },
    /signed grant is already bound to another attempt/,
  );
  assert.throws(
    () => {
      const candidate = precommitFor(f, "execution-replay", {
        execution_request_digest: original.execution_request_digest,
      });
      return precommitAttempt(store, candidate);
    },
    /execution request is already bound to another attempt/,
  );
  assert.throws(
    () => {
      const candidate = precommitFor(f, "receipt-replay", {
        replay_reservation_receipt_digest: original.replay_reservation_receipt_digest,
      });
      return precommitAttempt(store, candidate);
    },
    /replay receipt is already bound to another attempt/,
  );
  assert.equal(store.snapshot().generation, 1);
});

test("credential and permit clone, cross-wire, cross-store, and replay attempts fail closed", (t) => {
  const f = fixture(t, "clone-crosswire");
  const store = f.open();
  const first = precommitFor(f, "wire-a");
  const second = precommitFor(f, "wire-b");
  const a = commitAttempt(store, first);
  const b = commitAttempt(store, second);
  const aControl = {};
  const aProvider = createInstrumentBootstrapProviderRedemptionPort(
    store,
    enrollmentFor(first, aControl),
  );
  const aSiblingPort = createInstrumentBootstrapProviderRedemptionPort(
    store,
    enrollmentFor(first, {}),
  );
  const bProvider = createInstrumentBootstrapProviderRedemptionPort(
    store,
    enrollmentFor(second, {}),
  );

  assert.throws(
    () => aProvider.redeem({ ...a.committed.dispatch_credential }, a.providerRequest),
    /not issued by this live durable store/,
  );
  assert.throws(
    () => aProvider.redeem(a.committed.dispatch_credential, b.providerRequest),
    /request drift/,
  );
  assert.throws(
    () => bProvider.redeem(a.committed.dispatch_credential, a.providerRequest),
    /crosswired to another custody instance/,
  );

  const other = fixture(t, "clone-crosswire-other");
  const otherStore = other.open();
  const otherPrecommit = precommitFor(other, "clone-crosswire-other");
  assert.throws(
    () => createInstrumentBootstrapProviderRedemptionPort(
      otherStore,
      { ...enrollmentFor(first, {}), custody_binding: custodyFor(first).binding },
    ),
    /another durable store/,
  );
  const otherProvider = createInstrumentBootstrapProviderRedemptionPort(
    otherStore,
    enrollmentFor(otherPrecommit, {}),
  );
  assert.throws(
    () => otherProvider.redeem(a.committed.dispatch_credential, a.providerRequest),
    /not issued by this live durable store/,
  );

  const redemption = aProvider.redeem(
    a.committed.dispatch_credential,
    a.providerRequest,
  );
  const permit = redemption.permit;
  assert.throws(
    () => aProvider.redeem(a.committed.dispatch_credential, a.providerRequest),
    /not issued by this live durable store/,
  );
  assert.throws(
    () => aSiblingPort.consumeBootstrapObservation(permit, () => {
      throw new Error("must not run");
    }),
    /not issued to this provider port/,
  );

  let calls = 0;
  const report = aProvider.consumeBootstrapObservation(permit, (redemption) => {
    calls += 1;
    return successReport(a.expected, redemption, "wire-a");
  });
  assert.equal(report.outcome, "succeeded");
  assert.equal(calls, 1);
  assert.throws(
    () => aProvider.consumeBootstrapObservation(permit, () => { calls += 1; }),
    /not issued to this provider port/,
  );
  assert.equal(calls, 1);

  const bPermit = bProvider.redeem(
    b.committed.dispatch_credential,
    b.providerRequest,
  ).permit;
  const permitClone = Object.assign(Object.create(null), bPermit);
  assert.throws(
    () => bProvider.consumeBootstrapObservation(permitClone, () => {
      throw new Error("must not run");
    }),
    /not issued to this provider port/,
  );
});

test("redemption refuses stale authority, expired windows, and connection-generation drift without consuming credentials", (t) => {
  const f = fixture(t, "redemption-preflight");
  const store = f.open();
  const precommit = precommitFor(f, "redemption-preflight");
  const c = commitAttempt(store, precommit);
  const control = { authority: false };
  const provider = createInstrumentBootstrapProviderRedemptionPort(
    store,
    enrollmentFor(precommit, control),
  );
  assert.throws(
    () => provider.redeem(c.committed.dispatch_credential, c.providerRequest),
    /authority revalidation refused/,
  );
  assert.equal(store.readAttempt(precommit.attempt_ref).state, "dispatch_committed");

  control.authority = true;
  control.connectionGeneration = precommit.connection_generation + 1;
  assert.throws(
    () => provider.redeem(c.committed.dispatch_credential, c.providerRequest),
    /connection_generation custody drift/,
  );
  assert.equal(store.readAttempt(precommit.attempt_ref).state, "dispatch_committed");

  control.connectionGeneration = precommit.connection_generation;
  f.clock.set(precommit.grant_expires_at);
  assert.throws(
    () => provider.redeem(c.committed.dispatch_credential, c.providerRequest),
    /outside the bootstrap grant window/,
  );
  assert.equal(store.readAttempt(precommit.attempt_ref).state, "dispatch_committed");
});

for (const drift of ["authority", "generation", "window"]) {
  test(`observation ${drift} preflight becomes exact refused_no_effect and never calls hardware`, (t) => {
    const f = fixture(t, `consume-${drift}`);
    const store = f.open();
    const precommit = precommitFor(f, `consume-${drift}`);
    const c = commitAttempt(store, precommit);
    const control = {};
    const { permit, provider } = redeemCommitted(
      store,
      precommit,
      c.committed,
      c.expected,
      control,
    );
    if (drift === "authority") control.authority = false;
    if (drift === "generation") {
      control.connectionGeneration = precommit.connection_generation + 1;
    }
    if (drift === "window") f.clock.set(precommit.grant_expires_at);

    let callbackCalls = 0;
    const report = provider.consumeBootstrapObservation(permit, () => {
      callbackCalls += 1;
      throw new Error("hardware callback must not run after failed preflight");
    });
    assert.equal(callbackCalls, 0);
    assert.equal(report.outcome, "refused_no_effect");
    for (const field of [
      "observation_ref",
      "observation_digest",
      "response_digest",
      "assurance_claims_digest",
      "invariant_witness_digest",
    ]) assert.equal(report[field], null);
    const terminal = store.readAttempt(precommit.attempt_ref);
    assert.equal(terminal.state, "refused_no_effect");
    assert.equal(terminal.terminal_reason_code, "preflight_refused");
    assert.deepEqual(terminal.provider_report, report);
    assert.equal(
      terminal.terminal_binding.dispatch_redemption_digest,
      terminal.redemption.dispatch_redemption_digest,
    );
  });
}

for (const failure of ["throw", "invalid", "promise"]) {
  test(`observation callback ${failure} becomes an exact sticky provider ambiguity`, (t) => {
    const f = fixture(t, `callback-${failure}`);
    const store = f.open();
    const precommit = precommitFor(f, `callback-${failure}`);
    const c = commitAttempt(store, precommit);
    const { permit, provider } = redeemCommitted(store, precommit, c.committed, c.expected);
    let callbackCalls = 0;
    const report = provider.consumeBootstrapObservation(permit, (redemption) => {
      callbackCalls += 1;
      if (failure === "throw") throw new Error("injected provider failure after source access");
      if (failure === "promise") return Promise.resolve(successReport(c.expected, redemption));
      return { outcome: "succeeded", dispatch_redemption_digest: digest("forged") };
    });
    assert.equal(callbackCalls, 1);
    assert.equal(report.outcome, "ambiguous");
    const terminal = store.readAttempt(precommit.attempt_ref);
    assert.equal(terminal.state, "ambiguous");
    assert.equal(terminal.recovery_disposition, "sticky_ambiguity");
    assert.equal(terminal.durable_ambiguity, null);
    assert.deepEqual(terminal.provider_report, report);
    assert.equal(
      terminal.terminal_reason_code,
      failure === "invalid" ? "provider_report_invalid" : "provider_callback_failed",
    );
    assert.equal(
      report.dispatch_redemption_digest,
      terminal.redemption.dispatch_redemption_digest,
    );
    for (const field of [
      "observation_ref",
      "observation_digest",
      "response_digest",
      "assurance_claims_digest",
      "invariant_witness_digest",
    ]) assert.equal(report[field], null);
  });
}

test("anchor commit response loss and CAS rejection recover only the exact durable tail without reminting", (t) => {
  const responseLost = fixture(t, "anchor-response-loss");
  const store = responseLost.open();
  const precommit = precommitFor(responseLost, "anchor-response-loss");
  const durable = precommitAttempt(store, precommit);
  responseLost.anchor.armAmbiguousCommit();
  assert.throws(
    () => store.commitDispatch({
      version: 1,
      attempt_ref: precommit.attempt_ref,
      expected_durable_attempt_binding_digest: durable.durable_attempt_binding_digest,
    }, custodyFor(precommit).projection),
    (error) => error.anchor_commit_outcome === "ambiguous",
  );
  const committed = store.readAttempt(precommit.attempt_ref);
  assert.equal(committed.state, "dispatch_committed");
  const replay = store.commitDispatch({
    version: 1,
    attempt_ref: precommit.attempt_ref,
    expected_durable_attempt_binding_digest: durable.durable_attempt_binding_digest,
  }, custodyFor(precommit).projection);
  assert.equal(replay.already_committed, true);
  assert.equal(replay.dispatch_credential, null);

  const rejected = fixture(t, "anchor-cas-reject");
  const rejectedStore = rejected.open();
  const rejectedPrecommit = precommitFor(rejected, "anchor-cas-reject");
  rejected.anchor.armReject();
  assert.throws(
    () => precommitAttempt(rejectedStore, rejectedPrecommit),
    (error) => error.anchor_commit_outcome === "ambiguous",
  );
  assert.equal(fs.readdirSync(path.join(rejected.root, "bootstrap-events")).length, 1);
  const recovered = rejectedStore.snapshot();
  assert.equal(recovered.generation, 1);
  assert.equal(recovered.attempts[0].attempt_ref, rejectedPrecommit.attempt_ref);
  assert.equal(rejected.anchor.state.generation, 1);
});

test("restart makes dispatch and redemption heads sticky ambiguous with exact nullable redemption", (t) => {
  const dispatched = fixture(t, "restart-dispatched");
  let store = dispatched.open();
  const precommit = precommitFor(dispatched, "restart-dispatched");
  const c = commitAttempt(store, precommit);
  const dispatchDigest = c.committed.dispatch.dispatch_record_digest;
  store.close();
  store = dispatched.open();
  const terminal = store.readAttempt(precommit.attempt_ref);
  assert.equal(terminal.state, "ambiguous");
  assert.equal(terminal.terminal_reason_code, "restart_in_flight");
  assert.equal(terminal.durable_ambiguity.dispatch_record_digest, dispatchDigest);
  assert.equal(terminal.durable_ambiguity.dispatch_redemption_digest, null);
  assert.throws(
    () => store.commitDispatch({
      version: 1,
      attempt_ref: precommit.attempt_ref,
      expected_durable_attempt_binding_digest: precommit.durable_attempt_binding_digest,
    }, custodyFor(precommit).projection),
    /live store/,
    "a custody projection issued by the closed store cannot authorize restart replay",
  );

  const redeemed = fixture(t, "restart-redeemed");
  store = redeemed.open();
  const redeemedPrecommit = precommitFor(redeemed, "restart-redeemed");
  const rc = commitAttempt(store, redeemedPrecommit);
  redeemCommitted(store, redeemedPrecommit, rc.committed, rc.expected);
  const redemptionDigest = store.readAttempt(redeemedPrecommit.attempt_ref)
    .redemption.dispatch_redemption_digest;
  store.close();
  store = redeemed.open();
  const redeemedTerminal = store.readAttempt(redeemedPrecommit.attempt_ref);
  assert.equal(redeemedTerminal.state, "ambiguous");
  assert.equal(
    redeemedTerminal.durable_ambiguity.dispatch_redemption_digest,
    redemptionDigest,
  );
  assert.equal(redeemedTerminal.provider_report, null);
});

test("terminal data survives restart while custody authority is never reminted or re-entered", (t) => {
  const f = fixture(t, "terminal-replay");
  let store = f.open();
  const precommit = precommitFor(f, "terminal-replay");
  const c = commitAttempt(store, precommit);
  const { permit, provider } = redeemCommitted(store, precommit, c.committed, c.expected);
  let calls = 0;
  const report = provider.consumeBootstrapObservation(permit, (redemption) => {
    calls += 1;
    return successReport(c.expected, redemption, "terminal-replay");
  });
  const terminalGeneration = store.snapshot().generation;
  assert.equal(calls, 1);
  assert.throws(
    () => provider.consumeBootstrapObservation(permit, () => { calls += 1; }),
    /not issued to this provider port/,
  );
  assert.equal(calls, 1);
  store.close();

  store = f.open();
  assert.equal(store.snapshot().generation, terminalGeneration);
  const terminal = store.readAttempt(precommit.attempt_ref);
  assert.equal(terminal.state, "succeeded");
  assert.deepEqual(terminal.provider_report, report);
  assert.throws(
    () => precommitAttempt(store, precommit),
    /live store/,
    "terminal data remains readable but closed-store custody cannot be rebound after restart",
  );
  assert.throws(
    () => store.markAmbiguous({
      version: 1,
      attempt_ref: precommit.attempt_ref,
      expected_attempt_digest: terminal.attempt_digest,
      reason_code: "late_reclassification",
    }),
    /requires an in-flight dispatch/,
  );
});

test("external anchor rollback, fork, and local truncation are detected from a hot store", (t) => {
  const rollback = fixture(t, "anchor-rollback");
  const rollbackStore = rollback.open();
  precommitAttempt(rollbackStore, precommitFor(rollback, "anchor-rollback"));
  const validAnchor = clone(rollback.anchor.state);
  rollback.anchor.state = null;
  assert.throws(() => rollbackStore.snapshot(), /rollback, truncation, or anchor fork/);
  rollback.anchor.state = { ...validAnchor, head_event_digest: digest("anchor-fork") };
  assert.throws(() => rollbackStore.snapshot(), /rollback, truncation, or anchor fork/);

  const truncated = fixture(t, "local-truncation");
  const truncatedStore = truncated.open();
  precommitAttempt(truncatedStore, precommitFor(truncated, "local-truncation"));
  fs.unlinkSync(eventPath(truncated));
  assert.throws(() => truncatedStore.snapshot(), /rollback, truncation, or anchor fork/);
});

for (const attack of ["tamper", "truncate", "symlink", "hardlink", "oversize"]) {
  test(`event ${attack} fails closed before projection replay`, (t) => {
    const f = fixture(t, `event-${attack}`);
    let store = f.open();
    precommitAttempt(store, precommitFor(f, `event-${attack}`));
    store.close();
    const candidate = eventPath(f);
    if (attack === "tamper") {
      const envelope = JSON.parse(fs.readFileSync(candidate, "utf8"));
      const ciphertext = Buffer.from(envelope.ciphertext, "base64");
      ciphertext[0] ^= 0x80;
      envelope.ciphertext = ciphertext.toString("base64");
      fs.writeFileSync(candidate, `${JSON.stringify(envelope)}\n`, { mode: 0o600 });
      fs.chmodSync(candidate, 0o600);
    } else if (attack === "truncate") {
      fs.truncateSync(candidate, 1);
    } else if (attack === "symlink") {
      fs.unlinkSync(candidate);
      fs.symlinkSync(path.join(f.root, "bootstrap-runtime.json"), candidate);
    } else if (attack === "hardlink") {
      fs.linkSync(candidate, path.join(f.root, "event-copy"));
    } else {
      fs.truncateSync(candidate, (1024 * 1024) + 1);
    }
    assert.throws(
      () => f.open(),
      /authenticate|authentic|JSON|single-link regular file|unsafe permissions or size/i,
    );
  });
}

test("root and event-directory swaps are detected by inode identity while the store is open", (t) => {
  const rootSwap = fixture(t, "root-swap");
  const rootStore = rootSwap.open();
  const movedRoot = `${rootSwap.root}.moved`;
  t.after(() => fs.rmSync(movedRoot, { recursive: true, force: true }));
  fs.renameSync(rootSwap.root, movedRoot);
  fs.mkdirSync(rootSwap.root, { mode: 0o700 });
  fs.mkdirSync(path.join(rootSwap.root, "bootstrap-events"), { mode: 0o700 });
  assert.throws(() => rootStore.snapshot(), /root identity changed/);

  const eventSwap = fixture(t, "event-root-swap");
  const eventStore = eventSwap.open();
  const events = path.join(eventSwap.root, "bootstrap-events");
  const movedEvents = `${events}.moved`;
  fs.renameSync(events, movedEvents);
  fs.mkdirSync(events, { mode: 0o700 });
  assert.throws(() => eventStore.snapshot(), /events directory identity changed/);

  const coldSwap = fixture(t, "cold-root-swap");
  let coldStore = coldSwap.open();
  precommitAttempt(coldStore, precommitFor(coldSwap, "cold-root-swap"));
  coldStore.close();
  const coldMovedRoot = `${coldSwap.root}.moved`;
  t.after(() => fs.rmSync(coldMovedRoot, { recursive: true, force: true }));
  fs.renameSync(coldSwap.root, coldMovedRoot);
  fs.mkdirSync(coldSwap.root, { mode: 0o700 });
  assert.throws(
    () => coldSwap.open(),
    /rollback, truncation, or anchor fork/,
    "external CAS state prevents a replaced local root from minting a fresh namespace",
  );
});

test("unsafe roots, metadata links, event permissions, and clock rollback fail closed", (t) => {
  const publicRoot = fixture(t, "public-root");
  fs.chmodSync(publicRoot.root, 0o755);
  assert.throws(() => publicRoot.open(), /must not permit group\/other access/);

  const metadataLink = fixture(t, "metadata-hardlink");
  let store = metadataLink.open();
  store.close();
  fs.linkSync(
    path.join(metadataLink.root, "bootstrap-runtime.json"),
    path.join(metadataLink.root, "metadata-copy"),
  );
  assert.throws(() => metadataLink.open(), /single-link regular file/);

  const eventPermissions = fixture(t, "event-permissions");
  store = eventPermissions.open();
  precommitAttempt(store, precommitFor(eventPermissions, "event-permissions"));
  store.close();
  fs.chmodSync(eventPath(eventPermissions), 0o644);
  assert.throws(() => eventPermissions.open(), /unsafe permissions or size/);

  const rollbackClock = fixture(t, "clock-rollback");
  store = rollbackClock.open();
  rollbackClock.clock.set("2026-07-18T00:09:59.999Z");
  assert.throws(
    () => precommitAttempt(store, precommitFor(rollbackClock, "clock-rollback")),
    /clock moved backwards/,
  );
  assert.equal(store.snapshot().generation, 0);
});

test("broker port is branded, frozen, least-authority, hook-bounded, and response-loss safe", (t) => {
  const f = fixture(t, "broker-port");
  const store = f.open();
  const hookCalls = [];
  const broker = createInstrumentBootstrapBrokerPort(store, {
    before_call(event) {
      assert.ok(Object.isFrozen(event));
      hookCalls.push(`before:${event.method}`);
    },
    after_call(event) {
      hookCalls.push(`after:${event.method}`);
    },
  });
  assert.equal(assertInstrumentBootstrapBrokerPort(broker), broker);
  assert.ok(Object.isFrozen(broker));
  assert.deepEqual(Object.keys(broker).sort(), [
    "commitDispatch",
    "markAmbiguous",
    "precommitAttempt",
    "readAttempt",
    "snapshot",
  ]);
  for (const forbidden of ["close", "redeem", "consumeBootstrapObservation"]) {
    assert.equal(broker[forbidden], undefined);
  }
  assert.throws(() => assertInstrumentBootstrapBrokerPort({ ...broker }), /must attenuate/);
  assert.throws(() => assertInstrumentBootstrapProviderRedemptionPort(broker), /provider port/);

  const precommit = precommitFor(f, "broker-port");
  const durable = broker.precommitAttempt(precommit, custodyFor(precommit).projection);
  assert.equal(broker.readAttempt(precommit.attempt_ref).state, "precommitted");
  assert.equal(broker.snapshot().generation, 1);
  assert.deepEqual(hookCalls, [
    "before:precommitAttempt",
    "after:precommitAttempt",
    "before:readAttempt",
    "after:readAttempt",
    "before:snapshot",
    "after:snapshot",
  ]);

  const rejectingHook = createInstrumentBootstrapBrokerPort(store, {
    before_call: () => "replacement",
  });
  assert.throws(() => rejectingHook.snapshot(), /hook must return undefined/);

  let loseCommitResponse = true;
  const lossy = createInstrumentBootstrapBrokerPort(store, {
    after_call({ method }) {
      if (method === "commitDispatch" && loseCommitResponse) {
        loseCommitResponse = false;
        throw new Error("injected broker commit response loss");
      }
    },
  });
  const commitRequest = {
    version: 1,
    attempt_ref: precommit.attempt_ref,
    expected_durable_attempt_binding_digest: durable.durable_attempt_binding_digest,
  };
  assert.throws(
    () => lossy.commitDispatch(commitRequest, custodyFor(precommit).projection),
    /commit response loss/,
  );
  assert.equal(store.readAttempt(precommit.attempt_ref).state, "dispatch_committed");
  const replay = lossy.commitDispatch(commitRequest, custodyFor(precommit).projection);
  assert.equal(replay.already_committed, true);
  assert.equal(replay.dispatch_credential, null);
  const ambiguous = lossy.markAmbiguous({
    version: 1,
    attempt_ref: precommit.attempt_ref,
    expected_attempt_digest: replay.attempt.attempt_digest,
    reason_code: "broker_response_lost",
  });
  assert.equal(ambiguous.state, "ambiguous");
  assert.equal(ambiguous.durable_ambiguity.dispatch_redemption_digest, null);
});
