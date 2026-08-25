"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const {
  createInstrumentBootstrapBroker,
} = require("../lib/bootstrap-broker.js");
const {
  PROVIDER_METHODS,
  buildNormalizedOperationRegistry,
  defineProviderDescriptor,
} = require("../lib/provider-contract.js");
const {
  createDurableInstrumentBootstrapStore,
  createInstrumentBootstrapBrokerCustodyBinding,
  createInstrumentBootstrapBrokerPort,
  createInstrumentBootstrapProviderRedemptionPort,
} = require("../../../mcp/domains/physical/instrument-bootstrap-store.js");
const {
  PHYSICAL_BOOTSTRAP_GRANT_DOMAIN,
  PHYSICAL_BOOTSTRAP_GRANT_KEY_USAGE,
  assertVerifiedPhysicalBootstrapGrant,
  createPhysicalBootstrapGrantVerifier,
  normalizeMcpPhysicalExecutionRequest,
  physicalBootstrapGrantSignatureInputDigest,
  projectVerifiedPhysicalBootstrapGrant,
} = require("../../../mcp/domains/physical/physical-authority.js");
const {
  normalizePhysicalScopeNucleusAxis,
} = require("../../../mcp/core/governance/index.js");
const {
  buildEffectTemplateRegistry,
} = require("../../../mcp/core/requested-effects.js");
const {
  hashCanonicalJson,
} = require("../../../mcp/core/verification/verification-contracts.js");

const BOOTSTRAP_OPERATIONS = Object.freeze([
  "instrument.inventory",
  "instrument.capabilities",
  "instrument.health",
]);

function digest(label) {
  return hashCanonicalJson({ bootstrap_broker_fixture: label });
}

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

function createRegistries(abiVersion = 3, capabilityOverrides = {}) {
  const effectRegistry = buildEffectTemplateRegistry([{
    version: 1,
    template_id: "instrument.observe.usb.v1",
    subject_kind: "instrument",
    action: "observe",
    channel: "usb",
    persistence: "none",
    bounds: {},
  }, {
    version: 1,
    template_id: "instrument.configure.usb.v1",
    subject_kind: "instrument",
    action: "configure",
    channel: "usb",
    persistence: "ephemeral",
    bounds: {},
  }]);
  const operationRegistry = buildNormalizedOperationRegistry(
    BOOTSTRAP_OPERATIONS.map((operationId) => ({
      version: 1,
      operation_id: operationId,
      semantic_version: 1,
      parameters: {},
      public_summary_codes: [
        "operation_failed",
        "operation_inconclusive",
        "operation_refused",
        "operation_stopped",
        "operation_succeeded",
      ],
    })),
  );
  const observed = effectRegistry.get("instrument.observe.usb.v1");
  const capabilities = BOOTSTRAP_OPERATIONS.map((operationId) => ({
    capability_id: `fixture.${operationId.split(".").at(-1)}`,
    operation_id: operationId,
    operation_digest: operationRegistry.get(operationId).operation_digest,
    worst_case_effects: [{
      template_id: observed.template_id,
      template_digest: observed.template_digest,
      subject_kind: observed.subject_kind,
      action: observed.action,
      channel: observed.channel,
      persistence: observed.persistence,
    }],
    idempotency: "read_only_idempotent",
    retry_policy: "new_attempt_after_confirmed_no_effect",
    stop_semantics: "not_applicable",
    restore_policy: "not_required",
    ...(capabilityOverrides[operationId] || {}),
  }));
  const descriptor = defineProviderDescriptor({
    version: 1,
    abi_version: abiVersion,
    provider_id: "bootstrap_fixture",
    provider_version: "1.0.0",
    implementation_digest: digest(`provider-implementation-v${abiVersion}`),
    operation_registry_digest: operationRegistry.registry_digest,
    capabilities,
  }, operationRegistry, effectRegistry);
  return { descriptor, effectRegistry, operationRegistry };
}

function physicalAxis() {
  return normalizePhysicalScopeNucleusAxis({
    version: 1,
    physical_enabled: true,
    policy_version: 1,
    policy_id: "bootstrap-broker-test-policy-v1",
    policy_digest: digest("physical-policy"),
    projection_version: 1,
    projection_digest: digest("physical-projection"),
    provenance_digest: digest("physical-provenance"),
    compatibility_digest: digest("physical-compatibility"),
    transition_receipt_registry_digest: digest("physical-transition-registry"),
    authority_epoch: 7,
    revocation_generation: 2,
  });
}

function replayReservation(claim, now, generation, previousReceiptDigest) {
  const receipt = {
    version: 1,
    reservation_ref: `bootstrap-grant-replay-reservation:${hashCanonicalJson(claim).slice(0, 40)}`,
    replay_claim: claim,
    replay_claim_digest: hashCanonicalJson(claim),
    generation,
    previous_receipt_digest: previousReceiptDigest,
    reserved_at: now,
    fsynced_at: now,
  };
  return {
    version: 1,
    disposition: "created",
    reservation_receipt: { ...receipt, receipt_digest: hashCanonicalJson(receipt) },
  };
}

function makeEnvironment(t, options = {}) {
  const { descriptor, effectRegistry, operationRegistry } = createRegistries();
  const identities = Object.freeze({
    session_nucleus_hash: digest(`session-nucleus:${options.label || "default"}`),
    execution_principal_id: "principal:bootstrap-broker-worker-1",
    instrument_ref: "instrument:bootstrap-reader-1",
    enrollment_candidate_ref: "enrollment-candidate:bootstrap-reader-1",
    connection_ref: "instrument-connection:bootstrap-reader-1",
    provider_binary_digest: digest("provider-binary"),
    transport_digest: digest("provider-transport"),
    bootstrap_manifest_digest: digest("bootstrap-manifest"),
    bootstrap_invariants_digest: digest("bootstrap-invariants"),
  });
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "bob-bootstrap-broker-"));
  fs.chmodSync(root, 0o700);
  const anchor = new MemoryStateAnchor();
  let storeNow = Date.parse("2026-07-18T00:00:20.000Z");
  const store = createDurableInstrumentBootstrapStore({
    root,
    runtimeId: `physical-runtime:v1:${digest(options.label || "default").slice(0, 32)}`,
    sessionNucleusHash: identities.session_nucleus_hash,
    masterKey: crypto.createHash("sha256").update(`broker-key:${options.label || "default"}`).digest(),
    stateAnchor: anchor,
    now: () => new Date(storeNow++),
  });
  const controls = {
    after_precommit: null,
    lose_precommit_ack: false,
    lose_commit_ack: false,
    connection_generation: 1,
    connected: true,
    describe_mode: "success",
    provider_mode: "success",
    release_deferred: null,
  };
  const brokerPort = createInstrumentBootstrapBrokerPort(store, {
    after_call({ method }) {
      if (method === "precommitAttempt" && controls.after_precommit) {
        controls.after_precommit();
      }
      if (method === "precommitAttempt" && controls.lose_precommit_ack) {
        controls.lose_precommit_ack = false;
        throw new Error("injected precommit acknowledgement loss");
      }
      if (method === "commitDispatch" && controls.lose_commit_ack) {
        controls.lose_commit_ack = false;
        throw new Error("injected dispatch commit acknowledgement loss");
      }
    },
  });
  const keyPair = crypto.generateKeyPairSync("ed25519");
  const issuerPublicKeyDigest = crypto.createHash("sha256").update(
    keyPair.publicKey.export({ type: "spki", format: "der" }),
  ).digest("hex");
  let trustedNow = "2026-07-18T00:00:10.000Z";
  let grantSequence = 0;
  let priorReplayReceiptDigest = null;
  const authorities = new Map();
  const grantsBySignedDigest = new Map();
  const verifier = createPhysicalBootstrapGrantVerifier({
    verifier_id: `bootstrap-broker-verifier-${digest(options.label || "default").slice(0, 12)}`,
    trusted_now: () => trustedNow,
    resolve_current_authority(query) {
      const entry = authorities.get(query.execution_request_digest);
      if (!entry) throw new Error("fixture authority is unavailable");
      return entry.authority;
    },
    verify_ed25519(verification) {
      return crypto.verify(
        null,
        Buffer.from(verification.signature_input_digest, "hex"),
        keyPair.publicKey,
        Buffer.from(verification.signature, "base64url"),
      );
    },
    reserve_replay(claim) {
      const reservation = replayReservation(
        claim,
        trustedNow,
        grantSequence,
        priorReplayReceiptDigest,
      );
      priorReplayReceiptDigest = reservation.reservation_receipt.receipt_digest;
      return reservation;
    },
  });

  function readConnection() {
    return {
      connection_ref: identities.connection_ref,
      connection_generation: controls.connection_generation,
      connected: controls.connected,
    };
  }

  const custodyBinding = createInstrumentBootstrapBrokerCustodyBinding(brokerPort, {
    custody_authority: Object.freeze(Object.create(null)),
    read_connection_generation: readConnection,
  });

  const providerPort = createInstrumentBootstrapProviderRedemptionPort(store, {
    provider_id: descriptor.provider_id,
    provider_descriptor_digest: descriptor.descriptor_digest,
    provider_binary_digest: identities.provider_binary_digest,
    transport_digest: identities.transport_digest,
    bootstrap_manifest_digest: identities.bootstrap_manifest_digest,
    bootstrap_invariants_digest: identities.bootstrap_invariants_digest,
    execution_principal_id: identities.execution_principal_id,
    instrument_ref: identities.instrument_ref,
    enrollment_candidate_ref: identities.enrollment_candidate_ref,
    custody_binding: custodyBinding,
    revalidateBootstrapAuthority(expected) {
      const entry = grantsBySignedDigest.get(expected.signed_grant_digest);
      if (!entry) return false;
      assertVerifiedPhysicalBootstrapGrant(entry.grant, verifier, entry.assert_bindings);
      return true;
    },
  });

  const counts = Object.fromEntries(PROVIDER_METHODS.map((method) => [method, 0]));
  let reportSequence = 0;
  function providerReport(request, redemption, outcome = "succeeded") {
    reportSequence += 1;
    const suffix = `${request.operation_id.split(".").at(-1)}-${reportSequence}`;
    const succeeded = outcome === "succeeded";
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
      outcome,
      observation_ref: succeeded ? `bootstrap-observation:${suffix}` : null,
      observation_digest: succeeded ? digest(`observation:${suffix}`) : null,
      receipt_ref: `bootstrap-receipt:${suffix}`,
      receipt_digest: digest(`receipt:${suffix}`),
      response_digest: succeeded ? digest(`response:${suffix}`) : null,
      observed_at: "2026-07-18T00:00:30.000Z",
      assurance_claims_digest: succeeded ? digest(`assurance:${suffix}`) : null,
      invariant_witness_digest: succeeded ? digest(`witness:${suffix}`) : null,
    };
  }

  function persistProviderResult(request, outcome = "succeeded") {
    const redemption = providerPort.redeem(request.dispatch_credential, request);
    return providerPort.consumeBootstrapObservation(redemption.permit, (projection) => (
      providerReport(request, projection, outcome)
    ));
  }

  function invokeBootstrap(request) {
    switch (controls.provider_mode) {
      case "success": return persistProviderResult(request);
      case "refused": return persistProviderResult(request, "refused_no_effect");
      case "reported_ambiguous": return persistProviderResult(request, "ambiguous");
      case "error_before_redeem": throw new Error("injected provider failure before redemption");
      case "error_after_redeem":
        providerPort.redeem(request.dispatch_credential, request);
        throw new Error("injected provider failure after redemption");
      case "callback_failure": {
        const redemption = providerPort.redeem(request.dispatch_credential, request);
        return providerPort.consumeBootstrapObservation(redemption.permit, () => {
          throw new Error("injected observation callback failure");
        });
      }
      case "credential_clone":
        providerPort.redeem(Object.freeze({ ...request.dispatch_credential }), request);
        throw new Error("cloned credential unexpectedly redeemed");
      case "never": return new Promise(() => {});
      case "response_loss":
        persistProviderResult(request);
        return new Promise(() => {});
      case "return_without_durable":
        return providerReport(request, {
          dispatch_redemption_digest: digest("untrusted-provider-redemption"),
        });
      case "deferred":
        return new Promise((resolve, reject) => {
          controls.release_deferred = () => {
            try { resolve(persistProviderResult(request)); } catch (error) { reject(error); }
          };
        });
      default: throw new Error(`unknown provider fixture mode ${controls.provider_mode}`);
    }
  }

  const provider = {};
  for (const method of PROVIDER_METHODS) {
    provider[method] = (request) => {
      counts[method] += 1;
      if (method === "describe") {
        if (controls.describe_mode === "never") return new Promise(() => {});
        if (controls.describe_mode === "throw") throw new Error("injected describe failure");
        return clone(descriptor);
      }
      if (BOOTSTRAP_OPERATIONS.includes(`instrument.${method}`)) return invokeBootstrap(request);
      throw new Error(`active provider method ${method} must not be invoked during bootstrap`);
    };
  }
  Object.freeze(provider);

  const broker = createInstrumentBootstrapBroker({
    operation_registry: operationRegistry,
    effect_registry: effectRegistry,
    bootstrap_store: brokerPort,
    grant_verifier: verifier,
    execution_principal_id: identities.execution_principal_id,
    providers: [{
      provider_projection: descriptor,
      provider,
      provider_binary_digest: identities.provider_binary_digest,
      transport_digest: identities.transport_digest,
      bootstrap_manifest_digest: identities.bootstrap_manifest_digest,
      bootstrap_invariants_digest: identities.bootstrap_invariants_digest,
      instruments: [{
        instrument_ref: identities.instrument_ref,
        enrollment_candidate_ref: identities.enrollment_candidate_ref,
        custody_binding: custodyBinding,
      }],
    }],
    provider_call_timeout_ms: options.timeout_ms || 50,
  });

  function makeGrant(operationId = "instrument.inventory", overrides = {}) {
    grantSequence += 1;
    const operation = operationRegistry.get(operationId);
    const requestedTemplate = effectRegistry.get("instrument.observe.usb.v1");
    const request = normalizeMcpPhysicalExecutionRequest({
      version: 1,
      grant_kind: "bootstrap",
      session_id: "session-bootstrap-broker-1",
      session_nucleus_hash: identities.session_nucleus_hash,
      caller_role_id: "orchestrator",
      requester_principal_id: "principal:bootstrap-requester-1",
      ipc_peer_principal_id: "principal:bootstrap-ipc-peer-1",
      execution_principal_id: overrides.execution_principal_id || identities.execution_principal_id,
      instrument_ref: overrides.instrument_ref || identities.instrument_ref,
      operation_id: operationId,
      parameter_digest: hashCanonicalJson({}),
      authority_epoch: 7,
      revocation_generation: 2,
      nonce: `bootstrap-broker-${grantSequence}-nonce`,
      sequence: grantSequence,
      not_before: "2026-07-18T00:00:00.000Z",
      expires_at: "2026-07-18T01:00:00.000Z",
      requested_effects: [{
        version: 1,
        template_id: requestedTemplate.template_id,
        template_digest: requestedTemplate.template_digest,
        subject_ref: overrides.instrument_ref || identities.instrument_ref,
        subject_kind: requestedTemplate.subject_kind,
        action: requestedTemplate.action,
        channel: requestedTemplate.channel,
        persistence: requestedTemplate.persistence,
        bounds: {},
      }],
      enrollment_candidate_ref: overrides.enrollment_candidate_ref
        || identities.enrollment_candidate_ref,
      bootstrap_manifest_digest: overrides.bootstrap_manifest_digest
        || identities.bootstrap_manifest_digest,
      provider_binary_digest: overrides.provider_binary_digest
        || identities.provider_binary_digest,
      transport_digest: overrides.transport_digest || identities.transport_digest,
      rf_state: "off",
    }, effectRegistry);
    const providerId = overrides.provider_id || descriptor.provider_id;
    const providerDescriptorDigest = overrides.provider_descriptor_digest
      || descriptor.descriptor_digest;
    const operationDigest = overrides.operation_digest || operation.operation_digest;
    const bootstrapInvariantsDigest = overrides.bootstrap_invariants_digest
      || identities.bootstrap_invariants_digest;
    const axis = physicalAxis();
    const authority = {
      version: 1,
      session_id: request.session_id,
      session_nucleus_hash: request.session_nucleus_hash,
      execution_request_digest: request.execution_request_digest,
      physical_scope_axis: axis,
      caller_role_id: request.caller_role_id,
      requester_principal_id: request.requester_principal_id,
      ipc_peer_principal_id: request.ipc_peer_principal_id,
      execution_principal_id: request.execution_principal_id,
      provider_id: providerId,
      provider_descriptor_digest: providerDescriptorDigest,
      instrument_ref: request.instrument_ref,
      enrollment_candidate_ref: request.enrollment_candidate_ref,
      bootstrap_manifest_digest: request.bootstrap_manifest_digest,
      provider_binary_digest: request.provider_binary_digest,
      transport_digest: request.transport_digest,
      operation_id: request.operation_id,
      operation_digest: operationDigest,
      parameter_digest: request.parameter_digest,
      requested_effects_digest: request.requested_effects_digest,
      bootstrap_invariants_digest: bootstrapInvariantsDigest,
      authority_decision: "allow",
      authority_reason: "exact_allow",
      authority_resolution_digest: digest(`authority-resolution:${grantSequence}`),
      trust_root_id: "trust-root:bootstrap-broker-test",
      trust_root_epoch: 6,
      trust_registry_digest: digest("trust-registry"),
      trust_root_trusted: true,
      trust_root_revoked: false,
      issuer_principal_id: "principal:bootstrap-broker-authority",
      issuer_key_id: "signer-key:bootstrap-broker-authority",
      issuer_epoch: 3,
      issuer_public_key_digest: issuerPublicKeyDigest,
      key_usage: PHYSICAL_BOOTSTRAP_GRANT_KEY_USAGE,
      issuer_trusted: true,
      issuer_revoked: false,
    };
    authorities.set(request.execution_request_digest, { authority });
    const payload = {
      version: 1,
      grant_kind: "bootstrap",
      grant_ref: `physical-grant:bootstrap-broker-${grantSequence}`,
      session_id: request.session_id,
      session_nucleus_hash: request.session_nucleus_hash,
      physical_scope_axis_digest: axis.axis_digest,
      physical_scope_policy_id: axis.policy_id,
      physical_scope_policy_digest: axis.policy_digest,
      physical_scope_projection_digest: axis.projection_digest,
      authority_epoch: request.authority_epoch,
      revocation_generation: request.revocation_generation,
      execution_request_digest: request.execution_request_digest,
      request_nonce: request.nonce,
      request_sequence: request.sequence,
      caller_role_id: request.caller_role_id,
      requester_principal_id: request.requester_principal_id,
      ipc_peer_principal_id: request.ipc_peer_principal_id,
      execution_principal_id: request.execution_principal_id,
      provider_id: providerId,
      provider_descriptor_digest: providerDescriptorDigest,
      instrument_ref: request.instrument_ref,
      enrollment_candidate_ref: request.enrollment_candidate_ref,
      bootstrap_manifest_digest: request.bootstrap_manifest_digest,
      provider_binary_digest: request.provider_binary_digest,
      transport_digest: request.transport_digest,
      operation_id: request.operation_id,
      operation_digest: operationDigest,
      parameter_digest: request.parameter_digest,
      requested_effects_digest: request.requested_effects_digest,
      bootstrap_invariants_digest: bootstrapInvariantsDigest,
      rf_state: request.rf_state,
      authority_decision: authority.authority_decision,
      authority_reason: authority.authority_reason,
      authority_resolution_digest: authority.authority_resolution_digest,
      not_before: request.not_before,
      expires_at: request.expires_at,
    };
    const authentication = {
      version: 1,
      method: "ed25519",
      key_usage: PHYSICAL_BOOTSTRAP_GRANT_KEY_USAGE,
      trust_root_id: authority.trust_root_id,
      trust_root_epoch: authority.trust_root_epoch,
      trust_registry_digest: authority.trust_registry_digest,
      issuer_principal_id: authority.issuer_principal_id,
      issuer_key_id: authority.issuer_key_id,
      issuer_epoch: authority.issuer_epoch,
      issuer_public_key_digest: authority.issuer_public_key_digest,
      signed_at: "2026-07-18T00:00:05.000Z",
      signed_payload_digest: hashCanonicalJson(payload),
    };
    const signatureInputDigest = physicalBootstrapGrantSignatureInputDigest(payload, authentication);
    const envelope = {
      version: 1,
      kind: "physical_bootstrap_grant",
      domain: PHYSICAL_BOOTSTRAP_GRANT_DOMAIN,
      payload,
      authentication: {
        ...authentication,
        signature: crypto.sign(
          null,
          Buffer.from(signatureInputDigest, "hex"),
          keyPair.privateKey,
        ).toString("base64url"),
      },
    };
    const projectionBindings = {
      execution_request: request,
      effect_registry: effectRegistry,
      provider_id: providerId,
      provider_descriptor_digest: providerDescriptorDigest,
      operation_digest: operationDigest,
      bootstrap_invariants_digest: bootstrapInvariantsDigest,
    };
    const grant = projectVerifiedPhysicalBootstrapGrant(envelope, verifier, projectionBindings);
    const assertBindings = Object.freeze({
      execution_request_digest: request.execution_request_digest,
      provider_id: providerId,
      provider_descriptor_digest: providerDescriptorDigest,
      bootstrap_manifest_digest: request.bootstrap_manifest_digest,
      provider_binary_digest: request.provider_binary_digest,
      transport_digest: request.transport_digest,
      operation_id: request.operation_id,
      operation_digest: operationDigest,
      bootstrap_invariants_digest: bootstrapInvariantsDigest,
    });
    const entry = { assert_bindings: assertBindings, authority, grant, request };
    grantsBySignedDigest.set(grant.signed_grant_digest, entry);
    return entry;
  }

  t.after(() => {
    broker.close();
    store.close();
    fs.rmSync(root, { recursive: true, force: true });
  });
  return {
    broker,
    brokerPort,
    controls,
    counts,
    custodyBinding,
    descriptor,
    effectRegistry,
    identities,
    makeGrant,
    operationRegistry,
    provider,
    readConnection,
    setTrustedNow(value) { trustedNow = value; },
    store,
    verifier,
  };
}

function executeRequest(env, entry) {
  return {
    grant_projection: entry.grant,
    provider_projection: env.descriptor,
  };
}

function brokerInput(env, descriptor = env.descriptor, provider = env.provider) {
  return {
    operation_registry: env.operationRegistry,
    effect_registry: env.effectRegistry,
    bootstrap_store: env.brokerPort,
    grant_verifier: env.verifier,
    execution_principal_id: env.identities.execution_principal_id,
    providers: [{
      provider_projection: descriptor,
      provider,
      provider_binary_digest: env.identities.provider_binary_digest,
      transport_digest: env.identities.transport_digest,
      bootstrap_manifest_digest: env.identities.bootstrap_manifest_digest,
      bootstrap_invariants_digest: env.identities.bootstrap_invariants_digest,
      instruments: [{
        instrument_ref: env.identities.instrument_ref,
        enrollment_candidate_ref: env.identities.enrollment_candidate_ref,
        custody_binding: env.custodyBinding,
      }],
    }],
    provider_call_timeout_ms: 50,
  };
}

async function waitUntil(predicate) {
  for (let count = 0; count < 100; count += 1) {
    if (predicate()) return;
    await new Promise((resolve) => setImmediate(resolve));
  }
  throw new Error("fixture condition was not reached");
}

test("dispatches exactly the three ABI-v3 read-only bootstrap methods", async (t) => {
  const env = makeEnvironment(t, { label: "three-methods" });
  for (const operationId of BOOTSTRAP_OPERATIONS) {
    const result = await env.broker.executeOnce(executeRequest(env, env.makeGrant(operationId)));
    assert.equal(result.state, "succeeded");
    assert.equal(result.terminal_kind, "provider_report");
    assert.equal(result.provider_report.operation_id, operationId);
    assert.doesNotMatch(JSON.stringify(result), /dispatch_credential|credential_ref/);
  }
  assert.equal(env.counts.describe, 1);
  assert.equal(env.counts.inventory, 1);
  assert.equal(env.counts.capabilities, 1);
  assert.equal(env.counts.health, 1);
  for (const method of PROVIDER_METHODS) {
    if (!["describe", "inventory", "capabilities", "health"].includes(method)) {
      assert.equal(env.counts[method], 0);
    }
  }
  assert.equal(env.store.snapshot().attempts.length, 3);
});

test("concurrent and later duplicate execution invokes the provider exactly once", async (t) => {
  const env = makeEnvironment(t, { label: "duplicate" });
  const entry = env.makeGrant();
  env.controls.provider_mode = "deferred";
  const first = env.broker.executeOnce(executeRequest(env, entry));
  const duplicate = env.broker.executeOnce(executeRequest(env, entry));
  await waitUntil(() => typeof env.controls.release_deferred === "function");
  env.controls.release_deferred();
  const [left, right] = await Promise.all([first, duplicate]);
  assert.deepEqual(left, right);
  assert.equal(env.counts.inventory, 1);
  const replay = await env.broker.executeOnce(executeRequest(env, entry));
  assert.deepEqual(replay, left);
  assert.equal(env.counts.inventory, 1);
  assert.equal(env.counts.describe, 1);
});

test("registration rejects ABI-v2, effectful, and ambiguous bootstrap declarations before provider access", (t) => {
  const env = makeEnvironment(t, { label: "registration-rejection" });
  let providerReads = 0;
  const untouchedProvider = new Proxy({}, {
    get() {
      providerReads += 1;
      return () => { throw new Error("rejected provider must not be invoked"); };
    },
  });
  const v2 = createRegistries(2).descriptor;
  assert.throws(
    () => createInstrumentBootstrapBroker(brokerInput(env, v2, untouchedProvider)),
    /require provider ABI 3/,
  );
  assert.equal(providerReads, 0);

  const effectfulDeclaration = clone(env.descriptor);
  delete effectfulDeclaration.capabilities_digest;
  delete effectfulDeclaration.descriptor_digest;
  const configure = env.effectRegistry.get("instrument.configure.usb.v1");
  const inventory = effectfulDeclaration.capabilities.find(
    (capability) => capability.operation_id === "instrument.inventory",
  );
  inventory.worst_case_effects = [{
    template_id: configure.template_id,
    template_digest: configure.template_digest,
    subject_kind: configure.subject_kind,
    action: configure.action,
    channel: configure.channel,
    persistence: configure.persistence,
  }];
  inventory.idempotency = "attempt_idempotent";
  inventory.retry_policy = "never";
  inventory.stop_semantics = "bounded";
  const effectful = defineProviderDescriptor(
    effectfulDeclaration,
    env.operationRegistry,
    env.effectRegistry,
  );
  assert.throws(
    () => createInstrumentBootstrapBroker(brokerInput(env, effectful, untouchedProvider)),
    /not a local read-only bootstrap observation/,
  );
  assert.equal(providerReads, 0);

  const duplicateDeclaration = clone(env.descriptor);
  delete duplicateDeclaration.capabilities_digest;
  delete duplicateDeclaration.descriptor_digest;
  duplicateDeclaration.capabilities.push({
    ...clone(duplicateDeclaration.capabilities.find(
      (capability) => capability.operation_id === "instrument.inventory",
    )),
    capability_id: "fixture.inventory.duplicate",
  });
  const duplicate = defineProviderDescriptor(
    duplicateDeclaration,
    env.operationRegistry,
    env.effectRegistry,
  );
  assert.throws(
    () => createInstrumentBootstrapBroker(brokerInput(env, duplicate, untouchedProvider)),
    /more than one instrument\.inventory capability/,
  );
  assert.equal(providerReads, 0);

  const clonedCustodyInput = brokerInput(env);
  clonedCustodyInput.providers[0].instruments[0].custody_binding = Object.freeze({
    ...env.custodyBinding,
  });
  assert.throws(
    () => createInstrumentBootstrapBroker(clonedCustodyInput),
    /private store-issued capability/,
  );

  const other = makeEnvironment(t, { label: "registration-cross-store-custody" });
  const crossStoreInput = brokerInput(env);
  crossStoreInput.providers[0].instruments[0].custody_binding = other.custodyBinding;
  assert.throws(
    () => createInstrumentBootstrapBroker(crossStoreInput),
    /another broker store/,
  );
});

test("exact projection identity, inert grant fields, and every registration binding fail closed", async (t) => {
  const env = makeEnvironment(t, { label: "projection-binding" });
  const valid = env.makeGrant();
  await assert.rejects(
    env.broker.executeOnce({
      grant_projection: valid.grant,
      provider_projection: Object.freeze(clone(env.descriptor)),
    }),
    /not registered by exact identity/,
  );
  await assert.rejects(
    env.broker.executeOnce({
      grant_projection: Object.freeze(clone(valid.grant)),
      provider_projection: env.descriptor,
    }),
    /revalidation failed/,
  );

  let accessorReads = 0;
  const accessorGrant = { ...valid.grant };
  Object.defineProperty(accessorGrant, "instrument_ref", {
    enumerable: true,
    get() {
      accessorReads += 1;
      return env.identities.instrument_ref;
    },
  });
  Object.freeze(accessorGrant);
  await assert.rejects(
    env.broker.executeOnce({
      grant_projection: accessorGrant,
      provider_projection: env.descriptor,
    }),
    /instrument_ref must be an enumerable data field/,
  );
  assert.equal(accessorReads, 0);

  let proxyTraps = 0;
  const proxyGrant = new Proxy(valid.grant, {
    get() { proxyTraps += 1; throw new Error("grant proxy get trap ran"); },
    getPrototypeOf() { proxyTraps += 1; throw new Error("grant proxy prototype trap ran"); },
    ownKeys() { proxyTraps += 1; throw new Error("grant proxy ownKeys trap ran"); },
  });
  await assert.rejects(
    env.broker.executeOnce({
      grant_projection: proxyGrant,
      provider_projection: env.descriptor,
    }),
    /frozen plain object/,
  );
  assert.equal(proxyTraps, 0);

  const drifted = [
    env.makeGrant("instrument.inventory", { provider_binary_digest: digest("other-binary") }),
    env.makeGrant("instrument.inventory", {
      provider_descriptor_digest: digest("other-provider-descriptor"),
    }),
    env.makeGrant("instrument.inventory", {
      execution_principal_id: "principal:other-bootstrap-worker",
    }),
    env.makeGrant("instrument.inventory", {
      instrument_ref: "instrument:other-bootstrap-reader",
    }),
    env.makeGrant("instrument.inventory", {
      enrollment_candidate_ref: "enrollment-candidate:other-bootstrap-reader",
    }),
    env.makeGrant("instrument.inventory", { transport_digest: digest("other-transport") }),
    env.makeGrant("instrument.inventory", {
      bootstrap_manifest_digest: digest("other-bootstrap-manifest"),
    }),
    env.makeGrant("instrument.inventory", {
      bootstrap_invariants_digest: digest("other-bootstrap-invariants"),
    }),
  ];
  for (const entry of drifted) {
    await assert.rejects(env.broker.executeOnce(executeRequest(env, entry)));
  }
  assert.equal(env.counts.describe, 0);
  assert.equal(env.counts.inventory, 0);
  assert.equal(env.store.snapshot().attempts.length, 0);
});

test("revoked and expired grants are rejected before store or provider invocation", async (t) => {
  await t.test("revocation", async (subtest) => {
    const env = makeEnvironment(subtest, { label: "revoked" });
    const entry = env.makeGrant();
    entry.authority.issuer_revoked = true;
    await assert.rejects(
      env.broker.executeOnce(executeRequest(env, entry)),
      /revalidation failed/,
    );
    assert.equal(env.counts.describe, 0);
    assert.equal(env.store.snapshot().attempts.length, 0);
  });
  await t.test("window expiry", async (subtest) => {
    const env = makeEnvironment(subtest, { label: "expired" });
    const entry = env.makeGrant();
    env.setTrustedNow("2026-07-18T01:00:00.000Z");
    await assert.rejects(
      env.broker.executeOnce(executeRequest(env, entry)),
      /revalidation failed/,
    );
    assert.equal(env.counts.describe, 0);
    assert.equal(env.store.snapshot().attempts.length, 0);
  });
});

test("a broker restart fails closed when durable terminal custody is no longer connected", async (t) => {
  const env = makeEnvironment(t, { label: "terminal-restart" });
  const entry = env.makeGrant();
  const terminal = await env.broker.executeOnce(executeRequest(env, entry));
  assert.equal(terminal.state, "succeeded");
  assert.equal(env.counts.describe, 1);
  assert.equal(env.counts.inventory, 1);
  env.controls.connected = false;
  const restarted = createInstrumentBootstrapBroker(brokerInput(env));
  t.after(() => restarted.close());
  const replay = await restarted.executeOnce(executeRequest(env, entry));
  assert.equal(replay.state, "succeeded");
  assert.equal(replay.outcome, "unavailable");
  assert.equal(replay.reason_code, "custody_revalidation_failed");
  assert.equal(replay.custody_binding_digest, terminal.custody_binding_digest);
  assert.equal(env.counts.describe, 1);
  assert.equal(env.counts.inventory, 1);
});

test("precommit acknowledgement loss recovers exact lineage without duplicate dispatch", async (t) => {
  const env = makeEnvironment(t, { label: "precommit-ack-loss" });
  const entry = env.makeGrant();
  env.controls.lose_precommit_ack = true;
  const result = await env.broker.executeOnce(executeRequest(env, entry));
  assert.equal(result.state, "succeeded");
  assert.equal(env.counts.inventory, 1);
  assert.equal(env.store.snapshot().attempts.length, 1);
});

test("pre-dispatch generation and authority drift leave a precommit and invoke no bootstrap method", async (t) => {
  await t.test("connection generation", async (subtest) => {
    const env = makeEnvironment(subtest, { label: "generation-drift" });
    const entry = env.makeGrant();
    env.controls.after_precommit = () => {
      env.controls.connection_generation += 1;
      env.controls.after_precommit = null;
    };
    const result = await env.broker.executeOnce(executeRequest(env, entry));
    assert.equal(result.outcome, "unavailable");
    assert.equal(result.reason_code, "connection_generation_drift");
    assert.equal(env.counts.inventory, 0);
    assert.equal(env.store.snapshot().attempts[0].state, "precommitted");
  });
  await t.test("authority revocation", async (subtest) => {
    const env = makeEnvironment(subtest, { label: "pre-dispatch-revocation" });
    const entry = env.makeGrant();
    env.controls.after_precommit = () => {
      entry.authority.issuer_revoked = true;
      env.controls.after_precommit = null;
    };
    const result = await env.broker.executeOnce(executeRequest(env, entry));
    assert.equal(result.outcome, "unavailable");
    assert.equal(result.reason_code, "authorization_revalidation_failed");
    assert.equal(env.counts.inventory, 0);
    assert.equal(env.store.snapshot().attempts[0].state, "precommitted");
  });
});

test("dispatch commit acknowledgement loss is sticky ambiguity and never invokes the provider", async (t) => {
  const env = makeEnvironment(t, { label: "commit-ack-loss" });
  const entry = env.makeGrant();
  env.controls.lose_commit_ack = true;
  const result = await env.broker.executeOnce(executeRequest(env, entry));
  assert.equal(result.state, "ambiguous");
  assert.equal(result.terminal_kind, "durable_ambiguity");
  assert.equal(result.reason_code, "dispatch_commit_ack_lost");
  assert.equal(result.durable_ambiguity.dispatch_redemption_digest, null);
  assert.equal(env.counts.inventory, 0);
  const replay = await env.broker.executeOnce(executeRequest(env, entry));
  assert.deepEqual(replay, result);
  assert.equal(env.counts.inventory, 0);
  assert.equal(env.broker.snapshot().instrument_quarantine_count, 0);
});

test("provider terminal and error dimensions preserve the exact durable disposition", async (t) => {
  const cases = [
    ["refused", "provider_report", "refused_no_effect"],
    ["reported_ambiguous", "provider_report", "ambiguous"],
    ["callback_failure", "provider_report", "ambiguous"],
    ["error_before_redeem", "durable_ambiguity", null],
    ["error_after_redeem", "durable_ambiguity", null],
    ["credential_clone", "durable_ambiguity", null],
    ["return_without_durable", "durable_ambiguity", null],
  ];
  for (const [mode, terminalKind, providerOutcome] of cases) {
    await t.test(mode, async (subtest) => {
      const env = makeEnvironment(subtest, { label: `provider-${mode}` });
      const entry = env.makeGrant();
      env.controls.provider_mode = mode;
      const result = await env.broker.executeOnce(executeRequest(env, entry));
      assert.equal(result.terminal_kind, terminalKind);
      assert.equal(result.state, terminalKind === "provider_report" ? providerOutcome : "ambiguous");
      if (terminalKind === "provider_report") {
        assert.equal(result.provider_report.outcome, providerOutcome);
      } else {
        assert.equal(result.provider_report, null);
        assert.ok(result.durable_ambiguity);
      }
      if (mode === "error_before_redeem" || mode === "credential_clone"
          || mode === "return_without_durable") {
        assert.equal(result.durable_ambiguity.dispatch_redemption_digest, null);
      }
      if (mode === "error_after_redeem") {
        assert.match(result.durable_ambiguity.dispatch_redemption_digest, /^[a-f0-9]{64}$/);
      }
      assert.equal(env.counts.inventory, 1);
      assert.equal(env.broker.snapshot().instrument_quarantine_count, 0);
      const replay = await env.broker.executeOnce(executeRequest(env, entry));
      assert.deepEqual(replay, result);
      assert.equal(env.counts.inventory, 1);
    });
  }
});

test("different attempts cannot overlap on one instrument", async (t) => {
  const env = makeEnvironment(t, { label: "instrument-exclusion" });
  const firstEntry = env.makeGrant("instrument.inventory");
  const secondEntry = env.makeGrant("instrument.health");
  env.controls.provider_mode = "deferred";
  const first = env.broker.executeOnce(executeRequest(env, firstEntry));
  await waitUntil(() => typeof env.controls.release_deferred === "function");
  const blocked = await env.broker.executeOnce(executeRequest(env, secondEntry));
  assert.equal(blocked.outcome, "unavailable");
  assert.equal(blocked.reason_code, "instrument_bootstrap_busy");
  assert.equal(env.counts.health, 0);
  assert.equal(env.store.snapshot().attempts.length, 1);
  env.controls.release_deferred();
  assert.equal((await first).state, "succeeded");
  assert.equal(env.counts.inventory, 1);
});

test("provider timeout creates a visible sticky quarantine that blocks later grants", async (t) => {
  const env = makeEnvironment(t, { label: "provider-timeout", timeout_ms: 10 });
  const firstEntry = env.makeGrant("instrument.inventory");
  env.controls.provider_mode = "never";
  const result = await env.broker.executeOnce(executeRequest(env, firstEntry));
  assert.equal(result.state, "ambiguous");
  assert.equal(result.reason_code, "provider_timeout");
  const snapshot = env.broker.snapshot();
  assert.equal(snapshot.instrument_quarantine_count, 1);
  assert.deepEqual(snapshot.instrument_quarantines[0], {
    instrument_ref: env.identities.instrument_ref,
    attempt_ref: result.attempt_ref,
    provider_id: env.descriptor.provider_id,
    reason_code: "provider_call_timeout",
    provider_call_pending: true,
    provider_call_settled_after_timeout: false,
  });
  const sameReplay = await env.broker.executeOnce(executeRequest(env, firstEntry));
  assert.deepEqual(sameReplay, result);
  const later = await env.broker.executeOnce(executeRequest(
    env,
    env.makeGrant("instrument.capabilities"),
  ));
  assert.equal(later.outcome, "unavailable");
  assert.equal(later.reason_code, "instrument_provider_call_quarantined");
  assert.equal(env.counts.capabilities, 0);
  assert.equal(env.store.snapshot().attempts.length, 1);
});

test("lost provider response replays its durable terminal but still exposes the unresolved call", async (t) => {
  const env = makeEnvironment(t, { label: "provider-response-loss", timeout_ms: 10 });
  const entry = env.makeGrant();
  env.controls.provider_mode = "response_loss";
  const result = await env.broker.executeOnce(executeRequest(env, entry));
  assert.equal(result.state, "succeeded");
  assert.equal(result.terminal_kind, "provider_report");
  assert.equal(env.counts.inventory, 1);
  assert.equal(env.broker.snapshot().instrument_quarantine_count, 1);
  const replay = await env.broker.executeOnce(executeRequest(env, entry));
  assert.deepEqual(replay, result);
  assert.equal(env.counts.inventory, 1);
  const blocked = await env.broker.executeOnce(executeRequest(
    env,
    env.makeGrant("instrument.health"),
  ));
  assert.equal(blocked.reason_code, "instrument_provider_call_quarantined");
  assert.equal(env.counts.health, 0);
});

test("describe failures are bounded and an unresolved describe quarantines the instrument", async (t) => {
  await t.test("settled failure", async (subtest) => {
    const env = makeEnvironment(subtest, { label: "describe-failure" });
    const entry = env.makeGrant();
    env.controls.describe_mode = "throw";
    const unavailable = await env.broker.executeOnce(executeRequest(env, entry));
    assert.equal(unavailable.outcome, "unavailable");
    assert.equal(unavailable.reason_code, "provider_descriptor_unavailable");
    assert.equal(env.store.snapshot().attempts.length, 0);
    assert.equal(env.broker.snapshot().instrument_quarantine_count, 0);
    env.controls.describe_mode = "success";
    assert.equal((await env.broker.executeOnce(executeRequest(env, entry))).state, "succeeded");
    assert.equal(env.counts.describe, 2);
  });
  await t.test("timeout", async (subtest) => {
    const env = makeEnvironment(subtest, { label: "describe-timeout", timeout_ms: 10 });
    const entry = env.makeGrant();
    env.controls.describe_mode = "never";
    const unavailable = await env.broker.executeOnce(executeRequest(env, entry));
    assert.equal(unavailable.outcome, "unavailable");
    assert.equal(unavailable.reason_code, "provider_descriptor_timeout");
    assert.equal(env.store.snapshot().attempts.length, 0);
    assert.equal(env.broker.snapshot().instrument_quarantine_count, 1);
  });
});
