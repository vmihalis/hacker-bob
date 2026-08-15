"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");

const bootstrapOperations = require(
  "../packages/bob-instrument-chameleon/lib/bootstrap-operations.js"
);
const {
  BOOTSTRAP_ASSURANCE_PROFILE_ID,
  BOOTSTRAP_INVARIANT_WITNESS_DOMAIN,
  BOOTSTRAP_INVARIANT_WITNESS_KEY_USAGE,
  BOOTSTRAP_INVARIANTS_DIGEST,
  CHAMELEON_BOOTSTRAP_ASSURANCE_CLAIMS,
  CHAMELEON_BOOTSTRAP_COMMAND_ALLOWLIST,
  CHAMELEON_BOOTSTRAP_FORBIDDEN_REQUEST_FIELDS,
  CHAMELEON_BOOTSTRAP_MANIFEST,
  CHAMELEON_BOOTSTRAP_OPERATION_REGISTRY,
  allocateChameleonBootstrapResponseReceipt,
  bootstrapInvariantWitnessSignatureInputDigest,
  compileChameleonBootstrapOperation,
  createChameleonBootstrapGrantAttenuator,
  createChameleonBootstrapInvariantWitnessVerifier,
  createChameleonBootstrapReceiptAllocator,
  normalizeChameleonBootstrapRequest,
  normalizeChameleonBootstrapResponse,
  projectChameleonBootstrapGrant,
  verifyChameleonBootstrapInvariantWitness,
} = bootstrapOperations;
const {
  aggregateChameleonBootstrapResponsePayloads,
} = require("../packages/bob-instrument-chameleon/lib/bootstrap-response-payloads.js");
const {
  FIXED_FRAME_BYTES,
  SOF,
  SOF_LRC,
  calculateLrc,
  createFrameParser,
} = require("../packages/bob-instrument-chameleon/lib/codec.js");
const {
  PHYSICAL_BOOTSTRAP_GRANT_DOMAIN,
  PHYSICAL_BOOTSTRAP_GRANT_KEY_USAGE,
  createPhysicalBootstrapGrantVerifier,
  normalizeMcpPhysicalExecutionRequest,
  physicalBootstrapGrantSignatureInputDigest,
  projectVerifiedPhysicalBootstrapGrant,
} = require("../mcp/domains/physical/physical-authority.js");
const {
  normalizePhysicalScopeNucleusAxis,
} = require("../mcp/core/governance/governance-contracts.js");
const {
  TRUSTED_CLOCK_MAPPING_DOMAIN,
  createPhysicalTrustedClockPort,
  physicalClockMappingSigningMessage,
  publicKeyDigest,
} = require("../mcp/domains/physical/physical-trusted-clock.js");
const {
  buildEffectTemplateRegistry,
} = require("../mcp/core/requested-effects.js");
const {
  hashCanonicalJson,
} = require("../mcp/core/verification/verification-contracts.js");
const {
  NATIVE_BOOTSTRAP_SEQUENCE_ASSURANCE,
  assertNativeBootstrapCommandBinding,
  assertNativeBootstrapSequenceCompletion,
  claimNativeBootstrapSequenceStep,
  completeNativeBootstrapSequence,
  createNativeBootstrapSequenceGuard,
} = require(
  "../packages/bob-instrument-chameleon-native-darwin/lib/native-bootstrap-sequence.js"
);

const ROOT = path.join(__dirname, "..");

function digest(label) {
  return hashCanonicalJson({ label });
}

function template(templateId, subjectKind, action, channel, persistence, bounds = {}) {
  return {
    version: 1,
    template_id: templateId,
    subject_kind: subjectKind,
    action,
    channel,
    persistence,
    bounds,
  };
}

function effectRegistry() {
  return buildEffectTemplateRegistry([
    template("instrument.observe.usb.v1", "instrument", "observe", "usb", "none"),
    template("instrument.observe.local.v1", "instrument", "observe", "instrument_local", "none"),
    template("instrument.transmit.rf.v1", "instrument", "transmit", "rf", "ephemeral"),
    template("target.observe.usb.v1", "target", "observe", "usb", "none"),
    template("environment.observe.usb.v1", "environment", "observe", "usb", "none"),
  ]);
}

function requestedEffect(registry, templateId, subjectRef) {
  const declared = registry.get(templateId);
  return {
    version: 1,
    template_id: declared.template_id,
    template_digest: declared.template_digest,
    subject_ref: subjectRef,
    subject_kind: declared.subject_kind,
    action: declared.action,
    channel: declared.channel,
    persistence: declared.persistence,
    bounds: {},
  };
}

function bootstrapRequest(registry, operationId = "instrument.inventory") {
  const suffix = operationId.split(".").at(-1);
  return {
    version: 1,
    grant_kind: "bootstrap",
    session_id: "session-chameleon-bootstrap-1",
    session_nucleus_hash: digest("session-nucleus"),
    caller_role_id: "orchestrator",
    requester_principal_id: "principal:bootstrap-requester-1",
    ipc_peer_principal_id: "principal:bootstrap-ipc-peer-1",
    execution_principal_id: "principal:bootstrap-worker-1",
    instrument_ref: "instrument:chameleon-enrollment-candidate-1",
    operation_id: operationId,
    parameter_digest: hashCanonicalJson({}),
    authority_epoch: 7,
    revocation_generation: 2,
    nonce: `chameleon-bootstrap-${suffix}-nonce-1`,
    sequence: 11,
    not_before: "2026-07-18T00:00:00.000Z",
    expires_at: "2026-07-18T00:01:00.000Z",
    requested_effects: [requestedEffect(
      registry,
      "instrument.observe.usb.v1",
      "instrument:chameleon-enrollment-candidate-1",
    )],
    enrollment_candidate_ref: "enrollment-candidate:chameleon-reader-1",
    bootstrap_manifest_digest: CHAMELEON_BOOTSTRAP_MANIFEST.manifest_digest,
    provider_binary_digest: digest("chameleon-provider-binary"),
    transport_digest: digest("chameleon-usb-transport"),
    rf_state: "off",
  };
}

function bootstrapAxis(overrides = {}) {
  return normalizePhysicalScopeNucleusAxis({
    version: 1,
    physical_enabled: true,
    policy_version: 1,
    policy_id: "chameleon-bootstrap-policy-v1",
    policy_digest: digest("chameleon-bootstrap-policy"),
    projection_version: 1,
    projection_digest: digest("chameleon-bootstrap-scope-projection"),
    provenance_digest: digest("chameleon-bootstrap-scope-provenance"),
    compatibility_digest: digest("chameleon-bootstrap-scope-compatibility"),
    transition_receipt_registry_digest: digest("chameleon-bootstrap-transition-registry"),
    authority_epoch: 7,
    revocation_generation: 2,
    ...overrides,
  });
}

function replayReservation(claim, now, options = {}) {
  const receipt = {
    version: 1,
    reservation_ref: options.reservation_ref
      || `bootstrap-grant-replay-reservation:${hashCanonicalJson(claim).slice(0, 40)}`,
    replay_claim: options.replay_claim || claim,
    replay_claim_digest: hashCanonicalJson(options.replay_claim || claim),
    generation: options.generation || 1,
    previous_receipt_digest: options.generation > 1
      ? options.previous_receipt_digest || digest("prior-bootstrap-replay-receipt")
      : null,
    reserved_at: options.reserved_at || now,
    fsynced_at: options.fsynced_at || now,
  };
  return {
    version: 1,
    disposition: options.disposition || "created",
    reservation_receipt: { ...receipt, receipt_digest: hashCanonicalJson(receipt) },
  };
}

function signedTrustedClock(readNow) {
  const keyPair = crypto.generateKeyPairSync("ed25519");
  const payload = {
    version: 1,
    clock_id: "physical-clock:chameleon-bootstrap-test",
    monotonic_epoch_id: digest("chameleon-bootstrap-monotonic-epoch"),
    mapping_generation: 1,
    reference_monotonic_ms: 0,
    reference_utc: "2026-07-18T00:00:00.000Z",
    max_uncertainty_ms: 0,
    not_before: "2026-07-17T23:59:00.000Z",
    expires_at: "2026-07-18T01:00:00.000Z",
    trust_root_epoch: 4,
    authority_epoch: 7,
    revocation_generation: 2,
    signer_key_id: "clock-key:chameleon-bootstrap-test",
    signer_public_key_digest: publicKeyDigest(keyPair.publicKey),
  };
  const payloadDigest = hashCanonicalJson(payload);
  const signature = crypto.sign(
    null,
    physicalClockMappingSigningMessage(payloadDigest),
    keyPair.privateKey,
  ).toString("base64url");
  const basis = {
    version: 1,
    domain: TRUSTED_CLOCK_MAPPING_DOMAIN,
    payload,
    payload_digest: payloadDigest,
    scheme: "ed25519",
    signature,
  };
  const mapping = {
    ...basis,
    signed_mapping_digest: hashCanonicalJson(basis),
  };
  return createPhysicalTrustedClockPort({
    port_id: "chameleon_bootstrap_test_clock",
    clock_id: payload.clock_id,
    monotonic_epoch_id: payload.monotonic_epoch_id,
    uncertainty_ceiling_ms: 0,
    read_monotonic_ms: () => (
      Date.parse(readNow()) - Date.parse(payload.reference_utc)
    ),
    read_signed_mapping: () => mapping,
    resolve_current_trust: () => ({
      version: 1,
      trusted: true,
      revoked: false,
      clock_id: payload.clock_id,
      monotonic_epoch_id: payload.monotonic_epoch_id,
      current_mapping_generation: payload.mapping_generation,
      current_signed_mapping_digest: mapping.signed_mapping_digest,
      trust_root_epoch: payload.trust_root_epoch,
      authority_epoch: payload.authority_epoch,
      revocation_generation: payload.revocation_generation,
      signer_key_id: payload.signer_key_id,
      signer_public_key_digest: payload.signer_public_key_digest,
      public_key: keyPair.publicKey,
    }),
  });
}

function authorizedBootstrap(registry, operationId = "instrument.inventory", options = {}) {
  const input = { ...bootstrapRequest(registry, operationId), ...(options.request || {}) };
  const request = normalizeMcpPhysicalExecutionRequest(input, registry);
  const operation = CHAMELEON_BOOTSTRAP_OPERATION_REGISTRY.get(request.operation_id);
  if (!operation) throw new Error(`test fixture operation ${request.operation_id} is unavailable`);
  const keyPair = crypto.generateKeyPairSync("ed25519");
  const issuerPublicKeyDigest = crypto.createHash("sha256").update(
    keyPair.publicKey.export({ type: "spki", format: "der" }),
  ).digest("hex");
  const providerDescriptorDigest = options.provider_descriptor_digest
    || digest("chameleon-provider-descriptor");
  const bindings = {
    execution_request: request,
    effect_registry: registry,
    provider_id: options.provider_id || "chameleon_ultra",
    provider_descriptor_digest: providerDescriptorDigest,
    operation_digest: options.operation_digest || operation.operation_digest,
    bootstrap_invariants_digest: options.bootstrap_invariants_digest || BOOTSTRAP_INVARIANTS_DIGEST,
  };
  const authority = {
    version: 1,
    session_id: request.session_id,
    session_nucleus_hash: request.session_nucleus_hash,
    execution_request_digest: request.execution_request_digest,
    physical_scope_axis: bootstrapAxis(),
    caller_role_id: request.caller_role_id,
    requester_principal_id: request.requester_principal_id,
    ipc_peer_principal_id: request.ipc_peer_principal_id,
    execution_principal_id: request.execution_principal_id,
    provider_id: bindings.provider_id,
    provider_descriptor_digest: bindings.provider_descriptor_digest,
    instrument_ref: request.instrument_ref,
    enrollment_candidate_ref: request.enrollment_candidate_ref,
    bootstrap_manifest_digest: request.bootstrap_manifest_digest,
    provider_binary_digest: request.provider_binary_digest,
    transport_digest: request.transport_digest,
    operation_id: request.operation_id,
    operation_digest: bindings.operation_digest,
    parameter_digest: request.parameter_digest,
    requested_effects_digest: request.requested_effects_digest,
    bootstrap_invariants_digest: bindings.bootstrap_invariants_digest,
    authority_decision: "allow",
    authority_reason: "exact_allow",
    authority_resolution_digest: digest("chameleon-bootstrap-authority-resolution"),
    trust_root_id: "trust-root:chameleon-bootstrap-test",
    trust_root_epoch: 6,
    trust_registry_digest: digest("chameleon-bootstrap-trust-registry"),
    trust_root_trusted: true,
    trust_root_revoked: false,
    issuer_principal_id: "principal:chameleon-bootstrap-authority",
    issuer_key_id: "signer-key:chameleon-bootstrap-authority",
    issuer_epoch: 3,
    issuer_public_key_digest: issuerPublicKeyDigest,
    key_usage: PHYSICAL_BOOTSTRAP_GRANT_KEY_USAGE,
    issuer_trusted: true,
    issuer_revoked: false,
    ...(options.authority || {}),
  };
  let now = options.now || "2026-07-18T00:00:10.000Z";
  let verifyCount = 0;
  let reserveCount = 0;
  const replayClaims = new Map();
  const verifier = createPhysicalBootstrapGrantVerifier({
    verifier_id: options.verifier_id || "chameleon-bootstrap-grant-verifier-v1",
    ...(options.deterministic_clock === true
      ? { trusted_now: () => now }
      : { trusted_clock_port: signedTrustedClock(() => now) }),
    resolve_current_authority: () => authority,
    verify_ed25519: (verification) => {
      verifyCount += 1;
      return crypto.verify(
        null,
        Buffer.from(verification.signature_input_digest, "hex"),
        keyPair.publicKey,
        Buffer.from(verification.signature, "base64url"),
      );
    },
    reserve_replay: (claim) => {
      reserveCount += 1;
      const existing = [...replayClaims.values()].find((entry) => (
        entry.reservation_receipt.replay_claim.grant_ref === claim.grant_ref
        || entry.reservation_receipt.replay_claim.execution_request_digest
          === claim.execution_request_digest
      ));
      if (existing) return { ...existing, disposition: "existing_same" };
      const reservation = replayReservation(claim, now, {
        generation: replayClaims.size + 1,
        previous_receipt_digest: [...replayClaims.values()].at(-1)
          ?.reservation_receipt.receipt_digest,
      });
      replayClaims.set(claim.grant_ref, reservation);
      return reservation;
    },
  });
  const axis = authority.physical_scope_axis;
  const payload = {
    version: 1,
    grant_kind: "bootstrap",
    grant_ref: options.grant_ref || `physical-grant:chameleon-bootstrap-${operationId.split(".").at(-1)}-1`,
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
    provider_id: bindings.provider_id,
    provider_descriptor_digest: bindings.provider_descriptor_digest,
    instrument_ref: request.instrument_ref,
    enrollment_candidate_ref: request.enrollment_candidate_ref,
    bootstrap_manifest_digest: request.bootstrap_manifest_digest,
    provider_binary_digest: request.provider_binary_digest,
    transport_digest: request.transport_digest,
    operation_id: request.operation_id,
    operation_digest: bindings.operation_digest,
    parameter_digest: request.parameter_digest,
    requested_effects_digest: request.requested_effects_digest,
    bootstrap_invariants_digest: bindings.bootstrap_invariants_digest,
    rf_state: request.rf_state,
    authority_decision: authority.authority_decision,
    authority_reason: authority.authority_reason,
    authority_resolution_digest: authority.authority_resolution_digest,
    not_before: request.not_before,
    expires_at: request.expires_at,
    ...(options.payload || {}),
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
    signed_at: options.signed_at || "2026-07-18T00:00:05.000Z",
    signed_payload_digest: hashCanonicalJson(payload),
  };
  const signatureInputDigest = physicalBootstrapGrantSignatureInputDigest(payload, authentication);
  const signature = crypto.sign(
    null,
    Buffer.from(signatureInputDigest, "hex"),
    keyPair.privateKey,
  ).toString("base64url");
  const envelope = {
    version: 1,
    kind: "physical_bootstrap_grant",
    domain: PHYSICAL_BOOTSTRAP_GRANT_DOMAIN,
    payload,
    authentication: { ...authentication, signature },
  };
  const coreGrant = projectVerifiedPhysicalBootstrapGrant(envelope, verifier, bindings);
  const attenuator = createChameleonBootstrapGrantAttenuator({
    attenuator_id: options.attenuator_id || "chameleon-bootstrap-attenuator-v1",
    bootstrap_grant_verifier: verifier,
    provider_descriptor_digest: options.observed_provider_descriptor_digest
      || providerDescriptorDigest,
    provider_binary_digest: options.observed_provider_binary_digest
      || request.provider_binary_digest,
    transport_digest: options.observed_transport_digest || request.transport_digest,
  });
  let grant = null;
  function project() {
    grant = projectChameleonBootstrapGrant(coreGrant, attenuator);
    return grant;
  }
  if (!options.defer_attenuation) project();
  return {
    input,
    request,
    authority,
    bindings,
    verifier,
    envelope,
    coreGrant,
    attenuator,
    get grant() {
      return grant;
    },
    project,
    setNow(value) {
      now = value;
    },
    getVerifyCount() {
      return verifyCount;
    },
    getReserveCount() {
      return reserveCount;
    },
  };
}

function grantFor(registry, operationId = "instrument.inventory") {
  return authorizedBootstrap(registry, operationId).grant;
}

function bootstrapWireFrame(command, dataInput) {
  const data = Buffer.from(dataInput);
  const frame = Buffer.alloc(FIXED_FRAME_BYTES + data.length);
  frame[0] = SOF;
  frame[1] = SOF_LRC;
  frame.writeUInt16BE(command, 2);
  frame.writeUInt16BE(0x68, 4);
  frame.writeUInt16BE(data.length, 6);
  frame[8] = calculateLrc(frame.subarray(2, 8));
  data.copy(frame, 9);
  frame[9 + data.length] = calculateLrc(data);
  return frame;
}

function sourceOwnedDecodedPayload(grant, responseFields = {}) {
  const compiled = compileChameleonBootstrapOperation(grant);
  let entries;
  if (grant.operation_id === "instrument.inventory") {
    entries = [
      [1000, [2, 2]],
      [1017, Buffer.from(responseFields.git_revision || "v2.2.0", "utf8")],
      [1033, [responseFields.model === "Chameleon Lite" ? 1 : 0]],
    ];
  } else if (grant.operation_id === "instrument.capabilities") {
    const ids = responseFields.reported_command_ids
      || [1000, 1017, 1025, 1033, 1035];
    const bytes = Buffer.alloc(ids.length * 2);
    ids.forEach((commandId, index) => bytes.writeUInt16BE(commandId, index * 2));
    entries = [[1035, bytes]];
  } else {
    const battery = responseFields.battery
      || { percent: 83, voltage_mv: 3975, charging_state: "not_reported" };
    const bytes = Buffer.alloc(3);
    bytes.writeUInt16BE(battery.voltage_mv, 0);
    bytes[2] = battery.percent;
    entries = [[1025, bytes]];
  }
  const parsed = createFrameParser().push(Buffer.concat(
    entries.map(([command, data]) => bootstrapWireFrame(command, data)),
  ));
  assert.equal(parsed.frames.length, entries.length);
  return aggregateChameleonBootstrapResponsePayloads(compiled, parsed.frames);
}

let bootstrapEvidenceSequence = 0;

function authenticatedBootstrapWitness(grant, decoded, options = {}) {
  bootstrapEvidenceSequence += 1;
  const keyPair = crypto.generateKeyPairSync("ed25519");
  const payload = {
    version: 1,
    provider_id: "chameleon_ultra",
    bootstrap_grant_projection_digest: grant.bootstrap_grant_projection_digest,
    execution_request_digest: grant.execution_request_digest,
    operation_id: grant.operation_id,
    operation_digest: grant.operation_digest,
    command_set_digest: grant.command_set_digest,
    decoded_payload_digest: decoded.decoded_payload_digest,
    instrument_ref: grant.instrument_ref,
    enrollment_candidate_ref: grant.enrollment_candidate_ref,
    bootstrap_invariants_digest: BOOTSTRAP_INVARIANTS_DIGEST,
    witness_principal_id: "principal:chameleon-bootstrap-observer",
    observed_at: options.observed_at || "2026-07-18T00:00:20.000Z",
    rf_invariant_verdict: "pending_independent_observation_hil",
    mode_invariant_verdict: "not_observed_get_device_mode_not_allowlisted",
    workspace_invariant_verdict: "satisfied_by_closed_command_effect_manifest",
    workspace_write_count: 0,
    independent_observation_hil_status: "not_performed",
  };
  const authentication = {
    version: 1,
    method: "ed25519",
    key_usage: BOOTSTRAP_INVARIANT_WITNESS_KEY_USAGE,
    trust_root_id: "trust-root:chameleon-bootstrap-observer",
    trust_root_epoch: 1,
    trust_registry_digest: digest("chameleon-bootstrap-observer-registry"),
    signer_key_id: "signer-key:chameleon-bootstrap-observer",
    signer_epoch: 1,
    signer_public_key_digest: publicKeyDigest(keyPair.publicKey),
    signed_at: options.signed_at || "2026-07-18T00:00:25.000Z",
    expires_at: options.expires_at || "2026-07-18T00:00:50.000Z",
    signed_payload_digest: hashCanonicalJson(payload),
  };
  const signature = crypto.sign(
    null,
    Buffer.from(bootstrapInvariantWitnessSignatureInputDigest(payload, authentication), "hex"),
    keyPair.privateKey,
  ).toString("base64url");
  const trust = {
    version: 1,
    trusted: true,
    revoked: false,
    witness_principal_id: payload.witness_principal_id,
    trust_root_id: authentication.trust_root_id,
    trust_root_epoch: authentication.trust_root_epoch,
    trust_registry_digest: authentication.trust_registry_digest,
    signer_key_id: authentication.signer_key_id,
    signer_epoch: authentication.signer_epoch,
    signer_public_key_digest: authentication.signer_public_key_digest,
    key_usage: authentication.key_usage,
  };
  const verifier = createChameleonBootstrapInvariantWitnessVerifier({
    verifier_id: `chameleon-bootstrap-witness-verifier-${bootstrapEvidenceSequence}`,
    trusted_clock_port: signedTrustedClock(
      () => options.now || "2026-07-18T00:00:30.000Z",
    ),
    resolve_current_trust: () => trust,
    verify_ed25519: (verification) => crypto.verify(
      null,
      Buffer.from(verification.signature_input_digest, "hex"),
      keyPair.publicKey,
      Buffer.from(verification.signature, "base64url"),
    ),
  });
  return verifyChameleonBootstrapInvariantWitness({
    version: 1,
    kind: "chameleon_bootstrap_invariant_witness",
    domain: BOOTSTRAP_INVARIANT_WITNESS_DOMAIN,
    payload,
    authentication: { ...authentication, signature },
  }, decoded, grant, verifier);
}

function sourceAcknowledgedAllocation(grant, decoded, witness) {
  bootstrapEvidenceSequence += 1;
  const committed = new Map();
  const allocator = createChameleonBootstrapReceiptAllocator({
    allocator_id: `chameleon-bootstrap-receipt-allocator-${bootstrapEvidenceSequence}`,
    commit_allocation: (allocation) => {
      committed.set(allocation.receipt_ref, allocation);
      return true;
    },
    resolve_committed_allocation: (receiptRef) => committed.get(receiptRef),
  });
  return allocateChameleonBootstrapResponseReceipt(decoded, witness, grant, allocator);
}

function normalizedBootstrapEvidence(grant, responseFields = {}, options = {}) {
  const decoded = options.decoded || sourceOwnedDecodedPayload(grant, responseFields);
  const witness = authenticatedBootstrapWitness(grant, decoded, options);
  const allocation = sourceAcknowledgedAllocation(grant, decoded, witness);
  return {
    allocation,
    decoded,
    response: normalizeChameleonBootstrapResponse(decoded, allocation, witness, grant),
    witness,
  };
}

test("the declarative manifest exactly matches PH-P8 coverage and exposes only three provider-internal reads", () => {
  const coverage = JSON.parse(fs.readFileSync(
    path.join(ROOT, "docs", "plane-physical", "coverage.json"),
    "utf8",
  ));
  assert.deepEqual(CHAMELEON_BOOTSTRAP_OPERATION_REGISTRY.ids(), [
    "instrument.capabilities",
    "instrument.health",
    "instrument.inventory",
  ]);
  assert.deepEqual(CHAMELEON_BOOTSTRAP_COMMAND_ALLOWLIST, [1000, 1017, 1025, 1033, 1035]);
  assert.equal(CHAMELEON_BOOTSTRAP_MANIFEST.exposure, "provider_private");
  assert.equal(CHAMELEON_BOOTSTRAP_MANIFEST.disposition, "provider_internal");
  assert.equal(CHAMELEON_BOOTSTRAP_MANIFEST.assurance_ceiling_profile_id, "bootstrap_read_only");
  assert.equal(CHAMELEON_BOOTSTRAP_MANIFEST.operations.length, 3);

  const expectedCommands = {
    "instrument.inventory": [1000, 1017, 1033],
    "instrument.capabilities": [1035],
    "instrument.health": [1025],
  };
  for (const operation of CHAMELEON_BOOTSTRAP_MANIFEST.operations) {
    assert.deepEqual(operation.command_ids, expectedCommands[operation.operation_id]);
    assert.deepEqual(operation.parameters, {});
    assert.deepEqual(operation.effect, {
      subject_kind: "instrument",
      action: "observe",
      channel: "usb",
      persistence: "none",
    });
    assert.deepEqual(operation.invariants, {
      request_payload_bytes: 0,
      rf_state: "off",
      mode_change: "forbidden",
      slot_access: "forbidden",
      workspace_write: "forbidden",
    });
    assert.equal(operation.exposure, "provider_private");
    assert.equal(operation.disposition, "provider_internal");
    assert.equal(Object.isFrozen(operation), true);
  }

  const variants = coverage.capability_dependency_registry["CU-CORE-INVENTORY"].variants;
  assert.deepEqual(variants.identity_version.all_of.map((value) => Number(value.split(":")[1])),
    expectedCommands["instrument.inventory"]);
  assert.deepEqual(variants.capabilities.all_of.map((value) => Number(value.split(":")[1])),
    expectedCommands["instrument.capabilities"]);
  assert.deepEqual(variants.battery_health.all_of.map((value) => Number(value.split(":")[1])),
    expectedCommands["instrument.health"]);
  for (const operationId of Object.keys(expectedCommands)) {
    assert.deepEqual(coverage.normalized_operation_registry[operationId], {
      exposure: "provider_private",
      minimum_assurance_profile_id: "bootstrap_read_only",
    });
  }
  const row = coverage.coverage.find((entry) => entry.provider_capability_id === "CU-CORE-INVENTORY");
  assert.deepEqual(row.upstream_command_ids, CHAMELEON_BOOTSTRAP_COMMAND_ALLOWLIST);

  const source = fs.readFileSync(
    path.join(ROOT, "packages", "bob-instrument-chameleon", "lib", "bootstrap-operations.js"),
    "utf8",
  );
  assert.doesNotMatch(source, /require\(["'](?:node:)?(?:fs|child_process|net|dgram|worker_threads)["']\)/);
  assert.doesNotMatch(source, /serialport|navigator\.serial|usb\.openDevice/i);
  assert.equal(
    Object.keys(bootstrapOperations).some((name) => /execute|connect|exchange|passthrough/i.test(name)),
    false,
  );
});

test("each bootstrap grant binds one operation and deterministically compiles only its fixed zero-payload subset", () => {
  const registry = effectRegistry();
  const expectedCommands = {
    "instrument.inventory": [1000, 1017, 1033],
    "instrument.capabilities": [1035],
    "instrument.health": [1025],
  };
  const grantDigests = new Set();
  for (const [operationId, commandIds] of Object.entries(expectedCommands)) {
    const authorized = authorizedBootstrap(registry, operationId);
    const input = authorized.input;
    const normalized = normalizeChameleonBootstrapRequest(input, registry);
    const grant = authorized.grant;
    const compiled = compileChameleonBootstrapOperation(grant);
    assert.equal(normalized.execution_request_digest, grant.execution_request_digest);
    assert.equal(grant.operation_id, operationId);
    assert.deepEqual(grant.command_ids, commandIds);
    assert.equal(grant.enrollment_candidate_ref, input.enrollment_candidate_ref);
    assert.equal(grant.bootstrap_manifest_digest, CHAMELEON_BOOTSTRAP_MANIFEST.manifest_digest);
    assert.equal(grant.provider_binary_digest, input.provider_binary_digest);
    assert.equal(grant.transport_digest, input.transport_digest);
    assert.equal(grant.authority_epoch, input.authority_epoch);
    assert.equal(grant.nonce, input.nonce);
    assert.equal(grant.not_before, input.not_before);
    assert.equal(grant.expires_at, input.expires_at);
    assert.equal(grant.caller_role_id, input.caller_role_id);
    assert.equal(grant.requester_principal_id, input.requester_principal_id);
    assert.equal(grant.execution_principal_id, input.execution_principal_id);
    assert.equal(grant.ipc_peer_principal_id, input.ipc_peer_principal_id);
    assert.equal(grant.trusted_clock_mode, "signed_monotonic_wall_mapping");
    assert.equal(compiled.trusted_clock_mode, "signed_monotonic_wall_mapping");
    assert.deepEqual(compiled.commands.map((command) => command.command_id), commandIds);
    for (const command of compiled.commands) {
      assert.equal(command.payload_kind, "none");
      assert.equal(command.payload_byte_length, 0);
      assert.equal(Object.keys(command).includes("payload"), false);
    }
    assert.equal(compiled.effect.action, "observe");
    assert.equal(compiled.effect.channel, "usb");
    assert.equal(compiled.effect.persistence, "none");
    assert.equal(Object.isFrozen(grant), true);
    assert.equal(Object.isFrozen(compiled.commands), true);
    grantDigests.add(grant.bootstrap_grant_projection_digest);
  }
  assert.equal(grantDigests.size, 3, "health, capabilities, and inventory remain separate grants");

  const inventoryGrant = grantFor(registry, "instrument.inventory");
  assert.throws(
    () => compileChameleonBootstrapOperation(inventoryGrant, { command_id: 1001 }),
    /no raw command or payload input/,
  );
  assert.throws(
    () => compileChameleonBootstrapOperation({ ...inventoryGrant }),
    /signed core authority and closed Chameleon attenuator/,
  );
});

test("Chameleon attenuation rejects unsigned minting, clones, verifier substitution, and every provider binding drift", () => {
  const registry = effectRegistry();
  const rawRequest = bootstrapRequest(registry);
  assert.doesNotThrow(() => normalizeChameleonBootstrapRequest(rawRequest, registry));
  assert.throws(
    () => projectChameleonBootstrapGrant(rawRequest, registry),
    /attenuator must be configured by the provider runtime/,
    "the retired unsigned request projector cannot mint provider authority",
  );
  assert.throws(
    () => authorizedBootstrap(registry, "instrument.inventory", {
      defer_attenuation: true,
      deterministic_clock: true,
    }),
    /attenuation requires a signed monotonic wall-clock mapping/,
    "production Chameleon attenuation cannot consume deterministic test-clock authority",
  );

  {
    const fixture = authorizedBootstrap(registry, "instrument.inventory", { defer_attenuation: true });
    assert.throws(
      () => projectChameleonBootstrapGrant({ ...fixture.coreGrant }, fixture.attenuator),
      /was not issued by the configured verifier/,
    );
  }
  {
    const fixture = authorizedBootstrap(registry, "instrument.inventory", { defer_attenuation: true });
    const other = authorizedBootstrap(registry, "instrument.inventory");
    const wrongVerifier = createChameleonBootstrapGrantAttenuator({
      attenuator_id: "wrong-verifier-attenuator-v1",
      bootstrap_grant_verifier: other.verifier,
      provider_descriptor_digest: fixture.bindings.provider_descriptor_digest,
      provider_binary_digest: fixture.request.provider_binary_digest,
      transport_digest: fixture.request.transport_digest,
    });
    assert.throws(
      () => projectChameleonBootstrapGrant(fixture.coreGrant, wrongVerifier),
      /was not issued by the configured verifier/,
    );
  }
  for (const [name, fixture, pattern] of [
    [
      "provider",
      authorizedBootstrap(registry, "instrument.inventory", {
        provider_id: "other_provider",
        defer_attenuation: true,
      }),
      /provider_id does not match the trusted bootstrap binding/,
    ],
    [
      "manifest",
      authorizedBootstrap(registry, "instrument.inventory", {
        request: { bootstrap_manifest_digest: digest("substituted-bootstrap-manifest") },
        defer_attenuation: true,
      }),
      /bootstrap_manifest_digest does not match the trusted bootstrap binding/,
    ],
    [
      "provider binary",
      authorizedBootstrap(registry, "instrument.inventory", {
        observed_provider_binary_digest: digest("substituted-provider-binary"),
        defer_attenuation: true,
      }),
      /provider_binary_digest does not match the trusted bootstrap binding/,
    ],
    [
      "transport",
      authorizedBootstrap(registry, "instrument.inventory", {
        observed_transport_digest: digest("substituted-transport"),
        defer_attenuation: true,
      }),
      /transport_digest does not match the trusted bootstrap binding/,
    ],
    [
      "operation",
      authorizedBootstrap(registry, "instrument.inventory", {
        operation_digest: digest("substituted-operation"),
        defer_attenuation: true,
      }),
      /operation_digest does not match the trusted bootstrap binding/,
    ],
    [
      "invariant",
      authorizedBootstrap(registry, "instrument.inventory", {
        bootstrap_invariants_digest: digest("substituted-invariants"),
        defer_attenuation: true,
      }),
      /bootstrap_invariants_digest does not match the trusted bootstrap binding/,
    ],
  ]) {
    assert.throws(() => fixture.project(), pattern, name);
  }

  {
    const localEffect = requestedEffect(
      registry,
      "instrument.observe.local.v1",
      "instrument:chameleon-enrollment-candidate-1",
    );
    const fixture = authorizedBootstrap(registry, "instrument.inventory", {
      request: { requested_effects: [localEffect] },
      defer_attenuation: true,
    });
    assert.throws(
      () => fixture.project(),
      /must be exactly instrument\.observe\/usb\/none/,
      "generic non-RF bootstrap authority is narrower at the Chameleon boundary",
    );
  }

  {
    const fixture = authorizedBootstrap(registry, "instrument.inventory", { defer_attenuation: true });
    fixture.project();
    assert.throws(
      () => fixture.project(),
      /already been attenuated/,
      "one core authority cannot mint multiple provider capabilities",
    );
  }
});

test("compilation live-revalidates authority while receipts retain safe signed and replay audit joins", () => {
  const registry = effectRegistry();
  const fixture = authorizedBootstrap(registry, "instrument.inventory");
  const { grant } = fixture;
  const compiled = compileChameleonBootstrapOperation(grant);
  const decoded = sourceOwnedDecodedPayload(grant, {
    model: "Chameleon Ultra",
    git_revision: "v2.2.0",
  });
  for (const artifact of [grant, compiled]) {
    assert.equal(artifact.signed_grant_digest, grant.signed_grant_digest);
    assert.equal(artifact.core_grant_projection_digest, grant.core_grant_projection_digest);
    assert.equal(
      artifact.replay_reservation_receipt_digest,
      grant.replay_reservation_receipt_digest,
    );
    const serialized = JSON.stringify(artifact);
    assert.equal(serialized.includes(fixture.envelope.authentication.signature), false);
    assert.doesNotMatch(serialized, /"authentication"|issuer_public_key|trust_root|"raw_bytes"|"payload":/);
  }

  fixture.authority.issuer_revoked = true;
  assert.throws(
    () => compileChameleonBootstrapOperation(grant),
    /issuer is not currently usable/,
    "revocation after attenuation wins the final compilation fence",
  );
  assert.equal(fixture.getVerifyCount(), 1, "live checks do not repeat signature verification");
  assert.equal(fixture.getReserveCount(), 1, "live checks do not repeat replay admission");

  const response = normalizedBootstrapEvidence(grant, {}, { decoded }).response;
  assert.equal(response.signed_grant_digest, grant.signed_grant_digest);
  assert.equal(response.core_grant_projection_digest, grant.core_grant_projection_digest);
  assert.equal(
    response.replay_reservation_receipt_digest,
    grant.replay_reservation_receipt_digest,
  );
  assert.equal(JSON.stringify(response).includes(fixture.envelope.authentication.signature), false);
  const expiryFixture = authorizedBootstrap(registry, "instrument.inventory");
  assert.throws(
    () => normalizedBootstrapEvidence(expiryFixture.grant, {}, {
      observed_at: expiryFixture.grant.expires_at,
      signed_at: "2026-07-18T00:01:05.000Z",
      expires_at: "2026-07-18T00:02:00.000Z",
      now: "2026-07-18T00:01:10.000Z",
    }),
    /outside the bootstrap grant window/,
    "bootstrap expiry is exclusive",
  );
});

test("bootstrap rejects prior-state fields, wider effects, unknown operations, and command escape hatches", () => {
  const registry = effectRegistry();
  const valid = bootstrapRequest(registry);
  for (const field of CHAMELEON_BOOTSTRAP_FORBIDDEN_REQUEST_FIELDS) {
    assert.throws(
      () => normalizeChameleonBootstrapRequest({ ...valid, [field]: "forbidden" }, registry),
      /cannot presuppose inventory, snapshot, task, plan, experiment, resource, target, or environment state/,
      `${field} must be forbidden before bootstrap inventory exists`,
    );
  }
  for (const field of ["command_id", "raw_command", "raw_payload", "slot", "mode", "rf_operation"] ) {
    assert.throws(
      () => normalizeChameleonBootstrapRequest({ ...valid, [field]: "escape" }, registry),
      /unknown fields/,
    );
  }
  for (const operationId of [
    "instrument.mode",
    "instrument.slot",
    "instrument.rf",
    "provider.raw_passthrough",
  ]) {
    assert.throws(
      () => normalizeChameleonBootstrapRequest({ ...valid, operation_id: operationId }, registry),
      /is not a provider-internal Chameleon bootstrap operation/,
    );
  }
  assert.throws(
    () => normalizeChameleonBootstrapRequest({
      ...valid,
      bootstrap_manifest_digest: digest("attacker-manifest"),
    }, registry),
    /does not match the closed Chameleon manifest/,
  );
  assert.throws(
    () => normalizeChameleonBootstrapRequest({
      ...valid,
      parameter_digest: digest("nonempty-parameters"),
    }, registry),
    /must bind the empty zero-payload parameter object/,
  );
  assert.throws(
    () => normalizeChameleonBootstrapRequest({
      ...valid,
      requested_effects: [requestedEffect(
        registry,
        "instrument.observe.local.v1",
        valid.instrument_ref,
      )],
    }, registry),
    /must be exactly instrument.observe\/usb\/none/,
  );
  assert.throws(
    () => normalizeChameleonBootstrapRequest({
      ...valid,
      requested_effects: [requestedEffect(
        registry,
        "instrument.transmit.rf.v1",
        valid.instrument_ref,
      )],
    }, registry),
    /read-only, non-RF/,
  );
  for (const [templateId, subjectRef] of [
    ["target.observe.usb.v1", "target:owned-card-1"],
    ["environment.observe.usb.v1", "environment:lab-zone-1"],
  ]) {
    assert.throws(
      () => normalizeChameleonBootstrapRequest({
        ...valid,
        requested_effects: [requestedEffect(registry, templateId, subjectRef)],
      }, registry),
      /must bind exactly to instrument/,
    );
  }
});

test("responses expose bounded metadata and exact bootstrap-capped assurance without enabling reported unknown commands", () => {
  const registry = effectRegistry();
  const inventoryGrant = grantFor(registry, "instrument.inventory");
  const inventory = normalizedBootstrapEvidence(inventoryGrant, {
    model: "Chameleon Ultra",
    git_revision: "v2.2.0-17-commit1234567",
  }).response;
  assert.equal(inventory.model, "Chameleon Ultra");
  assert.equal(inventory.application_version, "2.2");
  assert.equal(inventory.git_revision, "v2.2.0-17-commit1234567");
  assert.deepEqual(inventory.assurance_claims, CHAMELEON_BOOTSTRAP_ASSURANCE_CLAIMS);
  assert.deepEqual(inventory.assurance_claims, {
    profile_id: BOOTSTRAP_ASSURANCE_PROFILE_ID,
    identity_enrollment: "unverified",
    firmware_provenance: "self_reported",
    command_surface_conformance: "bootstrap_allowlisted",
    transport_trust: "local_observed",
    rf_invariant_assurance: "pending_independent_observation_hil",
    mode_invariant_assurance: "not_observed_get_device_mode_not_allowlisted",
    workspace_invariant_assurance: "closed_command_effect_manifest_only",
    production_ready: false,
    execution_authority: false,
    lifecycle_authority: false,
    assurance_claims_digest: CHAMELEON_BOOTSTRAP_ASSURANCE_CLAIMS.assurance_claims_digest,
  });
  assert.equal(inventory.invariants.rf_remained_off, null);
  assert.equal(inventory.invariants.mode_unchanged, null);
  assert.equal(inventory.invariants.workspace_unchanged, true);
  assert.equal(inventory.invariants.independent_observation_hil_status, "not_performed");
  assert.equal(inventory.production_ready, false);
  assert.equal(inventory.execution_authority, false);
  assert.equal(inventory.lifecycle_authority, false);
  assert.equal(Object.keys(inventory).some((field) => /chip|address|raw|byte/i.test(field)), false);

  const capabilitiesGrant = grantFor(registry, "instrument.capabilities");
  const capabilities = normalizedBootstrapEvidence(capabilitiesGrant, {
    reported_command_ids: [1000, 1017, 1025, 1033, 1035, 65530],
  }).response;
  assert.deepEqual(
    capabilities.bootstrap_allowlisted_reported_command_ids,
    CHAMELEON_BOOTSTRAP_COMMAND_ALLOWLIST,
  );
  assert.equal(capabilities.unrecognized_reported_command_count, 1);
  assert.deepEqual(
    compileChameleonBootstrapOperation(capabilitiesGrant).commands.map((command) => command.command_id),
    [1035],
    "reported unknown or cross-operation commands never widen the current grant",
  );

  const healthGrant = grantFor(registry, "instrument.health");
  const health = normalizedBootstrapEvidence(healthGrant, {
    battery: { percent: 83, voltage_mv: 3975, charging_state: "not_reported" },
  }).response;
  assert.deepEqual(health.battery, {
    percent: 83,
    voltage_mv: 3975,
    charging_state: "not_reported",
  });
  assert.match(health.observation_ref, /^bootstrap-observation:/);
  assert.match(health.receipt_ref, /^bootstrap-receipt:/);
  assert.equal(Object.isFrozen(health.battery), true);
});

test("response binding fails closed on caller assertions and every cloned evidence artifact", () => {
  const registry = effectRegistry();
  const grant = grantFor(registry, "instrument.inventory");
  const evidence = normalizedBootstrapEvidence(grant, {
    model: "Chameleon Ultra",
    git_revision: "v2.2.0",
  });
  assert.throws(
    () => normalizeChameleonBootstrapResponse({
      rf_state_before: "off",
      rf_state_after: "off",
      mode_state_before_digest: digest("caller-mode"),
      mode_state_after_digest: digest("caller-mode"),
      workspace_write_count: 0,
      observation_ref: "bootstrap-observation:caller-selected",
      receipt_ref: "bootstrap-receipt:caller-selected",
      raw_bytes: Buffer.from([1, 2, 3]),
    }, evidence.allocation, evidence.witness, grant),
    /source-owned parser aggregation/,
  );
  assert.throws(
    () => normalizeChameleonBootstrapResponse(
      { ...evidence.decoded }, evidence.allocation, evidence.witness, grant,
    ),
    /source-owned parser aggregation/,
  );
  assert.throws(
    () => normalizeChameleonBootstrapResponse(
      evidence.decoded, { ...evidence.allocation }, evidence.witness, grant,
    ),
    /source-acknowledged and canonically resolved/,
  );
  assert.throws(
    () => normalizeChameleonBootstrapResponse(
      evidence.decoded, evidence.allocation, { ...evidence.witness }, grant,
    ),
    /must be authenticated/,
  );
  assert.throws(
    () => normalizeChameleonBootstrapResponse(
      evidence.decoded,
      evidence.allocation,
      evidence.witness,
      { ...grant },
    ),
    /signed core authority and closed Chameleon attenuator/,
  );
});

test("bootstrap request and branded response boundary reject accessors without invocation", () => {
  const registry = effectRegistry();
  let getterCalls = 0;
  const request = bootstrapRequest(registry);
  Object.defineProperty(request, "operation_id", {
    enumerable: true,
    get() {
      getterCalls += 1;
      return "instrument.inventory";
    },
  });
  assert.throws(
    () => normalizeChameleonBootstrapRequest(request, registry),
    /operation_id must be an enumerable data field/u,
  );
  assert.equal(getterCalls, 0);

  const grant = grantFor(registry, "instrument.capabilities");
  const evidence = normalizedBootstrapEvidence(grant, {
    reported_command_ids: [1000, 1017, 1025, 1033, 1035],
  });
  const fakeDecoded = {};
  Object.defineProperty(fakeDecoded, "response_fields", {
    enumerable: true,
    get() {
      getterCalls += 1;
      return { reported_command_ids: [1000, 1017, 1025, 1033, 1035] };
    },
  });
  assert.throws(
    () => normalizeChameleonBootstrapResponse(
      fakeDecoded,
      evidence.allocation,
      evidence.witness,
      grant,
    ),
    /source-owned parser aggregation/u,
  );
  assert.equal(getterCalls, 0);
});

test("native bootstrap sequence guard is grant-bound, exact, inert, and fail-closed", () => {
  const registry = effectRegistry();
  const expected = {
    "instrument.inventory": [1000, 1017, 1033],
    "instrument.capabilities": [1035],
    "instrument.health": [1025],
  };
  assert.equal(NATIVE_BOOTSTRAP_SEQUENCE_ASSURANCE.import_is_inert, true);
  assert.equal(NATIVE_BOOTSTRAP_SEQUENCE_ASSURANCE.hardware_effect, false);
  assert.equal(NATIVE_BOOTSTRAP_SEQUENCE_ASSURANCE.production_ready, false);

  for (const [operationId, commandIds] of Object.entries(expected)) {
    const grant = grantFor(registry, operationId);
    const compiled = compileChameleonBootstrapOperation(grant);
    const guard = createNativeBootstrapSequenceGuard(compiled);
    assert.throws(
      () => claimNativeBootstrapSequenceStep(guard, { command_sequence: 2 }),
      (error) => error.code === "chameleon_native_bootstrap_sequence_rejected"
        && error.reason_code === "sequence_reorder_or_omission",
    );
    assert.throws(
      () => completeNativeBootstrapSequence(guard),
      (error) => error.reason_code === "sequence_incomplete",
    );
    const bindings = [];
    for (let index = 0; index < commandIds.length; index += 1) {
      const sequence = index + 1;
      const binding = claimNativeBootstrapSequenceStep(guard, {
        command_sequence: sequence,
      });
      assert.equal(assertNativeBootstrapCommandBinding(binding), binding);
      assert.equal(binding.operation_id, operationId);
      assert.equal(binding.operation_digest, compiled.operation_digest);
      assert.equal(binding.command_set_digest, compiled.command_set_digest);
      assert.equal(binding.command_sequence, sequence);
      assert.equal(binding.command_id, commandIds[index]);
      assert.equal(binding.request_payload_byte_length, 0);
      assert.equal(binding.bootstrap_grant_projection_digest,
        compiled.bootstrap_grant_projection_digest);
      bindings.push(binding);
      assert.throws(
        () => claimNativeBootstrapSequenceStep(guard, { command_sequence: sequence }),
        (error) => ["sequence_duplicate_or_replay", "sequence_has_no_remaining_commands"]
          .includes(error.reason_code),
      );
    }
    const completion = completeNativeBootstrapSequence(guard);
    assert.equal(assertNativeBootstrapSequenceCompletion(completion), completion);
    assert.equal(completion.semantic_admission_complete, true);
    assert.equal(completion.device_effect_performed, false);
    assert.equal(completion.production_ready, false);
    assert.deepEqual(bindings.map((binding) => binding.command_id), commandIds);
    assert.throws(() => completeNativeBootstrapSequence(guard),
      (error) => error.reason_code === "sequence_already_completed");
  }
});
