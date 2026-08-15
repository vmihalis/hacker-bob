"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");

const payloadCodec = require("../lib/bootstrap-response-payloads.js");
const {
  BOOTSTRAP_RESPONSE_PAYLOAD_VERSION,
  CHAMELEON_GET_APP_VERSION_RESPONSE_SCHEMA,
  CHAMELEON_SUCCESS_STATUS,
  CHAMELEON_V220_BOOTSTRAP_RESPONSE_PAYLOAD_PROFILE,
  aggregateChameleonBootstrapResponsePayloads,
  assertChameleonBootstrapDecodedPayload,
  assertChameleonGetAppVersionDecodedPayload,
  decodeChameleonGetAppVersionResponsePayload,
} = payloadCodec;
const {
  BOOTSTRAP_INVARIANT_WITNESS_DOMAIN,
  BOOTSTRAP_INVARIANT_WITNESS_KEY_USAGE,
  CHAMELEON_BOOTSTRAP_MANIFEST,
  CHAMELEON_BOOTSTRAP_OPERATION_REGISTRY,
  BOOTSTRAP_INVARIANTS_DIGEST,
  allocateChameleonBootstrapResponseReceipt,
  bootstrapInvariantWitnessSignatureInputDigest,
  compileChameleonBootstrapOperation,
  createChameleonBootstrapGrantAttenuator,
  createChameleonBootstrapInvariantWitnessVerifier,
  createChameleonBootstrapReceiptAllocator,
  normalizeChameleonBootstrapResponse,
  projectChameleonBootstrapGrant,
  verifyChameleonBootstrapInvariantWitness,
} = require("../lib/bootstrap-operations.js");
const {
  FIXED_FRAME_BYTES,
  SOF,
  SOF_LRC,
  V2_2_0_PROFILE_PINS,
  calculateLrc,
  createFrameParser,
} = require("../lib/codec.js");
const {
  PHYSICAL_BOOTSTRAP_GRANT_DOMAIN,
  PHYSICAL_BOOTSTRAP_GRANT_KEY_USAGE,
  createPhysicalBootstrapGrantVerifier,
  normalizeMcpPhysicalExecutionRequest,
  physicalBootstrapGrantSignatureInputDigest,
  projectVerifiedPhysicalBootstrapGrant,
} = require("../../../mcp/domains/physical/physical-authority.js");
const {
  normalizePhysicalScopeNucleusAxis,
} = require("../../../mcp/core/governance/index.js");
const {
  TRUSTED_CLOCK_MAPPING_DOMAIN,
  createPhysicalTrustedClockPort,
  physicalClockMappingSigningMessage,
  publicKeyDigest,
} = require("../../../mcp/domains/physical/physical-trusted-clock.js");
const {
  buildEffectTemplateRegistry,
} = require("../../../mcp/core/requested-effects.js");
const {
  hashCanonicalJson,
} = require("../../../mcp/core/verification/verification-contracts.js");

function digest(label) {
  return hashCanonicalJson({ label });
}

function effectRegistry() {
  return buildEffectTemplateRegistry([{
    version: 1,
    template_id: "instrument.observe.usb.v1",
    subject_kind: "instrument",
    action: "observe",
    channel: "usb",
    persistence: "none",
    bounds: {},
  }]);
}

function signedClock(now) {
  const keyPair = crypto.generateKeyPairSync("ed25519");
  const payload = {
    version: 1,
    clock_id: "physical-clock:chameleon-payload-test",
    monotonic_epoch_id: digest("chameleon-payload-clock-epoch"),
    mapping_generation: 1,
    reference_monotonic_ms: 0,
    reference_utc: "2026-07-18T00:00:00.000Z",
    max_uncertainty_ms: 0,
    not_before: "2026-07-17T23:59:00.000Z",
    expires_at: "2026-07-18T01:00:00.000Z",
    trust_root_epoch: 3,
    authority_epoch: 7,
    revocation_generation: 2,
    signer_key_id: "clock-key:chameleon-payload-test",
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
  const mapping = { ...basis, signed_mapping_digest: hashCanonicalJson(basis) };
  return createPhysicalTrustedClockPort({
    port_id: "chameleon_payload_test_clock",
    clock_id: payload.clock_id,
    monotonic_epoch_id: payload.monotonic_epoch_id,
    uncertainty_ceiling_ms: 0,
    read_monotonic_ms: () => Date.parse(now) - Date.parse(payload.reference_utc),
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

function compiledFixture(operationId) {
  const now = "2026-07-18T00:00:10.000Z";
  const registry = effectRegistry();
  const template = registry.get("instrument.observe.usb.v1");
  const request = normalizeMcpPhysicalExecutionRequest({
    version: 1,
    grant_kind: "bootstrap",
    session_id: `session-chameleon-payload-${operationId.split(".").at(-1)}`,
    session_nucleus_hash: digest(`nucleus-${operationId}`),
    caller_role_id: "orchestrator",
    requester_principal_id: "principal:chameleon-payload-requester",
    ipc_peer_principal_id: "principal:chameleon-payload-ipc-peer",
    execution_principal_id: "principal:chameleon-payload-worker",
    instrument_ref: "instrument:chameleon-payload-candidate",
    operation_id: operationId,
    parameter_digest: hashCanonicalJson({}),
    authority_epoch: 7,
    revocation_generation: 2,
    nonce: `chameleon-payload-${operationId.split(".").at(-1)}-nonce`,
    sequence: 1,
    not_before: "2026-07-18T00:00:00.000Z",
    expires_at: "2026-07-18T00:01:00.000Z",
    requested_effects: [{
      version: 1,
      template_id: template.template_id,
      template_digest: template.template_digest,
      subject_ref: "instrument:chameleon-payload-candidate",
      subject_kind: template.subject_kind,
      action: template.action,
      channel: template.channel,
      persistence: template.persistence,
      bounds: {},
    }],
    enrollment_candidate_ref: "enrollment-candidate:chameleon-payload-reader",
    bootstrap_manifest_digest: CHAMELEON_BOOTSTRAP_MANIFEST.manifest_digest,
    provider_binary_digest: digest("chameleon-payload-provider-binary"),
    transport_digest: digest("chameleon-payload-transport"),
    rf_state: "off",
  }, registry);
  const operation = CHAMELEON_BOOTSTRAP_OPERATION_REGISTRY.get(operationId);
  const providerDescriptorDigest = digest("chameleon-payload-provider-descriptor");
  const bindings = {
    execution_request: request,
    effect_registry: registry,
    provider_id: "chameleon_ultra",
    provider_descriptor_digest: providerDescriptorDigest,
    operation_digest: operation.operation_digest,
    bootstrap_invariants_digest: BOOTSTRAP_INVARIANTS_DIGEST,
  };
  const axis = normalizePhysicalScopeNucleusAxis({
    version: 1,
    physical_enabled: true,
    policy_version: 1,
    policy_id: "chameleon-payload-test-policy",
    policy_digest: digest("chameleon-payload-policy"),
    projection_version: 1,
    projection_digest: digest("chameleon-payload-scope-projection"),
    provenance_digest: digest("chameleon-payload-scope-provenance"),
    compatibility_digest: digest("chameleon-payload-scope-compatibility"),
    transition_receipt_registry_digest: digest("chameleon-payload-transition-registry"),
    authority_epoch: 7,
    revocation_generation: 2,
  });
  const issuerKeys = crypto.generateKeyPairSync("ed25519");
  const issuerPublicKeyDigest = crypto.createHash("sha256").update(
    issuerKeys.publicKey.export({ type: "spki", format: "der" }),
  ).digest("hex");
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
    provider_id: "chameleon_ultra",
    provider_descriptor_digest: providerDescriptorDigest,
    instrument_ref: request.instrument_ref,
    enrollment_candidate_ref: request.enrollment_candidate_ref,
    bootstrap_manifest_digest: request.bootstrap_manifest_digest,
    provider_binary_digest: request.provider_binary_digest,
    transport_digest: request.transport_digest,
    operation_id: request.operation_id,
    operation_digest: operation.operation_digest,
    parameter_digest: request.parameter_digest,
    requested_effects_digest: request.requested_effects_digest,
    bootstrap_invariants_digest: BOOTSTRAP_INVARIANTS_DIGEST,
    authority_decision: "allow",
    authority_reason: "exact_allow",
    authority_resolution_digest: digest("chameleon-payload-authority-resolution"),
    trust_root_id: "trust-root:chameleon-payload-test",
    trust_root_epoch: 6,
    trust_registry_digest: digest("chameleon-payload-trust-registry"),
    trust_root_trusted: true,
    trust_root_revoked: false,
    issuer_principal_id: "principal:chameleon-payload-authority",
    issuer_key_id: "signer-key:chameleon-payload-authority",
    issuer_epoch: 3,
    issuer_public_key_digest: issuerPublicKeyDigest,
    key_usage: PHYSICAL_BOOTSTRAP_GRANT_KEY_USAGE,
    issuer_trusted: true,
    issuer_revoked: false,
  };
  const verifier = createPhysicalBootstrapGrantVerifier({
    verifier_id: `chameleon-payload-${operationId.split(".").at(-1)}-verifier`,
    trusted_clock_port: signedClock(now),
    resolve_current_authority: () => authority,
    verify_ed25519: (verification) => crypto.verify(
      null,
      Buffer.from(verification.signature_input_digest, "hex"),
      issuerKeys.publicKey,
      Buffer.from(verification.signature, "base64url"),
    ),
    reserve_replay: (claim) => {
      const receipt = {
        version: 1,
        reservation_ref: `bootstrap-grant-replay-reservation:${hashCanonicalJson(claim).slice(0, 40)}`,
        replay_claim: claim,
        replay_claim_digest: hashCanonicalJson(claim),
        generation: 1,
        previous_receipt_digest: null,
        reserved_at: now,
        fsynced_at: now,
      };
      return {
        version: 1,
        disposition: "created",
        reservation_receipt: { ...receipt, receipt_digest: hashCanonicalJson(receipt) },
      };
    },
  });
  const payload = {
    version: 1,
    grant_kind: "bootstrap",
    grant_ref: `physical-grant:chameleon-payload-${operationId.split(".").at(-1)}`,
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
    provider_id: "chameleon_ultra",
    provider_descriptor_digest: providerDescriptorDigest,
    instrument_ref: request.instrument_ref,
    enrollment_candidate_ref: request.enrollment_candidate_ref,
    bootstrap_manifest_digest: request.bootstrap_manifest_digest,
    provider_binary_digest: request.provider_binary_digest,
    transport_digest: request.transport_digest,
    operation_id: request.operation_id,
    operation_digest: operation.operation_digest,
    parameter_digest: request.parameter_digest,
    requested_effects_digest: request.requested_effects_digest,
    bootstrap_invariants_digest: BOOTSTRAP_INVARIANTS_DIGEST,
    rf_state: request.rf_state,
    authority_decision: "allow",
    authority_reason: "exact_allow",
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
    issuer_public_key_digest: issuerPublicKeyDigest,
    signed_at: "2026-07-18T00:00:05.000Z",
    signed_payload_digest: hashCanonicalJson(payload),
  };
  const signature = crypto.sign(
    null,
    Buffer.from(physicalBootstrapGrantSignatureInputDigest(payload, authentication), "hex"),
    issuerKeys.privateKey,
  ).toString("base64url");
  const coreGrant = projectVerifiedPhysicalBootstrapGrant({
    version: 1,
    kind: "physical_bootstrap_grant",
    domain: PHYSICAL_BOOTSTRAP_GRANT_DOMAIN,
    payload,
    authentication: { ...authentication, signature },
  }, verifier, bindings);
  const attenuator = createChameleonBootstrapGrantAttenuator({
    attenuator_id: `chameleon-payload-${operationId.split(".").at(-1)}-attenuator`,
    bootstrap_grant_verifier: verifier,
    provider_descriptor_digest: providerDescriptorDigest,
    provider_binary_digest: request.provider_binary_digest,
    transport_digest: request.transport_digest,
  });
  const grant = projectChameleonBootstrapGrant(coreGrant, attenuator);
  return { grant, compiled: compileChameleonBootstrapOperation(grant) };
}

function wireFrame(command, status, dataInput) {
  const data = Buffer.from(dataInput);
  const frame = Buffer.alloc(FIXED_FRAME_BYTES + data.length);
  frame[0] = SOF;
  frame[1] = SOF_LRC;
  frame.writeUInt16BE(command, 2);
  frame.writeUInt16BE(status, 4);
  frame.writeUInt16BE(data.length, 6);
  frame[8] = calculateLrc(frame.subarray(2, 8));
  data.copy(frame, 9);
  frame[9 + data.length] = calculateLrc(data);
  return frame;
}

function decodedFrames(entries, prefix = Buffer.alloc(0)) {
  const result = createFrameParser().push(Buffer.concat([
    prefix,
    ...entries.map(([command, data, status = CHAMELEON_SUCCESS_STATUS]) => (
      wireFrame(command, status, data)
    )),
  ]));
  assert.equal(result.frames.length, entries.length);
  return result.frames;
}

function containsBytes(value, seen = new Set()) {
  if (Buffer.isBuffer(value) || value instanceof Uint8Array) return true;
  if (!value || typeof value !== "object" || seen.has(value)) return false;
  seen.add(value);
  return Object.values(value).some((child) => containsBytes(child, seen));
}

let evidenceFixtureSequence = 0;

function authenticatedInvariantWitness(fixture, decoded, options = {}) {
  evidenceFixtureSequence += 1;
  const keyPair = options.key_pair || crypto.generateKeyPairSync("ed25519");
  const signerPublicKeyDigest = publicKeyDigest(keyPair.publicKey);
  const payload = {
    version: 1,
    provider_id: "chameleon_ultra",
    bootstrap_grant_projection_digest: fixture.grant.bootstrap_grant_projection_digest,
    execution_request_digest: fixture.grant.execution_request_digest,
    operation_id: fixture.grant.operation_id,
    operation_digest: fixture.grant.operation_digest,
    command_set_digest: fixture.grant.command_set_digest,
    decoded_payload_digest: decoded.decoded_payload_digest,
    instrument_ref: fixture.grant.instrument_ref,
    enrollment_candidate_ref: fixture.grant.enrollment_candidate_ref,
    bootstrap_invariants_digest: BOOTSTRAP_INVARIANTS_DIGEST,
    witness_principal_id: "principal:chameleon-bootstrap-observer",
    observed_at: options.observed_at || "2026-07-18T00:00:20.000Z",
    rf_invariant_verdict: "pending_independent_observation_hil",
    mode_invariant_verdict: "not_observed_get_device_mode_not_allowlisted",
    workspace_invariant_verdict: "satisfied_by_closed_command_effect_manifest",
    workspace_write_count: 0,
    independent_observation_hil_status: "not_performed",
    ...(options.payload || {}),
  };
  const authentication = {
    version: 1,
    method: "ed25519",
    key_usage: BOOTSTRAP_INVARIANT_WITNESS_KEY_USAGE,
    trust_root_id: "trust-root:chameleon-bootstrap-observer",
    trust_root_epoch: 1,
    trust_registry_digest: digest("chameleon-bootstrap-observer-trust-registry"),
    signer_key_id: "signer-key:chameleon-bootstrap-observer",
    signer_epoch: 1,
    signer_public_key_digest: signerPublicKeyDigest,
    signed_at: "2026-07-18T00:00:25.000Z",
    expires_at: "2026-07-18T00:00:50.000Z",
    signed_payload_digest: hashCanonicalJson(payload),
    ...(options.authentication || {}),
  };
  const signature = crypto.sign(
    null,
    Buffer.from(bootstrapInvariantWitnessSignatureInputDigest(payload, authentication), "hex"),
    keyPair.privateKey,
  ).toString("base64url");
  const envelope = {
    version: 1,
    kind: "chameleon_bootstrap_invariant_witness",
    domain: BOOTSTRAP_INVARIANT_WITNESS_DOMAIN,
    payload,
    authentication: { ...authentication, signature },
  };
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
    ...(options.trust || {}),
  };
  const verifier = createChameleonBootstrapInvariantWitnessVerifier({
    verifier_id: `chameleon-payload-witness-verifier-${evidenceFixtureSequence}`,
    trusted_clock_port: signedClock(options.now || "2026-07-18T00:00:30.000Z"),
    resolve_current_trust: options.resolve_current_trust || (() => trust),
    verify_ed25519: options.verify_ed25519 || ((verification) => crypto.verify(
      null,
      Buffer.from(verification.signature_input_digest, "hex"),
      keyPair.publicKey,
      Buffer.from(verification.signature, "base64url"),
    )),
  });
  const envelopeInput = typeof options.mutate_envelope === "function"
    ? options.mutate_envelope(envelope)
    : (options.envelope || envelope);
  const witness = verifyChameleonBootstrapInvariantWitness(
    envelopeInput,
    decoded,
    fixture.grant,
    verifier,
  );
  return { envelope, keyPair, trust, verifier, witness };
}

function acknowledgedReceiptAllocation(fixture, decoded, witness, options = {}) {
  evidenceFixtureSequence += 1;
  const committed = new Map();
  const allocator = createChameleonBootstrapReceiptAllocator({
    allocator_id: `chameleon-payload-receipt-allocator-${evidenceFixtureSequence}`,
    commit_allocation: options.commit_allocation || ((allocation) => {
      committed.set(allocation.receipt_ref, allocation);
      return true;
    }),
    resolve_committed_allocation: options.resolve_committed_allocation
      || ((receiptRef) => committed.get(receiptRef)),
  });
  const allocation = allocateChameleonBootstrapResponseReceipt(
    decoded,
    witness,
    fixture.grant,
    allocator,
  );
  return { allocation, allocator, committed };
}

function normalizedResponse(fixture, decoded, options = {}) {
  const witnessed = authenticatedInvariantWitness(fixture, decoded, options.witness);
  const allocated = acknowledgedReceiptAllocation(
    fixture,
    decoded,
    witnessed.witness,
    options.allocation,
  );
  return {
    normalized: normalizeChameleonBootstrapResponse(
      decoded,
      allocated.allocation,
      witnessed.witness,
      fixture.grant,
    ),
    ...witnessed,
    ...allocated,
  };
}

test("source-pinned profile and export surface are closed, pure, and byte-free", () => {
  assert.deepEqual(Object.keys(payloadCodec).sort(), [
    "BOOTSTRAP_RESPONSE_PAYLOAD_VERSION",
    "CHAMELEON_GET_APP_VERSION_RESPONSE_SCHEMA",
    "CHAMELEON_SUCCESS_STATUS",
    "CHAMELEON_V220_BOOTSTRAP_RESPONSE_PAYLOAD_PROFILE",
    "aggregateChameleonBootstrapResponsePayloads",
    "assertChameleonBootstrapDecodedPayload",
    "assertChameleonGetAppVersionDecodedPayload",
    "decodeChameleonGetAppVersionResponsePayload",
  ].sort());
  assert.equal(BOOTSTRAP_RESPONSE_PAYLOAD_VERSION, 1);
  assert.equal(CHAMELEON_SUCCESS_STATUS, 0x68);
  assert.deepEqual(
    CHAMELEON_V220_BOOTSTRAP_RESPONSE_PAYLOAD_PROFILE.source_pins,
    V2_2_0_PROFILE_PINS,
  );
  assert.equal(Object.isFrozen(CHAMELEON_V220_BOOTSTRAP_RESPONSE_PAYLOAD_PROFILE), true);
  assert.equal(Object.isFrozen(CHAMELEON_GET_APP_VERSION_RESPONSE_SCHEMA), true);
  assert.equal(CHAMELEON_GET_APP_VERSION_RESPONSE_SCHEMA.command_id, 1000);
  assert.equal(CHAMELEON_GET_APP_VERSION_RESPONSE_SCHEMA.response_success_status, 0x68);
  assert.equal(CHAMELEON_GET_APP_VERSION_RESPONSE_SCHEMA.response_payload_exact_byte_length, 2);
  assert.deepEqual(
    Object.keys(CHAMELEON_V220_BOOTSTRAP_RESPONSE_PAYLOAD_PROFILE.command_payload_shapes),
    ["1000", "1017", "1025", "1033", "1035"],
  );
  assert.equal(
    Object.hasOwn(CHAMELEON_V220_BOOTSTRAP_RESPONSE_PAYLOAD_PROFILE.command_payload_shapes, "1002"),
    false,
    "GET_DEVICE_MODE stays outside the negative-only bootstrap decoder",
  );
  const source = fs.readFileSync(
    path.join(__dirname, "..", "lib", "bootstrap-response-payloads.js"),
    "utf8",
  );
  assert.doesNotMatch(source, /require\(["'](?:node:)?(?:fs|net|dgram|child_process|serialport)["']\)/u);
  assert.doesNotMatch(source, /openDevice|navigator\.serial|createConnection|writeFile/u);
});

test("fixed get_app_version decoder is byte-free, exact, and type-distinct", () => {
  const [frame] = decodedFrames([[1000, [2, 2]]]);
  const decoded = decodeChameleonGetAppVersionResponsePayload(frame);
  assert.equal(assertChameleonGetAppVersionDecodedPayload(decoded), decoded);
  assert.equal(decoded.response_fields.application_version, "2.2");
  assert.equal(decoded.operation_schema_digest,
    CHAMELEON_GET_APP_VERSION_RESPONSE_SCHEMA.operation_schema_digest);
  assert.equal(containsBytes(decoded), false);
  assert.throws(
    () => assertChameleonBootstrapDecodedPayload(decoded),
    /source-owned parser aggregation/u,
  );
  assert.throws(
    () => assertChameleonGetAppVersionDecodedPayload({ ...decoded }),
    /fixed source-owned validator/u,
  );
  for (const [command, status, data] of [
    [1001, CHAMELEON_SUCCESS_STATUS, [2, 2]],
    [1000, 0x0067, [2, 2]],
    [1000, CHAMELEON_SUCCESS_STATUS, [2]],
    [1000, CHAMELEON_SUCCESS_STATUS, [2, 2, 0]],
  ]) {
    const [invalid] = decodedFrames([[command, data, status]]);
    assert.throws(
      () => decodeChameleonGetAppVersionResponsePayload(invalid),
      /command must be 1000|success status 0x0068|exactly 2 payload bytes/u,
    );
  }
});

test("inventory frames decode in compiled order and feed response normalization without fake witnesses", () => {
  const fixture = compiledFixture("instrument.inventory");
  const frames = decodedFrames([
    [1000, [2, 2]],
    [1017, Buffer.from("v2.2.0-7-gf349dbe", "utf8")],
    [1033, [0]],
  ]);
  const decoded = aggregateChameleonBootstrapResponsePayloads(fixture.compiled, frames);
  assert.deepEqual(decoded.response_fields, {
    application_version: "2.2",
    git_revision: "v2.2.0-7-gf349dbe",
    model: "Chameleon Ultra",
  });
  assert.deepEqual(decoded.command_ids, [1000, 1017, 1033]);
  assert.equal(decoded.compiled_operation_digest, fixture.compiled.compiled_operation_digest);
  assert.equal(decoded.trusted_clock_mode, "signed_monotonic_wall_mapping");
  assert.equal(decoded.bootstrap_grant_projection_digest,
    fixture.grant.bootstrap_grant_projection_digest);
  assert.equal(Object.isFrozen(decoded), true);
  assert.equal(Object.isFrozen(decoded.response_fields), true);
  assert.equal(containsBytes(decoded), false);
  for (const forbidden of [
    "observed_at", "rf_state_before", "rf_state_after", "mode_state_before_digest",
    "mode_state_after_digest", "workspace_write_count",
  ]) {
    assert.equal(Object.hasOwn(decoded, forbidden), false);
    assert.equal(Object.hasOwn(decoded.response_fields, forbidden), false);
  }

  assert.equal(assertChameleonBootstrapDecodedPayload(decoded), decoded);
  const { normalized } = normalizedResponse(fixture, decoded);
  assert.equal(normalized.application_version, "2.2");
  assert.equal(normalized.model, "Chameleon Ultra");
  assert.equal(normalized.invariants.rf_remained_off, null);
  assert.equal(normalized.invariants.mode_unchanged, null);
  assert.equal(normalized.invariants.workspace_unchanged, true);
  assert.equal(normalized.production_ready, false);
  assert.equal(normalized.execution_authority, false);
  assert.equal(normalized.lifecycle_authority, false);
});

test("health and capabilities decode network-order source shapes honestly", () => {
  const health = compiledFixture("instrument.health");
  const healthDecoded = aggregateChameleonBootstrapResponsePayloads(
    health.compiled,
    decodedFrames([[1025, [0x0f, 0x87, 83]]]),
  );
  assert.deepEqual(healthDecoded.response_fields, {
    battery: { percent: 83, voltage_mv: 3975, charging_state: "not_reported" },
  });
  assert.equal(normalizedResponse(health, healthDecoded).normalized.battery.charging_state,
    "not_reported");

  const capabilities = compiledFixture("instrument.capabilities");
  const capabilitiesDecoded = aggregateChameleonBootstrapResponsePayloads(
    capabilities.compiled,
    decodedFrames([[1035, [0x03, 0xe8, 0x03, 0xf9, 0xff, 0xfe]]]),
  );
  assert.deepEqual(capabilitiesDecoded.response_fields.reported_command_ids, [1000, 1017, 65534]);
  assert.equal(containsBytes(capabilitiesDecoded), false);

  const lite = compiledFixture("instrument.inventory");
  assert.equal(aggregateChameleonBootstrapResponsePayloads(lite.compiled, decodedFrames([
    [1000, [2, 2]], [1017, Buffer.from("v2.2.0")], [1033, [1]],
  ])).response_fields.model, "Chameleon Lite");
});

test("response normalization requires the branded evidence chain and mints no caller-selected refs", () => {
  const fixture = compiledFixture("instrument.inventory");
  const decoded = aggregateChameleonBootstrapResponsePayloads(fixture.compiled, decodedFrames([
    [1000, [2, 2]], [1017, Buffer.from("v2.2.0")], [1033, [0]],
  ]));
  const artifacts = normalizedResponse(fixture, decoded);
  const { allocation, normalized, witness } = artifacts;

  assert.equal(normalized.observation_ref,
    `bootstrap-observation:v1:${normalized.observation_digest}`);
  assert.equal(normalized.receipt_ref, `bootstrap-receipt:v1:${normalized.receipt_digest}`);
  assert.equal(normalized.receipt_allocation_assurance, "fixture_source_acknowledged");
  assert.deepEqual(normalized.production_readiness_blockers, [
    "independent_rf_observation_hil_not_performed",
    "device_mode_not_observed_get_device_mode_not_allowlisted",
    "durable_receipt_store_not_authenticated",
    "durable_bootstrap_attempt_dispatch_binding_absent",
    "usb_connection_generation_binding_absent",
  ]);
  assert.equal(JSON.stringify(normalized).includes(artifacts.envelope.authentication.signature), false);
  for (const callerAssertion of [
    "rf_state_before", "rf_state_after", "mode_state_before_digest",
    "mode_state_after_digest", "workspace_write_count",
  ]) {
    assert.equal(Object.hasOwn(normalized, callerAssertion), false);
  }

  assert.throws(
    () => normalizeChameleonBootstrapResponse(
      { ...decoded }, allocation, witness, fixture.grant,
    ),
    /source-owned parser aggregation/,
  );
  assert.throws(
    () => normalizeChameleonBootstrapResponse(
      decoded, { ...allocation }, witness, fixture.grant,
    ),
    /source-acknowledged and canonically resolved/,
  );
  assert.throws(
    () => normalizeChameleonBootstrapResponse(
      decoded, allocation, { ...witness }, fixture.grant,
    ),
    /must be authenticated/,
  );
  assert.throws(
    () => normalizeChameleonBootstrapResponse(
      decoded, allocation, witness, { ...fixture.grant },
    ),
    /signed core authority and closed Chameleon attenuator/,
  );
  assert.throws(
    () => normalizeChameleonBootstrapResponse({
      rf_state_before: "off",
      rf_state_after: "off",
      mode_state_before_digest: digest("caller-mode"),
      mode_state_after_digest: digest("caller-mode"),
      workspace_write_count: 0,
      observation_ref: "bootstrap-observation:caller",
      receipt_ref: "bootstrap-receipt:caller",
    }, allocation, witness, fixture.grant),
    /source-owned parser aggregation/,
  );
});

test("authenticated invariant witnesses reject stronger RF, mode, workspace, and HIL claims", () => {
  for (const [payload, pattern] of [
    [{ rf_invariant_verdict: "rf_remained_off" }, /pending independent observation\/HIL/],
    [{ mode_invariant_verdict: "mode_unchanged" }, /command 1002 is not allowlisted/],
    [{ workspace_write_count: 1 }, /closed no-write command manifest/],
    [{ workspace_invariant_verdict: "observed_unchanged" }, /closed no-write command manifest/],
    [{ independent_observation_hil_status: "performed" }, /must remain not_performed/],
  ]) {
    const fixture = compiledFixture("instrument.health");
    const decoded = aggregateChameleonBootstrapResponsePayloads(
      fixture.compiled,
      decodedFrames([[1025, [0x0f, 0x87, 83]]]),
    );
    assert.throws(() => authenticatedInvariantWitness(fixture, decoded, { payload }), pattern);
  }

  {
    const fixture = compiledFixture("instrument.health");
    const decoded = aggregateChameleonBootstrapResponsePayloads(
      fixture.compiled,
      decodedFrames([[1025, [0x0f, 0x87, 83]]]),
    );
    assert.throws(
      () => authenticatedInvariantWitness(fixture, decoded, {
        mutate_envelope: (envelope) => ({
          ...envelope,
          authentication: {
            ...envelope.authentication,
            signature: `${envelope.authentication.signature.slice(0, -1)}${
              envelope.authentication.signature.endsWith("A") ? "Q" : "A"
            }`,
          },
        }),
      }),
      /signature is invalid/,
    );
  }
  {
    const fixture = compiledFixture("instrument.health");
    const decoded = aggregateChameleonBootstrapResponsePayloads(
      fixture.compiled,
      decodedFrames([[1025, [0x0f, 0x87, 83]]]),
    );
    assert.throws(
      () => authenticatedInvariantWitness(fixture, decoded, { trust: { revoked: true } }),
      /signer is not currently trusted/,
    );
  }
  {
    const fixture = compiledFixture("instrument.health");
    const decoded = aggregateChameleonBootstrapResponsePayloads(
      fixture.compiled,
      decodedFrames([[1025, [0x0f, 0x87, 83]]]),
    );
    assert.throws(
      () => authenticatedInvariantWitness(fixture, decoded, {
        observed_at: "2026-07-18T00:01:00.000Z",
        now: "2026-07-18T00:00:30.000Z",
      }),
      /future under trusted clock uncertainty/,
    );
  }
  {
    const fixture = compiledFixture("instrument.health");
    const decoded = aggregateChameleonBootstrapResponsePayloads(
      fixture.compiled,
      decodedFrames([[1025, [0x0f, 0x87, 83]]]),
    );
    assert.throws(
      () => authenticatedInvariantWitness(fixture, decoded, {
        authentication: { signed_at: "2026-07-18T00:00:15.000Z" },
      }),
      /cannot be signed before its observation/,
    );
  }
});

test("receipt allocation must acknowledge and exactly resolve its derived content address", () => {
  function healthEvidence() {
    const fixture = compiledFixture("instrument.health");
    const decoded = aggregateChameleonBootstrapResponsePayloads(
      fixture.compiled,
      decodedFrames([[1025, [0x0f, 0x87, 83]]]),
    );
    const witness = authenticatedInvariantWitness(fixture, decoded).witness;
    return { decoded, fixture, witness };
  }

  {
    const evidence = healthEvidence();
    assert.throws(
      () => acknowledgedReceiptAllocation(evidence.fixture, evidence.decoded, evidence.witness, {
        commit_allocation: () => false,
      }),
      /not acknowledged by its source/,
    );
  }
  {
    const evidence = healthEvidence();
    let prepared;
    assert.throws(
      () => acknowledgedReceiptAllocation(evidence.fixture, evidence.decoded, evidence.witness, {
        commit_allocation: (allocation) => {
          prepared = allocation;
          return true;
        },
        resolve_committed_allocation: () => ({
          ...prepared,
          receipt_ref: `bootstrap-receipt:v1:${digest("substituted-receipt")}`,
        }),
      }),
      /detached from its content-addressed allocation/,
    );
  }
  {
    const evidence = healthEvidence();
    const first = acknowledgedReceiptAllocation(
      evidence.fixture,
      evidence.decoded,
      evidence.witness,
    );
    assert.throws(
      () => allocateChameleonBootstrapResponseReceipt(
        evidence.decoded,
        evidence.witness,
        evidence.fixture.grant,
        first.allocator,
      ),
      /already has a receipt allocation/,
    );
    assert.throws(
      () => allocateChameleonBootstrapResponseReceipt(
        evidence.decoded,
        evidence.witness,
        evidence.fixture.grant,
        first.allocator,
        "bootstrap-receipt:caller-selected",
      ),
      /exactly four bound inputs/,
    );
  }
});

test("only branded compiled operations and parser frames cross the aggregation seam", () => {
  const fixture = compiledFixture("instrument.health");
  const frames = decodedFrames([[1025, [0x0f, 0x87, 83]]]);
  assert.throws(
    () => aggregateChameleonBootstrapResponsePayloads({ ...fixture.compiled }, frames),
    /closed grant compiler/,
  );
  assert.throws(
    () => aggregateChameleonBootstrapResponsePayloads(fixture.compiled, [{
      command: 1025,
      status: 0x68,
      stream_tainted: false,
      data: Buffer.from([0x0f, 0x87, 83]),
    }]),
    /live Chameleon frame parser/,
  );
});

test("status, order, cardinality, and parser taint fail closed", () => {
  const inventory = compiledFixture("instrument.inventory");
  const valid = decodedFrames([
    [1000, [2, 2]], [1017, Buffer.from("v2.2.0")], [1033, [0]],
  ]);
  assert.throws(
    () => aggregateChameleonBootstrapResponsePayloads(inventory.compiled, valid.slice(0, 2)),
    /cardinality/,
  );
  assert.throws(
    () => aggregateChameleonBootstrapResponsePayloads(inventory.compiled, [...valid, valid[0]]),
    /cardinality/,
  );
  assert.throws(
    () => aggregateChameleonBootstrapResponsePayloads(
      inventory.compiled,
      decodedFrames([[1017, Buffer.from("v2.2.0")], [1000, [2, 2]], [1033, [0]]]),
    ),
    /compiled command order/,
  );
  assert.throws(
    () => aggregateChameleonBootstrapResponsePayloads(
      inventory.compiled,
      decodedFrames([[1000, [2, 2], 0], [1017, Buffer.from("v2.2.0")], [1033, [0]]]),
    ),
    /status must be Chameleon success status 0x0068/,
  );
  assert.throws(
    () => aggregateChameleonBootstrapResponsePayloads(
      inventory.compiled,
      decodedFrames(
        [[1000, [2, 2]], [1017, Buffer.from("v2.2.0")], [1033, [0]]],
        Buffer.from([0xaa]),
      ),
    ),
    /tainted parser stream/,
  );
});

test("every source-pinned payload shape rejects truncation, extension, and invalid semantics", () => {
  const inventory = compiledFixture("instrument.inventory");
  const inventoryCases = [
    [[[1000, [2]], [1017, Buffer.from("v2.2.0")], [1033, [0]]], /exactly 2 payload bytes/],
    [[[1000, [2, 2, 0]], [1017, Buffer.from("v2.2.0")], [1033, [0]]], /exactly 2 payload bytes/],
    [[[1000, [2, 2]], [1017, Buffer.from([0xc3, 0x28])], [1033, [0]]], /strict UTF-8/],
    [[[1000, [2, 2]], [1017, Buffer.alloc(129, 0x61)], [1033, [0]]], /1-128 strict UTF-8 bytes/],
    [[[1000, [2, 2]], [1017, Buffer.from(" v2.2.0")], [1033, [0]]], /display-safe Git metadata/],
    [[[1000, [2, 2]], [1017, Buffer.from("v2.2.0\0")], [1033, [0]]], /display-safe Git metadata/],
    [[[1000, [2, 2]], [1017, Buffer.from("v2.2.0\u202egit")], [1033, [0]]], /display-safe Git metadata/],
    [[[1000, [2, 2]], [1017, Buffer.from("v2.2.0")], [1033, []]], /exactly 1 payload bytes/],
    [[[1000, [2, 2]], [1017, Buffer.from("v2.2.0")], [1033, [2]]], /unknown v2.2.0 device model/],
  ];
  for (const [entries, pattern] of inventoryCases) {
    assert.throws(
      () => aggregateChameleonBootstrapResponsePayloads(
        inventory.compiled,
        decodedFrames(entries),
      ),
      pattern,
    );
  }

  for (const [data, pattern] of [
    [[], /non-empty bounded big-endian u16 list/],
    [[0x03], /non-empty bounded big-endian u16 list/],
    [[0x03, 0xe8, 0x03, 0xe8], /duplicate command IDs/],
  ]) {
    const fixture = compiledFixture("instrument.capabilities");
    assert.throws(
      () => aggregateChameleonBootstrapResponsePayloads(
        fixture.compiled,
        decodedFrames([[1035, data]]),
      ),
      pattern,
    );
  }

  for (const [data, pattern] of [
    [[0x0f, 0x87], /exactly 3 payload bytes/],
    [[0x0f, 0x87, 83, 1], /exactly 3 payload bytes/],
    [[0x27, 0x11, 83], /battery voltage exceeds 10000 mV/],
    [[0x0f, 0x87, 101], /battery percentage must be 0-100/],
  ]) {
    const fixture = compiledFixture("instrument.health");
    assert.throws(
      () => aggregateChameleonBootstrapResponsePayloads(
        fixture.compiled,
        decodedFrames([[1025, data]]),
      ),
      pattern,
    );
  }
});
