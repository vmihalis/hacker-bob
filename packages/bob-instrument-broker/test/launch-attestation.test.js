"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");

const {
  LAUNCH_ATTESTATION_DOMAIN,
  LAUNCH_ATTESTATION_MAX_LIFETIME_MS,
  LAUNCH_ATTESTATION_ROLES,
  assertConformanceLaunchAttestationSigner,
  assertConformanceLaunchAttestationVerifier,
  assertConformanceLaunchHostResolver,
  assertConformanceLaunchReplayPort,
  assertVerifiedLaunchAttestation,
  createConformanceLaunchAttestationSigner,
  createConformanceLaunchAttestationVerifier,
  createConformanceLaunchHostResolver,
  createConformanceLaunchReplayPort,
  launchAttestationAuthorityStateDigest,
  launchHostSnapshotDigest,
  launchProcessInstanceBindingDigest,
  launchProfileDigest,
  launchReplayReceiptDigest,
  normalizeLaunchAttestationPayload,
  normalizeSignedLaunchAttestation,
  signLaunchAttestation,
  verifyAndReserveLaunchAttestation,
} = require("../lib/launch-attestation.js");
const {
  publicKeyDigest,
} = require("../lib/ipc-contract.js");
const {
  hashCanonicalJson,
} = require("../../../mcp/core/verification/verification-contracts.js");

const FIXED_NOW = "2026-07-19T04:00:00.000Z";
const HOST_FIELDS = Object.freeze([
  "host_snapshot_scheme",
  "os_platform",
  "os_architecture",
  "os_effective_uid",
  "os_effective_gid",
  "os_real_uid",
  "os_real_gid",
  "process_id",
  "process_credential_scheme",
  "process_credential_digest",
  "process_start_token_digest",
  "runtime_implementation",
  "runtime_abi",
  "runtime_implementation_digest",
  "native_inspector_measurement_scheme",
  "native_inspector_implementation_digest",
  "native_inspector_measurement_digest",
  "native_inspector_measurement_complete",
  "code_signing_identity_scheme",
  "code_signing_identity_digest",
  "code_signing_identity_complete",
  "mapped_code_identity_scheme",
  "mapped_code_identity_digest",
  "mapped_code_identity_complete",
  "mapped_code_identity_audit_token_bound",
  "mapped_code_identity_stable",
  "cdhash_algorithm",
  "cdhash_set_digest",
  "cdhash_complete",
  "dynamic_code_validity_scheme",
  "dynamic_code_validity_state",
  "dynamic_code_validity_digest",
  "dynamic_code_validity_complete",
  "bundle_immutability_scheme",
  "bundle_immutability_evidence_digest",
  "bundle_immutability_complete",
  "bundle_manifest_digest",
  "entrypoint_digest",
  "config_manifest_digest",
]);

function digest(label) {
  return hashCanonicalJson({ label });
}

function nonce() {
  return crypto.randomBytes(18).toString("base64url");
}

function clone(value) {
  return structuredClone(value);
}

function authorityFixture() {
  const authorityKeys = crypto.generateKeyPairSync("ed25519");
  const requestKeys = crypto.generateKeyPairSync("ed25519");
  const responseKeys = crypto.generateKeyPairSync("ed25519");
  const roleKeys = crypto.generateKeyPairSync("ed25519");
  const authority = {
    authority_id: "launch-authority:test-root",
    authority_key_id: "launch-key:test-root-v1",
    authority_public_key_digest: publicKeyDigest(authorityKeys.publicKey),
    authority_trust_root_epoch: 4,
    authority_epoch: 9,
    authority_generation: 12,
    revocation_generation: 3,
    revocation_state_digest: digest("revocation-state"),
    anchor_digest: digest("external-anchor"),
    trusted_clock_digest: digest("trusted-clock"),
    runtime_epoch_digest: digest("runtime-epoch"),
    hil_qualification_digest: digest("conformance-hil-placeholder"),
  };
  return { authorityKeys, requestKeys, responseKeys, roleKeys, authority };
}

function payloadFor(role, fixture, overrides = {}) {
  const ipcPeerPrincipal = role === "cleanup_only_worker" || role === "safety_supervisor"
    ? "principal:safety-supervisor"
    : "principal:grant-issuer";
  const executionPrincipal = role === "cleanup_only_worker" || role === "safety_supervisor"
    ? "principal:cleanup-worker"
    : "principal:active-device-worker";
  const processPrincipal = role === "issuer_peer" || role === "safety_supervisor"
    ? ipcPeerPrincipal
    : executionPrincipal;
  const common = {
    version: 1,
    launch_attestation_id: `launch-attestation:${role}-instance-1`,
    role,
    attestation_assurance: "caller_injected_conformance_only",
    production_ready: false,
    separate_identity_authorized: false,
    hardware_authorized: false,
    host_snapshot_scheme: "darwin_audit_token_mapped_code_v1",
    os_platform: "darwin",
    os_architecture: "arm64",
    os_effective_uid: role === "issuer_peer" ? 502 : 503,
    os_effective_gid: role === "issuer_peer" ? 82 : 83,
    os_real_uid: role === "issuer_peer" ? 502 : 503,
    os_real_gid: role === "issuer_peer" ? 82 : 83,
    process_id: role === "issuer_peer" ? 4123 : 4124,
    process_credential_scheme: "darwin_audit_token_v1",
    process_credential_digest: digest(`${role}-audit-token`),
    process_start_token_digest: digest(`${role}-process-start`),
    runtime_implementation: "nodejs",
    runtime_abi: "napi_v9_node20",
    runtime_implementation_digest: digest(`${role}-node-runtime`),
    native_inspector_measurement_scheme: "mapped_native_addon_cdhash_v1",
    native_inspector_implementation_digest: digest("native-inspector-implementation"),
    native_inspector_measurement_digest: digest("native-inspector-mapped-image"),
    native_inspector_measurement_complete: true,
    code_signing_identity_scheme: "darwin_static_signing_identity_v1",
    code_signing_identity_digest: digest(`${role}-stable-signing-identity`),
    code_signing_identity_complete: true,
    mapped_code_identity_scheme: "darwin_seccode_audit_token_cdhash_v1",
    mapped_code_identity_digest: digest(`${role}-mapped-code`),
    mapped_code_identity_complete: true,
    mapped_code_identity_audit_token_bound: true,
    mapped_code_identity_stable: true,
    cdhash_algorithm: 2,
    cdhash_set_digest: digest(`${role}-complete-cdhash-set`),
    cdhash_complete: true,
    dynamic_code_validity_scheme: "darwin_dynamic_seccode_validity_v1",
    dynamic_code_validity_state: "valid",
    dynamic_code_validity_digest: digest(`${role}-dynamic-code-validity`),
    dynamic_code_validity_complete: true,
    bundle_immutability_scheme: "root_owned_sealed_bundle_v1",
    bundle_immutability_evidence_digest: digest(`${role}-bundle-immutability-evidence`),
    bundle_immutability_complete: true,
    bundle_manifest_digest: digest(`${role}-bundle-manifest`),
    entrypoint_digest: digest(`${role}-entrypoint`),
    config_manifest_digest: digest(`${role}-config-manifest`),
    process_principal_id: processPrincipal,
    ipc_peer_principal_id: ipcPeerPrincipal,
    execution_principal_id: executionPrincipal,
    ipc_profile_request_key_id: role === "cleanup_only_worker" || role === "safety_supervisor"
      ? "ipc-key:safety-cleanup-request-v1"
      : "ipc-key:issuer-active-request-v1",
    ipc_profile_request_public_key_digest: publicKeyDigest(fixture.requestKeys.publicKey),
    ipc_profile_response_key_id: role === "cleanup_only_worker" || role === "safety_supervisor"
      ? "ipc-key:cleanup-response-v1"
      : "ipc-key:active-response-v1",
    ipc_profile_response_public_key_digest: publicKeyDigest(fixture.responseKeys.publicKey),
    ipc_process_key_custody: role === "issuer_peer" || role === "safety_supervisor"
      ? "request_signer_response_verifier"
      : "request_verifier_response_signer",
    role_key_usage: {
      issuer_peer: "physical_grant_signing",
      active_device_worker: "worker_receipt_provenance_signing",
      cleanup_only_worker: "recovery_receipt_signing",
      safety_supervisor: "nondelegable_cleanup_root_signing",
    }[role],
    role_key_id: `role-key:${role}-v1`,
    role_public_key_digest: publicKeyDigest(fixture.roleKeys.publicKey),
    role_key_custody_profile_digest: digest(`${role}-role-key-custody-profile`),
    ...fixture.authority,
    authority_state_digest: launchAttestationAuthorityStateDigest(fixture.authority),
    issued_at: "2026-07-19T03:59:50.000Z",
    expires_at: "2026-07-19T04:00:40.000Z",
    nonce: nonce(),
  };
  if (["issuer_peer", "active_device_worker", "cleanup_only_worker"].includes(role)) {
    Object.assign(common, {
      provider_id: "chameleon_ultra",
      provider_descriptor_digest: digest("provider-descriptor"),
      provider_implementation_digest: digest("provider-implementation"),
    });
  }
  if (["active_device_worker", "cleanup_only_worker"].includes(role)) {
    Object.assign(common, {
      device_acl_profile_digest: digest("device-acl-profile-without-device-id"),
      device_enrollment_profile_digest: digest("opaque-device-enrollment-profile"),
    });
  }
  if (role === "cleanup_only_worker") {
    Object.assign(common, {
      precommitted_cleanup_plan_digest: digest("cleanup-plan"),
      precommitted_snapshot_digest: digest("precommitted-snapshot"),
      precommitted_restore_digest: digest("precommitted-restore"),
      fence_state_digest: digest("fenced-active-worker"),
      cleanup_root_profile_digest: digest("cleanup-root-profile"),
    });
  }
  if (role === "safety_supervisor") {
    Object.assign(common, {
      deadman_profile_digest: digest("deadman-profile"),
      interlock_profile_digest: digest("interlock-profile"),
      cleanup_policy_digest: digest("cleanup-policy"),
      fence_authority_profile_digest: digest("fence-authority-profile"),
      cleanup_root_profile_digest: digest("cleanup-root-profile"),
    });
  }
  Object.assign(common, overrides);
  if (Object.keys(overrides).some((field) => [
    "authority_id",
    "authority_key_id",
    "authority_public_key_digest",
    "authority_trust_root_epoch",
    "authority_epoch",
    "authority_generation",
    "revocation_generation",
    "revocation_state_digest",
    "anchor_digest",
    "trusted_clock_digest",
    "runtime_epoch_digest",
    "hil_qualification_digest",
  ].includes(field)) && !Object.hasOwn(overrides, "authority_state_digest")) {
    common.authority_state_digest = launchAttestationAuthorityStateDigest(common);
  }
  return common;
}

function hostBasis(payload) {
  return Object.fromEntries(HOST_FIELDS.map((field) => [field, payload[field]]));
}

function currentAuthority(fixture, signed, trustedNow = FIXED_NOW) {
  return {
    version: 1,
    trusted: true,
    revoked: false,
    ...fixture.authority,
    authority_state_digest: launchAttestationAuthorityStateDigest(fixture.authority),
    authority_public_key: fixture.authorityKeys.publicKey,
    current_launch_attestation_digest: signed.launch_attestation_digest,
    current_launch_profile_digest: launchProfileDigest(signed.payload),
    current_process_instance_binding_digest: launchProcessInstanceBindingDigest(signed.payload),
    trusted_now: trustedNow,
  };
}

function safeRejection(error) {
  assert.equal(error?.code, "launch_attestation_rejected");
  assert.equal(error?.message, "Launch attestation was rejected");
  assert.equal(Object.hasOwn(error, "cause"), false);
  return true;
}

function makeFixture(role = "active_device_worker", options = {}) {
  const fixture = authorityFixture();
  const payload = payloadFor(role, fixture, options.payload_overrides);
  const signer = createConformanceLaunchAttestationSigner({
    port_id: `signer_${role}`,
    ...fixture.authority,
    authority_private_key: fixture.authorityKeys.privateKey,
  });
  const signed = signLaunchAttestation(signer, payload);
  const behavior = {
    authority: (value) => value,
    host: (value) => value,
    replay: null,
  };
  const calls = { authority: 0, host: 0, replay: 0 };
  const captured = { authority_query: null, host_query: null, replay_claim: null };
  const seen = new Set();
  const verifier = createConformanceLaunchAttestationVerifier({
    port_id: `verifier_${role}`,
    resolve_current_authority(query) {
      calls.authority += 1;
      captured.authority_query = query;
      return behavior.authority(currentAuthority(fixture, signed), calls.authority);
    },
  });
  const hostPortId = `host_${role}`;
  const hostResolver = createConformanceLaunchHostResolver({
    port_id: hostPortId,
    resolve_live_process(query) {
      calls.host += 1;
      captured.host_query = query;
      const basis = behavior.host(hostBasis(signed.payload));
      return {
        version: 1,
        ...basis,
        snapshot_digest: launchHostSnapshotDigest(hostPortId, basis),
      };
    },
  });
  const replayPortId = `replay_${role}`;
  const replay = createConformanceLaunchReplayPort({
    port_id: replayPortId,
    reserve_once(claim) {
      calls.replay += 1;
      captured.replay_claim = claim;
      if (behavior.replay) return behavior.replay(claim, replayPortId);
      const disposition = seen.has(claim.launch_attestation_digest) ? "replay" : "reserved";
      if (disposition === "reserved") seen.add(claim.launch_attestation_digest);
      const basis = {
        version: 1,
        disposition,
        claim_digest: claim.claim_digest,
        reservation_generation: calls.replay,
      };
      return {
        ...basis,
        receipt_digest: launchReplayReceiptDigest(replayPortId, basis),
      };
    },
  });
  return {
    fixture,
    payload,
    signed,
    signer,
    verifier,
    hostResolver,
    replay,
    behavior,
    calls,
    captured,
    verify(attestation = signed) {
      return verifyAndReserveLaunchAttestation({
        attestation,
        verifier_port: verifier,
        host_resolver_port: hostResolver,
        replay_port: replay,
      });
    },
  };
}

function recomputeEnvelopeDigest(attestation) {
  const basis = {
    version: attestation.version,
    kind: attestation.kind,
    domain: attestation.domain,
    payload: attestation.payload,
    payload_digest: attestation.payload_digest,
    authentication: attestation.authentication,
  };
  attestation.launch_attestation_digest = hashCanonicalJson(basis);
  return attestation;
}

test("all four mutually exclusive launch roles verify one exact process instance", () => {
  for (const role of LAUNCH_ATTESTATION_ROLES) {
    const instance = makeFixture(role);
    const verified = instance.verify();
    assert.equal(assertVerifiedLaunchAttestation(verified), verified);
    assert.equal(Object.isFrozen(verified), true);
    assert.equal(verified.role, role);
    assert.equal(verified.production_ready, false);
    assert.equal(verified.separate_identity_authorized, false);
    assert.equal(verified.hardware_authorized, false);
    assert.equal(instance.calls.replay, 1);
    assert.equal(instance.calls.authority, 2);
    assert.equal(instance.signed.payload.production_ready, false);
    assert.equal(instance.signed.payload.hardware_authorized, false);
    assert.throws(() => instance.verify(), safeRejection, role);
    assert.equal(instance.calls.replay, 2);
    assert.throws(
      () => assertVerifiedLaunchAttestation({ ...verified }),
      /privately branded/,
    );

    const projection = JSON.stringify(verified);
    for (const forbidden of [
      instance.signed.authentication.signature,
      instance.payload.process_credential_digest,
      instance.payload.ipc_profile_request_key_id,
      instance.payload.ipc_profile_response_key_id,
      instance.payload.authority_key_id,
      instance.payload.role_key_id,
      instance.payload.device_enrollment_profile_digest,
      "chameleon_ultra",
      "/dev/",
    ].filter(Boolean)) {
      assert.equal(projection.includes(forbidden), false, `${role}: ${forbidden}`);
    }
  }
});

test("role custody makes provider and device fields closed and mutually exclusive", () => {
  const fixture = authorityFixture();
  const safety = payloadFor("safety_supervisor", fixture);
  assert.equal(normalizeLaunchAttestationPayload(safety).role, "safety_supervisor");
  assert.throws(
    () => normalizeLaunchAttestationPayload({
      ...safety,
      provider_id: "chameleon_ultra",
      provider_descriptor_digest: digest("unexpected-provider"),
      provider_implementation_digest: digest("unexpected-provider-implementation"),
    }),
    /unknown fields/,
  );

  const issuer = payloadFor("issuer_peer", fixture);
  assert.equal(Object.hasOwn(normalizeLaunchAttestationPayload(issuer), "device_acl_profile_digest"), false);
  assert.throws(
    () => normalizeLaunchAttestationPayload({
      ...issuer,
      device_acl_profile_digest: digest("issuer-must-not-own-device"),
      device_enrollment_profile_digest: digest("issuer-must-not-enroll-device"),
    }),
    /unknown fields/,
  );

  const active = payloadFor("active_device_worker", fixture);
  delete active.device_acl_profile_digest;
  assert.throws(() => normalizeLaunchAttestationPayload(active), /missing fields/);
  const cleanup = payloadFor("cleanup_only_worker", fixture);
  delete cleanup.precommitted_restore_digest;
  assert.throws(() => normalizeLaunchAttestationPayload(cleanup), /missing fields/);
  const incompleteSafety = payloadFor("safety_supervisor", fixture);
  delete incompleteSafety.interlock_profile_digest;
  assert.throws(() => normalizeLaunchAttestationPayload(incompleteSafety), /missing fields/);
  assert.throws(
    () => normalizeLaunchAttestationPayload(payloadFor("active_device_worker", fixture, {
      process_principal_id: "principal:grant-issuer",
    })),
    /role custody/,
  );
  assert.throws(
    () => normalizeLaunchAttestationPayload(payloadFor("issuer_peer", fixture, {
      execution_principal_id: "principal:grant-issuer",
    })),
    /must be distinct/,
  );
  assert.throws(
    () => normalizeLaunchAttestationPayload(payloadFor("active_device_worker", fixture, {
      ipc_process_key_custody: "request_signer_response_verifier",
    })),
    /key_custody does not match/,
  );
  assert.throws(
    () => normalizeLaunchAttestationPayload(payloadFor("active_device_worker", fixture, {
      role_key_usage: "physical_grant_signing",
    })),
    /role_key_usage does not match/,
  );
  assert.throws(
    () => normalizeLaunchAttestationPayload(payloadFor("active_device_worker", fixture, {
      production_ready: true,
      hardware_authorized: true,
    })),
    /cannot claim production/,
  );
});

test("partial, unstable, or non-audit-token-bound mapped code identity cannot be attested", () => {
  const fixture = authorityFixture();
  for (const field of [
    "native_inspector_measurement_complete",
    "code_signing_identity_complete",
    "mapped_code_identity_complete",
    "mapped_code_identity_audit_token_bound",
    "mapped_code_identity_stable",
    "cdhash_complete",
    "dynamic_code_validity_complete",
    "bundle_immutability_complete",
  ]) {
    assert.throws(
      () => normalizeLaunchAttestationPayload(payloadFor("active_device_worker", fixture, {
        [field]: false,
      })),
      /must be true/,
      field,
    );
  }
  assert.throws(
    () => normalizeLaunchAttestationPayload(payloadFor("active_device_worker", fixture, {
      dynamic_code_validity_state: "invalid",
    })),
    /must be valid/,
  );
  assert.throws(
    () => normalizeLaunchAttestationPayload(payloadFor("active_device_worker", fixture, {
      cdhash_algorithm: "sha256",
    })),
    /safe integer/,
  );
  assert.throws(
    () => normalizeLaunchAttestationPayload(payloadFor("active_device_worker", fixture, {
      os_real_uid: 999,
    })),
    /real and effective UID\/GID must be exactly equal/,
  );
});

test("signer and resolver ports are inert, private, key-redacted conformance projections", () => {
  const instance = makeFixture();
  for (const [port, assertPort] of [
    [instance.signer, assertConformanceLaunchAttestationSigner],
    [instance.verifier, assertConformanceLaunchAttestationVerifier],
    [instance.hostResolver, assertConformanceLaunchHostResolver],
    [instance.replay, assertConformanceLaunchReplayPort],
  ]) {
    assert.equal(assertPort(port), port);
    assert.equal(port.production_ready, false);
    assert.equal(port.hardware_authorized, false);
    assert.equal(port.separate_identity_authorized, false);
    assert.equal(Object.isFrozen(port), true);
    assert.doesNotMatch(
      JSON.stringify(port),
      /private_key|public_key|resolve_|reserve_once|signature|ipc-key:|launch-key:/,
    );
    assert.throws(() => assertPort({ ...port }), /privately branded/);
  }
  assert.equal(instance.calls.authority, 0);
  assert.equal(instance.calls.host, 0);
  assert.equal(instance.calls.replay, 0);

  const wrongKeys = crypto.generateKeyPairSync("ed25519");
  assert.throws(() => createConformanceLaunchAttestationSigner({
    port_id: "wrong_signer",
    ...instance.fixture.authority,
    authority_private_key: wrongKeys.privateKey,
  }), /public-key digest is inconsistent/);

  assert.throws(
    () => normalizeLaunchAttestationPayload(payloadFor("issuer_peer", instance.fixture, {
      ipc_profile_response_key_id: "ipc-key:issuer-active-request-v1",
    })),
    /pairwise distinct/,
  );
  assert.throws(
    () => normalizeLaunchAttestationPayload(payloadFor("issuer_peer", instance.fixture, {
      ipc_profile_response_public_key_digest:
        publicKeyDigest(instance.fixture.requestKeys.publicKey),
    })),
    /pairwise distinct/,
  );
  assert.throws(
    () => normalizeLaunchAttestationPayload(payloadFor("issuer_peer", instance.fixture, {
      role_key_id: "ipc-key:issuer-active-request-v1",
    })),
    /role-key: namespace/,
  );
  assert.throws(
    () => normalizeLaunchAttestationPayload(payloadFor("issuer_peer", instance.fixture, {
      role_public_key_digest: publicKeyDigest(instance.fixture.requestKeys.publicKey),
    })),
    /pairwise distinct/,
  );
});

test("the independently current profile rejects role-key identity and custody drift", () => {
  for (const [field, replacement] of [
    ["role_key_id", "role-key:active-device-worker-v2"],
    ["role_public_key_digest", digest("different-role-public-key")],
    ["role_key_custody_profile_digest", digest("different-role-key-custody")],
  ]) {
    const instance = makeFixture("active_device_worker");
    const replacementPayload = payloadFor("active_device_worker", instance.fixture, {
      [field]: replacement,
    });
    const replacementAttestation = signLaunchAttestation(instance.signer, replacementPayload);
    instance.behavior.authority = (value) => ({
      ...value,
      current_launch_attestation_digest: replacementAttestation.launch_attestation_digest,
    });
    assert.throws(() => instance.verify(replacementAttestation), safeRejection, field);
    assert.equal(instance.calls.host, 0, field);
    assert.equal(instance.calls.replay, 0, field);
  }
});

test("signature, signed payload, and envelope tampering fail before live resolution or replay", () => {
  const instance = makeFixture();
  for (const mutate of [
    (value) => { value.authentication.signature = `${value.authentication.signature[0] === "A" ? "B" : "A"}${value.authentication.signature.slice(1)}`; },
    (value) => { value.payload.bundle_manifest_digest = digest("tampered-bundle"); },
    (value) => { value.payload_digest = digest("tampered-payload-digest"); },
    (value) => { value.launch_attestation_digest = digest("tampered-envelope-digest"); },
  ]) {
    const tampered = clone(instance.signed);
    mutate(tampered);
    assert.throws(() => instance.verify(tampered), safeRejection);
  }
  assert.equal(instance.calls.host, 0);
  assert.equal(instance.calls.replay, 0);
});

test("a cryptographically invalid fork is rejected even when current-state digests are advanced to it", () => {
  const instance = makeFixture();
  const forged = clone(instance.signed);
  forged.authentication.signature = crypto.randomBytes(64).toString("base64url");
  recomputeEnvelopeDigest(forged);
  instance.behavior.authority = (value) => ({
    ...value,
    current_launch_attestation_digest: forged.launch_attestation_digest,
  });
  assert.throws(() => instance.verify(forged), safeRejection);
  assert.equal(instance.calls.host, 0);
  assert.equal(instance.calls.replay, 0);
});

test("freshness is checked against resolver-owned trusted time with a bounded lifetime", () => {
  const expired = makeFixture();
  expired.behavior.authority = (value) => ({ ...value, trusted_now: "2026-07-19T04:00:40.000Z" });
  assert.throws(() => expired.verify(), safeRejection);
  assert.equal(expired.calls.host, 0);

  const future = makeFixture();
  future.behavior.authority = (value) => ({ ...value, trusted_now: "2026-07-19T03:59:40.000Z" });
  assert.throws(() => future.verify(), safeRejection);
  assert.equal(future.calls.host, 0);

  const fixture = authorityFixture();
  assert.throws(
    () => normalizeLaunchAttestationPayload(payloadFor("issuer_peer", fixture, {
      issued_at: "2026-07-19T04:00:00.000Z",
      expires_at: new Date(Date.parse("2026-07-19T04:00:00.000Z")
        + LAUNCH_ATTESTATION_MAX_LIFETIME_MS + 1).toISOString(),
    })),
    /lifetime/,
  );
});

test("authority rollback, fork, revocation, key, epoch, anchor, clock, and HIL drift fail closed", () => {
  const cases = [
    ["revoked", (value) => ({ ...value, revoked: true })],
    ["attestation fork", (value) => ({ ...value, current_launch_attestation_digest: digest("fork") })],
    ["profile fork", (value) => ({ ...value, current_launch_profile_digest: digest("profile-fork") })],
    ["process fork", (value) => ({ ...value, current_process_instance_binding_digest: digest("process-fork") })],
    ["generation rollback", (value) => ({ ...value, authority_generation: value.authority_generation - 1 })],
    ["authority epoch", (value) => ({ ...value, authority_epoch: value.authority_epoch + 1 })],
    ["revocation generation", (value) => ({ ...value, revocation_generation: value.revocation_generation + 1 })],
    ["revocation state", (value) => ({ ...value, revocation_state_digest: digest("revocation-state-drift") })],
    ["anchor", (value) => ({ ...value, anchor_digest: digest("anchor-drift") })],
    ["clock", (value) => ({ ...value, trusted_clock_digest: digest("clock-drift") })],
    ["runtime epoch", (value) => ({ ...value, runtime_epoch_digest: digest("epoch-drift") })],
    ["HIL", (value) => ({ ...value, hil_qualification_digest: digest("hil-drift") })],
  ];
  for (const [label, transform] of cases) {
    const instance = makeFixture();
    instance.behavior.authority = transform;
    assert.throws(() => instance.verify(), safeRejection, label);
    assert.equal(instance.calls.host, 0, label);
    assert.equal(instance.calls.replay, 0, label);
  }
});

test("post-reservation authority read-back catches revocation, fork, outage, and clock rollback", () => {
  const cases = [
    ["revocation", (value) => ({ ...value, revoked: true })],
    ["ticket fork", (value) => ({
      ...value,
      current_launch_attestation_digest: digest("post-reservation-fork"),
    })],
    ["outage", () => { throw new Error("post-reservation authority outage"); }],
    ["clock rollback", (value) => ({ ...value, trusted_now: "2026-07-19T03:59:59.999Z" })],
  ];
  for (const [label, secondRead] of cases) {
    const instance = makeFixture();
    instance.behavior.authority = (value, call) => call === 1 ? value : secondRead(value);
    assert.throws(() => instance.verify(), safeRejection, label);
    assert.equal(instance.calls.authority, 2, label);
    assert.equal(instance.calls.host, 1, label);
    assert.equal(instance.calls.replay, 1, label);
    assert.throws(() => instance.verify(), safeRejection, `${label} reservation burned`);
  }
});

test("every live process, audit-token, code, CDHash, and immutable bundle drift fails before replay", () => {
  const cases = [
    ["effective UID", "os_effective_uid", 900],
    ["effective GID", "os_effective_gid", 901],
    ["PID", "process_id", 9999],
    ["audit token", "process_credential_digest", digest("different-audit-token")],
    ["process start", "process_start_token_digest", digest("different-start")],
    ["runtime ABI", "runtime_abi", "napi_v8_node18"],
    ["native inspector", "native_inspector_measurement_digest", digest("different-inspector")],
    ["static signing identity", "code_signing_identity_digest", digest("different-signing-id")],
    ["mapped code", "mapped_code_identity_digest", digest("different-mapped-code")],
    ["CDHash", "cdhash_set_digest", digest("different-cdhash-set")],
    ["dynamic validity", "dynamic_code_validity_digest", digest("different-validity")],
    ["bundle immutability", "bundle_immutability_evidence_digest", digest("different-immutability")],
    ["bundle", "bundle_manifest_digest", digest("different-bundle")],
    ["entrypoint", "entrypoint_digest", digest("different-entrypoint")],
    ["config", "config_manifest_digest", digest("different-config")],
  ];
  for (const [label, field, replacement] of cases) {
    const instance = makeFixture();
    instance.behavior.host = (value) => ({ ...value, [field]: replacement });
    assert.throws(() => instance.verify(), safeRejection, label);
    assert.equal(instance.calls.replay, 0, label);
  }
});

test("resolver outages, asynchronous results, hostile accessors, and malformed results are redacted", () => {
  for (const configure of [
    (instance) => { instance.behavior.authority = () => { throw new Error("/secret/authority/key"); }; },
    (instance) => { instance.behavior.authority = async (value) => value; },
    (instance) => { instance.behavior.host = () => { throw new Error("/dev/cu.secret-device"); }; },
    (instance) => { instance.behavior.host = async (value) => value; },
    (instance) => {
      instance.behavior.replay = async (claim, portId) => {
        const basis = { version: 1, disposition: "reserved", claim_digest: claim.claim_digest, reservation_generation: 1 };
        return { ...basis, receipt_digest: launchReplayReceiptDigest(portId, basis) };
      };
    },
    (instance) => { instance.behavior.replay = () => ({ malformed: true }); },
  ]) {
    const instance = makeFixture();
    configure(instance);
    assert.throws(() => instance.verify(), safeRejection);
  }

  const accessor = makeFixture();
  let calls = 0;
  accessor.behavior.authority = (value) => {
    const hostile = { ...value };
    Object.defineProperty(hostile, "trusted_now", {
      enumerable: true,
      get() {
        calls += 1;
        throw new Error("hostile accessor");
      },
    });
    return hostile;
  };
  assert.throws(() => accessor.verify(), safeRejection);
  assert.equal(calls, 0);
});

test("one-use reservation receives only opaque bindings and is mandatory before admission", () => {
  const instance = makeFixture("cleanup_only_worker");
  const verified = instance.verify();
  assert.equal(instance.calls.authority, 2);
  assert.equal(instance.calls.host, 1);
  assert.equal(instance.calls.replay, 1);
  assert.equal(verified.replay_receipt_digest.length, 64);
  const claim = JSON.stringify(instance.captured.replay_claim);
  for (const forbidden of [
    instance.payload.nonce,
    instance.payload.process_credential_digest,
    instance.payload.ipc_profile_request_key_id,
    instance.payload.ipc_profile_response_key_id,
    instance.payload.role_key_id,
    instance.payload.device_enrollment_profile_digest,
    instance.signed.authentication.signature,
  ]) {
    assert.equal(claim.includes(forbidden), false, forbidden);
  }

  const denied = makeFixture();
  denied.behavior.replay = (replayClaim, portId) => {
    const basis = {
      version: 1,
      disposition: "fork",
      claim_digest: replayClaim.claim_digest,
      reservation_generation: 1,
    };
    return { ...basis, receipt_digest: launchReplayReceiptDigest(portId, basis) };
  };
  assert.throws(() => denied.verify(), safeRejection);

  const tampered = makeFixture();
  tampered.behavior.replay = (replayClaim, portId) => {
    const basis = {
      version: 1,
      disposition: "reserved",
      claim_digest: replayClaim.claim_digest,
      reservation_generation: 1,
    };
    return { ...basis, receipt_digest: digest(`not-${portId}`) };
  };
  assert.throws(() => tampered.verify(), safeRejection);
});

test("Proxy, accessor, symbol, and unknown fields are rejected without attacker reads", () => {
  const fixture = authorityFixture();
  const payload = payloadFor("issuer_peer", fixture);
  let proxyReads = 0;
  const proxy = new Proxy(payload, {
    get(target, property, receiver) {
      proxyReads += 1;
      return Reflect.get(target, property, receiver);
    },
  });
  assert.throws(() => normalizeLaunchAttestationPayload(proxy), /plain own-data object/);
  assert.equal(proxyReads, 0);

  let accessorReads = 0;
  const accessor = { ...payload };
  Object.defineProperty(accessor, "role", {
    enumerable: true,
    get() {
      accessorReads += 1;
      return "issuer_peer";
    },
  });
  assert.throws(() => normalizeLaunchAttestationPayload(accessor), /plain own-data object/);
  assert.equal(accessorReads, 0);

  const symbol = { ...payload, [Symbol("raw-path")]: "/dev/cu.secret" };
  assert.throws(() => normalizeLaunchAttestationPayload(symbol), /plain own-data object/);
  assert.throws(
    () => normalizeLaunchAttestationPayload({ ...payload, raw_device_path: "/dev/cu.secret" }),
    /unknown fields/,
  );

  const instance = makeFixture();
  const envelopeProxy = new Proxy(instance.signed, {});
  assert.throws(() => normalizeSignedLaunchAttestation(envelopeProxy), /plain own-data object/);
  assert.equal(instance.signed.domain, LAUNCH_ATTESTATION_DOMAIN);
});
