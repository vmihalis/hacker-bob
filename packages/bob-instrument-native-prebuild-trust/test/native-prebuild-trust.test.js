"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const test = require("node:test");

const trust = require("../lib");

const PACKAGE_ROOT = path.resolve(__dirname, "..");
const NOW = "2026-07-19T12:00:00.000Z";
const PACKAGE_NAME = "@hacker-bob/instrument-native-prebuild-darwin-arm64";
const COMPONENT_KINDS = Object.freeze([
  "node_native_addon",
  "node_native_addon",
  "mach_o_executable",
  "mach_o_executable",
]);
const CODE_TYPES = Object.freeze(["bundle", "bundle", "executable", "executable"]);
const ARTIFACT_PATHS = Object.freeze([
  "native/ipc-acceptor.node",
  "native/chameleon-cdc-custody.node",
  "bin/bob-safety-watchdog",
  "bin/bob-privileged-launcher",
]);

function digest(label) {
  return crypto.createHash("sha256").update(label).digest("hex");
}

function clone(value) {
  return structuredClone(value);
}

function makeManifest() {
  return {
    version: 1,
    kind: "native_prebuild_release_manifest",
    package_name: PACKAGE_NAME,
    package_version: "1.2.3",
    release_id: "native-prebuild:2026.07.19.1",
    release_epoch: 7,
    target: {
      os: "darwin",
      architecture: "arm64",
      node_major: 20,
      napi_version: 9,
      node_api_only: true,
      deployment_format: "signed_immutable_prebuild_set",
    },
    components: trust.NATIVE_PREBUILD_REQUIRED_COMPONENTS.map((componentId, index) => ({
      component_id: componentId,
      artifact_path: ARTIFACT_PATHS[index],
      artifact_kind: COMPONENT_KINDS[index],
      byte_size: 8192 + index,
      sha256: digest(`artifact-${index}`),
      source_digest: digest(`source-${index}`),
      builder_digest: digest(`builder-${index}`),
      toolchain_digest: digest(`toolchain-${index}`),
      provenance_digest: digest(`provenance-${index}`),
      dynamic_dependency_policy: {
        exact_dependencies: ["/usr/lib/libSystem.B.dylib"],
        weak_dependencies_allowed: false,
        upward_dependencies_allowed: false,
        rpaths_allowed: false,
      },
      macho_signing_policy: {
        signature_kind: "developer_id",
        code_type: CODE_TYPES[index],
        team_identifier: "ABCDEF1234",
        signing_identifier: `org.hackerbob.native.${componentId.replaceAll("_", "-")}`,
        cdhash_algorithm: "sha256",
        hardened_runtime_required: true,
        notarization_required: true,
        adhoc_allowed: false,
        designated_requirement_digest: digest(`designated-requirement-${index}`),
        entitlements_digest: digest(`entitlements-${index}`),
      },
    })),
    source_tree_digest: digest("source-tree"),
    builder_identity_digest: digest("builder-identity"),
    toolchain_manifest_digest: digest("toolchain-manifest"),
    provenance_statement_digest: digest("provenance-statement"),
    principal_acl_policy_digest: digest("principal-acl-policy"),
    filesystem_policy: {
      install_root_owner_uid: 0,
      install_root_owner_gid: 0,
      artifact_owner_uid: 0,
      artifact_owner_gid: 0,
      install_root_path_digest: digest("install-root"),
      required_open_scheme: "openat_no_follow_descriptor_walk_v1",
      max_static_inspection_age_ms: 30 * 60 * 1000,
      required_immutability_evidence_scheme:
        "read_only_mount_or_darwin_system_immutable_flags_v1",
      require_root_owned_ancestry: true,
      require_no_symlinks: true,
      require_regular_files: true,
      require_single_link: true,
      require_stable_file_identity: true,
      require_retained_artifact_fds: true,
      require_root_immutable: true,
      require_artifact_immutable: true,
      require_read_only_mount_or_system_immutable: true,
      require_mapped_image_binding: true,
    },
    native_attestation_policy: {
      scheme: "darwin_loaded_image_identity_v1",
      attestor_implementation_digest: digest("attestor-implementation"),
      attestor_source_digest: digest("attestor-source"),
      attestor_loaded_image_digest: digest("attestor-loaded-image"),
      component_identity_binding_scheme:
        "darwin_fd_codesign_loaded_mapped_cross_binding_v1",
      max_attestation_age_ms: 20 * 60 * 1000,
      require_kernel_originated_identity: true,
      require_on_disk_fd_binding: true,
      require_loaded_or_exec_image_binding: true,
      require_mapped_process_image_binding: true,
      require_component_host_or_equivalent_validation: true,
      require_pre_post_identity_match: true,
      require_live_double_read: true,
      require_principal_acl_binding: true,
    },
    hil_policy: {
      suite_id: "plane_ph_native_prebuild_hil",
      suite_digest: digest("hil-suite"),
      authority_scope_digest: digest("hil-authority-scope"),
      device_qualification_policy_digest: digest("hil-device-policy"),
      fixture_manifest_digest: digest("hil-fixture-manifest"),
      operator_witness_policy_digest: digest("hil-witness-policy"),
      max_evidence_age_ms: 10 * 60 * 1000,
      required_gate_ids: [...trust.NATIVE_PREBUILD_REQUIRED_HIL_GATES],
    },
    issued_at: "2026-07-19T00:00:00.000Z",
    expires_at: "2026-07-20T00:00:00.000Z",
  };
}

function keyDigest(publicKey) {
  return digest(publicKey.export({ type: "spki", format: "der" }));
}

function createFixture() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  const manifest = makeManifest();
  const manifestDigest = trust.digestReleaseManifest(manifest);
  const publicDer = publicKey.export({ type: "spki", format: "der" });
  const publicDigest = keyDigest(publicKey);
  const claim = {
    manifest_digest: manifestDigest,
    key_id: "native-release-key:primary",
    public_key_digest: publicDigest,
    trust_epoch: 7,
  };
  const signature = crypto.sign(null, trust.releaseSignatureMessage(claim), privateKey)
    .toString("base64url");
  const envelope = {
    version: 1,
    kind: "signed_native_prebuild_release",
    signature_domain: trust.NATIVE_PREBUILD_SIGNATURE_DOMAIN,
    manifest,
    manifest_digest: manifestDigest,
    authentication: {
      scheme: "ed25519",
      key_usage: trust.NATIVE_PREBUILD_KEY_USAGE,
      key_id: claim.key_id,
      public_key_digest: publicDigest,
      trust_epoch: 7,
      signed_manifest_digest: manifestDigest,
      signature,
    },
  };
  const trustPolicy = {
    version: 1,
    kind: "native_prebuild_trust_policy",
    current_trust_epoch: 7,
    minimum_release_epoch: 7,
    revoked_release_ids: [],
    revoked_manifest_digests: [],
    keys: [{
      key_id: claim.key_id,
      public_key_spki_der: publicDer.toString("base64url"),
      public_key_digest: publicDigest,
      trust_epoch: 7,
      not_before: "2026-07-18T00:00:00.000Z",
      not_after: "2026-07-21T00:00:00.000Z",
      revoked: false,
      revocation_epoch: 0,
      allowed_package_names: [PACKAGE_NAME],
      allowed_component_ids: [...trust.NATIVE_PREBUILD_REQUIRED_COMPONENTS],
    }],
  };
  const context = {
    now: NOW,
    expected_manifest_digest: manifestDigest,
    expected_package_name: PACKAGE_NAME,
    expected_package_version: manifest.package_version,
    expected_release_epoch: manifest.release_epoch,
    expected_install_root_path_digest: manifest.filesystem_policy.install_root_path_digest,
    host_os: "darwin",
    host_architecture: "arm64",
    host_node_major: 20,
    host_napi_version: 9,
    principal_acl_policy_digest: manifest.principal_acl_policy_digest,
    expected_principal_acl_evidence_digest: digest("principal-acl-evidence"),
    expected_hil_authority_scope_digest: manifest.hil_policy.authority_scope_digest,
    expected_hil_device_identity_digest: digest("hil-device-identity"),
    expected_hil_fixture_manifest_digest: manifest.hil_policy.fixture_manifest_digest,
    expected_hil_operator_witness_digest: digest("hil-operator-witness"),
  };
  const staticBody = {
    version: 1,
    kind: "native_prebuild_static_inspection",
    manifest_digest: manifestDigest,
    inspection_id: "static-inspection:fixture",
    inspected_at: "2026-07-19T11:45:00.000Z",
    valid_until: "2026-07-19T12:15:00.000Z",
    root: {
      install_root_path_digest: manifest.filesystem_policy.install_root_path_digest,
      install_root_owner_uid: 0,
      install_root_owner_gid: 0,
      install_root_mode: 0o555,
      root_owned_ancestry: true,
      no_symlink_walk: true,
      open_scheme: manifest.filesystem_policy.required_open_scheme,
      openat_walk_complete: true,
      stable_file_identity: true,
      terminal_reopen_match: true,
      retained_artifact_fds: true,
      root_immutable: true,
      immutability_scheme: "darwin_system_immutable_flags_v1",
      filesystem_immutability_evidence_digest: digest("filesystem-immutability-evidence"),
      principal_acl_policy_digest: manifest.principal_acl_policy_digest,
      principal_acl_evidence_digest: context.expected_principal_acl_evidence_digest,
    },
    components: manifest.components.map((component, index) => ({
      component_id: component.component_id,
      artifact_path: component.artifact_path,
      artifact_kind: component.artifact_kind,
      byte_size: component.byte_size,
      sha256: component.sha256,
      owner_uid: 0,
      owner_gid: 0,
      mode: 0o555,
      nlink: 1,
      regular_file: true,
      symlink: false,
      immutable: true,
      openat_no_follow: true,
      pre_post_identity_match: true,
      fd_identity_digest: digest(`fd-identity-${index}`),
      actual_dynamic_dependencies: [...component.dynamic_dependency_policy.exact_dependencies],
      weak_dependencies_present: false,
      upward_dependencies_present: false,
      rpaths: [],
      macho_signature: {
        signature_kind: component.macho_signing_policy.signature_kind,
        code_type: component.macho_signing_policy.code_type,
        team_identifier: component.macho_signing_policy.team_identifier,
        signing_identifier: component.macho_signing_policy.signing_identifier,
        cdhash_algorithm: component.macho_signing_policy.cdhash_algorithm,
        selected_cdhash: `${index + 1}`.repeat(40),
        hardened_runtime: true,
        notarization_verified: true,
        adhoc: false,
        designated_requirement_digest:
          component.macho_signing_policy.designated_requirement_digest,
        entitlements_digest: component.macho_signing_policy.entitlements_digest,
        signature_validation_complete: true,
      },
    })),
  };
  const staticInspection = {
    ...staticBody,
    inspection_digest: trust.digestStaticInspectionEvidenceBody(staticBody),
  };
  const nativeBody = {
    version: 1,
    kind: "native_prebuild_loaded_image_attestation",
    manifest_digest: manifestDigest,
    inspection_digest: staticInspection.inspection_digest,
    attestation_id: "native-attestation:fixture",
    observed_at: "2026-07-19T11:50:00.000Z",
    valid_until: "2026-07-19T12:10:00.000Z",
    host: {
      os: "darwin",
      architecture: "arm64",
      node_major: 20,
      napi_version: 9,
    },
    attestor: {
      implementation_digest: manifest.native_attestation_policy.attestor_implementation_digest,
      source_digest: manifest.native_attestation_policy.attestor_source_digest,
      loaded_image_digest: manifest.native_attestation_policy.attestor_loaded_image_digest,
      install_root_path_digest: staticInspection.root.install_root_path_digest,
      filesystem_immutability_evidence_digest:
        staticInspection.root.filesystem_immutability_evidence_digest,
      root_owned_immutable: true,
      principal_acl_policy_digest: manifest.principal_acl_policy_digest,
      principal_acl_evidence_digest: context.expected_principal_acl_evidence_digest,
      kernel_evidence_complete: true,
      live_double_read_complete: true,
    },
    components: manifest.components.map((component, index) => {
      const staticComponent = staticInspection.components[index];
      const identity = {
        component_id: component.component_id,
        artifact_sha256: component.sha256,
        static_cdhash: staticComponent.macho_signature.selected_cdhash,
        on_disk_fd_identity_digest: staticComponent.fd_identity_digest,
        loaded_image_sha256: component.sha256,
        loaded_or_exec_image_identity_digest: digest(`loaded-image-${index}`),
        mapped_process_image_identity_digest: digest(`mapped-image-${index}`),
        identity_binding_scheme:
          manifest.native_attestation_policy.component_identity_binding_scheme,
        host_or_equivalent_validation_mode: component.artifact_kind === "node_native_addon"
          ? "exact_openat_loaded_mapped_image_identity_v1"
          : "hardened_runtime_designated_requirement_v1",
      };
      const identityBindingDigest = trust.digestNativeComponentIdentityBinding({
        version: 1,
        scheme: identity.identity_binding_scheme,
        manifest_digest: manifestDigest,
        inspection_digest: staticInspection.inspection_digest,
        component_id: identity.component_id,
        artifact_kind: component.artifact_kind,
        artifact_sha256: identity.artifact_sha256,
        static_cdhash: identity.static_cdhash,
        designated_requirement_digest:
          staticComponent.macho_signature.designated_requirement_digest,
        on_disk_fd_identity_digest: identity.on_disk_fd_identity_digest,
        loaded_image_sha256: identity.loaded_image_sha256,
        loaded_or_exec_image_identity_digest: identity.loaded_or_exec_image_identity_digest,
        mapped_process_image_identity_digest: identity.mapped_process_image_identity_digest,
        host_or_equivalent_validation_mode: identity.host_or_equivalent_validation_mode,
        attestor_implementation_digest:
          manifest.native_attestation_policy.attestor_implementation_digest,
        principal_acl_evidence_digest: context.expected_principal_acl_evidence_digest,
      });
      return {
        ...identity,
        identity_binding_digest: identityBindingDigest,
        host_or_equivalent_validation_complete: true,
        on_disk_fd_bound: true,
        loaded_or_exec_image_bound: true,
        mapped_process_image_bound: true,
        pre_post_identity_match: true,
        kernel_originated: true,
      };
    }),
  };
  const nativeAttestation = {
    ...nativeBody,
    attestation_digest: trust.digestNativeAttestationEvidenceBody(nativeBody),
  };
  const hilBody = {
    version: 1,
    kind: "native_prebuild_hil_qualification",
    manifest_digest: manifestDigest,
    native_attestation_digest: nativeAttestation.attestation_digest,
    suite_id: manifest.hil_policy.suite_id,
    suite_digest: manifest.hil_policy.suite_digest,
    authority_scope_digest: manifest.hil_policy.authority_scope_digest,
    device_qualification_policy_digest: manifest.hil_policy.device_qualification_policy_digest,
    fixture_manifest_digest: manifest.hil_policy.fixture_manifest_digest,
    operator_witness_policy_digest: manifest.hil_policy.operator_witness_policy_digest,
    hil_run_id: "hil-run:fixture",
    run_at: "2026-07-19T11:55:00.000Z",
    valid_until: "2026-07-19T12:05:00.000Z",
    gate_results: trust.NATIVE_PREBUILD_REQUIRED_HIL_GATES.map((gateId, index) => ({
      gate_id: gateId,
      passed: true,
      evidence_digest: digest(`hil-evidence-${index}`),
      authority_scope_digest: context.expected_hil_authority_scope_digest,
      device_identity_digest: context.expected_hil_device_identity_digest,
      operator_witness_digest: context.expected_hil_operator_witness_digest,
    })),
  };
  const hilEvidence = {
    ...hilBody,
    hil_evidence_digest: trust.digestHilEvidenceBody(hilBody),
  };
  return {
    publicKey,
    privateKey,
    envelope,
    trustPolicy,
    context,
    staticInspection,
    nativeAttestation,
    hilEvidence,
  };
}

function doctorInput(fixture) {
  return {
    envelope: fixture.envelope,
    trust_policy: fixture.trustPolicy,
    evaluation_context: fixture.context,
    static_inspection: fixture.staticInspection,
    native_attestation: fixture.nativeAttestation,
    hil_evidence: fixture.hilEvidence,
  };
}

function resealStatic(fixture) {
  const body = clone(fixture.staticInspection);
  delete body.inspection_digest;
  fixture.staticInspection.inspection_digest = trust.digestStaticInspectionEvidenceBody(body);
}

function resealNative(fixture) {
  const body = clone(fixture.nativeAttestation);
  delete body.attestation_digest;
  fixture.nativeAttestation.attestation_digest = trust.digestNativeAttestationEvidenceBody(body);
}

function selectAliasedReleaseKey(fixture, options = {}) {
  const primary = fixture.trustPolicy.keys[0];
  const alias = clone(primary);
  alias.key_id = "native-release-key:secondary";
  alias.revoked = false;
  alias.revocation_epoch = 0;
  if (options.revoke_primary === true) {
    primary.revoked = true;
    primary.revocation_epoch = fixture.trustPolicy.current_trust_epoch;
  }
  fixture.trustPolicy.keys = options.reverse === true
    ? [alias, primary]
    : [primary, alias];
  fixture.envelope.authentication.key_id = alias.key_id;
  fixture.envelope.authentication.signature = crypto.sign(null, trust.releaseSignatureMessage({
    manifest_digest: fixture.envelope.manifest_digest,
    key_id: alias.key_id,
    public_key_digest: alias.public_key_digest,
    trust_epoch: alias.trust_epoch,
  }), fixture.privateKey).toString("base64url");
}

function resealNativeComponentBinding(fixture, index) {
  const manifest = fixture.envelope.manifest;
  const component = fixture.nativeAttestation.components[index];
  const staticComponent = fixture.staticInspection.components[index];
  component.identity_binding_digest = trust.digestNativeComponentIdentityBinding({
    version: 1,
    scheme: component.identity_binding_scheme,
    manifest_digest: fixture.nativeAttestation.manifest_digest,
    inspection_digest: fixture.nativeAttestation.inspection_digest,
    component_id: component.component_id,
    artifact_kind: manifest.components[index].artifact_kind,
    artifact_sha256: component.artifact_sha256,
    static_cdhash: component.static_cdhash,
    designated_requirement_digest:
      staticComponent.macho_signature.designated_requirement_digest,
    on_disk_fd_identity_digest: component.on_disk_fd_identity_digest,
    loaded_image_sha256: component.loaded_image_sha256,
    loaded_or_exec_image_identity_digest: component.loaded_or_exec_image_identity_digest,
    mapped_process_image_identity_digest: component.mapped_process_image_identity_digest,
    host_or_equivalent_validation_mode: component.host_or_equivalent_validation_mode,
    attestor_implementation_digest: fixture.nativeAttestation.attestor.implementation_digest,
    principal_acl_evidence_digest:
      fixture.nativeAttestation.attestor.principal_acl_evidence_digest,
  });
  resealNative(fixture);
}

test("verifies the release signature without granting authority", () => {
  const fixture = createFixture();
  const verified = trust.verifyReleaseEnvelope({
    envelope: fixture.envelope,
    trust_policy: fixture.trustPolicy,
    now: NOW,
  });
  assert.equal(verified.release_signature_valid, true);
  assert.equal(verified.assurance, "ed25519_release_signature_only");
  assert.equal(verified.production_ready, false);
  assert.equal(verified.hardware_access_authorized, false);
  assert.ok(Object.isFrozen(verified));
});

test("complete evidence remains explicitly non-authorizing", () => {
  const report = trust.evaluateNativePrebuildDoctor(doctorInput(createFixture()));
  assert.equal(report.status, "diagnostic_complete_non_authorizing");
  assert.equal(report.release_signature_valid, true);
  assert.equal(report.static_inspection_valid, true);
  assert.equal(report.native_attestation_valid, true);
  assert.equal(report.hil_evidence_valid, true);
  assert.equal(report.production_ready, false);
  assert.equal(report.hardware_access_authorized, false);
  assert.equal(report.authoritative, false);
  assert.equal(report.host_inspection_performed, false);
  assert.equal(report.native_execution_performed, false);
});

test("missing evidence reports blocked and qualified-pending-HIL boundaries", () => {
  const fixture = createFixture();
  let input = doctorInput(fixture);
  input.static_inspection = null;
  assert.equal(trust.evaluateNativePrebuildDoctor(input).status, "blocked");
  input = doctorInput(fixture);
  input.native_attestation = null;
  assert.equal(trust.evaluateNativePrebuildDoctor(input).status, "blocked");
  input = doctorInput(fixture);
  input.hil_evidence = null;
  const report = trust.evaluateNativePrebuildDoctor(input);
  assert.equal(report.status, "qualified_pending_hil");
  assert.equal(report.production_ready, false);
  assert.equal(report.hardware_access_authorized, false);
});

test("forged signatures and cross-domain envelopes are unavailable", () => {
  const forged = createFixture();
  forged.envelope.authentication.signature = `${
    forged.envelope.authentication.signature[0] === "A" ? "B" : "A"
  }${forged.envelope.authentication.signature.slice(1)}`;
  let report = trust.evaluateNativePrebuildDoctor(doctorInput(forged));
  assert.equal(report.status, "unavailable");
  assert.equal(report.release_signature_valid, false);

  const wrongDomain = createFixture();
  wrongDomain.envelope.signature_domain = "hacker-bob/another-signature-domain/v1";
  report = trust.evaluateNativePrebuildDoctor(doctorInput(wrongDomain));
  assert.equal(report.status, "unavailable");
});

test("key revocation, release revocation, manifest revocation, and trust epochs fail closed", () => {
  const revokedKey = createFixture();
  revokedKey.trustPolicy.keys[0].revoked = true;
  revokedKey.trustPolicy.keys[0].revocation_epoch = 7;
  assert.equal(trust.evaluateNativePrebuildDoctor(doctorInput(revokedKey)).status, "unavailable");

  const revokedRelease = createFixture();
  revokedRelease.trustPolicy.revoked_release_ids = [revokedRelease.envelope.manifest.release_id];
  assert.equal(trust.evaluateNativePrebuildDoctor(doctorInput(revokedRelease)).status,
    "unavailable");

  const revokedManifest = createFixture();
  revokedManifest.trustPolicy.revoked_manifest_digests = [
    revokedManifest.envelope.manifest_digest,
  ];
  assert.equal(trust.evaluateNativePrebuildDoctor(doctorInput(revokedManifest)).status,
    "unavailable");

  const oldRelease = createFixture();
  oldRelease.trustPolicy.minimum_release_epoch = 8;
  assert.equal(trust.evaluateNativePrebuildDoctor(doctorInput(oldRelease)).status, "unavailable");
});

test("revoked Ed25519 key material cannot survive under another key ID", () => {
  for (const options of [
    { revoke_primary: false, reverse: false },
    { revoke_primary: true, reverse: false },
    { revoke_primary: true, reverse: true },
  ]) {
    const fixture = createFixture();
    selectAliasedReleaseKey(fixture, options);
    assert.throws(() => trust.verifyReleaseEnvelope({
      envelope: fixture.envelope,
      trust_policy: fixture.trustPolicy,
      now: NOW,
    }), /alias Ed25519 key material|strictly sorted/u);
    assert.equal(trust.evaluateNativePrebuildDoctor(doctorInput(fixture)).status, "unavailable");
  }
});

test("key time windows, release time windows, package scope, and component scope fail closed", () => {
  const expiredKey = createFixture();
  expiredKey.trustPolicy.keys[0].not_after = NOW;
  assert.equal(trust.evaluateNativePrebuildDoctor(doctorInput(expiredKey)).status, "unavailable");

  const expiredRelease = createFixture();
  expiredRelease.context.now = expiredRelease.envelope.manifest.expires_at;
  assert.equal(trust.evaluateNativePrebuildDoctor(doctorInput(expiredRelease)).status,
    "unavailable");

  const wrongPackage = createFixture();
  wrongPackage.trustPolicy.keys[0].allowed_package_names = ["@hacker-bob/wrong-package"];
  assert.equal(trust.evaluateNativePrebuildDoctor(doctorInput(wrongPackage)).status,
    "unavailable");

  const missingComponentScope = createFixture();
  missingComponentScope.trustPolicy.keys[0].allowed_component_ids.pop();
  assert.equal(trust.evaluateNativePrebuildDoctor(doctorInput(missingComponentScope)).status,
    "unavailable");
});

test("manifest requires the exact complete four-component set and actual artifact kinds", () => {
  const missing = makeManifest();
  missing.components.pop();
  assert.throws(() => trust.digestReleaseManifest(missing), /complete|required component/u);

  const swapped = makeManifest();
  [swapped.components[0], swapped.components[1]] = [swapped.components[1], swapped.components[0]];
  assert.throws(() => trust.digestReleaseManifest(swapped), /required component/u);

  const wrongSafetyKind = makeManifest();
  wrongSafetyKind.components[2].artifact_kind = "node_native_addon";
  assert.throws(() => trust.digestReleaseManifest(wrongSafetyKind), /required component/u);
});

test("manifest rejects traversal, aliases, duplicate paths, and hostile dependency strings", () => {
  for (const badPath of ["../escape.node", "/absolute/addon.node", "native/./addon.node",
    "native\\addon.node", "native/%2e%2e/addon.node", "Native/addon.node",
    "native/caf\u00e9.node", "native/cafe\u0301.node"]) {
    const manifest = makeManifest();
    manifest.components[0].artifact_path = badPath;
    assert.throws(() => trust.digestReleaseManifest(manifest));
  }
  const duplicate = makeManifest();
  duplicate.components[1].artifact_path = duplicate.components[0].artifact_path;
  assert.throws(() => trust.digestReleaseManifest(duplicate), /unique/u);

  const caseFoldAlias = makeManifest();
  caseFoldAlias.components[0].artifact_path = "Native/Shared.node";
  caseFoldAlias.components[1].artifact_path = "native/shared.node";
  assert.throws(() => trust.digestReleaseManifest(caseFoldAlias));

  const fileDirectoryAlias = makeManifest();
  fileDirectoryAlias.components[0].artifact_path = "native/shared.node";
  fileDirectoryAlias.components[1].artifact_path = "native/shared.node/child.node";
  assert.throws(() => trust.digestReleaseManifest(fileDirectoryAlias), /file-directory aliases/u);

  for (const dependency of ["@rpath/evil.dylib", "/usr/lib/../evil.dylib",
    "/usr/lib/libSystem.B.dylib?x", "/usr/lib/%2e%2e/evil.dylib",
    "/usr/lib/evil.dylib\0suffix"]) {
    const manifest = makeManifest();
    manifest.components[0].dynamic_dependency_policy.exact_dependencies = [dependency];
    assert.throws(() => trust.digestReleaseManifest(manifest));
  }
});

test("manifest requires distinct artifact and role-defining code-signing identities", () => {
  for (const mutate of [
    (manifest) => { manifest.components[1].sha256 = manifest.components[0].sha256; },
    (manifest) => {
      manifest.components[1].macho_signing_policy.signing_identifier =
        manifest.components[0].macho_signing_policy.signing_identifier;
    },
    (manifest) => {
      manifest.components[1].macho_signing_policy.designated_requirement_digest =
        manifest.components[0].macho_signing_policy.designated_requirement_digest;
    },
  ]) {
    const manifest = makeManifest();
    mutate(manifest);
    assert.throws(() => trust.digestReleaseManifest(manifest), /must be distinct/u);
  }
});

test("target binds Darwin arm64, Node 20, N-API 9, and Node-API-only ABI", () => {
  for (const [field, value] of [["os", "linux"], ["architecture", "x64"],
    ["node_major", 21], ["napi_version", 8], ["node_api_only", false]]) {
    const manifest = makeManifest();
    manifest.target[field] = value;
    assert.throws(() => trust.digestReleaseManifest(manifest));
  }
});

test("doctor blocks dependency and Mach-O signing evidence drift", () => {
  const dependency = createFixture();
  dependency.staticInspection.components[0].actual_dynamic_dependencies = [
    "/usr/lib/libc++.1.dylib",
  ];
  resealStatic(dependency);
  let report = trust.evaluateNativePrebuildDoctor(doctorInput(dependency));
  assert.equal(report.status, "blocked");
  assert.match(report.findings[0], /static_component_rejected/u);

  const adhoc = createFixture();
  adhoc.staticInspection.components[0].macho_signature.adhoc = true;
  resealStatic(adhoc);
  report = trust.evaluateNativePrebuildDoctor(doctorInput(adhoc));
  assert.equal(report.status, "blocked");
  assert.match(report.findings[0], /static_codesign_rejected/u);

  const wrongCodeType = createFixture();
  wrongCodeType.staticInspection.components[0].macho_signature.code_type = "executable";
  resealStatic(wrongCodeType);
  assert.equal(trust.evaluateNativePrebuildDoctor(doctorInput(wrongCodeType)).status, "blocked");
});

test("doctor blocks root ownership, immutability, symlinks, unstable files, and ACL drift", () => {
  const mutations = [
    (fixture) => { fixture.staticInspection.root.install_root_owner_uid = 501; },
    (fixture) => { fixture.staticInspection.root.root_immutable = false; },
    (fixture) => { fixture.staticInspection.root.immutability_scheme = "caller_boolean_only"; },
    (fixture) => { fixture.staticInspection.root.no_symlink_walk = false; },
    (fixture) => { fixture.staticInspection.root.stable_file_identity = false; },
    (fixture) => { fixture.staticInspection.components[0].pre_post_identity_match = false; },
    (fixture) => { fixture.staticInspection.root.principal_acl_evidence_digest = digest("wrong"); },
    (fixture) => { fixture.staticInspection.root.install_root_path_digest = digest("wrong-root"); },
  ];
  for (const mutate of mutations) {
    const fixture = createFixture();
    mutate(fixture);
    resealStatic(fixture);
    assert.equal(trust.evaluateNativePrebuildDoctor(doctorInput(fixture)).status, "blocked");
  }
});

test("doctor blocks mapped-image and equivalent-host-control gaps", () => {
  const mutations = [
    (fixture) => { fixture.nativeAttestation.components[0].loaded_image_sha256 = digest("wrong"); },
    (fixture) => { fixture.nativeAttestation.components[0].mapped_process_image_bound = false; },
    (fixture) => {
      fixture.nativeAttestation.components[0].loaded_or_exec_image_identity_digest =
        digest("substituted-loaded-or-exec-identity");
    },
    (fixture) => {
      fixture.nativeAttestation.components[0].mapped_process_image_identity_digest =
        digest("substituted-mapped-process-identity");
    },
    (fixture) => {
      fixture.nativeAttestation.components[0].identity_binding_digest =
        digest("fabricated-identity-binding");
    },
    (fixture) => {
      fixture.nativeAttestation.components[0].host_or_equivalent_validation_mode =
        "unqualified_stock_host";
    },
    (fixture) => {
      fixture.nativeAttestation.components[2].host_or_equivalent_validation_complete = false;
    },
    (fixture) => { fixture.nativeAttestation.attestor.kernel_evidence_complete = false; },
    (fixture) => {
      fixture.nativeAttestation.components[0].on_disk_fd_identity_digest = digest("wrong-fd");
    },
    (fixture) => {
      fixture.nativeAttestation.attestor.source_digest = digest("untrusted-attestor-source");
    },
    (fixture) => {
      fixture.nativeAttestation.attestor.filesystem_immutability_evidence_digest =
        digest("different-filesystem-evidence");
    },
    (fixture) => {
      fixture.nativeAttestation.attestor.principal_acl_evidence_digest =
        digest("different-acl-evidence");
    },
  ];
  for (const mutate of mutations) {
    const fixture = createFixture();
    mutate(fixture);
    resealNative(fixture);
    assert.equal(trust.evaluateNativePrebuildDoctor(doctorInput(fixture)).status, "blocked");
  }
});

test("doctor rejects one retained or mapped object serving multiple component roles", () => {
  for (const field of ["fd_identity_digest", "selected_cdhash"]) {
    const fixture = createFixture();
    if (field === "fd_identity_digest") {
      fixture.staticInspection.components[1].fd_identity_digest =
        fixture.staticInspection.components[0].fd_identity_digest;
    } else {
      fixture.staticInspection.components[1].macho_signature.selected_cdhash =
        fixture.staticInspection.components[0].macho_signature.selected_cdhash;
    }
    resealStatic(fixture);
    const report = trust.evaluateNativePrebuildDoctor(doctorInput(fixture));
    assert.equal(report.status, "blocked");
    assert.match(report.findings[0], /static_component_identity_collision/u);
  }

  for (const field of [
    "loaded_or_exec_image_identity_digest",
    "mapped_process_image_identity_digest",
  ]) {
    const fixture = createFixture();
    fixture.nativeAttestation.components[1][field] =
      fixture.nativeAttestation.components[0][field];
    resealNativeComponentBinding(fixture, 1);
    const report = trust.evaluateNativePrebuildDoctor(doctorInput(fixture));
    assert.equal(report.status, "blocked");
    assert.match(report.findings[0], /native_component_identity_collision/u);
  }
});

test("doctor blocks incomplete or transplanted HIL evidence", () => {
  const failed = createFixture();
  failed.hilEvidence.gate_results[0].passed = false;
  const failedBody = clone(failed.hilEvidence);
  delete failedBody.hil_evidence_digest;
  failed.hilEvidence.hil_evidence_digest = trust.digestHilEvidenceBody(failedBody);
  assert.equal(trust.evaluateNativePrebuildDoctor(doctorInput(failed)).status, "blocked");

  const transplanted = createFixture();
  transplanted.hilEvidence.native_attestation_digest = digest("another-attestation");
  const transplantedBody = clone(transplanted.hilEvidence);
  delete transplantedBody.hil_evidence_digest;
  transplanted.hilEvidence.hil_evidence_digest = trust.digestHilEvidenceBody(transplantedBody);
  assert.equal(trust.evaluateNativePrebuildDoctor(doctorInput(transplanted)).status, "blocked");

  const wrongSuite = createFixture();
  wrongSuite.hilEvidence.suite_digest = digest("another-suite");
  const wrongSuiteBody = clone(wrongSuite.hilEvidence);
  delete wrongSuiteBody.hil_evidence_digest;
  wrongSuite.hilEvidence.hil_evidence_digest = trust.digestHilEvidenceBody(wrongSuiteBody);
  assert.equal(trust.evaluateNativePrebuildDoctor(doctorInput(wrongSuite)).status, "blocked");

  const wrongWitness = createFixture();
  wrongWitness.hilEvidence.gate_results[0].operator_witness_digest = digest("another-witness");
  const wrongWitnessBody = clone(wrongWitness.hilEvidence);
  delete wrongWitnessBody.hil_evidence_digest;
  wrongWitness.hilEvidence.hil_evidence_digest = trust.digestHilEvidenceBody(wrongWitnessBody);
  assert.equal(trust.evaluateNativePrebuildDoctor(doctorInput(wrongWitness)).status, "blocked");
});

test("doctor rejects stale native and HIL evidence despite self-consistent digests", () => {
  const staleNative = createFixture();
  staleNative.nativeAttestation.observed_at = "2026-07-19T11:30:00.000Z";
  staleNative.nativeAttestation.valid_until = "2026-07-19T11:50:00.000Z";
  resealNative(staleNative);
  assert.equal(trust.evaluateNativePrebuildDoctor(doctorInput(staleNative)).status, "blocked");

  const staleHil = createFixture();
  staleHil.hilEvidence.run_at = "2026-07-19T11:40:00.000Z";
  staleHil.hilEvidence.valid_until = "2026-07-19T11:50:00.000Z";
  const staleHilBody = clone(staleHil.hilEvidence);
  delete staleHilBody.hil_evidence_digest;
  staleHil.hilEvidence.hil_evidence_digest = trust.digestHilEvidenceBody(staleHilBody);
  assert.equal(trust.evaluateNativePrebuildDoctor(doctorInput(staleHil)).status, "blocked");
});

test("closed schemas reject proxies, accessors, symbols, sparse arrays, and extra fields", () => {
  const proxyFixture = createFixture();
  let trapRead = false;
  proxyFixture.envelope.manifest = new Proxy(proxyFixture.envelope.manifest, {
    get() { trapRead = true; throw new Error("getter trap"); },
  });
  const proxyReport = trust.evaluateNativePrebuildDoctor(doctorInput(proxyFixture));
  assert.equal(proxyReport.status, "unavailable");
  assert.equal(trapRead, false);

  const accessorManifest = makeManifest();
  let getterRead = false;
  Object.defineProperty(accessorManifest, "package_name", {
    enumerable: true,
    get() { getterRead = true; return PACKAGE_NAME; },
  });
  assert.throws(() => trust.digestReleaseManifest(accessorManifest));
  assert.equal(getterRead, false);

  const symbolManifest = makeManifest();
  symbolManifest[Symbol("hidden")] = "surprise";
  assert.throws(() => trust.digestReleaseManifest(symbolManifest));

  const sparseManifest = makeManifest();
  sparseManifest.components = new Array(4);
  sparseManifest.components[0] = makeManifest().components[0];
  assert.throws(() => trust.digestReleaseManifest(sparseManifest));

  const extra = makeManifest();
  extra.production_ready = true;
  assert.throws(() => trust.digestReleaseManifest(extra));
});

test("evidence digests are domain-separated and reject hostile evidence bodies", () => {
  const fixture = createFixture();
  const staticBody = clone(fixture.staticInspection);
  delete staticBody.inspection_digest;
  const nativeBody = clone(fixture.nativeAttestation);
  delete nativeBody.attestation_digest;
  assert.notEqual(trust.digestStaticInspectionEvidenceBody(staticBody),
    trust.digestNativeAttestationEvidenceBody(nativeBody));
  assert.throws(() => trust.digestStaticInspectionEvidenceBody(new Proxy(staticBody, {})));
  staticBody[Symbol("hidden")] = true;
  assert.throws(() => trust.digestStaticInspectionEvidenceBody(staticBody));
});

test("public API contains verification and diagnostics but no signer or private key", () => {
  const names = Object.keys(trust);
  assert.equal(names.some((name) => /private|signEnvelope|createReleaseEnvelope/u.test(name)), false);
  assert.equal(typeof trust.verifyReleaseEnvelope, "function");
  assert.equal(typeof trust.evaluateNativePrebuildDoctor, "function");
  assert.equal("production_ready" in trust, false);
});

test("package import is inert: no filesystem, process, network, native, or hardware activation", () => {
  const script = `
    const Module = require("node:module");
    const original = Module._load;
    const forbidden = new Set([
      "node:fs", "fs", "node:child_process", "child_process", "node:net", "net",
      "node:dgram", "dgram", "node:http", "http", "node:https", "https",
      "node:worker_threads", "worker_threads", "serialport", "usb"
    ]);
    process.dlopen = () => { throw new Error("native load on import"); };
    Module._load = function(request, parent, isMain) {
      if (forbidden.has(request) || request.endsWith(".node")) {
        throw new Error("forbidden import activation: " + request);
      }
      return Reflect.apply(original, this, [request, parent, isMain]);
    };
    const before = process._getActiveHandles().length;
    const api = require(${JSON.stringify(PACKAGE_ROOT)});
    if (typeof api.verifyReleaseEnvelope !== "function") process.exit(21);
    if (process._getActiveHandles().length !== before) process.exit(22);
  `;
  const result = spawnSync(process.execPath, ["-e", script], {
    encoding: "utf8",
    timeout: 5000,
  });
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stdout, "");
});

test("verification survives hostile same-process mutable intrinsic replacement", () => {
  const fixture = createFixture();
  const payload = Buffer.from(JSON.stringify({
    verification: {
      envelope: fixture.envelope,
      trust_policy: fixture.trustPolicy,
      now: NOW,
    },
    doctor: doctorInput(fixture),
  })).toString("base64url");
  const script = `
    const crypto = require("node:crypto");
    const api = require(${JSON.stringify(PACKAGE_ROOT)});
    const input = JSON.parse(Buffer.from(${JSON.stringify(payload)}, "base64url").toString("utf8"));
    const der = Buffer.from(input.verification.trust_policy.keys[0].public_key_spki_der,
      "base64url");
    const key = crypto.createPublicKey({ key: der, type: "spki", format: "der" });
    const keyPrototype = Object.getPrototypeOf(key);
    Set.prototype.has = () => { throw new Error("poisoned Set.has"); };
    Set.prototype.add = () => { throw new Error("poisoned Set.add"); };
    global.Set = function PoisonedSet() { throw new Error("poisoned Set constructor"); };
    Array.prototype.map = () => { throw new Error("poisoned Array.map"); };
    Buffer.prototype.equals = () => { throw new Error("poisoned Buffer.equals"); };
    keyPrototype.export = () => { throw new Error("poisoned KeyObject.export"); };
    const verified = api.verifyReleaseEnvelope(input.verification);
    if (!verified.release_signature_valid) process.exit(31);
    const report = api.evaluateNativePrebuildDoctor(input.doctor);
    if (report.status !== "diagnostic_complete_non_authorizing") process.exit(32);
    const attacker = crypto.generateKeyPairSync("ed25519");
    const auth = input.verification.envelope.authentication;
    auth.signature = crypto.sign(null, api.releaseSignatureMessage({
      manifest_digest: auth.signed_manifest_digest,
      key_id: auth.key_id,
      public_key_digest: auth.public_key_digest,
      trust_epoch: auth.trust_epoch,
    }), attacker.privateKey).toString("base64url");
    let keySubstitutions = 0;
    Object.defineProperty(Array.prototype, "0", {
      configurable: true,
      set(value) {
        const substitute = value != null && value.type === "public"
          && value.asymmetricKeyType === "ed25519";
        if (substitute) keySubstitutions += 1;
        Object.defineProperty(this, "0", {
          value: substitute ? attacker.publicKey : value,
          enumerable: true,
          writable: true,
          configurable: true,
        });
      },
    });
    let forgedResult = "accepted";
    try {
      api.verifyReleaseEnvelope(input.verification);
    } catch (error) {
      forgedResult = error.code;
    } finally {
      delete Array.prototype[0];
    }
    if (forgedResult !== "signature_invalid" || keySubstitutions !== 0) process.exit(33);
  `;
  const result = spawnSync(process.execPath, ["-e", script], {
    encoding: "utf8",
    timeout: 5000,
  });
  assert.equal(result.status, 0, result.stderr);
});

test("dry-run package contains source/docs only and excludes tests, binaries, and secrets", () => {
  const result = spawnSync("npm", ["pack", "--dry-run", "--json", "--ignore-scripts"], {
    cwd: PACKAGE_ROOT,
    encoding: "utf8",
    timeout: 30_000,
  });
  assert.equal(result.status, 0, result.stderr);
  const report = JSON.parse(result.stdout);
  const files = report[0].files.map((entry) => entry.path).sort();
  assert.deepEqual(files, [
    "README.md",
    "lib/data-contract.js",
    "lib/doctor-v2.js",
    "lib/doctor.js",
    "lib/index.js",
    "lib/javascript-worker-closure.js",
    "lib/release-trust-v2.js",
    "lib/release-trust.js",
    "package.json",
  ]);
  assert.equal(files.some((file) => /(?:^|\/)test(?:\/|$)|\.node$|PRIVATE|secret/iu.test(file)),
    false);
});
