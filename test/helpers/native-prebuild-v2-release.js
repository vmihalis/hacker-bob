"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");

const trust = require("../../packages/bob-instrument-native-prebuild-trust/lib/index.js");

const PACKAGE_NAME = "@hacker-bob/instrument-native-prebuild-darwin-arm64";
const PACKAGE_VERSION = "2.0.0";
const NOW = "2026-07-19T12:00:00.000Z";
const ARTIFACT_PATHS = Object.freeze([
  "native/ipc-acceptor.node",
  "native/chameleon-cdc-custody.node",
  "bin/bob-safety-watchdog",
  "bin/bob-privileged-launcher",
  "bin/bob-lifecycle-custodian",
  "bin/bob-native-dispatch-custodian",
]);
const ARTIFACT_KINDS = Object.freeze([
  "node_native_addon",
  "node_native_addon",
  "mach_o_executable",
  "mach_o_executable",
  "mach_o_executable",
  "mach_o_executable",
]);
const CODE_TYPES = Object.freeze([
  "bundle",
  "bundle",
  "executable",
  "executable",
  "executable",
  "executable",
]);

function digest(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function writeJson(filePath, value) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, `${JSON.stringify(value, null, 2)}\n`, "utf8");
}

function schemaContents(label) {
  const byteSize = 512 + label.length;
  return Buffer.from(`{"fixture_schema":"${label}"}`.padEnd(byteSize, " "), "utf8");
}

function schemaArtifact(label) {
  const contents = schemaContents(label);
  return {
    artifact_path: `schemas/${label}.schema.json`,
    byte_size: contents.length,
    sha256: digest(contents),
    media_type: "application/schema+json",
    canonicalization: "jcs_rfc8785_v1",
    load_scheme: "openat_no_follow_fd_sha256_v1",
  };
}

function manifestSchemaArtifacts(manifest) {
  const schemas = [];
  for (const component of manifest.components) {
    for (const field of [
      "request_schema",
      "result_schema",
      "effect_journal_schema",
      "receipt_schema",
    ]) {
      schemas.push(component.capability_abi[field]);
    }
  }
  const durable = manifest.authority_handoff_policy.durable_exchange_policy;
  for (const field of [
    "grant_record_schema",
    "go_record_schema",
    "receipt_record_schema",
    "outbox_record_schema",
  ]) {
    schemas.push(durable[field]);
  }
  return schemas.map((schema) => {
    const prefix = "schemas/";
    const suffix = ".schema.json";
    const label = schema.artifact_path.slice(prefix.length, -suffix.length);
    return {
      path: schema.artifact_path,
      contents: schemaContents(label),
    };
  });
}

function serializedRequirement(index) {
  const bytes = Buffer.from(`hacker-bob-sec-requirement-v2:${index}:exact-binary`, "utf8");
  return {
    format: "security_framework_sec_requirement_data_v1",
    data: bytes.toString("base64url"),
    byte_size: bytes.length,
    digest: digest(bytes),
  };
}

function componentRecord(componentId, index, artifact) {
  const byteSize = artifact.contents.length;
  const uuid = `${index + 1}`.repeat(32);
  const requirement = serializedRequirement(index);
  return {
    component_id: componentId,
    artifact_path: artifact.path,
    artifact_kind: ARTIFACT_KINDS[index],
    byte_size: byteSize,
    sha256: digest(artifact.contents),
    source_digest: digest(`v2-source-${index}`),
    builder_digest: digest(`v2-builder-${index}`),
    toolchain_digest: digest(`v2-toolchain-${index}`),
    provenance_digest: digest(`v2-provenance-${index}`),
    exact_dynamic_dependencies: ["/usr/lib/libSystem.B.dylib"],
    code_identity: {
      signature_kind: "developer_id",
      code_type: CODE_TYPES[index],
      team_identifier: "ABCDEF1234",
      signing_identifier: `org.hackerbob.native.v2.${componentId.replaceAll("_", "-")}`,
      cdhash_algorithm: "sha256_truncated_160",
      selected_cdhash: `${index + 1}`.repeat(40),
      candidate_set_digest_scheme: "darwin_cdhash_candidate_set_jcs_v1",
      candidate_set_digest: digest(`v2-candidate-set-${index}`),
      serialized_sec_requirement_format: requirement.format,
      serialized_sec_requirement_data_base64url: requirement.data,
      serialized_sec_requirement_byte_size: requirement.byte_size,
      serialized_sec_requirement_digest: requirement.digest,
      code_directory_flags: 0x10000 + index,
      entitlements_digest_scheme: "security_entitlements_der_sha256_v1",
      entitlements_digest: digest(`v2-entitlements-${index}`),
      hardened_runtime_required: true,
      notarization_required: true,
      adhoc_allowed: false,
    },
    macho_identity: {
      file_type: index < 2 ? 8 : 2,
      cpu_type: 16777228,
      cpu_subtype: 0,
      macho_flags: 0x200000 + index,
      uuid,
      load_commands_digest: digest(`v2-load-commands-${index}`),
      code_signature_blob_digest: digest(`v2-code-signature-${index}`),
      text_segment_file_digest: digest(`v2-text-file-${index}`),
      slice_offset: 0,
      slice_size: byteSize,
    },
    launch_principal: {
      principal_id: `bob_native_${index + 1}`,
      uid: 601 + index,
      gid: 701 + index,
      supplementary_groups_digest: digest(`v2-groups-${index}`),
      audit_session_policy_digest: digest(`v2-audit-session-${index}`),
      sandbox_profile_digest: digest(`v2-sandbox-${index}`),
      no_login_identity: true,
      clear_supplementary_groups: true,
      identity_drop_before_capability_grant: true,
    },
    mapped_measurement: {
      scheme: "darwin_running_code_guest_audit_token_v1",
      expected_mapped_text_digest: digest(`v2-mapped-text-${index}`),
      expected_mapped_linkedit_digest: digest(`v2-mapped-linkedit-${index}`),
      expected_loaded_uuid: uuid,
      measurement_layout_digest: digest(`v2-measurement-layout-${index}`),
      require_kernel_audit_token: true,
      require_pidversion_binding: true,
      require_running_code_guest_validation: true,
      require_cdhash_match: true,
      require_macho_uuid_match: true,
      require_pre_grant_measurement: true,
      require_post_grant_identity_stability: true,
    },
    capability_abi: {
      abi_id: `bob_native_abi_${index + 1}`,
      abi_version: 1,
      request_schema: schemaArtifact(`${componentId}-request`),
      result_schema: schemaArtifact(`${componentId}-result`),
      effect_journal_schema: schemaArtifact(`${componentId}-effect-journal`),
      receipt_schema: schemaArtifact(`${componentId}-receipt`),
      descriptor_count: 2,
      descriptor_table: [{
        ordinal: 0,
        role: "authority_root",
        descriptor_type: "directory",
        access_mode: "read_only",
        required_status_flags: 0,
        forbidden_status_flags: 11,
        required_descriptor_flags: 1,
        forbidden_descriptor_flags: 0,
        sender_cloexec_required: true,
        receiver_cloexec_before_ack: true,
        identity_recheck_before_effect: true,
        close_before_receipt: true,
        transfer_mode: "scm_rights_once_v1",
      }, {
        ordinal: 1,
        role: "result_channel",
        descriptor_type: "unix_stream_socket",
        access_mode: "read_write",
        required_status_flags: 6,
        forbidden_status_flags: 9,
        required_descriptor_flags: 1,
        forbidden_descriptor_flags: 0,
        sender_cloexec_required: true,
        receiver_cloexec_before_ack: true,
        identity_recheck_before_effect: true,
        close_before_receipt: true,
        transfer_mode: "scm_rights_once_v1",
      }],
      single_grant: true,
      forbid_path_reopen: true,
      close_unexpected_descriptors: true,
    },
  };
}

function createManifest(artifacts) {
  return {
    version: 2,
    kind: "native_prebuild_release_manifest",
    package_name: PACKAGE_NAME,
    package_version: PACKAGE_VERSION,
    release_id: "native-prebuild-v2:2026.07.19.optional-provider-test",
    release_epoch: 11,
    target: {
      os: "darwin",
      architecture: "arm64",
      node_major: 20,
      napi_version: 9,
      node_api_only: true,
      deployment_format: "signed_immutable_prebuild_set_v2",
    },
    components: trust.NATIVE_PREBUILD_REQUIRED_COMPONENTS_V2.map(
      (componentId, index) => componentRecord(componentId, index, artifacts[index]),
    ),
    source_tree_digest: digest("v2-source-tree"),
    builder_identity_digest: digest("v2-builder-identity"),
    toolchain_manifest_digest: digest("v2-toolchain-manifest"),
    provenance_statement_digest: digest("v2-provenance-statement"),
    principal_acl_policy_digest: digest("v2-principal-acl-policy"),
    immutable_install_policy_digest: digest("v2-immutable-install-policy"),
    authority_handoff_policy: {
      scheme: "post_exec_audittoken_seccode_scm_rights_v1",
      supervisor_component_id: "privileged_launcher",
      supervisor_role: "post_exec_capability_supervisor",
      process_lineage_scheme: "audit_token_pidversion_instance_start_direct_parent_v1",
      listener_identity_scheme: "root_owned_single_launch_listener_generation_v1",
      post_exec_connection_scheme: "fresh_post_exec_af_unix_connection_v1",
      capability_set_digest_scheme: "ordered_descriptor_semantics_sha256_v1",
      grant_go_binding_scheme: "durable_grant_go_sequence_binding_v1",
      transport: "af_unix_sock_stream_scm_rights_v1",
      peer_identity_scheme: "local_peertoken_audit_token_pidversion_v1",
      running_code_validation_scheme: "seccodecopyguestwithattributes_audit_v1",
      security_requirement_validation_scheme: "serialized_secrequirement_exact_match_v1",
      deadline_policy: {
        clock: "mach_continuous_time_v1",
        challenge_timeout_ms: 2000,
        attestation_timeout_ms: 2000,
        grant_timeout_ms: 2000,
        go_timeout_ms: 2000,
        receipt_timeout_ms: 2000,
        cleanup_timeout_ms: 2000,
        total_timeout_ms: 12000,
        clamp_to_parent_deadline: true,
        signed_deadline_in_grant: true,
        check_before_each_effect: true,
      },
      nonce_policy: {
        scheme: "getentropy_256bit_monotonic_generation_v1",
        entropy_bits: 256,
        generation_bits: 64,
        bind_manifest_digest: true,
        bind_component_id: true,
        bind_audit_token: true,
        monotonic_generation: true,
        single_use: true,
        durable_replay_fence_before_grant: true,
      },
      durable_exchange_policy: {
        scheme: "durable_grant_go_receipt_outbox_v1",
        grant_record_schema: schemaArtifact("handoff-grant-record"),
        go_record_schema: schemaArtifact("handoff-go-record"),
        receipt_record_schema: schemaArtifact("handoff-receipt-record"),
        outbox_record_schema: schemaArtifact("handoff-outbox-record"),
        fsync_grant_before_go: true,
        go_only_after_scm_rights_ack: true,
        fsync_receipt_before_success: true,
        fsync_outbox_before_ack: true,
        effect_receipt_correlation_required: true,
        unreceipted_grant_recovery_required: true,
        close_capabilities_before_receipt: true,
        authenticated_receipt_required: true,
        fail_closed_on_receipt_loss: true,
      },
    },
    doctor_policy: {
      external_keyring_policy_digest: digest("v2-external-keyring-policy"),
      live_attestor_policy_digest: digest("v2-live-attestor-policy"),
      max_evidence_age_ms: 20 * 60 * 1000,
      require_external_immutable_keyring: true,
      require_live_native_attestation: true,
      require_native_transcript_authentication: true,
    },
    issued_at: "2026-07-19T00:00:00.000Z",
    expires_at: "2026-07-20T00:00:00.000Z",
  };
}

function createNativePrebuildV2ReleaseSource(root) {
  const artifacts = ARTIFACT_PATHS.map((artifactPath, index) => ({
    path: artifactPath,
    contents: Buffer.from(`inert-v2-signed-artifact-${index}-${"x".repeat(index + 1)}`, "utf8"),
  }));
  const manifest = createManifest(artifacts);
  const schemaArtifacts = manifestSchemaArtifacts(manifest);
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  const publicDer = publicKey.export({ type: "spki", format: "der" });
  const publicKeyDigest = digest(publicDer);
  const manifestDigest = trust.digestReleaseManifestV2(manifest);
  const claim = {
    manifest_digest: manifestDigest,
    key_id: "native-release-v2-key:optional-provider-test",
    public_key_digest: publicKeyDigest,
    trust_epoch: 11,
  };
  const envelope = {
    version: 2,
    kind: "signed_native_prebuild_release",
    signature_domain: trust.NATIVE_PREBUILD_SIGNATURE_V2_DOMAIN,
    manifest,
    manifest_digest: manifestDigest,
    authentication: {
      scheme: "ed25519",
      key_usage: trust.NATIVE_PREBUILD_KEY_V2_USAGE,
      key_id: claim.key_id,
      public_key_digest: publicKeyDigest,
      trust_epoch: 11,
      signed_manifest_digest: manifestDigest,
      signature: crypto.sign(null, trust.releaseSignatureMessageV2(claim), privateKey)
        .toString("base64url"),
    },
  };
  const trustPolicy = {
    version: 2,
    kind: "native_prebuild_trust_policy",
    current_trust_epoch: 11,
    minimum_release_epoch: 11,
    revoked_release_ids: [],
    revoked_manifest_digests: [],
    keys: [{
      key_id: claim.key_id,
      public_key_spki_der: publicDer.toString("base64url"),
      public_key_digest: publicKeyDigest,
      trust_epoch: 11,
      not_before: "2026-07-18T00:00:00.000Z",
      not_after: "2026-07-21T00:00:00.000Z",
      revoked: false,
      revocation_epoch: 0,
      allowed_package_names: [PACKAGE_NAME],
      allowed_component_ids: [...trust.NATIVE_PREBUILD_REQUIRED_COMPONENTS_V2],
    }],
  };

  fs.mkdirSync(root, { recursive: true });
  writeJson(path.join(root, "package.json"), {
    name: PACKAGE_NAME,
    version: PACKAGE_VERSION,
    private: true,
    type: "commonjs",
  });
  for (let index = 0; index < artifacts.length; index += 1) {
    const artifact = artifacts[index];
    const destination = path.join(root, ...artifact.path.split("/"));
    fs.mkdirSync(path.dirname(destination), { recursive: true });
    fs.writeFileSync(destination, artifact.contents);
    fs.chmodSync(destination, ARTIFACT_KINDS[index] === "mach_o_executable" ? 0o755 : 0o644);
  }
  for (const schema of schemaArtifacts) {
    const destination = path.join(root, ...schema.path.split("/"));
    fs.mkdirSync(path.dirname(destination), { recursive: true });
    fs.writeFileSync(destination, schema.contents);
    fs.chmodSync(destination, 0o644);
  }

  return {
    artifacts,
    schemaArtifacts,
    manifest,
    releaseVerification: {
      envelope,
      trust_policy: trustPolicy,
      now: NOW,
    },
  };
}

module.exports = {
  createNativePrebuildV2ReleaseSource,
};
