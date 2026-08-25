"use strict";

const assert = require("node:assert/strict");
const { spawnSync } = require("node:child_process");
const crypto = require("node:crypto");
const path = require("node:path");
const test = require("node:test");

const trust = require("../lib");
const golden = require("./vectors/native-prebuild-v2-golden.json");

const NOW = "2026-07-19T12:00:00.000Z";
const PACKAGE_NAME = "@hacker-bob/instrument-native-prebuild-darwin-arm64";
const PACKAGE_ROOT = path.resolve(__dirname, "..");
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
  "bundle", "bundle", "executable", "executable", "executable", "executable",
]);

function digest(label) {
  return crypto.createHash("sha256").update(label).digest("hex");
}

function clone(value) {
  return structuredClone(value);
}

function supervisorIdentityAtListener(supervisor, lineage) {
  const identity = clone(supervisor);
  identity.supervisor_listener_generation = lineage.supervisor_listener_generation;
  identity.supervisor_listener_identity_digest = lineage.supervisor_listener_identity_digest;
  return identity;
}

function schemaArtifact(label) {
  return {
    artifact_path: `schemas/${label}.schema.json`,
    byte_size: 512 + label.length,
    sha256: digest(`schema-artifact:${label}`),
    media_type: "application/schema+json",
    canonicalization: "jcs_rfc8785_v1",
    load_scheme: "openat_no_follow_fd_sha256_v1",
  };
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

function makeManifestV2() {
  return {
    version: 2,
    kind: "native_prebuild_release_manifest",
    package_name: PACKAGE_NAME,
    package_version: "2.0.0",
    release_id: "native-prebuild-v2:2026.07.19.1",
    release_epoch: 11,
    target: {
      os: "darwin",
      architecture: "arm64",
      node_major: 20,
      napi_version: 9,
      node_api_only: true,
      deployment_format: "signed_immutable_prebuild_set_v2",
    },
    components: trust.NATIVE_PREBUILD_REQUIRED_COMPONENTS_V2.map((componentId, index) => {
      const byteSize = 16384 + index;
      const uuid = `${index + 1}`.repeat(32);
      const requirement = serializedRequirement(index);
      return {
        component_id: componentId,
        artifact_path: ARTIFACT_PATHS[index],
        artifact_kind: ARTIFACT_KINDS[index],
        byte_size: byteSize,
        sha256: digest(`v2-artifact-${index}`),
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
    }),
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

function makeSession(component, index) {
  const second = (value) => `2026-07-19T11:50:${String(value).padStart(2, "0")}.000Z`;
  const session = {
    component_id: component.component_id,
    handoff_session_id: `v2-session:${index + 1}`,
    worker_lineage: clone(component.component_handoff.worker_lineage),
    exchange_binding: clone(component.component_handoff.exchange_binding),
    started_at: second(0),
    challenged_at: second(1),
    attested_at: second(2),
    grant_recorded_at: second(3),
    scm_rights_acked_at: second(4),
    go_recorded_at: second(5),
    effect_recorded_at: second(6),
    receipt_recorded_at: second(7),
    outbox_recorded_at: second(8),
    completed_at: second(9),
    receipt_record_digest: digest(`v2-receipt-record-${index}`),
    outbox_record_digest: digest(`v2-outbox-record-${index}`),
    handoff_session_digest: digest(`v2-transcript-placeholder-${index}`),
    attested_before_grant: true,
    single_scm_rights_grant: true,
    grant_fsynced_before_go: true,
    go_after_scm_rights_ack: true,
    receipt_fsynced_before_success: true,
    outbox_fsynced_before_ack: true,
    capabilities_closed_before_receipt: true,
    receipt_authenticated: true,
    effect_receipt_correlated: true,
  };
  const body = clone(session);
  delete body.handoff_session_digest;
  session.handoff_session_digest = trust.digestHandoffSessionV2(body);
  return session;
}

function observedMacho(component) {
  return clone(component.macho_identity);
}

function observedPrincipal(component) {
  return {
    principal_id: component.launch_principal.principal_id,
    uid: component.launch_principal.uid,
    gid: component.launch_principal.gid,
    supplementary_groups_digest: component.launch_principal.supplementary_groups_digest,
    audit_session_policy_digest: component.launch_principal.audit_session_policy_digest,
    sandbox_profile_digest: component.launch_principal.sandbox_profile_digest,
    no_login_identity: true,
    supplementary_groups_cleared: true,
    identity_dropped_before_capability_grant: true,
  };
}

function observedSchema(schema, label) {
  return {
    artifact_path: schema.artifact_path,
    byte_size: schema.byte_size,
    sha256: schema.sha256,
    fd_identity_digest: digest(`observed-schema-fd:${label}`),
    media_type: schema.media_type,
    canonicalization: schema.canonicalization,
    load_scheme: schema.load_scheme,
    regular_file: true,
    single_link: true,
    immutable: true,
    openat_no_follow: true,
    pre_post_identity_match: true,
    sha256_verified: true,
    parser_compiled: true,
  };
}

function observedAbi(component, index) {
  return {
    abi_id: component.capability_abi.abi_id,
    abi_version: component.capability_abi.abi_version,
    request_schema: observedSchema(component.capability_abi.request_schema,
      `${index}:request`),
    result_schema: observedSchema(component.capability_abi.result_schema, `${index}:result`),
    effect_journal_schema: observedSchema(component.capability_abi.effect_journal_schema,
      `${index}:effect-journal`),
    receipt_schema: observedSchema(component.capability_abi.receipt_schema,
      `${index}:receipt`),
    descriptor_count: component.capability_abi.descriptor_count,
    descriptor_table: component.capability_abi.descriptor_table.map((row, descriptorIndex) => ({
      ...row,
      observed_status_flags: row.required_status_flags,
      observed_descriptor_flags: row.required_descriptor_flags,
      descriptor_identity_digest: digest(`observed-capability-fd:${index}:${descriptorIndex}`),
      type_validation_complete: true,
      access_validation_complete: true,
    })),
    single_grant_observed: true,
    no_path_reopen_observed: true,
    unexpected_descriptors_closed: true,
  };
}

function observedMapped(component) {
  const body = {
    scheme: component.mapped_measurement.scheme,
    mapped_text_digest: component.mapped_measurement.expected_mapped_text_digest,
    mapped_linkedit_digest: component.mapped_measurement.expected_mapped_linkedit_digest,
    loaded_uuid: component.mapped_measurement.expected_loaded_uuid,
    measurement_layout_digest: component.mapped_measurement.measurement_layout_digest,
    audit_token_bound: true,
    pidversion_bound: true,
    seccode_guest_validated: true,
    cdhash_matched: true,
    macho_uuid_matched: true,
  };
  return {
    scheme: body.scheme,
    mapped_text_digest: body.mapped_text_digest,
    mapped_linkedit_digest: body.mapped_linkedit_digest,
    loaded_uuid: body.loaded_uuid,
    measurement_layout_digest: body.measurement_layout_digest,
    measurement_digest: trust.digestObservedMappedMeasurementV2(body),
    audit_token_bound: body.audit_token_bound,
    pidversion_bound: body.pidversion_bound,
    seccode_guest_validated: body.seccode_guest_validated,
    cdhash_matched: body.cdhash_matched,
    macho_uuid_matched: body.macho_uuid_matched,
  };
}

function makeEvidenceBody(manifest, manifestDigest) {
  const attestorIdentity = digest("v2-live-attestor-identity");
  const components = manifest.components.map((component, index) => {
    const macho = observedMacho(component);
    const principal = observedPrincipal(component);
    const mapped = observedMapped(component);
    const abi = observedAbi(component, index);
    const fields = {
      component_id: component.component_id,
      artifact_sha256: component.sha256,
      on_disk_fd_identity_digest: digest(`v2-on-disk-fd-${index}`),
      signature_kind: component.code_identity.signature_kind,
      code_type: component.code_identity.code_type,
      team_identifier: component.code_identity.team_identifier,
      signing_identifier: component.code_identity.signing_identifier,
      cdhash_algorithm: component.code_identity.cdhash_algorithm,
      selected_cdhash: component.code_identity.selected_cdhash,
      candidate_set_digest_scheme: component.code_identity.candidate_set_digest_scheme,
      candidate_set_digest: component.code_identity.candidate_set_digest,
      serialized_sec_requirement_digest:
        component.code_identity.serialized_sec_requirement_digest,
      code_directory_flags: component.code_identity.code_directory_flags,
      entitlements_digest_scheme: component.code_identity.entitlements_digest_scheme,
      entitlements_digest: component.code_identity.entitlements_digest,
      candidate_set_enumeration_complete: true,
      serialized_sec_requirement_instantiated: true,
      code_signing_information_complete: true,
      hardened_runtime: true,
      notarization_verified: true,
      adhoc: false,
      macho_identity: macho,
      launch_principal: principal,
      mapped_measurement: mapped,
      capability_abi: abi,
      running_code_identity_digest: digest(`v2-running-code-${index}`),
    };
    return {
      ...fields,
      static_code_fd_validated: true,
      running_code_guest_validated: true,
      audit_token_kernel_originated: true,
      pre_grant_measurement_complete: true,
      post_grant_identity_stable: true,
    };
  });
  const supervisorComponentIndex = trust.NATIVE_PREBUILD_REQUIRED_COMPONENTS_V2
    .indexOf(manifest.authority_handoff_policy.supervisor_component_id);
  const supervisorComponent = components[supervisorComponentIndex];
  const supervisorIdentity = {
    supervisor_component_id: manifest.authority_handoff_policy.supervisor_component_id,
    supervisor_role: manifest.authority_handoff_policy.supervisor_role,
    supervisor_audit_token_digest: digest("v2-supervisor-audit-token"),
    supervisor_process_id: 900,
    supervisor_process_pidversion: 1900,
    supervisor_process_instance_digest: digest("v2-supervisor-process-instance"),
    supervisor_process_start_digest: digest("v2-supervisor-process-start"),
    supervisor_mapped_image_digest: supervisorComponent.mapped_measurement.measurement_digest,
    supervisor_principal_id: supervisorComponent.launch_principal.principal_id,
    supervisor_principal_policy_digest:
      trust.digestObservedLaunchPrincipalV2(supervisorComponent.launch_principal),
    supervisor_listener_generation: `${components.length - 1}`,
    supervisor_listener_identity_digest:
      digest(`v2-supervisor-listener-${components.length - 2}`),
  };
  supervisorComponent.component_handoff = {
    kind: "supervisor",
    supervisor_identity: clone(supervisorIdentity),
  };
  const recipientComponents = [];
  let recipientIndex = 0;
  for (let index = 0; index < components.length; index += 1) {
    const component = components[index];
    if (component.component_id === manifest.authority_handoff_policy.supervisor_component_id) {
      continue;
    }
    const abiDigest = trust.digestObservedCapabilityAbiV2(component.capability_abi);
    const handoffSessionId = `v2-session:${recipientIndex + 1}`;
    const workerLineage = {
      worker_audit_token_digest: digest(`v2-worker-audit-token-${index}`),
      worker_process_id: 1000 + index,
      worker_process_pidversion: 2000 + index,
      worker_process_instance_digest: digest(`v2-worker-process-instance-${index}`),
      worker_process_start_digest: digest(`v2-worker-process-start-${index}`),
      worker_mapped_image_digest: component.mapped_measurement.measurement_digest,
      worker_principal_id: component.launch_principal.principal_id,
      worker_principal_policy_digest:
        trust.digestObservedLaunchPrincipalV2(component.launch_principal),
      worker_direct_parent_process_id: supervisorIdentity.supervisor_process_id,
      worker_direct_parent_audit_token_digest:
        supervisorIdentity.supervisor_audit_token_digest,
      worker_direct_parent_instance_digest:
        supervisorIdentity.supervisor_process_instance_digest,
      worker_direct_parent_start_digest: supervisorIdentity.supervisor_process_start_digest,
      supervisor_listener_generation: `${recipientIndex + 1}`,
      supervisor_listener_identity_digest:
        digest(`v2-supervisor-listener-${recipientIndex}`),
      post_exec_connection_identity_digest: digest(`v2-post-exec-connection-${index}`),
      fresh_post_exec_connection: true,
      direct_child_of_supervisor: true,
    };
    const exchangeBinding = {
      launch_nonce_digest: digest(`v2-launch-nonce-${index}`),
      launch_generation: `${recipientIndex + 1}`,
      capability_set_digest: trust.digestCapabilitySetV2({
        version: 2,
        component_id: component.component_id,
        capability_abi_digest: abiDigest,
      }),
      capability_generation: `${recipientIndex + 1}`,
      capability_abi_digest: abiDigest,
      grant_id: `v2-grant:${recipientIndex + 1}`,
      grant_nonce_digest: digest(`v2-grant-nonce-${index}`),
      grant_sequence: `${(recipientIndex * 2) + 1}`,
      grant_record_digest: digest(`v2-grant-record-placeholder-${index}`),
      go_id: `v2-go:${recipientIndex + 1}`,
      go_sequence: `${(recipientIndex * 2) + 2}`,
      go_record_digest: digest(`v2-go-record-placeholder-${index}`),
    };
    exchangeBinding.grant_record_digest = trust.digestGrantRecordV2({
      version: 2,
      manifest_digest: manifestDigest,
      component_id: component.component_id,
      handoff_session_id: handoffSessionId,
      supervisor_identity: supervisorIdentityAtListener(supervisorIdentity, workerLineage),
      worker_lineage: workerLineage,
      launch_nonce_digest: exchangeBinding.launch_nonce_digest,
      launch_generation: exchangeBinding.launch_generation,
      capability_set_digest: exchangeBinding.capability_set_digest,
      capability_generation: exchangeBinding.capability_generation,
      capability_abi_digest: exchangeBinding.capability_abi_digest,
      grant_id: exchangeBinding.grant_id,
      grant_nonce_digest: exchangeBinding.grant_nonce_digest,
      grant_sequence: exchangeBinding.grant_sequence,
    });
    exchangeBinding.go_record_digest = trust.digestGoRecordV2({
      version: 2,
      manifest_digest: manifestDigest,
      component_id: component.component_id,
      handoff_session_id: handoffSessionId,
      supervisor_identity: supervisorIdentityAtListener(supervisorIdentity, workerLineage),
      worker_lineage: workerLineage,
      launch_nonce_digest: exchangeBinding.launch_nonce_digest,
      launch_generation: exchangeBinding.launch_generation,
      capability_set_digest: exchangeBinding.capability_set_digest,
      capability_generation: exchangeBinding.capability_generation,
      grant_id: exchangeBinding.grant_id,
      grant_sequence: exchangeBinding.grant_sequence,
      grant_record_digest: exchangeBinding.grant_record_digest,
      go_id: exchangeBinding.go_id,
      go_sequence: exchangeBinding.go_sequence,
    });
    component.component_handoff = {
      kind: "capability_recipient",
      worker_lineage: workerLineage,
      exchange_binding: exchangeBinding,
      handoff_session_digest: digest(`v2-transcript-placeholder-${index}`),
    };
    recipientComponents.push(component);
    recipientIndex += 1;
  }
  const sessions = recipientComponents.map((component, index) => makeSession(component, index));
  for (let index = 0; index < recipientComponents.length; index += 1) {
    recipientComponents[index].component_handoff.handoff_session_digest =
      sessions[index].handoff_session_digest;
  }
  for (let index = 0; index < components.length; index += 1) {
    const component = components[index];
    component.component_binding_digest = trust.digestComponentBindingV2({
      version: 2,
      manifest_digest: manifestDigest,
      component_id: component.component_id,
      artifact_sha256: component.artifact_sha256,
      on_disk_fd_identity_digest: component.on_disk_fd_identity_digest,
      component_handoff: component.component_handoff,
      selected_cdhash: component.selected_cdhash,
      candidate_set_digest: component.candidate_set_digest,
      serialized_sec_requirement_digest: component.serialized_sec_requirement_digest,
      code_directory_flags: component.code_directory_flags,
      entitlements_digest: component.entitlements_digest,
      macho_identity_digest: trust.digestObservedMachoIdentityV2(component.macho_identity),
      launch_principal_digest:
        trust.digestObservedLaunchPrincipalV2(component.launch_principal),
      mapped_measurement_digest: component.mapped_measurement.measurement_digest,
      capability_abi_digest: trust.digestObservedCapabilityAbiV2(component.capability_abi),
      running_code_identity_digest: component.running_code_identity_digest,
      attestor_identity_digest: attestorIdentity,
    });
  }
  return {
    version: 2,
    kind: "native_prebuild_post_exec_attestation",
    manifest_digest: manifestDigest,
    evidence_id: "v2-attestation:fixture",
    observed_at: "2026-07-19T11:55:00.000Z",
    valid_until: "2026-07-19T12:10:00.000Z",
    host: { os: "darwin", architecture: "arm64", node_major: 20, napi_version: 9 },
    external_keyring: {
      policy_digest: manifest.doctor_policy.external_keyring_policy_digest,
      evidence_digest: digest("v2-external-keyring-evidence"),
      keyring_identity_digest: digest("v2-keyring-identity"),
      immutable_storage_evidence_digest: digest("v2-keyring-immutable-storage"),
      revocation_snapshot_digest: digest("v2-keyring-revocations"),
      observed_trust_epoch: 11,
      root_owned: true,
      immutable: true,
      external_to_caller: true,
      verified_by_native_attestor: true,
    },
    immutable_install: {
      policy_digest: manifest.immutable_install_policy_digest,
      evidence_digest: digest("v2-immutable-install-evidence"),
      install_identity_digest: digest("v2-install-identity"),
      principal_acl_policy_digest: manifest.principal_acl_policy_digest,
      principal_acl_evidence_digest: digest("v2-principal-acl-evidence"),
      root_owned: true,
      immutable: true,
      descriptor_walk_complete: true,
      no_symlink_walk: true,
      native_attested: true,
    },
    attestor: {
      implementation_digest: digest("v2-attestor-implementation"),
      loaded_image_digest: digest("v2-attestor-loaded-image"),
      identity_digest: attestorIdentity,
      audit_token_digest: digest("v2-attestor-audit-token"),
      native_process: true,
      live_observation: true,
      external_keyring_read_native: true,
      caller_js_authority: false,
    },
    handoff: {
      scheme: manifest.authority_handoff_policy.scheme,
      supervisor_identity: supervisorIdentity,
      process_lineage_scheme: manifest.authority_handoff_policy.process_lineage_scheme,
      listener_identity_scheme: manifest.authority_handoff_policy.listener_identity_scheme,
      post_exec_connection_scheme:
        manifest.authority_handoff_policy.post_exec_connection_scheme,
      capability_set_digest_scheme:
        manifest.authority_handoff_policy.capability_set_digest_scheme,
      grant_go_binding_scheme: manifest.authority_handoff_policy.grant_go_binding_scheme,
      transport: manifest.authority_handoff_policy.transport,
      peer_identity_scheme: manifest.authority_handoff_policy.peer_identity_scheme,
      running_code_validation_scheme:
        manifest.authority_handoff_policy.running_code_validation_scheme,
      security_requirement_validation_scheme:
        manifest.authority_handoff_policy.security_requirement_validation_scheme,
      deadline_clock: manifest.authority_handoff_policy.deadline_policy.clock,
      nonce_scheme: manifest.authority_handoff_policy.nonce_policy.scheme,
      nonce_entropy_bits: manifest.authority_handoff_policy.nonce_policy.entropy_bits,
      nonce_generation_bits: manifest.authority_handoff_policy.nonce_policy.generation_bits,
      durable_exchange_scheme: manifest.authority_handoff_policy.durable_exchange_policy.scheme,
      grant_record_schema: observedSchema(
        manifest.authority_handoff_policy.durable_exchange_policy.grant_record_schema,
        "handoff:grant"),
      go_record_schema: observedSchema(
        manifest.authority_handoff_policy.durable_exchange_policy.go_record_schema,
        "handoff:go"),
      receipt_record_schema: observedSchema(
        manifest.authority_handoff_policy.durable_exchange_policy.receipt_record_schema,
        "handoff:receipt"),
      outbox_record_schema: observedSchema(
        manifest.authority_handoff_policy.durable_exchange_policy.outbox_record_schema,
        "handoff:outbox"),
      replay_fence_identity_digest: digest("v2-replay-fence-identity"),
      replay_fence_snapshot_digest: digest("v2-replay-fence-snapshot"),
      previous_committed_generation: "0",
      committed_generation:
        sessions[sessions.length - 1].exchange_binding.launch_generation,
      sessions,
      all_capabilities_withheld_until_attestation: true,
      all_scm_rights_single_grant: true,
      all_receipts_authenticated: true,
      replay_fence_durable: true,
      outbox_recovery_complete: true,
      native_transcript_authenticated: true,
    },
    components,
  };
}

function createFixture() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  const manifest = makeManifestV2();
  const manifestDigest = trust.digestReleaseManifestV2(manifest);
  const publicDer = publicKey.export({ type: "spki", format: "der" });
  const publicDigest = digest(publicDer);
  const claim = {
    manifest_digest: manifestDigest,
    key_id: "native-release-v2-key:primary",
    public_key_digest: publicDigest,
    trust_epoch: 11,
  };
  const signature = crypto.sign(null, trust.releaseSignatureMessageV2(claim), privateKey)
    .toString("base64url");
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
      public_key_digest: publicDigest,
      trust_epoch: 11,
      signed_manifest_digest: manifestDigest,
      signature,
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
      public_key_digest: publicDigest,
      trust_epoch: 11,
      not_before: "2026-07-18T00:00:00.000Z",
      not_after: "2026-07-21T00:00:00.000Z",
      revoked: false,
      revocation_epoch: 0,
      allowed_package_names: [PACKAGE_NAME],
      allowed_component_ids: [...trust.NATIVE_PREBUILD_REQUIRED_COMPONENTS_V2],
    }],
  };
  const evidenceBody = makeEvidenceBody(manifest, manifestDigest);
  const liveAttestation = {
    ...evidenceBody,
    attestation_digest: trust.digestNativePrebuildAttestationV2Body(evidenceBody),
  };
  const context = {
    now: NOW,
    expected_manifest_digest: manifestDigest,
    expected_package_name: PACKAGE_NAME,
    expected_package_version: manifest.package_version,
    expected_release_epoch: manifest.release_epoch,
    host_os: "darwin",
    host_architecture: "arm64",
    host_node_major: 20,
    host_napi_version: 9,
    principal_acl_policy_digest: manifest.principal_acl_policy_digest,
    expected_principal_acl_evidence_digest:
      liveAttestation.immutable_install.principal_acl_evidence_digest,
    immutable_install_policy_digest: manifest.immutable_install_policy_digest,
    expected_immutable_install_evidence_digest:
      liveAttestation.immutable_install.evidence_digest,
    expected_install_identity_digest: liveAttestation.immutable_install.install_identity_digest,
    external_keyring_policy_digest: manifest.doctor_policy.external_keyring_policy_digest,
    expected_external_keyring_evidence_digest: liveAttestation.external_keyring.evidence_digest,
    expected_external_keyring_identity_digest:
      liveAttestation.external_keyring.keyring_identity_digest,
    live_attestor_policy_digest: manifest.doctor_policy.live_attestor_policy_digest,
    expected_live_attestor_identity_digest: liveAttestation.attestor.identity_digest,
    expected_replay_fence_identity_digest:
      liveAttestation.handoff.replay_fence_identity_digest,
    expected_replay_fence_snapshot_digest:
      liveAttestation.handoff.replay_fence_snapshot_digest,
  };
  return { envelope, trustPolicy, context, liveAttestation };
}

function doctorInput(fixture) {
  return {
    envelope: fixture.envelope,
    trust_policy: fixture.trustPolicy,
    evaluation_context: fixture.context,
    live_attestation: fixture.liveAttestation,
  };
}

function synchronizeRecipientBinding(fixture, recipientIndex) {
  const session = fixture.liveAttestation.handoff.sessions[recipientIndex];
  let component = null;
  for (let index = 0; index < fixture.liveAttestation.components.length; index += 1) {
    if (fixture.liveAttestation.components[index].component_id === session.component_id) {
      component = fixture.liveAttestation.components[index];
    }
  }
  assert.notEqual(component, null);
  const componentHandoff = component.component_handoff;
  const lineage = componentHandoff.worker_lineage;
  const exchange = componentHandoff.exchange_binding;
  exchange.grant_record_digest = trust.digestGrantRecordV2({
    version: 2,
    manifest_digest: fixture.liveAttestation.manifest_digest,
    component_id: component.component_id,
    handoff_session_id: session.handoff_session_id,
    supervisor_identity: supervisorIdentityAtListener(
      fixture.liveAttestation.handoff.supervisor_identity,
      lineage,
    ),
    worker_lineage: lineage,
    launch_nonce_digest: exchange.launch_nonce_digest,
    launch_generation: exchange.launch_generation,
    capability_set_digest: exchange.capability_set_digest,
    capability_generation: exchange.capability_generation,
    capability_abi_digest: exchange.capability_abi_digest,
    grant_id: exchange.grant_id,
    grant_nonce_digest: exchange.grant_nonce_digest,
    grant_sequence: exchange.grant_sequence,
  });
  exchange.go_record_digest = trust.digestGoRecordV2({
    version: 2,
    manifest_digest: fixture.liveAttestation.manifest_digest,
    component_id: component.component_id,
    handoff_session_id: session.handoff_session_id,
    supervisor_identity: supervisorIdentityAtListener(
      fixture.liveAttestation.handoff.supervisor_identity,
      lineage,
    ),
    worker_lineage: lineage,
    launch_nonce_digest: exchange.launch_nonce_digest,
    launch_generation: exchange.launch_generation,
    capability_set_digest: exchange.capability_set_digest,
    capability_generation: exchange.capability_generation,
    grant_id: exchange.grant_id,
    grant_sequence: exchange.grant_sequence,
    grant_record_digest: exchange.grant_record_digest,
    go_id: exchange.go_id,
    go_sequence: exchange.go_sequence,
  });
  session.worker_lineage = clone(lineage);
  session.exchange_binding = clone(exchange);
  const sessionBody = clone(session);
  delete sessionBody.handoff_session_digest;
  session.handoff_session_digest = trust.digestHandoffSessionV2(sessionBody);
  componentHandoff.handoff_session_digest = session.handoff_session_digest;
}

function resealEvidence(fixture) {
  try {
    for (let index = 0; index < fixture.liveAttestation.handoff.sessions.length; index += 1) {
      const session = fixture.liveAttestation.handoff.sessions[index];
      const sessionBody = clone(session);
      delete sessionBody.handoff_session_digest;
      session.handoff_session_digest = trust.digestHandoffSessionV2(sessionBody);
    }
    for (let index = 0; index < fixture.liveAttestation.components.length; index += 1) {
      const component = fixture.liveAttestation.components[index];
      const mappedBody = clone(component.mapped_measurement);
      delete mappedBody.measurement_digest;
      component.mapped_measurement.measurement_digest =
        trust.digestObservedMappedMeasurementV2(mappedBody);
      component.component_binding_digest = trust.digestComponentBindingV2({
        version: 2,
        manifest_digest: fixture.liveAttestation.manifest_digest,
        component_id: component.component_id,
        artifact_sha256: component.artifact_sha256,
        on_disk_fd_identity_digest: component.on_disk_fd_identity_digest,
        component_handoff: component.component_handoff,
        selected_cdhash: component.selected_cdhash,
        candidate_set_digest: component.candidate_set_digest,
        serialized_sec_requirement_digest: component.serialized_sec_requirement_digest,
        code_directory_flags: component.code_directory_flags,
        entitlements_digest: component.entitlements_digest,
        macho_identity_digest: trust.digestObservedMachoIdentityV2(component.macho_identity),
        launch_principal_digest:
          trust.digestObservedLaunchPrincipalV2(component.launch_principal),
        mapped_measurement_digest: component.mapped_measurement.measurement_digest,
        capability_abi_digest:
          trust.digestObservedCapabilityAbiV2(component.capability_abi),
        running_code_identity_digest: component.running_code_identity_digest,
        attestor_identity_digest: fixture.liveAttestation.attestor.identity_digest,
      });
    }
  } catch {
    // Invalid hostile bodies intentionally cannot receive a self-consistent seal.
  }
  const body = clone(fixture.liveAttestation);
  delete body.attestation_digest;
  try {
    fixture.liveAttestation.attestation_digest =
      trust.digestNativePrebuildAttestationV2Body(body);
  } catch {
    // Hostile-schema cases intentionally cannot be resealed. The doctor must
    // still reject them before treating the stale digest as evidence.
  }
}

test("v2 enrolls the exact six role-distinct native components", () => {
  assert.deepEqual(trust.NATIVE_PREBUILD_REQUIRED_COMPONENTS_V2, [
    "native_ipc_acceptor",
    "chameleon_cdc_custody",
    "safety_watchdog",
    "privileged_launcher",
    "lifecycle_custodian",
    "native_dispatch_custodian",
  ]);
  assert.deepEqual(trust.NATIVE_PREBUILD_RECIPIENT_COMPONENTS_V2, [
    "native_ipc_acceptor",
    "chameleon_cdc_custody",
    "safety_watchdog",
    "lifecycle_custodian",
    "native_dispatch_custodian",
  ]);
  assert.equal(trust.digestReleaseManifestV2(makeManifestV2()).length, 64);

  const missing = makeManifestV2();
  missing.components.pop();
  assert.throws(() => trust.digestReleaseManifestV2(missing), /complete/u);

  const swapped = makeManifestV2();
  [swapped.components[4], swapped.components[5]] = [swapped.components[5],
    swapped.components[4]];
  assert.throws(() => trust.digestReleaseManifestV2(swapped), /required component/u);
});

test("v1 and v2 remain independently domain-separated and compatible", () => {
  const fixture = createFixture();
  const verified = trust.verifyReleaseEnvelopeV2({
    envelope: fixture.envelope,
    trust_policy: fixture.trustPolicy,
    now: NOW,
  });
  assert.equal(verified.release_signature_valid, true);
  assert.equal(verified.production_ready, false);
  assert.equal(verified.hardware_access_authorized, false);
  assert.equal(verified.authoritative, false);
  assert.throws(() => trust.verifyReleaseEnvelope({
    envelope: fixture.envelope,
    trust_policy: fixture.trustPolicy,
    now: NOW,
  }));
  assert.notEqual(trust.NATIVE_PREBUILD_MANIFEST_DOMAIN,
    trust.NATIVE_PREBUILD_MANIFEST_V2_DOMAIN);
  assert.equal(trust.NATIVE_PREBUILD_TRUST_VERSION, 1);
  assert.equal(trust.NATIVE_PREBUILD_TRUST_V2_VERSION, 2);
});

test("v2 golden manifest and evidence digests are stable", () => {
  const manifest = makeManifestV2();
  const manifestDigest = trust.digestReleaseManifestV2(manifest);
  const evidenceBody = makeEvidenceBody(manifest, manifestDigest);
  const evidenceDigest = trust.digestNativePrebuildAttestationV2Body(evidenceBody);
  assert.equal(golden.manifest_domain, trust.NATIVE_PREBUILD_MANIFEST_V2_DOMAIN);
  assert.equal(golden.attestation_domain, trust.NATIVE_PREBUILD_ATTESTATION_V2_DOMAIN);
  assert.deepEqual(golden.required_component_ids,
    trust.NATIVE_PREBUILD_REQUIRED_COMPONENTS_V2);
  assert.equal(manifestDigest, golden.manifest_digest);
  assert.equal(evidenceDigest, golden.attestation_digest);
  assert.notEqual(manifestDigest, evidenceDigest);
});

test("v2 doctor validates the closed counterpart but never grants authority", () => {
  const fixture = createFixture();
  const report = trust.evaluateNativePrebuildDoctorV2(doctorInput(fixture));
  assert.equal(report.status, "diagnostic_complete_non_authorizing");
  assert.equal(report.release_signature_valid, true);
  assert.equal(report.v2_schema_valid, true);
  assert.equal(report.external_immutable_keyring_evidence_valid, true);
  assert.equal(report.live_native_attestation_evidence_valid, true);
  assert.equal(report.production_ready, false);
  assert.equal(report.hardware_access_authorized, false);
  assert.equal(report.authoritative, false);
  assert.equal(report.host_inspection_performed, false);
  assert.equal(report.native_execution_performed, false);
  assert.equal(report.external_keyring_read_performed, false);
  assert.equal(report.capability_transfer_performed, false);

  fixture.liveAttestation = null;
  const absent = trust.evaluateNativePrebuildDoctorV2(doctorInput(fixture));
  assert.equal(absent.status, "blocked");
  assert.equal(absent.production_ready, false);
});

test("v2 manifest pins every exact code, Mach-O, principal, measurement, and ABI field", () => {
  const mutations = [
    (manifest) => { manifest.components[0].code_identity.selected_cdhash = "a".repeat(39); },
    (manifest) => { delete manifest.components[0].code_identity.candidate_set_digest; },
    (manifest) => {
      manifest.components[0].code_identity.serialized_sec_requirement_digest = "f".repeat(63);
    },
    (manifest) => { manifest.components[0].code_identity.code_directory_flags = -1; },
    (manifest) => { manifest.components[0].code_identity.entitlements_digest = "f".repeat(63); },
    (manifest) => { manifest.components[0].macho_identity.cpu_type = 7; },
    (manifest) => { manifest.components[0].macho_identity.uuid = "A".repeat(32); },
    (manifest) => { manifest.components[0].launch_principal.uid = 0; },
    (manifest) => { manifest.components[0].launch_principal.no_login_identity = false; },
    (manifest) => {
      manifest.components[0].mapped_measurement.expected_loaded_uuid = "f".repeat(32);
    },
    (manifest) => {
      manifest.components[0].mapped_measurement.require_pre_grant_measurement = false;
    },
    (manifest) => { manifest.components[0].capability_abi.single_grant = false; },
    (manifest) => { delete manifest.components[0].capability_abi.receipt_schema.sha256; },
  ];
  for (const mutate of mutations) {
    const manifest = makeManifestV2();
    mutate(manifest);
    assert.throws(() => trust.digestReleaseManifestV2(manifest));
  }
});

test("v2 manifest rejects role aliasing across every authority-defining identity", () => {
  const mutations = [
    (manifest) => { manifest.components[1].sha256 = manifest.components[0].sha256; },
    (manifest) => {
      manifest.components[1].code_identity.selected_cdhash =
        manifest.components[0].code_identity.selected_cdhash;
    },
    (manifest) => {
      manifest.components[1].code_identity.candidate_set_digest =
        manifest.components[0].code_identity.candidate_set_digest;
    },
    (manifest) => {
      manifest.components[1].code_identity.serialized_sec_requirement_format =
        manifest.components[0].code_identity.serialized_sec_requirement_format;
      manifest.components[1].code_identity.serialized_sec_requirement_data_base64url =
        manifest.components[0].code_identity.serialized_sec_requirement_data_base64url;
      manifest.components[1].code_identity.serialized_sec_requirement_byte_size =
        manifest.components[0].code_identity.serialized_sec_requirement_byte_size;
      manifest.components[1].code_identity.serialized_sec_requirement_digest =
        manifest.components[0].code_identity.serialized_sec_requirement_digest;
    },
    (manifest) => {
      manifest.components[1].macho_identity.uuid = manifest.components[0].macho_identity.uuid;
      manifest.components[1].mapped_measurement.expected_loaded_uuid =
        manifest.components[0].macho_identity.uuid;
    },
    (manifest) => {
      manifest.components[1].launch_principal.uid = manifest.components[0].launch_principal.uid;
    },
    (manifest) => {
      manifest.components[1].capability_abi.abi_id =
        manifest.components[0].capability_abi.abi_id;
    },
  ];
  for (const mutate of mutations) {
    const manifest = makeManifestV2();
    mutate(manifest);
    assert.throws(() => trust.digestReleaseManifestV2(manifest), /distinct/u);
  }
});

test("v2 carries bounded canonical SecRequirement bytes and binds their digest", () => {
  const mismatch = makeManifestV2();
  mismatch.components[0].code_identity.serialized_sec_requirement_digest = digest("wrong");
  assert.throws(() => trust.digestReleaseManifestV2(mismatch), /digest does not match/u);

  const wrongSize = makeManifestV2();
  wrongSize.components[0].code_identity.serialized_sec_requirement_byte_size += 1;
  assert.throws(() => trust.digestReleaseManifestV2(wrongSize), /size does not match/u);

  const noncanonical = makeManifestV2();
  noncanonical.components[0].code_identity.serialized_sec_requirement_data_base64url += "=";
  assert.throws(() => trust.digestReleaseManifestV2(noncanonical));

  const oversized = makeManifestV2();
  const bytes = Buffer.alloc((16 * 1024) + 1, 0x41);
  oversized.components[0].code_identity.serialized_sec_requirement_data_base64url =
    bytes.toString("base64url");
  oversized.components[0].code_identity.serialized_sec_requirement_byte_size = bytes.length;
  oversized.components[0].code_identity.serialized_sec_requirement_digest = digest(bytes);
  assert.throws(() => trust.digestReleaseManifestV2(oversized), /size is out of bounds/u);
});

test("v2 carries exact signed schema references and descriptor tables", () => {
  const mutations = [
    (manifest) => { manifest.components[0].capability_abi.descriptor_count = 3; },
    (manifest) => { manifest.components[0].capability_abi.descriptor_table[1].ordinal = 0; },
    (manifest) => {
      manifest.components[0].capability_abi.descriptor_table[0].descriptor_type = "pathname";
    },
    (manifest) => {
      manifest.components[0].capability_abi.descriptor_table[0].forbidden_status_flags = 1;
      manifest.components[0].capability_abi.descriptor_table[0].required_status_flags = 1;
    },
    (manifest) => {
      manifest.components[0].capability_abi.descriptor_table[0].forbidden_status_flags = 8;
    },
    (manifest) => {
      manifest.components[0].capability_abi.descriptor_table[1].required_status_flags = 4;
    },
    (manifest) => {
      manifest.components[0].capability_abi.descriptor_table[0]
        .required_descriptor_flags = 0;
    },
    (manifest) => {
      manifest.components[0].capability_abi.request_schema.artifact_path = "../schema.json";
    },
    (manifest) => {
      manifest.components[0].capability_abi.result_schema.sha256 =
        manifest.components[0].capability_abi.request_schema.sha256;
    },
    (manifest) => {
      manifest.authority_handoff_policy.durable_exchange_policy.grant_record_schema
        .artifact_path = manifest.components[0].capability_abi.request_schema.artifact_path;
    },
  ];
  for (const mutate of mutations) {
    const manifest = makeManifestV2();
    mutate(manifest);
    assert.throws(() => trust.digestReleaseManifestV2(manifest));
  }
});

test("v2 doctor binds schema bytes, descriptor roles, types, flags, and FD identities", () => {
  const mutations = [
    (fixture) => {
      fixture.liveAttestation.components[0].capability_abi.request_schema.sha256 =
        digest("substituted-request-schema");
    },
    (fixture) => {
      fixture.liveAttestation.components[0].capability_abi.descriptor_table[0].role =
        "substituted_role";
    },
    (fixture) => {
      fixture.liveAttestation.components[0].capability_abi.descriptor_table[0]
        .descriptor_type = "regular_file";
    },
    (fixture) => {
      fixture.liveAttestation.components[0].capability_abi.descriptor_table[1]
        .observed_status_flags = 0;
    },
    (fixture) => {
      fixture.liveAttestation.components[0].capability_abi.descriptor_table[0]
        .observed_status_flags = 2;
    },
    (fixture) => {
      fixture.liveAttestation.components[0].capability_abi.descriptor_table[0]
        .observed_descriptor_flags = 0;
    },
    (fixture) => {
      fixture.liveAttestation.components[0].capability_abi.descriptor_table[0]
        .descriptor_identity_digest =
          fixture.liveAttestation.handoff.grant_record_schema.fd_identity_digest;
    },
  ];
  for (const mutate of mutations) {
    const fixture = createFixture();
    mutate(fixture);
    resealEvidence(fixture);
    assert.equal(trust.evaluateNativePrebuildDoctorV2(doctorInput(fixture)).status, "blocked");
  }
});

test("v2 handoff policy is exact, bounded, nonce-generational, and durable", () => {
  const mutations = [
    (manifest) => { manifest.authority_handoff_policy.scheme = "pre_exec_path_check"; },
    (manifest) => { manifest.authority_handoff_policy.supervisor_component_id = "watchdog"; },
    (manifest) => { manifest.authority_handoff_policy.supervisor_role = "worker"; },
    (manifest) => { manifest.authority_handoff_policy.process_lineage_scheme = "pid_only"; },
    (manifest) => { manifest.authority_handoff_policy.listener_identity_scheme = "path_only"; },
    (manifest) => {
      manifest.authority_handoff_policy.post_exec_connection_scheme = "reused_connection";
    },
    (manifest) => {
      manifest.authority_handoff_policy.capability_set_digest_scheme = "unordered_roles";
    },
    (manifest) => {
      manifest.authority_handoff_policy.grant_go_binding_scheme = "distinct_only";
    },
    (manifest) => { manifest.authority_handoff_policy.transport = "path_reopen"; },
    (manifest) => {
      manifest.authority_handoff_policy.deadline_policy.clock = "wall_clock";
    },
    (manifest) => {
      manifest.authority_handoff_policy.deadline_policy.total_timeout_ms = 13000;
    },
    (manifest) => {
      manifest.authority_handoff_policy.nonce_policy.entropy_bits = 128;
    },
    (manifest) => {
      manifest.authority_handoff_policy.nonce_policy.durable_replay_fence_before_grant = false;
    },
    (manifest) => {
      manifest.authority_handoff_policy.durable_exchange_policy.fsync_grant_before_go = false;
    },
    (manifest) => {
      manifest.authority_handoff_policy.durable_exchange_policy
        .unreceipted_grant_recovery_required = false;
    },
    (manifest) => {
      manifest.authority_handoff_policy.durable_exchange_policy
        .authenticated_receipt_required = false;
    },
  ];
  for (const mutate of mutations) {
    const manifest = makeManifestV2();
    mutate(manifest);
    assert.throws(() => trust.digestReleaseManifestV2(manifest));
  }
});

test("v2 doctor rejects drift in every post-exec identity dimension", () => {
  const mutations = [
    (fixture) => { fixture.liveAttestation.components[0].selected_cdhash = "f".repeat(40); },
    (fixture) => {
      fixture.liveAttestation.components[0].candidate_set_digest = digest("wrong-candidates");
    },
    (fixture) => {
      fixture.liveAttestation.components[0].serialized_sec_requirement_digest =
        digest("wrong-requirement");
    },
    (fixture) => { fixture.liveAttestation.components[0].code_directory_flags += 1; },
    (fixture) => {
      fixture.liveAttestation.components[0].entitlements_digest = digest("wrong-entitlements");
    },
    (fixture) => { fixture.liveAttestation.components[0].macho_identity.macho_flags += 1; },
    (fixture) => { fixture.liveAttestation.components[0].launch_principal.uid += 1; },
    (fixture) => {
      fixture.liveAttestation.components[0].mapped_measurement.mapped_text_digest =
        digest("wrong-mapped-text");
    },
    (fixture) => {
      fixture.liveAttestation.components[0].capability_abi.request_schema.sha256 =
        digest("wrong-abi");
    },
    (fixture) => {
      fixture.liveAttestation.components[0].running_code_guest_validated = false;
    },
    (fixture) => {
      fixture.liveAttestation.components[0].component_handoff
        .worker_lineage.fresh_post_exec_connection = false;
    },
    (fixture) => {
      fixture.liveAttestation.components[0].component_handoff
        .worker_lineage.direct_child_of_supervisor = false;
    },
  ];
  for (const mutate of mutations) {
    const fixture = createFixture();
    mutate(fixture);
    resealEvidence(fixture);
    const report = trust.evaluateNativePrebuildDoctorV2(doctorInput(fixture));
    assert.equal(report.status, "blocked");
    assert.equal(report.production_ready, false);
  }
});

test("v2 doctor rejects replay, deadline, order, receipt, outbox, and transcript gaps", () => {
  const mutations = [
    (fixture) => {
      fixture.liveAttestation.handoff.sessions[1].exchange_binding.launch_nonce_digest =
        fixture.liveAttestation.handoff.sessions[0].exchange_binding.launch_nonce_digest;
    },
    (fixture) => {
      fixture.liveAttestation.handoff.sessions[1].exchange_binding.launch_generation = "1";
    },
    (fixture) => { fixture.liveAttestation.handoff.previous_committed_generation = "1"; },
    (fixture) => { fixture.liveAttestation.handoff.committed_generation = "7"; },
    (fixture) => {
      fixture.liveAttestation.handoff.replay_fence_snapshot_digest =
        digest("substituted-replay-fence-snapshot");
    },
    (fixture) => {
      fixture.liveAttestation.handoff.sessions[0].attested_at =
        "2026-07-19T11:50:04.000Z";
    },
    (fixture) => {
      fixture.liveAttestation.handoff.sessions[0].go_recorded_at =
        "2026-07-19T11:50:03.000Z";
    },
    (fixture) => {
      fixture.liveAttestation.handoff.sessions[0].receipt_authenticated = false;
    },
    (fixture) => { fixture.liveAttestation.handoff.outbox_recovery_complete = false; },
    (fixture) => { fixture.liveAttestation.handoff.native_transcript_authenticated = false; },
    (fixture) => { fixture.liveAttestation.external_keyring.external_to_caller = false; },
    (fixture) => {
      fixture.liveAttestation.external_keyring.keyring_identity_digest =
        digest("substituted-keyring");
    },
    (fixture) => {
      fixture.liveAttestation.immutable_install.install_identity_digest =
        digest("substituted-install");
    },
    (fixture) => { fixture.liveAttestation.attestor.caller_js_authority = true; },
  ];
  for (const mutate of mutations) {
    const fixture = createFixture();
    mutate(fixture);
    resealEvidence(fixture);
    assert.equal(trust.evaluateNativePrebuildDoctorV2(doctorInput(fixture)).status, "blocked");
  }
});

test("v2 attests the launcher once as supervisor and rejects self-parent worker models", () => {
  const valid = createFixture();
  assert.equal(valid.liveAttestation.handoff.sessions.length, 5);
  assert.equal(valid.liveAttestation.handoff.sessions.some((session) =>
    session.component_id === "privileged_launcher"), false);
  assert.equal(valid.liveAttestation.components[3].component_handoff.kind, "supervisor");

  const extraSupervisorSession = createFixture();
  const forged = clone(extraSupervisorSession.liveAttestation.handoff.sessions[0]);
  forged.component_id = "privileged_launcher";
  extraSupervisorSession.liveAttestation.handoff.sessions.push(forged);
  resealEvidence(extraSupervisorSession);
  assert.equal(trust.evaluateNativePrebuildDoctorV2(
    doctorInput(extraSupervisorSession),
  ).status, "blocked");

  const selfParent = createFixture();
  const lineage = selfParent.liveAttestation.components[0]
    .component_handoff.worker_lineage;
  lineage.worker_direct_parent_process_id = lineage.worker_process_id;
  lineage.worker_direct_parent_audit_token_digest = lineage.worker_audit_token_digest;
  lineage.worker_direct_parent_instance_digest = lineage.worker_process_instance_digest;
  lineage.worker_direct_parent_start_digest = lineage.worker_process_start_digest;
  synchronizeRecipientBinding(selfParent, 0);
  resealEvidence(selfParent);
  const report = trust.evaluateNativePrebuildDoctorV2(doctorInput(selfParent));
  assert.equal(report.status, "blocked");
  assert.deepEqual(report.findings, ["live_attestation:process_lineage_rejected"]);

  const substitutedSupervisor = createFixture();
  substitutedSupervisor.liveAttestation.handoff.supervisor_identity
    .supervisor_process_start_digest = digest("substituted-supervisor-start");
  resealEvidence(substitutedSupervisor);
  assert.deepEqual(trust.evaluateNativePrebuildDoctorV2(
    doctorInput(substitutedSupervisor),
  ).findings, ["live_attestation:supervisor_identity_rejected"]);
});

test("v2 cross-binds and freshness-checks every explicit lineage and exchange identity", () => {
  const replayMutations = [
    (fixture, first, second) => {
      second.worker_audit_token_digest = first.worker_audit_token_digest;
    },
    (fixture, first, second) => { second.worker_process_id = first.worker_process_id; },
    (fixture, first, second) => {
      second.worker_process_instance_digest = first.worker_process_instance_digest;
    },
    (fixture, first, second) => {
      second.worker_process_start_digest = first.worker_process_start_digest;
    },
    (fixture, first, second) => {
      second.supervisor_listener_generation = first.supervisor_listener_generation;
    },
    (fixture, first, second) => {
      second.supervisor_listener_identity_digest = first.supervisor_listener_identity_digest;
    },
    (fixture, first, second) => {
      second.post_exec_connection_identity_digest =
        first.post_exec_connection_identity_digest;
    },
    (fixture, first, second, firstExchange, secondExchange) => {
      secondExchange.launch_nonce_digest = firstExchange.launch_nonce_digest;
    },
    (fixture, first, second, firstExchange, secondExchange) => {
      secondExchange.launch_generation = firstExchange.launch_generation;
    },
    (fixture, first, second, firstExchange, secondExchange) => {
      secondExchange.capability_generation = firstExchange.capability_generation;
    },
    (fixture, first, second, firstExchange, secondExchange) => {
      secondExchange.grant_id = firstExchange.grant_id;
    },
    (fixture, first, second, firstExchange, secondExchange) => {
      secondExchange.grant_nonce_digest = firstExchange.grant_nonce_digest;
    },
    (fixture, first, second, firstExchange, secondExchange) => {
      secondExchange.grant_sequence = firstExchange.grant_sequence;
      secondExchange.go_sequence = firstExchange.go_sequence;
    },
    (fixture, first, second, firstExchange, secondExchange) => {
      secondExchange.go_id = firstExchange.go_id;
    },
  ];
  for (const mutate of replayMutations) {
    const fixture = createFixture();
    const firstHandoff = fixture.liveAttestation.components[0].component_handoff;
    const secondHandoff = fixture.liveAttestation.components[1].component_handoff;
    mutate(fixture, firstHandoff.worker_lineage, secondHandoff.worker_lineage,
      firstHandoff.exchange_binding, secondHandoff.exchange_binding);
    synchronizeRecipientBinding(fixture, 1);
    resealEvidence(fixture);
    const report = trust.evaluateNativePrebuildDoctorV2(doctorInput(fixture));
    assert.equal(report.status, "blocked");
    assert.deepEqual(report.findings, ["live_attestation:replay_fence_rejected"]);
  }

  const substitutedCapabilitySet = createFixture();
  substitutedCapabilitySet.liveAttestation.components[1]
    .component_handoff.exchange_binding.capability_set_digest =
      substitutedCapabilitySet.liveAttestation.components[0]
        .component_handoff.exchange_binding.capability_set_digest;
  synchronizeRecipientBinding(substitutedCapabilitySet, 1);
  resealEvidence(substitutedCapabilitySet);
  assert.deepEqual(trust.evaluateNativePrebuildDoctorV2(
    doctorInput(substitutedCapabilitySet),
  ).findings, ["live_attestation:capability_set_rejected"]);

  const nonAdjacentGo = createFixture();
  nonAdjacentGo.liveAttestation.components[1]
    .component_handoff.exchange_binding.go_sequence = "5";
  synchronizeRecipientBinding(nonAdjacentGo, 1);
  resealEvidence(nonAdjacentGo);
  assert.deepEqual(trust.evaluateNativePrebuildDoctorV2(
    doctorInput(nonAdjacentGo),
  ).findings, ["live_attestation:replay_fence_rejected"]);

  const substitutedGrantRecord = createFixture();
  const substitutedComponentHandoff = substitutedGrantRecord.liveAttestation.components[0]
    .component_handoff;
  const substitutedSession = substitutedGrantRecord.liveAttestation.handoff.sessions[0];
  substitutedComponentHandoff.exchange_binding.grant_record_digest =
    digest("substituted-authenticated-grant-record");
  substitutedSession.exchange_binding = clone(substitutedComponentHandoff.exchange_binding);
  const substitutedSessionBody = clone(substitutedSession);
  delete substitutedSessionBody.handoff_session_digest;
  substitutedSession.handoff_session_digest =
    trust.digestHandoffSessionV2(substitutedSessionBody);
  substitutedComponentHandoff.handoff_session_digest =
    substitutedSession.handoff_session_digest;
  resealEvidence(substitutedGrantRecord);
  assert.deepEqual(trust.evaluateNativePrebuildDoctorV2(
    doctorInput(substitutedGrantRecord),
  ).findings, ["live_attestation:authenticated_exchange_rejected"]);
});

test("v2 generation and sequence fields are canonical full-width uint64 decimals", () => {
  const mutations = [
    (fixture) => {
      fixture.liveAttestation.handoff.previous_committed_generation = 0;
    },
    (fixture) => {
      fixture.liveAttestation.handoff.committed_generation = "05";
    },
    (fixture) => {
      fixture.liveAttestation.handoff.supervisor_identity.supervisor_listener_generation =
        "18446744073709551616";
    },
    (fixture) => {
      fixture.liveAttestation.handoff.sessions[0]
        .exchange_binding.launch_generation = "01";
    },
    (fixture) => {
      fixture.liveAttestation.handoff.sessions[0]
        .exchange_binding.grant_sequence = 1;
    },
  ];
  for (const mutate of mutations) {
    const fixture = createFixture();
    mutate(fixture);
    resealEvidence(fixture);
    assert.equal(trust.evaluateNativePrebuildDoctorV2(doctorInput(fixture)).status, "blocked");
  }

  const fullWidth = createFixture();
  const last = fullWidth.liveAttestation.components[5].component_handoff;
  last.worker_lineage.supervisor_listener_generation = "18446744073709551613";
  last.exchange_binding.launch_generation = "18446744073709551613";
  last.exchange_binding.capability_generation = "18446744073709551613";
  last.exchange_binding.grant_sequence = "18446744073709551614";
  last.exchange_binding.go_sequence = "18446744073709551615";
  fullWidth.liveAttestation.handoff.supervisor_identity.supervisor_listener_generation =
    last.worker_lineage.supervisor_listener_generation;
  fullWidth.liveAttestation.components[3]
    .component_handoff.supervisor_identity.supervisor_listener_generation =
      last.worker_lineage.supervisor_listener_generation;
  fullWidth.liveAttestation.handoff.committed_generation = last.exchange_binding.launch_generation;
  synchronizeRecipientBinding(fullWidth, 4);
  resealEvidence(fullWidth);
  assert.equal(trust.evaluateNativePrebuildDoctorV2(doctorInput(fullWidth)).status,
    "diagnostic_complete_non_authorizing");
});

test("v2 hostile schemas reject proxies, accessors, symbols, sparse arrays, and extras", () => {
  const proxy = makeManifestV2();
  let trapRead = false;
  proxy.components[0].code_identity = new Proxy(proxy.components[0].code_identity, {
    get() { trapRead = true; throw new Error("getter trap"); },
  });
  assert.throws(() => trust.digestReleaseManifestV2(proxy));
  assert.equal(trapRead, false);

  const accessor = makeManifestV2();
  let getterRead = false;
  Object.defineProperty(accessor.components[0], "sha256", {
    enumerable: true,
    get() { getterRead = true; return digest("forged"); },
  });
  assert.throws(() => trust.digestReleaseManifestV2(accessor));
  assert.equal(getterRead, false);

  const symbol = makeManifestV2();
  symbol.authority_handoff_policy[Symbol("hidden")] = true;
  assert.throws(() => trust.digestReleaseManifestV2(symbol));

  const sparse = makeManifestV2();
  sparse.components = new Array(6);
  sparse.components[0] = makeManifestV2().components[0];
  assert.throws(() => trust.digestReleaseManifestV2(sparse));

  const extra = makeManifestV2();
  extra.production_ready = true;
  assert.throws(() => trust.digestReleaseManifestV2(extra));

  const fixture = createFixture();
  fixture.liveAttestation.components[0].grant_authority = true;
  resealEvidence(fixture);
  assert.equal(trust.evaluateNativePrebuildDoctorV2(doctorInput(fixture)).status, "blocked");
});

test("v2 public surface has digest/verify/doctor functions but no signer or authority", () => {
  const names = Object.keys(trust);
  assert.equal(typeof trust.digestReleaseManifestV2, "function");
  assert.equal(typeof trust.verifyReleaseEnvelopeV2, "function");
  assert.equal(typeof trust.evaluateNativePrebuildDoctorV2, "function");
  assert.equal(names.some((name) => /signEnvelope|privateKey|grantAuthority/u.test(name)), false);
  assert.equal("production_ready" in trust, false);
});

test("v2 verification survives hostile same-process mutable intrinsic replacement", () => {
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
    const input = JSON.parse(Buffer.from(${JSON.stringify(payload)}, "base64url")
      .toString("utf8"));
    Set.prototype.has = () => { throw new Error("poisoned Set.has"); };
    Set.prototype.add = () => { throw new Error("poisoned Set.add"); };
    global.Set = function PoisonedSet() { throw new Error("poisoned Set constructor"); };
    Array.prototype.map = () => { throw new Error("poisoned Array.map"); };
    Buffer.prototype.equals = () => { throw new Error("poisoned Buffer.equals"); };
    const verified = api.verifyReleaseEnvelopeV2(input.verification);
    if (!verified.release_signature_valid || verified.production_ready) process.exit(41);
    const report = api.evaluateNativePrebuildDoctorV2(input.doctor);
    if (report.status !== "diagnostic_complete_non_authorizing"
        || report.production_ready) process.exit(42);
    const attacker = crypto.generateKeyPairSync("ed25519");
    const auth = input.verification.envelope.authentication;
    auth.signature = crypto.sign(null, api.releaseSignatureMessageV2({
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
      api.verifyReleaseEnvelopeV2(input.verification);
    } catch (error) {
      forgedResult = error.code;
    } finally {
      delete Array.prototype[0];
    }
    if (forgedResult !== "signature_invalid" || keySubstitutions !== 0) process.exit(43);
  `;
  const result = spawnSync(process.execPath, ["-e", script], {
    encoding: "utf8",
    timeout: 5000,
  });
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stdout, "");
});
