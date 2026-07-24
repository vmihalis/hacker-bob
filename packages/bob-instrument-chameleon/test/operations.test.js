"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");

const operations = require("../lib/operations.js");
const {
  CHAMELEON_AVAILABILITY_EVIDENCE_VERSION,
  CHAMELEON_AVAILABILITY_BACKEND_VERSION,
  CHAMELEON_BOOTSTRAP_SUBSET,
  CHAMELEON_SEMANTIC_DIGESTS,
  CHAMELEON_SEMANTIC_MANIFEST,
  CHAMELEON_V220_CODEC_PROFILE,
  CHAMELEON_V220_SOURCE_PROFILE,
  buildChameleonAvailabilityVariantQualification,
  createTestChameleonAvailabilityEvidenceResolverPort,
  dependencyProofContract,
  getChameleonAvailabilityVariant,
  getChameleonCapability,
  getChameleonCommandOwner,
  getChameleonCommandSourceProvenance,
  getChameleonOperation,
  normalizeChameleonEvaluatorSelection,
  resolveChameleonAvailability,
  resolveChameleonAvailabilityEvidence,
  resolveProductionShapedChameleonAvailabilityEvidence,
  reviewedManifestSnapshot,
} = operations;

function digest(label) {
  return crypto.createHash("sha256").update(JSON.stringify({ label })).digest("hex");
}

function hashJson(value) {
  return crypto.createHash("sha256").update(JSON.stringify(value)).digest("hex");
}

function evidenceRequest(overrides = {}) {
  return {
    version: CHAMELEON_AVAILABILITY_EVIDENCE_VERSION,
    provider_id: "chameleon_ultra",
    evidence_ref: "availability-evidence:test-1",
    semantic_manifest_digest: CHAMELEON_SEMANTIC_MANIFEST.manifest_digest,
    source_profile_digest: CHAMELEON_V220_SOURCE_PROFILE.source_profile_digest,
    codec_profile_digest: CHAMELEON_V220_CODEC_PROFILE.codec_profile_digest,
    assurance_profile_registry_digest:
      CHAMELEON_SEMANTIC_DIGESTS.assurance_profile_registry_sha256,
    dependency_proof_registry_digest:
      CHAMELEON_SEMANTIC_DIGESTS.dependency_proof_provider_registry_sha256,
    inventory_projection_digest: digest("inventory-projection"),
    device_identity_digest: digest("device-identity"),
    custody_id: "custody:chameleon-test-1",
    custody_projection_digest: digest("custody-projection"),
    session_id: "session:chameleon-test-1",
    authority_id: "authority:chameleon-test-1",
    authority_epoch: 7,
    revocation_generation: 3,
    authority_resolution_digest: digest("authority-resolution"),
    ...overrides,
  };
}

const PROOF_BINDING_FIELDS = [
  "version",
  "provider_id",
  "evidence_ref",
  "semantic_manifest_digest",
  "source_profile_digest",
  "codec_profile_digest",
  "assurance_profile_registry_digest",
  "dependency_proof_registry_digest",
  "inventory_projection_digest",
  "device_identity_digest",
  "custody_id",
  "custody_projection_digest",
  "session_id",
  "authority_id",
  "authority_epoch",
  "revocation_generation",
  "authority_resolution_digest",
];

function proof(ref, verdict = "satisfied", request = evidenceRequest(), overrides = {}) {
  const contract = dependencyProofContract(ref);
  assert.ok(contract, `test dependency ${ref} must exist`);
  const basis = {
    ...Object.fromEntries(PROOF_BINDING_FIELDS.map((field) => [field, request[field]])),
    dependency_ref: ref,
    provider_contract_digest: contract.contract_digest,
    owner_principal: contract.owner_principal,
    artifact_digest: digest(`artifact:${ref}`),
    trust_epoch: 11,
    verdict,
    observed_at: "2026-07-20T00:00:00.000Z",
    expires_at: "2026-07-20T02:00:00.000Z",
    revoked: false,
    ...overrides,
  };
  return {
    ...basis,
    proof_digest: hashJson({
      domain: "bob.chameleon.availability.dependency-proof.v1",
      ...basis,
    }),
  };
}

function resolvedEvidence(request, overrides = {}) {
  return {
    ...request,
    evidence_owner_principal: "principal:availability-evidence-test",
    evidence_artifact_digest: digest("availability-evidence-artifact"),
    evidence_trust_epoch: 13,
    observed_at: "2026-07-20T00:00:00.000Z",
    expires_at: "2026-07-20T02:00:00.000Z",
    revoked: false,
    reported_command_ids: [...CHAMELEON_V220_CODEC_PROFILE.command_ids, 2000, 65535],
    assurance_claims: {
      identity_enrollment: "unverified",
      firmware_provenance: "self_reported",
      command_surface_conformance: "bootstrap_allowlisted",
      transport_trust: "local_observed",
    },
    dependency_proofs: [],
    ...overrides,
  };
}

function dependencyState(entry, overrides = {}) {
  return {
    dependency_ref: entry.dependency_ref,
    provider_contract_digest: entry.provider_contract_digest,
    owner_principal: entry.owner_principal,
    artifact_digest: entry.artifact_digest,
    trust_epoch: entry.trust_epoch,
    verdict: entry.verdict,
    proof_digest: entry.proof_digest,
    revoked: false,
    ...overrides,
  };
}

function resolvedCurrentState(request, evidence, currentRequest, overrides = {}) {
  return {
    ...request,
    evidence_projection_digest: currentRequest.evidence_projection_digest,
    evidence_owner_principal: evidence.evidence_owner_principal,
    evidence_artifact_digest: evidence.evidence_artifact_digest,
    evidence_trust_epoch: evidence.evidence_trust_epoch,
    current_time: "2026-07-20T01:00:00.000Z",
    evidence_revoked: false,
    inventory_current: true,
    device_current: true,
    custody_current: true,
    session_current: true,
    authority_current: true,
    reported_command_ids_digest: currentRequest.reported_command_ids_digest,
    assurance_claims_digest: currentRequest.assurance_claims_digest,
    dependency_states: evidence.dependency_proofs.map((entry) => dependencyState(entry)),
    ...overrides,
  };
}

function fixtureResolverPort(request, evidence, currentStateOverrides = {}, portOverrides = {}) {
  return createTestChameleonAvailabilityEvidenceResolverPort({
    version: CHAMELEON_AVAILABILITY_EVIDENCE_VERSION,
    port_id: "availability-evidence-port:test-1",
    test_only: true,
    verification_model: "synchronous_exact_evidence_and_current_state",
    resolve_evidence: () => evidence,
    resolve_current_state: (currentRequest) => resolvedCurrentState(
      request,
      evidence,
      currentRequest,
      currentStateOverrides,
    ),
    ...portOverrides,
  });
}

function evidenceFixture({
  requestOverrides = {},
  evidenceOverrides = {},
  currentStateOverrides = {},
  portOverrides = {},
} = {}) {
  const request = evidenceRequest(requestOverrides);
  const evidence = resolvedEvidence(request, evidenceOverrides);
  const port = fixtureResolverPort(request, evidence, currentStateOverrides, portOverrides);
  return resolveChameleonAvailabilityEvidence(port, request);
}

function availabilityInput(overrides = {}) {
  const {
    alternative_selections = [],
    evidence_projection = null,
    ...evidenceOverrides
  } = overrides;
  return {
    version: 1,
    provider_id: "chameleon_ultra",
    evidence_projection: evidence_projection || evidenceFixture({ evidenceOverrides }),
    alternative_selections,
  };
}

function status(projection, capabilityId, variantId) {
  const value = projection.variants.find((entry) => (
    entry.capability_id === capabilityId && entry.variant_id === variantId
  ));
  assert.ok(value, `${capabilityId}/${variantId} must be present`);
  return value;
}

test("the package embeds the complete immutable reviewed semantic ceiling", () => {
  const packageJson = JSON.parse(fs.readFileSync(path.join(__dirname, "..", "package.json"), "utf8"));
  assert.equal(packageJson.exports["./operations"], "./lib/operations.js");
  assert.deepEqual(CHAMELEON_SEMANTIC_MANIFEST.counts, {
    normalized_operations: 50,
    coverage_rows: 51,
    availability_variants: 112,
    effect_profiles: 16,
    technique_ids: 33,
    dependency_proof_providers: 22,
    command_owners: 147,
    command_source_entries: 147,
    compiled_commands: 37,
  });
  assert.equal(CHAMELEON_SEMANTIC_MANIFEST.command_source_metadata_authority,
    "provenance_only");
  assert.equal(CHAMELEON_SEMANTIC_DIGESTS.normalized_operation_registry_sha256,
    "2d048b7a95212ebf3dab3880465c5a920fb2236ac591334a3c940dab606ce8f1");
  assert.equal(CHAMELEON_SEMANTIC_DIGESTS.assurance_profile_registry_sha256,
    "6ca848e291e9630560fef47875e4f111b24f418804d5b271f517d3243d3e9c55");
  assert.equal(CHAMELEON_SEMANTIC_DIGESTS.capability_dependency_registry_sha256,
    "62ae7c98a576cb3d19aeaefad5860216a89692e29ba443f94163e260fe6ecfca");
  assert.equal(CHAMELEON_SEMANTIC_DIGESTS.dependency_proof_provider_registry_sha256,
    "67e4b6a4c2545e836c6680dd102e12017fa3706a692f45bc96612f17abd49f42");
  assert.equal(CHAMELEON_SEMANTIC_DIGESTS.command_ownership_sha256,
    "f92a84341f8d79b0340071fe90eb00beafab1cc3b099f2e6252299e744aab2f7");
  assert.equal(CHAMELEON_SEMANTIC_DIGESTS.coverage_semantics_sha256,
    "5e197912d21dafc7c99c9ece6cdca645913ddc23a74151436b71ea5ff2b78e12");
  assert.equal(CHAMELEON_SEMANTIC_DIGESTS.command_source_registry_sha256,
    "464bcd9c4ef1045a48d052832b8ad2e67aa240c4375b6ce51298b29abeb617c5");
  assert.equal(Object.isFrozen(reviewedManifestSnapshot()), true);
  assert.equal(Object.isFrozen(reviewedManifestSnapshot().coverage), true);
  assert.equal(Object.isFrozen(reviewedManifestSnapshot().coverage[0]), true);
  assert.throws(() => {
    reviewedManifestSnapshot().coverage[0].disposition = "planned";
  }, /read only|Cannot assign/u);

  const inventory = getChameleonCapability("CU-CORE-INVENTORY");
  assert.deepEqual(inventory.upstream_command_ids, [1000, 1017, 1025, 1033, 1035]);
  assert.deepEqual(CHAMELEON_BOOTSTRAP_SUBSET.operation_ids, [
    "instrument.capabilities",
    "instrument.health",
    "instrument.inventory",
  ]);
  assert.deepEqual(CHAMELEON_BOOTSTRAP_SUBSET.command_ids, inventory.upstream_command_ids);
  assert.equal(Object.isFrozen(CHAMELEON_BOOTSTRAP_SUBSET), true);

  assert.equal(getChameleonCommandOwner(3007).disposition, "unsupported");
  assert.equal(getChameleonCommandOwner(3008).disposition, "unsupported");
  assert.equal(getChameleonCommandOwner(3032).disposition, "unsupported");
  assert.equal(getChameleonCommandOwner(6010).disposition, "provider_internal");
  assert.equal(getChameleonCommandOwner(65535), null);
  assert.equal(getChameleonAvailabilityVariant("CU-HF-14A-DISCOVERY", "default")
    .effect_profile_refs.includes("EP-TARGET-TRANSMIT-RF"), true);
  assert.equal(getChameleonOperation("protocol.compiled_exchange")
    .minimum_assurance_profile_id, "enrolled_source_pinned");
  assert.equal(getChameleonOperation("protocol.discovery_probe").exposure,
    "technique_compiled");
  assert.equal(getChameleonOperation("protocol.discovery_probe")
    .minimum_assurance_profile_id, "enrolled_conformance_tested");
  assert.deepEqual(Object.entries(reviewedManifestSnapshot().normalized_operation_registry)
    .filter(([, contract]) => contract.minimum_assurance_profile_id
      === "enrolled_conformance_tested")
    .map(([operationId]) => operationId), ["protocol.discovery_probe"]);
  assert.equal(getChameleonAvailabilityVariant("CU-HF-14A-COMPILED-PROBE", "default"), null);
  for (const variantId of ["requa_atqa_v1", "wupa_atqa_v1"]) {
    const variant = getChameleonAvailabilityVariant("CU-HF-14A-COMPILED-PROBE", variantId);
    assert.equal(variant.parameter_selector_id, variantId);
    assert.deepEqual(variant.normalized_operations, ["protocol.discovery_probe"]);
    assert.deepEqual(variant.technique_bindings, ["protocol.probe"]);
    assert.deepEqual(variant.effect_profile_refs, ["EP-TARGET-TRANSMIT-RF"]);
  }

  const discoverySource = getChameleonCommandSourceProvenance(2000);
  assert.equal(discoverySource.declaration_symbol, "DATA_CMD_HF14A_SCAN");
  assert.equal(discoverySource.runtime_handler_symbol, "cmd_processor_hf14a_scan");
  assert.deepEqual(discoverySource.hook_symbols, [
    "after_hf_reader_run",
    "before_hf_reader_run",
  ]);
  assert.equal(discoverySource.metadata_authority, "provenance_only");
  assert.equal(discoverySource.dispatch_authority, false);
  assert.equal(discoverySource.compiler_authority, false);
  assert.equal(getChameleonCommandSourceProvenance(3007).runtime_handler_symbol, null);
  assert.equal(getChameleonCommandSourceProvenance(6010).declaration_symbol, null);
  assert.equal(getChameleonCommandSourceProvenance(65535), null);
});

test("the operation surface is transport-free and has no evaluator raw or administration API", () => {
  const source = fs.readFileSync(path.join(__dirname, "..", "lib", "operations.js"), "utf8");
  assert.doesNotMatch(source, /require\(["'](?:node:)?(?:fs|child_process|net|dgram|http|https|tls|worker_threads)["']\)/u);
  assert.doesNotMatch(source, /serialport|navigator\.serial|usb\.openDevice|bluetooth\.requestDevice/iu);
  assert.doesNotMatch(source, /require\([^\n]*docs\/plane-physical/u);
  assert.doesNotMatch(source, /#define\s+DATA_CMD|static\s+cmd_data_map_t|data_frame_tx_t\s*\*/u);
  assert.doesNotMatch(
    resolveChameleonAvailability.toString(),
    /COMMAND_SOURCE|declaration_symbol|runtime_handler_symbol|hook_symbols/u,
    "source symbol metadata cannot participate in runtime availability",
  );
  assert.doesNotMatch(
    normalizeChameleonEvaluatorSelection.toString(),
    /COMMAND_SOURCE|declaration_symbol|runtime_handler_symbol|hook_symbols/u,
    "source symbol metadata cannot participate in evaluator selection",
  );
  assert.deepEqual(Object.keys(operations).sort(), [
    "CHAMELEON_AVAILABILITY_EVIDENCE_VERSION",
    "CHAMELEON_AVAILABILITY_BACKEND_VERSION",
    "CHAMELEON_BOOTSTRAP_SUBSET",
    "CHAMELEON_SEMANTIC_DIGESTS",
    "CHAMELEON_SEMANTIC_MANIFEST",
    "CHAMELEON_V220_CODEC_PROFILE",
    "CHAMELEON_V220_SOURCE_PROFILE",
    "buildChameleonAvailabilityVariantQualification",
    "createTestChameleonAvailabilityEvidenceResolverPort",
    "dependencyProofContract",
    "getChameleonAvailabilityVariant",
    "getChameleonCapability",
    "getChameleonCommandOwner",
    "getChameleonCommandSourceProvenance",
    "getChameleonOperation",
    "normalizeChameleonEvaluatorSelection",
    "resolveChameleonAvailability",
    "resolveChameleonAvailabilityEvidence",
    "resolveProductionShapedChameleonAvailabilityEvidence",
    "reviewedManifestSnapshot",
  ].sort());
  for (const operationId of [
    "protocol.apdu_exchange",
    "protocol.respond",
    "protocol.transceive",
  ]) {
    assert.equal(getChameleonOperation(operationId).exposure, "provider_private");
  }
  for (const operationId of [
    "instrument.admin_configure",
    "instrument.erase",
    "instrument.firmware_manage",
    "instrument.manual_action",
  ]) {
    assert.equal(getChameleonOperation(operationId).exposure, "operator_only");
  }
  assert.equal(
    Object.keys(operations).some((key) => /execute|exchange|respond|raw|apdu|admin|firmware|erase/iu.test(key)),
    false,
  );
});

test("availability intersects same-manifest inventory, codec profile, assurance, and proofs", () => {
  const bootstrapOnly = resolveChameleonAvailability(availabilityInput());
  assert.equal(bootstrapOnly.variants.length, 112);
  assert.equal(bootstrapOnly.execution_authority, false);
  assert.equal(bootstrapOnly.production_ready, false);
  assert.equal(bootstrapOnly.runtime_ready, false);
  assert.deepEqual(bootstrapOnly.readiness_blockers, [
    "production_availability_evidence_verifier_not_implemented",
  ]);
  assert.equal(status(bootstrapOnly, "CU-CORE-INVENTORY", "identity_version")
    .requirements_satisfied, true);
  assert.equal(status(bootstrapOnly, "CU-CORE-INVENTORY", "capabilities")
    .requirements_satisfied, true);
  assert.equal(status(bootstrapOnly, "CU-CORE-INVENTORY", "battery_health")
    .requirements_satisfied, true);
  assert.equal(status(bootstrapOnly, "CU-CORE-INVENTORY", "identity_version")
    .runtime_available, false);
  assert.deepEqual(bootstrapOnly.unrecognized_reported_command_ids, [65535]);
  assert.deepEqual(bootstrapOnly.uncompiled_reported_command_ids, [2000]);

  const codecUnavailable = status(bootstrapOnly, "CU-CORE-FRAME-CODEC", "default");
  assert.equal(codecUnavailable.runtime_available, false);
  assert.deepEqual(codecUnavailable.missing_all_of, ["conformance:chameleon_frame_codec_v1"]);
  const withConformance = resolveChameleonAvailability(availabilityInput({
    dependency_proofs: [proof("conformance:chameleon_frame_codec_v1")],
  }));
  assert.equal(status(withConformance, "CU-CORE-FRAME-CODEC", "default")
    .requirements_satisfied, true);
  assert.equal(status(withConformance, "CU-CORE-FRAME-CODEC", "default")
    .runtime_available, false);
  assert.equal(status(withConformance, "CU-CORE-FRAME-CODEC", "default")
    .evaluator_callable, false);

  const discovery = status(withConformance, "CU-HF-14A-DISCOVERY", "default");
  assert.equal(discovery.manifest_supported, true);
  assert.equal(discovery.runtime_available, false, "semantic support cannot widen the codec profile");
  assert.equal(discovery.missing_all_of.includes("command:2000"), true);
  assert.equal(discovery.evaluator_callable, false);
  assert.equal(discovery.execution_authority, false);
  assert.equal(
    getChameleonCommandSourceProvenance(2000).runtime_handler_symbol !== null,
    true,
    "factual handler presence is provenance and cannot satisfy codec availability",
  );

  const desfireWithoutSelection = status(
    withConformance,
    "CU-HF-DESFIRE-ENUMERATE",
    "default",
  );
  assert.deepEqual(desfireWithoutSelection.selected_alternatives, [null]);
  const explicitAlternative =
    "capability_variant:CU-HF-ISO14443-4-APDU/reader_apdu";
  const withExplicitAlternative = resolveChameleonAvailability(availabilityInput({
    alternative_selections: [{
      capability_id: "CU-HF-DESFIRE-ENUMERATE",
      variant_id: "default",
      group_index: 0,
      dependency_ref: explicitAlternative,
    }],
  }));
  assert.deepEqual(status(
    withExplicitAlternative,
    "CU-HF-DESFIRE-ENUMERATE",
    "default",
  ).selected_alternatives, [explicitAlternative]);
});

test("closed HF14A probes stay negative-only until distinct HIL conformance and command review", () => {
  const sourcePinnedClaims = {
    identity_enrollment: "operator_enrolled",
    firmware_provenance: "operator_pinned",
    command_surface_conformance: "manifest_intersected",
    transport_trust: "operator_provisioned",
  };
  const conformanceTestedClaims = {
    ...sourcePinnedClaims,
    command_surface_conformance: "conformance_tested",
  };
  const compilerProof = proof("compiler:iso14443a_closed_probe_v1");
  const hilProof = proof("conformance:chameleon_hf14a_closed_probe_v1");
  assert.notEqual(
    dependencyProofContract("compiler:iso14443a_closed_probe_v1").contract_digest,
    dependencyProofContract("conformance:chameleon_hf14a_closed_probe_v1").contract_digest,
  );
  assert.notEqual(
    dependencyProofContract("conformance:chameleon_frame_codec_v1").contract_digest,
    dependencyProofContract("conformance:chameleon_hf14a_closed_probe_v1").contract_digest,
  );

  const sourceOnly = resolveChameleonAvailability(availabilityInput({
    assurance_claims: sourcePinnedClaims,
    dependency_proofs: [compilerProof],
  }));
  for (const variantId of ["requa_atqa_v1", "wupa_atqa_v1"]) {
    const probe = status(sourceOnly, "CU-HF-14A-COMPILED-PROBE", variantId);
    assert.equal(probe.runtime_available, false);
    assert.equal(probe.evaluator_callable, false);
    assert.equal(probe.execution_authority, false);
    assert.equal(probe.missing_all_of.includes(
      "conformance:chameleon_hf14a_closed_probe_v1",
    ), true, "compiler/source evidence cannot substitute for an owned HIL verdict");
    assert.deepEqual(probe.assurance_failures, [
      "protocol.discovery_probe:command_surface_conformance:conformance_tested",
    ]);
  }

  const wrongConformance = resolveChameleonAvailability(availabilityInput({
    assurance_claims: conformanceTestedClaims,
    dependency_proofs: [
      compilerProof,
      proof("conformance:chameleon_frame_codec_v1"),
    ],
  }));
  assert.equal(status(
    wrongConformance,
    "CU-HF-14A-COMPILED-PROBE",
    "requa_atqa_v1",
  ).missing_all_of.includes("conformance:chameleon_hf14a_closed_probe_v1"), true);

  const allSemanticProofs = resolveChameleonAvailability(availabilityInput({
    reported_command_ids: [...CHAMELEON_V220_CODEC_PROFILE.command_ids, 2010],
    assurance_claims: conformanceTestedClaims,
    dependency_proofs: [compilerProof, hilProof],
  }));
  assert.equal(allSemanticProofs.uncompiled_reported_command_ids.includes(2010), true);
  const raw = status(allSemanticProofs, "CU-HF-14A-RAW", "default");
  assert.equal(raw.runtime_available, false);
  assert.deepEqual(raw.missing_all_of, ["command:2010"]);
  assert.deepEqual(raw.effect_profile_refs, [
    "EP-TARGET-DESTROY-RF",
    "EP-TARGET-MUTATE-RF-STATEFUL",
    "EP-TARGET-TRANSMIT-RF",
  ]);
  for (const variantId of ["requa_atqa_v1", "wupa_atqa_v1"]) {
    const probe = status(allSemanticProofs, "CU-HF-14A-COMPILED-PROBE", variantId);
    assert.equal(probe.runtime_available, false);
    assert.deepEqual(probe.missing_all_of, [
      "capability_variant:CU-HF-14A-RAW/default",
    ]);
    assert.deepEqual(probe.assurance_failures, []);
    assert.equal(probe.execution_authority, false);
  }
});

test("closed availability projections reject drift, proof substitution, and caller fabrication", () => {
  for (const [field, value, pattern] of [
    ["semantic_manifest_digest", digest("alien-manifest"), /semantic_manifest_digest drifted/u],
    ["source_profile_digest", digest("alien-source"), /source_profile_digest drifted/u],
    ["codec_profile_digest", digest("alien-codec"), /codec_profile_digest drifted/u],
    ["assurance_profile_registry_digest", digest("alien-assurance"), /assurance_profile_registry_digest drifted/u],
    ["dependency_proof_registry_digest", digest("alien-proofs"), /dependency_proof_registry_digest drifted/u],
  ]) {
    assert.throws(() => resolveChameleonAvailability(availabilityInput({ [field]: value })), pattern);
  }
  assert.throws(
    () => resolveChameleonAvailability(availabilityInput({ raw_command: 2000 })),
    /unknown fields: raw_command/u,
  );
  assert.throws(
    () => resolveChameleonAvailability(availabilityInput({
      dependency_proofs: [{
        ...proof("conformance:chameleon_frame_codec_v1"),
        provider_contract_digest: dependencyProofContract("transport:ble_nus_v1").contract_digest,
      }],
    })),
    /does not match the reviewed dependency contract/u,
  );
  assert.throws(
    () => resolveChameleonAvailability(availabilityInput({
      alternative_selections: [{
        capability_id: "CU-HF-DESFIRE-ENUMERATE",
        variant_id: "default",
        group_index: 0,
        dependency_ref: "capability_variant:CU-HF-14A-DISCOVERY/default",
      }],
    })),
    /is not an alternative in the selected group/u,
  );
  assert.throws(
    () => normalizeChameleonEvaluatorSelection({
      capability_id: "CU-HF-14A-DISCOVERY",
      variant_id: "default",
      operation_id: "protocol.discover",
      technique_id: "credential.classify",
      parameters: { parameter_selector_id: "default" },
    }, { ...resolveChameleonAvailability(availabilityInput()) }),
    /resolver-issued availability projection/u,
  );
});

test("runtime availability requires branded evidence and test evidence cannot be promoted", () => {
  const evidence = evidenceFixture();
  assert.equal(Object.isFrozen(evidence), true);
  assert.equal(evidence.resolver_verified, true);
  assert.equal(evidence.production_ready, false);
  assert.equal(evidence.runtime_ready, false);
  assert.equal(evidence.execution_authority, false);
  assert.deepEqual(evidence.readiness_blockers, [
    "production_availability_evidence_verifier_not_implemented",
  ]);
  assert.throws(() => {
    evidence.production_ready = true;
  }, /read only|Cannot assign/u);

  for (const lookalike of [
    resolvedEvidence(evidenceRequest()),
    { ...evidence },
    { ...evidence, production_ready: true, runtime_ready: true, execution_authority: true },
  ]) {
    assert.throws(
      () => resolveChameleonAvailability({
        version: 1,
        provider_id: "chameleon_ultra",
        evidence_projection: lookalike,
        alternative_selections: [],
      }),
      /resolver-issued branded evidence/u,
    );
  }
  let proxyTrapCalls = 0;
  const evidenceProxy = new Proxy(evidence, {
    ownKeys(target) {
      proxyTrapCalls += 1;
      return Reflect.ownKeys(target);
    },
  });
  assert.throws(
    () => resolveChameleonAvailability({
      version: 1,
      provider_id: "chameleon_ultra",
      evidence_projection: evidenceProxy,
      alternative_selections: [],
    }),
    /resolver-issued branded evidence/u,
  );
  assert.equal(proxyTrapCalls, 0);

  assert.throws(
    () => resolveChameleonAvailability({
      version: 1,
      provider_id: "chameleon_ultra",
      reported_command_ids: [1000],
      assurance_claims: {
        identity_enrollment: "hardware_bound",
        firmware_provenance: "hardware_attested",
        command_surface_conformance: "conformance_tested",
        transport_trust: "hardware_attested",
      },
      dependency_proofs: [],
      alternative_selections: [],
    }),
    /unknown fields: assurance_claims, dependency_proofs, reported_command_ids/u,
  );

  const availability = resolveChameleonAvailability(availabilityInput({
    evidence_projection: evidence,
  }));
  assert.equal(availability.production_ready, false);
  assert.equal(availability.runtime_ready, false);
  assert.equal(availability.execution_authority, false);
  assert.equal(availability.variants.every((entry) => (
    entry.production_ready === false
      && entry.runtime_available === false
      && entry.evaluator_callable === false
      && entry.execution_authority === false
  )), true);
  assert.equal(
    availability.variants.every((entry) => !entry.evaluator_callable || entry.production_ready),
    true,
  );
  assert.throws(() => {
    availability.runtime_ready = true;
  }, /read only|Cannot assign/u);

  const selectedWithoutProof = resolveChameleonAvailability(availabilityInput({
    alternative_selections: [{
      capability_id: "CU-HF-DESFIRE-ENUMERATE",
      variant_id: "default",
      group_index: 0,
      dependency_ref: "capability_variant:CU-HF-ISO14443-4-APDU/reader_apdu",
    }],
  }));
  assert.equal(status(
    selectedWithoutProof,
    "CU-HF-DESFIRE-ENUMERATE",
    "default",
  ).requirements_satisfied, false, "caller policy can select but cannot manufacture proof");
});

test("dependency evidence is exact-bound to manifests, inventory, identity, custody, session, authority, and owner", () => {
  const dependencyRef = "conformance:chameleon_frame_codec_v1";
  const baseRequest = evidenceRequest();
  for (const [field, alienValue] of [
    ["evidence_ref", "availability-evidence:cross-wired"],
    ["semantic_manifest_digest", digest("cross-semantic-manifest")],
    ["source_profile_digest", digest("cross-source-manifest")],
    ["codec_profile_digest", digest("cross-codec-manifest")],
    ["assurance_profile_registry_digest", digest("cross-assurance-registry")],
    ["dependency_proof_registry_digest", digest("cross-proof-registry")],
    ["inventory_projection_digest", digest("cross-inventory")],
    ["device_identity_digest", digest("cross-device")],
    ["custody_id", "custody:cross-wired"],
    ["custody_projection_digest", digest("cross-custody")],
    ["session_id", "session:cross-wired"],
    ["authority_id", "authority:cross-wired"],
    ["authority_epoch", 99],
    ["revocation_generation", 99],
    ["authority_resolution_digest", digest("cross-authority-resolution")],
  ]) {
    const crossRequest = { ...baseRequest, [field]: alienValue };
    const crossProof = proof(dependencyRef, "satisfied", crossRequest);
    assert.throws(
      () => evidenceFixture({ evidenceOverrides: { dependency_proofs: [crossProof] } }),
      new RegExp(`${field} drifted`, "u"),
    );
  }

  assert.throws(
    () => evidenceFixture({
      evidenceOverrides: {
        dependency_proofs: [proof(
          dependencyRef,
          "satisfied",
          baseRequest,
          { owner_principal: "principal:wrong-proof-owner" },
        )],
      },
    }),
    /owner_principal does not match the reviewed dependency owner/u,
  );

  const validProof = proof(dependencyRef);
  for (const [field, value] of [
    ["artifact_digest", digest("current-artifact-drift")],
    ["trust_epoch", validProof.trust_epoch + 1],
    ["verdict", "unsatisfied"],
    ["proof_digest", digest("current-proof-drift")],
  ]) {
    assert.throws(
      () => evidenceFixture({
        evidenceOverrides: { dependency_proofs: [validProof] },
        currentStateOverrides: {
          dependency_states: [dependencyState(validProof, { [field]: value })],
        },
      }),
      new RegExp(`${field} drifted`, "u"),
    );
  }

  assert.throws(
    () => evidenceFixture({
      evidenceOverrides: {
        dependency_proofs: [{ ...validProof, proof_digest: digest("detached-proof") }],
      },
    }),
    /proof_digest does not bind the exact evidence context and verdict/u,
  );
});

test("stale, revoked, or non-current evidence and dependency proofs fail closed", () => {
  assert.throws(
    () => evidenceFixture({
      evidenceOverrides: { expires_at: "2026-07-20T00:30:00.000Z" },
    }),
    /evidence is stale/u,
  );
  assert.throws(
    () => evidenceFixture({ evidenceOverrides: { revoked: true } }),
    /evidence is revoked/u,
  );
  assert.throws(
    () => evidenceFixture({ currentStateOverrides: { evidence_revoked: true } }),
    /evidence is revoked/u,
  );

  const staleProof = proof(
    "conformance:chameleon_frame_codec_v1",
    "satisfied",
    evidenceRequest(),
    { expires_at: "2026-07-20T00:30:00.000Z" },
  );
  assert.throws(
    () => evidenceFixture({ evidenceOverrides: { dependency_proofs: [staleProof] } }),
    /proof is stale/u,
  );
  const revokedProof = proof(
    "conformance:chameleon_frame_codec_v1",
    "satisfied",
    evidenceRequest(),
    { revoked: true },
  );
  assert.throws(
    () => evidenceFixture({ evidenceOverrides: { dependency_proofs: [revokedProof] } }),
    /dependency_states\[0\] is revoked/u,
  );

  for (const field of [
    "inventory_current",
    "device_current",
    "custody_current",
    "session_current",
    "authority_current",
  ]) {
    assert.throws(
      () => evidenceFixture({ currentStateOverrides: { [field]: false } }),
      new RegExp(`${field} must be true`, "u"),
    );
  }
  for (const [field, value] of [
    ["session_id", "session:stale-current-state"],
    ["authority_id", "authority:stale-current-state"],
    ["authority_epoch", 8],
    ["revocation_generation", 4],
    ["evidence_trust_epoch", 14],
  ]) {
    assert.throws(
      () => evidenceFixture({ currentStateOverrides: { [field]: value } }),
      new RegExp(`${field} drifted`, "u"),
    );
  }
});

test("availability evidence ports reject lookalikes, weak or async callbacks, accessors, and proxies", () => {
  const request = evidenceRequest();
  const evidence = resolvedEvidence(request);
  const port = fixtureResolverPort(request, evidence);
  assert.equal(port.production_ready, false);
  assert.equal(Object.isFrozen(port), true);
  assert.throws(() => {
    port.production_ready = true;
  }, /read only|Cannot assign/u);
  assert.throws(
    () => resolveChameleonAvailabilityEvidence({ ...port }, request),
    /branded synchronous resolver port/u,
  );
  assert.throws(
    () => resolveChameleonAvailabilityEvidence({ ...port, production_ready: true }, request),
    /branded synchronous resolver port/u,
  );

  const validPortInput = {
    version: CHAMELEON_AVAILABILITY_EVIDENCE_VERSION,
    port_id: "availability-evidence-port:hostile",
    test_only: true,
    verification_model: "synchronous_exact_evidence_and_current_state",
    resolve_evidence: () => evidence,
    resolve_current_state: (currentRequest) => resolvedCurrentState(
      request,
      evidence,
      currentRequest,
    ),
  };
  assert.throws(
    () => createTestChameleonAvailabilityEvidenceResolverPort({
      ...validPortInput,
      test_only: false,
    }),
    /factory is test-only/u,
  );
  assert.throws(
    () => createTestChameleonAvailabilityEvidenceResolverPort({
      ...validPortInput,
      verification_model: "eventually_consistent_caller_asserted",
    }),
    /rejects weak verification models/u,
  );
  for (const field of ["resolve_evidence", "resolve_current_state"]) {
    assert.throws(
      () => createTestChameleonAvailabilityEvidenceResolverPort({
        ...validPortInput,
        [field]: async () => evidence,
      }),
      new RegExp(`${field} must be synchronous`, "u"),
    );
    assert.throws(
      () => createTestChameleonAvailabilityEvidenceResolverPort({
        ...validPortInput,
        [field]: new Proxy(validPortInput[field], {}),
      }),
      new RegExp(`${field} must be synchronous`, "u"),
    );
  }

  const promiseEvidencePort = fixtureResolverPort(request, evidence, {}, {
    resolve_evidence: () => Promise.resolve(evidence),
  });
  assert.throws(
    () => resolveChameleonAvailabilityEvidence(promiseEvidencePort, request),
    /must be synchronous; async resolver ports are rejected/u,
  );
  const promiseStatePort = fixtureResolverPort(request, evidence, {}, {
    resolve_current_state: () => Promise.resolve({}),
  });
  assert.throws(
    () => resolveChameleonAvailabilityEvidence(promiseStatePort, request),
    /must be synchronous; async resolver ports are rejected/u,
  );

  let trapCalls = 0;
  const requestProxy = new Proxy(request, {
    ownKeys(target) {
      trapCalls += 1;
      return Reflect.ownKeys(target);
    },
  });
  assert.throws(
    () => resolveChameleonAvailabilityEvidence(port, requestProxy),
    /must be an object/u,
  );
  assert.equal(trapCalls, 0);
  const evidenceProxyPort = fixtureResolverPort(request, evidence, {}, {
    resolve_evidence: () => new Proxy(evidence, {
      get(target, field, receiver) {
        trapCalls += 1;
        return Reflect.get(target, field, receiver);
      },
    }),
  });
  assert.throws(
    () => resolveChameleonAvailabilityEvidence(evidenceProxyPort, request),
    /cannot return a proxy/u,
  );
  assert.equal(trapCalls, 0);

  let getterCalls = 0;
  const accessorEvidence = resolvedEvidence(request);
  Object.defineProperty(accessorEvidence, "reported_command_ids", {
    enumerable: true,
    get() {
      getterCalls += 1;
      return [1000];
    },
  });
  const accessorEvidencePort = fixtureResolverPort(request, accessorEvidence);
  assert.throws(
    () => resolveChameleonAvailabilityEvidence(accessorEvidencePort, request),
    /reported_command_ids must be an enumerable data field/u,
  );
  assert.equal(getterCalls, 0);

  const accessorStatePort = fixtureResolverPort(request, evidence, {}, {
    resolve_current_state: (currentRequest) => {
      const state = resolvedCurrentState(request, evidence, currentRequest);
      Object.defineProperty(state, "current_time", {
        enumerable: true,
        get() {
          getterCalls += 1;
          return "2026-07-20T01:00:00.000Z";
        },
      });
      return state;
    },
  });
  assert.throws(
    () => resolveChameleonAvailabilityEvidence(accessorStatePort, request),
    /current_time must be an enumerable data field/u,
  );
  assert.equal(getterCalls, 0);
});

test("availability and selection inputs reject accessors, sparse arrays, and adorned arrays without invocation", () => {
  let getterCalls = 0;
  const accessorInput = availabilityInput();
  Object.defineProperty(accessorInput, "provider_id", {
    enumerable: true,
    get() {
      getterCalls += 1;
      return "chameleon_ultra";
    },
  });
  assert.throws(
    () => resolveChameleonAvailability(accessorInput),
    /provider_id must be an enumerable data field/u,
  );
  assert.equal(getterCalls, 0);

  const accessorProof = proof("conformance:chameleon_frame_codec_v1");
  Object.defineProperty(accessorProof, "dependency_ref", {
    enumerable: true,
    get() {
      getterCalls += 1;
      return "conformance:chameleon_frame_codec_v1";
    },
  });
  for (const [field, value, pattern] of [
    ["reported_command_ids", Object.assign([1000], { extra: true }), /extra or symbol fields/u],
    ["dependency_proofs", [accessorProof], /dependency_ref must be an enumerable data field/u],
    ["alternative_selections", Object.assign([], { extra: true }), /extra or symbol fields/u],
  ]) {
    assert.throws(
      () => resolveChameleonAvailability(availabilityInput({ [field]: value })),
      pattern,
    );
  }
  const sparseCommands = new Array(1);
  assert.throws(
    () => resolveChameleonAvailability(availabilityInput({
      reported_command_ids: sparseCommands,
    })),
    /dense enumerable data array/u,
  );
  assert.equal(getterCalls, 0);

  const selection = {
    capability_id: "CU-HF-14A-DISCOVERY",
    variant_id: "default",
    operation_id: "protocol.discover",
    technique_id: "credential.classify",
    parameters: { parameter_selector_id: "default" },
  };
  Object.defineProperty(selection, "operation_id", {
    enumerable: true,
    get() {
      getterCalls += 1;
      return "protocol.discover";
    },
  });
  assert.throws(
    () => normalizeChameleonEvaluatorSelection(
      selection,
      resolveChameleonAvailability(availabilityInput()),
    ),
    /operation_id must be an enumerable data field/u,
  );
  assert.equal(getterCalls, 0);
});

test("operator-only and provider-private variants can never become evaluator-callable", () => {
  const enrolled = resolveChameleonAvailability(availabilityInput({
    assurance_claims: {
      identity_enrollment: "operator_enrolled",
      firmware_provenance: "operator_pinned",
      command_surface_conformance: "manifest_intersected",
      transport_trust: "operator_provisioned",
    },
  }));
  const dfu = status(enrolled, "CU-ADMIN-DFU", "default");
  assert.equal(dfu.requirements_satisfied, true);
  assert.equal(dfu.runtime_available, false);
  assert.equal(dfu.evaluator_callable, false);
  assert.throws(
    () => normalizeChameleonEvaluatorSelection({
      capability_id: "CU-ADMIN-DFU",
      variant_id: "default",
      operation_id: "instrument.firmware_manage",
      technique_id: null,
      parameters: { parameter_selector_id: "default" },
    }, enrolled),
    /not runtime available/u,
  );

  const raw = status(enrolled, "CU-HF-14A-RAW", "default");
  assert.equal(raw.runtime_available, false);
  assert.equal(raw.evaluator_callable, false);
  assert.equal(getChameleonOperation("protocol.transceive").exposure, "provider_private");
  assert.throws(
    () => normalizeChameleonEvaluatorSelection({
      capability_id: "CU-HF-14A-RAW",
      variant_id: "default",
      operation_id: "protocol.transceive",
      technique_id: null,
      parameters: { parameter_selector_id: "default" },
    }, enrolled),
    /not runtime available/u,
  );
});
