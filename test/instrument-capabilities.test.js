"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");

const {
  buildExecutedEvidenceRegistry,
} = require("../mcp/lib/executed-evidence-registry.js");
const {
  INSTRUMENT_CAPABILITY_CLAIM_DOMAIN,
  INSTRUMENT_CAPABILITY_EVIDENCE_DOMAIN,
  INSTRUMENT_CAPABILITY_PROOF_DOMAIN,
  MAX_QUERY_LIMIT,
  buildInstrumentCapabilitySignerRegistry,
  createInstrumentCapabilityIndexPort,
  defineInstrumentCapabilitySemanticManifest,
  installInstrumentCapabilityIndexPort,
  instrumentCapabilitySignatureInputDigest,
  queryInstrumentCapabilityIndexPort,
} = require("../mcp/lib/instrument-capabilities.js");
const {
  chameleonCapabilityProofSignerBinding,
  createChameleonCapabilityExecutedEvidenceRegistry,
  createChameleonInstrumentCapabilitySemanticManifest,
  projectChameleonAlternativeSelection,
  projectChameleonReportedCommands,
} = require("../mcp/lib/instrument-capabilities-chameleon.js");
const {
  TRUSTED_CLOCK_MAPPING_DOMAIN,
  createPhysicalTrustedClockPort,
  physicalClockMappingSigningMessage,
  publicKeyDigest,
} = require("../mcp/lib/physical-trusted-clock.js");
const {
  createDeterministicProviderFixture,
} = require("../packages/bob-instrument-deterministic/lib/fixtures.js");
const {
  hashCanonicalJson,
} = require("../mcp/lib/verification-contracts.js");
const queryTool = require("../mcp/lib/tools/query-instrument-capabilities.js");

function digest(label) {
  return hashCanonicalJson({ label });
}

function iso(milliseconds) {
  return new Date(milliseconds).toISOString();
}

function signClockMapping(keyPair, payload) {
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
  return { ...basis, signed_mapping_digest: hashCanonicalJson(basis) };
}

function signedClock(now, suffix = "primary") {
  const signer = crypto.generateKeyPairSync("ed25519");
  const referenceMonotonicMs = 10_000;
  const currentMonotonicMs = 10_100;
  const payload = {
    version: 1,
    clock_id: `physical-clock:ph-i1-${suffix}`,
    monotonic_epoch_id: digest(`clock-epoch:${suffix}`),
    mapping_generation: 1,
    reference_monotonic_ms: referenceMonotonicMs,
    reference_utc: iso(now - 100),
    max_uncertainty_ms: 5,
    not_before: iso(now - 60_000),
    expires_at: iso(now + 30 * 60_000),
    trust_root_epoch: 1,
    authority_epoch: 7,
    revocation_generation: 2,
    signer_key_id: `clock-key:ph-i1-${suffix}`,
    signer_public_key_digest: publicKeyDigest(signer.publicKey),
  };
  const mapping = signClockMapping(signer, payload);
  const trust = {
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
    public_key: signer.publicKey,
  };
  return createPhysicalTrustedClockPort({
    port_id: `ph_i1_${suffix}`,
    clock_id: payload.clock_id,
    monotonic_epoch_id: payload.monotonic_epoch_id,
    uncertainty_ceiling_ms: 25,
    read_monotonic_ms: () => currentMonotonicMs,
    read_signed_mapping: () => mapping,
    resolve_current_trust: () => trust,
  });
}

function signedEnvelope({ domain, payload, registry, keyId, trustEpoch, privateKey }) {
  const payloadDigest = hashCanonicalJson(payload);
  const unsigned = {
    domain,
    payload,
    payload_digest: payloadDigest,
    signer_registry_digest: registry.registry_digest,
    signer_key_id: keyId,
    signer_trust_epoch: trustEpoch,
    signature_scheme: "ed25519",
  };
  const signature = crypto.sign(
    null,
    Buffer.from(instrumentCapabilitySignatureInputDigest(unsigned), "hex"),
    privateKey,
  ).toString("base64url");
  const signedBody = { version: 1, ...unsigned, signature };
  return { ...signedBody, envelope_digest: hashCanonicalJson(signedBody) };
}

function claim(axis, value, payload, manifest) {
  return {
    claim: value,
    claim_digest: hashCanonicalJson({
      domain: INSTRUMENT_CAPABILITY_CLAIM_DOMAIN,
      axis,
      claim: value,
      semantic_manifest_digest: manifest.semantic_manifest_digest,
      inventory_checkpoint_digest: payload.inventory_checkpoint_digest,
      evidence_generation: payload.evidence_generation,
    }),
  };
}

function assuranceClaims(values, payload, manifest) {
  return Object.fromEntries(Object.entries(values).map(([axis, value]) => [
    axis,
    claim(axis, value, payload, manifest),
  ]));
}

const BOOTSTRAP_CLAIMS = Object.freeze({
  identity_enrollment: "unverified",
  firmware_provenance: "self_reported",
  command_surface_conformance: "bootstrap_allowlisted",
  transport_trust: "local_observed",
});

function chameleonFixture(options = {}) {
  const now = options.now || Date.now();
  const executedRegistry = createChameleonCapabilityExecutedEvidenceRegistry({
    attested_at: iso(now - 60_000),
    expires_at: iso(now + 30 * 60_000),
    trust_epoch: 3,
  });
  const manifest = createChameleonInstrumentCapabilitySemanticManifest(executedRegistry);
  const evidenceKey = crypto.generateKeyPairSync("ed25519");
  const proofRefs = options.proofRefs || [];
  const proofKeys = new Map(proofRefs.map((ref) => [ref, crypto.generateKeyPairSync("ed25519")]));
  const signerEntries = [{
    key_id: "signer-key:ph-i1-index",
    purpose: "index_evidence",
    owner_principal: "principal:ph-i1-index",
    signed_verdict_type: "instrument_capability_index_v1",
    trust_epoch: 5,
    authority_epoch: 7,
    revocation_generation: 2,
    disposition: "enrolled",
    binding_digest: manifest.instrument_capability_manifest_digest,
    valid_from: iso(now - 60_000),
    expires_at: iso(now + 20 * 60_000),
    public_key_pem: evidenceKey.publicKey.export({ type: "spki", format: "pem" }),
  }];
  for (const ref of proofRefs) {
    const binding = chameleonCapabilityProofSignerBinding(ref, executedRegistry);
    signerEntries.push({
      key_id: `signer-key:proof-${proofRefs.indexOf(ref) + 1}`,
      purpose: "dependency_proof",
      owner_principal: binding.canonical_owner_principal,
      signed_verdict_type: binding.canonical_signed_verdict_type,
      trust_epoch: binding.trust_epoch,
      authority_epoch: 7,
      revocation_generation: 2,
      disposition: options.revokedProofRef === ref ? "revoked" : "enrolled",
      binding_digest: binding.executed_provider_digest,
      valid_from: iso(now - 60_000),
      expires_at: iso(now + 20 * 60_000),
      public_key_pem: proofKeys.get(ref).publicKey.export({ type: "spki", format: "pem" }),
      executed_provider_id: binding.executed_provider_id,
      executed_provider_digest: binding.executed_provider_digest,
    });
  }
  const signerRegistry = buildInstrumentCapabilitySignerRegistry({
    version: 1,
    registry_id: `ph_i1_signers_${options.suffix || "default"}`,
    entries: signerEntries,
  }, executedRegistry);
  const predicateProjection = projectChameleonReportedCommands(
    options.reportedCommands || [1000, 1017, 1025, 1033, 1035],
  );
  const payload = {
    version: 1,
    target_domain: options.targetDomain || "physical-capability.example.test",
    session_nucleus_hash: digest("session-nucleus"),
    physical_scope_axis_digest: digest("physical-scope-axis"),
    instrument_ref: options.instrumentRef || "instrument:enrolled-1",
    enrollment_candidate_ref: "enrollment-candidate:enrolled-1",
    provider_id: manifest.provider_id,
    provider_descriptor_digest: manifest.provider_descriptor_digest,
    provider_binary_digest: digest("provider-binary"),
    transport_digest: digest("transport"),
    bootstrap_manifest_digest: digest("bootstrap-manifest"),
    connection_generation: 1,
    semantic_manifest_digest: manifest.semantic_manifest_digest,
    operation_registry_digest: manifest.operation_registry_digest,
    capabilities_digest: manifest.capabilities_digest,
    inventory_checkpoint_ref: `physical-inventory-checkpoint:${digest("inventory-checkpoint")}`,
    inventory_checkpoint_digest: digest("inventory-checkpoint"),
    inventory_projection_digest: digest("inventory-projection"),
    evidence_generation: 1,
    previous_evidence_digest: null,
    authority_epoch: 7,
    revocation_generation: 2,
    authority_resolution_digest: digest("authority-resolution"),
    observed_at: iso(now - 1_000),
    expires_at: iso(now + 10 * 60_000),
    assurance_claims: null,
    reported_device_predicate_digests:
      predicateProjection.reported_device_predicate_digests,
    alternative_selections: (options.alternativeSelections || []).map(
      projectChameleonAlternativeSelection,
    ),
    dependency_proofs: [],
  };
  payload.assurance_claims = assuranceClaims(
    options.assuranceClaims || BOOTSTRAP_CLAIMS,
    payload,
    manifest,
  );
  for (const ref of proofRefs) {
    const binding = chameleonCapabilityProofSignerBinding(ref, executedRegistry);
    const stale = options.staleProofRef === ref;
    const proofPayload = {
      version: 1,
      target_domain: payload.target_domain,
      session_nucleus_hash: payload.session_nucleus_hash,
      instrument_ref: payload.instrument_ref,
      provider_id: payload.provider_id,
      semantic_manifest_digest: payload.semantic_manifest_digest,
      inventory_checkpoint_digest: payload.inventory_checkpoint_digest,
      evidence_generation: payload.evidence_generation,
      authority_epoch: payload.authority_epoch,
      revocation_generation: payload.revocation_generation,
      authority_resolution_digest: payload.authority_resolution_digest,
      dependency_ref_digest: binding.dependency_ref_digest,
      reviewed_contract_digest: binding.reviewed_contract_digest,
      canonical_identity_digest: binding.canonical_identity_digest,
      executed_provider_id: binding.executed_provider_id,
      executed_provider_digest: binding.executed_provider_digest,
      owner_principal: binding.canonical_owner_principal,
      signed_verdict_type: binding.canonical_signed_verdict_type,
      implementation_digest: binding.implementation_digest,
      trust_epoch: binding.trust_epoch,
      artifact_digest: binding.implementation_digest,
      proof_generation: 1,
      verdict: options.unsatisfiedProofRef === ref ? "unsatisfied" : "satisfied",
      observed_at: iso(now - 1_000),
      expires_at: stale ? iso(now - 100) : iso(now + 10 * 60_000),
    };
    payload.dependency_proofs.push(signedEnvelope({
      domain: INSTRUMENT_CAPABILITY_PROOF_DOMAIN,
      payload: proofPayload,
      registry: signerRegistry,
      keyId: `signer-key:proof-${proofRefs.indexOf(ref) + 1}`,
      trustEpoch: binding.trust_epoch,
      privateKey: proofKeys.get(ref).privateKey,
    }));
  }
  if (options.forkProofRef) {
    const proof = payload.dependency_proofs[proofRefs.indexOf(options.forkProofRef)];
    payload.dependency_proofs.push(proof);
  }
  const evidenceEnvelope = signedEnvelope({
    domain: INSTRUMENT_CAPABILITY_EVIDENCE_DOMAIN,
    payload,
    registry: signerRegistry,
    keyId: "signer-key:ph-i1-index",
    trustEpoch: 5,
    privateKey: evidenceKey.privateKey,
  });
  const port = createInstrumentCapabilityIndexPort({
    version: 1,
    mode: "conformance",
    bindings: [{
      manifest,
      signer_registry: signerRegistry,
      evidence_envelope: evidenceEnvelope,
      trusted_clock_port: signedClock(now, options.suffix || "default"),
      inventory_checkpoint: null,
    }],
  });
  return {
    now,
    executedRegistry,
    manifest,
    signerRegistry,
    evidenceEnvelope,
    evidenceKey,
    proofKeys,
    port,
    predicateProjection,
  };
}

function query(fixture, overrides = {}) {
  return queryInstrumentCapabilityIndexPort(fixture.port, {
    target_domain: fixture.evidenceEnvelope.payload.target_domain,
    instrument_ref: fixture.evidenceEnvelope.payload.instrument_ref,
    ...overrides,
  });
}

test("Chameleon semantics compile all variants behind a provider-neutral public index", () => {
  const fixture = chameleonFixture({ suffix: "compile" });
  assert.equal(fixture.manifest.variant_count, 112);
  assert.equal(fixture.manifest.proof_contract_count, 24);
  assert.equal(fixture.predicateProjection.rejected_command_count, 0);
  const result = query(fixture, { operation_id: "instrument.inventory" });
  assert.equal(result.total_matched, 1);
  assert.equal(result.records[0].requirements_status, "satisfied");
  assert.equal(result.records[0].availability, "unavailable");
  assert.deepEqual(result.records[0].unavailable_reason_codes, [
    "current_inventory_checkpoint_missing",
    "production_clock_not_qualified",
    "production_trust_not_enrolled",
  ]);
  const serialized = JSON.stringify(result);
  // The command codes are word-anchored so they match a leaked code and not a
  // coincidence inside a digest. Unanchored, this failed whenever a
  // content-derived digest happened to contain the digits — CI hit
  // "instrument-capability:79d3a63(1017)f2f5..." and reported a provider leak
  // that was not there. The vendor and upstream terms need no anchor: they
  // cannot occur in hex.
  assert.doesNotMatch(
    serialized,
    /chameleon|command:|upstream|provider_capability|signature|proof-|\b(?:1000|1017|1033)\b/iu,
  );
  assert.doesNotMatch(serialized, /"[a-z0-9_]*digest"/iu);
  assert.equal(serialized.includes(fixture.manifest.semantic_manifest_digest), false);
  assert.equal(serialized.includes(fixture.manifest.provider_descriptor_digest), false);
});

test("unknown commands and firmware-only claims cannot enable exact command predicates", () => {
  const projected = projectChameleonReportedCommands([65535]);
  assert.deepEqual(projected.reported_device_predicate_digests, []);
  assert.equal(projected.rejected_command_count, 1);
  const fixture = chameleonFixture({
    suffix: "firmware-only",
    reportedCommands: [65535],
    assuranceClaims: {
      identity_enrollment: "hardware_bound",
      firmware_provenance: "hardware_attested",
      command_surface_conformance: "conformance_tested",
      transport_trust: "hardware_attested",
    },
  });
  const result = query(fixture, { operation_id: "protocol.discover" });
  assert.equal(result.records[0].requirements_status, "unsatisfied");
  assert.equal(result.records[0].unavailable_reason_codes.includes("missing_device_predicate"), true);
});

test("incomparable assurance, unresolved any-of groups, and exact selector drift fail closed", () => {
  const incomparable = chameleonFixture({
    suffix: "incomparable",
    reportedCommands: [2000],
    assuranceClaims: {
      identity_enrollment: "not_applicable",
      firmware_provenance: "operator_pinned",
      command_surface_conformance: "manifest_intersected",
      transport_trust: "operator_provisioned",
    },
  });
  const discovery = query(incomparable, { operation_id: "protocol.discover" });
  assert.equal(discovery.records[0].requirements_status, "unsatisfied");
  assert.equal(discovery.records[0].unavailable_reason_codes.includes("assurance_not_satisfied"), true);

  const unresolved = chameleonFixture({
    suffix: "unresolved-any",
    proofRefs: ["compiler:desfire_enumerate_v1"],
    assuranceClaims: {
      identity_enrollment: "operator_enrolled",
      firmware_provenance: "operator_pinned",
      command_surface_conformance: "manifest_intersected",
      transport_trust: "operator_provisioned",
    },
  });
  const desfire = query(unresolved, {
    operation_id: "protocol.compiled_exchange",
    technique_id: "application.enumerate",
  });
  assert.equal(desfire.records[0].unavailable_reason_codes.includes("unresolved_alternative"), true);
  assert.throws(
    () => query(unresolved, { operation_id: "protocol.compiled_exchange", technique_id: "credential.replay" }),
    (error) => error.code === "instrument_capability_query_contract_mismatch",
  );
  assert.throws(
    () => query(unresolved, { parameter_selector_id: "invented_selector" }),
    (error) => error.code === "instrument_capability_query_contract_mismatch",
  );
  assert.throws(
    () => query(unresolved, { limit: MAX_QUERY_LIMIT + 1 }),
    /safe integer/u,
  );
});

test("stale, revoked, forked, substituted, and type-confused proof evidence is rejected", () => {
  assert.throws(
    () => query(chameleonFixture({
      suffix: "stale-proof",
      proofRefs: ["conformance:chameleon_frame_codec_v1"],
      staleProofRef: "conformance:chameleon_frame_codec_v1",
    }), { operation_id: "provider.frame_encode" }),
    /proof.*stale|dependency_proofs.*stale/iu,
  );
  assert.throws(
    () => query(chameleonFixture({
      suffix: "revoked-proof",
      proofRefs: ["conformance:chameleon_frame_codec_v1"],
      revokedProofRef: "conformance:chameleon_frame_codec_v1",
    }), { operation_id: "provider.frame_encode" }),
    /not enrolled/iu,
  );
  assert.throws(
    () => query(chameleonFixture({
      suffix: "forked-proof",
      proofRefs: ["conformance:chameleon_frame_codec_v1"],
      forkProofRef: "conformance:chameleon_frame_codec_v1",
    }), { operation_id: "provider.frame_encode" }),
    /fork or duplicate/iu,
  );

  const fixture = chameleonFixture({
    suffix: "substitution",
    proofRefs: [
      "conformance:chameleon_frame_codec_v1",
      "transport:ble_nus_v1",
    ],
  });
  const alteredPayload = structuredClone(fixture.evidenceEnvelope.payload);
  const alteredProofPayload = {
    ...alteredPayload.dependency_proofs[0].payload,
    canonical_identity_digest:
      alteredPayload.dependency_proofs[1].payload.canonical_identity_digest,
  };
  alteredPayload.dependency_proofs[0] = signedEnvelope({
    domain: INSTRUMENT_CAPABILITY_PROOF_DOMAIN,
    payload: alteredProofPayload,
    registry: fixture.signerRegistry,
    keyId: "signer-key:proof-1",
    trustEpoch: 3,
    privateKey: fixture.proofKeys.get("conformance:chameleon_frame_codec_v1").privateKey,
  });
  const altered = signedEnvelope({
    domain: INSTRUMENT_CAPABILITY_EVIDENCE_DOMAIN,
    payload: alteredPayload,
    registry: fixture.signerRegistry,
    keyId: "signer-key:ph-i1-index",
    trustEpoch: 5,
    privateKey: fixture.evidenceKey.privateKey,
  });
  const alteredPort = createInstrumentCapabilityIndexPort({
    version: 1,
    mode: "conformance",
    bindings: [{
      manifest: fixture.manifest,
      signer_registry: fixture.signerRegistry,
      evidence_envelope: altered,
      trusted_clock_port: signedClock(fixture.now, "substitution-altered"),
      inventory_checkpoint: null,
    }],
  });
  assert.throws(
    () => queryInstrumentCapabilityIndexPort(alteredPort, {
      target_domain: alteredPayload.target_domain,
      instrument_ref: alteredPayload.instrument_ref,
    }),
    /canonical_identity_digest.*drifted from the closed proof contract/iu,
  );
});

test("proof identity canonicalization is injective and domain-separated for reviewed spellings", () => {
  const now = Date.now();
  const registry = createChameleonCapabilityExecutedEvidenceRegistry({
    attested_at: iso(now - 1_000),
    expires_at: iso(now + 60_000),
    trust_epoch: 3,
  });
  const compiler = chameleonCapabilityProofSignerBinding("compiler:desfire_auth_probe_v1", registry);
  const conformance = chameleonCapabilityProofSignerBinding(
    "conformance:chameleon_frame_codec_v1",
    registry,
  );
  const transport = chameleonCapabilityProofSignerBinding("transport:ble_nus_v1", registry);
  for (const pair of [[compiler, conformance], [compiler, transport], [conformance, transport]]) {
    assert.notEqual(pair[0].dependency_ref_digest, pair[1].dependency_ref_digest);
    assert.notEqual(pair[0].canonical_identity_digest, pair[1].canonical_identity_digest);
    assert.notEqual(pair[0].executed_provider_id, pair[1].executed_provider_id);
    assert.notEqual(pair[0].canonical_owner_principal, pair[0].canonical_signed_verdict_type);
  }
  assert.throws(
    () => chameleonCapabilityProofSignerBinding("compiler:UPPERCASE", registry),
    /not registered|grammar/iu,
  );
});

function orthogonalFixture(options = {}) {
  const now = Date.now();
  const provider = createDeterministicProviderFixture();
  const executedRegistry = buildExecutedEvidenceRegistry({
    source_adapters: [],
    context_resolvers: [],
    replay_executors: [],
    verifier_templates: [],
    dependency_proof_providers: [],
  });
  const writeOperation = provider.operationRegistry.get("representation.write");
  const predicateDigest = digest("orthogonal-device-predicate");
  const satisfaction = {
    identity_enrollment: {
      not_required: ["not_required"],
      enrolled: ["not_required", "enrolled"],
      not_applicable: ["not_required", "not_applicable"],
    },
    firmware_provenance: {
      not_required: ["not_required"],
      attested: ["not_required", "attested"],
      not_applicable: ["not_required", "not_applicable"],
    },
    command_surface_conformance: {
      not_required: ["not_required"],
      tested: ["not_required", "tested"],
      not_applicable: ["not_required", "not_applicable"],
    },
    transport_trust: {
      not_required: ["not_required"],
      authenticated: ["not_required", "authenticated"],
      not_applicable: ["not_required", "not_applicable"],
    },
  };
  const profile = {
    identity_enrollment: "enrolled",
    firmware_provenance: "attested",
    command_surface_conformance: "tested",
    transport_trust: "authenticated",
  };
  const manifest = defineInstrumentCapabilitySemanticManifest({
    version: 1,
    provider_descriptor: provider.descriptor,
    semantic_manifest_digest: digest("orthogonal-semantic-manifest"),
    assurance_profile_registry_digest: hashCanonicalJson({ full: profile }),
    assurance_satisfaction_registry_digest: hashCanonicalJson(satisfaction),
    dependency_proof_registry_digest: hashCanonicalJson({}),
    assurance_profiles: { full: profile },
    assurance_satisfaction: satisfaction,
    proof_contracts: [],
    variants: [{
      variant_ref: `capability-variant:${digest("orthogonal-write-variant")}`,
      parameter_selector_id: "bounded_write",
      disposition: "planned",
      reason_code: "orthogonal_test_provider",
      operation_bindings: [{
        operation_id: writeOperation.operation_id,
        operation_digest: writeOperation.operation_digest,
        operation_authority: "provider_abi",
        minimum_assurance_profile_id: "full",
        ...(options.operationBindingOverrides || {}),
      }],
      technique_bindings: [{
        technique_id: "credential.clone_to_media",
        technique_digest: digest("orthogonal-technique"),
      }],
      effect_profile_refs: [`effect-profile:${digest("orthogonal-effect")}`],
      formula: {
        all_of: [{ kind: "device_predicate", predicate_digest: predicateDigest }],
        any_of: [],
      },
      provider_variant_digest: digest("orthogonal-provider-variant"),
    }],
  }, executedRegistry);
  const evidenceKey = crypto.generateKeyPairSync("ed25519");
  const signerRegistry = buildInstrumentCapabilitySignerRegistry({
    version: 1,
    registry_id: "orthogonal_signers",
    entries: [{
      key_id: "signer-key:orthogonal-index",
      purpose: "index_evidence",
      owner_principal: "principal:orthogonal-index",
      signed_verdict_type: "instrument_capability_index_v1",
      trust_epoch: 5,
      authority_epoch: 7,
      revocation_generation: 2,
      disposition: "enrolled",
      binding_digest: manifest.instrument_capability_manifest_digest,
      valid_from: iso(now - 60_000),
      expires_at: iso(now + 20 * 60_000),
      public_key_pem: evidenceKey.publicKey.export({ type: "spki", format: "pem" }),
    }],
  }, executedRegistry);
  const payload = {
    version: 1,
    target_domain: "orthogonal-physical.example.test",
    session_nucleus_hash: digest("orthogonal-session"),
    physical_scope_axis_digest: digest("orthogonal-scope"),
    instrument_ref: "instrument:orthogonal-provider-1",
    enrollment_candidate_ref: "enrollment-candidate:orthogonal-1",
    provider_id: manifest.provider_id,
    provider_descriptor_digest: manifest.provider_descriptor_digest,
    provider_binary_digest: digest("orthogonal-binary"),
    transport_digest: digest("orthogonal-transport"),
    bootstrap_manifest_digest: digest("orthogonal-bootstrap"),
    connection_generation: 1,
    semantic_manifest_digest: manifest.semantic_manifest_digest,
    operation_registry_digest: manifest.operation_registry_digest,
    capabilities_digest: manifest.capabilities_digest,
    inventory_checkpoint_ref: `physical-inventory-checkpoint:${digest("orthogonal-checkpoint")}`,
    inventory_checkpoint_digest: digest("orthogonal-checkpoint"),
    inventory_projection_digest: digest("orthogonal-inventory-projection"),
    evidence_generation: 1,
    previous_evidence_digest: null,
    authority_epoch: 7,
    revocation_generation: 2,
    authority_resolution_digest: digest("orthogonal-authority"),
    observed_at: iso(now - 1_000),
    expires_at: iso(now + 10 * 60_000),
    assurance_claims: null,
    reported_device_predicate_digests: [predicateDigest],
    alternative_selections: [],
    dependency_proofs: [],
  };
  payload.assurance_claims = assuranceClaims(profile, payload, manifest);
  const evidenceEnvelope = signedEnvelope({
    domain: INSTRUMENT_CAPABILITY_EVIDENCE_DOMAIN,
    payload,
    registry: signerRegistry,
    keyId: "signer-key:orthogonal-index",
    trustEpoch: 5,
    privateKey: evidenceKey.privateKey,
  });
  const port = createInstrumentCapabilityIndexPort({
    version: 1,
    mode: "conformance",
    bindings: [{
      manifest,
      signer_registry: signerRegistry,
      evidence_envelope: evidenceEnvelope,
      trusted_clock_port: signedClock(now, "orthogonal"),
      inventory_checkpoint: null,
    }],
  });
  return { manifest, evidenceEnvelope, port };
}

test("an orthogonal deterministic provider uses the same index and query with no provider branch", () => {
  assert.throws(
    () => orthogonalFixture({ operationBindingOverrides: { operation_digest: digest("abi-drift") } }),
    /provider_abi operation is absent or digest-drifted/,
  );
  assert.throws(
    () => orthogonalFixture({ operationBindingOverrides: { operation_authority: "semantic_manifest" } }),
    /semantic operation collides with a provider_abi operation ID/,
  );
  const fixture = orthogonalFixture();
  const result = queryInstrumentCapabilityIndexPort(fixture.port, {
    target_domain: fixture.evidenceEnvelope.payload.target_domain,
    instrument_ref: fixture.evidenceEnvelope.payload.instrument_ref,
    operation_id: "representation.write",
    technique_id: "credential.clone_to_media",
    parameter_selector_id: "bounded_write",
  });
  assert.equal(result.total_matched, 1);
  assert.equal(result.records[0].requirements_status, "satisfied");
  const source = fs.readFileSync(path.join(__dirname, "..", "mcp", "lib", "instrument-capabilities.js"), "utf8");
  assert.doesNotMatch(source, /chameleon|command_id|reported_command|firmware_version/iu);
});

test("the installed MCP query is bounded, registry-shaped, and fail-closed without production trust", () => {
  assert.equal(queryTool.name, "bob_query_instrument_capabilities");
  assert.equal(queryTool.inputSchema.additionalProperties, false);
  assert.equal(queryTool.inputSchema.properties.limit.maximum, MAX_QUERY_LIMIT);
  assert.throws(
    () => queryTool.handler({
      target_domain: "no-index.example.test",
      instrument_ref: "instrument:none",
    }),
    (error) => error.code === "instrument_capability_runtime_unconfigured",
  );
  const fixture = chameleonFixture({ suffix: "installed-tool" });
  assert.throws(
    () => installInstrumentCapabilityIndexPort(fixture.port),
    /only a production-qualified index port/,
  );
  assert.throws(
    () => installInstrumentCapabilityIndexPort(fixture.port, { test_only: true }),
    /accepts only a branded production port/,
  );
  const bindingBase = {
    manifest: fixture.manifest,
    signer_registry: fixture.signerRegistry,
    trusted_clock_port: signedClock(fixture.now, "hostile-envelope"),
    inventory_checkpoint: null,
  };
  let hostileTrapCalls = 0;
  const proxiedEnvelope = new Proxy(fixture.evidenceEnvelope, {
    get() {
      hostileTrapCalls += 1;
      throw new Error("hostile evidence proxy trap must not run");
    },
  });
  assert.throws(
    () => createInstrumentCapabilityIndexPort({
      version: 1,
      mode: "conformance",
      bindings: [{ ...bindingBase, evidence_envelope: proxiedEnvelope }],
    }),
    /must be an exact plain data object/,
  );
  const accessorEnvelope = { ...fixture.evidenceEnvelope };
  Object.defineProperty(accessorEnvelope, "payload", {
    enumerable: true,
    get() {
      hostileTrapCalls += 1;
      throw new Error("hostile evidence accessor must not run");
    },
  });
  assert.throws(
    () => createInstrumentCapabilityIndexPort({
      version: 1,
      mode: "conformance",
      bindings: [{ ...bindingBase, evidence_envelope: accessorEnvelope }],
    }),
    /payload must be an enumerable data property/,
  );
  assert.equal(hostileTrapCalls, 0);
  const first = queryInstrumentCapabilityIndexPort(fixture.port, {
    target_domain: fixture.evidenceEnvelope.payload.target_domain,
    instrument_ref: fixture.evidenceEnvelope.payload.instrument_ref,
    limit: 1,
  });
  assert.equal(first.returned_count, 1);
  assert.match(first.next_cursor, /^capability-cursor:v1:[a-f0-9]{64}:1$/u);
  const second = queryInstrumentCapabilityIndexPort(fixture.port, {
    target_domain: fixture.evidenceEnvelope.payload.target_domain,
    instrument_ref: fixture.evidenceEnvelope.payload.instrument_ref,
    limit: 1,
    cursor: first.next_cursor,
  });
  assert.equal(second.returned_count, 1);
  assert.notEqual(second.records[0].capability_ref, first.records[0].capability_ref);
});
