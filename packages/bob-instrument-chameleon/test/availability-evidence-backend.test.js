"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");

const backend = require("../lib/availability-evidence-backend.js");
const operations = require("../lib/operations.js");
const {
  CHAMELEON_AVAILABILITY_BACKEND_VERSION,
  CHAMELEON_SEMANTIC_DIGESTS,
  CHAMELEON_SEMANTIC_MANIFEST,
  CHAMELEON_V220_CODEC_PROFILE,
  CHAMELEON_V220_SOURCE_PROFILE,
  buildChameleonAvailabilityVariantQualification,
  dependencyProofContract,
  getChameleonAvailabilityVariant,
  resolveChameleonAvailability,
  resolveProductionShapedChameleonAvailabilityEvidence,
} = operations;
const {
  CHAMELEON_AVAILABILITY_EVIDENCE_DOMAIN,
  CHAMELEON_AVAILABILITY_OWNER_CONTEXT_DOMAIN,
  CHAMELEON_AVAILABILITY_TRUST_DOMAIN,
  MAX_EVIDENCE_LIFETIME_MS,
  MAX_TRUST_LIFETIME_MS,
  assertChameleonAvailabilityEvidenceBackendPort,
  assertChameleonAvailabilityEvidenceBackendProjection,
  chameleonAvailabilityEvidenceIdentityDigest,
  chameleonAvailabilityEvidenceSigningMessage,
  chameleonAvailabilityTrustSigningMessage,
  createChameleonAvailabilityEvidenceBackendPort,
  resolveChameleonAvailabilityEvidenceBackend,
} = backend;
const {
  openProductionPhysicalMonotonicOwner,
  readPhysicalMonotonicOwnerState,
} = require("../../../mcp/lib/physical-monotonic-owner.js");
const {
  TRUSTED_CLOCK_MAPPING_DOMAIN,
  physicalClockMappingSigningMessage,
  publicKeyDigest: physicalClockPublicKeyDigest,
} = require("../../../mcp/lib/physical-trusted-clock.js");
const {
  PHYSICAL_TRUSTED_CLOCK_AUTHORITY_BUNDLE_DOMAIN,
  PHYSICAL_TRUSTED_CLOCK_AUTHORITY_FILE,
  PHYSICAL_TRUSTED_CLOCK_TRUST_DOMAIN,
  openProductionPhysicalTrustedClockPort,
  physicalClockTrustSigningMessage,
} = require("../../../mcp/lib/physical-trusted-clock-store.js");
const { sessionNucleusFromState } = require("../../../mcp/lib/governance-contracts.js");
const { sessionDir } = require("../../../mcp/lib/paths.js");
const { normalizePhysicalScopeNucleusAxis } = require("../../../mcp/lib/physical-scope-axis.js");
const { buildInitialSessionState } = require("../../../mcp/lib/session-state-contracts.js");
const { writeSessionStateDocument } = require("../../../mcp/lib/session-state-store.js");
const {
  SANDBOX_AGENT_UID_ENV,
  SANDBOX_ISOLATION_ACK_ENV,
  SANDBOX_ISOLATION_ACK_TOKEN,
  SANDBOX_SIGNER_UID_ENV,
} = require("../../../mcp/lib/sandbox-isolation-attest.js");
const { hashCanonicalJson } = require("../../../mcp/lib/verification-contracts.js");

const CLOCK_OWNER_CONTEXT = "hacker-bob/physical-trusted-clock-high-water/v1";
const DEPENDENCY_PROOF_BINDING_FIELDS = Object.freeze([
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
]);

function digest(label) {
  return crypto.createHash("sha256").update(JSON.stringify({ label })).digest("hex");
}

function hashJson(value) {
  return crypto.createHash("sha256").update(JSON.stringify(value)).digest("hex");
}

function iso(milliseconds) {
  return new Date(milliseconds).toISOString();
}

function monotonicMs() {
  return Number(process.hrtime.bigint() / 1_000_000n);
}

function spki(key) {
  return key.export({ type: "spki", format: "der" }).toString("base64url");
}

function keyDigest(key) {
  return crypto.createHash("sha256").update(
    key.export({ type: "spki", format: "der" }),
  ).digest("hex");
}

function installPhysicalSession(domain) {
  const physicalScope = normalizePhysicalScopeNucleusAxis({
    version: 1,
    physical_enabled: true,
    policy_version: 1,
    policy_id: "chameleon_availability_backend_fixture",
    policy_digest: digest(`policy:${domain}`),
    projection_version: 1,
    projection_digest: digest(`projection:${domain}`),
    provenance_digest: digest(`provenance:${domain}`),
    compatibility_digest: digest(`compatibility:${domain}`),
    transition_receipt_registry_digest: digest(`transition:${domain}`),
    authority_epoch: 1,
    revocation_generation: 0,
  });
  const directory = sessionDir(domain);
  fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
  fs.chmodSync(directory, 0o700);
  const state = buildInitialSessionState(domain, `https://${domain}`, {
    physicalScope,
    egressProfile: {
      name: "default",
      region: null,
      proxy_configured: false,
      egress_profile_identity_hash: null,
      egress_profile_identity_version: null,
      egress_profile_identity_source: {
        proxy_url_source: "none",
        proxy_env_var: null,
        proxy_url_redacted: null,
        resolved_proxy: null,
      },
    },
  });
  writeSessionStateDocument(domain, {}, state);
  const nucleus = sessionNucleusFromState(state);
  fs.writeFileSync(
    path.join(directory, "session-nucleus.json"),
    `${JSON.stringify(nucleus, null, 2)}\n`,
    { mode: 0o600 },
  );
  return nucleus;
}

function signClockMapping(signer, payload) {
  const payloadDigest = hashCanonicalJson(payload);
  const signature = crypto.sign(
    null,
    physicalClockMappingSigningMessage(payloadDigest),
    signer.privateKey,
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

function signClockTrust(root, payload) {
  const payloadDigest = hashCanonicalJson(payload);
  const signature = crypto.sign(
    null,
    physicalClockTrustSigningMessage(payloadDigest),
    root.privateKey,
  ).toString("base64url");
  const basis = {
    version: 1,
    domain: PHYSICAL_TRUSTED_CLOCK_TRUST_DOMAIN,
    payload,
    payload_digest: payloadDigest,
    scheme: "ed25519",
    signature,
    trust_root_public_key_spki_base64url: spki(root.publicKey),
  };
  return { ...basis, trust_statement_digest: hashCanonicalJson(basis) };
}

function installClockAuthority(fixture) {
  const signerDigest = physicalClockPublicKeyDigest(fixture.clockSigner.publicKey);
  const notBefore = iso(fixture.referenceUtcMs - 60_000);
  const expiresAt = iso(fixture.referenceUtcMs + 20 * 60_000);
  const mapping = signClockMapping(fixture.clockSigner, {
    version: 1,
    clock_id: fixture.clockId,
    monotonic_epoch_id: fixture.monotonicEpochId,
    mapping_generation: 1,
    reference_monotonic_ms: fixture.referenceMonotonicMs,
    reference_utc: iso(fixture.referenceUtcMs),
    max_uncertainty_ms: 5,
    not_before: notBefore,
    expires_at: expiresAt,
    trust_root_epoch: 1,
    authority_epoch: 1,
    revocation_generation: 0,
    signer_key_id: "clock-key:chameleon-availability-fixture",
    signer_public_key_digest: signerDigest,
  });
  const trust = signClockTrust(fixture.clockTrustRoot, {
    version: 1,
    target_domain: fixture.domain,
    session_nucleus_hash: fixture.nucleus.nucleus_hash,
    trusted: true,
    revoked: false,
    clock_id: fixture.clockId,
    monotonic_epoch_id: fixture.monotonicEpochId,
    current_mapping_generation: 1,
    current_signed_mapping_digest: mapping.signed_mapping_digest,
    trust_root_epoch: 1,
    authority_epoch: 1,
    revocation_generation: 0,
    signer_key_id: "clock-key:chameleon-availability-fixture",
    signer_public_key_digest: signerDigest,
    signer_public_key_spki_base64url: spki(fixture.clockSigner.publicKey),
    trust_root_key_id: "clock-trust-root:chameleon-availability-fixture",
    trust_root_public_key_digest: physicalClockPublicKeyDigest(
      fixture.clockTrustRoot.publicKey,
    ),
    not_before: notBefore,
    expires_at: expiresAt,
  });
  const basis = {
    version: 1,
    domain: PHYSICAL_TRUSTED_CLOCK_AUTHORITY_BUNDLE_DOMAIN,
    signed_mapping: mapping,
    signed_trust: trust,
  };
  fs.writeFileSync(
    path.join(fixture.clockAuthorityRoot, PHYSICAL_TRUSTED_CLOCK_AUTHORITY_FILE),
    `${JSON.stringify({ ...basis, bundle_digest: hashCanonicalJson(basis) })}\n`,
    { mode: 0o600 },
  );
}

function setup(t, label) {
  const uid = typeof process.getuid === "function" ? process.getuid() : null;
  if (uid == null || uid === 0) throw new Error("availability backend fixture requires non-root uid");
  const prior = Object.fromEntries([
    ["HOME", process.env.HOME],
    [SANDBOX_ISOLATION_ACK_ENV, process.env[SANDBOX_ISOLATION_ACK_ENV]],
    [SANDBOX_SIGNER_UID_ENV, process.env[SANDBOX_SIGNER_UID_ENV]],
    [SANDBOX_AGENT_UID_ENV, process.env[SANDBOX_AGENT_UID_ENV]],
  ]);
  const roots = {
    home: fs.mkdtempSync(path.join(os.tmpdir(), `bob-availability-home-${label}-`)),
    clockOwnerRoot: fs.mkdtempSync(path.join(os.tmpdir(), `bob-availability-clock-owner-${label}-`)),
    clockAuthorityRoot: fs.mkdtempSync(path.join(os.tmpdir(), `bob-availability-clock-authority-${label}-`)),
    availabilityOwnerRoot: fs.mkdtempSync(path.join(os.tmpdir(), `bob-availability-owner-${label}-`)),
  };
  for (const root of Object.values(roots)) fs.chmodSync(root, 0o700);
  process.env.HOME = roots.home;
  process.env[SANDBOX_ISOLATION_ACK_ENV] = SANDBOX_ISOLATION_ACK_TOKEN;
  process.env[SANDBOX_SIGNER_UID_ENV] = String(uid);
  process.env[SANDBOX_AGENT_UID_ENV] = String(uid + 1);
  t.after(() => {
    for (const [name, value] of Object.entries(prior)) {
      if (value === undefined) delete process.env[name];
      else process.env[name] = value;
    }
    for (const root of Object.values(roots)) {
      fs.rmSync(root, { recursive: true, force: true });
    }
  });
  const suffix = crypto.randomBytes(5).toString("hex");
  const domain = `availability-${label}-${suffix}.example.com`;
  const nucleus = installPhysicalSession(domain);
  const fixture = {
    ...roots,
    domain,
    nucleus,
    clockId: `physical-clock:chameleon-availability-${suffix}`,
    monotonicEpochId: digest(`availability-clock-epoch:${suffix}`),
    referenceMonotonicMs: monotonicMs(),
    referenceUtcMs: Date.now(),
    clockSigner: crypto.generateKeyPairSync("ed25519"),
    clockTrustRoot: crypto.generateKeyPairSync("ed25519"),
    availabilityTrustRoot: crypto.generateKeyPairSync("ed25519"),
    evidenceSigner: crypto.generateKeyPairSync("ed25519"),
    availabilityTrustRootKeyId: `availability-trust-root:${suffix}`,
    evidenceSignerKeyId: `availability-key:${suffix}`,
    evidenceOwnerPrincipal: `principal:availability-issuer-${suffix}`,
  };
  installClockAuthority(fixture);
  fixture.clockOwner = openProductionPhysicalMonotonicOwner({
    version: 1,
    target_domain: domain,
    session_nucleus_hash: nucleus.nucleus_hash,
    external_owner_root: roots.clockOwnerRoot,
    context_domain: CLOCK_OWNER_CONTEXT,
  });
  fixture.clock = openProductionPhysicalTrustedClockPort({
    version: 1,
    target_domain: domain,
    session_nucleus_hash: nucleus.nucleus_hash,
    port_id: `availability_clock_${suffix}`,
    clock_id: fixture.clockId,
    uncertainty_ceiling_ms: 50,
    authority_root: roots.clockAuthorityRoot,
    monotonic_head_owner: fixture.clockOwner,
  });
  fixture.availabilityOwner = openProductionPhysicalMonotonicOwner({
    version: 1,
    target_domain: domain,
    session_nucleus_hash: nucleus.nucleus_hash,
    external_owner_root: roots.availabilityOwnerRoot,
    context_domain: CHAMELEON_AVAILABILITY_OWNER_CONTEXT_DOMAIN,
  });
  fixture.backendPort = createChameleonAvailabilityEvidenceBackendPort({
    version: 2,
    port_id: `availability_backend_${suffix}`,
    target_domain: domain,
    session_nucleus_hash: nucleus.nucleus_hash,
    trust_root_key_id: fixture.availabilityTrustRootKeyId,
    trust_root_public_key_spki_base64url: spki(fixture.availabilityTrustRoot.publicKey),
    trusted_clock_port: fixture.clock,
    monotonic_owner_port: fixture.availabilityOwner,
  });
  return fixture;
}

function signAvailabilityTrust(fixture, options = {}) {
  const notBeforeMs = options.not_before_ms == null
    ? fixture.referenceUtcMs - 60_000 : options.not_before_ms;
  const expiresAtMs = options.expires_at_ms == null
    ? fixture.referenceUtcMs + 10 * 60_000 : options.expires_at_ms;
  const signer = {
    key_id: fixture.evidenceSignerKeyId,
    owner_principal: fixture.evidenceOwnerPrincipal,
    public_key_spki_base64url: spki(fixture.evidenceSigner.publicKey),
    public_key_digest: keyDigest(fixture.evidenceSigner.publicKey),
    evidence_trust_epoch: options.evidence_trust_epoch || 1,
    revocation_generation: options.signer_revocation_generation || 0,
    revoked: options.revoked === true,
    not_before: iso(notBeforeMs),
    expires_at: iso(expiresAtMs),
  };
  const payload = {
    version: 2,
    target_domain: fixture.domain,
    session_nucleus_hash: fixture.nucleus.nucleus_hash,
    trust_root_key_id: fixture.availabilityTrustRootKeyId,
    trust_root_public_key_digest: keyDigest(fixture.availabilityTrustRoot.publicKey),
    trust_generation: options.trust_generation || 1,
    trust_root_epoch: options.trust_root_epoch || 1,
    revocation_generation: options.trust_revocation_generation || 0,
    not_before: iso(notBeforeMs),
    expires_at: iso(expiresAtMs),
    evidence_signers: [signer],
  };
  const payloadDigest = hashCanonicalJson(payload);
  const signature = crypto.sign(
    null,
    chameleonAvailabilityTrustSigningMessage(payloadDigest),
    fixture.availabilityTrustRoot.privateKey,
  ).toString("base64url");
  const basis = {
    version: 2,
    domain: CHAMELEON_AVAILABILITY_TRUST_DOMAIN,
    payload,
    payload_digest: payloadDigest,
    scheme: "ed25519",
    signature,
  };
  return { ...basis, trust_statement_digest: hashCanonicalJson(basis) };
}

function inventoryDependencyBindingDigest(reportedCommandIds) {
  const variant = getChameleonAvailabilityVariant("CU-CORE-INVENTORY", "identity_version");
  const reported = new Set(reportedCommandIds);
  return hashJson({
    all_of: variant.all_of.map((dependencyRef) => {
      const commandId = Number(dependencyRef.slice("command:".length));
      return {
        dependency_ref: dependencyRef,
        dependency_kind: "command",
        reported: reported.has(commandId),
        compiled: CHAMELEON_V220_CODEC_PROFILE.command_ids.includes(commandId),
        satisfied: reported.has(commandId)
          && CHAMELEON_V220_CODEC_PROFILE.command_ids.includes(commandId),
      };
    }),
    any_of: [],
    selected_alternatives: [],
  });
}

function signedDependencyProof(fixture, request, overrides = {}) {
  const dependencyRef = "conformance:chameleon_frame_codec_v1";
  const contract = dependencyProofContract(dependencyRef);
  const basis = {
    ...Object.fromEntries(
      DEPENDENCY_PROOF_BINDING_FIELDS.map((field) => [field, request[field]]),
    ),
    dependency_ref: dependencyRef,
    provider_contract_digest: contract.contract_digest,
    owner_principal: contract.owner_principal,
    artifact_digest: digest("availability-dependency-proof-artifact"),
    trust_epoch: 1,
    verdict: "satisfied",
    observed_at: iso(fixture.referenceUtcMs - 60_000),
    expires_at: iso(fixture.referenceUtcMs + 5 * 60_000),
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

function signAvailabilityEvidence(fixture, options = {}) {
  const evidenceSequence = options.evidence_sequence || 1;
  const nonce = options.nonce || `availability-nonce:${digest(`nonce:${evidenceSequence}`).slice(0, 32)}`;
  const issuerPublicKeyDigest = keyDigest(fixture.evidenceSigner.publicKey);
  const identityDigest = chameleonAvailabilityEvidenceIdentityDigest({
    version: 2,
    provider_id: "chameleon_ultra",
    target_domain: fixture.domain,
    session_nucleus_hash: fixture.nucleus.nucleus_hash,
    issuer_key_id: fixture.evidenceSignerKeyId,
    issuer_public_key_digest: issuerPublicKeyDigest,
    evidence_sequence: evidenceSequence,
    nonce,
  });
  const request = {
    version: 2,
    provider_id: "chameleon_ultra",
    evidence_ref: `bob-chameleon-availability:v2:sha256:${identityDigest}`,
    target_domain: fixture.domain,
    session_nucleus_hash: fixture.nucleus.nucleus_hash,
    semantic_manifest_digest: CHAMELEON_SEMANTIC_MANIFEST.manifest_digest,
    source_profile_digest: CHAMELEON_V220_SOURCE_PROFILE.source_profile_digest,
    codec_profile_digest: CHAMELEON_V220_CODEC_PROFILE.codec_profile_digest,
    assurance_profile_registry_digest:
      CHAMELEON_SEMANTIC_DIGESTS.assurance_profile_registry_sha256,
    dependency_proof_registry_digest:
      CHAMELEON_SEMANTIC_DIGESTS.dependency_proof_provider_registry_sha256,
    inventory_projection_digest: digest("availability-inventory-projection"),
    device_identity_digest: digest("availability-device-identity"),
    custody_id: "custody:availability-fixture",
    custody_projection_digest: digest("availability-custody-projection"),
    session_id: "session:availability-fixture",
    authority_id: "authority:availability-fixture",
    authority_epoch: 3,
    revocation_generation: 1,
    authority_resolution_digest: digest("availability-authority-resolution"),
    ...(options.request_overrides || {}),
  };
  const reportedCommandIds = [...CHAMELEON_V220_CODEC_PROFILE.command_ids];
  const assuranceClaims = {
    identity_enrollment: "operator_enrolled",
    firmware_provenance: "operator_pinned",
    command_surface_conformance: "manifest_intersected",
    transport_trust: "operator_provisioned",
  };
  const dependencyProofs = options.dependency_proof_overrides == null
    ? []
    : [signedDependencyProof(fixture, request, options.dependency_proof_overrides)];
  const alternativeSelections = [];
  const qualification = buildChameleonAvailabilityVariantQualification({
    request,
    capability_id: "CU-CORE-INVENTORY",
    variant_id: "identity_version",
    dependency_binding_digest: inventoryDependencyBindingDigest(reportedCommandIds),
    reported_command_ids_digest: hashJson(reportedCommandIds),
    assurance_claims_digest: hashJson(assuranceClaims),
    dependency_proofs_digest: hashJson(dependencyProofs),
    alternative_selections_digest: hashJson(alternativeSelections),
  });
  const observedAtMs = options.observed_at_ms == null
    ? fixture.referenceUtcMs : options.observed_at_ms;
  const expiresAtMs = options.expires_at_ms == null
    ? observedAtMs + 5 * 60_000 : options.expires_at_ms;
  const observedMonotonicMs = options.observed_monotonic_ms == null
    ? fixture.referenceMonotonicMs : options.observed_monotonic_ms;
  const expiresMonotonicMs = options.expires_monotonic_ms == null
    ? observedMonotonicMs + 5 * 60_000 : options.expires_monotonic_ms;
  const payload = {
    ...request,
    evidence_identity_digest: identityDigest,
    evidence_owner_principal: fixture.evidenceOwnerPrincipal,
    evidence_artifact_digest: digest(`availability-evidence-artifact:${evidenceSequence}`),
    evidence_trust_epoch: options.evidence_trust_epoch || 1,
    issuer_key_id: fixture.evidenceSignerKeyId,
    issuer_public_key_digest: issuerPublicKeyDigest,
    issuer_revocation_generation: options.signer_revocation_generation || 0,
    authority_trust_generation: options.trust_generation || 1,
    trust_root_epoch: options.trust_root_epoch || 1,
    evidence_sequence: evidenceSequence,
    nonce,
    observed_at: iso(observedAtMs),
    expires_at: iso(expiresAtMs),
    clock_id: fixture.clockId,
    monotonic_epoch_id: fixture.monotonicEpochId,
    observed_monotonic_ms: observedMonotonicMs,
    expires_monotonic_ms: expiresMonotonicMs,
    reported_command_ids: reportedCommandIds,
    assurance_claims: assuranceClaims,
    dependency_proofs: dependencyProofs,
    variant_qualifications: options.no_qualification ? [] : [qualification],
    ...(options.payload_overrides || {}),
  };
  const payloadDigest = hashCanonicalJson(payload);
  const signature = crypto.sign(
    null,
    chameleonAvailabilityEvidenceSigningMessage(payloadDigest),
    fixture.evidenceSigner.privateKey,
  ).toString("base64url");
  const basis = {
    version: 2,
    domain: CHAMELEON_AVAILABILITY_EVIDENCE_DOMAIN,
    payload,
    payload_digest: payloadDigest,
    scheme: "ed25519",
    signature,
  };
  return {
    request,
    document: { ...basis, signed_evidence_digest: hashCanonicalJson(basis) },
  };
}

function resolveFixture(fixture, trust, evidence) {
  return resolveProductionShapedChameleonAvailabilityEvidence(fixture.backendPort, {
    version: CHAMELEON_AVAILABILITY_BACKEND_VERSION,
    request: evidence.request,
    signed_current_trust: trust,
    signed_evidence: evidence.document,
  });
}

function variantStatus(projection, capabilityId, variantId) {
  return projection.variants.find((entry) => (
    entry.capability_id === capabilityId && entry.variant_id === variantId
  ));
}

test("signed current evidence qualifies exactly one RF-off inventory variant without authority or release readiness",
  { concurrency: false }, (t) => {
    const fixture = setup(t, "positive");
    const trust = signAvailabilityTrust(fixture);
    const evidence = signAvailabilityEvidence(fixture);
    assert.equal(assertChameleonAvailabilityEvidenceBackendPort(fixture.backendPort), fixture.backendPort);
    assert.equal(fixture.backendPort.production_ready, false);
    assert.deepEqual(fixture.backendPort.production_blockers, [
      "availability_trust_root_custody_not_bob_enrolled",
      "production_restart_stable_trusted_clock_not_enrolled",
    ]);
    assert.equal(fixture.backendPort.trust_root_bob_enrolled, false);
    assert.throws(() => JSON.stringify(fixture.backendPort), /process-local private capabilities/u);

    const verified = resolveFixture(fixture, trust, evidence);
    assert.equal(verified.runtime_ready, true);
    assert.equal(verified.production_ready, false);
    assert.equal(verified.release_ready, false);
    assert.equal(verified.hil_verified, false);
    assert.equal(verified.execution_authority, false);
    assert.equal(verified.variant_qualifications.length, 1);
    assert.equal(verified.replay_receipt.idempotent, false);
    assert.equal(verified.replay_receipt.exact_durable_readback, true);
    const firstDurable = readPhysicalMonotonicOwnerState(fixture.availabilityOwner);
    assert.equal(firstDurable.claims.length, 1);
    assert.equal(firstDurable.store_sequence, verified.replay_receipt.store_sequence);

    const availability = resolveChameleonAvailability({
      version: 1,
      provider_id: "chameleon_ultra",
      evidence_projection: verified,
      alternative_selections: [],
    });
    assert.equal(availability.variants.length, 112);
    assert.equal(availability.variants.filter((entry) => entry.runtime_available).length, 1);
    assert.equal(
      availability.variants.every((entry) => !entry.evaluator_callable || entry.production_ready),
      true,
      "non-production signed availability must never expose an evaluator-callable variant",
    );
    const inventory = variantStatus(availability, "CU-CORE-INVENTORY", "identity_version");
    assert.equal(inventory.requirements_satisfied, true);
    assert.equal(inventory.evidence_qualified, true);
    assert.equal(inventory.runtime_available, true);
    assert.equal(inventory.production_ready, false);
    assert.equal(inventory.evaluator_callable, false);
    assert.equal(inventory.execution_authority, false);

    const retried = resolveFixture(fixture, trust, evidence);
    assert.equal(retried.replay_receipt.idempotent, true);
    assert.ok(retried.replay_receipt.store_sequence > verified.replay_receipt.store_sequence);
    const durable = readPhysicalMonotonicOwnerState(fixture.availabilityOwner);
    assert.equal(durable.claims.length, 1);
    assert.equal(durable.store_sequence, retried.replay_receipt.store_sequence);
    assert.ok(durable.clock_monotonic_ms >= firstDurable.clock_monotonic_ms);
    assert.ok(
      Date.parse(durable.clock_trusted_utc) >= Date.parse(firstDurable.clock_trusted_utc),
    );
    assert.ok(
      durable.clock_durable_observation_sequence
        > firstDurable.clock_durable_observation_sequence,
      "idempotent verification persists the newer clock high-water",
    );
  });

test("backend rejects lookalikes, callbacks, signature substitution, exact binding drift, and durable evidence forks",
  { concurrency: false }, (t) => {
    const fixture = setup(t, "hostile");
    const trust = signAvailabilityTrust(fixture);
    const evidence = signAvailabilityEvidence(fixture);
    assert.throws(
      () => assertChameleonAvailabilityEvidenceBackendPort({ ...fixture.backendPort }),
      /privately branded/u,
    );
    assert.throws(
      () => createChameleonAvailabilityEvidenceBackendPort({
        version: 2,
        port_id: "callback_backend",
        target_domain: fixture.domain,
        session_nucleus_hash: fixture.nucleus.nucleus_hash,
        trust_root_key_id: fixture.availabilityTrustRootKeyId,
        trust_root_public_key_spki_base64url: spki(fixture.availabilityTrustRoot.publicKey),
        trusted_clock_port: fixture.clock,
        monotonic_owner_port: fixture.availabilityOwner,
        resolve_evidence() {},
      }),
      /fields are not exact/u,
    );
    assert.throws(
      () => resolveChameleonAvailabilityEvidenceBackend({ ...fixture.backendPort }, {
        version: 2,
        request: evidence.request,
        signed_current_trust: trust,
        signed_evidence: evidence.document,
      }),
      /privately branded/u,
    );

    const badSignature = structuredClone(evidence.document);
    badSignature.signature = `${badSignature.signature.slice(0, -1)}${badSignature.signature.endsWith("A") ? "B" : "A"}`;
    assert.throws(
      () => resolveFixture(fixture, trust, { ...evidence, document: badSignature }),
      /signature.*(?:invalid|canonical)/u,
    );

    const driftedRequest = {
      ...evidence,
      request: { ...evidence.request, device_identity_digest: digest("substituted-device") },
    };
    assert.throws(
      () => resolveFixture(fixture, trust, driftedRequest),
      /device_identity_digest does not match request/u,
    );

    const first = resolveFixture(fixture, trust, evidence);
    assert.equal(first.replay_receipt.idempotent, false);
    const forkPayload = {
      ...evidence.document.payload,
      evidence_artifact_digest: digest("substituted-signed-artifact"),
    };
    const forkPayloadDigest = hashCanonicalJson(forkPayload);
    const forkSignature = crypto.sign(
      null,
      chameleonAvailabilityEvidenceSigningMessage(forkPayloadDigest),
      fixture.evidenceSigner.privateKey,
    ).toString("base64url");
    const forkBasis = {
      version: 2,
      domain: CHAMELEON_AVAILABILITY_EVIDENCE_DOMAIN,
      payload: forkPayload,
      payload_digest: forkPayloadDigest,
      scheme: "ed25519",
      signature: forkSignature,
    };
    const fork = {
      ...evidence,
      document: { ...forkBasis, signed_evidence_digest: hashCanonicalJson(forkBasis) },
    };
    assert.throws(() => resolveFixture(fixture, trust, fork), /conflicts with durable claim/u);

    const backendProjection = resolveChameleonAvailabilityEvidenceBackend(
      fixture.backendPort,
      {
        version: 2,
        request: signAvailabilityEvidence(fixture, {
          evidence_sequence: 2,
          nonce: `availability-nonce:${digest("backend-projection").slice(0, 32)}`,
        }).request,
        signed_current_trust: trust,
        signed_evidence: signAvailabilityEvidence(fixture, {
          evidence_sequence: 2,
          nonce: `availability-nonce:${digest("backend-projection").slice(0, 32)}`,
        }).document,
      },
    );
    assert.equal(
      assertChameleonAvailabilityEvidenceBackendProjection(backendProjection),
      backendProjection,
    );
    assert.throws(
      () => assertChameleonAvailabilityEvidenceBackendProjection({ ...backendProjection }),
      /resolver-issued privately branded/u,
    );
  });

test("current signer revocation, trust rollback, replayed sequence, and replayed nonce fail closed",
  { concurrency: false }, (t) => {
    const revokedFixture = setup(t, "revoked");
    const revokedTrust = signAvailabilityTrust(revokedFixture, { revoked: true });
    const revokedEvidence = signAvailabilityEvidence(revokedFixture);
    assert.throws(
      () => resolveFixture(revokedFixture, revokedTrust, revokedEvidence),
      /signer is revoked/u,
    );

    const fixture = setup(t, "rollback");
    const trust2 = signAvailabilityTrust(fixture, { trust_generation: 2 });
    const evidence2 = signAvailabilityEvidence(fixture, {
      evidence_sequence: 2,
      trust_generation: 2,
      nonce: `availability-nonce:${digest("trust-gen-2").slice(0, 32)}`,
    });
    resolveFixture(fixture, trust2, evidence2);

    const trust1 = signAvailabilityTrust(fixture, { trust_generation: 1 });
    const evidence3OldTrust = signAvailabilityEvidence(fixture, {
      evidence_sequence: 3,
      trust_generation: 1,
      nonce: `availability-nonce:${digest("trust-gen-1").slice(0, 32)}`,
    });
    assert.throws(
      () => resolveFixture(fixture, trust1, evidence3OldTrust),
      /trust high-water moved backwards/u,
    );

    const replaySequence = signAvailabilityEvidence(fixture, {
      evidence_sequence: 2,
      trust_generation: 2,
      nonce: `availability-nonce:${digest("different-nonce-same-sequence").slice(0, 32)}`,
    });
    assert.throws(
      () => resolveFixture(fixture, trust2, replaySequence),
      /sequence was replayed or moved backwards/u,
    );

    const replayNonce = signAvailabilityEvidence(fixture, {
      evidence_sequence: 3,
      trust_generation: 2,
      nonce: evidence2.document.payload.nonce,
    });
    assert.throws(
      () => resolveFixture(fixture, trust2, replayNonce),
      /nonce was already consumed/u,
    );
  });

test("reviewed trust/evidence lifetimes and wall-to-monotonic skew are bounded",
  { concurrency: false }, (t) => {
    const trustFixture = setup(t, "trust-lifetime");
    const longTrust = signAvailabilityTrust(trustFixture, {
      not_before_ms: trustFixture.referenceUtcMs - 60_000,
      expires_at_ms: trustFixture.referenceUtcMs - 60_000 + MAX_TRUST_LIFETIME_MS + 1,
    });
    assert.throws(
      () => resolveFixture(trustFixture, longTrust, signAvailabilityEvidence(trustFixture)),
      /no longer than 24 hours/u,
    );

    const wallFixture = setup(t, "wall-lifetime");
    const wallEvidence = signAvailabilityEvidence(wallFixture, {
      expires_at_ms: wallFixture.referenceUtcMs + MAX_EVIDENCE_LIFETIME_MS + 1,
    });
    assert.throws(
      () => resolveFixture(wallFixture, signAvailabilityTrust(wallFixture), wallEvidence),
      /wall-time validity.*15 minutes/u,
    );

    const monotonicFixture = setup(t, "monotonic-lifetime");
    const monotonicEvidence = signAvailabilityEvidence(monotonicFixture, {
      expires_monotonic_ms:
        monotonicFixture.referenceMonotonicMs + MAX_EVIDENCE_LIFETIME_MS + 1,
    });
    assert.throws(
      () => resolveFixture(
        monotonicFixture,
        signAvailabilityTrust(monotonicFixture),
        monotonicEvidence,
      ),
      /monotonic validity.*15 minutes/u,
    );

    const skewFixture = setup(t, "freshness-skew");
    const skewEvidence = signAvailabilityEvidence(skewFixture, {
      expires_at_ms: skewFixture.referenceUtcMs + 5 * 60_000,
      expires_monotonic_ms: skewFixture.referenceMonotonicMs + 14 * 60_000,
    });
    assert.throws(
      () => resolveFixture(skewFixture, signAvailabilityTrust(skewFixture), skewEvidence),
      /wall and monotonic freshness bindings exceed/u,
    );
  });

test("signed envelopes cannot promote stale or revoked dependency proofs",
  { concurrency: false }, (t) => {
    const staleFixture = setup(t, "stale-dependency");
    const staleEvidence = signAvailabilityEvidence(staleFixture, {
      dependency_proof_overrides: {
        observed_at: iso(staleFixture.referenceUtcMs - 2 * 60_000),
        expires_at: iso(staleFixture.referenceUtcMs - 1),
      },
    });
    assert.throws(
      () => resolveFixture(
        staleFixture,
        signAvailabilityTrust(staleFixture),
        staleEvidence,
      ),
      /dependency_proofs\[0\] is stale at trusted-clock uncertainty/u,
    );

    const revokedFixture = setup(t, "revoked-dependency");
    const revokedEvidence = signAvailabilityEvidence(revokedFixture, {
      dependency_proof_overrides: { revoked: true },
    });
    assert.throws(
      () => resolveFixture(
        revokedFixture,
        signAvailabilityTrust(revokedFixture),
        revokedEvidence,
      ),
      /dependency_proofs\[0\] is revoked/u,
    );
  });
