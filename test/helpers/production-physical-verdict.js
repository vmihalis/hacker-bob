"use strict";

// Build a genuine production-qualified physical verdict entirely from local,
// synthetic evidence.  This is test support, but it deliberately uses the
// production ledger/store/trust paths: no test brand is promoted and no
// caller-supplied production callback is installed.

const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { types: utilTypes } = require("node:util");

const {
  ZERO_HASH,
  assertVerifiedPhysicalClaimProjection,
  attemptAllocationBindingDigest,
  buildPhysicalExperimentSignerTrustRegistry,
  buildPhysicalObserverEnrollmentRegistry,
  buildPhysicalReceiptTrustRegistry,
  createPhysicalAllocationIssuer,
  createPhysicalAppendIssuer,
  createPhysicalExperimentLedger,
  createMechanismAPhysicalExperimentLedger,
  createProductionPhysicalExperimentLedger,
  createTestPhysicalExperimentDurableHeadPort,
  enrollProductionPhysicalExperimentTrust,
  executionConsumptionBindingDigest,
  normalizePhysicalExperimentRowPayload,
  observationConsumptionBindingDigest,
  observerAttemptBindingDigest,
  rowAuthorizationContextDigest,
  signatureInputDigest,
} = require("../../mcp/domains/physical/physical-experiment-contract.js");
const {
  assertReportSafePhysicalVerdict,
  projectReportSafePhysicalVerdict,
} = require("../../mcp/domains/physical/physical-capability-consumers.js");
const {
  buildDurableReceiptTrustRegistry,
  buildExecutedEvidenceRegistry,
  createDurableEvidenceReceiptIssuer,
} = require("../../mcp/core/executed-evidence-registry.js");
const {
  buildSessionNucleus,
  normalizePhysicalScopeNucleusAxis,
} = require("../../mcp/core/governance/governance-contracts.js");
const {
  buildEffectTemplateRegistry,
  normalizeRequestedEffect,
} = require("../../mcp/core/requested-effects.js");
const { hashCanonicalJson } = require("../../mcp/core/verification/verification-contracts.js");
const {
  SANDBOX_AGENT_UID_ENV,
  SANDBOX_ISOLATION_ACK_ENV,
  SANDBOX_ISOLATION_ACK_TOKEN,
  SANDBOX_SIGNER_UID_ENV,
} = require("../../mcp/core/ledger-integrity/sandbox-isolation-attest.js");
const {
  openProductionPhysicalMonotonicOwner,
} = require("../../mcp/domains/physical/physical-monotonic-owner.js");
const {
  TRUSTED_CLOCK_MAPPING_DOMAIN,
  physicalClockMappingSigningMessage,
  publicKeyDigest,
} = require("../../mcp/domains/physical/physical-trusted-clock.js");
const {
  PHYSICAL_TRUSTED_CLOCK_AUTHORITY_BUNDLE_DOMAIN,
  PHYSICAL_TRUSTED_CLOCK_AUTHORITY_FILE,
  PHYSICAL_TRUSTED_CLOCK_TRUST_DOMAIN,
  openProductionPhysicalTrustedClockPort,
  physicalClockTrustSigningMessage,
} = require("../../mcp/domains/physical/physical-trusted-clock-store.js");

const DIGEST_RE = /^[a-f0-9]{64}$/u;

function digest(value) {
  return crypto.createHash("sha256").update(String(value)).digest("hex");
}

function iso(milliseconds) {
  return new Date(milliseconds).toISOString();
}

function signPhysicalClockMapping(keyPairInput, payload) {
  const payloadDigest = hashCanonicalJson(payload);
  const signature = crypto.sign(
    null,
    physicalClockMappingSigningMessage(payloadDigest),
    keyPairInput.privateKey,
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

function signPhysicalClockTrust(keyPairInput, payload) {
  const payloadDigest = hashCanonicalJson(payload);
  const signature = crypto.sign(
    null,
    physicalClockTrustSigningMessage(payloadDigest),
    keyPairInput.privateKey,
  ).toString("base64url");
  const basis = {
    version: 1,
    domain: PHYSICAL_TRUSTED_CLOCK_TRUST_DOMAIN,
    payload,
    payload_digest: payloadDigest,
    scheme: "ed25519",
    signature,
    trust_root_public_key_spki_base64url: keyPairInput.publicKey.export({
      type: "spki",
      format: "der",
    }).toString("base64url"),
  };
  return { ...basis, trust_statement_digest: hashCanonicalJson(basis) };
}

function installNonAuthorizingRestartDurableClock({
  targetDomain,
  sessionNucleusHash,
  suffix,
  authorityRoot,
  ownerRoot,
}) {
  const signer = crypto.generateKeyPairSync("ed25519");
  const trustRoot = crypto.generateKeyPairSync("ed25519");
  const clockId = `physical-clock:verdict-fixture-${suffix}`;
  const monotonicEpochId = digest(`physical-clock-epoch:${suffix}`);
  const referenceMonotonicMs = Number(process.hrtime.bigint() / 1_000_000n);
  const referenceUtcMs = Date.now();
  const notBefore = iso(referenceUtcMs - 60_000);
  const expiresAt = iso(referenceUtcMs + 10 * 60_000);
  const signerKeyId = `clock-key:verdict-fixture-${suffix}`;
  const signerDigest = publicKeyDigest(signer.publicKey);
  const mapping = signPhysicalClockMapping(signer, {
    version: 1,
    clock_id: clockId,
    monotonic_epoch_id: monotonicEpochId,
    mapping_generation: 1,
    reference_monotonic_ms: referenceMonotonicMs,
    reference_utc: iso(referenceUtcMs),
    max_uncertainty_ms: 5,
    not_before: notBefore,
    expires_at: expiresAt,
    trust_root_epoch: 1,
    authority_epoch: 1,
    revocation_generation: 0,
    signer_key_id: signerKeyId,
    signer_public_key_digest: signerDigest,
  });
  const trust = signPhysicalClockTrust(trustRoot, {
    version: 1,
    target_domain: targetDomain,
    session_nucleus_hash: sessionNucleusHash,
    trusted: true,
    revoked: false,
    clock_id: clockId,
    monotonic_epoch_id: monotonicEpochId,
    current_mapping_generation: 1,
    current_signed_mapping_digest: mapping.signed_mapping_digest,
    trust_root_epoch: 1,
    authority_epoch: 1,
    revocation_generation: 0,
    signer_key_id: signerKeyId,
    signer_public_key_digest: signerDigest,
    signer_public_key_spki_base64url: signer.publicKey.export({
      type: "spki",
      format: "der",
    }).toString("base64url"),
    trust_root_key_id: `clock-trust-root:verdict-fixture-${suffix}`,
    trust_root_public_key_digest: publicKeyDigest(trustRoot.publicKey),
    not_before: notBefore,
    expires_at: expiresAt,
  });
  const bundleBasis = {
    version: 1,
    domain: PHYSICAL_TRUSTED_CLOCK_AUTHORITY_BUNDLE_DOMAIN,
    signed_mapping: mapping,
    signed_trust: trust,
  };
  fs.writeFileSync(
    path.join(authorityRoot, PHYSICAL_TRUSTED_CLOCK_AUTHORITY_FILE),
    `${JSON.stringify({
      ...bundleBasis,
      bundle_digest: hashCanonicalJson(bundleBasis),
    })}\n`,
    { mode: 0o600 },
  );
  const owner = openProductionPhysicalMonotonicOwner({
    version: 1,
    target_domain: targetDomain,
    session_nucleus_hash: sessionNucleusHash,
    external_owner_root: ownerRoot,
    context_domain: "hacker-bob/physical-trusted-clock-high-water/v1",
  });
  return Object.freeze({
    owner,
    port: openProductionPhysicalTrustedClockPort({
      version: 1,
      target_domain: targetDomain,
      session_nucleus_hash: sessionNucleusHash,
      port_id: `verdict_clock_${suffix}`,
      clock_id: clockId,
      uncertainty_ceiling_ms: 50,
      authority_root: authorityRoot,
      monotonic_head_owner: owner,
    }),
    reopen() {
      const reopenedOwner = openProductionPhysicalMonotonicOwner({
        version: 1,
        target_domain: targetDomain,
        session_nucleus_hash: sessionNucleusHash,
        external_owner_root: ownerRoot,
        context_domain: "hacker-bob/physical-trusted-clock-high-water/v1",
      });
      return openProductionPhysicalTrustedClockPort({
        version: 1,
        target_domain: targetDomain,
        session_nucleus_hash: sessionNucleusHash,
        port_id: `verdict_clock_${suffix}`,
        clock_id: clockId,
        uncertainty_ceiling_ms: 50,
        authority_root: authorityRoot,
        monotonic_head_owner: reopenedOwner,
      });
    },
  });
}

function keyPair() {
  const pair = crypto.generateKeyPairSync("ed25519");
  return {
    publicKeyPem: pair.publicKey.export({ type: "spki", format: "pem" }),
    privateKeyPem: pair.privateKey.export({ type: "pkcs8", format: "pem" }),
  };
}

function assuranceClaims() {
  const claims = {
    identity_enrollment: digest("production-fixture:identity-enrollment"),
    firmware_provenance: digest("production-fixture:firmware-provenance"),
    command_surface_conformance: digest("production-fixture:command-surface-conformance"),
    transport_trust: digest("production-fixture:transport-trust"),
  };
  return { ...claims, claims_digest: hashCanonicalJson(claims) };
}

function createConformanceDurableHeadPort(suffix) {
  return createTestPhysicalExperimentDurableHeadPort({
    version: 1,
    port_id: `physical-ledger-head-port:fixture-conformance-${suffix}`,
    test_only: true,
    consistency_model: "linearizable_compare_and_append",
    compare_and_append() { return false; },
    read_head() { return null; },
    resolve_committed_append() { return null; },
  });
}

function createSignerFixture(
  validFrom,
  expiresAt,
  controlIndependenceDomainRef = "independence-domain:observer-b",
  instrumentIdentityRef = "instrument-identity:chameleon-ultra-fixture",
) {
  const definitions = [{
    signer_key_id: "signer-key:instrument",
    signer_principal_ref: "principal:instrument-worker",
    trust_domain_ref: "trust-domain:instrument",
    independence_domain_ref: "independence-domain:instrument-controller",
    instrument_identity_ref: instrumentIdentityRef,
    allowed_row_kinds: ["execution_receipt"],
  }, {
    signer_key_id: "signer-key:observer-a",
    signer_principal_ref: "principal:observer-a",
    trust_domain_ref: "trust-domain:observer-a",
    independence_domain_ref: "independence-domain:observer-a",
    observer_identity_ref: "observer:positive",
    allowed_row_kinds: ["observation"],
  }, {
    signer_key_id: "signer-key:observer-b",
    signer_principal_ref: "principal:observer-b",
    trust_domain_ref: "trust-domain:observer-b",
    independence_domain_ref: controlIndependenceDomainRef,
    observer_identity_ref: "observer:control",
    allowed_row_kinds: ["observation"],
  }, {
    signer_key_id: "signer-key:verifier",
    signer_principal_ref: "principal:physical-verifier",
    trust_domain_ref: "trust-domain:verifier",
    independence_domain_ref: "independence-domain:verifier",
    allowed_row_kinds: ["claim_verdict"],
  }];
  const privateKeys = new Map();
  const registry = buildPhysicalExperimentSignerTrustRegistry({
    version: 1,
    registry_id: "physical-production-verdict-fixture-signers",
    signers: definitions.map((definition) => {
      const keys = keyPair();
      privateKeys.set(definition.signer_key_id, keys.privateKeyPem);
      return {
        ...definition,
        signature_scheme: "ed25519",
        public_key_pem: keys.publicKeyPem,
        trust_root_epoch: 1,
        valid_from: validFrom,
        expires_at: expiresAt,
        trusted: true,
        revoked: false,
      };
    }),
  });
  const definitionsByKey = new Map(definitions.map((definition) => [
    definition.signer_key_id,
    definition,
  ]));
  const signers = Object.fromEntries(registry.describe().map((descriptor) => {
    const definition = definitionsByKey.get(descriptor.signer_key_id);
    return [descriptor.signer_key_id, Object.freeze({
      ...definition,
      trust_root_epoch: descriptor.trust_root_epoch,
      signer_enrollment_digest: descriptor.signer_enrollment_digest,
    })];
  }));
  return Object.freeze({
    registry,
    signers: Object.freeze(signers),
    sign(signatureInput, signerKeyId) {
      return crypto.sign(
        null,
        Buffer.from(signatureInput, "hex"),
        privateKeys.get(signerKeyId),
      ).toString("base64url");
    },
  });
}

function createReceiptRuntime({ validFrom, expiresAt, allocationTime }) {
  const keys = keyPair();
  const registry = buildPhysicalReceiptTrustRegistry({
    version: 1,
    registry_id: "physical-production-verdict-fixture-receipts",
    issuers: [{
      issuer_key_id: "signer-key:physical-ledger",
      issuer_epoch: 1,
      public_key_pem: keys.publicKeyPem,
      valid_from: validFrom,
      expires_at: expiresAt,
      trusted: true,
      revoked: false,
    }],
  });
  const uniqueReservations = new Map();
  const allocatedSubjects = new Map();
  const consumedSubjects = new Map();
  const allocationReceipts = new Map();
  const consumptionReceipts = new Map();
  const appendReservations = new Map();
  const appendReceipts = new Map();
  let allocationIssuerTime = allocationTime;
  let appendSequence = 0;

  const allocationIssuer = createPhysicalAllocationIssuer({
    registry,
    issuer_key_id: "signer-key:physical-ledger",
    issuer_epoch: 1,
    private_key_pem: keys.privateKeyPem,
    now: () => allocationIssuerTime,
    reserve_unique_batch({ binding_digest: bindingDigest, unique_keys: uniqueKeys, allocation }) {
      if (uniqueKeys.some((key) => (
        uniqueReservations.has(key) && uniqueReservations.get(key) !== bindingDigest
      ))) return false;
      for (const key of uniqueKeys) uniqueReservations.set(key, bindingDigest);
      for (const cohort of allocation.cohort_bindings) {
        allocatedSubjects.set(cohort.grant_ref, allocation.attempt_id);
        for (const nonce of cohort.challenge_nonces) {
          allocatedSubjects.set(`challenge:${nonce}`, allocation.attempt_id);
        }
      }
      return true;
    },
    consume_unique({ subject_ref: subjectRef, plan_hash: planHash, attempt_id: attemptId,
      binding_digest: bindingDigest }) {
      if (allocatedSubjects.get(subjectRef) !== attemptId) return false;
      const prior = consumedSubjects.get(subjectRef);
      if (prior) {
        return prior.plan_hash === planHash
          && prior.attempt_id === attemptId
          && prior.binding_digest === bindingDigest;
      }
      consumedSubjects.set(subjectRef, {
        plan_hash: planHash,
        attempt_id: attemptId,
        binding_digest: bindingDigest,
      });
      return true;
    },
    resolve_allocation_receipt({ binding_digest: bindingDigest }) {
      return allocationReceipts.get(bindingDigest) || null;
    },
    resolve_consumption_receipt({ subject_ref: subjectRef }) {
      return consumptionReceipts.get(subjectRef) || null;
    },
    commit_receipt(receipt) {
      if (receipt.kind === "attempt_allocation") {
        allocationReceipts.set(receipt.body.binding_digest, receipt);
      } else if (receipt.kind === "physical_consumption") {
        consumptionReceipts.set(receipt.body.subject_ref, receipt);
      }
      return true;
    },
  });

  function setAllocationIssuerTime(timestamp) {
    if (Date.parse(timestamp) > Date.parse(allocationIssuerTime)) allocationIssuerTime = timestamp;
  }

  function appendIssuerAt(timestamp) {
    return createPhysicalAppendIssuer({
      registry,
      issuer_key_id: "signer-key:physical-ledger",
      issuer_epoch: 1,
      private_key_pem: keys.privateKeyPem,
      now: () => timestamp,
      reserve_append({ append_binding_digest: bindingDigest, append_request: request }) {
        const requestDigest = hashCanonicalJson(request);
        const prior = appendReservations.get(bindingDigest);
        if (prior) return prior.request_digest === requestDigest;
        appendSequence += 1;
        const reservation = {
          version: 1,
          append_binding_digest: bindingDigest,
          journal_sequence: appendSequence,
        };
        reservation.reservation_digest = hashCanonicalJson({
          domain: "hacker-bob/physical-append-reservation-receipt/v1",
          ...reservation,
        });
        appendReservations.set(bindingDigest, { request_digest: requestDigest, reservation });
        return true;
      },
      resolve_append_reservation({ append_binding_digest: bindingDigest }) {
        const prior = appendReservations.get(bindingDigest);
        return prior == null ? null : structuredClone(prior.reservation);
      },
      commit_receipt(receipt) {
        appendReceipts.set(receipt.body.append_binding_digest, receipt);
        return true;
      },
      resolve_append_receipt({ append_binding_digest: bindingDigest }) {
        return appendReceipts.get(bindingDigest) || null;
      },
    });
  }

  return Object.freeze({
    registry,
    allocationIssuer,
    appendIssuerAt,
    setAllocationIssuerTime,
  });
}

function createEvidenceRuntime({
  validFrom,
  expiresAt,
  attestedAt,
  initialIssuerTime,
  surfaceRef = "surface:hotel-door-controller",
}) {
  const sourceRows = new Map();
  const sourceContexts = new Map();
  const committedBySemantic = new Map();
  const committedByRef = new Map();
  const keys = keyPair();
  let issuerTime = initialIssuerTime;

  function component(name, implementationKind = "tool") {
    return {
      version: 1,
      owner_principal: `principal:${name}`,
      [`${implementationKind}_digest`]: digest(`${name}:${implementationKind}`),
      signed_verdict_type: "physical.transition.v1",
      trust_epoch: 1,
      trust_state: "trusted",
      attested_at: attestedAt,
      freshness_window_ms: 31_536_000_000,
      expires_at: expiresAt,
      revoked: false,
    };
  }

  const registry = buildExecutedEvidenceRegistry({
    source_adapters: [{
      ...component("physical-observations", "artifact"),
      source_id: "physical.observations",
      ref_prefix: "physical-observation",
      resolve: async (ref) => sourceRows.get(ref) || null,
      reverify: async (row) => ({
        version: 1,
        verified: true,
        verification_digest: digest(`reverify:${row.row_hash}`),
      }),
      project_integrity: (row) => ({
        payload_digest: row.envelope.payload_digest,
        implementation_digest: digest("physical-observations:artifact"),
        content_hash_valid: true,
      }),
      project_signer_trust: (row) => ({
        owner_principal: "principal:physical-observations",
        signer_key_id: row.envelope.signer_key_id,
        signed_verdict_type: "physical.transition.v1",
        trust_epoch: 1,
        signature_valid: true,
        trusted: true,
        revoked: false,
      }),
      project_execution_identity: (row) => row.payload.execution_identity,
      project_node_contract_digest: (row) => sourceContexts.get(row.row_ref).node_contract_digest,
      project_context_digest: (row) => sourceContexts.get(row.row_ref).context_digest,
      project_surfaces: () => [surfaceRef],
      project_outcome: (row) => ({
        disposition: "verified",
        verdict_hash: row.row_hash,
        observed_at: row.payload.received_at,
      }),
      project_cleanup: () => ({ status: "not_required" }),
    }],
    context_resolvers: [{
      ...component("physical-experiment-context"),
      resolver_id: "physical.experiment-context",
      context_kind: "physical",
      resolve_context: async (request) => ({
        version: 1,
        execution_identity: request.execution_identity,
        node_contract_digest: request.node_contract_digest,
        context_digest: request.context_digest,
        surface_refs: [surfaceRef],
        resolved_at: request.resolved_at,
      }),
    }],
    replay_executors: [{
      ...component("physical-experiment-bind"),
      executor_id: "physical.experiment-bind",
      mode: "verified-verdict-bind",
      required_dependency_keys: [],
      execute: async ({ evidence, context }, callback) => ({
        version: 1,
        disposition: evidence.outcome.disposition,
        signed_verdict_type: "physical.transition.v1",
        verdict_hash: evidence.outcome.verdict_hash,
        consumed_evidence_digest: evidence.evidence_digest,
        execution_identity: context.execution_identity,
        node_contract_digest: context.node_contract_digest,
        context_digest: context.context_digest,
        executed_at: callback.now,
        cleanup_status: "not_required",
      }),
    }],
    verifier_templates: [{
      ...component("physical-transition-template", "artifact"),
      template_id: "physical.transition-positive-control",
      template_version: 1,
      mode: "verified-verdict-bind",
      source_ids: ["physical.observations"],
      context_resolver_id: "physical.experiment-context",
      replay_executor_id: "physical.experiment-bind",
      dependency_provider_ids: [],
      decision_rule_digest: digest("production-fixture:decision-rule"),
      adjudicate: async ({ replay, context }, callback) => ({
        version: 1,
        disposition: replay.disposition,
        signed_verdict_type: "physical.transition.v1",
        verdict_hash: replay.verdict_hash,
        replay_digest: replay.replay_digest,
        execution_identity: context.execution_identity,
        node_contract_digest: context.node_contract_digest,
        context_digest: context.context_digest,
        decided_at: callback.now,
      }),
    }],
    dependency_proof_providers: [],
  });
  const verifierTemplate = registry.get(
    "verifier_templates",
    "physical.transition-positive-control",
  );
  const receiptRegistry = buildDurableReceiptTrustRegistry({
    version: 1,
    registry_id: "physical-production-verdict-fixture-evidence-receipts",
    issuers: [{
      issuer_key_id: "signer-key:evidence-receipt",
      issuer_epoch: 1,
      signature_scheme: "ed25519",
      public_key_pem: keys.publicKeyPem,
      receipt_kinds: ["executed_evidence_verification", "physical_verifier_execution"],
      valid_from: validFrom,
      expires_at: expiresAt,
      trusted: true,
      revoked: false,
    }],
  });
  const receiptIssuer = createDurableEvidenceReceiptIssuer({
    trust_registry: receiptRegistry,
    issuer_key_id: "signer-key:evidence-receipt",
    issuer_epoch: 1,
    private_key_pem: keys.privateKeyPem,
    now: () => issuerTime,
    commit_receipt(receipt, binding) {
      committedBySemantic.set(binding.semantic_digest, receipt);
      committedByRef.set(receipt.receipt_ref, receipt);
      return true;
    },
    resolve_committed_receipt({ semantic_digest: semanticDigest }) {
      return committedBySemantic.get(semanticDigest) || null;
    },
  });

  function setIssuerTime(timestamp) {
    if (Date.parse(timestamp) > Date.parse(issuerTime)) issuerTime = timestamp;
  }

  function recordObservation(row, plan) {
    sourceRows.set(row.row_ref, row);
    sourceContexts.set(row.row_ref, {
      node_contract_digest: plan.contract_hash,
      context_digest: plan.plan_hash,
    });
  }

  return Object.freeze({
    registry,
    receiptRegistry,
    receiptIssuer,
    verifierTemplate,
    recordObservation,
    resolveReceipt: (ref) => committedByRef.get(ref) || null,
    setIssuerTime,
  });
}

function installPhysicalSession(
  targetDomain,
  transitionReceiptRegistryDigest = digest("production-fixture:transition-registry"),
) {
  const physicalScope = normalizePhysicalScopeNucleusAxis({
    version: 1,
    physical_enabled: true,
    policy_version: 1,
    policy_id: "physical_production_verdict_fixture",
    policy_digest: digest("production-fixture:physical-policy"),
    projection_version: 1,
    projection_digest: digest("production-fixture:physical-projection"),
    provenance_digest: digest("production-fixture:physical-provenance"),
    compatibility_digest: digest("production-fixture:physical-compatibility"),
    transition_receipt_registry_digest: transitionReceiptRegistryDigest,
    authority_epoch: 1,
    revocation_generation: 0,
  });
  const nucleus = buildSessionNucleus({
    target_domain: targetDomain,
    target_url: `https://${targetDomain}`,
    scope_policy: {
      target_domain: targetDomain,
      target_url: `https://${targetDomain}`,
      checkpoint_mode: "normal",
      block_internal_hosts: false,
      block_internal_hosts_source: "mode_default",
    },
    egress_identity: { egress_profile: "default", proxy_configured: false },
    auth_context: { auth_status: "pending" },
    operator_constraint: { handoff_provenance_required: true },
    lifecycle_state: "VERIFY",
    physical_scope: physicalScope,
  });
  const directory = path.join(os.homedir(), "hacker-bob-sessions", targetDomain);
  if (fs.existsSync(directory)) {
    throw new Error("production physical verdict fixture refuses to replace an existing session");
  }
  fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
  fs.writeFileSync(
    path.join(directory, "session-nucleus.json"),
    `${JSON.stringify(nucleus, null, 2)}\n`,
    { encoding: "utf8", mode: 0o600 },
  );
  return Object.freeze({ nucleus, directory });
}

function observerPlan(kind, controlIndependenceDomainRef = "independence-domain:observer-b") {
  const positive = kind === "positive";
  const plan = {
    observer_id: `${kind}-observer`,
    observer_identity_ref: `observer:${kind}`,
    observer_enrollment_ref: `observer-enrollment:${kind}`,
    source_kind: "sensor",
    source_ref: `sensor:external-${positive ? "a" : "b"}`,
    source_assurance_scheme: "signed-fixture-v1",
    required_trust_domain_ref: `trust-domain:observer-${positive ? "a" : "b"}`,
    required_independence_domain_ref: `independence-domain:observer-${positive ? "a" : "b"}`,
    challenge_nonce: positive
      ? "AAAAAAAAAAAAAAAAAAAAAA"
      : "BBBBBBBBBBBBBBBBBBBBBB",
    attempt_binding_digest: digest(`${kind}:placeholder-binding`),
    external_outcome: true,
  };
  if (!positive) plan.required_independence_domain_ref = controlIndependenceDomainRef;
  return plan;
}

function createPlan({
  sessionNucleusHash,
  signerRegistry,
  observerRegistry,
  physicalReceiptRegistry,
  evidenceRuntime,
  effectRegistry,
  receiptRuntime,
  suffix,
  claimPredicateDigest,
  controlIndependenceDomainRef,
  experimentProfile = null,
}) {
  const profile = experimentProfile || {};
  const effectTemplateId = profile.effect_template_id || "target.credential-present";
  const effectTemplate = effectRegistry.get(effectTemplateId);
  if (!effectTemplate) throw new Error("physical verdict fixture experiment effect template is unavailable");
  const requestedEffect = normalizeRequestedEffect(profile.requested_effect || {
    version: 1,
    template_id: "target.credential-present",
    template_digest: effectTemplate.template_digest,
    subject_ref: "target:hotel-door-controller",
    subject_kind: "target",
    action: "present",
    channel: "rf",
    persistence: "ephemeral",
    bounds: { duration_ms: 250, carrier: "hf" },
  }, effectRegistry, "physical_verdict_fixture.requested_effect");
  const expectedPositive = digest(`production-fixture:${suffix}:accepted`);
  const expectedControl = digest(`production-fixture:${suffix}:denied`);
  const plan = {
    version: 1,
    experiment_id: profile.experiment_id || "production-credential-differential",
    task_id: `PH-FIXTURE-${suffix}`,
    attempt_id: `attempt-${suffix}`,
    session_nucleus_hash: sessionNucleusHash,
    node_id: profile.node_id || "PH-C3",
    contract_hash: digest(`production-fixture:${suffix}:node-contract`),
    execution_request_digest: digest(`production-fixture:${suffix}:execution-request`),
    hypothesis_ref: "hypothesis:controlled-transition",
    claim_predicate_digest: claimPredicateDigest
      || digest(`production-fixture:${suffix}:claim-predicate`),
    expected_positive_outcome_digest: expectedPositive,
    expected_control_outcome_digest: expectedControl,
    verifier_template_id: evidenceRuntime.verifierTemplate.template_id,
    verifier_template_version: evidenceRuntime.verifierTemplate.template_version,
    verifier_template_digest: evidenceRuntime.verifierTemplate.template_digest,
    decision_rule_digest: evidenceRuntime.verifierTemplate.decision_rule_digest,
    observation_window: {
      start_rule: "execution_ended",
      max_duration_ms: 10_000,
      max_clock_offset_abs_ms: 60_000,
      max_clock_uncertainty_ms: 250,
    },
    retry_policy: {
      fresh_attempt_and_challenge: true,
      max_attempts: 1,
      retry_on: ["transport_failure", "inconclusive"],
    },
    trust_registry_digest: signerRegistry.registry_digest,
    executed_evidence_registry_digest: evidenceRuntime.registry.registry_digest,
    evidence_receipt_registry_digest: evidenceRuntime.receiptRegistry.registry_digest,
    evidence_receipt_issuer_key_id: "signer-key:evidence-receipt",
    evidence_receipt_issuer_epoch: 1,
    observer_enrollment_registry_digest: observerRegistry.registry_digest,
    physical_receipt_registry_digest: physicalReceiptRegistry.registry_digest,
    allocation_issuer_key_id: "signer-key:physical-ledger",
    allocation_issuer_epoch: 1,
    append_issuer_key_id: "signer-key:physical-ledger",
    append_issuer_epoch: 1,
    attempt_allocation_receipt: null,
    // This fixture is exercised inside the full MCP suite, where process-level
    // contention can delay an otherwise immediate append by several seconds.
    // Keep the window bounded while avoiding a scheduler-dependent false
    // negative; production policies are supplied by the production runtime.
    ingestion_policy: { max_future_skew_ms: 30_000, max_ingestion_delay_ms: 30_000 },
    consumption_registry_digest: physicalReceiptRegistry.registry_digest,
    consumption_issuer_key_id: "signer-key:physical-ledger",
    consumption_issuer_epoch: 1,
    instrument_ref: profile.instrument_ref || "instrument:chameleon-ultra-fixture",
    instrument_identity_ref: profile.instrument_identity_ref
      || "instrument-identity:chameleon-ultra-fixture",
    instrument_inventory_ref: profile.instrument_inventory_ref
      || "inventory:chameleon-ultra-fixture",
    assurance_profile_id: profile.assurance_profile_id || "chameleon-ultra-enrolled-v1",
    instrument_assurance_claims: assuranceClaims(),
    provider_manifest_digest: profile.provider_manifest_digest
      || digest("production-fixture:provider-manifest"),
    source_asset_ref: profile.source_asset_ref || "source:credential-fixture",
    target_asset_ref: profile.target_asset_ref || "target:hotel-door-controller",
    operation_id: profile.operation_id || "hf.credential-present",
    parameter_digest: profile.parameter_digest
      || digest("production-fixture:operation-parameters"),
    requested_effects_registry_digest: effectRegistry.registry_digest,
    requested_effects: [requestedEffect],
    requested_effects_digest: hashCanonicalJson([requestedEffect]),
    positive_cohort: {
      kind: "positive",
      stimulus_plan_ref: "stimulus-plan:positive",
      stimulus_plan_digest: digest(`production-fixture:${suffix}:positive-stimulus-plan`),
      cohort_execution_request_digest: digest(`production-fixture:${suffix}:positive-execution-request`),
      grant_ref: `grant:positive-${suffix}`,
      execution_identity: `execution:positive-${suffix}`,
      expected_outcome_digest: expectedPositive,
      observer_plan: [observerPlan("positive", controlIndependenceDomainRef)],
    },
    control_cohort: {
      kind: "control",
      stimulus_plan_ref: "stimulus-plan:control",
      stimulus_plan_digest: digest(`production-fixture:${suffix}:control-stimulus-plan`),
      cohort_execution_request_digest: digest(`production-fixture:${suffix}:control-execution-request`),
      grant_ref: `grant:control-${suffix}`,
      execution_identity: `execution:control-${suffix}`,
      expected_outcome_digest: expectedControl,
      observer_plan: [observerPlan("control", controlIndependenceDomainRef)],
    },
    controls: [{
      kind: "negative",
      plan_ref: "stimulus-plan:control",
      plan_digest: digest(`production-fixture:${suffix}:control-stimulus-plan`),
    }],
    cleanup_plan_digest: digest(`production-fixture:${suffix}:cleanup-plan`),
  };
  for (const cohortField of ["positive_cohort", "control_cohort"]) {
    const cohort = plan[cohortField];
    plan[cohortField] = {
      ...cohort,
      observer_plan: cohort.observer_plan.map((observer) => {
        const enrollment = observerRegistry.get(observer.observer_enrollment_ref);
        const attemptBinding = observerAttemptBindingDigest({
          session_nucleus_hash: plan.session_nucleus_hash,
          experiment_id: plan.experiment_id,
          task_id: plan.task_id,
          attempt_id: plan.attempt_id,
          execution_request_digest: plan.execution_request_digest,
          cohort_kind: cohort.kind,
          cohort_execution_request_digest: cohort.cohort_execution_request_digest,
          stimulus_plan_ref: cohort.stimulus_plan_ref,
          stimulus_plan_digest: cohort.stimulus_plan_digest,
          observer_enrollment_digest: enrollment.enrollment_digest,
          signer_key_id: enrollment.signer_key_id,
          ...observer,
        });
        return { ...observer, attempt_binding_digest: attemptBinding };
      }),
    };
  }
  const allocationBody = {
    version: 1,
    session_nucleus_hash: plan.session_nucleus_hash,
    experiment_id: plan.experiment_id,
    task_id: plan.task_id,
    attempt_id: plan.attempt_id,
    execution_request_digest: plan.execution_request_digest,
    cohort_bindings: [plan.positive_cohort, plan.control_cohort].map((cohort) => ({
      cohort_kind: cohort.kind,
      cohort_execution_request_digest: cohort.cohort_execution_request_digest,
      grant_ref: cohort.grant_ref,
      execution_identity: cohort.execution_identity,
      challenge_nonces: cohort.observer_plan.map((observer) => observer.challenge_nonce).sort(),
    })),
  };
  allocationBody.binding_digest = attemptAllocationBindingDigest(allocationBody);
  plan.attempt_allocation_receipt = receiptRuntime.allocationIssuer.issueAttemptAllocation(allocationBody);
  return plan;
}

function commonPayload(plan) {
  return {
    version: 1,
    plan_hash: plan.plan_hash,
    session_nucleus_hash: plan.session_nucleus_hash,
    task_id: plan.task_id,
    attempt_id: plan.attempt_id,
  };
}

function issueConsumption(receiptRuntime, plan, {
  kind,
  bindingDigest,
  subjectRef,
  sequence,
  consumedAt,
}) {
  receiptRuntime.setAllocationIssuerTime(consumedAt);
  return receiptRuntime.allocationIssuer.issueConsumption({
    version: 1,
    kind,
    binding_digest: bindingDigest,
    subject_ref: subjectRef,
    consumption_ref: `consumption:${kind}-${sequence}-${bindingDigest.slice(0, 16)}`,
    plan_hash: plan.plan_hash,
    attempt_id: plan.attempt_id,
    sequence,
    consumed_at: consumedAt,
  });
}

function executionPayload(receiptRuntime, plan, cohortKind, startedAt, endedAt) {
  const cohort = cohortKind === "positive" ? plan.positive_cohort : plan.control_cohort;
  const payload = {
    ...commonPayload(plan),
    cohort_kind: cohortKind,
    stimulus_plan_ref: cohort.stimulus_plan_ref,
    stimulus_plan_digest: cohort.stimulus_plan_digest,
    cohort_execution_request_digest: cohort.cohort_execution_request_digest,
    grant_ref: cohort.grant_ref,
    execution_identity: cohort.execution_identity,
    execution_request_digest: plan.execution_request_digest,
    instrument_ref: plan.instrument_ref,
    instrument_identity_ref: plan.instrument_identity_ref,
    instrument_inventory_ref: plan.instrument_inventory_ref,
    provider_manifest_digest: plan.provider_manifest_digest,
    instrument_trust_domain_ref: "trust-domain:instrument",
    status: "executed",
    started_at: startedAt,
    ended_at: endedAt,
    stimulus_artifact_ref: `artifact:v1:${cohortKind}-stimulus`,
  };
  const bindingDigest = executionConsumptionBindingDigest(
    plan,
    cohort,
    payload.grant_ref,
    payload.execution_identity,
  );
  payload.consumption_attestation = issueConsumption(receiptRuntime, plan, {
    kind: "grant",
    bindingDigest,
    subjectRef: payload.grant_ref,
    sequence: cohortKind === "positive" ? 1 : 2,
    consumedAt: startedAt,
  });
  return payload;
}

function observationPayload(receiptRuntime, plan, cohortKind, executionReceiptRef,
  capturedAt, receivedAt) {
  const cohort = cohortKind === "positive" ? plan.positive_cohort : plan.control_cohort;
  const observer = cohort.observer_plan[0];
  const payload = {
    ...commonPayload(plan),
    cohort_kind: cohortKind,
    execution_receipt_ref: executionReceiptRef,
    grant_ref: cohort.grant_ref,
    execution_identity: cohort.execution_identity,
    observer_id: observer.observer_id,
    observer_enrollment_ref: observer.observer_enrollment_ref,
    source_kind: observer.source_kind,
    source_ref: observer.source_ref,
    trust_domain_ref: observer.required_trust_domain_ref,
    independence_domain_ref: observer.required_independence_domain_ref,
    observer_identity_ref: observer.observer_identity_ref,
    source_assurance_scheme: observer.source_assurance_scheme,
    challenge_nonce: observer.challenge_nonce,
    attempt_binding_digest: observer.attempt_binding_digest,
    replay_guard: { kind: "one_time_challenge", value: observer.challenge_nonce },
    observed_outcome_digest: cohort.expected_outcome_digest,
    observed_state_digest: digest(`production-fixture:${cohortKind}:state`),
    artifact_ref: `artifact:v1:${cohortKind}-observation`,
    captured_at: capturedAt,
    received_at: receivedAt,
    clock_offset_ms: 0,
    clock_uncertainty_ms: 25,
  };
  const bindingDigest = observationConsumptionBindingDigest(
    plan,
    observer,
    payload,
    payload.replay_guard,
  );
  payload.consumption_attestation = issueConsumption(receiptRuntime, plan, {
    kind: "one_time_challenge",
    bindingDigest,
    subjectRef: `challenge:${observer.challenge_nonce}`,
    sequence: cohortKind === "positive" ? 1 : 2,
    consumedAt: capturedAt,
  });
  return payload;
}

function appendSignedRow({
  ledger,
  receiptRuntime,
  signerFixture,
  evidenceRuntime,
  rowKind,
  payload,
  signerKeyId,
  signedAt,
}) {
  const normalizedPayload = normalizePhysicalExperimentRowPayload(rowKind, payload, ledger.plan);
  const signer = signerFixture.signers[signerKeyId];
  const payloadDigest = hashCanonicalJson(normalizedPayload);
  const authorizationContextDigest = rowAuthorizationContextDigest(
    rowKind,
    normalizedPayload,
    ledger.plan,
  );
  const rows = ledger.rows();
  const sequence = rows.length + 1;
  const previousRowHash = rows.at(-1)?.row_hash || ZERO_HASH;
  const envelope = {
    version: 1,
    signer_key_id: signerKeyId,
    signer_principal_ref: signer.signer_principal_ref,
    signature_scheme: "ed25519",
    trust_root_epoch: signer.trust_root_epoch,
    trust_domain_ref: signer.trust_domain_ref,
    independence_domain_ref: signer.independence_domain_ref,
    trust_registry_digest: ledger.plan.trust_registry_digest,
    signer_enrollment_digest: signer.signer_enrollment_digest,
    authorization_context_digest: authorizationContextDigest,
    sequence,
    previous_row_hash: previousRowHash,
    payload_digest: payloadDigest,
    signed_at: signedAt,
  };
  envelope.append_receipt = receiptRuntime.appendIssuerAt(signedAt).issueAppend({
    version: 1,
    plan_hash: ledger.plan.plan_hash,
    row_kind: rowKind,
    payload_digest: payloadDigest,
    expected_sequence: sequence,
    previous_row_hash: previousRowHash,
    authorization_context_digest: authorizationContextDigest,
    signed_at: signedAt,
  });
  const signatureInput = signatureInputDigest(rowKind, payloadDigest, envelope);
  const row = ledger.append({
    version: 1,
    row_kind: rowKind,
    payload: normalizedPayload,
    envelope: {
      ...envelope,
      signature: signerFixture.sign(signatureInput, signerKeyId),
    },
  }).row;
  if (rowKind === "observation") evidenceRuntime.recordObservation(row, ledger.plan);
  return row;
}

async function issueExecutedEvidence({ evidenceRuntime, plan, observation, execution, now }) {
  evidenceRuntime.setIssuerTime(now);
  const source = evidenceRuntime.registry.get("source_adapters", "physical.observations");
  const resolver = evidenceRuntime.registry.get(
    "context_resolvers",
    "physical.experiment-context",
  );
  const executor = evidenceRuntime.registry.get("replay_executors", "physical.experiment-bind");
  const executedEvidenceRef = {
    version: 1,
    source_id: "physical.observations",
    source_adapter_digest: source.adapter_digest,
    evidence_ref: observation.row_ref,
    expected_payload_digest: observation.envelope.payload_digest,
    expected_verdict_hash: observation.row_hash,
    execution_identity: execution.payload.execution_identity,
    node_contract_digest: plan.contract_hash,
    context_digest: plan.plan_hash,
  };
  const receipt = await evidenceRuntime.receiptIssuer.issueExecutedEvidence({
    evidence_registry: evidenceRuntime.registry,
    plan_hash: plan.plan_hash,
    verification_request: {
      version: 1,
      executed_evidence_ref: executedEvidenceRef,
      context_resolver_ref: {
        resolver_id: resolver.resolver_id,
        resolver_digest: resolver.resolver_digest,
      },
      context_request: {
        execution_identity: executedEvidenceRef.execution_identity,
        node_contract_digest: executedEvidenceRef.node_contract_digest,
        context_digest: executedEvidenceRef.context_digest,
        resolved_at: now,
      },
      replay_executor_ref: {
        executor_id: executor.executor_id,
        executor_digest: executor.executor_digest,
      },
      verifier_template_ref: {
        template_id: evidenceRuntime.verifierTemplate.template_id,
        template_version: evidenceRuntime.verifierTemplate.template_version,
        template_digest: evidenceRuntime.verifierTemplate.template_digest,
      },
      dependency_proof_refs: [],
    },
    verification_deps: {
      now,
      isTrustEpochTrusted: () => true,
      isComponentRevoked: () => false,
    },
  });
  return {
    binding: {
      version: 1,
      executed_evidence_ref: executedEvidenceRef,
      verification_receipt_ref: receipt.receipt_ref,
      verification_receipt_digest: receipt.receipt_digest,
    },
    receipt,
  };
}

async function createClaimPayload({
  evidenceRuntime,
  plan,
  executions,
  observations,
  evidenceNow,
  decidedAt,
  validityKind = "historical_event",
  liveExpiresAt = null,
}) {
  const positive = await issueExecutedEvidence({
    evidenceRuntime,
    plan,
    observation: observations[0],
    execution: executions[0],
    now: evidenceNow,
  });
  const control = await issueExecutedEvidence({
    evidenceRuntime,
    plan,
    observation: observations[1],
    execution: executions[1],
    now: evidenceNow,
  });
  evidenceRuntime.setIssuerTime(decidedAt);
  const verifierReceipt = await evidenceRuntime.receiptIssuer.issuePhysicalVerifierExecution({
    version: 1,
    registry_digest: plan.executed_evidence_registry_digest,
    plan_hash: plan.plan_hash,
    verifier_template_id: plan.verifier_template_id,
    verifier_template_version: plan.verifier_template_version,
    verifier_template_digest: plan.verifier_template_digest,
    decision_rule_digest: plan.decision_rule_digest,
    evidence_verification_receipt_digests: [
      positive.binding.verification_receipt_digest,
      control.binding.verification_receipt_digest,
    ].sort(),
    outcome: "verified",
    reason_code: "differential_verified",
    decided_at: decidedAt,
  });
  return {
    payload: {
      ...commonPayload(plan),
      execution_receipt_refs: executions.map((row) => row.row_ref),
      observation_refs: observations.map((row) => row.row_ref),
      positive_executed_evidence_refs: [positive.binding],
      control_executed_evidence_refs: [control.binding],
      executed_evidence_registry_digest: plan.executed_evidence_registry_digest,
      verifier_template_id: plan.verifier_template_id,
      verifier_template_version: plan.verifier_template_version,
      verifier_template_digest: plan.verifier_template_digest,
      decision_rule_digest: plan.decision_rule_digest,
      verifier_execution_receipt_ref: verifierReceipt.receipt_ref,
      verifier_execution_receipt_digest: verifierReceipt.receipt_digest,
      outcome: "verified",
      reason_code: "differential_verified",
      validity_kind: validityKind,
      valid_from: decidedAt,
      decided_at: decidedAt,
      ...(validityKind === "live_capability" ? {
        state_epoch: 1,
        expires_at: liveExpiresAt,
        capability_instance_ref: "capability-instance:production-fixture-state-1",
        custody_state_digest: digest("production-fixture:custody-state-1"),
      } : {}),
    },
    receipts: [positive.receipt, control.receipt, verifierReceipt],
  };
}

function installStructuralMechanismAHarness(enabled) {
  if (enabled !== true) return null;
  const signerUid = typeof process.getuid === "function" ? process.getuid() : null;
  if (signerUid == null || signerUid === 0) {
    throw new Error("production physical verdict structural fixture requires a non-root uid");
  }
  const prior = {
    home: process.env.HOME,
    ack: process.env[SANDBOX_ISOLATION_ACK_ENV],
    signer: process.env[SANDBOX_SIGNER_UID_ENV],
    agent: process.env[SANDBOX_AGENT_UID_ENV],
  };
  const signerHome = fs.mkdtempSync(path.join(os.tmpdir(), "bob-physical-signer-owner-"));
  process.env.HOME = signerHome;
  process.env[SANDBOX_ISOLATION_ACK_ENV] = SANDBOX_ISOLATION_ACK_TOKEN;
  process.env[SANDBOX_SIGNER_UID_ENV] = String(signerUid);
  process.env[SANDBOX_AGENT_UID_ENV] = String(signerUid + 1);
  let restored = false;
  return Object.freeze({
    signerHome,
    restore() {
      if (restored) return;
      restored = true;
      if (prior.home === undefined) delete process.env.HOME;
      else process.env.HOME = prior.home;
      for (const [value, envName] of [
        [prior.ack, SANDBOX_ISOLATION_ACK_ENV],
        [prior.signer, SANDBOX_SIGNER_UID_ENV],
        [prior.agent, SANDBOX_AGENT_UID_ENV],
      ]) {
        if (value === undefined) delete process.env[envName];
        else process.env[envName] = value;
      }
      fs.rmSync(signerHome, { recursive: true, force: true });
    },
  });
}

const EXPERIMENT_PROFILE_FIELDS = Object.freeze([
  "effect_registry",
  "effect_template_id",
  "requested_effect",
  "surface_ref",
  "experiment_id",
  "node_id",
  "instrument_ref",
  "instrument_identity_ref",
  "instrument_inventory_ref",
  "assurance_profile_id",
  "provider_manifest_digest",
  "source_asset_ref",
  "target_asset_ref",
  "operation_id",
  "parameter_digest",
]);

function normalizeFixtureExperimentProfile(input) {
  if (input == null) return null;
  if (typeof input !== "object" || Array.isArray(input) || utilTypes.isProxy(input)
      || Object.getPrototypeOf(input) !== Object.prototype) {
    throw new Error("physical verdict fixture experiment_profile must be a plain data object");
  }
  const keys = Reflect.ownKeys(input);
  const expected = [...EXPERIMENT_PROFILE_FIELDS].sort();
  const actual = keys.filter((key) => typeof key === "string").sort();
  if (keys.some((key) => typeof key !== "string")
      || actual.length !== expected.length
      || actual.some((key, index) => key !== expected[index])) {
    throw new Error(
      `physical verdict fixture experiment_profile must carry exactly ${EXPERIMENT_PROFILE_FIELDS.join(", ")}`,
    );
  }
  const descriptors = Object.getOwnPropertyDescriptors(input);
  const values = {};
  for (const field of EXPERIMENT_PROFILE_FIELDS) {
    const descriptor = descriptors[field];
    if (!descriptor || !("value" in descriptor) || !descriptor.enumerable) {
      throw new Error(`physical verdict fixture experiment_profile.${field} must be an enumerable data field`);
    }
    values[field] = descriptor.value;
  }
  if (utilTypes.isProxy(values.effect_registry)
      || typeof values.effect_registry?.get !== "function") {
    throw new Error("physical verdict fixture experiment_profile.effect_registry must be a Bob registry");
  }
  const normalizedEffect = normalizeRequestedEffect(
    values.requested_effect,
    values.effect_registry,
    "physical_verdict_fixture.experiment_profile.requested_effect",
  );
  if (normalizedEffect.template_id !== values.effect_template_id) {
    throw new Error("physical verdict fixture experiment profile effect template drift");
  }
  for (const field of EXPERIMENT_PROFILE_FIELDS.filter((name) => ![
    "effect_registry",
    "requested_effect",
  ].includes(name))) {
    if (typeof values[field] !== "string" || values[field].length < 1) {
      throw new Error(`physical verdict fixture experiment_profile.${field} must be text`);
    }
  }
  return Object.freeze({ ...values, requested_effect: normalizedEffect });
}

async function createPhysicalVerdictFixture(options, ledgerMode) {
  const experimentProfile = normalizeFixtureExperimentProfile(options.experiment_profile || null);
  let mechanismAHarness = null;
  let monotonicOwnerRoot = null;
  let trustedClockOwnerRoot = null;
  let trustedClockAuthorityRoot = null;
  let trustedClockRuntime = null;
  const suffix = crypto.randomBytes(8).toString("hex");
  const targetDomain = options.target_domain || `physical-verdict-fixture-${suffix}.local`;
  if (typeof targetDomain !== "string" || targetDomain.length < 1
      || targetDomain !== targetDomain.trim() || targetDomain.includes("/")
      || targetDomain.includes("..")) {
    throw new Error("production physical verdict fixture target_domain is invalid");
  }
  const now = Date.now();
  const timeline = now - 5_000;
  const validFrom = iso(now - 86_400_000);
  const expiresAt = iso(now + 31_536_000_000);
  const attestedAt = iso(timeline - 1_000);
  const controlIndependenceDomainRef = options.shared_observer_independence_domain === true
    ? "independence-domain:observer-a"
    : "independence-domain:observer-b";
  const transitionReceiptRegistryDigest = options.transition_receipt_registry_digest
    || digest("production-fixture:transition-registry");
  const validityKind = options.validity_kind || "historical_event";
  if (!DIGEST_RE.test(transitionReceiptRegistryDigest)) {
    throw new Error("production physical verdict fixture transition registry digest is invalid");
  }
  if (!["historical_event", "live_capability"].includes(validityKind)) {
    throw new Error("production physical verdict fixture validity_kind is invalid");
  }
  mechanismAHarness = installStructuralMechanismAHarness(
    options.structural_mechanism_a === true,
  );
  let session;
  try {
    session = installPhysicalSession(targetDomain, transitionReceiptRegistryDigest);
  } catch (error) {
    if (mechanismAHarness) mechanismAHarness.restore();
    throw error;
  }
  let cleaned = false;
  function cleanup() {
    if (cleaned) return;
    cleaned = true;
    fs.rmSync(session.directory, { recursive: true, force: true });
    if (monotonicOwnerRoot != null) {
      fs.rmSync(monotonicOwnerRoot, { recursive: true, force: true });
    }
    if (trustedClockOwnerRoot != null) {
      fs.rmSync(trustedClockOwnerRoot, { recursive: true, force: true });
    }
    if (trustedClockAuthorityRoot != null) {
      fs.rmSync(trustedClockAuthorityRoot, { recursive: true, force: true });
    }
    if (mechanismAHarness) mechanismAHarness.restore();
  }

  try {
    const signerFixture = createSignerFixture(
      validFrom,
      expiresAt,
      controlIndependenceDomainRef,
      experimentProfile?.instrument_identity_ref,
    );
    const receiptRuntime = createReceiptRuntime({
      validFrom,
      expiresAt,
      allocationTime: iso(timeline - 100),
    });
    const evidenceRuntime = createEvidenceRuntime({
      validFrom,
      expiresAt,
      attestedAt,
      initialIssuerTime: iso(timeline + 700),
      surfaceRef: experimentProfile?.surface_ref,
    });
    const observerRegistry = buildPhysicalObserverEnrollmentRegistry([{
      observer_enrollment_ref: "observer-enrollment:positive",
      observer_identity_ref: "observer:positive",
      signer_key_id: "signer-key:observer-a",
      source_kind: "sensor",
      source_ref: "sensor:external-a",
      source_assurance_scheme: "signed-fixture-v1",
      trust_domain_ref: "trust-domain:observer-a",
      independence_domain_ref: "independence-domain:observer-a",
      external_outcome_allowed: true,
      valid_from: validFrom,
      expires_at: expiresAt,
      revoked: false,
    }, {
      observer_enrollment_ref: "observer-enrollment:control",
      observer_identity_ref: "observer:control",
      signer_key_id: "signer-key:observer-b",
      source_kind: "sensor",
      source_ref: "sensor:external-b",
      source_assurance_scheme: "signed-fixture-v1",
      trust_domain_ref: "trust-domain:observer-b",
      independence_domain_ref: controlIndependenceDomainRef,
      external_outcome_allowed: true,
      valid_from: validFrom,
      expires_at: expiresAt,
      revoked: false,
    }]);
    const effectRegistry = experimentProfile?.effect_registry || buildEffectTemplateRegistry([{
      version: 1,
      template_id: "target.credential-present",
      subject_kind: "target",
      action: "present",
      channel: "rf",
      persistence: "ephemeral",
      bounds: {
        duration_ms: { kind: "integer", required: true, min: 1, max: 5_000 },
        carrier: { kind: "enum", required: true, values: ["hf", "lf"] },
      },
    }]);
    const plan = createPlan({
      sessionNucleusHash: session.nucleus.nucleus_hash,
      signerRegistry: signerFixture.registry,
      observerRegistry,
      physicalReceiptRegistry: receiptRuntime.registry,
      evidenceRuntime,
      effectRegistry,
      receiptRuntime,
      suffix,
      claimPredicateDigest: options.claim_predicate_digest,
      controlIndependenceDomainRef,
      experimentProfile,
    });
    const trustEnrollment = enrollProductionPhysicalExperimentTrust({
      version: 1,
      target_domain: targetDomain,
      session_nucleus_hash: session.nucleus.nucleus_hash,
      signerTrustRegistry: signerFixture.registry,
      observerEnrollmentRegistry: observerRegistry,
      physicalReceiptRegistry: receiptRuntime.registry,
      evidenceReceiptRegistry: evidenceRuntime.receiptRegistry,
      effectRegistry,
      evidenceRegistry: evidenceRuntime.registry,
    });
    const trustedLedgerInput = {
      version: 1,
      target_domain: targetDomain,
      plan,
      trustEnrollment,
      signerTrustRegistry: signerFixture.registry,
      observerEnrollmentRegistry: observerRegistry,
      physicalReceiptRegistry: receiptRuntime.registry,
      evidenceReceiptRegistry: evidenceRuntime.receiptRegistry,
      effectRegistry,
      evidenceRegistry: evidenceRuntime.registry,
    };
    let monotonicHeadOwner = null;
    if (ledgerMode === "production") {
      monotonicOwnerRoot = fs.mkdtempSync(
        path.join(os.tmpdir(), "bob-physical-experiment-monotonic-owner-"),
      );
      fs.chmodSync(monotonicOwnerRoot, 0o700);
      monotonicHeadOwner = openProductionPhysicalMonotonicOwner({
        version: 1,
        target_domain: targetDomain,
        session_nucleus_hash: session.nucleus.nucleus_hash,
        external_owner_root: monotonicOwnerRoot,
        context_domain: "hacker-bob/physical-experiment-row-head/v1",
      });
      trustedLedgerInput.monotonicHeadOwner = monotonicHeadOwner;
      if (options.restart_durable_clock === true) {
        trustedClockOwnerRoot = fs.mkdtempSync(
          path.join(os.tmpdir(), "bob-physical-trusted-clock-owner-"),
        );
        trustedClockAuthorityRoot = fs.mkdtempSync(
          path.join(os.tmpdir(), "bob-physical-trusted-clock-authority-"),
        );
        fs.chmodSync(trustedClockOwnerRoot, 0o700);
        fs.chmodSync(trustedClockAuthorityRoot, 0o700);
        trustedClockRuntime = installNonAuthorizingRestartDurableClock({
          targetDomain,
          sessionNucleusHash: session.nucleus.nucleus_hash,
          suffix,
          authorityRoot: trustedClockAuthorityRoot,
          ownerRoot: trustedClockOwnerRoot,
        });
        trustedLedgerInput.trustedClock = trustedClockRuntime.port;
      }
    }
    const ledger = ledgerMode === "production"
      ? createProductionPhysicalExperimentLedger(trustedLedgerInput)
      : createMechanismAPhysicalExperimentLedger(trustedLedgerInput);
    const conformanceLedger = createPhysicalExperimentLedger({
      plan,
      durableHeadPort: createConformanceDurableHeadPort(suffix),
      resolveSigner() {
        throw new Error("empty conformance ledger has no admitted signer rows");
      },
      verifySignature() { return false; },
      observerEnrollmentRegistry: observerRegistry,
      physicalReceiptRegistry: receiptRuntime.registry,
      evidenceReceiptRegistry: evidenceRuntime.receiptRegistry,
      trustedNow: () => iso(Date.now()),
      isSignerCurrentlyRevoked() { return false; },
      isObserverEnrollmentCurrentlyRevoked() { return false; },
      isEvidenceComponentCurrentlyRevoked() { return false; },
      effectRegistry,
      evidenceRegistry: evidenceRuntime.registry,
      resolveExecutedEvidenceVerification() { return null; },
      resolveVerifierExecutionReceipt() { return null; },
    });
    if (conformanceLedger.readiness().production_ready !== false) {
      throw new Error("physical verdict conformance ledger was unexpectedly promoted");
    }
    const positiveExecution = appendSignedRow({
      ledger,
      receiptRuntime,
      signerFixture,
      evidenceRuntime,
      rowKind: "execution_receipt",
      payload: executionPayload(
        receiptRuntime,
        ledger.plan,
        "positive",
        iso(timeline),
        iso(timeline + 100),
      ),
      signerKeyId: "signer-key:instrument",
      signedAt: iso(Date.now()),
    });
    const controlExecution = appendSignedRow({
      ledger,
      receiptRuntime,
      signerFixture,
      evidenceRuntime,
      rowKind: "execution_receipt",
      payload: executionPayload(
        receiptRuntime,
        ledger.plan,
        "control",
        iso(timeline + 200),
        iso(timeline + 300),
      ),
      signerKeyId: "signer-key:instrument",
      signedAt: iso(Date.now()),
    });
    const positiveObservation = appendSignedRow({
      ledger,
      receiptRuntime,
      signerFixture,
      evidenceRuntime,
      rowKind: "observation",
      payload: observationPayload(
        receiptRuntime,
        ledger.plan,
        "positive",
        positiveExecution.row_ref,
        iso(timeline + 400),
        iso(timeline + 450),
      ),
      signerKeyId: "signer-key:observer-a",
      signedAt: iso(Date.now()),
    });
    const controlObservation = appendSignedRow({
      ledger,
      receiptRuntime,
      signerFixture,
      evidenceRuntime,
      rowKind: "observation",
      payload: observationPayload(
        receiptRuntime,
        ledger.plan,
        "control",
        controlExecution.row_ref,
        iso(timeline + 500),
        iso(timeline + 550),
      ),
      signerKeyId: "signer-key:observer-b",
      signedAt: iso(Date.now()),
    });
    const claim = await createClaimPayload({
      evidenceRuntime,
      plan: ledger.plan,
      executions: [positiveExecution, controlExecution],
      observations: [positiveObservation, controlObservation],
      evidenceNow: iso(timeline + 700),
      decidedAt: iso(timeline + 900),
      validityKind,
      liveExpiresAt: validityKind === "live_capability"
        ? (options.live_expires_at || iso(now + 120_000))
        : null,
    });
    for (const receipt of claim.receipts) ledger.ingestEvidenceReceipt(receipt);
    const claimRow = appendSignedRow({
      ledger,
      receiptRuntime,
      signerFixture,
      evidenceRuntime,
      rowKind: "claim_verdict",
      payload: claim.payload,
      signerKeyId: "signer-key:verifier",
      signedAt: iso(Date.now()),
    });
    const issueProjection = options.issue_projection !== false;
    const projection = ledgerMode === "production" && issueProjection
      ? assertVerifiedPhysicalClaimProjection(ledger.projectVerifiedClaim())
      : null;
    const verdict = ledgerMode === "production" && issueProjection
      ? assertReportSafePhysicalVerdict(projectReportSafePhysicalVerdict(projection, {
        asset_locator: ledger.plan.target_asset_ref,
        session_nucleus_hash: session.nucleus.nucleus_hash,
        verified_verdict_ref: claimRow.row_ref,
      }))
      : null;
    const nonauthorizingClaimProjection = ledgerMode === "production"
      ? null
      : ledger.rebuildIndex().claim_projection;
    return Object.freeze({
      projection,
      verdict,
      ledger,
      nonauthorizing_claim_projection: nonauthorizingClaimProjection,
      conformance_ledger: conformanceLedger,
      target_domain: targetDomain,
      asset_locator: ledger.plan.target_asset_ref,
      verified_verdict_ref: claimRow.row_ref,
      monotonic_owner_root: monotonicOwnerRoot,
      monotonic_head_owner: monotonicHeadOwner,
      trusted_clock_owner_root: trustedClockOwnerRoot,
      trusted_clock_authority_root: trustedClockAuthorityRoot,
      trusted_clock: trustedClockRuntime?.port || null,
      reopen_production_ledger: ledgerMode === "production"
        ? () => {
          const reopenedOwner = openProductionPhysicalMonotonicOwner({
            version: 1,
            target_domain: targetDomain,
            session_nucleus_hash: session.nucleus.nucleus_hash,
            external_owner_root: monotonicOwnerRoot,
            context_domain: "hacker-bob/physical-experiment-row-head/v1",
          });
          return createProductionPhysicalExperimentLedger({
            ...trustedLedgerInput,
            monotonicHeadOwner: reopenedOwner,
            ...(trustedClockRuntime == null ? {} : {
              trustedClock: trustedClockRuntime.reopen(),
            }),
          });
        }
        : null,
      cleanup,
    });
  } catch (error) {
    cleanup();
    throw error;
  }
}

function createProductionPhysicalVerdictFixture(options = {}) {
  return createPhysicalVerdictFixture(options, "production");
}

function createMechanismAPhysicalExperimentFixture(options = {}) {
  return createPhysicalVerdictFixture(options, "mechanism_a");
}

module.exports = Object.freeze({
  createMechanismAPhysicalExperimentFixture,
  createProductionPhysicalVerdictFixture,
});
