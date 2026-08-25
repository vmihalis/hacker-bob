"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const {
  ZERO_HASH,
  attemptAllocationBindingDigest,
  buildPhysicalObserverEnrollmentRegistry,
  buildPhysicalExperimentSignerTrustRegistry,
  buildPhysicalReceiptTrustRegistry,
  consumptionAttestationInputDigest,
  createPhysicalAllocationIssuer,
  createPhysicalAppendIssuer,
  createPhysicalExperimentLedger,
  createMechanismAPhysicalExperimentLedger,
  createProductionPhysicalExperimentLedger,
  enrollProductionPhysicalExperimentTrust,
  createTestPhysicalExperimentDurableHeadPort,
  executionConsumptionBindingDigest,
  assertCurrentProductionPhysicalExperimentTrust,
  assertTestVerifiedPhysicalClaimProjection,
  assertVerifiedPhysicalClaimProjection,
  assertMechanismAPhysicalExperimentLedger,
  assertProductionPhysicalExperimentLedger,
  describeMechanismAPhysicalExperimentLedger,
  describeProductionPhysicalExperimentLedger,
  normalizePhysicalExperimentPlan,
  normalizePhysicalExperimentRowPayload,
  observerAttemptBindingDigest,
  observationConsumptionBindingDigest,
  rebuildPhysicalExperimentIndex,
  rowAuthorizationContextDigest,
  signatureInputDigest,
} = require("../mcp/domains/physical/physical-experiment-contract.js");
const {
  createProductionPhysicalVerdictResolverPort,
  installPhysicalVerdictResolver,
  resolvePhysicalVerdict,
} = require("../mcp/domains/physical/physical-verdict-runtime.js");
const {
  assertReportSafePhysicalVerdict,
} = require("../mcp/domains/physical/physical-capability-consumers.js");
const {
  buildSessionNucleus,
  normalizePhysicalScopeNucleusAxis,
} = require("../mcp/core/governance/index.js");
const { hashCanonicalJson } = require("../mcp/core/verification/verification-contracts.js");
const {
  buildDurableReceiptTrustRegistry,
  buildExecutedEvidenceRegistry,
  createDurableEvidenceReceiptIssuer,
} = require("../mcp/core/executed-evidence-registry.js");
const { buildEffectTemplateRegistry } = require("../mcp/core/requested-effects.js");
const {
  physicalSurfaceTransitionClaimPredicateDigest,
} = require("../mcp/domains/physical/physical-surface-transition.js");
const {
  createMechanismAPhysicalExperimentFixture,
  createProductionPhysicalVerdictFixture,
} = require("./helpers/production-physical-verdict.js");
const {
  SANDBOX_AGENT_UID_ENV,
  SANDBOX_ISOLATION_ACK_ENV,
  SANDBOX_ISOLATION_ACK_TOKEN,
  SANDBOX_SIGNER_UID_ENV,
} = require("../mcp/core/ledger-integrity/index.js");
const {
  ingestMechanismAPhysicalExperimentReceipt,
  openMechanismAPhysicalExperimentDurableHeadPort,
} = require("../mcp/domains/physical/physical-experiment-store.js");
const {
  PHYSICAL_EXPERIMENT_TRUST_PRIVATE_KEY_BASENAME,
} = require("../mcp/core/ledger-integrity/index.js");
const {
  compareAndSetPhysicalMonotonicOwnerState,
  readPhysicalMonotonicOwnerState,
} = require("../mcp/domains/physical/physical-monotonic-owner.js");
const {
  FIXED_SOURCE_BLOCKER,
} = require("../mcp/domains/physical/physical-trusted-clock-store.js");

function digest(value) {
  return crypto.createHash("sha256").update(String(value)).digest("hex");
}

const TRUST_REGISTRY_DIGEST = digest("immutable-trust-registry-snapshot");
const SOURCE_ROWS = new Map();
const SOURCE_CONTEXT = new Map();
const EVIDENCE_VERIFICATION_RECEIPTS = new Map();
const VERIFIER_EXECUTION_RECEIPTS = new Map();
const EVIDENCE_RECEIPTS_BY_SEMANTIC = new Map();
let PH_S10_CALLS = 0;
let PH_S10_CALLBACKS_ENABLED = true;

function componentCommon(name, implementationKind = "tool") {
  return {
    version: 1,
    owner_principal: `principal:${name}`,
    [`${implementationKind}_digest`]: digest(`${name}:${implementationKind}`),
    signed_verdict_type: "physical.transition.v1",
    trust_epoch: 9,
    trust_state: "trusted",
    attested_at: "2026-07-18T00:00:00.000Z",
    freshness_window_ms: 315_360_000_000,
    revoked: false,
  };
}

const EVIDENCE_REGISTRY = buildExecutedEvidenceRegistry({
  source_adapters: [{
    ...componentCommon("physical-observations", "artifact"),
    source_id: "physical.observations",
    ref_prefix: "physical-observation",
    resolve: async (ref) => {
      PH_S10_CALLS += 1;
      if (!PH_S10_CALLBACKS_ENABLED) throw new Error("PH-S10 callback should not run during deterministic rebuild");
      return SOURCE_ROWS.get(ref) || null;
    },
    reverify: async (row) => ({ version: 1, verified: true, verification_digest: digest(`reverify:${row.row_hash}`) }),
    project_integrity: (row) => ({
      payload_digest: row.envelope.payload_digest,
      implementation_digest: digest("physical-observations:artifact"),
      content_hash_valid: true,
    }),
    project_signer_trust: (row) => ({
      owner_principal: "principal:physical-observations",
      signer_key_id: row.envelope.signer_key_id,
      signed_verdict_type: "physical.transition.v1",
      trust_epoch: 9,
      signature_valid: true,
      trusted: true,
      revoked: false,
    }),
    project_execution_identity: (row) => row.payload.execution_identity,
    project_node_contract_digest: (row) => SOURCE_CONTEXT.get(row.row_ref).node_contract_digest,
    project_context_digest: (row) => SOURCE_CONTEXT.get(row.row_ref).context_digest,
    project_surfaces: () => ["surface:hotel-door-controller"],
    project_outcome: (row) => ({
      disposition: "verified",
      verdict_hash: row.row_hash,
      observed_at: row.payload.received_at,
    }),
    project_cleanup: () => ({ status: "not_required" }),
  }],
  context_resolvers: [{
    ...componentCommon("physical-experiment-context"),
    resolver_id: "physical.experiment-context",
    context_kind: "physical",
    resolve_context: async (request) => ({
      version: 1,
      execution_identity: request.execution_identity,
      node_contract_digest: request.node_contract_digest,
      context_digest: request.context_digest,
      surface_refs: ["surface:hotel-door-controller"],
      resolved_at: request.resolved_at,
    }),
  }],
  replay_executors: [{
    ...componentCommon("physical-experiment-bind"),
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
    ...componentCommon("physical-transition-template", "artifact"),
    template_id: "physical.transition-positive-control",
    template_version: 3,
    mode: "verified-verdict-bind",
    source_ids: ["physical.observations"],
    context_resolver_id: "physical.experiment-context",
    replay_executor_id: "physical.experiment-bind",
    dependency_provider_ids: [],
    decision_rule_digest: digest("decision-rule"),
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
const VERIFIER_TEMPLATE = EVIDENCE_REGISTRY.get(
  "verifier_templates",
  "physical.transition-positive-control",
);

function ed25519PemPair() {
  const pair = crypto.generateKeyPairSync("ed25519");
  return {
    publicKeyPem: pair.publicKey.export({ type: "spki", format: "pem" }),
    privateKeyPem: pair.privateKey.export({ type: "pkcs8", format: "pem" }),
  };
}

const PHYSICAL_RECEIPT_KEYS = ed25519PemPair();
const EVIDENCE_RECEIPT_KEYS = ed25519PemPair();
const SURFACE_TRANSITION_KEYS = ed25519PemPair();
const FIXTURE_TRUSTED_NOW = "2026-07-18T00:00:07.000Z";
const FIXTURE_EVIDENCE_NOW = "2026-07-18T00:00:05.000Z";
const FIXTURE_PHYSICAL_ISSUER_START = "2026-07-18T00:00:00.500Z";
let PHYSICAL_ISSUER_NOW = FIXTURE_PHYSICAL_ISSUER_START;
let EVIDENCE_ISSUER_NOW = FIXTURE_EVIDENCE_NOW;

const PHYSICAL_RECEIPT_REGISTRY = buildPhysicalReceiptTrustRegistry({
  version: 1,
  registry_id: "physical-durable-ledger",
  issuers: [{
    issuer_key_id: "signer-key:physical-ledger",
    issuer_epoch: 4,
    public_key_pem: PHYSICAL_RECEIPT_KEYS.publicKeyPem,
    valid_from: "2026-07-18T00:00:00.000Z",
    expires_at: "2036-07-19T00:00:00.000Z",
    trusted: true,
    revoked: false,
  }],
});

const EVIDENCE_RECEIPT_REGISTRY = buildDurableReceiptTrustRegistry({
  version: 1,
  registry_id: "physical-evidence-receipts",
  issuers: [{
    issuer_key_id: "signer-key:evidence-receipt",
    issuer_epoch: 5,
    signature_scheme: "ed25519",
    public_key_pem: EVIDENCE_RECEIPT_KEYS.publicKeyPem,
    receipt_kinds: ["executed_evidence_verification", "physical_verifier_execution"],
    valid_from: "2026-07-18T00:00:00.000Z",
    expires_at: "2036-07-19T00:00:00.000Z",
    trusted: true,
    revoked: false,
  }],
});

const SURFACE_TRANSITION_RECEIPT_REGISTRY = buildDurableReceiptTrustRegistry({
  version: 1,
  registry_id: "physical-surface-transition-receipts",
  issuers: [{
    issuer_key_id: "signer-key:surface-transition",
    issuer_epoch: 1,
    signature_scheme: "ed25519",
    public_key_pem: SURFACE_TRANSITION_KEYS.publicKeyPem,
    receipt_kinds: ["physical_surface_transition"],
    valid_from: "2026-07-18T00:00:00.000Z",
    expires_at: "2036-07-19T00:00:00.000Z",
    trusted: true,
    revoked: false,
  }],
});

const OBSERVER_ENROLLMENT_REGISTRY = buildPhysicalObserverEnrollmentRegistry([{
  observer_enrollment_ref: "observer-enrollment:positive",
  observer_identity_ref: "observer:positive",
  signer_key_id: "signer-key:observer-a",
  source_kind: "sensor",
  source_ref: "sensor:external-a",
  source_assurance_scheme: "signed-fixture-v1",
  trust_domain_ref: "trust-domain:observer-a",
  independence_domain_ref: "independence-domain:observer-a",
  external_outcome_allowed: true,
  valid_from: "2026-07-18T00:00:00.000Z",
  expires_at: "2036-07-19T00:00:00.000Z",
  revoked: false,
}, {
  observer_enrollment_ref: "observer-enrollment:control",
  observer_identity_ref: "observer:control",
  signer_key_id: "signer-key:observer-b",
  source_kind: "sensor",
  source_ref: "sensor:external-b",
  source_assurance_scheme: "signed-fixture-v1",
  trust_domain_ref: "trust-domain:observer-b",
  independence_domain_ref: "independence-domain:observer-b",
  external_outcome_allowed: true,
  valid_from: "2026-07-18T00:00:00.000Z",
  expires_at: "2036-07-19T00:00:00.000Z",
  revoked: false,
}]);

const UNIQUE_RESERVATIONS = new Map();
const ALLOCATED_SUBJECTS = new Map();
const CONSUMED_SUBJECTS = new Map();
const PHYSICAL_DURABLE_RECEIPTS = new Map();
const SURFACE_TRANSITION_RECEIPTS_BY_SEMANTIC = new Map();
const ALLOCATION_RECEIPTS = new Map();
const CONSUMPTION_RECEIPTS = new Map();
const APPEND_RESERVATIONS = new Map();
const APPEND_RECEIPTS = new Map();
let APPEND_JOURNAL_SEQUENCE = 0;

function reserveFixtureAppend({ append_binding_digest, append_request }) {
  const requestDigest = hashCanonicalJson(append_request);
  const existing = APPEND_RESERVATIONS.get(append_binding_digest);
  if (existing) {
    if (existing.request_digest !== requestDigest) {
      throw new Error("fixture append reservation binding collision");
    }
    return true;
  }
  APPEND_JOURNAL_SEQUENCE += 1;
  const reservation = {
    version: 1,
    append_binding_digest,
    journal_sequence: APPEND_JOURNAL_SEQUENCE,
  };
  reservation.reservation_digest = hashCanonicalJson({
    domain: "hacker-bob/physical-append-reservation-receipt/v1",
    ...reservation,
  });
  APPEND_RESERVATIONS.set(append_binding_digest, {
    request_digest: requestDigest,
    reservation,
  });
  return true;
}

function resolveFixtureAppendReservation({ append_binding_digest }) {
  const entry = APPEND_RESERVATIONS.get(append_binding_digest);
  return entry == null ? null : structuredClone(entry.reservation);
}

function commitFixtureAppendReceipt(receipt) {
  PHYSICAL_DURABLE_RECEIPTS.set(receipt.receipt_digest, receipt);
  APPEND_RECEIPTS.set(receipt.body.append_binding_digest, receipt);
  return true;
}

function resolveFixtureAppendReceipt({ append_binding_digest }) {
  return APPEND_RECEIPTS.get(append_binding_digest) || null;
}

const PHYSICAL_ALLOCATION_ISSUER = createPhysicalAllocationIssuer({
  registry: PHYSICAL_RECEIPT_REGISTRY,
  issuer_key_id: "signer-key:physical-ledger",
  issuer_epoch: 4,
  private_key_pem: PHYSICAL_RECEIPT_KEYS.privateKeyPem,
  now: () => PHYSICAL_ISSUER_NOW,
  reserve_unique_batch({ binding_digest, unique_keys, allocation }) {
    if (unique_keys.some((key) => UNIQUE_RESERVATIONS.has(key) && UNIQUE_RESERVATIONS.get(key) !== binding_digest)) {
      return false;
    }
    for (const key of unique_keys) UNIQUE_RESERVATIONS.set(key, binding_digest);
    for (const cohort of allocation.cohort_bindings) {
      ALLOCATED_SUBJECTS.set(cohort.grant_ref, allocation.attempt_id);
      for (const nonce of cohort.challenge_nonces) {
        ALLOCATED_SUBJECTS.set(`challenge:${nonce}`, allocation.attempt_id);
      }
    }
    return true;
  },
  consume_unique({ subject_ref, plan_hash, attempt_id, binding_digest }) {
    if (ALLOCATED_SUBJECTS.get(subject_ref) !== attempt_id) return false;
    const prior = CONSUMED_SUBJECTS.get(subject_ref);
    if (prior) {
      return prior.plan_hash === plan_hash
        && prior.attempt_id === attempt_id
        && prior.binding_digest === binding_digest;
    }
    CONSUMED_SUBJECTS.set(subject_ref, { plan_hash, attempt_id, binding_digest });
    return true;
  },
  resolve_allocation_receipt({ binding_digest }) {
    return ALLOCATION_RECEIPTS.get(binding_digest) || null;
  },
  resolve_consumption_receipt({ subject_ref }) {
    return CONSUMPTION_RECEIPTS.get(subject_ref) || null;
  },
  commit_receipt(receipt) {
    PHYSICAL_DURABLE_RECEIPTS.set(receipt.receipt_digest, receipt);
    if (receipt.kind === "attempt_allocation") {
      ALLOCATION_RECEIPTS.set(receipt.body.binding_digest, receipt);
    } else if (receipt.kind === "physical_consumption") {
      CONSUMPTION_RECEIPTS.set(receipt.body.subject_ref, receipt);
    }
    return true;
  },
});

const PHYSICAL_APPEND_ISSUER = createPhysicalAppendIssuer({
  registry: PHYSICAL_RECEIPT_REGISTRY,
  issuer_key_id: "signer-key:physical-ledger",
  issuer_epoch: 4,
  private_key_pem: PHYSICAL_RECEIPT_KEYS.privateKeyPem,
  now: () => FIXTURE_TRUSTED_NOW,
  reserve_append: reserveFixtureAppend,
  resolve_append_reservation: resolveFixtureAppendReservation,
  commit_receipt: commitFixtureAppendReceipt,
  resolve_append_receipt: resolveFixtureAppendReceipt,
});

function physicalAppendIssuerAt(timestamp) {
  return createPhysicalAppendIssuer({
    registry: PHYSICAL_RECEIPT_REGISTRY,
    issuer_key_id: "signer-key:physical-ledger",
    issuer_epoch: 4,
    private_key_pem: PHYSICAL_RECEIPT_KEYS.privateKeyPem,
    now: () => timestamp,
    reserve_append: reserveFixtureAppend,
    resolve_append_reservation: resolveFixtureAppendReservation,
    commit_receipt: commitFixtureAppendReceipt,
    resolve_append_receipt: resolveFixtureAppendReceipt,
  });
}

const EVIDENCE_RECEIPT_ISSUER = createDurableEvidenceReceiptIssuer({
  trust_registry: EVIDENCE_RECEIPT_REGISTRY,
  issuer_key_id: "signer-key:evidence-receipt",
  issuer_epoch: 5,
  private_key_pem: EVIDENCE_RECEIPT_KEYS.privateKeyPem,
  now: () => EVIDENCE_ISSUER_NOW,
  commit_receipt(receipt, binding) {
    EVIDENCE_RECEIPTS_BY_SEMANTIC.set(binding.semantic_digest, receipt);
    if (receipt.receipt_kind === "executed_evidence_verification") {
      EVIDENCE_VERIFICATION_RECEIPTS.set(receipt.receipt_ref, receipt);
    } else {
      VERIFIER_EXECUTION_RECEIPTS.set(receipt.receipt_ref, receipt);
    }
    return true;
  },
  resolve_committed_receipt({ semantic_digest }) {
    return EVIDENCE_RECEIPTS_BY_SEMANTIC.get(semantic_digest) || null;
  },
});

const SURFACE_TRANSITION_ISSUER = createDurableEvidenceReceiptIssuer({
  trust_registry: SURFACE_TRANSITION_RECEIPT_REGISTRY,
  issuer_key_id: "signer-key:surface-transition",
  issuer_epoch: 1,
  private_key_pem: SURFACE_TRANSITION_KEYS.privateKeyPem,
  now: () => "2026-07-18T00:00:07.500Z",
  commit_receipt(receipt, binding) {
    SURFACE_TRANSITION_RECEIPTS_BY_SEMANTIC.set(binding.semantic_digest, receipt);
    return true;
  },
  resolve_committed_receipt({ semantic_digest }) {
    return SURFACE_TRANSITION_RECEIPTS_BY_SEMANTIC.get(semantic_digest) || null;
  },
});

function resetDurableFixtureState() {
  UNIQUE_RESERVATIONS.clear();
  ALLOCATED_SUBJECTS.clear();
  CONSUMED_SUBJECTS.clear();
  PHYSICAL_DURABLE_RECEIPTS.clear();
  ALLOCATION_RECEIPTS.clear();
  CONSUMPTION_RECEIPTS.clear();
  APPEND_RESERVATIONS.clear();
  APPEND_RECEIPTS.clear();
  EVIDENCE_VERIFICATION_RECEIPTS.clear();
  VERIFIER_EXECUTION_RECEIPTS.clear();
  EVIDENCE_RECEIPTS_BY_SEMANTIC.clear();
  SURFACE_TRANSITION_RECEIPTS_BY_SEMANTIC.clear();
  SOURCE_ROWS.clear();
  SOURCE_CONTEXT.clear();
  APPEND_JOURNAL_SEQUENCE = 0;
  PH_S10_CALLS = 0;
  PH_S10_CALLBACKS_ENABLED = true;
  PHYSICAL_ISSUER_NOW = FIXTURE_PHYSICAL_ISSUER_START;
  EVIDENCE_ISSUER_NOW = FIXTURE_EVIDENCE_NOW;
}

test.beforeEach(resetDurableFixtureState);

const EFFECT_REGISTRY = buildEffectTemplateRegistry([{
  version: 1,
  template_id: "target.credential-present",
  subject_kind: "target",
  action: "present",
  channel: "rf",
  persistence: "ephemeral",
  bounds: {
    duration_ms: { kind: "integer", required: true, min: 1, max: 5000 },
    carrier: { kind: "enum", required: true, values: ["hf", "lf"] },
  },
}]);
const EFFECT_TEMPLATE = EFFECT_REGISTRY.get("target.credential-present");

function effectFixture() {
  return {
    version: 1,
    template_id: "target.credential-present",
    template_digest: EFFECT_TEMPLATE.template_digest,
    subject_ref: "target:hotel-door-controller",
    subject_kind: "target",
    action: "present",
    channel: "rf",
    persistence: "ephemeral",
    bounds: { duration_ms: 750, carrier: "hf" },
  };
}

function assuranceClaims() {
  const body = {
    identity_enrollment: digest("identity-enrollment"),
    firmware_provenance: digest("firmware-provenance"),
    command_surface_conformance: digest("command-surface-conformance"),
    transport_trust: digest("transport-trust"),
  };
  return { ...body, claims_digest: hashCanonicalJson(body) };
}

const SIGNERS = Object.freeze({
  "signer-key:instrument": Object.freeze({
    signer_principal_ref: "principal:instrument-worker",
    trust_domain_ref: "trust-domain:instrument",
    independence_domain_ref: "independence-domain:instrument-controller",
    instrument_identity_ref: "instrument-identity:chameleon-ultra-1",
    allowed_row_kinds: ["execution_receipt"],
  }),
  "signer-key:observer-a": Object.freeze({
    signer_principal_ref: "principal:observer-a",
    trust_domain_ref: "trust-domain:observer-a",
    independence_domain_ref: "independence-domain:observer-a",
    observer_identity_ref: "observer:positive",
    allowed_row_kinds: ["observation"],
  }),
  "signer-key:observer-b": Object.freeze({
    signer_principal_ref: "principal:observer-b",
    trust_domain_ref: "trust-domain:observer-b",
    independence_domain_ref: "independence-domain:observer-b",
    observer_identity_ref: "observer:control",
    allowed_row_kinds: ["observation"],
  }),
  "signer-key:verifier": Object.freeze({
    signer_principal_ref: "principal:physical-verifier",
    trust_domain_ref: "trust-domain:verifier",
    independence_domain_ref: "independence-domain:verifier",
    allowed_row_kinds: ["claim_verdict"],
  }),
  "signer-key:cleanup": Object.freeze({
    signer_principal_ref: "principal:cleanup-worker",
    trust_domain_ref: "trust-domain:cleanup",
    independence_domain_ref: "independence-domain:cleanup",
    allowed_row_kinds: ["cleanup_verdict"],
  }),
  "signer-key:same-domain": Object.freeze({
    signer_principal_ref: "principal:instrument-observer",
    trust_domain_ref: "trust-domain:instrument",
    independence_domain_ref: "independence-domain:instrument-controller",
    observer_identity_ref: "observer:positive",
    allowed_row_kinds: ["observation"],
  }),
  "signer-key:same-trust-independent": Object.freeze({
    signer_principal_ref: "principal:same-trust-independent-observer",
    trust_domain_ref: "trust-domain:instrument",
    independence_domain_ref: "independence-domain:observer-a",
    observer_identity_ref: "observer:positive",
    allowed_row_kinds: ["observation"],
  }),
  "signer-key:same-independence": Object.freeze({
    signer_principal_ref: "principal:same-independence-observer",
    trust_domain_ref: "trust-domain:observer-a",
    independence_domain_ref: "independence-domain:instrument-controller",
    observer_identity_ref: "observer:positive",
    allowed_row_kinds: ["observation"],
  }),
});

function productionSignerFixture() {
  const privateKeys = new Map();
  const definitions = Object.entries(SIGNERS)
    .filter(([signerKeyId]) => [
      "signer-key:instrument",
      "signer-key:observer-a",
      "signer-key:observer-b",
      "signer-key:verifier",
      "signer-key:cleanup",
    ].includes(signerKeyId))
    .map(([signerKeyId, signer]) => {
      const keys = ed25519PemPair();
      privateKeys.set(signerKeyId, keys.privateKeyPem);
      return {
        signer_key_id: signerKeyId,
        signer_principal_ref: signer.signer_principal_ref,
        signature_scheme: "ed25519",
        public_key_pem: keys.publicKeyPem,
        trust_root_epoch: 9,
        trust_domain_ref: signer.trust_domain_ref,
        independence_domain_ref: signer.independence_domain_ref,
        allowed_row_kinds: signer.allowed_row_kinds,
        valid_from: "2026-07-01T00:00:00.000Z",
        expires_at: "2036-07-01T00:00:00.000Z",
        trusted: true,
        revoked: false,
        ...(signer.instrument_identity_ref == null
          ? {}
          : { instrument_identity_ref: signer.instrument_identity_ref }),
        ...(signer.observer_identity_ref == null
          ? {}
          : { observer_identity_ref: signer.observer_identity_ref }),
      };
    });
  const registry = buildPhysicalExperimentSignerTrustRegistry({
    version: 1,
    registry_id: "physical-production-signers",
    signers: definitions,
  });
  const byKey = Object.fromEntries(registry.describe().map((descriptor) => [
    descriptor.signer_key_id,
    {
      ...SIGNERS[descriptor.signer_key_id],
      trust_root_epoch: descriptor.trust_root_epoch,
      signer_enrollment_digest: descriptor.signer_enrollment_digest,
    },
  ]));
  return {
    registry,
    signers: Object.freeze(byKey),
    sign({ signatureInput, signerKeyId }) {
      return crypto.sign(
        null,
        Buffer.from(signatureInput, "hex"),
        privateKeys.get(signerKeyId),
      ).toString("base64url");
    },
  };
}

function installProductionPhysicalSession(domain) {
  const physicalScope = normalizePhysicalScopeNucleusAxis({
    version: 1,
    physical_enabled: true,
    policy_version: 1,
    policy_id: "physical_experiment_fixture",
    policy_digest: digest("physical-production-policy"),
    projection_version: 1,
    projection_digest: digest("physical-production-projection"),
    provenance_digest: digest("physical-production-provenance"),
    compatibility_digest: digest("physical-production-compatibility"),
    transition_receipt_registry_digest: digest("physical-transition-registry"),
    authority_epoch: 1,
    revocation_generation: 0,
  });
  const nucleus = buildSessionNucleus({
    target_domain: domain,
    target_url: `https://${domain}`,
    scope_policy: {
      target_domain: domain,
      target_url: `https://${domain}`,
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
  const directory = path.join(os.homedir(), "hacker-bob-sessions", domain);
  fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
  fs.writeFileSync(
    path.join(directory, "session-nucleus.json"),
    `${JSON.stringify(nucleus, null, 2)}\n`,
    { encoding: "utf8", mode: 0o600 },
  );
  return { nucleus, directory };
}

async function withProductionHome(callback) {
  const priorHome = process.env.HOME;
  const priorIsolation = {
    ack: process.env[SANDBOX_ISOLATION_ACK_ENV],
    signer: process.env[SANDBOX_SIGNER_UID_ENV],
    agent: process.env[SANDBOX_AGENT_UID_ENV],
  };
  const signerUid = typeof process.getuid === "function" ? process.getuid() : null;
  if (signerUid == null || signerUid === 0) {
    throw new Error("production structural Mechanism-A fixture requires a non-root uid");
  }
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-physical-production-ledger-"));
  process.env.HOME = home;
  // Structural Mechanism-A harness only: the real production constructor and
  // live owner probe run unchanged. No brand/boolean/callback is injected.
  process.env[SANDBOX_ISOLATION_ACK_ENV] = SANDBOX_ISOLATION_ACK_TOKEN;
  process.env[SANDBOX_SIGNER_UID_ENV] = String(signerUid);
  process.env[SANDBOX_AGENT_UID_ENV] = String(signerUid + 1);
  try {
    return await callback(home);
  } finally {
    if (priorHome === undefined) delete process.env.HOME;
    else process.env.HOME = priorHome;
    for (const [field, envName] of [
      [priorIsolation.ack, SANDBOX_ISOLATION_ACK_ENV],
      [priorIsolation.signer, SANDBOX_SIGNER_UID_ENV],
      [priorIsolation.agent, SANDBOX_AGENT_UID_ENV],
    ]) {
      if (field === undefined) delete process.env[envName];
      else process.env[envName] = field;
    }
    fs.rmSync(home, { recursive: true, force: true });
  }
}

let DURABLE_HEAD_PORT_ORDINAL = 0;

function createDurableHeadFixture({ loseNextCompareAcknowledgement = false } = {}) {
  DURABLE_HEAD_PORT_ORDINAL += 1;
  const heads = new Map();
  const commits = new Map();
  let compareCalls = 0;
  let loseNext = loseNextCompareAcknowledgement;
  let beforeNextCompare = null;
  const port = createTestPhysicalExperimentDurableHeadPort({
    version: 1,
    port_id: `physical-ledger-head-port:test-${DURABLE_HEAD_PORT_ORDINAL}`,
    test_only: true,
    consistency_model: "linearizable_compare_and_append",
    compare_and_append(command) {
      compareCalls += 1;
      const beforeCompare = beforeNextCompare;
      beforeNextCompare = null;
      if (beforeCompare) beforeCompare();
      const commitKey = `${command.plan_hash}:${command.row_commit_digest}`;
      const existing = commits.get(commitKey);
      if (existing) return hashCanonicalJson(existing) === hashCanonicalJson(command);
      const head = heads.get(command.plan_hash) || null;
      const currentSequence = head == null ? 0 : head.expected_sequence;
      const currentRowDigest = head == null ? ZERO_HASH : head.row_digest;
      if (command.expected_sequence !== currentSequence + 1
          || command.previous_row_hash !== currentRowDigest) return false;
      const committed = structuredClone(command);
      commits.set(commitKey, committed);
      heads.set(command.plan_hash, committed);
      if (loseNext) {
        loseNext = false;
        throw new Error("lost durable head compare-and-append acknowledgement");
      }
      return true;
    },
    read_head({ plan_hash }) {
      const head = heads.get(plan_hash);
      return head == null ? null : structuredClone(head);
    },
    resolve_committed_append({ plan_hash, row_commit_digest }) {
      const committed = commits.get(`${plan_hash}:${row_commit_digest}`);
      return committed == null ? null : structuredClone(committed);
    },
  });
  return {
    port,
    get compareCalls() { return compareCalls; },
    get committedCount() { return commits.size; },
    beforeNextCompare(callback) { beforeNextCompare = callback; },
    loseNextCompareAcknowledgement() { loseNext = true; },
  };
}

function trustDeps(overrides = {}) {
  const signers = overrides.signers || SIGNERS;
  const durableHeadPort = overrides.durableHeadPort || createDurableHeadFixture().port;
  return {
    resolveSigner({
      signer_key_id,
      trust_root_epoch,
      trust_registry_digest,
      authorization_context_digest,
      authorization_context,
    }) {
      const signer = signers[signer_key_id];
      if (!signer) throw new Error(`unknown signer ${signer_key_id}`);
      if (trust_registry_digest !== TRUST_REGISTRY_DIGEST) throw new Error("unknown trust snapshot");
      if (hashCanonicalJson(authorization_context) !== authorization_context_digest) {
        throw new Error("authorization context digest drift");
      }
      if (
        authorization_context.row_kind === "execution_receipt"
        && authorization_context.binding.instrument_identity_ref !== signer.instrument_identity_ref
      ) throw new Error("signer is not assigned to this instrument identity");
      if (
        authorization_context.row_kind === "observation"
        && authorization_context.binding.observer_identity_ref !== signer.observer_identity_ref
      ) throw new Error("signer is not assigned to this observer identity");
      return {
        signer_principal_ref: signer.signer_principal_ref,
        trust_domain_ref: signer.trust_domain_ref,
        independence_domain_ref: signer.independence_domain_ref,
        trust_root_epoch,
        trust_registry_digest,
        signer_enrollment_digest: digest(`enrollment:${signer_key_id}`),
        authorization_context_digest,
        allowed_row_kinds: signer.allowed_row_kinds,
        trusted: true,
        revoked: false,
      };
    },
    verifySignature({ signature_input_digest, envelope }) {
      return envelope.signature === digest(`${signature_input_digest}:${envelope.signer_key_id}`);
    },
    observerEnrollmentRegistry: overrides.observerEnrollmentRegistry || OBSERVER_ENROLLMENT_REGISTRY,
    physicalReceiptRegistry: overrides.physicalReceiptRegistry || PHYSICAL_RECEIPT_REGISTRY,
    evidenceReceiptRegistry: overrides.evidenceReceiptRegistry || EVIDENCE_RECEIPT_REGISTRY,
    durableHeadPort,
    trustedNow: overrides.trustedNow || (() => FIXTURE_TRUSTED_NOW),
    isSignerCurrentlyRevoked: overrides.isSignerCurrentlyRevoked || (() => false),
    isObserverEnrollmentCurrentlyRevoked: overrides.isObserverEnrollmentCurrentlyRevoked || (() => false),
    isEvidenceComponentCurrentlyRevoked: overrides.isEvidenceComponentCurrentlyRevoked || (() => false),
    effectRegistry: overrides.effectRegistry || EFFECT_REGISTRY,
    evidenceRegistry: overrides.evidenceRegistry || EVIDENCE_REGISTRY,
    resolveExecutedEvidenceVerification({ verification_receipt_ref }) {
      return EVIDENCE_VERIFICATION_RECEIPTS.get(verification_receipt_ref) || null;
    },
    resolveVerifierExecutionReceipt({ receipt_ref }) {
      return VERIFIER_EXECUTION_RECEIPTS.get(receipt_ref) || null;
    },
  };
}

function planDeps(overrides = {}) {
  return {
    observerEnrollmentRegistry: overrides.observerEnrollmentRegistry || OBSERVER_ENROLLMENT_REGISTRY,
    physicalReceiptRegistry: overrides.physicalReceiptRegistry || PHYSICAL_RECEIPT_REGISTRY,
    evidenceReceiptRegistry: overrides.evidenceReceiptRegistry || EVIDENCE_RECEIPT_REGISTRY,
    trustedNow: overrides.trustedNow || FIXTURE_TRUSTED_NOW,
  };
}

function normalizePlan(input, overrides = {}) {
  return normalizePhysicalExperimentPlan(input, "physical_experiment_plan", planDeps(overrides));
}

function observerPlan(kind, overrides = {}) {
  const suffix = kind === "positive" ? "a" : "b";
  return {
    observer_id: `${kind}-observer`,
    observer_identity_ref: `observer:${kind}`,
    observer_enrollment_ref: `observer-enrollment:${kind}`,
    source_kind: "sensor",
    source_ref: `sensor:external-${suffix}`,
    source_assurance_scheme: "signed-fixture-v1",
    required_trust_domain_ref: `trust-domain:observer-${suffix}`,
    required_independence_domain_ref: `independence-domain:observer-${suffix}`,
    challenge_nonce: kind === "positive"
      ? "AAAAAAAAAAAAAAAAAAAAAA"
      : "BBBBBBBBBBBBBBBBBBBBBB",
    attempt_binding_digest: digest(`${kind}:placeholder-binding`),
    external_outcome: true,
    ...overrides,
  };
}

function planFixture(overrides = {}, options = {}) {
  const observerRegistry = options.observerEnrollmentRegistry || OBSERVER_ENROLLMENT_REGISTRY;
  const positiveOutcome = overrides.expected_positive_outcome_digest || digest("accepted");
  const controlOutcome = overrides.expected_control_outcome_digest || digest("denied");
  const base = {
    version: 1,
    experiment_id: "credential-replay-differential",
    task_id: "PH-TASK-1",
    attempt_id: "attempt-1",
    session_nucleus_hash: digest("session-nucleus"),
    node_id: "PH-C3",
    contract_hash: digest("node-contract"),
    execution_request_digest: digest("execution-request"),
    hypothesis_ref: "hypothesis:controlled-transition",
    claim_predicate_digest: digest("claim-predicate"),
    expected_positive_outcome_digest: positiveOutcome,
    expected_control_outcome_digest: controlOutcome,
    verifier_template_id: "physical.transition-positive-control",
    verifier_template_version: 3,
    verifier_template_digest: VERIFIER_TEMPLATE.template_digest,
    decision_rule_digest: digest("decision-rule"),
    observation_window: {
      start_rule: "execution_ended",
      max_duration_ms: 10_000,
      max_clock_offset_abs_ms: 60_000,
      max_clock_uncertainty_ms: 250,
    },
    retry_policy: {
      fresh_attempt_and_challenge: true,
      max_attempts: 3,
      retry_on: ["transport_failure", "inconclusive"],
    },
    trust_registry_digest: TRUST_REGISTRY_DIGEST,
    executed_evidence_registry_digest: EVIDENCE_REGISTRY.registry_digest,
    evidence_receipt_registry_digest: EVIDENCE_RECEIPT_REGISTRY.registry_digest,
    evidence_receipt_issuer_key_id: "signer-key:evidence-receipt",
    evidence_receipt_issuer_epoch: 5,
    observer_enrollment_registry_digest: observerRegistry.registry_digest,
    physical_receipt_registry_digest: PHYSICAL_RECEIPT_REGISTRY.registry_digest,
    allocation_issuer_key_id: "signer-key:physical-ledger",
    allocation_issuer_epoch: 4,
    append_issuer_key_id: "signer-key:physical-ledger",
    append_issuer_epoch: 4,
    attempt_allocation_receipt: null,
    ingestion_policy: { max_future_skew_ms: 250, max_ingestion_delay_ms: 10_000 },
    consumption_registry_digest: PHYSICAL_RECEIPT_REGISTRY.registry_digest,
    consumption_issuer_key_id: "signer-key:physical-ledger",
    consumption_issuer_epoch: 4,
    instrument_ref: "instrument:chameleon-ultra-1",
    instrument_identity_ref: "instrument-identity:chameleon-ultra-1",
    instrument_inventory_ref: "inventory:chameleon-ultra-1",
    assurance_profile_id: "chameleon-ultra-enrolled-v1",
    instrument_assurance_claims: assuranceClaims(),
    provider_manifest_digest: digest("provider-manifest"),
    source_asset_ref: "source:credential-fixture",
    target_asset_ref: "target:hotel-door-controller",
    operation_id: "hf.credential-present",
    parameter_digest: digest("operation-parameters"),
    requested_effects_registry_digest: EFFECT_REGISTRY.registry_digest,
    requested_effects: [effectFixture()],
    requested_effects_digest: hashCanonicalJson([effectFixture()]),
    positive_cohort: {
      kind: "positive",
      stimulus_plan_ref: "stimulus-plan:positive",
      stimulus_plan_digest: digest("positive-stimulus-plan"),
      cohort_execution_request_digest: digest("positive-execution-request"),
      grant_ref: "grant:positive",
      execution_identity: "execution:positive",
      expected_outcome_digest: positiveOutcome,
      observer_plan: [observerPlan("positive")],
    },
    control_cohort: {
      kind: "control",
      stimulus_plan_ref: "stimulus-plan:control",
      stimulus_plan_digest: digest("control-stimulus-plan"),
      cohort_execution_request_digest: digest("control-execution-request"),
      grant_ref: "grant:control",
      execution_identity: "execution:control",
      expected_outcome_digest: controlOutcome,
      observer_plan: [observerPlan("control")],
    },
    controls: [{
      kind: "negative",
      plan_ref: "stimulus-plan:control",
      plan_digest: digest("control-stimulus-plan"),
    }],
    cleanup_plan_digest: digest("cleanup-plan"),
  };
  const merged = { ...base, ...overrides };
  for (const cohortField of ["positive_cohort", "control_cohort"]) {
    const kind = cohortField === "positive_cohort" ? "positive" : "control";
    const cohort = merged[cohortField];
    merged[cohortField] = {
      ...cohort,
      observer_plan: cohort.observer_plan.map((observer) => {
        const enrollment = observerRegistry.get(observer.observer_enrollment_ref);
        const binding = observerAttemptBindingDigest({
          session_nucleus_hash: merged.session_nucleus_hash,
          experiment_id: merged.experiment_id,
          task_id: merged.task_id,
          attempt_id: merged.attempt_id,
          execution_request_digest: merged.execution_request_digest,
          cohort_kind: kind,
          cohort_execution_request_digest: cohort.cohort_execution_request_digest,
          stimulus_plan_ref: cohort.stimulus_plan_ref,
          stimulus_plan_digest: cohort.stimulus_plan_digest,
          observer_enrollment_digest: enrollment && enrollment.enrollment_digest,
          signer_key_id: enrollment && enrollment.signer_key_id,
          ...observer,
        });
        return { ...observer, attempt_binding_digest: binding };
      }),
    };
  }
  if (overrides.attempt_allocation_receipt == null) {
    const allocationBody = {
      version: 1,
      session_nucleus_hash: merged.session_nucleus_hash,
      experiment_id: merged.experiment_id,
      task_id: merged.task_id,
      attempt_id: merged.attempt_id,
      execution_request_digest: merged.execution_request_digest,
      cohort_bindings: [merged.positive_cohort, merged.control_cohort].map((cohort) => ({
        cohort_kind: cohort.kind,
        cohort_execution_request_digest: cohort.cohort_execution_request_digest,
        grant_ref: cohort.grant_ref,
        execution_identity: cohort.execution_identity,
        challenge_nonces: cohort.observer_plan.map((observer) => observer.challenge_nonce).sort(),
      })),
    };
    allocationBody.binding_digest = attemptAllocationBindingDigest(allocationBody);
    merged.attempt_allocation_receipt = PHYSICAL_ALLOCATION_ISSUER.issueAttemptAllocation(allocationBody);
  }
  return merged;
}

function rowEnvelope(rowKind, payload, plan, signerKeyId, sequence, previousRowHash, options = {}) {
  const normalizedPayload = normalizePhysicalExperimentRowPayload(rowKind, payload, plan);
  const signer = options.signers?.[signerKeyId] || SIGNERS[signerKeyId];
  const payloadDigest = hashCanonicalJson(normalizedPayload);
  const authorizationContextDigest = rowAuthorizationContextDigest(rowKind, normalizedPayload, plan);
  const signedAt = options.signedAt || FIXTURE_TRUSTED_NOW;
  const appendIssuer = options.appendIssuer || PHYSICAL_APPEND_ISSUER;
  const envelope = {
    version: 1,
    signer_key_id: signerKeyId,
    signer_principal_ref: signer.signer_principal_ref,
    signature_scheme: "ed25519",
    trust_root_epoch: signer.trust_root_epoch || 9,
    trust_domain_ref: signer.trust_domain_ref,
    independence_domain_ref: signer.independence_domain_ref,
    trust_registry_digest: plan.trust_registry_digest,
    signer_enrollment_digest: signer.signer_enrollment_digest || digest(`enrollment:${signerKeyId}`),
    authorization_context_digest: authorizationContextDigest,
    sequence,
    previous_row_hash: previousRowHash,
    payload_digest: payloadDigest,
    signed_at: signedAt,
  };
  envelope.append_receipt = appendIssuer.issueAppend({
    version: 1,
    plan_hash: plan.plan_hash,
    row_kind: rowKind,
    payload_digest: payloadDigest,
    expected_sequence: sequence,
    previous_row_hash: previousRowHash,
    authorization_context_digest: authorizationContextDigest,
    signed_at: signedAt,
  });
  const signatureInput = signatureInputDigest(rowKind, payloadDigest, envelope);
  const signature = typeof options.sign === "function"
    ? options.sign({ signatureInput, signerKeyId, envelope })
    : digest(`${signatureInput}:${signerKeyId}`);
  return {
    version: 1,
    row_kind: rowKind,
    payload: normalizedPayload,
    envelope: {
      ...envelope,
      signature,
    },
  };
}

function appendSigned(ledger, rowKind, payload, signerKeyId, {
  previousRowHash,
  signedAt,
  appendIssuer,
  signers,
  sign,
} = {}) {
  const rows = ledger.rows();
  const row = rowEnvelope(
    rowKind,
    payload,
    ledger.plan,
    signerKeyId,
    rows.length + 1,
    previousRowHash == null ? (rows.at(-1)?.row_hash || ZERO_HASH) : previousRowHash,
    { signedAt, appendIssuer, signers, sign },
  );
  const appended = ledger.append(row).row;
  if (rowKind === "observation") {
    SOURCE_ROWS.set(appended.row_ref, appended);
    SOURCE_CONTEXT.set(appended.row_ref, {
      node_contract_digest: ledger.plan.contract_hash,
      context_digest: ledger.plan.plan_hash,
    });
  }
  return appended;
}

function resignEnvelope(row, signerKeyId, changes) {
  const copy = structuredClone(row);
  copy.envelope = { ...copy.envelope, ...changes };
  const signatureInput = signatureInputDigest(
    copy.row_kind,
    copy.envelope.payload_digest,
    copy.envelope,
  );
  copy.envelope.signature = digest(`${signatureInput}:${signerKeyId}`);
  delete copy.row_hash;
  delete copy.row_ref;
  return copy;
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

function consumptionAttestation(plan, kind, bindingDigest, subjectRef, sequence, consumedAt, overrides = {}) {
  if (Date.parse(consumedAt) > Date.parse(PHYSICAL_ISSUER_NOW)) PHYSICAL_ISSUER_NOW = consumedAt;
  return PHYSICAL_ALLOCATION_ISSUER.issueConsumption({
    version: 1,
    kind,
    binding_digest: bindingDigest,
    subject_ref: subjectRef,
    consumption_ref: `consumption:${kind}-${sequence}-${bindingDigest.slice(0, 16)}`,
    plan_hash: plan.plan_hash,
    attempt_id: plan.attempt_id,
    sequence,
    consumed_at: consumedAt,
    ...overrides,
  });
}

function executionPayload(plan, cohortKind, overrides = {}) {
  const second = cohortKind === "control" ? 2 : 0;
  const cohort = cohortKind === "positive" ? plan.positive_cohort : plan.control_cohort;
  const base = {
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
    started_at: `2026-07-18T00:00:0${second}.000Z`,
    ended_at: `2026-07-18T00:00:0${second + 1}.000Z`,
    stimulus_artifact_ref: `artifact:v1:${cohortKind}-stimulus`,
  };
  const merged = { ...base, ...overrides };
  const binding = executionConsumptionBindingDigest(
    plan,
    cohort,
    merged.grant_ref,
    merged.execution_identity,
  );
  if (overrides.consumption_attestation == null) {
    merged.consumption_attestation = consumptionAttestation(
      plan,
      "grant",
      binding,
      merged.grant_ref,
      cohortKind === "positive" ? 1 : 2,
      merged.started_at,
    );
  }
  return merged;
}

function observationPayload(plan, cohortKind, executionReceiptRef, overrides = {}) {
  const observer = cohortKind === "positive"
    ? plan.positive_cohort.observer_plan[0]
    : plan.control_cohort.observer_plan[0];
  const second = cohortKind === "control" ? 4 : 2;
  const base = {
    ...commonPayload(plan),
    cohort_kind: cohortKind,
    execution_receipt_ref: executionReceiptRef,
    grant_ref: cohortKind === "positive" ? plan.positive_cohort.grant_ref : plan.control_cohort.grant_ref,
    execution_identity: cohortKind === "positive"
      ? plan.positive_cohort.execution_identity
      : plan.control_cohort.execution_identity,
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
    observed_outcome_digest: cohortKind === "positive"
      ? plan.expected_positive_outcome_digest
      : plan.expected_control_outcome_digest,
    observed_state_digest: digest(`${cohortKind}:state`),
    artifact_ref: `artifact:v1:${cohortKind}-observation`,
    captured_at: `2026-07-18T00:00:0${second}.000Z`,
    received_at: `2026-07-18T00:00:0${second}.100Z`,
    clock_offset_ms: 0,
    clock_uncertainty_ms: 50,
  };
  const merged = { ...base, ...overrides };
  const binding = observationConsumptionBindingDigest(plan, observer, merged, merged.replay_guard);
  if (overrides.consumption_attestation == null) {
    merged.consumption_attestation = consumptionAttestation(
      plan,
      merged.replay_guard.kind,
      binding,
      merged.replay_guard.kind === "one_time_challenge"
        ? `challenge:${observer.challenge_nonce}`
        : `monotonic:${observer.observer_enrollment_ref}`,
      cohortKind === "positive" ? 1 : 2,
      new Date(Date.parse(merged.captured_at) + merged.clock_offset_ms).toISOString(),
    );
  }
  return merged;
}

async function evidenceRef(plan, observation, receipt, evidenceNow = FIXTURE_EVIDENCE_NOW) {
  if (Date.parse(evidenceNow) > Date.parse(EVIDENCE_ISSUER_NOW)) EVIDENCE_ISSUER_NOW = evidenceNow;
  const source = EVIDENCE_REGISTRY.get("source_adapters", "physical.observations");
  const executedEvidenceRef = {
    version: 1,
    source_id: "physical.observations",
    source_adapter_digest: source.adapter_digest,
    evidence_ref: observation.row_ref,
    expected_payload_digest: observation.envelope.payload_digest,
    expected_verdict_hash: observation.row_hash,
    execution_identity: receipt.payload.execution_identity,
    node_contract_digest: plan.contract_hash,
    context_digest: plan.plan_hash,
  };
  const resolver = EVIDENCE_REGISTRY.get("context_resolvers", "physical.experiment-context");
  const executor = EVIDENCE_REGISTRY.get("replay_executors", "physical.experiment-bind");
  const verificationReceipt = await EVIDENCE_RECEIPT_ISSUER.issueExecutedEvidence({
    evidence_registry: EVIDENCE_REGISTRY,
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
        resolved_at: evidenceNow,
      },
      replay_executor_ref: {
        executor_id: executor.executor_id,
        executor_digest: executor.executor_digest,
      },
      verifier_template_ref: {
        template_id: VERIFIER_TEMPLATE.template_id,
        template_version: VERIFIER_TEMPLATE.template_version,
        template_digest: VERIFIER_TEMPLATE.template_digest,
      },
      dependency_proof_refs: [],
    },
    verification_deps: {
      now: evidenceNow,
      isTrustEpochTrusted: () => true,
      isComponentRevoked: () => false,
    },
  });
  return {
    version: 1,
    executed_evidence_ref: executedEvidenceRef,
    verification_receipt_ref: verificationReceipt.receipt_ref,
    verification_receipt_digest: verificationReceipt.receipt_digest,
  };
}

async function claimPayload(plan, receipts, observations, {
  outcome = "verified",
  reasonCode = "differential_verified",
  positiveEvidence = null,
  controlEvidence = null,
  decidedAt = "2026-07-18T00:00:06.000Z",
  evidenceNow = FIXTURE_EVIDENCE_NOW,
} = {}) {
  const positiveReceipt = receipts.find((row) => row.payload.cohort_kind === "positive");
  const controlReceipt = receipts.find((row) => row.payload.cohort_kind === "control");
  const positiveObservation = observations.find((row) => row.payload.cohort_kind === "positive");
  const controlObservation = observations.find((row) => row.payload.cohort_kind === "control");
  const positiveBindings = positiveEvidence == null && positiveObservation
    ? [await evidenceRef(plan, positiveObservation, positiveReceipt, evidenceNow)]
    : (positiveEvidence || []);
  const controlBindings = controlEvidence == null && controlObservation
    ? [await evidenceRef(plan, controlObservation, controlReceipt, evidenceNow)]
    : (controlEvidence || []);
  const verifierReceiptBody = {
    version: 1,
    registry_digest: plan.executed_evidence_registry_digest,
    plan_hash: plan.plan_hash,
    verifier_template_id: plan.verifier_template_id,
    verifier_template_version: plan.verifier_template_version,
    verifier_template_digest: plan.verifier_template_digest,
    decision_rule_digest: plan.decision_rule_digest,
    evidence_verification_receipt_digests: [
      ...positiveBindings,
      ...controlBindings,
    ].map((entry) => entry.verification_receipt_digest).sort(),
    outcome,
    reason_code: reasonCode,
    decided_at: decidedAt,
  };
  if (Date.parse(verifierReceiptBody.decided_at) > Date.parse(EVIDENCE_ISSUER_NOW)) {
    EVIDENCE_ISSUER_NOW = verifierReceiptBody.decided_at;
  }
  const verifierReceipt = await EVIDENCE_RECEIPT_ISSUER.issuePhysicalVerifierExecution(verifierReceiptBody);
  return {
    ...commonPayload(plan),
    execution_receipt_refs: receipts.map((row) => row.row_ref),
    observation_refs: observations.map((row) => row.row_ref),
    positive_executed_evidence_refs: positiveBindings,
    control_executed_evidence_refs: controlBindings,
    executed_evidence_registry_digest: plan.executed_evidence_registry_digest,
    verifier_template_id: plan.verifier_template_id,
    verifier_template_version: plan.verifier_template_version,
    verifier_template_digest: plan.verifier_template_digest,
    decision_rule_digest: plan.decision_rule_digest,
    verifier_execution_receipt_ref: verifierReceipt.receipt_ref,
    verifier_execution_receipt_digest: verifierReceipt.receipt_digest,
    outcome,
    reason_code: reasonCode,
    validity_kind: "historical_event",
    valid_from: decidedAt,
    decided_at: decidedAt,
  };
}

function seedDifferential(ledger) {
  const positiveReceipt = appendSigned(
    ledger,
    "execution_receipt",
    executionPayload(ledger.plan, "positive"),
    "signer-key:instrument",
  );
  const controlReceipt = appendSigned(
    ledger,
    "execution_receipt",
    executionPayload(ledger.plan, "control"),
    "signer-key:instrument",
  );
  const positiveObservation = appendSigned(
    ledger,
    "observation",
    observationPayload(ledger.plan, "positive", positiveReceipt.row_ref),
    "signer-key:observer-a",
  );
  const controlObservation = appendSigned(
    ledger,
    "observation",
    observationPayload(ledger.plan, "control", controlReceipt.row_ref),
    "signer-key:observer-b",
  );
  return {
    receipts: [positiveReceipt, controlReceipt],
    observations: [positiveObservation, controlObservation],
  };
}

async function appendVerifiedDifferentialClaim(ledger, claimOverrides = {}) {
  const seeded = seedDifferential(ledger);
  const payload = await claimPayload(ledger.plan, seeded.receipts, seeded.observations);
  Object.assign(payload, claimOverrides);
  const claim = appendSigned(ledger, "claim_verdict", payload, "signer-key:verifier");
  return { ...seeded, claim };
}

function surfaceTransitionTopology(targetDomain = "authorized-physical.local") {
  return {
    target_domain: targetDomain,
    participants: [{
      participant_id: "subject",
      role: "subject",
      node: { type: "asset", id: "target:hotel-door-controller" },
    }, {
      participant_id: "stimulus",
      role: "instrument",
      node: { type: "instrument", id: "instrument:chameleon-ultra-1" },
    }, {
      participant_id: "outcome",
      role: "outcome",
      node: { type: "control_point", id: "control-point:authorized-fixture" },
    }],
    arcs: [{
      arc_id: "subject-to-outcome",
      source_participant_id: "subject",
      target_participant_id: "outcome",
      edge_type: "demonstrated_transition",
    }, {
      arc_id: "stimulus-to-outcome",
      source_participant_id: "stimulus",
      target_participant_id: "outcome",
      edge_type: "demonstrated_transition",
    }],
  };
}

test("verified claim projection is ledger-issued, immutable, exact, and deterministically branded", async () => {
  const ledger = createPhysicalExperimentLedger({ plan: planFixture(), ...trustDeps() });
  const { claim } = await appendVerifiedDifferentialClaim(ledger);
  const projection = ledger.projectTestVerifiedClaim();
  const repeated = ledger.projectTestVerifiedClaim();

  assert.equal(assertTestVerifiedPhysicalClaimProjection(projection), projection);
  assert.equal(assertTestVerifiedPhysicalClaimProjection(repeated), repeated);
  assert.equal(projection.production_ready, false);
  assert.equal(projection.projection_trust_class, "test_only_conformance_projection");
  assert.throws(
    () => assertVerifiedPhysicalClaimProjection(projection),
    /production-qualified/,
  );
  assert.throws(
    () => ledger.projectVerifiedClaim(),
    /production verified physical claim projection is unavailable/,
  );
  assert.notEqual(projection, repeated);
  assert.deepEqual(projection, repeated);
  assert.ok(Object.isFrozen(projection));
  assert.ok(Object.isFrozen(projection.upstream_evidence_receipts));
  assert.equal(projection.session_nucleus_hash, ledger.plan.session_nucleus_hash);
  assert.equal(projection.experiment_id, ledger.plan.experiment_id);
  assert.equal(projection.task_id, ledger.plan.task_id);
  assert.equal(projection.attempt_id, ledger.plan.attempt_id);
  assert.equal(projection.plan_hash, ledger.plan.plan_hash);
  assert.equal(projection.execution_request_digest, ledger.plan.execution_request_digest);
  assert.equal(projection.claim_predicate_digest, ledger.plan.claim_predicate_digest);
  assert.equal(projection.claim_verdict_ref, claim.row_ref);
  assert.equal(projection.claim_verdict_hash, claim.row_hash);
  assert.equal(projection.claim_verdict_signer_key_id, claim.envelope.signer_key_id);
  assert.equal(projection.claim_verdict_signer_principal_ref, claim.envelope.signer_principal_ref);
  assert.equal(projection.claim_verdict_trust_root_epoch, claim.envelope.trust_root_epoch);
  assert.equal(projection.claim_verdict_trust_domain_ref, claim.envelope.trust_domain_ref);
  assert.equal(
    projection.claim_verdict_independence_domain_ref,
    claim.envelope.independence_domain_ref,
  );
  assert.equal(projection.verifier_execution_receipt_ref, claim.payload.verifier_execution_receipt_ref);
  assert.equal(projection.verifier_execution_receipt_digest, claim.payload.verifier_execution_receipt_digest);
  assert.deepEqual(projection.upstream_execution_identities, ["execution:control", "execution:positive"]);
  assert.equal(projection.upstream_evidence_receipts.length, 2);
  assert.match(projection.transition_state_epoch, /^historical-event:5:[a-f0-9]{16}$/);
  assert.equal(projection.validity_kind, "historical_event");
  assert.equal(projection.source_asset_ref, ledger.plan.source_asset_ref);
  assert.equal(projection.target_asset_ref, ledger.plan.target_asset_ref);
  assert.equal(projection.instrument_ref, ledger.plan.instrument_ref);
  assert.equal(
    projection.projection_digest,
    hashCanonicalJson(Object.fromEntries(
      Object.entries(projection).filter(([field]) => field !== "projection_digest"),
    )),
  );

  for (const forgery of [
    { ...projection },
    JSON.parse(JSON.stringify(projection)),
    Object.create(projection),
  ]) {
    assert.throws(
      () => assertTestVerifiedPhysicalClaimProjection(forgery),
      /must be issued by a live test Bob ledger/,
    );
  }
});

test("a durable row chain reconstructs a fresh live ledger and verified claim after restart", async () => {
  const deps = trustDeps();
  const original = createPhysicalExperimentLedger({ plan: planFixture(), ...deps });
  await appendVerifiedDifferentialClaim(original);
  const before = original.projectTestVerifiedClaim();
  const durableRows = structuredClone(original.rows());

  const recovered = createPhysicalExperimentLedger({
    plan: original.plan,
    initialRows: durableRows,
    ...deps,
  });
  const after = recovered.projectTestVerifiedClaim();

  assert.notEqual(after, before);
  assert.deepEqual(after, before);
  assert.equal(assertTestVerifiedPhysicalClaimProjection(after), after);
  assert.deepEqual(recovered.rows(), original.rows());

  const corrupted = structuredClone(durableRows);
  corrupted[1].envelope.previous_row_hash = digest("forked-restart-head");
  assert.throws(
    () => createPhysicalExperimentLedger({
      plan: original.plan,
      initialRows: corrupted,
      ...deps,
    }),
    /signature|hash chain|previous_row_hash|append receipt/u,
  );
});

test("one shared durable head prevents independently reconstructed ledgers from forking", () => {
  const durableHead = createDurableHeadFixture();
  const deps = trustDeps({ durableHeadPort: durableHead.port });
  const first = createPhysicalExperimentLedger({ plan: planFixture(), ...deps });
  appendSigned(
    first,
    "execution_receipt",
    executionPayload(first.plan, "positive"),
    "signer-key:instrument",
  );
  const second = createPhysicalExperimentLedger({
    plan: first.plan,
    initialRows: structuredClone(first.rows()),
    ...deps,
  });

  let competingWinner = null;
  durableHead.beforeNextCompare(() => {
    competingWinner = appendSigned(
      second,
      "execution_receipt",
      executionPayload(second.plan, "control", {
        stimulus_artifact_ref: "artifact:v1:control-competing-winner",
      }),
      "signer-key:instrument",
    );
  });
  assert.throws(
    () => appendSigned(
      first,
      "execution_receipt",
      executionPayload(first.plan, "control"),
      "signer-key:instrument",
    ),
    /durable head compare-and-append conflict/,
  );

  assert.equal(competingWinner.envelope.sequence, 2);
  assert.equal(second.rows().length, 2);
  assert.equal(first.rows().length, 1);
  assert.equal(durableHead.committedCount, 2);
  assert.equal(durableHead.compareCalls, 3);
  assert.throws(
    () => first.rebuildIndex(),
    /does not match the exact durable head/,
  );
});

test("append reservation, receipt, and durable head response loss reconcile through exact readback", () => {
  const durableHead = createDurableHeadFixture({
    loseNextCompareAcknowledgement: true,
  });
  const committedReceipts = new Map();
  let reserved = null;
  let reserveCalls = 0;
  let commitCalls = 0;
  const appendIssuer = createPhysicalAppendIssuer({
    registry: PHYSICAL_RECEIPT_REGISTRY,
    issuer_key_id: "signer-key:physical-ledger",
    issuer_epoch: 4,
    private_key_pem: PHYSICAL_RECEIPT_KEYS.privateKeyPem,
    now: () => FIXTURE_TRUSTED_NOW,
    reserve_append(command) {
      reserveCalls += 1;
      if (reserved != null) {
        assert.deepEqual(command, reserved.command);
        return true;
      }
      const reservation = {
        version: 1,
        append_binding_digest: command.append_binding_digest,
        journal_sequence: 77,
      };
      reservation.reservation_digest = hashCanonicalJson({
        domain: "hacker-bob/physical-append-reservation-receipt/v1",
        ...reservation,
      });
      reserved = { command: structuredClone(command), reservation };
      throw new Error("lost physical append reservation acknowledgement");
    },
    resolve_append_reservation({ append_binding_digest }) {
      if (reserved == null
          || reserved.reservation.append_binding_digest !== append_binding_digest) return null;
      return structuredClone(reserved.reservation);
    },
    commit_receipt(receipt) {
      commitCalls += 1;
      committedReceipts.set(receipt.body.append_binding_digest, receipt);
      throw new Error("lost physical append receipt commit acknowledgement");
    },
    resolve_append_receipt({ append_binding_digest }) {
      return committedReceipts.get(append_binding_digest) || null;
    },
  });
  const ledger = createPhysicalExperimentLedger({
    plan: planFixture(),
    ...trustDeps({ durableHeadPort: durableHead.port }),
  });
  const appended = appendSigned(
    ledger,
    "execution_receipt",
    executionPayload(ledger.plan, "positive"),
    "signer-key:instrument",
    { appendIssuer },
  );
  const {
    append_binding_digest: ignoredAppendBindingDigest,
    append_reservation_digest: ignoredAppendReservationDigest,
    journal_sequence: ignoredJournalSequence,
    ...appendRequest
  } = appended.envelope.append_receipt.body;
  const replayedReceipt = appendIssuer.issueAppend(appendRequest);

  assert.equal(replayedReceipt.receipt_digest, appended.envelope.append_receipt.receipt_digest);
  assert.equal(reserveCalls, 1);
  assert.equal(commitCalls, 1);
  assert.equal(durableHead.compareCalls, 1);
  assert.equal(durableHead.committedCount, 1);
  assert.equal(ledger.rows().length, 1);
  assert.deepEqual(ledger.readiness(), {
    version: 1,
    production_ready: false,
    durable_head_consistency: "linearizable_compare_and_append",
    durable_head_port_id: durableHead.port.port_id,
    durable_head_backend_assurance:
      "test_only_injected_callback_contract_no_production_backend",
    durability_trust_class: "test_only_injected_callback",
    external_monotonic_owner_bound: false,
    external_monotonic_owner_digest: null,
    historical_event_ready: false,
    live_capability_ready: false,
    live_capability_reason: "production_durable_head_not_installed",
    reason: "production_strongly_consistent_durable_head_backend_not_implemented",
  });
});

test("experiment ledgers reject lookalike, weak, and asynchronous durable head ports", () => {
  assert.throws(
    () => createPhysicalExperimentLedger({
      plan: planFixture(),
      ...trustDeps(),
      durableHeadPort: Object.freeze({
        version: 1,
        consistency_model: "linearizable_compare_and_append",
      }),
    }),
    /requires a branded strongly consistent durable head port/,
  );
  assert.throws(
    () => createTestPhysicalExperimentDurableHeadPort({
      version: 1,
      port_id: "physical-ledger-head-port:weak",
      test_only: true,
      consistency_model: "eventually_consistent",
      compare_and_append: () => true,
      read_head: () => null,
      resolve_committed_append: () => null,
    }),
    /rejects weak consistency models/,
  );
  assert.throws(
    () => createTestPhysicalExperimentDurableHeadPort({
      version: 1,
      port_id: "physical-ledger-head-port:async-declared",
      test_only: true,
      consistency_model: "linearizable_compare_and_append",
      compare_and_append: async () => true,
      read_head: () => null,
      resolve_committed_append: () => null,
    }),
    /compare_and_append must be synchronous/,
  );
  const promisePort = createTestPhysicalExperimentDurableHeadPort({
    version: 1,
    port_id: "physical-ledger-head-port:async-result",
    test_only: true,
    consistency_model: "linearizable_compare_and_append",
    compare_and_append: () => true,
    read_head: () => Promise.resolve(null),
    resolve_committed_append: () => null,
  });
  assert.throws(
    () => createPhysicalExperimentLedger({
      plan: planFixture(),
      ...trustDeps({ durableHeadPort: promisePort }),
    }),
    /async durable head ports are rejected/,
  );
});

test("test-only verified claims cannot issue production physical surface transitions", async () => {
  const topology = surfaceTransitionTopology();
  const ledger = createPhysicalExperimentLedger({
    plan: planFixture({
      claim_predicate_digest: physicalSurfaceTransitionClaimPredicateDigest(topology),
    }),
    ...trustDeps(),
  });
  await appendVerifiedDifferentialClaim(ledger);
  const projection = ledger.projectTestVerifiedClaim();
  const issueRequest = {
    verified_claim_projection: projection,
    ...topology,
  };
  await assert.rejects(
    SURFACE_TRANSITION_ISSUER.issuePhysicalSurfaceTransition(issueRequest),
    /production-qualified/,
  );
  await assert.rejects(
    SURFACE_TRANSITION_ISSUER.issuePhysicalSurfaceTransition({
      ...issueRequest,
      verified_claim_projection: { ...projection },
    }),
    /production-qualified/,
  );
  await assert.rejects(
    EVIDENCE_RECEIPT_ISSUER.issuePhysicalSurfaceTransition(issueRequest),
    /production-qualified/,
  );
});

test("verified claim projection rejects pre-claim and nonverified differential outcomes", async () => {
  const preClaim = createPhysicalExperimentLedger({ plan: planFixture(), ...trustDeps() });
  seedDifferential(preClaim);
  assert.throws(
    () => preClaim.projectTestVerifiedClaim(),
    /requires an appended claim verdict/,
  );

  resetDurableFixtureState();
  const refuted = createPhysicalExperimentLedger({ plan: planFixture(), ...trustDeps() });
  const positiveReceipt = appendSigned(
    refuted,
    "execution_receipt",
    executionPayload(refuted.plan, "positive"),
    "signer-key:instrument",
  );
  const controlReceipt = appendSigned(
    refuted,
    "execution_receipt",
    executionPayload(refuted.plan, "control"),
    "signer-key:instrument",
  );
  const positiveObservation = appendSigned(
    refuted,
    "observation",
    observationPayload(refuted.plan, "positive", positiveReceipt.row_ref),
    "signer-key:observer-a",
  );
  const controlObservation = appendSigned(
    refuted,
    "observation",
    observationPayload(refuted.plan, "control", controlReceipt.row_ref, {
      observed_outcome_digest: digest("unexpected-control-outcome"),
    }),
    "signer-key:observer-b",
  );
  appendSigned(
    refuted,
    "claim_verdict",
    await claimPayload(
      refuted.plan,
      [positiveReceipt, controlReceipt],
      [positiveObservation, controlObservation],
      { outcome: "refuted", reasonCode: "differential_refuted" },
    ),
    "signer-key:verifier",
  );
  assert.throws(
    () => refuted.projectTestVerifiedClaim(),
    /requires a verified\/differential_verified derived outcome/,
  );
});

test("verified claim projection revalidates signer, evidence, receipt, and live validity state", async () => {
  let signerRevoked = false;
  const signerLedger = createPhysicalExperimentLedger({
    plan: planFixture(),
    ...trustDeps({ isSignerCurrentlyRevoked: () => signerRevoked }),
  });
  await appendVerifiedDifferentialClaim(signerLedger);
  signerRevoked = true;
  assert.throws(() => signerLedger.projectTestVerifiedClaim(), /signer is currently revoked/);

  resetDurableFixtureState();
  let evidenceRevoked = false;
  const evidenceLedger = createPhysicalExperimentLedger({
    plan: planFixture(),
    ...trustDeps({ isEvidenceComponentCurrentlyRevoked: () => evidenceRevoked }),
  });
  await appendVerifiedDifferentialClaim(evidenceLedger);
  evidenceRevoked = true;
  assert.throws(
    () => evidenceLedger.projectTestVerifiedClaim(),
    /executed-evidence source_adapter physical.observations is currently revoked/,
  );

  resetDurableFixtureState();
  const receiptLedger = createPhysicalExperimentLedger({ plan: planFixture(), ...trustDeps() });
  const { claim: receiptClaim } = await appendVerifiedDifferentialClaim(receiptLedger);
  VERIFIER_EXECUTION_RECEIPTS.delete(receiptClaim.payload.verifier_execution_receipt_ref);
  assert.throws(() => receiptLedger.projectTestVerifiedClaim(), /verifier_execution_receipt must be an object/);

  resetDurableFixtureState();
  let trustedNow = FIXTURE_TRUSTED_NOW;
  const liveLedger = createPhysicalExperimentLedger({
    plan: planFixture(),
    ...trustDeps({ trustedNow: () => trustedNow }),
  });
  await appendVerifiedDifferentialClaim(liveLedger, {
    validity_kind: "live_capability",
    state_epoch: 12,
    expires_at: "2026-07-18T00:00:08.000Z",
    capability_instance_ref: "capability-instance:door-controller-state-12",
    custody_state_digest: digest("custody-state-12"),
  });
  const liveProjection = liveLedger.projectTestVerifiedClaim();
  assert.equal(liveProjection.transition_state_epoch, 12);
  assert.equal(liveProjection.expires_at, "2026-07-18T00:00:08.000Z");
  trustedNow = "2026-07-18T00:00:09.000Z";
  assert.throws(() => liveLedger.projectTestVerifiedClaim(), /live claim is stale/);
});

test("immutable plan hash binds task, attempt, predicate, differential, template, timing, and fresh retry", async () => {
  const input = planFixture();
  const plan = normalizePlan(input);
  const reordered = normalizePlan({
    cleanup_plan_digest: input.cleanup_plan_digest,
    ...input,
  });
  assert.equal(plan.plan_hash, reordered.plan_hash);
  assert.ok(Object.isFrozen(plan));
  assert.ok(Object.isFrozen(plan.positive_cohort.observer_plan));
  assert.deepEqual(plan.retry_policy.retry_on, ["inconclusive", "transport_failure"]);

  assert.throws(
    () => normalizePlan(planFixture({
      control_cohort: {
        ...input.control_cohort,
        expected_outcome_digest: input.expected_positive_outcome_digest,
      },
      expected_control_outcome_digest: input.expected_positive_outcome_digest,
    })),
    /discriminating control outcome/,
  );
  assert.throws(
    () => normalizePlan({
      ...input,
      retry_policy: { ...input.retry_policy, fresh_attempt_and_challenge: false },
    }),
    /fresh_attempt_and_challenge must be true/,
  );
  assert.throws(() => normalizePlan({ ...input, mutable_verdict: "verified" }), /unknown fields/);
  assert.throws(() => normalizePlan({ ...input, plan_hash: digest("wrong") }), /plan_hash does not match/);
});

test("signed positive/control rows rebuild deterministically and cleanup cannot rewrite the claim", async () => {
  const deps = trustDeps();
  const ledger = createPhysicalExperimentLedger({ plan: planFixture(), ...deps });
  const { receipts, observations } = seedDifferential(ledger);
  const claim = appendSigned(
    ledger,
    "claim_verdict",
    await claimPayload(ledger.plan, receipts, observations),
    "signer-key:verifier",
  );
  const cleanup = appendSigned(
    ledger,
    "cleanup_verdict",
    {
      ...commonPayload(ledger.plan),
      execution_receipt_refs: receipts.map((row) => row.row_ref),
      cleanup_plan_digest: ledger.plan.cleanup_plan_digest,
      outcome: "failed",
      cleanup_state_digest: digest("residual-state"),
      residual_state_artifact_ref: "artifact:v1:residual-state",
      decided_at: "2026-07-18T00:00:07.000Z",
    },
    "signer-key:cleanup",
  );

  const index = ledger.rebuildIndex();
  assert.equal(index.claim_verdict_ref, claim.row_ref);
  assert.equal(index.cleanup_verdict_ref, cleanup.row_ref);
  assert.equal(index.claim_projection.outcome, "verified");
  assert.equal(index.claim_projection.reason_code, "differential_verified");
  assert.equal(index.cleanup_projection.outcome, "failed");
  assert.notEqual(index.claim_verdict_ref, index.cleanup_verdict_ref);
  assert.ok(PH_S10_CALLS >= 2, "durable evidence issuance must execute the registered PH-S10 verifier");

  const callsAfterIssuance = PH_S10_CALLS;
  PH_S10_CALLBACKS_ENABLED = false;
  try {
    assert.deepEqual(ledger.rebuildIndex(), index);
    assert.equal(PH_S10_CALLS, callsAfterIssuance, "rebuild must verify receipts without rerunning source callbacks");
  } finally {
    PH_S10_CALLBACKS_ENABLED = true;
  }

  const copiedRegistry = {
    version: EVIDENCE_REGISTRY.version,
    registry_digest: EVIDENCE_REGISTRY.registry_digest,
    get: EVIDENCE_REGISTRY.get.bind(EVIDENCE_REGISTRY),
    describe: EVIDENCE_REGISTRY.describe.bind(EVIDENCE_REGISTRY),
  };
  assert.throws(
    () => rebuildPhysicalExperimentIndex(
      ledger.plan,
      ledger.rows(),
      { ...deps, evidenceRegistry: copiedRegistry },
    ),
    /closed Bob executed-evidence registry/,
  );

  const reversed = rebuildPhysicalExperimentIndex(ledger.plan, [...ledger.rows()].reverse(), deps);
  assert.deepEqual(reversed, index);
  assert.equal(reversed.index_digest, index.index_digest);

  const boundVerification = claim.payload.positive_executed_evidence_refs[0];
  const originalReceipt = EVIDENCE_VERIFICATION_RECEIPTS.get(boundVerification.verification_receipt_ref);
  const driftedReceipt = structuredClone(originalReceipt);
  driftedReceipt.payload.disposition = "refuted";
  EVIDENCE_VERIFICATION_RECEIPTS.set(boundVerification.verification_receipt_ref, driftedReceipt);
  assert.throws(() => ledger.rebuildIndex(), /signature verification failed|receipt_digest|semantic_digest/);
  EVIDENCE_VERIFICATION_RECEIPTS.set(boundVerification.verification_receipt_ref, originalReceipt);
  assert.deepEqual(ledger.rebuildIndex(), index);
});

test("a positive without the signed discriminating control remains inconclusive", async () => {
  const ledger = createPhysicalExperimentLedger({ plan: planFixture(), ...trustDeps() });
  const positiveReceipt = appendSigned(
    ledger,
    "execution_receipt",
    executionPayload(ledger.plan, "positive"),
    "signer-key:instrument",
  );
  const positiveObservation = appendSigned(
    ledger,
    "observation",
    observationPayload(ledger.plan, "positive", positiveReceipt.row_ref),
    "signer-key:observer-a",
  );
  assert.equal(ledger.rebuildIndex().claim_projection.outcome, "inconclusive");
  assert.equal(ledger.rebuildIndex().claim_projection.reason_code, "missing_executed_cohort");

  const incorrectlyVerified = await claimPayload(ledger.plan, [positiveReceipt], [positiveObservation]);
  assert.throws(
    () => appendSigned(ledger, "claim_verdict", incorrectlyVerified, "signer-key:verifier"),
    /claim verdict must be inconclusive\/missing_executed_cohort/,
  );
  const claim = appendSigned(
    ledger,
    "claim_verdict",
    await claimPayload(ledger.plan, [positiveReceipt], [positiveObservation], {
      outcome: "inconclusive",
      reasonCode: "missing_executed_cohort",
    }),
    "signer-key:verifier",
  );
  assert.equal(ledger.rebuildIndex().claim_verdict_ref, claim.row_ref);
  assert.equal(ledger.rebuildIndex().claim_projection.outcome, "inconclusive");
});

test("same-domain instrument and observer evidence cannot prove an external outcome", async () => {
  const sameTrustRegistry = buildPhysicalObserverEnrollmentRegistry([{
    observer_enrollment_ref: "observer-enrollment:positive",
    observer_identity_ref: "observer:positive",
    signer_key_id: "signer-key:same-trust-independent",
    source_kind: "sensor",
    source_ref: "sensor:instrument-controlled",
    source_assurance_scheme: "signed-fixture-v1",
    trust_domain_ref: "trust-domain:instrument",
    independence_domain_ref: "independence-domain:observer-a",
    external_outcome_allowed: true,
    valid_from: "2026-07-18T00:00:00.000Z",
    expires_at: "2026-07-19T00:00:00.000Z",
    revoked: false,
  }, ...OBSERVER_ENROLLMENT_REGISTRY.describe().filter((entry) => (
    entry.observer_enrollment_ref === "observer-enrollment:control"
  )).map(({ enrollment_digest, ...entry }) => entry)]);
  const input = planFixture({}, { observerEnrollmentRegistry: sameTrustRegistry });
  const plan = planFixture({
    attempt_id: "same-trust-attempt",
    execution_request_digest: digest("same-trust-execution-request"),
    positive_cohort: {
      ...input.positive_cohort,
      cohort_execution_request_digest: digest("same-trust-positive-request"),
      grant_ref: "grant:same-trust-positive",
      execution_identity: "execution:same-trust-positive",
      observer_plan: [observerPlan("positive", {
        source_ref: "sensor:instrument-controlled",
        required_trust_domain_ref: "trust-domain:instrument",
        required_independence_domain_ref: "independence-domain:observer-a",
        challenge_nonce: "EEEEEEEEEEEEEEEEEEEEEE",
      })],
    },
    control_cohort: {
      ...input.control_cohort,
      cohort_execution_request_digest: digest("same-trust-control-request"),
      grant_ref: "grant:same-trust-control",
      execution_identity: "execution:same-trust-control",
      observer_plan: [observerPlan("control", { challenge_nonce: "FFFFFFFFFFFFFFFFFFFFFF" })],
    },
  }, { observerEnrollmentRegistry: sameTrustRegistry });
  const ledger = createPhysicalExperimentLedger({
    plan,
    ...trustDeps({ observerEnrollmentRegistry: sameTrustRegistry }),
  });
  const positiveReceipt = appendSigned(
    ledger,
    "execution_receipt",
    executionPayload(ledger.plan, "positive"),
    "signer-key:instrument",
  );
  const controlReceipt = appendSigned(
    ledger,
    "execution_receipt",
    executionPayload(ledger.plan, "control"),
    "signer-key:instrument",
  );
  const positiveObservation = appendSigned(
    ledger,
    "observation",
    observationPayload(ledger.plan, "positive", positiveReceipt.row_ref),
    "signer-key:same-trust-independent",
  );
  const controlObservation = appendSigned(
    ledger,
    "observation",
    observationPayload(ledger.plan, "control", controlReceipt.row_ref),
    "signer-key:observer-b",
  );
  const receipts = [positiveReceipt, controlReceipt];
  const observations = [positiveObservation, controlObservation];
  assert.equal(ledger.rebuildIndex().claim_projection.reason_code, "independent_observer_missing");
  const sameTrustClaim = await claimPayload(ledger.plan, receipts, observations);
  assert.throws(
    () => appendSigned(ledger, "claim_verdict", sameTrustClaim, "signer-key:verifier"),
    /claim verdict must be inconclusive\/independent_observer_missing/,
  );
});

test("a distinct trust domain still cannot substitute for an independent control domain", async () => {
  const sameIndependenceRegistry = buildPhysicalObserverEnrollmentRegistry([{
    observer_enrollment_ref: "observer-enrollment:positive",
    observer_identity_ref: "observer:positive",
    signer_key_id: "signer-key:same-independence",
    source_kind: "sensor",
    source_ref: "sensor:shared-instrument-controller",
    source_assurance_scheme: "signed-fixture-v1",
    trust_domain_ref: "trust-domain:observer-a",
    independence_domain_ref: "independence-domain:instrument-controller",
    external_outcome_allowed: true,
    valid_from: "2026-07-18T00:00:00.000Z",
    expires_at: "2026-07-19T00:00:00.000Z",
    revoked: false,
  }, ...OBSERVER_ENROLLMENT_REGISTRY.describe().filter((entry) => (
    entry.observer_enrollment_ref === "observer-enrollment:control"
  )).map(({ enrollment_digest, ...entry }) => entry)]);
  const base = planFixture({}, { observerEnrollmentRegistry: sameIndependenceRegistry });
  const plan = planFixture({
    positive_cohort: {
      ...base.positive_cohort,
      observer_plan: [observerPlan("positive", {
        source_ref: "sensor:shared-instrument-controller",
        required_independence_domain_ref: "independence-domain:instrument-controller",
      })],
    },
  }, { observerEnrollmentRegistry: sameIndependenceRegistry });
  const ledger = createPhysicalExperimentLedger({
    plan,
    ...trustDeps({ observerEnrollmentRegistry: sameIndependenceRegistry }),
  });
  const positiveReceipt = appendSigned(
    ledger,
    "execution_receipt",
    executionPayload(ledger.plan, "positive"),
    "signer-key:instrument",
  );
  const controlReceipt = appendSigned(
    ledger,
    "execution_receipt",
    executionPayload(ledger.plan, "control"),
    "signer-key:instrument",
  );
  appendSigned(
    ledger,
    "observation",
    observationPayload(ledger.plan, "positive", positiveReceipt.row_ref),
    "signer-key:same-independence",
  );
  appendSigned(
    ledger,
    "observation",
    observationPayload(ledger.plan, "control", controlReceipt.row_ref),
    "signer-key:observer-b",
  );
  assert.equal(ledger.rebuildIndex().claim_projection.reason_code, "independent_observer_missing");
});

test("executed-evidence references must cover each signed observation in its exact cohort", async () => {
  const ledger = createPhysicalExperimentLedger({ plan: planFixture(), ...trustDeps() });
  const { receipts, observations } = seedDifferential(ledger);
  const missingControl = await claimPayload(ledger.plan, receipts, observations, { controlEvidence: [] });
  assert.throws(
    () => appendSigned(ledger, "claim_verdict", missingControl, "signer-key:verifier"),
    /claim verdict must be inconclusive\/executed_evidence_missing/,
  );
  const crossCohort = await evidenceRef(ledger.plan, observations[1], receipts[1]);
  const cohortDriftClaim = await claimPayload(ledger.plan, receipts, observations);
  assert.throws(
    () => appendSigned(
      ledger,
      "claim_verdict",
      {
        ...cohortDriftClaim,
        positive_executed_evidence_refs: [crossCohort],
        control_executed_evidence_refs: [],
      },
      "signer-key:verifier",
    ),
    /positive executed evidence must resolve to a positive observation row/,
  );
});

test("row signatures, canonical payloads, trust provenance, and the append-only hash chain fail closed", async () => {
  const deps = trustDeps();
  const ledger = createPhysicalExperimentLedger({ plan: planFixture(), ...deps });
  const first = appendSigned(
    ledger,
    "execution_receipt",
    executionPayload(ledger.plan, "positive"),
    "signer-key:instrument",
  );
  assert.equal(first.envelope.previous_row_hash, ZERO_HASH);

  const badChain = rowEnvelope(
    "execution_receipt",
    executionPayload(ledger.plan, "control"),
    ledger.plan,
    "signer-key:instrument",
    2,
    digest("unrelated-row"),
  );
  assert.throws(() => ledger.append(badChain), /hash chain is broken/);

  const goodSecond = rowEnvelope(
    "execution_receipt",
    executionPayload(ledger.plan, "control"),
    ledger.plan,
    "signer-key:instrument",
    2,
    first.row_hash,
  );
  const badSignature = structuredClone(goodSecond);
  badSignature.envelope.signature = digest("bad-signature");
  assert.throws(() => ledger.append(badSignature), /signature verification failed/);

  const tampered = structuredClone(goodSecond);
  tampered.payload.status = "failed";
  assert.throws(() => ledger.append(tampered), /payload_digest does not match/);

  const domainDrift = structuredClone(goodSecond);
  domainDrift.envelope.trust_domain_ref = "trust-domain:observer-a";
  assert.throws(() => ledger.append(domainDrift), /does not match the trusted signer registry/);

  const verifierSignedExecution = rowEnvelope(
    "execution_receipt",
    executionPayload(ledger.plan, "control", { instrument_trust_domain_ref: "trust-domain:verifier" }),
    ledger.plan,
    "signer-key:verifier",
    2,
    first.row_hash,
  );
  assert.throws(
    () => ledger.append(verifierSignedExecution),
    /not authorized for execution_receipt rows|not assigned to this instrument identity/,
  );
});

test("observation windows, opaque artifact handles, live verdict bindings, and terminal append order are closed", async () => {
  const ledger = createPhysicalExperimentLedger({ plan: planFixture(), ...trustDeps() });
  const receipt = appendSigned(
    ledger,
    "execution_receipt",
    executionPayload(ledger.plan, "positive"),
    "signer-key:instrument",
  );
  assert.throws(
    () => appendSigned(
      ledger,
      "observation",
      observationPayload(ledger.plan, "positive", receipt.row_ref, {
        captured_at: "2026-07-18T00:00:30.000Z",
        received_at: "2026-07-18T00:00:30.100Z",
      }),
      "signer-key:observer-a",
    ),
    /payload terminal timestamp is in the future|exceeds its plan-bound observation window/,
  );
  resetDurableFixtureState();
  const artifactLedger = createPhysicalExperimentLedger({ plan: planFixture(), ...trustDeps() });
  const artifactReceipt = appendSigned(
    artifactLedger,
    "execution_receipt",
    executionPayload(artifactLedger.plan, "positive"),
    "signer-key:instrument",
  );
  assert.throws(
    () => normalizePhysicalExperimentRowPayload("observation", observationPayload(
      artifactLedger.plan,
      "positive",
      artifactReceipt.row_ref,
      { artifact_ref: "/tmp/raw-card-dump.bin" },
    ), artifactLedger.plan),
    /namespaced opaque reference/,
  );

  resetDurableFixtureState();
  const fresh = createPhysicalExperimentLedger({ plan: planFixture(), ...trustDeps() });
  const { receipts, observations } = seedDifferential(fresh);
  const liveClaim = await claimPayload(fresh.plan, receipts, observations);
  liveClaim.validity_kind = "live_capability";
  assert.throws(
    () => normalizePhysicalExperimentRowPayload("claim_verdict", liveClaim, fresh.plan),
    /live capability is missing fields/,
  );
  appendSigned(
    fresh,
    "claim_verdict",
    await claimPayload(fresh.plan, receipts, observations),
    "signer-key:verifier",
  );
  assert.throws(
    () => appendSigned(
      fresh,
      "observation",
      observationPayload(fresh.plan, "positive", receipts[0].row_ref),
      "signer-key:observer-a",
    ),
    /claim evidence cannot be appended after the claim verdict/,
  );
});

test("observation clock offsets are mandatory, plan-bounded, and applied before temporal joins", () => {
  const ledger = createPhysicalExperimentLedger({ plan: planFixture(), ...trustDeps() });
  const receipt = appendSigned(
    ledger,
    "execution_receipt",
    executionPayload(ledger.plan, "positive"),
    "signer-key:instrument",
  );
  const corrected = observationPayload(ledger.plan, "positive", receipt.row_ref, {
    // The observer clock is ten seconds fast. Its reference-clock capture time
    // is 00:00:02, inside the plan-bound window following execution end.
    captured_at: "2026-07-18T00:00:12.000Z",
    received_at: "2026-07-18T00:00:02.100Z",
    clock_offset_ms: -10_000,
  });
  const appended = appendSigned(
    ledger,
    "observation",
    corrected,
    "signer-key:observer-a",
  );
  assert.equal(appended.payload.clock_offset_ms, -10_000);

  const missingOffset = structuredClone(corrected);
  delete missingOffset.clock_offset_ms;
  assert.throws(
    () => normalizePhysicalExperimentRowPayload("observation", missingOffset, ledger.plan),
    /missing fields: clock_offset_ms/,
  );

  const unboundedOffset = structuredClone(corrected);
  unboundedOffset.clock_offset_ms = 60_001;
  assert.throws(
    () => normalizePhysicalExperimentRowPayload("observation", unboundedOffset, ledger.plan),
    /clock_offset_ms must be a safe integer between -60000 and 60000/,
  );

  const impossibleReception = structuredClone(corrected);
  impossibleReception.clock_offset_ms = 0;
  assert.throws(
    () => normalizePhysicalExperimentRowPayload("observation", impossibleReception, ledger.plan),
    /received_at precedes the corrected capture interval/,
  );

  resetDurableFixtureState();
  const shortWindowLedger = createPhysicalExperimentLedger({
    plan: planFixture({
      observation_window: {
        start_rule: "execution_ended",
        max_duration_ms: 1_000,
        max_clock_offset_abs_ms: 60_000,
        max_clock_uncertainty_ms: 250,
      },
    }),
    ...trustDeps(),
  });
  const shortReceipt = appendSigned(
    shortWindowLedger,
    "execution_receipt",
    executionPayload(shortWindowLedger.plan, "positive"),
    "signer-key:instrument",
  );
  assert.throws(
    () => appendSigned(
      shortWindowLedger,
      "observation",
      observationPayload(shortWindowLedger.plan, "positive", shortReceipt.row_ref, {
        // Raw 00:00:01.500 would fit. Correcting the one-second-slow clock
        // yields 00:00:02.500, outside the window ending at 00:00:02.
        captured_at: "2026-07-18T00:00:01.500Z",
        received_at: "2026-07-18T00:00:03.000Z",
        clock_offset_ms: 1_000,
      }),
      "signer-key:observer-a",
    ),
    /exceeds its plan-bound observation window/,
  );
});

test("the plan hash closes inventory, assurance, assets, operation, parameters, effects, and control plans", async () => {
  const baselineInput = planFixture();
  const baseline = normalizePlan(baselineInput);
  const variants = [
    planFixture({ instrument_inventory_ref: "inventory:chameleon-ultra-2" }),
    planFixture({ provider_manifest_digest: digest("different-provider-manifest") }),
    planFixture({ source_asset_ref: "source:different-credential-fixture" }),
    (() => {
      const effect = { ...effectFixture(), subject_ref: "target:different-door-controller" };
      return planFixture({
        target_asset_ref: "target:different-door-controller",
        requested_effects: [effect],
        requested_effects_digest: hashCanonicalJson([effect]),
      });
    })(),
    planFixture({ operation_id: "hf.different-operation" }),
    planFixture({ parameter_digest: digest("different-parameters") }),
    (() => {
      const effect = { ...effectFixture(), bounds: { duration_ms: 500, carrier: "hf" } };
      return planFixture({ requested_effects: [effect], requested_effects_digest: hashCanonicalJson([effect]) });
    })(),
    (() => {
      const claims = assuranceClaims();
      claims.firmware_provenance = digest("different-firmware-provenance");
      claims.claims_digest = hashCanonicalJson({
        identity_enrollment: claims.identity_enrollment,
        firmware_provenance: claims.firmware_provenance,
        command_surface_conformance: claims.command_surface_conformance,
        transport_trust: claims.transport_trust,
      });
      return planFixture({ instrument_assurance_claims: claims });
    })(),
  ];
  for (const variant of variants) {
    assert.notEqual(normalizePlan(variant).plan_hash, baseline.plan_hash);
  }

  const sameRequestBase = planFixture();
  const sameRequest = planFixture({
    control_cohort: {
      ...sameRequestBase.control_cohort,
      cohort_execution_request_digest: sameRequestBase.positive_cohort.cohort_execution_request_digest,
    },
    attempt_allocation_receipt: sameRequestBase.attempt_allocation_receipt,
  });
  assert.throws(() => normalizePlan(sameRequest), /distinct execution requests/);

  const badControl = planFixture({
    controls: [{ kind: "negative", plan_ref: "stimulus-plan:unrelated", plan_digest: digest("unrelated") }],
  });
  assert.throws(() => normalizePlan(badControl), /must bind the control cohort/);

  const badClaims = planFixture();
  badClaims.instrument_assurance_claims.claims_digest = digest("self-authored-assurance-summary");
  assert.throws(() => normalizePlan(badClaims), /claims_digest does not match/);

  const weakChallenge = planFixture();
  weakChallenge.positive_cohort.observer_plan[0].challenge_nonce = "guessable";
  assert.throws(() => normalizePlan(weakChallenge), /128-bit-or-stronger/);
});

test("positive and control executions require exact stimuli, distinct grants and identities, and observation joins", async () => {
  const deps = trustDeps();
  const ledger = createPhysicalExperimentLedger({ plan: planFixture(), ...deps });
  const positive = appendSigned(
    ledger,
    "execution_receipt",
    executionPayload(ledger.plan, "positive"),
    "signer-key:instrument",
  );

  const reusedGrant = executionPayload(ledger.plan, "control");
  reusedGrant.grant_ref = positive.payload.grant_ref;
  assert.throws(
    () => appendSigned(ledger, "execution_receipt", reusedGrant, "signer-key:instrument"),
    /grant_ref does not match|binding_digest/,
  );
  const reusedExecution = executionPayload(ledger.plan, "control");
  reusedExecution.execution_identity = positive.payload.execution_identity;
  assert.throws(
    () => appendSigned(ledger, "execution_receipt", reusedExecution, "signer-key:instrument"),
    /execution_identity does not match|binding_digest/,
  );
  assert.throws(
    () => normalizePhysicalExperimentRowPayload(
      "execution_receipt",
      executionPayload(ledger.plan, "control", { stimulus_plan_ref: "stimulus-plan:positive" }),
      ledger.plan,
    ),
    /stimulus_plan_ref does not match/,
  );

  const joined = createPhysicalExperimentLedger({ plan: planFixture(), ...trustDeps() });
  const receipt = appendSigned(
    joined,
    "execution_receipt",
    executionPayload(joined.plan, "positive"),
    "signer-key:instrument",
  );
  const wrongJoin = observationPayload(joined.plan, "positive", receipt.row_ref);
  wrongJoin.grant_ref = "grant:wrong";
  assert.throws(
    () => appendSigned(joined, "observation", wrongJoin, "signer-key:observer-a"),
    /binding_digest does not match|grant\/execution binding drift/,
  );
});

test("one-use attestations close challenge replay, issuer drift, duplicate consumption, and monotonic guards", async () => {
  const ledger = createPhysicalExperimentLedger({ plan: planFixture(), ...trustDeps() });
  const positivePayload = executionPayload(ledger.plan, "positive");
  const idempotentConsumption = PHYSICAL_ALLOCATION_ISSUER.issueConsumption(
    positivePayload.consumption_attestation.body,
  );
  assert.equal(
    idempotentConsumption.receipt_digest,
    positivePayload.consumption_attestation.receipt_digest,
  );
  assert.throws(
    () => PHYSICAL_ALLOCATION_ISSUER.issueConsumption({
      ...positivePayload.consumption_attestation.body,
      consumption_ref: "consumption:conflicting-global-reissue",
    }),
    /conflicts with the requested durable binding/,
  );
  const invalidSignature = structuredClone(positivePayload);
  invalidSignature.consumption_attestation.signature = digest("invalid-consumption-signature");
  assert.throws(
    () => appendSigned(ledger, "execution_receipt", invalidSignature, "signer-key:instrument"),
    /signature verification failed/,
  );

  const wrongIssuer = structuredClone(positivePayload);
  wrongIssuer.consumption_attestation.issuer_key_id = "signer-key:unbound-consumption-ledger";
  assert.throws(
    () => normalizePhysicalExperimentRowPayload("execution_receipt", wrongIssuer, ledger.plan),
    /issuer drift/,
  );

  const positive = appendSigned(ledger, "execution_receipt", positivePayload, "signer-key:instrument");
  const controlPayload = executionPayload(ledger.plan, "control", {
    // Avoid consuming the control grant until the deliberately colliding
    // consumption_ref is in the signed durable receipt below.
    consumption_attestation: positive.payload.consumption_attestation,
  });
  const controlBinding = executionConsumptionBindingDigest(
    ledger.plan,
    ledger.plan.control_cohort,
    controlPayload.grant_ref,
    controlPayload.execution_identity,
  );
  controlPayload.consumption_attestation = consumptionAttestation(
    ledger.plan,
    "grant",
    controlBinding,
    controlPayload.grant_ref,
    2,
    controlPayload.started_at,
    { consumption_ref: positive.payload.consumption_attestation.consumption_ref },
  );
  assert.throws(
    () => appendSigned(ledger, "execution_receipt", controlPayload, "signer-key:instrument"),
    /unique consumption_ref/,
  );

  const observationLedger = createPhysicalExperimentLedger({ plan: planFixture(), ...trustDeps() });
  const receipt = appendSigned(
    observationLedger,
    "execution_receipt",
    executionPayload(observationLedger.plan, "positive"),
    "signer-key:instrument",
  );
  const guardDrift = observationPayload(observationLedger.plan, "positive", receipt.row_ref);
  guardDrift.replay_guard = { kind: "monotonic_sequence", value: 7 };
  assert.throws(
    () => appendSigned(observationLedger, "observation", guardDrift, "signer-key:observer-a"),
    /body.kind must be monotonic_sequence|binding_digest does not match/,
  );

  const reusedChallengeBase = planFixture();
  const reusedChallenge = planFixture({
    control_cohort: {
      ...reusedChallengeBase.control_cohort,
      observer_plan: [{
        ...reusedChallengeBase.control_cohort.observer_plan[0],
        challenge_nonce: reusedChallengeBase.positive_cohort.observer_plan[0].challenge_nonce,
      }],
    },
    attempt_allocation_receipt: reusedChallengeBase.attempt_allocation_receipt,
  });
  assert.throws(() => normalizePlan(reusedChallenge), /challenge nonces must be unique/);

  assert.throws(
    () => planFixture({ attempt_id: "attempt-2" }),
    /uniqueness reservation was refused/,
  );
  const retryBase = planFixture();
  const freshRetry = planFixture({
    attempt_id: "attempt-2",
    execution_request_digest: digest("execution-request-attempt-2"),
    positive_cohort: {
      ...retryBase.positive_cohort,
      cohort_execution_request_digest: digest("positive-request-attempt-2"),
      grant_ref: "grant:positive-attempt-2",
      execution_identity: "execution:positive-attempt-2",
      observer_plan: [observerPlan("positive", { challenge_nonce: "CCCCCCCCCCCCCCCCCCCCCC" })],
    },
    control_cohort: {
      ...retryBase.control_cohort,
      cohort_execution_request_digest: digest("control-request-attempt-2"),
      grant_ref: "grant:control-attempt-2",
      execution_identity: "execution:control-attempt-2",
      observer_plan: [observerPlan("control", { challenge_nonce: "DDDDDDDDDDDDDDDDDDDDDD" })],
    },
  });
  const normalizedRetry = normalizePlan(freshRetry);
  assert.equal(normalizedRetry.attempt_id, "attempt-2");
  assert.throws(
    () => normalizePhysicalExperimentRowPayload(
      "execution_receipt",
      executionPayload(normalizedRetry, "positive", {
        consumption_attestation: positivePayload.consumption_attestation,
      }),
      normalizedRetry,
    ),
    /binding_digest does not match|crosses an immutable plan or attempt boundary|subject_ref drift/,
  );
});

test("trusted signer assignments and PH-S10 receipts are contextual and content-bound", async () => {
  assert.throws(
    () => buildPhysicalObserverEnrollmentRegistry([{
      observer_enrollment_ref: "observer-enrollment:self-authored",
      observer_identity_ref: "observer:self-authored",
      signer_key_id: "signer-key:instrument",
      source_kind: "instrument",
      source_ref: "instrument:chameleon-ultra-1",
      source_assurance_scheme: "signed-fixture-v1",
      trust_domain_ref: "trust-domain:instrument",
      independence_domain_ref: "independence-domain:instrument-controller",
      external_outcome_allowed: true,
      valid_from: "2026-07-18T00:00:00.000Z",
      revoked: false,
    }]),
    /instrument-origin sources cannot be enrolled as external outcomes/,
  );

  const wrongObserverPlan = planFixture();
  wrongObserverPlan.positive_cohort.observer_plan[0].observer_identity_ref = "observer:unassigned";
  assert.throws(
    () => createPhysicalExperimentLedger({ plan: wrongObserverPlan, ...trustDeps() }),
    /does not match operator enrollment/,
  );

  const wrongInstrumentBase = planFixture();
  const wrongInstrumentLedger = createPhysicalExperimentLedger({
    plan: planFixture({
      attempt_id: "wrong-instrument-attempt",
      execution_request_digest: digest("wrong-instrument-request"),
      instrument_identity_ref: "instrument-identity:unassigned",
      positive_cohort: {
        ...wrongInstrumentBase.positive_cohort,
        cohort_execution_request_digest: digest("wrong-instrument-positive-request"),
        grant_ref: "grant:wrong-instrument-positive",
        execution_identity: "execution:wrong-instrument-positive",
        observer_plan: [observerPlan("positive", { challenge_nonce: "GGGGGGGGGGGGGGGGGGGGGG" })],
      },
      control_cohort: {
        ...wrongInstrumentBase.control_cohort,
        cohort_execution_request_digest: digest("wrong-instrument-control-request"),
        grant_ref: "grant:wrong-instrument-control",
        execution_identity: "execution:wrong-instrument-control",
        observer_plan: [observerPlan("control", { challenge_nonce: "HHHHHHHHHHHHHHHHHHHHHH" })],
      },
    }),
    ...trustDeps(),
  });
  assert.throws(
    () => appendSigned(
      wrongInstrumentLedger,
      "execution_receipt",
      executionPayload(wrongInstrumentLedger.plan, "positive"),
      "signer-key:instrument",
    ),
    /not assigned to this instrument identity/,
  );

  const evidenceLedger = createPhysicalExperimentLedger({ plan: planFixture(), ...trustDeps() });
  const { receipts, observations } = seedDifferential(evidenceLedger);
  const selfAuthored = await claimPayload(evidenceLedger.plan, receipts, observations);
  selfAuthored.positive_executed_evidence_refs[0].executed_evidence_ref.source_adapter_digest =
    digest("self-authored-adapter");
  assert.throws(
    () => appendSigned(evidenceLedger, "claim_verdict", selfAuthored, "signer-key:verifier"),
    /source adapter drift/,
  );

  const contentDrift = await claimPayload(evidenceLedger.plan, receipts, observations);
  contentDrift.control_executed_evidence_refs[0].verification_receipt_digest = digest("unresolved-receipt");
  assert.throws(
    () => appendSigned(evidenceLedger, "claim_verdict", contentDrift, "signer-key:verifier"),
    /verification_receipt_digest drift/,
  );

  resetDurableFixtureState();
  const revokedComponentLedger = createPhysicalExperimentLedger({
    plan: planFixture(),
    ...trustDeps({
      isEvidenceComponentCurrentlyRevoked: ({ component_kind: componentKind }) => (
        componentKind === "replay_executor"
      ),
    }),
  });
  const revokedSeed = seedDifferential(revokedComponentLedger);
  const revokedClaim = await claimPayload(
    revokedComponentLedger.plan,
    revokedSeed.receipts,
    revokedSeed.observations,
  );
  assert.throws(
    () => appendSigned(revokedComponentLedger, "claim_verdict", revokedClaim, "signer-key:verifier"),
    /replay_executor .* currently revoked/,
  );
});

test("signed chronology fails closed and live verdicts remain explicitly non-authorizing in the index", async () => {
  const chronologyLedger = createPhysicalExperimentLedger({ plan: planFixture(), ...trustDeps() });
  const backdated = rowEnvelope(
    "execution_receipt",
    executionPayload(chronologyLedger.plan, "positive"),
    chronologyLedger.plan,
    "signer-key:instrument",
    1,
    ZERO_HASH,
  );
  assert.throws(
    () => chronologyLedger.append(resignEnvelope(
      backdated,
      "signer-key:instrument",
      { signed_at: "2026-07-17T23:59:59.000Z" },
    )),
    /append_receipt signed_at drift|signed_at must not precede the payload terminal timestamp/,
  );

  resetDurableFixtureState();
  const delayedLedger = createPhysicalExperimentLedger({ plan: planFixture(), ...trustDeps() });
  const delayedSignedAt = "2026-07-18T00:00:06.000Z";
  assert.throws(
    () => appendSigned(
      delayedLedger,
      "execution_receipt",
      executionPayload(delayedLedger.plan, "positive"),
      "signer-key:instrument",
      { signedAt: delayedSignedAt, appendIssuer: physicalAppendIssuerAt(delayedSignedAt) },
    ),
    /signed_at is backdated beyond trusted clock skew/,
  );

  resetDurableFixtureState();
  const futureLedger = createPhysicalExperimentLedger({ plan: planFixture(), ...trustDeps() });
  const futurePayload = executionPayload(futureLedger.plan, "positive");
  futurePayload.started_at = "2099-01-01T00:00:00.000Z";
  futurePayload.ended_at = "2099-01-01T00:00:01.000Z";
  assert.throws(
    () => appendSigned(
      futureLedger,
      "execution_receipt",
      futurePayload,
      "signer-key:instrument",
    ),
    /payload terminal timestamp is in the future/,
  );

  resetDurableFixtureState();
  let signerCurrentlyRevoked = false;
  const revocationDeps = trustDeps({
    isSignerCurrentlyRevoked: () => signerCurrentlyRevoked,
  });
  const revocationLedger = createPhysicalExperimentLedger({ plan: planFixture(), ...revocationDeps });
  appendSigned(
    revocationLedger,
    "execution_receipt",
    executionPayload(revocationLedger.plan, "positive"),
    "signer-key:instrument",
  );
  const historicalIndex = revocationLedger.rebuildIndex();
  signerCurrentlyRevoked = true;
  assert.deepEqual(revocationLedger.rebuildIndex(), historicalIndex);
  assert.throws(
    () => appendSigned(
      revocationLedger,
      "execution_receipt",
      executionPayload(revocationLedger.plan, "control"),
      "signer-key:instrument",
    ),
    /signer is currently revoked/,
  );

  resetDurableFixtureState();
  const earlyClaimLedger = createPhysicalExperimentLedger({ plan: planFixture(), ...trustDeps() });
  const seeded = seedDifferential(earlyClaimLedger);
  const earlyClaim = await claimPayload(earlyClaimLedger.plan, seeded.receipts, seeded.observations);
  earlyClaim.decided_at = "2026-07-18T00:00:01.000Z";
  earlyClaim.valid_from = "2026-07-18T00:00:01.000Z";
  assert.throws(
    () => appendSigned(earlyClaimLedger, "claim_verdict", earlyClaim, "signer-key:verifier"),
    /decided_at precedes its signed evidence/,
  );

  resetDurableFixtureState();
  const liveLedger = createPhysicalExperimentLedger({ plan: planFixture(), ...trustDeps() });
  const liveSeed = seedDifferential(liveLedger);
  const live = await claimPayload(liveLedger.plan, liveSeed.receipts, liveSeed.observations);
  Object.assign(live, {
    validity_kind: "live_capability",
    state_epoch: 12,
    expires_at: "2026-07-18T00:01:00.000Z",
    capability_instance_ref: "capability-instance:door-controller-state-12",
    custody_state_digest: digest("custody-state-12"),
  });
  appendSigned(liveLedger, "claim_verdict", live, "signer-key:verifier");
  const projection = liveLedger.rebuildIndex().claim_projection;
  assert.equal(projection.outcome, "verified");
  assert.equal(projection.validity_kind, "live_capability");
  assert.equal(projection.prerequisite_eligibility, "requires_live_revalidation");
  assert.equal(projection.state_epoch, 12);
  assert.equal(projection.expires_at, "2026-07-18T00:01:00.000Z");
  assert.equal(projection.custody_state_digest, digest("custody-state-12"));
});

test("Mechanism-A experiment runtime detects local rollback but stays non-production without an independent owner", async () => {
  await withProductionHome(async (home) => {
    resetDurableFixtureState();
    const domain = `physical-production-${crypto.randomBytes(5).toString("hex")}.local`;
    const session = installProductionPhysicalSession(domain);
    const signerFixture = productionSignerFixture();
    const plan = planFixture({
      experiment_id: "production-credential-differential",
      task_id: "PH-PRODUCTION-TASK",
      attempt_id: `attempt-${crypto.randomBytes(4).toString("hex")}`,
      session_nucleus_hash: session.nucleus.nucleus_hash,
      trust_registry_digest: signerFixture.registry.registry_digest,
    });
    const trustEnrollment = enrollProductionPhysicalExperimentTrust({
      version: 1,
      target_domain: domain,
      session_nucleus_hash: session.nucleus.nucleus_hash,
      signerTrustRegistry: signerFixture.registry,
      observerEnrollmentRegistry: OBSERVER_ENROLLMENT_REGISTRY,
      physicalReceiptRegistry: PHYSICAL_RECEIPT_REGISTRY,
      evidenceReceiptRegistry: EVIDENCE_RECEIPT_REGISTRY,
      effectRegistry: EFFECT_REGISTRY,
      evidenceRegistry: EVIDENCE_REGISTRY,
    });
    const restartedTrustEnrollment = enrollProductionPhysicalExperimentTrust({
      version: 1,
      target_domain: domain,
      session_nucleus_hash: session.nucleus.nucleus_hash,
      signerTrustRegistry: signerFixture.registry,
      observerEnrollmentRegistry: OBSERVER_ENROLLMENT_REGISTRY,
      physicalReceiptRegistry: PHYSICAL_RECEIPT_REGISTRY,
      evidenceReceiptRegistry: EVIDENCE_RECEIPT_REGISTRY,
      effectRegistry: EFFECT_REGISTRY,
      evidenceRegistry: EVIDENCE_REGISTRY,
    });
    assert.notEqual(restartedTrustEnrollment, trustEnrollment);
    assert.deepEqual(
      assertCurrentProductionPhysicalExperimentTrust(restartedTrustEnrollment),
      assertCurrentProductionPhysicalExperimentTrust(trustEnrollment),
    );
    const productionInput = {
      version: 1,
      target_domain: domain,
      plan,
      trustEnrollment: restartedTrustEnrollment,
      signerTrustRegistry: signerFixture.registry,
      observerEnrollmentRegistry: OBSERVER_ENROLLMENT_REGISTRY,
      physicalReceiptRegistry: PHYSICAL_RECEIPT_REGISTRY,
      evidenceReceiptRegistry: EVIDENCE_RECEIPT_REGISTRY,
      effectRegistry: EFFECT_REGISTRY,
      evidenceRegistry: EVIDENCE_REGISTRY,
    };
    const signingOptions = () => {
      const signedAt = new Date().toISOString();
      return {
        signedAt,
        appendIssuer: physicalAppendIssuerAt(signedAt),
        signers: signerFixture.signers,
        sign: signerFixture.sign,
      };
    };

    const first = createMechanismAPhysicalExperimentLedger(productionInput);
    assert.equal(assertMechanismAPhysicalExperimentLedger(first), first);
    assert.equal(first.readiness().production_ready, false);
    assert.equal(first.readiness().durable_head_backend_assurance,
      "mechanism_a_local_signed_row_journal_with_signer_custodied_row_head_anchor");
    assert.equal(
      first.readiness().durability_trust_class,
      "mechanism_a_local_signer_custodied_rollback_detection",
    );
    assert.equal(first.readiness().external_monotonic_owner_bound, false);
    assert.equal(
      first.readiness().reason,
      "independently_retained_monotonic_row_head_owner_unavailable",
    );
    assert.deepEqual(describeMechanismAPhysicalExperimentLedger(first), {
      target_domain: domain,
      session_nucleus_hash: plan.session_nucleus_hash,
      plan_hash: first.plan.plan_hash,
      durable_head_port_id: first.readiness().durable_head_port_id,
      production_trust_binding_digest: trustEnrollment.trust_binding_digest,
      production_trust_head_sequence: trustEnrollment.trust_head_sequence,
      production_trust_head_digest: trustEnrollment.trust_head_digest,
      production_ready: false,
      blocker: "independently_retained_monotonic_row_head_owner_unavailable",
    });
    assert.throws(
      () => createProductionPhysicalExperimentLedger(productionInput),
      /genuine independently retained monotonic row-head owner/u,
      "a local signer-custodied anchor must never be promoted to production durability",
    );

    const timeline = Date.now() - 2_000;
    const time = (offset) => new Date(timeline + offset).toISOString();
    const positiveReceipt = appendSigned(
      first,
      "execution_receipt",
      executionPayload(first.plan, "positive", {
        started_at: time(0),
        ended_at: time(100),
      }),
      "signer-key:instrument",
      signingOptions(),
    );

    // Two independently opened ledgers share the immutable sequence filename;
    // one exact commit wins and the stale reconstruction cannot fork it.
    const winner = createMechanismAPhysicalExperimentLedger(productionInput);
    const controlReceipt = appendSigned(
      winner,
      "execution_receipt",
      executionPayload(winner.plan, "control", {
        started_at: time(200),
        ended_at: time(300),
      }),
      "signer-key:instrument",
      signingOptions(),
    );
    assert.throws(
      () => appendSigned(
        first,
        "execution_receipt",
        executionPayload(first.plan, "control", {
          started_at: time(200),
          ended_at: time(300),
          stimulus_artifact_ref: "artifact:v1:forked-control",
        }),
        "signer-key:instrument",
        signingOptions(),
      ),
      /compare-and-append conflict|reconstruction does not match the exact durable head/u,
    );

    const positiveObservation = appendSigned(
      winner,
      "observation",
      observationPayload(winner.plan, "positive", positiveReceipt.row_ref, {
        captured_at: time(400),
        received_at: time(450),
      }),
      "signer-key:observer-a",
      signingOptions(),
    );
    const controlObservation = appendSigned(
      winner,
      "observation",
      observationPayload(winner.plan, "control", controlReceipt.row_ref, {
        captured_at: time(500),
        received_at: time(550),
      }),
      "signer-key:observer-b",
      signingOptions(),
    );
    const decidedAt = time(900);
    const claimData = await claimPayload(
      winner.plan,
      [positiveReceipt, controlReceipt],
      [positiveObservation, controlObservation],
      { decidedAt, evidenceNow: time(700) },
    );
    for (const binding of [
      ...claimData.positive_executed_evidence_refs,
      ...claimData.control_executed_evidence_refs,
    ]) {
      winner.ingestEvidenceReceipt(
        EVIDENCE_VERIFICATION_RECEIPTS.get(binding.verification_receipt_ref),
      );
    }
    winner.ingestEvidenceReceipt(
      VERIFIER_EXECUTION_RECEIPTS.get(claimData.verifier_execution_receipt_ref),
    );
    const claim = appendSigned(
      winner,
      "claim_verdict",
      claimData,
      "signer-key:verifier",
      signingOptions(),
    );
    const index = winner.rebuildIndex();
    assert.equal(index.claim_verdict_ref, claim.row_ref);
    assert.equal(index.row_count, 5);
    assert.equal(index.row_chain_head, claim.row_hash);
    assert.equal(index.claim_projection.outcome, "verified");
    assert.equal(index.claim_projection.reason_code, "differential_verified");
    assert.throws(
      () => winner.projectVerifiedClaim(),
      /unavailable without a production durable head/u,
      "local rollback detection must not issue a production verification brand",
    );
    assert.throws(
      () => winner.projectTestVerifiedClaim(),
      /independently retained monotonic owner/u,
      "Mechanism-A evidence must not be mislabeled as injected-test evidence",
    );

    const durableRows = structuredClone(winner.rows());
    const recovered = createMechanismAPhysicalExperimentLedger(productionInput);
    const recoveredIndex = recovered.rebuildIndex();
    assert.deepEqual(recovered.rows(), durableRows);
    assert.deepEqual(recoveredIndex, index);
    assert.notEqual(recoveredIndex, index);
    assert.throws(
      () => recovered.append(structuredClone(durableRows[0])),
      /sequence|hash chain|append receipt|duplicate|backdated/u,
      "a signed row from an earlier sequence cannot be replayed at the durable head",
    );

    const finalRowPath = path.join(
      home,
      "hacker-bob-sessions",
      domain,
      "physical-campaign",
      "experiments",
      recovered.plan.plan_hash,
      "rows",
      "000005.json",
    );
    const experimentStagingPath = path.join(path.dirname(path.dirname(finalRowPath)), ".staging");
    const linkedRowStage = path.join(
      experimentStagingPath,
      `.000005.json.${process.pid}.${Date.now()}.${crypto.randomBytes(12).toString("hex")}.tmp`,
    );
    fs.linkSync(finalRowPath, linkedRowStage);
    assert.equal(fs.statSync(finalRowPath).nlink, 2);
    assert.equal(recovered.rebuildIndex().row_chain_head, claim.row_hash);
    assert.equal(fs.existsSync(linkedRowStage), false);
    assert.equal(fs.statSync(finalRowPath).nlink, 1);
    const finalRowBytes = fs.readFileSync(finalRowPath);
    const tamperedRecord = JSON.parse(finalRowBytes.toString("utf8"));
    tamperedRecord.row.payload.reason_code = "differential_refuted";
    fs.writeFileSync(finalRowPath, `${JSON.stringify(tamperedRecord)}\n`, "utf8");
    assert.throws(
      () => createMechanismAPhysicalExperimentLedger(productionInput),
      /record digest drift|signed row digest/u,
      "restart must re-read and authenticate the exact immutable signed row bytes",
    );
    fs.writeFileSync(finalRowPath, finalRowBytes);
    assert.deepEqual(createMechanismAPhysicalExperimentLedger(productionInput).rebuildIndex(), index);

    const experimentPlanRoot = path.dirname(path.dirname(finalRowPath));
    const rowTailBackup = path.join(experimentPlanRoot, ".000005.row-tail-backup");
    fs.renameSync(finalRowPath, rowTailBackup);
    try {
      assert.throws(
        () => createMechanismAPhysicalExperimentLedger(productionInput),
        /row journal rollback detected by signer-custodied row-head anchor/u,
        "a fresh open must reject deletion of the exact durable row tail",
      );
    } finally {
      fs.renameSync(rowTailBackup, finalRowPath);
    }
    assert.deepEqual(createMechanismAPhysicalExperimentLedger(productionInput).rebuildIndex(), index);

    const experimentPlanBackup = path.join(
      path.dirname(path.dirname(experimentPlanRoot)),
      `.experiment-plan-${recovered.plan.plan_hash}.rollback-backup`,
    );
    fs.renameSync(experimentPlanRoot, experimentPlanBackup);
    try {
      assert.throws(
        () => createMechanismAPhysicalExperimentLedger(productionInput),
        /row journal rollback detected by signer-custodied row-head anchor/u,
        "a fresh open must reject loss of the entire plan-local row store",
      );
    } finally {
      fs.rmSync(experimentPlanRoot, { recursive: true, force: true });
      fs.renameSync(experimentPlanBackup, experimentPlanRoot);
    }
    assert.deepEqual(createMechanismAPhysicalExperimentLedger(productionInput).rebuildIndex(), index);

    const trustHeadPath = path.join(
      home,
      "hacker-bob-sessions",
      domain,
      "physical-campaign",
      "experiment-trust",
      "heads",
      "000001.json",
    );
    const trustHeadBackup = path.join(
      path.dirname(path.dirname(trustHeadPath)),
      ".000001.cold-restart-backup",
    );
    fs.renameSync(trustHeadPath, trustHeadBackup);
    try {
      assert.throws(
        () => createMechanismAPhysicalExperimentLedger(productionInput),
        /stale or the signed head changed/u,
        "a freshly opened store must reject a missing isolated-owner trust tail",
      );
      const replacementTrustEnrollment = enrollProductionPhysicalExperimentTrust({
        version: 1,
        target_domain: domain,
        session_nucleus_hash: session.nucleus.nucleus_hash,
        signerTrustRegistry: signerFixture.registry,
        observerEnrollmentRegistry: OBSERVER_ENROLLMENT_REGISTRY,
        physicalReceiptRegistry: PHYSICAL_RECEIPT_REGISTRY,
        evidenceReceiptRegistry: EVIDENCE_RECEIPT_REGISTRY,
        effectRegistry: EFFECT_REGISTRY,
        evidenceRegistry: EVIDENCE_REGISTRY,
      });
      assert.notEqual(
        replacementTrustEnrollment.trust_head_digest,
        trustEnrollment.trust_head_digest,
      );
      assert.throws(
        () => createMechanismAPhysicalExperimentLedger({
          ...productionInput,
          trustEnrollment: replacementTrustEnrollment,
        }),
        /binding conflicts with the requested runtime/u,
        "a freshly enrolled replacement head cannot rebase an existing durable experiment store",
      );
    } finally {
      if (fs.existsSync(trustHeadPath)) fs.unlinkSync(trustHeadPath);
      fs.renameSync(trustHeadBackup, trustHeadPath);
    }
    assert.deepEqual(createMechanismAPhysicalExperimentLedger(productionInput).rebuildIndex(), index);

    for (const lookalike of [
      { ...recovered },
      Object.freeze({ ...recovered }),
      Object.create(recovered),
    ]) {
      assert.throws(
        () => assertProductionPhysicalExperimentLedger(lookalike),
        /live Bob-owned production composition/u,
      );
    }
    assert.throws(
      () => assertProductionPhysicalExperimentLedger(recovered),
      /live Bob-owned production composition/u,
      "the genuine local Mechanism-A ledger itself is not a production ledger",
    );
    assert.throws(
      () => createProductionPhysicalVerdictResolverPort({ version: 1, ledgers: [{ ...recovered }] }),
      /live Bob-owned production composition/u,
    );
    assert.throws(
      () => createProductionPhysicalVerdictResolverPort({ version: 1, ledgers: [recovered] }),
      /live Bob-owned production composition/u,
      "a production resolver must reject a correctly branded but non-production Mechanism-A ledger",
    );

    const driftedNucleus = buildSessionNucleus({
      ...session.nucleus,
      operator_constraint: {
        ...session.nucleus.operator_constraint,
        operator_note: "production ledger nucleus drift fixture",
      },
    });
    fs.writeFileSync(
      path.join(session.directory, "session-nucleus.json"),
      `${JSON.stringify(driftedNucleus, null, 2)}\n`,
      "utf8",
    );
    assert.notEqual(driftedNucleus.nucleus_hash, session.nucleus.nucleus_hash);
    assert.throws(
      () => recovered.rebuildIndex(),
      /session nucleus is unavailable or has drifted|exact current physical session nucleus/u,
    );
    fs.writeFileSync(
      path.join(session.directory, "session-nucleus.json"),
      `${JSON.stringify(session.nucleus, null, 2)}\n`,
      "utf8",
    );
    assert.deepEqual(recovered.rebuildIndex(), index);

    let appendGetterExecuted = false;
    const accessorRow = {};
    Object.defineProperty(accessorRow, "row_kind", {
      enumerable: true,
      get() {
        appendGetterExecuted = true;
        throw new Error("production append getter executed");
      },
    });
    assert.throws(() => recovered.append(accessorRow), /enumerable data property/u);
    assert.equal(appendGetterExecuted, false);
    assert.throws(
      () => recovered.append(new Proxy({}, {})),
      /plain non-proxy data objects/u,
    );
    assert.throws(
      () => recovered.append(Promise.resolve({})),
      /plain non-proxy data objects/u,
    );

    const accessorInput = { ...productionInput };
    Object.defineProperty(accessorInput, "plan", {
      enumerable: true,
      get() { throw new Error("production plan getter executed"); },
    });
    assert.throws(
      () => createProductionPhysicalExperimentLedger(accessorInput),
      /enumerable data property/u,
    );
    assert.throws(
      () => createProductionPhysicalExperimentLedger(new Proxy(productionInput, {})),
      /plain non-proxy data object/u,
    );
    assert.throws(
      () => createProductionPhysicalExperimentLedger({
        ...productionInput,
        plan: Promise.resolve(productionInput.plan),
      }),
      /plain non-proxy data objects/u,
    );
    assert.throws(
      () => createProductionPhysicalExperimentLedger({
        ...productionInput,
        signerTrustRegistry: Object.freeze({ ...signerFixture.registry }),
      }),
      /closed Bob registry/u,
      "a serialized production trust-registry lookalike cannot be promoted",
    );
    let evidenceReceiptGetterExecuted = false;
    const accessorReceipts = [];
    Object.defineProperty(accessorReceipts, "0", {
      enumerable: true,
      get() {
        evidenceReceiptGetterExecuted = true;
        throw new Error("production evidence receipt getter executed");
      },
    });
    assert.throws(
      () => createProductionPhysicalExperimentLedger({
        ...productionInput,
        evidenceReceipts: accessorReceipts,
      }),
      /enumerable data property/u,
    );
    assert.equal(evidenceReceiptGetterExecuted, false);
    assert.throws(
      () => createProductionPhysicalExperimentLedger({
        ...productionInput,
        evidenceReceipts: [Promise.resolve({})],
      }),
      /plain non-proxy data objects/u,
    );
    assert.throws(
      () => createProductionPhysicalExperimentLedger({
        ...productionInput,
        evidenceReceipts: [new Proxy({}, {})],
      }),
      /plain non-proxy data objects/u,
    );
    assert.throws(
      () => createProductionPhysicalExperimentLedger({
        ...productionInput,
        evidenceReceipts: new Array(1),
      }),
      /cannot be sparse/u,
    );
    const resolverAccessor = { version: 1 };
    Object.defineProperty(resolverAccessor, "ledgers", {
      enumerable: true,
      get() { throw new Error("resolver ledger getter executed"); },
    });
    assert.throws(
      () => createProductionPhysicalVerdictResolverPort(resolverAccessor),
      /enumerable data property/u,
    );
    assert.throws(
      () => createProductionPhysicalVerdictResolverPort({
        version: 1,
        ledgers: new Proxy([recovered], {}),
      }),
      /1\.\.1024 live ledgers/u,
    );
    assert.throws(
      () => createProductionPhysicalVerdictResolverPort({
        version: 1,
        ledgers: [Promise.resolve(recovered)],
      }),
      /live Bob-owned production composition/u,
    );

    const planRoot = path.dirname(path.dirname(finalRowPath));
    const persistedBinding = JSON.parse(
      fs.readFileSync(path.join(planRoot, "binding.json"), "utf8"),
    );
    const quotaPort = openMechanismAPhysicalExperimentDurableHeadPort({
      version: 1,
      target_domain: domain,
      session_nucleus_hash: recovered.plan.session_nucleus_hash,
      plan_hash: recovered.plan.plan_hash,
      trust_binding_digest: persistedBinding.trust_binding_digest,
      trust_head_digest: persistedBinding.trust_head_digest,
      signer_owner_custody_digest: persistedBinding.signer_owner_custody_digest,
    }, restartedTrustEnrollment);
    const receiptsPath = path.join(planRoot, "receipts");
    const oversizedDigest = digest("production-store-oversized-receipt");
    assert.throws(
      () => ingestMechanismAPhysicalExperimentReceipt(quotaPort, {
        receipt_ref: "evidence-verification:oversized-receipt",
        receipt_digest: oversizedDigest,
        padding: "x".repeat((2 * 1024 * 1024) + 1),
      }),
      /serialized size cap/u,
    );
    assert.equal(fs.existsSync(path.join(receiptsPath, `${oversizedDigest}.json`)), false);
    for (let index = 0; index < 128; index += 1) {
      const filePath = path.join(receiptsPath, `${digest(`quota-sparse-${index}`)}.json`);
      const descriptor = fs.openSync(filePath, "wx", 0o600);
      try {
        fs.ftruncateSync(descriptor, 2 * 1024 * 1024);
      } finally {
        fs.closeSync(descriptor);
      }
    }
    const quotaDigest = digest("production-store-quota-trigger");
    assert.throws(
      () => ingestMechanismAPhysicalExperimentReceipt(quotaPort, {
        receipt_ref: "evidence-verification:quota-trigger",
        receipt_digest: quotaDigest,
      }),
      /aggregate size cap/u,
    );
    assert.equal(fs.existsSync(path.join(receiptsPath, `${quotaDigest}.json`)), false);

    const {
      axis_digest: priorPhysicalAxisDigest,
      ...priorPhysicalAxisBody
    } = session.nucleus.physical_scope;
    assert.match(priorPhysicalAxisDigest, /^[a-f0-9]{64}$/u);
    const advancedPhysicalScope = normalizePhysicalScopeNucleusAxis({
      ...priorPhysicalAxisBody,
      revocation_generation: session.nucleus.physical_scope.revocation_generation + 1,
    });
    const advancedNucleus = buildSessionNucleus({
      ...session.nucleus,
      physical_scope: advancedPhysicalScope,
    });
    fs.writeFileSync(
      path.join(session.directory, "session-nucleus.json"),
      `${JSON.stringify(advancedNucleus, null, 2)}\n`,
      "utf8",
    );
    const advancedTrustEnrollment = enrollProductionPhysicalExperimentTrust({
      version: 1,
      target_domain: domain,
      session_nucleus_hash: advancedNucleus.nucleus_hash,
      signerTrustRegistry: signerFixture.registry,
      observerEnrollmentRegistry: OBSERVER_ENROLLMENT_REGISTRY,
      physicalReceiptRegistry: PHYSICAL_RECEIPT_REGISTRY,
      evidenceReceiptRegistry: EVIDENCE_RECEIPT_REGISTRY,
      effectRegistry: EFFECT_REGISTRY,
      evidenceRegistry: EVIDENCE_REGISTRY,
    });
    assert.equal(advancedTrustEnrollment.trust_head_sequence, 2);
    assert.equal(
      assertCurrentProductionPhysicalExperimentTrust(advancedTrustEnrollment).revocation_generation,
      advancedNucleus.physical_scope.revocation_generation,
    );
    assert.throws(
      () => assertCurrentProductionPhysicalExperimentTrust(restartedTrustEnrollment),
      /exact current physical session nucleus|authority or revocation generation drifted/u,
    );
    assert.throws(
      () => recovered.readiness(),
      /exact current physical session nucleus|authority or revocation generation drifted/u,
      "an existing Mechanism-A ledger must fail closed after current physical revocation advances",
    );
  });
});

test("Mechanism-A trust head survives restart recovery and rejects tamper, rollback, unsafe modes, and symlinks", async () => {
  const fixture = await createMechanismAPhysicalExperimentFixture({ structural_mechanism_a: true });
  const trustRoot = path.join(
    os.homedir(),
    "hacker-bob-sessions",
    fixture.target_domain,
    "physical-campaign",
    "experiment-trust",
  );
  const keyPath = path.join(trustRoot, "trust-signing-key.json");
  const privateKeyPath = path.join(
    trustRoot,
    PHYSICAL_EXPERIMENT_TRUST_PRIVATE_KEY_BASENAME,
  );
  const headPath = path.join(trustRoot, "heads", "000001.json");
  const stagingPath = path.join(trustRoot, ".staging");
  try {
    assert.equal(fs.statSync(keyPath).mode & 0o777, 0o600);
    assert.equal(fs.statSync(privateKeyPath).mode & 0o777, 0o400);
    assert.equal(fs.statSync(headPath).mode & 0o777, 0o600);
    assert.equal(fs.statSync(trustRoot).mode & 0o777, 0o700);
    assert.equal(fs.statSync(stagingPath).mode & 0o777, 0o700);
    const publicKeyDocument = JSON.parse(fs.readFileSync(keyPath, "utf8"));
    assert.deepEqual(Object.keys(publicKeyDocument).sort(), [
      "created_at",
      "key_id",
      "private_owner_key_path_digest",
      "public_key_pem",
      "public_key_spki_sha256",
      "record_digest",
      "signature_scheme",
      "target_domain",
      "version",
    ]);
    assert.equal(Object.hasOwn(publicKeyDocument, "private_key_pem"), false);
    assert.equal(Object.hasOwn(publicKeyDocument, "private_key_der_base64url"), false);
    assert.equal(JSON.stringify(publicKeyDocument).includes("PRIVATE KEY"), false);
    assert.equal(JSON.stringify(publicKeyDocument).includes(privateKeyPath), false);
    const privateKeyDocument = JSON.parse(fs.readFileSync(privateKeyPath, "utf8"));
    assert.deepEqual(Object.keys(privateKeyDocument).sort(), [
      "created_at",
      "private_key_der_base64url",
      "record_digest",
      "signature_scheme",
      "target_domain",
      "version",
    ]);

    const orphanKeyStage = path.join(
      stagingPath,
      `.trust-signing-key.json.${process.pid}.${Date.now()}.${crypto.randomBytes(12).toString("hex")}.tmp`,
    );
    fs.copyFileSync(keyPath, orphanKeyStage);
    fs.chmodSync(orphanKeyStage, 0o600);
    assert.equal(fixture.ledger.readiness().production_ready, false);
    assert.equal(fs.existsSync(orphanKeyStage), false);

    const linkedHeadStage = path.join(
      stagingPath,
      `.000001.json.${process.pid}.${Date.now()}.${crypto.randomBytes(12).toString("hex")}.tmp`,
    );
    fs.linkSync(headPath, linkedHeadStage);
    assert.equal(fs.statSync(headPath).nlink, 2);
    assert.equal(fixture.ledger.rebuildIndex().claim_projection.outcome, "verified");
    assert.equal(fs.existsSync(linkedHeadStage), false);
    assert.equal(fs.statSync(headPath).nlink, 1);

    const originalArrayAt = Array.prototype.at;
    Array.prototype.at = function poisonedAuthoritySelection() {
      throw new Error("Array.prototype.at authority poison executed");
    };
    try {
      assert.equal(fixture.ledger.readiness().production_ready, false);
    } finally {
      Array.prototype.at = originalArrayAt;
    }

    const headBytes = fs.readFileSync(headPath);
    const tamperedHead = JSON.parse(headBytes.toString("utf8"));
    tamperedHead.signature = `${tamperedHead.signature[0] === "A" ? "B" : "A"}${tamperedHead.signature.slice(1)}`;
    fs.writeFileSync(headPath, `${JSON.stringify(tamperedHead)}\n`, { encoding: "utf8", mode: 0o600 });
    assert.throws(
      () => fixture.ledger.readiness(),
      /signature verification failed|head digest drift/u,
    );
    fs.writeFileSync(headPath, headBytes, { mode: 0o600 });
    assert.equal(fixture.ledger.readiness().production_ready, false);

    fs.chmodSync(keyPath, 0o644);
    assert.throws(() => fixture.ledger.readiness(), /Bob-owned verified-read constraints/u);
    fs.chmodSync(keyPath, 0o600);

    fs.chmodSync(privateKeyPath, 0o600);
    assert.throws(
      () => fixture.ledger.readiness(),
      /signer-owner custody changed|Mechanism-A isolated signer-owner custody/u,
    );
    fs.chmodSync(privateKeyPath, 0o400);
    assert.equal(fixture.ledger.readiness().production_ready, false);

    const keyBackup = path.join(trustRoot, ".trust-signing-key.backup");
    fs.renameSync(keyPath, keyBackup);
    fs.symlinkSync(keyBackup, keyPath);
    try {
      assert.throws(
        () => fixture.ledger.readiness(),
        /Bob-owned verified-read constraints|signer-owner custody changed/u,
      );
    } finally {
      fs.unlinkSync(keyPath);
      fs.renameSync(keyBackup, keyPath);
    }

    const privateKeyBackup = path.join(trustRoot, ".private-owner-key.backup");
    fs.renameSync(privateKeyPath, privateKeyBackup);
    fs.symlinkSync(privateKeyBackup, privateKeyPath);
    try {
      assert.throws(
        () => fixture.ledger.readiness(),
        /Bob-owned verified-read constraints|signer-owner custody changed/u,
      );
    } finally {
      fs.unlinkSync(privateKeyPath);
      fs.renameSync(privateKeyBackup, privateKeyPath);
    }
    assert.equal(fixture.ledger.readiness().production_ready, false);

    const headBackup = path.join(trustRoot, ".000001.head-backup");
    fs.renameSync(headPath, headBackup);
    try {
      assert.throws(
        () => fixture.ledger.readiness(),
        /stale or the signed head changed/u,
        "a live port must detect deletion/rollback of the enrolled trust tail",
      );
      assert.throws(
        () => fixture.ledger.rebuildIndex(),
        /stale or the signed head changed/u,
      );
    } finally {
      fs.renameSync(headBackup, headPath);
    }
    assert.equal(fixture.ledger.readiness().production_ready, false);
  } finally {
    fixture.cleanup();
  }
});

test("same-uid physical verdict helper cannot promote local signer or journal custody", async () => {
  await assert.rejects(
    createProductionPhysicalVerdictFixture(),
    /Mechanism-A isolated signer-owner custody/u,
  );
});

test("production helper binds a genuine external owner, cold-reopens, and detects whole-tree rollback", async () => {
  const fixture = await createProductionPhysicalVerdictFixture({ structural_mechanism_a: true });
  const sessionDirectory = path.join(
    os.homedir(),
    "hacker-bob-sessions",
    fixture.target_domain,
  );
  const ownerRoot = fixture.monotonic_owner_root;
  try {
    assert.ok(Object.isFrozen(fixture));
    assert.equal(assertProductionPhysicalExperimentLedger(fixture.ledger), fixture.ledger);
    assert.equal(assertVerifiedPhysicalClaimProjection(fixture.projection), fixture.projection);
    assert.equal(assertReportSafePhysicalVerdict(fixture.verdict), fixture.verdict);
    const readiness = fixture.ledger.readiness();
    assert.equal(readiness.production_ready, true);
    assert.equal(readiness.historical_event_ready, true);
    assert.equal(readiness.external_monotonic_owner_bound, true);
    assert.equal(readiness.external_monotonic_owner_digest, fixture.monotonic_head_owner.slot_digest);
    assert.equal(readiness.durability_trust_class, "independently_retained_monotonic_owner");
    assert.equal(readiness.live_capability_ready, false);
    assert.equal(
      readiness.live_capability_reason,
      "restart_durable_signed_trusted_time_not_installed",
    );
    assert.equal(fixture.projection.production_ready, true);
    assert.equal(fixture.projection.durable_row_count, 5);
    assert.equal(
      fixture.projection.external_monotonic_owner_digest,
      fixture.monotonic_head_owner.slot_digest,
    );
    assert.equal(fixture.verdict.asset_locator, fixture.asset_locator);
    assert.equal(fixture.verdict.verified_verdict_ref, fixture.verified_verdict_ref);
    assert.equal(fixture.verdict.hardware_effects_invoked, false);
    assert.equal(fs.existsSync(sessionDirectory), true);
    assert.equal(fs.existsSync(ownerRoot), true);
    assert.throws(
      () => readPhysicalMonotonicOwnerState(fixture.monotonic_head_owner),
      /exclusively claimed/u,
    );
    assert.throws(
      () => compareAndSetPhysicalMonotonicOwnerState(
        fixture.monotonic_head_owner,
        null,
        { logical_sequence: 4 },
      ),
      /exclusively claimed/u,
      "a retained generic transfer port must not be able to rewrite the experiment owner head",
    );

    const coldReopened = fixture.reopen_production_ledger();
    assert.equal(assertProductionPhysicalExperimentLedger(coldReopened), coldReopened);
    assert.deepEqual(coldReopened.rows(), fixture.ledger.rows());
    assert.deepEqual(coldReopened.projectVerifiedClaim(), fixture.projection);
    assert.equal(
      describeProductionPhysicalExperimentLedger(coldReopened).external_monotonic_owner_digest,
      fixture.monotonic_head_owner.slot_digest,
    );

    const campaignRoot = path.join(sessionDirectory, "physical-campaign");
    const experimentPlanRoot = path.join(
      campaignRoot,
      "experiments",
      fixture.ledger.plan.plan_hash,
    );
    const localAnchorPlanRoot = path.join(
      campaignRoot,
      "experiment-trust",
      "experiment-row-head-anchors",
      fixture.ledger.plan.plan_hash,
    );
    const rollbackBackupRoot = fs.mkdtempSync(
      path.join(os.tmpdir(), "bob-physical-local-tree-rollback-"),
    );
    const experimentBackup = path.join(rollbackBackupRoot, "experiment-plan");
    const localAnchorBackup = path.join(rollbackBackupRoot, "local-anchor-plan");
    fs.renameSync(experimentPlanRoot, experimentBackup);
    fs.renameSync(localAnchorPlanRoot, localAnchorBackup);
    try {
      assert.throws(
        () => fixture.reopen_production_ledger(),
        /whole-tree rollback detected by independent monotonic owner/u,
      );
    } finally {
      fs.rmSync(experimentPlanRoot, { recursive: true, force: true });
      fs.rmSync(localAnchorPlanRoot, { recursive: true, force: true });
      fs.renameSync(experimentBackup, experimentPlanRoot);
      fs.renameSync(localAnchorBackup, localAnchorPlanRoot);
      fs.rmSync(rollbackBackupRoot, { recursive: true, force: true });
    }
    assert.equal(
      assertProductionPhysicalExperimentLedger(fixture.reopen_production_ledger()).readiness()
        .production_ready,
      true,
    );
  } finally {
    fixture.cleanup();
    fixture.cleanup();
  }
  assert.equal(fs.existsSync(sessionDirectory), false);
  assert.equal(fs.existsSync(ownerRoot), false);
});

test("live capability cannot mint a production projection or escape through the direct verdict resolver", async () => {
  const fixture = await createProductionPhysicalVerdictFixture({
    structural_mechanism_a: true,
    validity_kind: "live_capability",
    issue_projection: false,
  });
  try {
    assert.equal(fixture.projection, null);
    assert.equal(fixture.verdict, null);
    assert.equal(fixture.ledger.readiness().production_ready, true);
    assert.equal(fixture.ledger.readiness().live_capability_ready, false);
    assert.equal(
      fixture.ledger.readiness().live_capability_reason,
      "restart_durable_signed_trusted_time_not_installed",
    );
    assert.throws(
      () => fixture.ledger.projectVerifiedClaim(),
      /restart-durable signed trusted-time validation/u,
      "Date.now must not issue a production live-capability projection brand",
    );
    const resolver = createProductionPhysicalVerdictResolverPort({
      version: 1,
      ledgers: [fixture.ledger],
    });
    const uninstall = installPhysicalVerdictResolver(resolver);
    try {
      assert.throws(
        () => resolvePhysicalVerdict({
          target_domain: fixture.target_domain,
          asset_locator: fixture.asset_locator,
          verified_verdict_ref: fixture.verified_verdict_ref,
        }),
        /physical_verdict_runtime_unavailable/u,
      );
    } finally {
      uninstall();
    }
  } finally {
    fixture.cleanup();
  }
});

test("a restart-durable exact signed clock remains visible but non-authorizing without a native isolated source", async () => {
  const fixture = await createProductionPhysicalVerdictFixture({
    structural_mechanism_a: true,
    validity_kind: "live_capability",
    issue_projection: false,
    restart_durable_clock: true,
  });
  try {
    const readiness = fixture.ledger.readiness();
    assert.equal(readiness.production_ready, true);
    assert.equal(readiness.restart_durable_trusted_clock_bound, true);
    assert.equal(readiness.trusted_clock_port_id, fixture.trusted_clock.port_id);
    assert.equal(readiness.trusted_clock_exact_signed_time_ready, true);
    assert.equal(readiness.trusted_clock_production_ready, false);
    assert.equal(readiness.live_capability_ready, false);
    assert.equal(readiness.live_capability_reason, FIXED_SOURCE_BLOCKER);
    assert.throws(
      () => fixture.ledger.projectVerifiedClaim(),
      /restart-durable signed trusted-time validation/u,
      "a signed mapping cannot substitute for a native restart-stable clock epoch",
    );

    const reopened = fixture.reopen_production_ledger();
    const reopenedReadiness = reopened.readiness();
    assert.equal(reopenedReadiness.restart_durable_trusted_clock_bound, true);
    assert.equal(reopenedReadiness.trusted_clock_production_ready, false);
    assert.equal(reopenedReadiness.live_capability_reason, FIXED_SOURCE_BLOCKER);
    assert.throws(
      () => reopened.projectVerifiedClaim(),
      /restart-durable signed trusted-time validation/u,
    );

    const resolver = createProductionPhysicalVerdictResolverPort({
      version: 1,
      ledgers: [reopened],
    });
    const uninstall = installPhysicalVerdictResolver(resolver);
    try {
      assert.throws(
        () => resolvePhysicalVerdict({
          target_domain: fixture.target_domain,
          asset_locator: fixture.asset_locator,
          verified_verdict_ref: fixture.verified_verdict_ref,
        }),
        /physical_verdict_runtime_unavailable/u,
      );
    } finally {
      uninstall();
    }
  } finally {
    fixture.cleanup();
  }
});

test("Mechanism-A fixture remains useful for local detection but cannot issue an authorizing claim", async () => {
  const fixture = await createMechanismAPhysicalExperimentFixture({ structural_mechanism_a: true });
  const sessionDirectory = path.join(
    os.homedir(),
    "hacker-bob-sessions",
    fixture.target_domain,
  );
  try {
    assert.ok(Object.isFrozen(fixture));
    assert.equal(assertMechanismAPhysicalExperimentLedger(fixture.ledger), fixture.ledger);
    assert.equal(fixture.projection, null);
    assert.equal(fixture.verdict, null);
    assert.equal(fixture.ledger.readiness().production_ready, false);
    assert.equal(
      fixture.ledger.readiness().durability_trust_class,
      "mechanism_a_local_signer_custodied_rollback_detection",
    );
    assert.equal(fixture.ledger.readiness().external_monotonic_owner_bound, false);
    assert.equal(
      fixture.ledger.readiness().reason,
      "independently_retained_monotonic_row_head_owner_unavailable",
    );
    assert.equal(fixture.nonauthorizing_claim_projection.outcome, "verified");
    assert.equal(fixture.nonauthorizing_claim_projection.reason_code, "differential_verified");
    assert.equal(fixture.ledger.rebuildIndex().row_count, 5);
    assert.throws(
      () => assertProductionPhysicalExperimentLedger(fixture.ledger),
      /live Bob-owned production composition/u,
    );
    assert.throws(
      () => fixture.ledger.projectVerifiedClaim(),
      /unavailable without a production durable head/u,
    );
    assert.throws(
      () => fixture.ledger.projectTestVerifiedClaim(),
      /independently retained monotonic owner/u,
    );
    assert.equal(fs.existsSync(sessionDirectory), true);
  } finally {
    fixture.cleanup();
    fixture.cleanup();
  }
  assert.equal(fs.existsSync(sessionDirectory), false);
});

test("production signer enrollment refuses public-key aliasing across principals", () => {
  const keys = ed25519PemPair();
  const common = {
    signature_scheme: "ed25519",
    public_key_pem: keys.publicKeyPem,
    trust_root_epoch: 1,
    allowed_row_kinds: ["claim_verdict"],
    valid_from: "2026-07-01T00:00:00.000Z",
    expires_at: "2036-07-01T00:00:00.000Z",
    trusted: true,
    revoked: false,
  };
  assert.throws(
    () => buildPhysicalExperimentSignerTrustRegistry({
      version: 1,
      registry_id: "physical-production-key-alias-fixture",
      signers: [{
        ...common,
        signer_key_id: "signer-key:alias-a",
        signer_principal_ref: "principal:alias-a",
        trust_domain_ref: "trust-domain:alias-a",
        independence_domain_ref: "independence-domain:alias-a",
      }, {
        ...common,
        signer_key_id: "signer-key:alias-b",
        signer_principal_ref: "principal:alias-b",
        trust_domain_ref: "trust-domain:alias-b",
        independence_domain_ref: "independence-domain:alias-b",
      }],
    }),
    /public key material is already enrolled/u,
  );
});
