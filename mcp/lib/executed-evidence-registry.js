"use strict";

// Generic, closed dispatch substrate for already-executed evidence. Source-specific
// ledgers and verifier algorithms stay behind registered adapters; the dispatcher
// only enforces their common trust, freshness, execution, and context bindings.

const crypto = require("node:crypto");

const { hashCanonicalJson, isPlainObject } = require("./verification-contracts.js");
const {
  assertVerifiedPhysicalClaimProjection,
} = require("./physical-experiment-contract.js");
const {
  normalizePhysicalSurfaceLiveRevalidationPayload,
  normalizePhysicalSurfaceTransitionPayload,
  normalizePhysicalSurfaceTransitionTopology,
  physicalSurfaceTransitionClaimPredicateDigest,
} = require("./physical-surface-transition.js");
const {
  assertDurableReceiptTrustRegistry,
  assertExecutedEvidenceRegistry,
  buildDurableReceiptTrustRegistry,
  buildExecutedEvidenceRegistry,
  defineContextResolver,
  defineDependencyProofProvider,
  defineReplayExecutor,
  defineSourceAdapter,
  defineVerifierTemplate,
  normalizeAndVerifyDurableEvidenceReceipt,
  normalizeExecutedEvidenceRef,
  _runtime: {
    assertDurableIssuerUsable,
    assertRegistry,
    componentId,
    durableReceiptPrefix,
    durableReceiptSemanticDigest,
    durableReceiptSignatureInput,
    issuerState,
  },
} = require("./executed-evidence-contract.js");

const EXECUTED_EVIDENCE_REGISTRY_VERSION = 1;
const EXECUTED_EVIDENCE_REF_VERSION = 1;
const EXECUTED_EVIDENCE_PROJECTION_VERSION = 1;
const EVIDENCE_REVERIFICATION_VERSION = 1;
const EXECUTION_CONTEXT_VERSION = 1;
const REPLAY_RESULT_VERSION = 1;
const VERIFIED_OUTCOME_VERSION = 1;
const DEPENDENCY_PROOF_VERSION = 1;
const DURABLE_EVIDENCE_RECEIPT_VERSION = 1;
const DURABLE_RECEIPT_TRUST_REGISTRY_VERSION = 1;

const REPLAY_EXECUTOR_MODES = Object.freeze(["reexecute", "verified-verdict-bind"]);
const DEPENDENCY_PROOF_PROVIDER_KINDS = Object.freeze([
  "compiler",
  "conformance",
  "manual-procedure",
  "observer",
  "transport",
  "vault-tool",
]);
const TRUST_STATES = Object.freeze(["trusted", "degraded", "untrusted"]);
const VERIFICATION_DISPOSITIONS = Object.freeze(["verified", "refuted", "inconclusive"]);
const CLEANUP_STATUSES = Object.freeze(["not_required", "succeeded", "failed", "pending", "unknown"]);
const REGISTRY_KINDS = Object.freeze([
  "source_adapters",
  "context_resolvers",
  "replay_executors",
  "verifier_templates",
  "dependency_proof_providers",
]);

const HASH_PATTERN = /^[a-f0-9]{64}$/;
const ID_PATTERN = /^[a-z][a-z0-9._-]{0,127}$/;
const REF_PATTERN = /^[a-z][a-z0-9._-]{0,63}:[A-Za-z0-9][A-Za-z0-9._:-]{0,190}$/;
const DEPENDENCY_KEY_PATTERN = /^[A-Za-z][A-Za-z0-9_.-]{0,127}$/;
const DURABLE_EVIDENCE_RECEIPT_ISSUERS = new WeakSet();
const DURABLE_EVIDENCE_RECEIPT_KINDS = Object.freeze([
  "executed_evidence_verification",
  "physical_verifier_execution",
  "physical_surface_transition",
  "physical_surface_live_revalidation",
]);
const RECEIPT_REF_PREFIX = Object.freeze({
  executed_evidence_verification: "evidence-verification",
  physical_verifier_execution: "verifier-execution",
  physical_surface_transition: "surface-transition",
  physical_surface_live_revalidation: "surface-live-state",
});
const BASE64URL_SIGNATURE_PATTERN = /^[A-Za-z0-9_-]{86}$/;

function deepFreeze(value) {
  if (!value || (typeof value !== "object" && typeof value !== "function") || Object.isFrozen(value)) return value;
  for (const child of Object.values(value)) deepFreeze(child);
  return Object.freeze(value);
}

function assertClosedObject(value, label, required, optional = []) {
  if (!isPlainObject(value)) throw new Error(`${label} must be an object`);
  const allowed = new Set([...required, ...optional]);
  const unknown = Object.keys(value).filter((field) => !allowed.has(field)).sort();
  if (unknown.length > 0) throw new Error(`${label} has unknown fields: ${unknown.join(", ")}`);
  const missing = required.filter((field) => !Object.prototype.hasOwnProperty.call(value, field));
  if (missing.length > 0) throw new Error(`${label} is missing fields: ${missing.join(", ")}`);
  return value;
}

function assertId(value, label) {
  if (typeof value !== "string" || !ID_PATTERN.test(value)) throw new Error(`${label} must be a lowercase identifier`);
  return value;
}

function assertRef(value, label, prefix = null) {
  if (typeof value !== "string" || !REF_PATTERN.test(value)) throw new Error(`${label} must be a namespaced opaque reference`);
  if (prefix != null && !value.startsWith(`${prefix}:`)) throw new Error(`${label} must use the ${prefix}: namespace`);
  return value;
}

function assertDigest(value, label) {
  if (typeof value !== "string" || !HASH_PATTERN.test(value)) throw new Error(`${label} must be a lowercase SHA-256 digest`);
  return value;
}

function assertEnum(value, values, label) {
  if (!values.includes(value)) throw new Error(`${label} must be one of ${values.join(", ")}`);
  return value;
}

function assertInteger(value, label, min = 0) {
  if (!Number.isSafeInteger(value) || value < min) throw new Error(`${label} must be a safe integer >= ${min}`);
  return value;
}

function assertBoolean(value, label) {
  if (typeof value !== "boolean") throw new Error(`${label} must be a boolean`);
  return value;
}

function assertIsoTimestamp(value, label) {
  if (typeof value !== "string" || Number.isNaN(Date.parse(value)) || new Date(value).toISOString() !== value) {
    throw new Error(`${label} must be a canonical UTC ISO-8601 timestamp`);
  }
  return value;
}

function normalizeStringArray(value, label, validator, { nonempty = false } = {}) {
  if (!Array.isArray(value) || (nonempty && value.length === 0)) {
    throw new Error(`${label} must be ${nonempty ? "a non-empty " : "an "}array`);
  }
  const normalized = value.map((entry, index) => validator(entry, `${label}[${index}]`));
  const sorted = [...new Set(normalized)].sort();
  if (sorted.length !== normalized.length) throw new Error(`${label} must not contain duplicates`);
  return Object.freeze(sorted);
}

function implementationDigest(component) {
  return component.artifact_digest || component.tool_digest;
}

const COMMON_REQUIRED_FIELDS = Object.freeze([
  "version",
  "owner_principal",
  "signed_verdict_type",
  "trust_epoch",
  "trust_state",
  "attested_at",
  "freshness_window_ms",
  "revoked",
]);
const COMMON_OPTIONAL_FIELDS = Object.freeze([
  "artifact_digest",
  "tool_digest",
  "expires_at",
  "revoked_at",
  "revocation_ref",
]);

function normalizeCanonicalReceiptValue(value, label, depth = 0) {
  if (depth > 12) throw new Error(`${label} exceeds the maximum receipt nesting depth`);
  if (value == null || typeof value === "boolean" || typeof value === "string") return value;
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new Error(`${label} must contain finite JSON numbers`);
    return value;
  }
  if (Array.isArray(value)) {
    if (value.length > 256) throw new Error(`${label} arrays may contain at most 256 entries`);
    return Object.freeze(value.map((entry, index) => (
      normalizeCanonicalReceiptValue(entry, `${label}[${index}]`, depth + 1)
    )));
  }
  if (!isPlainObject(value)) throw new Error(`${label} must contain only canonical JSON values`);
  const keys = Object.keys(value).sort();
  if (keys.length > 256) throw new Error(`${label} objects may contain at most 256 fields`);
  const normalized = {};
  for (const key of keys) {
    if (!/^[a-z][a-z0-9_]{0,95}$/.test(key)) throw new Error(`${label} has invalid key ${key}`);
    normalized[key] = normalizeCanonicalReceiptValue(value[key], `${label}.${key}`, depth + 1);
  }
  return deepFreeze(normalized);
}

function normalizeAndVerifyPhysicalSurfaceTransitionReceipt(input, registry, options = {}) {
  const label = options.label || "physical_surface_transition_receipt";
  const receipt = normalizeAndVerifyDurableEvidenceReceipt(input, registry, {
    ...options,
    expected_kind: "physical_surface_transition",
    label,
  });
  const payload = normalizePhysicalSurfaceTransitionPayload(receipt.payload, `${label}.payload`);
  if (hashCanonicalJson(payload) !== hashCanonicalJson(receipt.payload)) {
    throw new Error(`${label}.payload is not in canonical transition form`);
  }
  if (Date.parse(receipt.signed_at) < Date.parse(payload.decided_at)) {
    throw new Error(`${label} predates the verifier decision`);
  }
  return deepFreeze({ ...receipt, payload });
}

function normalizeAndVerifyPhysicalSurfaceLiveRevalidationReceipt(input, registry, options = {}) {
  const label = options.label || "physical_surface_live_revalidation_receipt";
  const receipt = normalizeAndVerifyDurableEvidenceReceipt(input, registry, {
    ...options,
    expected_kind: "physical_surface_live_revalidation",
    label,
  });
  const payload = normalizePhysicalSurfaceLiveRevalidationPayload(receipt.payload, `${label}.payload`);
  if (hashCanonicalJson(payload) !== hashCanonicalJson(receipt.payload)) {
    throw new Error(`${label}.payload is not in canonical live-revalidation form`);
  }
  if (Date.parse(receipt.signed_at) < Date.parse(payload.revalidated_at)) {
    throw new Error(`${label} predates the live-state revalidation`);
  }
  return deepFreeze({ ...receipt, payload });
}

function privateKeyObject(privateKeyPem, label) {
  if (typeof privateKeyPem !== "string" || privateKeyPem.length > 16_384) {
    throw new Error(`${label} must be a bounded PEM private key`);
  }
  let privateKey;
  try {
    privateKey = crypto.createPrivateKey(privateKeyPem);
  } catch {
    throw new Error(`${label} is not a valid private key`);
  }
  if (privateKey.asymmetricKeyType !== "ed25519") throw new Error(`${label} must be an Ed25519 private key`);
  return privateKey;
}

function createDurableEvidenceReceiptIssuer({
  trust_registry: trustRegistry,
  issuer_key_id: issuerKeyId,
  issuer_epoch: issuerEpoch,
  private_key_pem: privateKeyPem,
  commit_receipt: commitReceipt,
  resolve_committed_receipt: resolveCommittedReceipt,
  now,
} = {}) {
  assertDurableReceiptTrustRegistry(trustRegistry);
  const keyId = assertRef(issuerKeyId, "durable_evidence_receipt_issuer.issuer_key_id", "signer-key");
  const epoch = assertInteger(issuerEpoch, "durable_evidence_receipt_issuer.issuer_epoch", 1);
  const entry = issuerState(trustRegistry, keyId, epoch);
  if (!entry) throw new Error("durable evidence receipt issuer key is not registered");
  const privateKey = privateKeyObject(privateKeyPem, "durable_evidence_receipt_issuer.private_key_pem");
  const keyProbe = Buffer.from(hashCanonicalJson({
    domain: "hacker-bob/durable-evidence-receipt-key-match/v1",
    registry_digest: trustRegistry.registry_digest,
    issuer_key_id: keyId,
    issuer_epoch: epoch,
  }), "hex");
  if (!crypto.verify(null, keyProbe, entry.publicKey, crypto.sign(null, keyProbe, privateKey))) {
    throw new Error("durable evidence receipt issuer private key does not match the registered public key");
  }
  if (typeof commitReceipt !== "function") throw new Error("durable evidence receipt issuer requires commit_receipt");
  if (typeof resolveCommittedReceipt !== "function") {
    throw new Error("durable evidence receipt issuer requires resolve_committed_receipt");
  }
  if (typeof now !== "function") throw new Error("durable evidence receipt issuer requires a trusted now function");

  function issue(receiptKind, payloadInput) {
    const payload = normalizeCanonicalReceiptValue(payloadInput, "durable_evidence_receipt.payload");
    const signedAt = assertIsoTimestamp(now(), "durable_evidence_receipt_issuer.now");
    const semanticEnvelope = {
      issuer_registry_digest: trustRegistry.registry_digest,
      issuer_key_id: keyId,
      issuer_epoch: epoch,
    };
    const envelope = {
      ...semanticEnvelope,
      semantic_digest: durableReceiptSemanticDigest(receiptKind, payload, semanticEnvelope),
      signature_scheme: "ed25519",
      signed_at: signedAt,
    };
    assertDurableIssuerUsable(entry, signedAt, {
      mode: "admission",
      trustedNow: signedAt,
      receiptKind,
    });
    const signatureInput = durableReceiptSignatureInput(receiptKind, payload, envelope);
    const signature = crypto.sign(null, Buffer.from(signatureInput, "hex"), privateKey).toString("base64url");
    const signedBody = {
      version: DURABLE_EVIDENCE_RECEIPT_VERSION,
      receipt_kind: receiptKind,
      payload,
      ...envelope,
      signature,
    };
    const receiptDigest = hashCanonicalJson(signedBody);
    return deepFreeze({
      ...signedBody,
      receipt_digest: receiptDigest,
      receipt_ref: `${durableReceiptPrefix(receiptKind)}:v1:${receiptDigest}`,
    });
  }

  function resolveCanonical(receiptKind, semanticDigest) {
    const resolved = resolveCommittedReceipt({
      receipt_kind: receiptKind,
      semantic_digest: semanticDigest,
      issuer_registry_digest: trustRegistry.registry_digest,
      issuer_key_id: keyId,
      issuer_epoch: epoch,
    });
    if (resolved && typeof resolved.then === "function") {
      throw new Error("resolve_committed_receipt must resolve synchronously");
    }
    if (resolved == null) return null;
    const verified = normalizeAndVerifyDurableEvidenceReceipt(resolved, trustRegistry, {
      expected_kind: receiptKind,
      mode: "historical",
      label: "committed_durable_evidence_receipt",
    });
    if (verified.semantic_digest !== semanticDigest) {
      throw new Error("committed durable evidence receipt semantic digest drift");
    }
    return verified;
  }

  async function issueAndCommit(receiptKind, payloadInput, validateReceipt = null) {
    const normalizedPayload = normalizeCanonicalReceiptValue(payloadInput, "durable_evidence_receipt.payload");
    const semanticDigest = durableReceiptSemanticDigest(receiptKind, normalizedPayload, {
      issuer_registry_digest: trustRegistry.registry_digest,
      issuer_key_id: keyId,
      issuer_epoch: epoch,
    });
    const prior = resolveCanonical(receiptKind, semanticDigest);
    if (prior) return prior;
    const receipt = issue(receiptKind, normalizedPayload);
    if (receipt.semantic_digest !== semanticDigest) throw new Error("durable receipt semantic digest drift during issue");
    if (typeof validateReceipt === "function") validateReceipt(receipt);
    try {
      const committed = await commitReceipt(receipt, Object.freeze({
        receipt_kind: receiptKind,
        semantic_digest: semanticDigest,
      }));
      if (committed !== true) throw new Error("durable evidence receipt was not atomically committed");
    } catch (error) {
      const recovered = resolveCanonical(receiptKind, semanticDigest);
      if (recovered) return recovered;
      throw error;
    }
    const canonical = resolveCanonical(receiptKind, semanticDigest);
    if (!canonical) throw new Error("durable evidence receipt commit is not resolvable by semantic digest");
    return canonical;
  }

  const issuer = Object.freeze({
    registry_digest: trustRegistry.registry_digest,
    issuer_key_id: keyId,
    issuer_epoch: epoch,
    async issueExecutedEvidence({
      evidence_registry: evidenceRegistry,
      verification_request: verificationRequest,
      plan_hash: planHash,
      verification_deps: verificationDeps = {},
    } = {}) {
      assertRegistry(evidenceRegistry);
      const normalizedRequest = normalizeVerificationRequest(verificationRequest);
      const verified = await verifyRegisteredEvidence(evidenceRegistry, normalizedRequest, verificationDeps);
      const ref = normalizedRequest.executed_evidence_ref;
      return issueAndCommit("executed_evidence_verification", {
        version: 1,
        evidence_registry_digest: evidenceRegistry.registry_digest,
        plan_hash: assertDigest(planHash, "evidence_receipt.plan_hash"),
        source_id: ref.source_id,
        source_adapter_digest: ref.source_adapter_digest,
        evidence_ref: ref.evidence_ref,
        payload_digest: ref.expected_payload_digest,
        verdict_hash: ref.expected_verdict_hash,
        execution_identity: ref.execution_identity,
        node_contract_digest: ref.node_contract_digest,
        context_digest: ref.context_digest,
        verified_outcome_digest: verified.verified_outcome_digest,
        disposition: verified.disposition,
        decided_at: verified.decided_at,
      });
    },
    async issuePhysicalVerifierExecution(payloadInput) {
      return issueAndCommit("physical_verifier_execution", payloadInput);
    },
    async issuePhysicalSurfaceTransition(input = {}) {
      assertClosedObject(input, "physical_surface_transition_issue", [
        "verified_claim_projection",
        "target_domain",
        "participants",
        "arcs",
      ]);
      const claim = assertVerifiedPhysicalClaimProjection(input.verified_claim_projection);
      const topology = normalizePhysicalSurfaceTransitionTopology({
        target_domain: input.target_domain,
        participants: input.participants,
        arcs: input.arcs,
      });
      const topologyDigest = physicalSurfaceTransitionClaimPredicateDigest(topology);
      if (topologyDigest !== claim.claim_predicate_digest) {
        throw new Error("physical surface transition topology does not match the verified claim predicate");
      }
      const payload = normalizePhysicalSurfaceTransitionPayload({
        version: 1,
        surface_graph_schema_version: 2,
        target_domain: topology.target_domain,
        session_nucleus_hash: claim.session_nucleus_hash,
        experiment_id: claim.experiment_id,
        task_id: claim.task_id,
        attempt_id: claim.attempt_id,
        plan_hash: claim.plan_hash,
        execution_request_digest: claim.execution_request_digest,
        claim_predicate_digest: claim.claim_predicate_digest,
        claim_verdict_ref: claim.claim_verdict_ref,
        claim_verdict_hash: claim.claim_verdict_hash,
        claim_verdict_signer_key_id: claim.claim_verdict_signer_key_id,
        claim_verdict_signer_principal_ref: claim.claim_verdict_signer_principal_ref,
        claim_verdict_trust_root_epoch: claim.claim_verdict_trust_root_epoch,
        claim_verdict_trust_domain_ref: claim.claim_verdict_trust_domain_ref,
        claim_verdict_independence_domain_ref: claim.claim_verdict_independence_domain_ref,
        claim_verdict_trust_registry_digest: claim.claim_verdict_trust_registry_digest,
        claim_verdict_signer_enrollment_digest: claim.claim_verdict_signer_enrollment_digest,
        claim_verdict_authorization_context_digest: claim.claim_verdict_authorization_context_digest,
        verified_claim_projection_digest: claim.projection_digest,
        verifier_execution_receipt_ref: claim.verifier_execution_receipt_ref,
        verifier_execution_receipt_digest: claim.verifier_execution_receipt_digest,
        executed_evidence_registry_digest: claim.executed_evidence_registry_digest,
        verifier_template_id: claim.verifier_template_id,
        verifier_template_version: claim.verifier_template_version,
        verifier_template_digest: claim.verifier_template_digest,
        decision_rule_digest: claim.decision_rule_digest,
        outcome: "verified",
        reason_code: "differential_verified",
        decided_at: claim.decided_at,
        upstream_execution_identities: claim.upstream_execution_identities,
        upstream_context_digest: claim.upstream_context_digest,
        physical_state_epoch: claim.transition_state_epoch,
        physical_state_digest: claim.transition_state_digest,
        external_observer_independence_domain_count:
          claim.external_observer_independence_domain_count,
        external_observer_independence_domain_digest:
          claim.external_observer_independence_domain_digest,
        high_impact_corroboration_satisfied:
          claim.high_impact_corroboration_satisfied,
        validity_kind: claim.validity_kind,
        valid_from: claim.valid_from,
        participants: topology.participants,
        arcs: topology.arcs,
        ...(claim.validity_kind === "live_capability" ? {
          expires_at: claim.expires_at,
          capability_instance_ref: claim.capability_instance_ref,
          custody_state_digest: claim.custody_state_digest,
        } : {}),
      });
      return issueAndCommit("physical_surface_transition", payload, (receipt) => {
        if (Date.parse(receipt.signed_at) < Date.parse(payload.decided_at)) {
          throw new Error("physical surface transition receipt cannot predate the verifier decision");
        }
      });
    },
    async issuePhysicalSurfaceLiveRevalidation(payloadInput) {
      const payload = normalizePhysicalSurfaceLiveRevalidationPayload(payloadInput);
      return issueAndCommit("physical_surface_live_revalidation", payload, (receipt) => {
        if (Date.parse(receipt.signed_at) < Date.parse(payload.revalidated_at)) {
          throw new Error("physical surface live-revalidation receipt cannot predate the state observation");
        }
      });
    },
  });
  DURABLE_EVIDENCE_RECEIPT_ISSUERS.add(issuer);
  return issuer;
}

function runtimeNow(deps) {
  const value = deps && deps.now != null ? deps.now : new Date();
  const date = value instanceof Date ? new Date(value.getTime()) : new Date(value);
  if (Number.isNaN(date.getTime())) throw new Error("deps.now must be a valid timestamp");
  return date;
}

function assertFresh(timestamp, windowMs, now, label) {
  const time = Date.parse(assertIsoTimestamp(timestamp, label));
  if (time > now.getTime()) throw new Error(`${label} is in the future`);
  if (now.getTime() - time > windowMs) throw new Error(`${label} is stale`);
}

function assertComponentUsable(component, now, deps, label) {
  if (component.trust_state !== "trusted") throw new Error(`${label} is trust-degraded`);
  if (component.revoked) throw new Error(`${label} is revoked`);
  assertFresh(component.attested_at, component.freshness_window_ms, now, `${label}.attested_at`);
  if (component.expires_at != null && now.getTime() > Date.parse(component.expires_at)) throw new Error(`${label} is expired`);
  if (deps && typeof deps.isTrustEpochTrusted === "function" && deps.isTrustEpochTrusted({
    component_id: componentId(component),
    owner_principal: component.owner_principal,
    trust_epoch: component.trust_epoch,
  }) !== true) throw new Error(`${label} trust epoch is not trusted`);
  if (deps && typeof deps.isComponentRevoked === "function" && deps.isComponentRevoked({
    component_id: componentId(component),
    owner_principal: component.owner_principal,
    trust_epoch: component.trust_epoch,
  }) === true) throw new Error(`${label} is runtime-revoked`);
}

function normalizeIntegrity(input, label) {
  assertClosedObject(input, label, ["payload_digest", "implementation_digest", "content_hash_valid"]);
  return deepFreeze({
    payload_digest: assertDigest(input.payload_digest, `${label}.payload_digest`),
    implementation_digest: assertDigest(input.implementation_digest, `${label}.implementation_digest`),
    content_hash_valid: assertBoolean(input.content_hash_valid, `${label}.content_hash_valid`),
  });
}

function normalizeSignerTrust(input, label) {
  assertClosedObject(input, label, [
    "owner_principal",
    "signer_key_id",
    "signed_verdict_type",
    "trust_epoch",
    "signature_valid",
    "trusted",
    "revoked",
  ]);
  return deepFreeze({
    owner_principal: assertRef(input.owner_principal, `${label}.owner_principal`, "principal"),
    signer_key_id: assertRef(input.signer_key_id, `${label}.signer_key_id`, "signer-key"),
    signed_verdict_type: assertId(input.signed_verdict_type, `${label}.signed_verdict_type`),
    trust_epoch: assertInteger(input.trust_epoch, `${label}.trust_epoch`, 1),
    signature_valid: assertBoolean(input.signature_valid, `${label}.signature_valid`),
    trusted: assertBoolean(input.trusted, `${label}.trusted`),
    revoked: assertBoolean(input.revoked, `${label}.revoked`),
  });
}

function normalizeOutcome(input, label) {
  assertClosedObject(input, label, ["disposition", "verdict_hash", "observed_at"], ["reason"]);
  const result = {
    disposition: assertEnum(input.disposition, VERIFICATION_DISPOSITIONS, `${label}.disposition`),
    verdict_hash: assertDigest(input.verdict_hash, `${label}.verdict_hash`),
    observed_at: assertIsoTimestamp(input.observed_at, `${label}.observed_at`),
  };
  if (input.reason != null) {
    if (typeof input.reason !== "string" || input.reason.length > 1024) throw new Error(`${label}.reason must be a string <= 1024 characters`);
    result.reason = input.reason;
  }
  return deepFreeze(result);
}

function normalizeCleanup(input, label) {
  assertClosedObject(input, label, ["status"], ["cleanup_verdict_hash", "observed_at"]);
  const result = { status: assertEnum(input.status, CLEANUP_STATUSES, `${label}.status`) };
  if (input.cleanup_verdict_hash != null) result.cleanup_verdict_hash = assertDigest(input.cleanup_verdict_hash, `${label}.cleanup_verdict_hash`);
  if (input.observed_at != null) result.observed_at = assertIsoTimestamp(input.observed_at, `${label}.observed_at`);
  return deepFreeze(result);
}

function normalizeEvidenceReverification(input, label = "evidence_reverification") {
  assertClosedObject(input, label, ["version", "verified", "verification_digest"]);
  if (input.version !== EVIDENCE_REVERIFICATION_VERSION) {
    throw new Error(`${label}.version must be ${EVIDENCE_REVERIFICATION_VERSION}`);
  }
  return deepFreeze({
    version: EVIDENCE_REVERIFICATION_VERSION,
    verified: assertBoolean(input.verified, `${label}.verified`),
    verification_digest: assertDigest(input.verification_digest, `${label}.verification_digest`),
  });
}

async function resolveAndReverifyExecutedEvidence(registry, refInput, deps = {}) {
  assertRegistry(registry);
  const ref = normalizeExecutedEvidenceRef(refInput);
  const source = registry.get("source_adapters", ref.source_id);
  if (!source) throw new Error(`executed evidence source adapter is unregistered: ${ref.source_id}`);
  if (source.adapter_digest !== ref.source_adapter_digest) throw new Error(`source adapter digest drift for ${ref.source_id}`);
  assertRef(ref.evidence_ref, "executed_evidence_ref.evidence_ref", source.ref_prefix);
  const now = runtimeNow(deps);
  assertComponentUsable(source, now, deps, `source adapter ${source.source_id}`);
  const callContext = Object.freeze({ now: now.toISOString(), ref, deps });
  const row = await source.resolve(ref.evidence_ref, callContext);
  if (row == null) throw new Error(`executed evidence did not resolve: ${ref.evidence_ref}`);
  const reverified = normalizeEvidenceReverification(
    await source.reverify(row, callContext),
    `source_adapter.${source.source_id}.reverification`,
  );
  if (reverified.verified !== true) {
    throw new Error(`source adapter ${source.source_id} read-time reverification failed`);
  }

  const integrity = normalizeIntegrity(source.project_integrity(row, reverified, callContext), "executed_evidence.integrity");
  const signerTrust = normalizeSignerTrust(source.project_signer_trust(row, reverified, callContext), "executed_evidence.signer_trust");
  const executionIdentity = assertRef(source.project_execution_identity(row, reverified, callContext), "executed_evidence.execution_identity", "execution");
  const nodeContractDigest = assertDigest(source.project_node_contract_digest(row, reverified, callContext), "executed_evidence.node_contract_digest");
  const contextDigest = assertDigest(source.project_context_digest(row, reverified, callContext), "executed_evidence.context_digest");
  const surfaceRefs = normalizeStringArray(source.project_surfaces(row, reverified, callContext), "executed_evidence.surface_refs", assertRef, { nonempty: true });
  const outcome = normalizeOutcome(source.project_outcome(row, reverified, callContext), "executed_evidence.outcome");
  const cleanup = normalizeCleanup(source.project_cleanup(row, reverified, callContext), "executed_evidence.cleanup");

  if (!integrity.content_hash_valid) throw new Error("executed evidence content hash is invalid");
  if (integrity.implementation_digest !== implementationDigest(source)) throw new Error("executed evidence implementation digest drift");
  if (integrity.payload_digest !== ref.expected_payload_digest) throw new Error("executed evidence payload digest drift");
  if (signerTrust.owner_principal !== source.owner_principal) throw new Error("executed evidence owner principal drift");
  if (signerTrust.signed_verdict_type !== source.signed_verdict_type) throw new Error("executed evidence signed verdict type drift");
  if (signerTrust.trust_epoch !== source.trust_epoch) throw new Error("executed evidence trust epoch drift");
  if (!signerTrust.signature_valid || !signerTrust.trusted) throw new Error("executed evidence signer trust is degraded");
  if (signerTrust.revoked) throw new Error("executed evidence signer is revoked");
  if (executionIdentity !== ref.execution_identity) throw new Error("executed evidence execution identity drift");
  if (nodeContractDigest !== ref.node_contract_digest) throw new Error("executed evidence node-contract digest drift");
  if (contextDigest !== ref.context_digest) throw new Error("executed evidence context digest drift");
  if (outcome.verdict_hash !== ref.expected_verdict_hash) throw new Error("executed evidence verdict hash drift");
  assertFresh(outcome.observed_at, source.freshness_window_ms, now, "executed_evidence.outcome.observed_at");

  const body = {
    version: EXECUTED_EVIDENCE_PROJECTION_VERSION,
    source_id: source.source_id,
    evidence_ref: ref.evidence_ref,
    reverification: reverified,
    integrity,
    signer_trust: signerTrust,
    execution_identity: executionIdentity,
    node_contract_digest: nodeContractDigest,
    context_digest: contextDigest,
    surface_refs: surfaceRefs,
    outcome,
    cleanup,
  };
  return deepFreeze({ ...body, evidence_digest: hashCanonicalJson(body) });
}

function normalizeComponentRef(input, label, idField, digestField, versionField = null) {
  const required = [idField, digestField];
  if (versionField) required.push(versionField);
  assertClosedObject(input, label, required);
  const result = {
    [idField]: assertId(input[idField], `${label}.${idField}`),
    [digestField]: assertDigest(input[digestField], `${label}.${digestField}`),
  };
  if (versionField) result[versionField] = assertInteger(input[versionField], `${label}.${versionField}`, 1);
  return deepFreeze(result);
}

function normalizeVerificationRequest(input) {
  assertClosedObject(input, "verification_request", [
    "version",
    "executed_evidence_ref",
    "context_resolver_ref",
    "context_request",
    "replay_executor_ref",
    "verifier_template_ref",
    "dependency_proof_refs",
  ]);
  if (input.version !== EXECUTED_EVIDENCE_REGISTRY_VERSION) throw new Error(`verification_request.version must be ${EXECUTED_EVIDENCE_REGISTRY_VERSION}`);
  if (!isPlainObject(input.context_request)) throw new Error("verification_request.context_request must be an object owned by its resolver");
  if (!Array.isArray(input.dependency_proof_refs)) throw new Error("verification_request.dependency_proof_refs must be an array");
  const dependencyProofRefs = input.dependency_proof_refs.map((entry, index) => {
    const label = `verification_request.dependency_proof_refs[${index}]`;
    assertClosedObject(entry, label, ["provider_id", "provider_digest", "proof"]);
    return Object.freeze({
      provider_id: assertId(entry.provider_id, `${label}.provider_id`),
      provider_digest: assertDigest(entry.provider_digest, `${label}.provider_digest`),
      proof: entry.proof,
    });
  });
  if (new Set(dependencyProofRefs.map((entry) => entry.provider_id)).size !== dependencyProofRefs.length) {
    throw new Error("verification_request.dependency_proof_refs must not contain duplicate providers");
  }
  dependencyProofRefs.sort((left, right) => left.provider_id.localeCompare(right.provider_id));
  return {
    version: EXECUTED_EVIDENCE_REGISTRY_VERSION,
    executed_evidence_ref: normalizeExecutedEvidenceRef(input.executed_evidence_ref),
    context_resolver_ref: normalizeComponentRef(input.context_resolver_ref, "context_resolver_ref", "resolver_id", "resolver_digest"),
    context_request: input.context_request,
    replay_executor_ref: normalizeComponentRef(input.replay_executor_ref, "replay_executor_ref", "executor_id", "executor_digest"),
    verifier_template_ref: normalizeComponentRef(input.verifier_template_ref, "verifier_template_ref", "template_id", "template_digest", "template_version"),
    dependency_proof_refs: Object.freeze(dependencyProofRefs),
  };
}

function normalizeExecutionContext(input, label = "execution_context") {
  assertClosedObject(input, label, ["version", "execution_identity", "node_contract_digest", "context_digest", "surface_refs", "resolved_at"]);
  if (input.version !== EXECUTION_CONTEXT_VERSION) throw new Error(`${label}.version must be ${EXECUTION_CONTEXT_VERSION}`);
  return deepFreeze({
    version: EXECUTION_CONTEXT_VERSION,
    execution_identity: assertRef(input.execution_identity, `${label}.execution_identity`, "execution"),
    node_contract_digest: assertDigest(input.node_contract_digest, `${label}.node_contract_digest`),
    context_digest: assertDigest(input.context_digest, `${label}.context_digest`),
    surface_refs: normalizeStringArray(input.surface_refs, `${label}.surface_refs`, assertRef, { nonempty: true }),
    resolved_at: assertIsoTimestamp(input.resolved_at, `${label}.resolved_at`),
  });
}

function normalizeDependencyProof(input, label) {
  assertClosedObject(input, label, [
    "version",
    "owner_principal",
    "implementation_digest",
    "signed_verdict_type",
    "trust_epoch",
    "signature_valid",
    "trusted",
    "revoked",
    "observed_at",
    "payload_digest",
    "execution_identity",
    "node_contract_digest",
    "context_digest",
    "verdict_hash",
  ]);
  if (input.version !== DEPENDENCY_PROOF_VERSION) throw new Error(`${label}.version must be ${DEPENDENCY_PROOF_VERSION}`);
  return deepFreeze({
    version: DEPENDENCY_PROOF_VERSION,
    owner_principal: assertRef(input.owner_principal, `${label}.owner_principal`, "principal"),
    implementation_digest: assertDigest(input.implementation_digest, `${label}.implementation_digest`),
    signed_verdict_type: assertId(input.signed_verdict_type, `${label}.signed_verdict_type`),
    trust_epoch: assertInteger(input.trust_epoch, `${label}.trust_epoch`, 1),
    signature_valid: assertBoolean(input.signature_valid, `${label}.signature_valid`),
    trusted: assertBoolean(input.trusted, `${label}.trusted`),
    revoked: assertBoolean(input.revoked, `${label}.revoked`),
    observed_at: assertIsoTimestamp(input.observed_at, `${label}.observed_at`),
    payload_digest: assertDigest(input.payload_digest, `${label}.payload_digest`),
    execution_identity: assertRef(input.execution_identity, `${label}.execution_identity`, "execution"),
    node_contract_digest: assertDigest(input.node_contract_digest, `${label}.node_contract_digest`),
    context_digest: assertDigest(input.context_digest, `${label}.context_digest`),
    verdict_hash: assertDigest(input.verdict_hash, `${label}.verdict_hash`),
  });
}

function normalizeReplayResult(input, label = "replay_result") {
  assertClosedObject(input, label, [
    "version",
    "disposition",
    "signed_verdict_type",
    "verdict_hash",
    "consumed_evidence_digest",
    "execution_identity",
    "node_contract_digest",
    "context_digest",
    "executed_at",
    "cleanup_status",
  ], ["reason"]);
  if (input.version !== REPLAY_RESULT_VERSION) throw new Error(`${label}.version must be ${REPLAY_RESULT_VERSION}`);
  const body = {
    version: REPLAY_RESULT_VERSION,
    disposition: assertEnum(input.disposition, VERIFICATION_DISPOSITIONS, `${label}.disposition`),
    signed_verdict_type: assertId(input.signed_verdict_type, `${label}.signed_verdict_type`),
    verdict_hash: assertDigest(input.verdict_hash, `${label}.verdict_hash`),
    consumed_evidence_digest: assertDigest(input.consumed_evidence_digest, `${label}.consumed_evidence_digest`),
    execution_identity: assertRef(input.execution_identity, `${label}.execution_identity`, "execution"),
    node_contract_digest: assertDigest(input.node_contract_digest, `${label}.node_contract_digest`),
    context_digest: assertDigest(input.context_digest, `${label}.context_digest`),
    executed_at: assertIsoTimestamp(input.executed_at, `${label}.executed_at`),
    cleanup_status: assertEnum(input.cleanup_status, CLEANUP_STATUSES, `${label}.cleanup_status`),
  };
  if (input.reason != null) {
    if (typeof input.reason !== "string" || input.reason.length > 1024) throw new Error(`${label}.reason must be a string <= 1024 characters`);
    body.reason = input.reason;
  }
  return deepFreeze({ ...body, replay_digest: hashCanonicalJson(body) });
}

function normalizeVerifiedOutcome(input, label = "verified_outcome") {
  assertClosedObject(input, label, [
    "version",
    "disposition",
    "signed_verdict_type",
    "verdict_hash",
    "replay_digest",
    "execution_identity",
    "node_contract_digest",
    "context_digest",
    "decided_at",
  ], ["reason"]);
  if (input.version !== VERIFIED_OUTCOME_VERSION) throw new Error(`${label}.version must be ${VERIFIED_OUTCOME_VERSION}`);
  const result = {
    version: VERIFIED_OUTCOME_VERSION,
    disposition: assertEnum(input.disposition, VERIFICATION_DISPOSITIONS, `${label}.disposition`),
    signed_verdict_type: assertId(input.signed_verdict_type, `${label}.signed_verdict_type`),
    verdict_hash: assertDigest(input.verdict_hash, `${label}.verdict_hash`),
    replay_digest: assertDigest(input.replay_digest, `${label}.replay_digest`),
    execution_identity: assertRef(input.execution_identity, `${label}.execution_identity`, "execution"),
    node_contract_digest: assertDigest(input.node_contract_digest, `${label}.node_contract_digest`),
    context_digest: assertDigest(input.context_digest, `${label}.context_digest`),
    decided_at: assertIsoTimestamp(input.decided_at, `${label}.decided_at`),
  };
  if (input.reason != null) {
    if (typeof input.reason !== "string" || input.reason.length > 1024) throw new Error(`${label}.reason must be a string <= 1024 characters`);
    result.reason = input.reason;
  }
  return deepFreeze(result);
}

function requireRegisteredComponent(registry, kind, id, digestField, expectedDigest, label) {
  const component = registry.get(kind, id);
  if (!component) throw new Error(`${label} is unregistered: ${id}`);
  if (component[digestField] !== expectedDigest) throw new Error(`${label} digest drift for ${id}`);
  return component;
}

async function verifyRegisteredEvidence(registry, input, deps = {}) {
  assertRegistry(registry);
  const request = normalizeVerificationRequest(input);
  const now = runtimeNow(deps);
  const source = requireRegisteredComponent(
    registry,
    "source_adapters",
    request.executed_evidence_ref.source_id,
    "adapter_digest",
    request.executed_evidence_ref.source_adapter_digest,
    "source adapter",
  );
  const resolver = requireRegisteredComponent(
    registry,
    "context_resolvers",
    request.context_resolver_ref.resolver_id,
    "resolver_digest",
    request.context_resolver_ref.resolver_digest,
    "context resolver",
  );
  const executor = requireRegisteredComponent(
    registry,
    "replay_executors",
    request.replay_executor_ref.executor_id,
    "executor_digest",
    request.replay_executor_ref.executor_digest,
    "replay executor",
  );
  const template = requireRegisteredComponent(
    registry,
    "verifier_templates",
    request.verifier_template_ref.template_id,
    "template_digest",
    request.verifier_template_ref.template_digest,
    "verifier template",
  );
  if (template.template_version !== request.verifier_template_ref.template_version) throw new Error("verifier template version drift");
  if (!template.source_ids.includes(source.source_id)) throw new Error("verifier template does not admit this source adapter");
  if (template.context_resolver_id !== resolver.resolver_id) throw new Error("verifier template context resolver mismatch");
  if (template.replay_executor_id !== executor.executor_id || template.mode !== executor.mode) throw new Error("verifier template replay executor mismatch");

  for (const [component, label] of [[resolver, "context resolver"], [executor, "replay executor"], [template, "verifier template"]]) {
    assertComponentUsable(component, now, deps, `${label} ${componentId(component)}`);
  }
  const evidence = await resolveAndReverifyExecutedEvidence(registry, request.executed_evidence_ref, deps);
  const callbackContext = Object.freeze({ now: now.toISOString(), deps, evidence });
  const context = normalizeExecutionContext(await resolver.resolve_context(request.context_request, callbackContext));
  assertFresh(context.resolved_at, resolver.freshness_window_ms, now, "execution_context.resolved_at");
  if (context.execution_identity !== evidence.execution_identity) throw new Error("execution context identity does not bind executed evidence");
  if (context.node_contract_digest !== evidence.node_contract_digest) throw new Error("execution context node-contract digest does not bind executed evidence");
  if (context.context_digest !== evidence.context_digest) throw new Error("execution context digest does not bind executed evidence");
  if (evidence.surface_refs.some((surfaceRef) => !context.surface_refs.includes(surfaceRef))) {
    throw new Error("execution context surfaces do not contain the executed evidence surfaces");
  }

  const proofIds = request.dependency_proof_refs.map((entry) => entry.provider_id).sort();
  if (JSON.stringify(proofIds) !== JSON.stringify(template.dependency_provider_ids)) {
    throw new Error("dependency proof providers do not exactly match the verifier template");
  }
  const dependencyProofs = [];
  for (const proofRef of request.dependency_proof_refs) {
    const provider = requireRegisteredComponent(
      registry,
      "dependency_proof_providers",
      proofRef.provider_id,
      "provider_digest",
      proofRef.provider_digest,
      "dependency proof provider",
    );
    assertComponentUsable(provider, now, deps, `dependency proof provider ${provider.provider_id}`);
    // eslint-disable-next-line no-await-in-loop
    const projection = normalizeDependencyProof(
      await provider.verify_proof(proofRef.proof, callbackContext),
      `dependency_proof.${provider.provider_id}`,
    );
    if (projection.owner_principal !== provider.owner_principal) throw new Error(`dependency proof ${provider.provider_id} owner principal drift`);
    if (projection.implementation_digest !== implementationDigest(provider)) throw new Error(`dependency proof ${provider.provider_id} implementation digest drift`);
    if (projection.signed_verdict_type !== provider.signed_verdict_type) throw new Error(`dependency proof ${provider.provider_id} signed verdict type drift`);
    if (projection.trust_epoch !== provider.trust_epoch) throw new Error(`dependency proof ${provider.provider_id} trust epoch drift`);
    if (!projection.signature_valid || !projection.trusted) throw new Error(`dependency proof ${provider.provider_id} signer trust is degraded`);
    if (projection.revoked) throw new Error(`dependency proof ${provider.provider_id} is revoked`);
    assertFresh(projection.observed_at, provider.freshness_window_ms, now, `dependency_proof.${provider.provider_id}.observed_at`);
    if (
      projection.execution_identity !== context.execution_identity ||
      projection.node_contract_digest !== context.node_contract_digest ||
      projection.context_digest !== context.context_digest
    ) {
      throw new Error(`dependency proof ${provider.provider_id} execution/context binding drift`);
    }
    if (projection.verdict_hash !== evidence.outcome.verdict_hash) throw new Error(`dependency proof ${provider.provider_id} verdict binding drift`);
    dependencyProofs.push(deepFreeze({ provider_id: provider.provider_id, provider_kind: provider.provider_kind, ...projection }));
  }

  for (const key of executor.required_dependency_keys) {
    if (!Object.prototype.hasOwnProperty.call(deps, key)) throw new Error(`replay executor ${executor.executor_id} requires dependency ${key}`);
  }
  const replay = normalizeReplayResult(
    await executor.execute({ evidence, context, dependency_proofs: dependencyProofs }, callbackContext),
  );
  assertFresh(replay.executed_at, executor.freshness_window_ms, now, "replay_result.executed_at");
  if (replay.signed_verdict_type !== executor.signed_verdict_type) throw new Error("replay signed verdict type drift");
  if (replay.consumed_evidence_digest !== evidence.evidence_digest) throw new Error("replay did not bind the resolved evidence");
  if (
    replay.execution_identity !== context.execution_identity ||
    replay.node_contract_digest !== context.node_contract_digest ||
    replay.context_digest !== context.context_digest
  ) {
    throw new Error("replay execution/context binding drift");
  }
  if (
    executor.mode === "verified-verdict-bind" &&
    (replay.disposition !== evidence.outcome.disposition || replay.verdict_hash !== evidence.outcome.verdict_hash)
  ) {
    throw new Error("verified-verdict bind executor changed the signed source verdict");
  }

  const outcome = normalizeVerifiedOutcome(
    await template.adjudicate({ evidence, context, replay, dependency_proofs: dependencyProofs }, callbackContext),
  );
  assertFresh(outcome.decided_at, template.freshness_window_ms, now, "verified_outcome.decided_at");
  if (outcome.signed_verdict_type !== template.signed_verdict_type) throw new Error("verified outcome signed verdict type drift");
  if (outcome.replay_digest !== replay.replay_digest) throw new Error("verified outcome does not bind this replay");
  if (
    outcome.execution_identity !== context.execution_identity ||
    outcome.node_contract_digest !== context.node_contract_digest ||
    outcome.context_digest !== context.context_digest
  ) {
    throw new Error("verified outcome execution/context binding drift");
  }
  if (outcome.disposition !== replay.disposition || outcome.verdict_hash !== replay.verdict_hash) {
    throw new Error("verifier template changed the executed replay outcome");
  }

  const body = {
    version: VERIFIED_OUTCOME_VERSION,
    registry_digest: registry.registry_digest,
    source_id: source.source_id,
    verifier_template_id: template.template_id,
    verifier_template_version: template.template_version,
    verifier_template_digest: template.template_digest,
    replay_executor_id: executor.executor_id,
    replay_mode: executor.mode,
    evidence_digest: evidence.evidence_digest,
    execution_identity: outcome.execution_identity,
    node_contract_digest: outcome.node_contract_digest,
    context_digest: outcome.context_digest,
    surface_refs: evidence.surface_refs,
    disposition: outcome.disposition,
    signed_verdict_type: outcome.signed_verdict_type,
    verdict_hash: outcome.verdict_hash,
    cleanup: evidence.cleanup,
    dependency_proofs: Object.freeze(dependencyProofs),
    decided_at: outcome.decided_at,
  };
  return deepFreeze({ ...body, verified_outcome_digest: hashCanonicalJson(body) });
}

module.exports = {
  CLEANUP_STATUSES,
  DEPENDENCY_PROOF_PROVIDER_KINDS,
  DURABLE_EVIDENCE_RECEIPT_KINDS,
  DURABLE_EVIDENCE_RECEIPT_VERSION,
  DURABLE_RECEIPT_TRUST_REGISTRY_VERSION,
  EVIDENCE_REVERIFICATION_VERSION,
  EXECUTED_EVIDENCE_PROJECTION_VERSION,
  EXECUTED_EVIDENCE_REF_VERSION,
  EXECUTED_EVIDENCE_REGISTRY_VERSION,
  REGISTRY_KINDS,
  REPLAY_EXECUTOR_MODES,
  TRUST_STATES,
  VERIFICATION_DISPOSITIONS,
  assertDurableReceiptTrustRegistry,
  assertExecutedEvidenceRegistry,
  buildExecutedEvidenceRegistry,
  buildDurableReceiptTrustRegistry,
  createDurableEvidenceReceiptIssuer,
  defineContextResolver,
  defineDependencyProofProvider,
  defineReplayExecutor,
  defineSourceAdapter,
  defineVerifierTemplate,
  normalizeExecutedEvidenceRef,
  normalizeAndVerifyDurableEvidenceReceipt,
  normalizeAndVerifyPhysicalSurfaceLiveRevalidationReceipt,
  normalizeAndVerifyPhysicalSurfaceTransitionReceipt,
  resolveAndReverifyExecutedEvidence,
  verifyRegisteredEvidence,
};
