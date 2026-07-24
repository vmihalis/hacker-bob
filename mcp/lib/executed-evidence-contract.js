"use strict";

// Closed dependency foundation shared by the physical experiment ledger and the\n// executed-evidence runtime. This module owns the registry and durable-receipt\n// private brands, canonical normalizers, and signature verification. It does not\n// issue receipts, accept signing keys, or expose a callback registration seam.

const crypto = require("node:crypto");

const { hashCanonicalJson, isPlainObject } = require("./verification-contracts.js");
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
const REGISTRY_INSTANCES = new WeakSet();
const DURABLE_RECEIPT_TRUST_REGISTRIES = new WeakSet();
const DURABLE_RECEIPT_TRUST_REGISTRY_STATE = new WeakMap();
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

function normalizeCommonComponent(input, label) {
  if (input.version !== EXECUTED_EVIDENCE_REGISTRY_VERSION) {
    throw new Error(`${label}.version must be ${EXECUTED_EVIDENCE_REGISTRY_VERSION}`);
  }
  const hasArtifact = Object.prototype.hasOwnProperty.call(input, "artifact_digest");
  const hasTool = Object.prototype.hasOwnProperty.call(input, "tool_digest");
  if (hasArtifact === hasTool) throw new Error(`${label} must bind exactly one of artifact_digest or tool_digest`);
  const normalized = {
    version: EXECUTED_EVIDENCE_REGISTRY_VERSION,
    owner_principal: assertRef(input.owner_principal, `${label}.owner_principal`, "principal"),
    signed_verdict_type: assertId(input.signed_verdict_type, `${label}.signed_verdict_type`),
    trust_epoch: assertInteger(input.trust_epoch, `${label}.trust_epoch`, 1),
    trust_state: assertEnum(input.trust_state, TRUST_STATES, `${label}.trust_state`),
    attested_at: assertIsoTimestamp(input.attested_at, `${label}.attested_at`),
    freshness_window_ms: assertInteger(input.freshness_window_ms, `${label}.freshness_window_ms`, 1),
    revoked: assertBoolean(input.revoked, `${label}.revoked`),
  };
  if (hasArtifact) normalized.artifact_digest = assertDigest(input.artifact_digest, `${label}.artifact_digest`);
  else normalized.tool_digest = assertDigest(input.tool_digest, `${label}.tool_digest`);
  if (input.expires_at != null) {
    normalized.expires_at = assertIsoTimestamp(input.expires_at, `${label}.expires_at`);
    if (Date.parse(normalized.expires_at) <= Date.parse(normalized.attested_at)) {
      throw new Error(`${label}.expires_at must be after attested_at`);
    }
  }
  if (normalized.revoked) {
    normalized.revoked_at = assertIsoTimestamp(input.revoked_at, `${label}.revoked_at`);
    normalized.revocation_ref = assertRef(input.revocation_ref, `${label}.revocation_ref`, "revocation");
  } else if (input.revoked_at != null || input.revocation_ref != null) {
    throw new Error(`${label} cannot carry revocation fields when revoked is false`);
  }
  return normalized;
}

function componentDescriptor(input, label, required, optional, specific) {
  assertClosedObject(input, label, [...COMMON_REQUIRED_FIELDS, ...required], [...COMMON_OPTIONAL_FIELDS, ...optional]);
  return { ...normalizeCommonComponent(input, label), ...specific };
}

function requireFunctions(input, label, names) {
  for (const name of names) {
    if (typeof input[name] !== "function") throw new Error(`${label}.${name} must be a function`);
  }
}

function defineSourceAdapter(input, label = "source_adapter") {
  const functions = [
    "resolve",
    "reverify",
    "project_integrity",
    "project_signer_trust",
    "project_execution_identity",
    "project_node_contract_digest",
    "project_context_digest",
    "project_surfaces",
    "project_outcome",
    "project_cleanup",
  ];
  requireFunctions(input, label, functions);
  const descriptor = componentDescriptor(input, label, ["source_id", "ref_prefix", ...functions], [], {
    source_id: assertId(input.source_id, `${label}.source_id`),
    ref_prefix: assertId(input.ref_prefix, `${label}.ref_prefix`),
  });
  for (const name of functions) delete descriptor[name];
  const adapterDigest = hashCanonicalJson({ component_kind: "source_adapter", ...descriptor });
  return deepFreeze({ ...descriptor, adapter_digest: adapterDigest, ...Object.fromEntries(functions.map((name) => [name, input[name]])) });
}

function defineContextResolver(input, label = "context_resolver") {
  requireFunctions(input, label, ["resolve_context"]);
  const descriptor = componentDescriptor(input, label, ["resolver_id", "context_kind", "resolve_context"], [], {
    resolver_id: assertId(input.resolver_id, `${label}.resolver_id`),
    context_kind: assertId(input.context_kind, `${label}.context_kind`),
  });
  delete descriptor.resolve_context;
  const resolverDigest = hashCanonicalJson({ component_kind: "context_resolver", ...descriptor });
  return deepFreeze({ ...descriptor, resolver_digest: resolverDigest, resolve_context: input.resolve_context });
}

function defineReplayExecutor(input, label = "replay_executor") {
  requireFunctions(input, label, ["execute"]);
  const descriptor = componentDescriptor(input, label, ["executor_id", "mode", "required_dependency_keys", "execute"], [], {
    executor_id: assertId(input.executor_id, `${label}.executor_id`),
    mode: assertEnum(input.mode, REPLAY_EXECUTOR_MODES, `${label}.mode`),
    required_dependency_keys: normalizeStringArray(
      input.required_dependency_keys,
      `${label}.required_dependency_keys`,
      (value, field) => {
        if (typeof value !== "string" || !DEPENDENCY_KEY_PATTERN.test(value)) throw new Error(`${field} must be a dependency key`);
        return value;
      },
    ),
  });
  delete descriptor.execute;
  const executorDigest = hashCanonicalJson({ component_kind: "replay_executor", ...descriptor });
  return deepFreeze({ ...descriptor, executor_digest: executorDigest, execute: input.execute });
}

function defineVerifierTemplate(input, label = "verifier_template") {
  requireFunctions(input, label, ["adjudicate"]);
  const descriptor = componentDescriptor(input, label, [
    "template_id",
    "template_version",
    "mode",
    "source_ids",
    "context_resolver_id",
    "replay_executor_id",
    "dependency_provider_ids",
    "decision_rule_digest",
    "adjudicate",
  ], [], {
    template_id: assertId(input.template_id, `${label}.template_id`),
    template_version: assertInteger(input.template_version, `${label}.template_version`, 1),
    mode: assertEnum(input.mode, REPLAY_EXECUTOR_MODES, `${label}.mode`),
    source_ids: normalizeStringArray(input.source_ids, `${label}.source_ids`, assertId, { nonempty: true }),
    context_resolver_id: assertId(input.context_resolver_id, `${label}.context_resolver_id`),
    replay_executor_id: assertId(input.replay_executor_id, `${label}.replay_executor_id`),
    dependency_provider_ids: normalizeStringArray(input.dependency_provider_ids, `${label}.dependency_provider_ids`, assertId),
    decision_rule_digest: assertDigest(input.decision_rule_digest, `${label}.decision_rule_digest`),
  });
  delete descriptor.adjudicate;
  const templateDigest = hashCanonicalJson({ component_kind: "verifier_template", ...descriptor });
  return deepFreeze({ ...descriptor, template_digest: templateDigest, adjudicate: input.adjudicate });
}

function defineDependencyProofProvider(input, label = "dependency_proof_provider") {
  requireFunctions(input, label, ["verify_proof"]);
  const descriptor = componentDescriptor(input, label, ["provider_id", "provider_kind", "verify_proof"], [], {
    provider_id: assertId(input.provider_id, `${label}.provider_id`),
    provider_kind: assertEnum(input.provider_kind, DEPENDENCY_PROOF_PROVIDER_KINDS, `${label}.provider_kind`),
  });
  delete descriptor.verify_proof;
  const providerDigest = hashCanonicalJson({ component_kind: "dependency_proof_provider", ...descriptor });
  return deepFreeze({ ...descriptor, provider_digest: providerDigest, verify_proof: input.verify_proof });
}

function addDefinitions(definitions, define, idField, label) {
  if (!Array.isArray(definitions)) throw new Error(`${label} must be an array`);
  const map = new Map();
  definitions.forEach((input, index) => {
    const value = define(input, `${label}[${index}]`);
    if (map.has(value[idField])) throw new Error(`${label} has duplicate ID ${value[idField]}`);
    map.set(value[idField], value);
  });
  return map;
}

function buildExecutedEvidenceRegistry(input) {
  assertClosedObject(input, "executed_evidence_registry", REGISTRY_KINDS);
  const tables = {
    source_adapters: addDefinitions(input.source_adapters, defineSourceAdapter, "source_id", "source_adapters"),
    context_resolvers: addDefinitions(input.context_resolvers, defineContextResolver, "resolver_id", "context_resolvers"),
    replay_executors: addDefinitions(input.replay_executors, defineReplayExecutor, "executor_id", "replay_executors"),
    verifier_templates: addDefinitions(input.verifier_templates, defineVerifierTemplate, "template_id", "verifier_templates"),
    dependency_proof_providers: addDefinitions(input.dependency_proof_providers, defineDependencyProofProvider, "provider_id", "dependency_proof_providers"),
  };

  for (const template of tables.verifier_templates.values()) {
    const resolver = tables.context_resolvers.get(template.context_resolver_id);
    const executor = tables.replay_executors.get(template.replay_executor_id);
    if (!resolver) throw new Error(`verifier template ${template.template_id} names unregistered context resolver ${template.context_resolver_id}`);
    if (!executor) throw new Error(`verifier template ${template.template_id} names unregistered replay executor ${template.replay_executor_id}`);
    if (executor.mode !== template.mode) throw new Error(`verifier template ${template.template_id} mode does not match replay executor`);
    if (resolver.signed_verdict_type !== template.signed_verdict_type || executor.signed_verdict_type !== template.signed_verdict_type) {
      throw new Error(`verifier template ${template.template_id} has signed verdict type drift`);
    }
    for (const sourceId of template.source_ids) {
      const source = tables.source_adapters.get(sourceId);
      if (!source) throw new Error(`verifier template ${template.template_id} names unregistered source adapter ${sourceId}`);
      if (source.signed_verdict_type !== template.signed_verdict_type) {
        throw new Error(`verifier template ${template.template_id} has source signed verdict type drift`);
      }
    }
    for (const providerId of template.dependency_provider_ids) {
      if (!tables.dependency_proof_providers.has(providerId)) {
        throw new Error(`verifier template ${template.template_id} names unregistered dependency proof provider ${providerId}`);
      }
    }
  }

  const descriptors = {};
  for (const kind of REGISTRY_KINDS) {
    descriptors[kind] = [...tables[kind].values()]
      .sort((left, right) => {
        const leftId = componentId(left);
        const rightId = componentId(right);
        return leftId.localeCompare(rightId);
      })
      .map((entry) => {
        const copy = {};
        for (const [key, value] of Object.entries(entry)) if (typeof value !== "function") copy[key] = value;
        return deepFreeze(copy);
      });
  }
  const frozenDescriptors = deepFreeze(descriptors);
  const registryDigest = hashCanonicalJson({ version: EXECUTED_EVIDENCE_REGISTRY_VERSION, ...frozenDescriptors });
  const registry = Object.freeze({
    version: EXECUTED_EVIDENCE_REGISTRY_VERSION,
    registry_digest: registryDigest,
    get(kind, id) {
      if (!REGISTRY_KINDS.includes(kind)) return null;
      return tables[kind].get(id) || null;
    },
    ids(kind) {
      if (!REGISTRY_KINDS.includes(kind)) throw new Error(`unknown executed-evidence registry kind ${kind}`);
      return Object.freeze([...tables[kind].keys()].sort());
    },
    describe() {
      return frozenDescriptors;
    },
  });
  REGISTRY_INSTANCES.add(registry);
  return registry;
}

function assertRegistry(registry) {
  if (!registry || !REGISTRY_INSTANCES.has(registry)) {
    throw new Error("registry must be a closed Bob executed-evidence registry");
  }
}

function assertExecutedEvidenceRegistry(registry) {
  assertRegistry(registry);
  return registry;
}

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

function publicKeyDescriptor(publicKeyPem, label) {
  if (typeof publicKeyPem !== "string" || publicKeyPem.length > 16_384) {
    throw new Error(`${label} must be a bounded PEM public key`);
  }
  let publicKey;
  try {
    publicKey = crypto.createPublicKey(publicKeyPem);
  } catch {
    throw new Error(`${label} is not a valid public key`);
  }
  if (publicKey.asymmetricKeyType !== "ed25519") throw new Error(`${label} must be an Ed25519 public key`);
  const der = publicKey.export({ type: "spki", format: "der" });
  return {
    publicKey,
    public_key_spki_sha256: crypto.createHash("sha256").update(der).digest("hex"),
  };
}

function buildDurableReceiptTrustRegistry(input) {
  assertClosedObject(input, "durable_receipt_trust_registry", ["version", "registry_id", "issuers"]);
  if (input.version !== DURABLE_RECEIPT_TRUST_REGISTRY_VERSION) {
    throw new Error(`durable_receipt_trust_registry.version must be ${DURABLE_RECEIPT_TRUST_REGISTRY_VERSION}`);
  }
  const registryId = assertId(input.registry_id, "durable_receipt_trust_registry.registry_id");
  if (!Array.isArray(input.issuers) || input.issuers.length === 0 || input.issuers.length > 64) {
    throw new Error("durable_receipt_trust_registry.issuers must be a non-empty array with at most 64 entries");
  }
  const issuers = new Map();
  const descriptors = input.issuers.map((issuer, index) => {
    const label = `durable_receipt_trust_registry.issuers[${index}]`;
    assertClosedObject(issuer, label, [
      "issuer_key_id",
      "issuer_epoch",
      "signature_scheme",
      "public_key_pem",
      "receipt_kinds",
      "valid_from",
      "trusted",
      "revoked",
    ], ["expires_at", "revoked_at"]);
    if (issuer.signature_scheme !== "ed25519") throw new Error(`${label}.signature_scheme must be ed25519`);
    if (typeof issuer.trusted !== "boolean" || typeof issuer.revoked !== "boolean") {
      throw new Error(`${label} trust flags must be booleans`);
    }
    const keyId = assertRef(issuer.issuer_key_id, `${label}.issuer_key_id`, "signer-key");
    const epoch = assertInteger(issuer.issuer_epoch, `${label}.issuer_epoch`, 1);
    const validFrom = assertIsoTimestamp(issuer.valid_from, `${label}.valid_from`);
    if (!Array.isArray(issuer.receipt_kinds) || issuer.receipt_kinds.length === 0
        || issuer.receipt_kinds.length > DURABLE_EVIDENCE_RECEIPT_KINDS.length) {
      throw new Error(`${label}.receipt_kinds must be a non-empty bounded array`);
    }
    const receiptKinds = issuer.receipt_kinds.map((kind, kindIndex) => (
      assertEnum(kind, DURABLE_EVIDENCE_RECEIPT_KINDS, `${label}.receipt_kinds[${kindIndex}]`)
    )).sort();
    if (new Set(receiptKinds).size !== receiptKinds.length) {
      throw new Error(`${label}.receipt_kinds must not contain duplicates`);
    }
    const key = `${keyId}:${epoch}`;
    if (issuers.has(key)) throw new Error(`${label} duplicates issuer ${key}`);
    const { publicKey, public_key_spki_sha256: publicKeyDigest } = publicKeyDescriptor(
      issuer.public_key_pem,
      `${label}.public_key_pem`,
    );
    const descriptor = {
      issuer_key_id: keyId,
      issuer_epoch: epoch,
      signature_scheme: "ed25519",
      public_key_spki_sha256: publicKeyDigest,
      receipt_kinds: Object.freeze(receiptKinds),
      valid_from: validFrom,
      trusted: issuer.trusted,
      revoked: issuer.revoked,
    };
    if (issuer.expires_at != null) {
      descriptor.expires_at = assertIsoTimestamp(issuer.expires_at, `${label}.expires_at`);
      if (Date.parse(descriptor.expires_at) <= Date.parse(validFrom)) {
        throw new Error(`${label}.expires_at must be after valid_from`);
      }
    }
    if (issuer.revoked) {
      descriptor.revoked_at = assertIsoTimestamp(issuer.revoked_at, `${label}.revoked_at`);
    } else if (issuer.revoked_at != null) {
      throw new Error(`${label}.revoked_at requires revoked=true`);
    }
    issuers.set(key, Object.freeze({ descriptor: deepFreeze(descriptor), publicKey }));
    return descriptor;
  }).sort((left, right) => (
    `${left.issuer_key_id}:${left.issuer_epoch}`.localeCompare(`${right.issuer_key_id}:${right.issuer_epoch}`)
  ));
  const registryDigest = hashCanonicalJson({
    version: DURABLE_RECEIPT_TRUST_REGISTRY_VERSION,
    registry_id: registryId,
    issuers: descriptors,
  });
  const registry = Object.freeze({
    version: DURABLE_RECEIPT_TRUST_REGISTRY_VERSION,
    registry_id: registryId,
    registry_digest: registryDigest,
    describe() {
      return deepFreeze({ issuers: descriptors });
    },
  });
  DURABLE_RECEIPT_TRUST_REGISTRIES.add(registry);
  DURABLE_RECEIPT_TRUST_REGISTRY_STATE.set(registry, issuers);
  return registry;
}

function assertDurableReceiptTrustRegistry(registry) {
  if (!registry || !DURABLE_RECEIPT_TRUST_REGISTRIES.has(registry)) {
    throw new Error("durable receipt trust registry must be a closed Bob registry");
  }
  return registry;
}

function issuerState(registry, keyId, epoch) {
  assertDurableReceiptTrustRegistry(registry);
  return DURABLE_RECEIPT_TRUST_REGISTRY_STATE.get(registry).get(`${keyId}:${epoch}`) || null;
}

function assertDurableIssuerUsable(entry, signedAt, {
  mode = "historical",
  trustedNow = null,
  receiptKind = null,
} = {}) {
  if (!entry || !entry.descriptor.trusted) throw new Error("durable receipt issuer is not trusted");
  const descriptor = entry.descriptor;
  if (receiptKind != null && !descriptor.receipt_kinds.includes(receiptKind)) {
    throw new Error(`durable receipt issuer is not authorized for ${receiptKind}`);
  }
  const signedMs = Date.parse(assertIsoTimestamp(signedAt, "durable_receipt.signed_at"));
  if (signedMs < Date.parse(descriptor.valid_from)) throw new Error("durable receipt predates issuer validity");
  if (descriptor.expires_at != null && signedMs > Date.parse(descriptor.expires_at)) {
    throw new Error("durable receipt postdates issuer validity");
  }
  if (descriptor.revoked && descriptor.revoked_at != null && signedMs >= Date.parse(descriptor.revoked_at)) {
    throw new Error("durable receipt was signed after issuer revocation");
  }
  if (mode === "admission") {
    const now = Date.parse(assertIsoTimestamp(trustedNow, "trusted_now"));
    if (signedMs > now) throw new Error("durable receipt signed_at is in the future");
    if (descriptor.revoked && now >= Date.parse(descriptor.revoked_at)) {
      throw new Error("durable receipt issuer is currently revoked");
    }
    if (descriptor.expires_at != null && now > Date.parse(descriptor.expires_at)) {
      throw new Error("durable receipt issuer is currently expired");
    }
  } else if (mode !== "historical") {
    throw new Error("durable receipt verification mode must be historical or admission");
  }
}

function durableReceiptSignatureInput(receiptKind, payload, envelope) {
  return hashCanonicalJson({
    domain: "hacker-bob/durable-evidence-receipt/v1",
    version: DURABLE_EVIDENCE_RECEIPT_VERSION,
    receipt_kind: receiptKind,
    payload,
    issuer_registry_digest: envelope.issuer_registry_digest,
    issuer_key_id: envelope.issuer_key_id,
    issuer_epoch: envelope.issuer_epoch,
    semantic_digest: envelope.semantic_digest,
    signature_scheme: envelope.signature_scheme,
    signed_at: envelope.signed_at,
  });
}

function durableReceiptSemanticDigest(receiptKind, payload, envelope) {
  return hashCanonicalJson({
    domain: "hacker-bob/durable-evidence-receipt-semantic/v1",
    version: DURABLE_EVIDENCE_RECEIPT_VERSION,
    receipt_kind: receiptKind,
    payload,
    issuer_registry_digest: envelope.issuer_registry_digest,
    issuer_key_id: envelope.issuer_key_id,
    issuer_epoch: envelope.issuer_epoch,
  });
}

function durableReceiptPrefix(receiptKind) {
  return RECEIPT_REF_PREFIX[receiptKind];
}

function normalizeAndVerifyDurableEvidenceReceipt(input, registry, {
  expected_kind: expectedKind = null,
  mode = "historical",
  trusted_now: trustedNow = null,
  label = "durable_evidence_receipt",
} = {}) {
  assertDurableReceiptTrustRegistry(registry);
  assertClosedObject(input, label, [
    "version",
    "receipt_kind",
    "payload",
    "issuer_registry_digest",
    "issuer_key_id",
    "issuer_epoch",
    "semantic_digest",
    "signature_scheme",
    "signed_at",
    "signature",
    "receipt_digest",
    "receipt_ref",
  ]);
  if (input.version !== DURABLE_EVIDENCE_RECEIPT_VERSION) {
    throw new Error(`${label}.version must be ${DURABLE_EVIDENCE_RECEIPT_VERSION}`);
  }
  const receiptKind = assertEnum(input.receipt_kind, DURABLE_EVIDENCE_RECEIPT_KINDS, `${label}.receipt_kind`);
  if (expectedKind != null && receiptKind !== expectedKind) throw new Error(`${label}.receipt_kind must be ${expectedKind}`);
  const payload = normalizeCanonicalReceiptValue(input.payload, `${label}.payload`);
  const envelope = {
    issuer_registry_digest: assertDigest(input.issuer_registry_digest, `${label}.issuer_registry_digest`),
    issuer_key_id: assertRef(input.issuer_key_id, `${label}.issuer_key_id`, "signer-key"),
    issuer_epoch: assertInteger(input.issuer_epoch, `${label}.issuer_epoch`, 1),
    semantic_digest: assertDigest(input.semantic_digest, `${label}.semantic_digest`),
    signature_scheme: input.signature_scheme === "ed25519"
      ? "ed25519"
      : (() => { throw new Error(`${label}.signature_scheme must be ed25519`); })(),
    signed_at: assertIsoTimestamp(input.signed_at, `${label}.signed_at`),
  };
  if (envelope.issuer_registry_digest !== registry.registry_digest) {
    throw new Error(`${label}.issuer_registry_digest does not match the closed registry`);
  }
  const expectedSemanticDigest = durableReceiptSemanticDigest(receiptKind, payload, envelope);
  if (envelope.semantic_digest !== expectedSemanticDigest) {
    throw new Error(`${label}.semantic_digest does not bind the canonical receipt payload`);
  }
  if (typeof input.signature !== "string" || !BASE64URL_SIGNATURE_PATTERN.test(input.signature)) {
    throw new Error(`${label}.signature must be a canonical 86-character Ed25519 base64url signature`);
  }
  const signatureBytes = Buffer.from(input.signature, "base64url");
  if (signatureBytes.length !== 64 || signatureBytes.toString("base64url") !== input.signature) {
    throw new Error(`${label}.signature must use canonical Ed25519 base64url encoding`);
  }
  const entry = issuerState(registry, envelope.issuer_key_id, envelope.issuer_epoch);
  assertDurableIssuerUsable(entry, envelope.signed_at, { mode, trustedNow, receiptKind });
  const signatureInput = durableReceiptSignatureInput(receiptKind, payload, envelope);
  const verified = entry && crypto.verify(
    null,
    Buffer.from(signatureInput, "hex"),
    entry.publicKey,
    signatureBytes,
  );
  if (!verified) throw new Error(`${label}.signature verification failed`);
  const signedBody = {
    version: DURABLE_EVIDENCE_RECEIPT_VERSION,
    receipt_kind: receiptKind,
    payload,
    ...envelope,
    signature: input.signature,
  };
  const receiptDigest = hashCanonicalJson(signedBody);
  if (assertDigest(input.receipt_digest, `${label}.receipt_digest`) !== receiptDigest) {
    throw new Error(`${label}.receipt_digest does not match the signed receipt`);
  }
  const expectedRef = `${durableReceiptPrefix(receiptKind)}:v1:${receiptDigest}`;
  if (assertRef(input.receipt_ref, `${label}.receipt_ref`, durableReceiptPrefix(receiptKind)) !== expectedRef) {
    throw new Error(`${label}.receipt_ref does not content-address the signed receipt`);
  }
  return deepFreeze({ ...signedBody, receipt_digest: receiptDigest, receipt_ref: expectedRef });
}
function normalizeExecutedEvidenceRef(input, label = "executed_evidence_ref") {
  assertClosedObject(input, label, [
    "version",
    "source_id",
    "source_adapter_digest",
    "evidence_ref",
    "expected_payload_digest",
    "expected_verdict_hash",
    "execution_identity",
    "node_contract_digest",
    "context_digest",
  ]);
  if (input.version !== EXECUTED_EVIDENCE_REF_VERSION) throw new Error(`${label}.version must be ${EXECUTED_EVIDENCE_REF_VERSION}`);
  return deepFreeze({
    version: EXECUTED_EVIDENCE_REF_VERSION,
    source_id: assertId(input.source_id, `${label}.source_id`),
    source_adapter_digest: assertDigest(input.source_adapter_digest, `${label}.source_adapter_digest`),
    evidence_ref: assertRef(input.evidence_ref, `${label}.evidence_ref`),
    expected_payload_digest: assertDigest(input.expected_payload_digest, `${label}.expected_payload_digest`),
    expected_verdict_hash: assertDigest(input.expected_verdict_hash, `${label}.expected_verdict_hash`),
    execution_identity: assertRef(input.execution_identity, `${label}.execution_identity`, "execution"),
    node_contract_digest: assertDigest(input.node_contract_digest, `${label}.node_contract_digest`),
    context_digest: assertDigest(input.context_digest, `${label}.context_digest`),
  });
}

function componentId(component) {
  return component.source_id || component.resolver_id || component.executor_id
    || component.template_id || component.provider_id;
}

module.exports = Object.freeze({
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
  buildDurableReceiptTrustRegistry,
  buildExecutedEvidenceRegistry,
  defineContextResolver,
  defineDependencyProofProvider,
  defineReplayExecutor,
  defineSourceAdapter,
  defineVerifierTemplate,
  normalizeAndVerifyDurableEvidenceReceipt,
  normalizeExecutedEvidenceRef,
  _runtime: Object.freeze({
    assertDurableIssuerUsable,
    assertRegistry,
    componentId,
    durableReceiptPrefix,
    durableReceiptSemanticDigest,
    durableReceiptSignatureInput,
    issuerState,
    normalizeCanonicalReceiptValue,
  }),
});

