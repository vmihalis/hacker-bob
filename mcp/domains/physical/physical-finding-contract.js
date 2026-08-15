"use strict";

// Closed verified-verdict and physical-finding contract shared by the consumer
// facade and the composition adapter. This layer owns both private WeakSet
// brands and their live production-claim revalidation; it exposes no generic
// branding, callback registration, or signing seam.

const crypto = require("node:crypto");
const { types: utilTypes } = require("node:util");

const {
  assertVerifiedPhysicalClaimProjection,
} = require("./physical-experiment-contract.js");
const {
  PHYSICAL_CAPABILITY_CONSUMER_VERSION,
  PHYSICAL_FINDING_KIND,
  PHYSICAL_VERDICT_KIND,
} = require("./physical-capability-manifest.js");
const {
  validateNoPhysicalSensitiveMaterial,
} = require("../../lib/physical-sensitive-material.js");
const {
  hashCanonicalJson,
} = require("../../core/verification/verification-contracts.js");

const DIGEST_RE = /^[a-f0-9]{64}$/u;
const OPAQUE_REF_RE = /^[a-z][a-z0-9._-]{0,63}:[A-Za-z0-9][A-Za-z0-9._:@-]{0,190}$/u;
const IDENTIFIER_RE = /^[a-z][a-z0-9._-]{0,127}$/u;
const CWE_RE = /^CWE-[1-9][0-9]{0,5}$/u;
const SEVERITY_VALUES = Object.freeze(["critical", "high", "medium", "low", "info"]);
const VALIDITY_KINDS = Object.freeze(["historical_event", "live_capability"]);
const REPORT_SAFE_VERDICTS = new WeakSet();
const REPORT_SAFE_VERDICT_STATE = new WeakMap();
const PHYSICAL_FINDINGS = new WeakSet();
const PHYSICAL_FINDING_STATE = new WeakMap();

function deepFreeze(value) {
  if (value == null || typeof value !== "object" || Object.isFrozen(value)) return value;
  for (const child of Object.values(value)) deepFreeze(child);
  return Object.freeze(value);
}

function assertClosedObject(value, label, required, optional = []) {
  if (value == null || typeof value !== "object" || Array.isArray(value)
      || utilTypes.isProxy(value) || Object.getPrototypeOf(value) !== Object.prototype) {
    throw new Error(`${label} must be a plain data object`);
  }
  const allowed = new Set([...required, ...optional]);
  const keys = Reflect.ownKeys(value);
  if (keys.some((key) => typeof key !== "string")) {
    throw new Error(`${label} cannot contain symbol fields`);
  }
  const unknown = keys.filter((field) => !allowed.has(field)).sort();
  const missing = required.filter((field) => !Object.prototype.hasOwnProperty.call(value, field));
  if (unknown.length > 0 || missing.length > 0) {
    throw new Error(
      `${label} fields are not exact (missing: ${missing.join(", ") || "none"}; unknown: ${unknown.join(", ") || "none"})`,
    );
  }
  const descriptors = Object.getOwnPropertyDescriptors(value);
  for (const field of keys) {
    const descriptor = descriptors[field];
    if (!descriptor || !Object.prototype.hasOwnProperty.call(descriptor, "value")
        || descriptor.enumerable !== true) {
      throw new Error(`${label}.${field} must be an enumerable data property`);
    }
  }
  return value;
}

function assertVersion(value, label) {
  if (value !== PHYSICAL_CAPABILITY_CONSUMER_VERSION) {
    throw new Error(`${label} must equal ${PHYSICAL_CAPABILITY_CONSUMER_VERSION}`);
  }
  return value;
}

function assertDigest(value, label) {
  if (typeof value !== "string" || !DIGEST_RE.test(value)) {
    throw new Error(`${label} must be a lowercase SHA-256 digest`);
  }
  return value;
}

function assertOpaqueRef(value, label, prefix = null) {
  if (typeof value !== "string" || !OPAQUE_REF_RE.test(value) || value.includes("..")) {
    throw new Error(`${label} must be a namespaced opaque reference`);
  }
  if (prefix != null && !value.startsWith(`${prefix}:`)) {
    throw new Error(`${label} must use the ${prefix}: namespace`);
  }
  return value;
}

function assertIdentifier(value, label) {
  if (typeof value !== "string" || !IDENTIFIER_RE.test(value)) {
    throw new Error(`${label} must be a lowercase identifier`);
  }
  return value;
}

function assertTimestamp(value, label) {
  if (typeof value !== "string" || Number.isNaN(Date.parse(value))
      || new Date(value).toISOString() !== value) {
    throw new Error(`${label} must be a canonical UTC ISO-8601 timestamp`);
  }
  return value;
}

function assertText(value, label, maximum) {
  if (typeof value !== "string" || value.length < 1 || value.length > maximum
      || value !== value.trim() || /[\u0000-\u001f\u007f]/u.test(value)) {
    throw new Error(`${label} must be trimmed control-free text of 1..${maximum} characters`);
  }
  validateNoPhysicalSensitiveMaterial(value, label, { maxTextChars: maximum });
  return value;
}
function normalizeReportSafeVerdictBody(input) {
  assertClosedObject(input, "physical verdict projection", [
    "version",
    "verdict_kind",
    "asset_locator",
    "verified_verdict_ref",
    "session_nucleus_hash",
    "verification_projection_digest",
    "experiment_id",
    "plan_hash",
    "outcome",
    "reason_code",
    "validity_kind",
    "valid_from",
    "decided_at",
    "transition_state_epoch",
    "transition_state_digest",
    "external_observer_independence_domain_count",
    "external_observer_independence_domain_digest",
    "high_impact_corroboration_satisfied",
    "replay_kind",
    "hardware_effects_invoked",
  ], ["expires_at"]);
  assertVersion(input.version, "physical verdict projection.version");
  if (input.verdict_kind !== PHYSICAL_VERDICT_KIND
      || input.outcome !== "verified"
      || input.reason_code !== "differential_verified") {
    throw new Error("physical verdict projection must be a differential verified verdict");
  }
  if (!VALIDITY_KINDS.includes(input.validity_kind)) {
    throw new Error("physical verdict projection.validity_kind is unsupported");
  }
  if (input.replay_kind !== "server_owned_projection" || input.hardware_effects_invoked !== false) {
    throw new Error("physical verdict projection must be a no-hardware server-owned projection");
  }
  const externalObserverDomainCount = input.external_observer_independence_domain_count;
  if (!Number.isSafeInteger(externalObserverDomainCount)
      || externalObserverDomainCount < 0 || externalObserverDomainCount > 256) {
    throw new Error(
      "physical verdict projection.external_observer_independence_domain_count must be between 0 and 256",
    );
  }
  if (typeof input.high_impact_corroboration_satisfied !== "boolean"
      || input.high_impact_corroboration_satisfied !== (externalObserverDomainCount >= 2)) {
    throw new Error("physical verdict projection high-impact corroboration does not match its domain count");
  }
  const validFrom = assertTimestamp(input.valid_from, "physical verdict projection.valid_from");
  const decidedAt = assertTimestamp(input.decided_at, "physical verdict projection.decided_at");
  const expiresAt = input.expires_at == null
    ? null
    : assertTimestamp(input.expires_at, "physical verdict projection.expires_at");
  if (input.validity_kind === "live_capability" && expiresAt == null) {
    throw new Error("live physical verdict projection requires expires_at");
  }
  if (input.validity_kind === "historical_event" && expiresAt != null) {
    throw new Error("historical physical verdict projection cannot carry expires_at");
  }
  const epoch = input.transition_state_epoch;
  if (!((Number.isSafeInteger(epoch) && epoch >= 0)
      || (typeof epoch === "string" && epoch.length >= 1 && epoch.length <= 128))) {
    throw new Error("physical verdict projection.transition_state_epoch is invalid");
  }
  return deepFreeze({
    version: input.version,
    verdict_kind: input.verdict_kind,
    asset_locator: assertOpaqueRef(input.asset_locator, "physical verdict projection.asset_locator"),
    verified_verdict_ref: assertOpaqueRef(
      input.verified_verdict_ref,
      "physical verdict projection.verified_verdict_ref",
      "physical-claim-verdict",
    ),
    session_nucleus_hash: assertDigest(
      input.session_nucleus_hash,
      "physical verdict projection.session_nucleus_hash",
    ),
    verification_projection_digest: assertDigest(
      input.verification_projection_digest,
      "physical verdict projection.verification_projection_digest",
    ),
    experiment_id: assertIdentifier(input.experiment_id, "physical verdict projection.experiment_id"),
    plan_hash: assertDigest(input.plan_hash, "physical verdict projection.plan_hash"),
    outcome: input.outcome,
    reason_code: input.reason_code,
    validity_kind: input.validity_kind,
    valid_from: validFrom,
    decided_at: decidedAt,
    transition_state_epoch: epoch,
    transition_state_digest: assertDigest(
      input.transition_state_digest,
      "physical verdict projection.transition_state_digest",
    ),
    external_observer_independence_domain_count: externalObserverDomainCount,
    external_observer_independence_domain_digest: assertDigest(
      input.external_observer_independence_domain_digest,
      "physical verdict projection.external_observer_independence_domain_digest",
    ),
    high_impact_corroboration_satisfied: input.high_impact_corroboration_satisfied,
    replay_kind: input.replay_kind,
    hardware_effects_invoked: false,
    ...(expiresAt == null ? {} : { expires_at: expiresAt }),
  });
}

function assertPhysicalVerdictSessionDigest(projectionDigest, currentDigest) {
  const projection = assertDigest(
    projectionDigest,
    "physical verdict projection.session_nucleus_hash",
  );
  const current = assertDigest(currentDigest, "current verified session nucleus hash");
  if (projection !== current) {
    throw new Error("physical verdict projection belongs to a different session nucleus");
  }
  return current;
}

function projectReportSafePhysicalVerdict(projectionInput, requestInput) {
  const projection = assertVerifiedPhysicalClaimProjection(projectionInput);
  assertClosedObject(requestInput, "physical verdict request", [
    "asset_locator",
    "session_nucleus_hash",
    "verified_verdict_ref",
  ]);
  const assetLocator = assertOpaqueRef(requestInput.asset_locator, "physical verdict request.asset_locator");
  const verdictRef = assertOpaqueRef(
    requestInput.verified_verdict_ref,
    "physical verdict request.verified_verdict_ref",
    "physical-claim-verdict",
  );
  if (projection.target_asset_ref !== assetLocator || projection.claim_verdict_ref !== verdictRef) {
    throw new Error("physical verdict request does not match the live ledger projection");
  }
  assertPhysicalVerdictSessionDigest(
    projection.session_nucleus_hash,
    requestInput.session_nucleus_hash,
  );
  const verdict = normalizeReportSafeVerdictBody({
    version: PHYSICAL_CAPABILITY_CONSUMER_VERSION,
    verdict_kind: PHYSICAL_VERDICT_KIND,
    asset_locator: assetLocator,
    verified_verdict_ref: verdictRef,
    session_nucleus_hash: requestInput.session_nucleus_hash,
    verification_projection_digest: projection.projection_digest,
    experiment_id: projection.experiment_id,
    plan_hash: projection.plan_hash,
    outcome: projection.outcome,
    reason_code: projection.reason_code,
    validity_kind: projection.validity_kind,
    valid_from: projection.valid_from,
    decided_at: projection.decided_at,
    transition_state_epoch: projection.transition_state_epoch,
    transition_state_digest: projection.transition_state_digest,
    external_observer_independence_domain_count:
      projection.external_observer_independence_domain_count,
    external_observer_independence_domain_digest:
      projection.external_observer_independence_domain_digest,
    high_impact_corroboration_satisfied: projection.high_impact_corroboration_satisfied,
    replay_kind: "server_owned_projection",
    hardware_effects_invoked: false,
    ...(projection.expires_at == null ? {} : { expires_at: projection.expires_at }),
  });
  REPORT_SAFE_VERDICTS.add(verdict);
  REPORT_SAFE_VERDICT_STATE.set(verdict, Object.freeze({ verdict, projection }));
  return verdict;
}

function assertReportSafePhysicalVerdict(value) {
  const issuance = value && REPORT_SAFE_VERDICT_STATE.get(value);
  if (value == null || typeof value !== "object" || !REPORT_SAFE_VERDICTS.has(value)
      || !issuance || issuance.verdict !== value || !Object.isFrozen(value)) {
    throw new Error("physical verdict must be issued by the server-owned verdict adapter");
  }
  const projection = assertVerifiedPhysicalClaimProjection(issuance.projection);
  if (projection.projection_digest !== value.verification_projection_digest
      || projection.claim_verdict_ref !== value.verified_verdict_ref
      || projection.session_nucleus_hash !== value.session_nucleus_hash
      || projection.external_observer_independence_domain_count
        !== value.external_observer_independence_domain_count
      || projection.external_observer_independence_domain_digest
        !== value.external_observer_independence_domain_digest
      || projection.high_impact_corroboration_satisfied
        !== value.high_impact_corroboration_satisfied) {
    throw new Error("physical verdict live projection binding drift");
  }
  return value;
}

function derivePhysicalFindingDedupeKey(input) {
  assertClosedObject(input, "physical finding dedupe input", [
    "asset_locator",
    "verified_verdict_ref",
    "verification_projection_digest",
    "title",
  ]);
  const assetLocator = assertOpaqueRef(
    input.asset_locator,
    "physical finding dedupe input.asset_locator",
  );
  const verdictRef = assertOpaqueRef(
    input.verified_verdict_ref,
    "physical finding dedupe input.verified_verdict_ref",
    "physical-claim-verdict",
  );
  const projectionDigest = assertDigest(
    input.verification_projection_digest,
    "physical finding dedupe input.verification_projection_digest",
  );
  const title = assertText(input.title, "physical finding dedupe input.title", 240);
  return crypto.createHash("sha256")
    .update(JSON.stringify([
      assetLocator,
      verdictRef,
      projectionDigest,
      title.toLowerCase(),
    ]))
    .digest("hex")
    .slice(0, 24);
}

function buildPhysicalFinding(input) {
  assertClosedObject(input, "physical finding input", [
    "title",
    "severity",
    "description",
    "impact",
    "verdict",
  ], ["cwe"]);
  const verdict = assertReportSafePhysicalVerdict(input.verdict);
  if (!SEVERITY_VALUES.includes(input.severity)) throw new Error("physical finding input.severity is invalid");
  const cwe = input.cwe == null ? null : input.cwe;
  if (cwe != null && (typeof cwe !== "string" || !CWE_RE.test(cwe))) {
    throw new Error("physical finding input.cwe must be a canonical CWE identifier");
  }
  const body = {
    version: PHYSICAL_CAPABILITY_CONSUMER_VERSION,
    finding_kind: PHYSICAL_FINDING_KIND,
    capability_pack: "physical",
    asset_locator: verdict.asset_locator,
    verified_verdict_ref: verdict.verified_verdict_ref,
    verification_projection_digest: verdict.verification_projection_digest,
    session_nucleus_hash: verdict.session_nucleus_hash,
    title: assertText(input.title, "physical finding input.title", 240),
    severity: input.severity,
    cwe,
    description: assertText(input.description, "physical finding input.description", 4000),
    impact: assertText(input.impact, "physical finding input.impact", 2000),
    validity_kind: verdict.validity_kind,
    decided_at: verdict.decided_at,
  };
  const finding = deepFreeze({
    ...body,
    finding_dedupe_key: derivePhysicalFindingDedupeKey({
      asset_locator: body.asset_locator,
      verified_verdict_ref: body.verified_verdict_ref,
      verification_projection_digest: body.verification_projection_digest,
      title: body.title,
    }),
  });
  PHYSICAL_FINDINGS.add(finding);
  PHYSICAL_FINDING_STATE.set(finding, Object.freeze({ finding, verdict }));
  return finding;
}

function assertPhysicalFinding(value) {
  const issuance = value && PHYSICAL_FINDING_STATE.get(value);
  if (value == null || typeof value !== "object" || !PHYSICAL_FINDINGS.has(value)
      || !issuance || issuance.finding !== value || !Object.isFrozen(value)) {
    throw new Error("physical finding must be issued by the physical finding adapter");
  }
  const verdict = assertReportSafePhysicalVerdict(issuance.verdict);
  if (verdict.asset_locator !== value.asset_locator
      || verdict.verified_verdict_ref !== value.verified_verdict_ref
      || verdict.verification_projection_digest !== value.verification_projection_digest
      || verdict.session_nucleus_hash !== value.session_nucleus_hash) {
    throw new Error("physical finding live verdict binding drift");
  }
  return value;
}

module.exports = Object.freeze({
  assertPhysicalFinding,
  assertPhysicalVerdictSessionDigest,
  assertReportSafePhysicalVerdict,
  buildPhysicalFinding,
  derivePhysicalFindingDedupeKey,
  projectReportSafePhysicalVerdict,
});

