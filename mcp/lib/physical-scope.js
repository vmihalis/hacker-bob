"use strict";

// PH-IP1 is a pure import/projection boundary. Operator-authored scope enters
// only through a configured verifier that checks a domain-separated detached
// signature, current authority, trusted time, and an atomic durable replay
// reservation. Raw authority records, proof bodies, signatures, and asset
// metadata never leave in the projection.

const { hashCanonicalJson } = require("./verification-contracts.js");
const {
  PHYSICAL_GRANT_KINDS,
} = require("./physical-authority.js");
const {
  normalizeRequestedEffect,
} = require("./requested-effects.js");
const {
  normalizeOpaqueRef,
} = require("./physical-quantities.js");
const {
  PHYSICAL_NODE_TYPES,
} = require("./surface-graph.js");
const {
  PHYSICAL_SCOPE_NUCLEUS_AXIS_VERSION,
  normalizePhysicalScopeNucleusAxis,
} = require("./physical-scope-axis.js");

const PHYSICAL_SCOPE_POLICY_VERSION = 1;
const PHYSICAL_SCOPE_IMPORT_VERSION = 1;
const PHYSICAL_SCOPE_AUTHENTICATION_VERSION = 1;
const PHYSICAL_SCOPE_PROJECTION_VERSION = 1;
const PHYSICAL_SCOPE_COMPATIBILITY_VERSION = 1;
const PHYSICAL_ONLY_BOOTSTRAP_VERSION = 1;
const PHYSICAL_SCOPE_REPLAY_RESERVATION_VERSION = 1;
const PHYSICAL_SCOPE_IMPORT_DOMAIN = "hacker-bob/physical-scope-import/v1";
const PHYSICAL_SCOPE_IMPORT_KIND = "physical_scope_import";
const PHYSICAL_SCOPE_IMPORT_KEY_USAGE = "physical_scope_import_signing";

const ASSET_ROLES = Object.freeze(["instrument", "source", "verifier"]);
const AUTHORITY_DECISIONS = Object.freeze(["allow", "deny"]);
const AUTHENTICATION_METHODS = Object.freeze(["detached_signature"]);
const CONSTRAINT_KINDS = Object.freeze([
  "attempt_budget",
  "control",
  "custody",
  "observer",
  "operator_presence",
  "power",
  "rf_containment",
  "spatial_envelope",
  "stimulus_sequence",
  "temporal_window",
  "thermal",
]);
const CONSTRAINT_SUBJECT_KINDS = Object.freeze([
  "asset",
  "effect_rule",
  "expected_transition",
  "policy",
]);
const EXCLUSION_KINDS = Object.freeze([
  "asset",
  "constraint",
  "effect_rule",
  "expected_transition",
  "operation",
]);
const PHYSICAL_NODE_TYPE_SET = new Set(PHYSICAL_NODE_TYPES);
const HASH_PATTERN = /^[a-f0-9]{64}$/;
const TOKEN_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:@-]{0,190}$/;
const IDENTIFIER_PATTERN = /^[a-z][a-z0-9._-]{0,127}$/;
const VERIFIED_SCOPE_IMPORT_PROJECTIONS = new WeakSet();
const VERIFIED_SCOPE_IMPORT_PROJECTION_STATE = new WeakMap();
const PHYSICAL_SCOPE_IMPORT_VERIFIERS = new WeakSet();
const PHYSICAL_SCOPE_IMPORT_VERIFIER_STATE = new WeakMap();
const REPLAY_RESERVATION_DISPOSITIONS = Object.freeze(["created", "existing_same"]);

const PHYSICAL_SCOPE_COMPATIBILITY_RULE = deepFreeze({
  version: PHYSICAL_SCOPE_COMPATIBILITY_VERSION,
  current_policy_version: PHYSICAL_SCOPE_POLICY_VERSION,
  accepted_policy_versions: [PHYSICAL_SCOPE_POLICY_VERSION],
  legacy_absent_behavior: "physical_disabled",
  migration_behavior: "explicit_identity_only",
  unknown_version_behavior: "reject",
  rollback_behavior: "new_session_nucleus_required",
});

function deepFreeze(value) {
  if (!value || typeof value !== "object" || Object.isFrozen(value)) return value;
  for (const child of Object.values(value)) deepFreeze(child);
  return Object.freeze(value);
}

function isPlainObject(value) {
  if (value == null || typeof value !== "object" || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function assertClosedObject(value, label, requiredFields, optionalFields = []) {
  if (!isPlainObject(value)) throw new Error(`${label} must be an object`);
  const allowed = new Set([...requiredFields, ...optionalFields]);
  const unknown = Object.keys(value).filter((field) => !allowed.has(field)).sort();
  if (unknown.length > 0) throw new Error(`${label} has unknown fields: ${unknown.join(", ")}`);
  const missing = requiredFields.filter((field) => !Object.prototype.hasOwnProperty.call(value, field));
  if (missing.length > 0) throw new Error(`${label} is missing fields: ${missing.join(", ")}`);
  return value;
}

function assertEnum(value, values, label) {
  if (!values.includes(value)) throw new Error(`${label} must be one of ${values.join(", ")}`);
  return value;
}

function assertToken(value, label) {
  if (typeof value !== "string" || !TOKEN_PATTERN.test(value)) {
    throw new Error(`${label} must be a bounded opaque token`);
  }
  return value;
}

function assertIdentifier(value, label) {
  if (typeof value !== "string" || !IDENTIFIER_PATTERN.test(value)) {
    throw new Error(`${label} must be a lowercase identifier`);
  }
  return value;
}

function assertDigest(value, label) {
  if (typeof value !== "string" || !HASH_PATTERN.test(value)) {
    throw new Error(`${label} must be a lowercase SHA-256 digest`);
  }
  return value;
}

function assertInteger(value, label, min = 0) {
  if (!Number.isSafeInteger(value) || value < min) {
    throw new Error(`${label} must be a safe integer >= ${min}`);
  }
  return value;
}

function assertBoolean(value, label) {
  if (typeof value !== "boolean") throw new Error(`${label} must be a boolean`);
  return value;
}

function assertCanonicalTimestamp(value, label) {
  if (typeof value !== "string" || Number.isNaN(Date.parse(value))) {
    throw new Error(`${label} must be a canonical UTC ISO-8601 timestamp`);
  }
  if (new Date(value).toISOString() !== value) {
    throw new Error(`${label} must use canonical UTC ISO-8601 form`);
  }
  return value;
}

function assertDerivedDigest(input, field, expected, label) {
  if (!Object.prototype.hasOwnProperty.call(input, field)) return;
  if (assertDigest(input[field], `${label}.${field}`) !== expected) {
    throw new Error(`${label}.${field} does not match normalized content`);
  }
}

function normalizeUniqueSorted(values, label, normalize, { allowEmpty = true, max = 4096 } = {}) {
  if (!Array.isArray(values) || values.length > max || (!allowEmpty && values.length === 0)) {
    throw new Error(`${label} must be ${allowEmpty ? "an" : "a non-empty"} array with at most ${max} entries`);
  }
  const normalized = values.map((value, index) => normalize(value, `${label}[${index}]`));
  const digests = normalized.map((value) => hashCanonicalJson(value));
  if (new Set(digests).size !== digests.length) throw new Error(`${label} must not contain duplicates`);
  return Object.freeze(normalized.sort((left, right) => {
    const leftDigest = hashCanonicalJson(left);
    const rightDigest = hashCanonicalJson(right);
    return leftDigest.localeCompare(rightDigest);
  }));
}

function normalizeStringSet(values, label, normalize, options = {}) {
  return normalizeUniqueSorted(values, label, normalize, options);
}

function normalizeGraphNode(input, label) {
  assertClosedObject(input, label, ["node_type", "node_ref"]);
  if (!PHYSICAL_NODE_TYPE_SET.has(input.node_type)) {
    throw new Error(`${label}.node_type is not a physical surface-graph node type`);
  }
  return deepFreeze({
    node_type: input.node_type,
    node_ref: normalizeOpaqueRef(input.node_ref, `${label}.node_ref`),
  });
}

function normalizeAssetAlias(input, label = "physical_asset_alias") {
  assertClosedObject(
    input,
    label,
    ["version", "asset_role", "asset_ref", "effect_subject_refs", "graph_nodes"],
  );
  if (input.version !== PHYSICAL_SCOPE_POLICY_VERSION) {
    throw new Error(`${label}.version must be ${PHYSICAL_SCOPE_POLICY_VERSION}`);
  }
  const assetRole = assertEnum(input.asset_role, ASSET_ROLES, `${label}.asset_role`);
  const assetRef = normalizeOpaqueRef(input.asset_ref, `${label}.asset_ref`, { prefix: assetRole });
  const effectSubjectRefs = normalizeStringSet(
    input.effect_subject_refs,
    `${label}.effect_subject_refs`,
    (value, itemLabel) => normalizeOpaqueRef(value, itemLabel),
    { allowEmpty: assetRole === "verifier", max: 256 },
  );
  const graphNodes = normalizeUniqueSorted(
    input.graph_nodes,
    `${label}.graph_nodes`,
    normalizeGraphNode,
    { allowEmpty: false, max: 256 },
  );
  if (assetRole === "instrument") {
    if (effectSubjectRefs.length !== 1 || effectSubjectRefs[0] !== assetRef) {
      throw new Error(`${label}.effect_subject_refs must contain only the instrument alias`);
    }
    if (!graphNodes.some((node) => node.node_type === "instrument" && node.node_ref === assetRef)) {
      throw new Error(`${label}.graph_nodes must anchor the instrument alias`);
    }
  } else {
    for (const [index, subjectRef] of effectSubjectRefs.entries()) {
      if (!subjectRef.startsWith("target:") && !subjectRef.startsWith("environment:")) {
        throw new Error(`${label}.effect_subject_refs[${index}] must use target: or environment:`);
      }
    }
    if (
      assetRole === "verifier"
      && !graphNodes.some((node) => node.node_type === "verifier" && node.node_ref === assetRef)
    ) {
      throw new Error(`${label}.graph_nodes must anchor the verifier alias`);
    }
  }
  return deepFreeze({
    version: PHYSICAL_SCOPE_POLICY_VERSION,
    asset_role: assetRole,
    asset_ref: assetRef,
    effect_subject_refs: effectSubjectRefs,
    graph_nodes: graphNodes,
  });
}

function assetIndex(assets) {
  return new Map(assets.map((asset) => [asset.asset_ref, asset]));
}

function normalizeScopeEffectTuple(input, registry, assetsByRef, label) {
  assertClosedObject(
    input,
    label,
    [
      "version",
      "grant_kind",
      "instrument_ref",
      "subject_asset_ref",
      "operation_id",
      "parameter_digest",
      "requested_effect",
    ],
    ["verifier_ref", "tuple_digest"],
  );
  if (input.version !== PHYSICAL_SCOPE_POLICY_VERSION) {
    throw new Error(`${label}.version must be ${PHYSICAL_SCOPE_POLICY_VERSION}`);
  }
  const instrumentRef = normalizeOpaqueRef(input.instrument_ref, `${label}.instrument_ref`, {
    prefix: "instrument",
  });
  const subjectAssetRef = normalizeOpaqueRef(input.subject_asset_ref, `${label}.subject_asset_ref`);
  const instrument = assetsByRef.get(instrumentRef);
  const subjectAsset = assetsByRef.get(subjectAssetRef);
  if (!instrument || instrument.asset_role !== "instrument") {
    throw new Error(`${label}.instrument_ref is not a declared instrument alias`);
  }
  if (!subjectAsset) throw new Error(`${label}.subject_asset_ref is not a declared asset alias`);
  const requestedEffect = normalizeRequestedEffect(input.requested_effect, registry, `${label}.requested_effect`);
  if (!subjectAsset.effect_subject_refs.includes(requestedEffect.subject_ref)) {
    throw new Error(`${label}.requested_effect.subject_ref is not bound to subject_asset_ref`);
  }
  if (requestedEffect.subject_kind === "instrument") {
    if (subjectAssetRef !== instrumentRef || requestedEffect.subject_ref !== instrumentRef) {
      throw new Error(`${label} instrument effects must bind the selected instrument alias exactly`);
    }
  } else if (subjectAsset.asset_role === "instrument") {
    throw new Error(`${label} target/environment effects cannot bind an instrument as subject_asset_ref`);
  }
  const normalized = {
    version: PHYSICAL_SCOPE_POLICY_VERSION,
    grant_kind: assertEnum(input.grant_kind, PHYSICAL_GRANT_KINDS, `${label}.grant_kind`),
    instrument_ref: instrumentRef,
    subject_asset_ref: subjectAssetRef,
    operation_id: assertToken(input.operation_id, `${label}.operation_id`),
    parameter_digest: assertDigest(input.parameter_digest, `${label}.parameter_digest`),
    requested_effect: requestedEffect,
  };
  if (Object.prototype.hasOwnProperty.call(input, "verifier_ref")) {
    const verifierRef = normalizeOpaqueRef(input.verifier_ref, `${label}.verifier_ref`, { prefix: "verifier" });
    if (!assetsByRef.has(verifierRef) || assetsByRef.get(verifierRef).asset_role !== "verifier") {
      throw new Error(`${label}.verifier_ref is not a declared verifier alias`);
    }
    normalized.verifier_ref = verifierRef;
  }
  const tupleDigest = hashCanonicalJson(normalized);
  assertDerivedDigest(input, "tuple_digest", tupleDigest, label);
  return deepFreeze({ ...normalized, tuple_digest: tupleDigest });
}

function normalizeScopeEffectRule(input, registry, assetsByRef, label = "physical_scope_effect_rule") {
  assertClosedObject(input, label, ["version", "rule_id", "decision", "tuple"], ["rule_digest"]);
  if (input.version !== PHYSICAL_SCOPE_POLICY_VERSION) {
    throw new Error(`${label}.version must be ${PHYSICAL_SCOPE_POLICY_VERSION}`);
  }
  const normalized = {
    version: PHYSICAL_SCOPE_POLICY_VERSION,
    rule_id: assertIdentifier(input.rule_id, `${label}.rule_id`),
    decision: assertEnum(input.decision, AUTHORITY_DECISIONS, `${label}.decision`),
    tuple: normalizeScopeEffectTuple(input.tuple, registry, assetsByRef, `${label}.tuple`),
  };
  const ruleDigest = hashCanonicalJson(normalized);
  assertDerivedDigest(input, "rule_digest", ruleDigest, label);
  return deepFreeze({ ...normalized, rule_digest: ruleDigest });
}

function assetHasGraphNode(asset, node) {
  return asset.graph_nodes.some(
    (candidate) => candidate.node_type === node.node_type && candidate.node_ref === node.node_ref,
  );
}

function normalizeExpectedTransition(input, assetsByRef, allowedTupleDigests, label = "expected_transition") {
  assertClosedObject(
    input,
    label,
    [
      "version",
      "transition_id",
      "source_asset_ref",
      "verifier_asset_ref",
      "source_node",
      "target_node",
      "edge_type",
      "expected_outcome_ref",
      "predicate_digest",
      "verifier_template_id",
      "verifier_template_version",
      "verifier_template_digest",
      "effect_tuple_digests",
    ],
    ["transition_digest"],
  );
  if (input.version !== PHYSICAL_SCOPE_POLICY_VERSION) {
    throw new Error(`${label}.version must be ${PHYSICAL_SCOPE_POLICY_VERSION}`);
  }
  if (input.edge_type !== "demonstrated_transition") {
    throw new Error(`${label}.edge_type must be demonstrated_transition`);
  }
  const sourceAssetRef = normalizeOpaqueRef(input.source_asset_ref, `${label}.source_asset_ref`, {
    prefix: "source",
  });
  const verifierAssetRef = normalizeOpaqueRef(input.verifier_asset_ref, `${label}.verifier_asset_ref`, {
    prefix: "verifier",
  });
  const sourceAsset = assetsByRef.get(sourceAssetRef);
  const verifierAsset = assetsByRef.get(verifierAssetRef);
  if (!sourceAsset || sourceAsset.asset_role !== "source") {
    throw new Error(`${label}.source_asset_ref is not a declared source alias`);
  }
  if (!verifierAsset || verifierAsset.asset_role !== "verifier") {
    throw new Error(`${label}.verifier_asset_ref is not a declared verifier alias`);
  }
  const sourceNode = normalizeGraphNode(input.source_node, `${label}.source_node`);
  const targetNode = normalizeGraphNode(input.target_node, `${label}.target_node`);
  if (!assetHasGraphNode(sourceAsset, sourceNode)) {
    throw new Error(`${label}.source_node is not bound to source_asset_ref`);
  }
  if (!assetHasGraphNode(verifierAsset, targetNode)) {
    throw new Error(`${label}.target_node is not bound to verifier_asset_ref`);
  }
  const effectTupleDigests = normalizeStringSet(
    input.effect_tuple_digests,
    `${label}.effect_tuple_digests`,
    assertDigest,
    { allowEmpty: false, max: 256 },
  );
  for (const tupleDigest of effectTupleDigests) {
    if (!allowedTupleDigests.has(tupleDigest)) {
      throw new Error(`${label}.effect_tuple_digests references a tuple without an exact allow rule`);
    }
  }
  const normalized = {
    version: PHYSICAL_SCOPE_POLICY_VERSION,
    transition_id: assertIdentifier(input.transition_id, `${label}.transition_id`),
    source_asset_ref: sourceAssetRef,
    verifier_asset_ref: verifierAssetRef,
    source_node: sourceNode,
    target_node: targetNode,
    edge_type: "demonstrated_transition",
    expected_outcome_ref: normalizeOpaqueRef(
      input.expected_outcome_ref,
      `${label}.expected_outcome_ref`,
      { prefix: "outcome" },
    ),
    predicate_digest: assertDigest(input.predicate_digest, `${label}.predicate_digest`),
    verifier_template_id: assertIdentifier(input.verifier_template_id, `${label}.verifier_template_id`),
    verifier_template_version: assertInteger(
      input.verifier_template_version,
      `${label}.verifier_template_version`,
      1,
    ),
    verifier_template_digest: assertDigest(
      input.verifier_template_digest,
      `${label}.verifier_template_digest`,
    ),
    effect_tuple_digests: effectTupleDigests,
  };
  const transitionDigest = hashCanonicalJson(normalized);
  assertDerivedDigest(input, "transition_digest", transitionDigest, label);
  return deepFreeze({ ...normalized, transition_digest: transitionDigest });
}

function normalizeConstraint(input, known, label) {
  assertClosedObject(
    input,
    label,
    ["version", "constraint_id", "constraint_kind", "constraint_ref", "constraint_digest", "applies_to"],
  );
  if (input.version !== PHYSICAL_SCOPE_POLICY_VERSION) {
    throw new Error(`${label}.version must be ${PHYSICAL_SCOPE_POLICY_VERSION}`);
  }
  const appliesTo = normalizeUniqueSorted(
    input.applies_to,
    `${label}.applies_to`,
    (binding, bindingLabel) => {
      assertClosedObject(binding, bindingLabel, ["subject_kind", "subject_ref"]);
      const subjectKind = assertEnum(
        binding.subject_kind,
        CONSTRAINT_SUBJECT_KINDS,
        `${bindingLabel}.subject_kind`,
      );
      const subjectRef = subjectKind === "asset"
        ? normalizeOpaqueRef(binding.subject_ref, `${bindingLabel}.subject_ref`)
        : assertIdentifier(binding.subject_ref, `${bindingLabel}.subject_ref`);
      const values = known[subjectKind];
      if (!values || !values.has(subjectRef)) {
        throw new Error(`${bindingLabel}.subject_ref is not declared in this policy`);
      }
      return deepFreeze({ subject_kind: subjectKind, subject_ref: subjectRef });
    },
    { allowEmpty: false, max: 1024 },
  );
  return deepFreeze({
    version: PHYSICAL_SCOPE_POLICY_VERSION,
    constraint_id: assertIdentifier(input.constraint_id, `${label}.constraint_id`),
    constraint_kind: assertEnum(input.constraint_kind, CONSTRAINT_KINDS, `${label}.constraint_kind`),
    constraint_ref: normalizeOpaqueRef(input.constraint_ref, `${label}.constraint_ref`, { prefix: "constraint" }),
    constraint_digest: assertDigest(input.constraint_digest, `${label}.constraint_digest`),
    applies_to: appliesTo,
  });
}

function normalizeExclusion(input, known, label) {
  assertClosedObject(input, label, ["version", "exclusion_id", "exclusion_kind", "excluded_ref", "reason_code"]);
  if (input.version !== PHYSICAL_SCOPE_POLICY_VERSION) {
    throw new Error(`${label}.version must be ${PHYSICAL_SCOPE_POLICY_VERSION}`);
  }
  const exclusionKind = assertEnum(input.exclusion_kind, EXCLUSION_KINDS, `${label}.exclusion_kind`);
  const excludedRef = exclusionKind === "asset"
    ? normalizeOpaqueRef(input.excluded_ref, `${label}.excluded_ref`)
    : assertIdentifier(input.excluded_ref, `${label}.excluded_ref`);
  const values = known[exclusionKind];
  if (!values || !values.has(excludedRef)) {
    throw new Error(`${label}.excluded_ref is not declared in this policy`);
  }
  return deepFreeze({
    version: PHYSICAL_SCOPE_POLICY_VERSION,
    exclusion_id: assertIdentifier(input.exclusion_id, `${label}.exclusion_id`),
    exclusion_kind: exclusionKind,
    excluded_ref: excludedRef,
    reason_code: assertIdentifier(input.reason_code, `${label}.reason_code`),
  });
}

function assertUniqueField(values, field, label) {
  const fields = values.map((value) => value[field]);
  if (new Set(fields).size !== fields.length) throw new Error(`${label} must not repeat ${field}`);
}

function normalizePhysicalScopePolicy(input, registry, label = "physical_scope_policy") {
  assertClosedObject(
    input,
    label,
    [
      "version",
      "policy_id",
      "authority_epoch",
      "revocation_generation",
      "transition_receipt_registry_digest",
      "asset_aliases",
      "effect_rules",
      "expected_transitions",
      "constraints",
      "exclusions",
    ],
    ["policy_digest"],
  );
  if (input.version !== PHYSICAL_SCOPE_POLICY_VERSION) {
    throw new Error(`${label}.version must be ${PHYSICAL_SCOPE_POLICY_VERSION}; unknown versions fail closed`);
  }
  const policyId = assertIdentifier(input.policy_id, `${label}.policy_id`);
  const assets = normalizeUniqueSorted(
    input.asset_aliases,
    `${label}.asset_aliases`,
    normalizeAssetAlias,
    { allowEmpty: false, max: 4096 },
  );
  assertUniqueField(assets, "asset_ref", `${label}.asset_aliases`);
  const assetsByRef = assetIndex(assets);
  const rules = normalizeUniqueSorted(
    input.effect_rules,
    `${label}.effect_rules`,
    (rule, ruleLabel) => normalizeScopeEffectRule(rule, registry, assetsByRef, ruleLabel),
    { allowEmpty: false, max: 4096 },
  );
  assertUniqueField(rules, "rule_id", `${label}.effect_rules`);
  const decisionTupleKeys = rules.map((rule) => `${rule.decision}:${rule.tuple.tuple_digest}`);
  if (new Set(decisionTupleKeys).size !== decisionTupleKeys.length) {
    throw new Error(`${label}.effect_rules repeats a decision for an exact tuple`);
  }
  const explicitlyAllowedTupleDigests = new Set(
    rules.filter((rule) => rule.decision === "allow").map((rule) => rule.tuple.tuple_digest),
  );
  if (explicitlyAllowedTupleDigests.size === 0) {
    throw new Error(`${label}.effect_rules requires at least one exact allow rule`);
  }
  const explicitlyDeniedTupleDigests = new Set(
    rules.filter((rule) => rule.decision === "deny").map((rule) => rule.tuple.tuple_digest),
  );
  const effectiveAllowedTupleDigests = new Set(
    [...explicitlyAllowedTupleDigests].filter((tupleDigest) => !explicitlyDeniedTupleDigests.has(tupleDigest)),
  );
  const transitions = normalizeUniqueSorted(
    input.expected_transitions,
    `${label}.expected_transitions`,
    (transition, transitionLabel) => normalizeExpectedTransition(
      transition,
      assetsByRef,
      effectiveAllowedTupleDigests,
      transitionLabel,
    ),
    { max: 4096 },
  );
  assertUniqueField(transitions, "transition_id", `${label}.expected_transitions`);
  const operationIds = new Set(rules.map((rule) => rule.tuple.operation_id));
  const known = {
    asset: new Set(assets.map((asset) => asset.asset_ref)),
    effect_rule: new Set(rules.map((rule) => rule.rule_id)),
    expected_transition: new Set(transitions.map((transition) => transition.transition_id)),
    operation: operationIds,
    policy: new Set([policyId]),
  };
  const constraints = normalizeUniqueSorted(
    input.constraints,
    `${label}.constraints`,
    (constraint, constraintLabel) => normalizeConstraint(constraint, known, constraintLabel),
    { max: 4096 },
  );
  assertUniqueField(constraints, "constraint_id", `${label}.constraints`);
  known.constraint = new Set(constraints.map((constraint) => constraint.constraint_id));
  const exclusions = normalizeUniqueSorted(
    input.exclusions,
    `${label}.exclusions`,
    (exclusion, exclusionLabel) => normalizeExclusion(exclusion, known, exclusionLabel),
    { max: 4096 },
  );
  assertUniqueField(exclusions, "exclusion_id", `${label}.exclusions`);

  const normalized = {
    version: PHYSICAL_SCOPE_POLICY_VERSION,
    policy_id: policyId,
    authority_epoch: assertInteger(input.authority_epoch, `${label}.authority_epoch`, 1),
    revocation_generation: assertInteger(
      input.revocation_generation,
      `${label}.revocation_generation`,
      0,
    ),
    transition_receipt_registry_digest: assertDigest(
      input.transition_receipt_registry_digest,
      `${label}.transition_receipt_registry_digest`,
    ),
    asset_aliases: assets,
    effect_rules: rules,
    expected_transitions: transitions,
    constraints,
    exclusions,
  };
  const policyDigest = hashCanonicalJson(normalized);
  assertDerivedDigest(input, "policy_digest", policyDigest, label);
  return deepFreeze({ ...normalized, policy_digest: policyDigest });
}

const IMPORT_PAYLOAD_FIELDS = Object.freeze([
  "version",
  "import_id",
  "operator_principal_id",
  "authored_at",
  "authoring_system_ref",
  "authorization_record_ref",
  "authorization_record_digest",
  "nonce",
  "sequence",
  "not_before",
  "expires_at",
  "policy",
]);

const IMPORT_AUTHENTICATION_BASIS_FIELDS = Object.freeze([
  "version",
  "method",
  "trust_root_id",
  "trust_root_epoch",
  "trust_registry_digest",
  "signer_principal_id",
  "signer_key_id",
  "signer_epoch",
  "signer_public_key_digest",
  "key_usage",
  "signed_at",
  "signed_payload_digest",
]);

function normalizePhysicalScopeImportPayload(input, registry, label = "physical_scope_import.payload") {
  assertClosedObject(input, label, IMPORT_PAYLOAD_FIELDS);
  if (input.version !== PHYSICAL_SCOPE_IMPORT_VERSION) {
    throw new Error(`${label}.version must be ${PHYSICAL_SCOPE_IMPORT_VERSION}`);
  }
  const notBefore = assertCanonicalTimestamp(input.not_before, `${label}.not_before`);
  const expiresAt = assertCanonicalTimestamp(input.expires_at, `${label}.expires_at`);
  if (Date.parse(expiresAt) <= Date.parse(notBefore)) {
    throw new Error(`${label}.expires_at must be after ${label}.not_before`);
  }
  return deepFreeze({
    version: PHYSICAL_SCOPE_IMPORT_VERSION,
    import_id: assertIdentifier(input.import_id, `${label}.import_id`),
    operator_principal_id: normalizeOpaqueRef(
      input.operator_principal_id,
      `${label}.operator_principal_id`,
      { prefix: "principal" },
    ),
    authored_at: assertCanonicalTimestamp(input.authored_at, `${label}.authored_at`),
    authoring_system_ref: normalizeOpaqueRef(
      input.authoring_system_ref,
      `${label}.authoring_system_ref`,
      { prefix: "authoring-system" },
    ),
    authorization_record_ref: normalizeOpaqueRef(
      input.authorization_record_ref,
      `${label}.authorization_record_ref`,
      { prefix: "authorization-record" },
    ),
    authorization_record_digest: assertDigest(
      input.authorization_record_digest,
      `${label}.authorization_record_digest`,
    ),
    nonce: assertToken(input.nonce, `${label}.nonce`),
    sequence: assertInteger(input.sequence, `${label}.sequence`, 1),
    not_before: notBefore,
    expires_at: expiresAt,
    policy: normalizePhysicalScopePolicy(input.policy, registry, `${label}.policy`),
  });
}

function normalizeImportAuthenticationBasis(input, payloadDigest, label) {
  assertClosedObject(input, label, IMPORT_AUTHENTICATION_BASIS_FIELDS);
  if (input.version !== PHYSICAL_SCOPE_AUTHENTICATION_VERSION) {
    throw new Error(`${label}.version must be ${PHYSICAL_SCOPE_AUTHENTICATION_VERSION}`);
  }
  const normalized = {
    version: PHYSICAL_SCOPE_AUTHENTICATION_VERSION,
    method: assertEnum(input.method, AUTHENTICATION_METHODS, `${label}.method`),
    trust_root_id: normalizeOpaqueRef(input.trust_root_id, `${label}.trust_root_id`, {
      prefix: "trust-root",
    }),
    trust_root_epoch: assertInteger(input.trust_root_epoch, `${label}.trust_root_epoch`, 1),
    trust_registry_digest: assertDigest(input.trust_registry_digest, `${label}.trust_registry_digest`),
    signer_principal_id: normalizeOpaqueRef(
      input.signer_principal_id,
      `${label}.signer_principal_id`,
      { prefix: "principal" },
    ),
    signer_key_id: normalizeOpaqueRef(input.signer_key_id, `${label}.signer_key_id`, {
      prefix: "signer-key",
    }),
    signer_epoch: assertInteger(input.signer_epoch, `${label}.signer_epoch`, 1),
    signer_public_key_digest: assertDigest(
      input.signer_public_key_digest,
      `${label}.signer_public_key_digest`,
    ),
    key_usage: assertEnum(input.key_usage, [PHYSICAL_SCOPE_IMPORT_KEY_USAGE], `${label}.key_usage`),
    signed_at: assertCanonicalTimestamp(input.signed_at, `${label}.signed_at`),
    signed_payload_digest: assertDigest(input.signed_payload_digest, `${label}.signed_payload_digest`),
  };
  if (normalized.signed_payload_digest !== payloadDigest) {
    throw new Error(`${label}.signed_payload_digest does not bind the normalized import payload`);
  }
  return deepFreeze(normalized);
}

function signatureInputDigestFromNormalized(payload, authenticationBasis) {
  return hashCanonicalJson({
    domain: PHYSICAL_SCOPE_IMPORT_DOMAIN,
    version: PHYSICAL_SCOPE_IMPORT_VERSION,
    kind: PHYSICAL_SCOPE_IMPORT_KIND,
    payload,
    authentication: authenticationBasis,
  });
}

function physicalScopeImportSignatureInputDigest(payloadInput, authenticationBasisInput, registry) {
  const payload = normalizePhysicalScopeImportPayload(payloadInput, registry);
  const payloadDigest = hashCanonicalJson(payload);
  const authentication = normalizeImportAuthenticationBasis(
    authenticationBasisInput,
    payloadDigest,
    "physical_scope_import.authentication",
  );
  return signatureInputDigestFromNormalized(payload, authentication);
}

function normalizeImportAuthentication(input, payloadDigest, label) {
  assertClosedObject(input, label, [...IMPORT_AUTHENTICATION_BASIS_FIELDS, "proof_ref", "proof_digest"]);
  const basis = normalizeImportAuthenticationBasis(
    Object.fromEntries(IMPORT_AUTHENTICATION_BASIS_FIELDS.map((field) => [field, input[field]])),
    payloadDigest,
    label,
  );
  return deepFreeze({
    ...basis,
    proof_ref: normalizeOpaqueRef(input.proof_ref, `${label}.proof_ref`, { prefix: "auth-proof" }),
    proof_digest: assertDigest(input.proof_digest, `${label}.proof_digest`),
  });
}

function normalizePhysicalScopeImportEnvelope(input, registry, label = "physical_scope_import") {
  assertClosedObject(
    input,
    label,
    ["kind", "domain", ...IMPORT_PAYLOAD_FIELDS, "authentication"],
    ["import_payload_digest", "signature_input_digest", "signed_import_digest"],
  );
  if (input.kind !== PHYSICAL_SCOPE_IMPORT_KIND) {
    throw new Error(`${label}.kind must be ${PHYSICAL_SCOPE_IMPORT_KIND}`);
  }
  if (input.domain !== PHYSICAL_SCOPE_IMPORT_DOMAIN) {
    throw new Error(`${label}.domain does not match the physical scope import signature domain`);
  }
  const payloadInput = Object.fromEntries(IMPORT_PAYLOAD_FIELDS.map((field) => [field, input[field]]));
  const payload = normalizePhysicalScopeImportPayload(payloadInput, registry, `${label}.payload`);
  const importPayloadDigest = hashCanonicalJson(payload);
  assertDerivedDigest(input, "import_payload_digest", importPayloadDigest, label);
  const authentication = normalizeImportAuthentication(
    input.authentication,
    importPayloadDigest,
    `${label}.authentication`,
  );
  if (Date.parse(authentication.signed_at) < Date.parse(payload.authored_at)) {
    throw new Error(`${label}.authentication.signed_at must not precede authored_at`);
  }
  if (Date.parse(authentication.signed_at) >= Date.parse(payload.expires_at)) {
    throw new Error(`${label}.authentication.signed_at must precede expires_at`);
  }
  const authenticationBasis = deepFreeze(Object.fromEntries(
    IMPORT_AUTHENTICATION_BASIS_FIELDS.map((field) => [field, authentication[field]]),
  ));
  const signatureInputDigest = signatureInputDigestFromNormalized(payload, authenticationBasis);
  assertDerivedDigest(input, "signature_input_digest", signatureInputDigest, label);
  const signedEnvelopeBasis = deepFreeze({
    version: PHYSICAL_SCOPE_IMPORT_VERSION,
    kind: PHYSICAL_SCOPE_IMPORT_KIND,
    domain: PHYSICAL_SCOPE_IMPORT_DOMAIN,
    payload,
    authentication,
  });
  const signedImportDigest = hashCanonicalJson(signedEnvelopeBasis);
  assertDerivedDigest(input, "signed_import_digest", signedImportDigest, label);
  return deepFreeze({
    ...payload,
    kind: PHYSICAL_SCOPE_IMPORT_KIND,
    domain: PHYSICAL_SCOPE_IMPORT_DOMAIN,
    import_payload_digest: importPayloadDigest,
    authentication,
    authentication_basis: authenticationBasis,
    signature_input_digest: signatureInputDigest,
    signed_import_digest: signedImportDigest,
  });
}

function normalizeCurrentPhysicalScopeImportAuthority(input, label = "current_physical_scope_import_authority") {
  assertClosedObject(input, label, [
    "version",
    "import_id",
    "import_payload_digest",
    "operator_principal_id",
    "authorization_record_ref",
    "authorization_record_digest",
    "policy_id",
    "policy_digest",
    "authority_epoch",
    "revocation_generation",
    "authorization_decision",
    "authorization_reason",
    "authorization_resolution_digest",
    "trust_root_id",
    "trust_root_epoch",
    "trust_registry_digest",
    "trust_root_trusted",
    "trust_root_revoked",
    "signer_principal_id",
    "signer_key_id",
    "signer_epoch",
    "signer_public_key_digest",
    "key_usage",
    "signer_trusted",
    "signer_revoked",
  ]);
  if (input.version !== PHYSICAL_SCOPE_AUTHENTICATION_VERSION) {
    throw new Error(`${label}.version must be ${PHYSICAL_SCOPE_AUTHENTICATION_VERSION}`);
  }
  const trustRootTrusted = assertBoolean(input.trust_root_trusted, `${label}.trust_root_trusted`);
  const trustRootRevoked = assertBoolean(input.trust_root_revoked, `${label}.trust_root_revoked`);
  const signerTrusted = assertBoolean(input.signer_trusted, `${label}.signer_trusted`);
  const signerRevoked = assertBoolean(input.signer_revoked, `${label}.signer_revoked`);
  if (!trustRootTrusted || trustRootRevoked) throw new Error(`${label} trust root is not currently usable`);
  if (!signerTrusted || signerRevoked) throw new Error(`${label} signer is not currently usable`);
  return deepFreeze({
    version: PHYSICAL_SCOPE_AUTHENTICATION_VERSION,
    import_id: assertIdentifier(input.import_id, `${label}.import_id`),
    import_payload_digest: assertDigest(input.import_payload_digest, `${label}.import_payload_digest`),
    operator_principal_id: normalizeOpaqueRef(
      input.operator_principal_id,
      `${label}.operator_principal_id`,
      { prefix: "principal" },
    ),
    authorization_record_ref: normalizeOpaqueRef(
      input.authorization_record_ref,
      `${label}.authorization_record_ref`,
      { prefix: "authorization-record" },
    ),
    authorization_record_digest: assertDigest(
      input.authorization_record_digest,
      `${label}.authorization_record_digest`,
    ),
    policy_id: assertIdentifier(input.policy_id, `${label}.policy_id`),
    policy_digest: assertDigest(input.policy_digest, `${label}.policy_digest`),
    authority_epoch: assertInteger(input.authority_epoch, `${label}.authority_epoch`, 1),
    revocation_generation: assertInteger(
      input.revocation_generation,
      `${label}.revocation_generation`,
      0,
    ),
    authorization_decision: assertEnum(input.authorization_decision, ["allow"], `${label}.authorization_decision`),
    authorization_reason: assertEnum(input.authorization_reason, ["exact_allow"], `${label}.authorization_reason`),
    authorization_resolution_digest: assertDigest(
      input.authorization_resolution_digest,
      `${label}.authorization_resolution_digest`,
    ),
    trust_root_id: normalizeOpaqueRef(input.trust_root_id, `${label}.trust_root_id`, {
      prefix: "trust-root",
    }),
    trust_root_epoch: assertInteger(input.trust_root_epoch, `${label}.trust_root_epoch`, 1),
    trust_registry_digest: assertDigest(input.trust_registry_digest, `${label}.trust_registry_digest`),
    trust_root_trusted: true,
    trust_root_revoked: false,
    signer_principal_id: normalizeOpaqueRef(
      input.signer_principal_id,
      `${label}.signer_principal_id`,
      { prefix: "principal" },
    ),
    signer_key_id: normalizeOpaqueRef(input.signer_key_id, `${label}.signer_key_id`, {
      prefix: "signer-key",
    }),
    signer_epoch: assertInteger(input.signer_epoch, `${label}.signer_epoch`, 1),
    signer_public_key_digest: assertDigest(
      input.signer_public_key_digest,
      `${label}.signer_public_key_digest`,
    ),
    key_usage: assertEnum(input.key_usage, [PHYSICAL_SCOPE_IMPORT_KEY_USAGE], `${label}.key_usage`),
    signer_trusted: true,
    signer_revoked: false,
  });
}

function createPhysicalScopeImportVerifier(input) {
  assertClosedObject(input, "physical_scope_import_verifier", [
    "verifier_id",
    "trusted_now",
    "resolve_current_authority",
    "verify_detached_signature",
    "reserve_replay",
  ]);
  for (const field of [
    "trusted_now",
    "resolve_current_authority",
    "verify_detached_signature",
    "reserve_replay",
  ]) {
    if (typeof input[field] !== "function") {
      throw new Error(`physical_scope_import_verifier.${field} must be a function`);
    }
  }
  const verifier = Object.freeze({
    version: PHYSICAL_SCOPE_AUTHENTICATION_VERSION,
    verifier_id: assertIdentifier(input.verifier_id, "physical_scope_import_verifier.verifier_id"),
  });
  PHYSICAL_SCOPE_IMPORT_VERIFIERS.add(verifier);
  PHYSICAL_SCOPE_IMPORT_VERIFIER_STATE.set(verifier, {
    trusted_now: input.trusted_now,
    resolve_current_authority: input.resolve_current_authority,
    verify_detached_signature: input.verify_detached_signature,
    reserve_replay: input.reserve_replay,
    last_trusted_now_ms: null,
    projected_import_ids: new Set(),
    projected_payload_digests: new Set(),
  });
  return verifier;
}

function assertPhysicalScopeImportVerifier(input) {
  if (!input || !PHYSICAL_SCOPE_IMPORT_VERIFIERS.has(input)
      || !PHYSICAL_SCOPE_IMPORT_VERIFIER_STATE.has(input)) {
    throw new Error("physical scope import verifier must be a configured Bob verifier");
  }
  return input;
}

function trustedScopeImportNow(verifierState) {
  const now = assertCanonicalTimestamp(verifierState.trusted_now(), "trusted_now");
  const nowMs = Date.parse(now);
  if (verifierState.last_trusted_now_ms != null && nowMs < verifierState.last_trusted_now_ms) {
    throw new Error("trusted clock moved backwards while verifying a physical scope import");
  }
  verifierState.last_trusted_now_ms = nowMs;
  return { now, nowMs };
}

function assertExactBindings(actual, expected, fields, label) {
  for (const field of fields) {
    if (actual[field] !== expected[field]) {
      throw new Error(`${label}.${field} does not match current authority`);
    }
  }
}

function resolveAndAssertCurrentScopeImport(imported, verifierState) {
  const query = deepFreeze({
    version: PHYSICAL_SCOPE_AUTHENTICATION_VERSION,
    domain: PHYSICAL_SCOPE_IMPORT_DOMAIN,
    kind: PHYSICAL_SCOPE_IMPORT_KIND,
    key_usage: PHYSICAL_SCOPE_IMPORT_KEY_USAGE,
    import_id: imported.import_id,
    import_payload_digest: imported.import_payload_digest,
    operator_principal_id: imported.operator_principal_id,
    policy_id: imported.policy.policy_id,
    policy_digest: imported.policy.policy_digest,
    authority_epoch: imported.policy.authority_epoch,
    revocation_generation: imported.policy.revocation_generation,
    authorization_record_ref: imported.authorization_record_ref,
    authorization_record_digest: imported.authorization_record_digest,
  });
  const current = normalizeCurrentPhysicalScopeImportAuthority(
    verifierState.resolve_current_authority(query),
  );
  const observed = trustedScopeImportNow(verifierState);
  assertExactBindings(imported, current, [
    "import_id",
    "import_payload_digest",
    "operator_principal_id",
    "authorization_record_ref",
    "authorization_record_digest",
  ], "physical_scope_import.current_authority");
  assertExactBindings(imported.policy, current, [
    "policy_id",
    "policy_digest",
    "authority_epoch",
    "revocation_generation",
  ], "physical_scope_import.current_policy");
  assertExactBindings(imported.authentication, current, [
    "trust_root_id",
    "trust_root_epoch",
    "trust_registry_digest",
    "signer_principal_id",
    "signer_key_id",
    "signer_epoch",
    "signer_public_key_digest",
    "key_usage",
  ], "physical_scope_import.current_trust");
  if (Date.parse(imported.authentication.signed_at) > observed.nowMs) {
    throw new Error("physical scope import was signed in the future");
  }
  if (observed.nowMs < Date.parse(imported.not_before)) {
    throw new Error("physical scope import is not yet valid");
  }
  if (observed.nowMs >= Date.parse(imported.expires_at)) {
    throw new Error("physical scope import has expired");
  }
  return { current, query, ...observed };
}

function normalizeScopeReplayClaim(input, label = "physical_scope_import_replay_claim") {
  assertClosedObject(input, label, [
    "version",
    "import_id",
    "signed_import_digest",
    "import_payload_digest",
    "operator_principal_id",
    "policy_digest",
    "authority_epoch",
    "revocation_generation",
    "authorization_record_digest",
    "nonce",
    "sequence",
    "expires_at",
  ]);
  if (input.version !== PHYSICAL_SCOPE_REPLAY_RESERVATION_VERSION) {
    throw new Error(`${label}.version must be ${PHYSICAL_SCOPE_REPLAY_RESERVATION_VERSION}`);
  }
  return deepFreeze({
    version: PHYSICAL_SCOPE_REPLAY_RESERVATION_VERSION,
    import_id: assertIdentifier(input.import_id, `${label}.import_id`),
    signed_import_digest: assertDigest(input.signed_import_digest, `${label}.signed_import_digest`),
    import_payload_digest: assertDigest(input.import_payload_digest, `${label}.import_payload_digest`),
    operator_principal_id: normalizeOpaqueRef(
      input.operator_principal_id,
      `${label}.operator_principal_id`,
      { prefix: "principal" },
    ),
    policy_digest: assertDigest(input.policy_digest, `${label}.policy_digest`),
    authority_epoch: assertInteger(input.authority_epoch, `${label}.authority_epoch`, 1),
    revocation_generation: assertInteger(input.revocation_generation, `${label}.revocation_generation`, 0),
    authorization_record_digest: assertDigest(
      input.authorization_record_digest,
      `${label}.authorization_record_digest`,
    ),
    nonce: assertToken(input.nonce, `${label}.nonce`),
    sequence: assertInteger(input.sequence, `${label}.sequence`, 1),
    expires_at: assertCanonicalTimestamp(input.expires_at, `${label}.expires_at`),
  });
}

function normalizeScopeReplayReservation(input, expectedClaim, label = "physical_scope_import_replay_reservation") {
  assertClosedObject(input, label, ["version", "disposition", "reservation_receipt"]);
  if (input.version !== PHYSICAL_SCOPE_REPLAY_RESERVATION_VERSION) {
    throw new Error(`${label}.version must be ${PHYSICAL_SCOPE_REPLAY_RESERVATION_VERSION}`);
  }
  const disposition = assertEnum(input.disposition, REPLAY_RESERVATION_DISPOSITIONS, `${label}.disposition`);
  const receiptInput = input.reservation_receipt;
  assertClosedObject(receiptInput, `${label}.reservation_receipt`, [
    "version",
    "reservation_ref",
    "replay_claim",
    "replay_claim_digest",
    "generation",
    "previous_receipt_digest",
    "reserved_at",
    "fsynced_at",
  ], ["receipt_digest"]);
  if (receiptInput.version !== PHYSICAL_SCOPE_REPLAY_RESERVATION_VERSION) {
    throw new Error(`${label}.reservation_receipt.version must be ${PHYSICAL_SCOPE_REPLAY_RESERVATION_VERSION}`);
  }
  const replayClaim = normalizeScopeReplayClaim(
    receiptInput.replay_claim,
    `${label}.reservation_receipt.replay_claim`,
  );
  if (hashCanonicalJson(replayClaim) !== hashCanonicalJson(expectedClaim)) {
    throw new Error(`${label}.reservation_receipt replay claim does not match the verified import`);
  }
  const replayClaimDigest = hashCanonicalJson(replayClaim);
  if (assertDigest(
    receiptInput.replay_claim_digest,
    `${label}.reservation_receipt.replay_claim_digest`,
  ) !== replayClaimDigest) {
    throw new Error(`${label}.reservation_receipt.replay_claim_digest does not match its claim`);
  }
  const reservedAt = assertCanonicalTimestamp(
    receiptInput.reserved_at,
    `${label}.reservation_receipt.reserved_at`,
  );
  const fsyncedAt = assertCanonicalTimestamp(
    receiptInput.fsynced_at,
    `${label}.reservation_receipt.fsynced_at`,
  );
  if (Date.parse(fsyncedAt) < Date.parse(reservedAt)) {
    throw new Error(`${label}.reservation_receipt.fsynced_at must not precede reserved_at`);
  }
  const generation = assertInteger(
    receiptInput.generation,
    `${label}.reservation_receipt.generation`,
    1,
  );
  const previousReceiptDigest = receiptInput.previous_receipt_digest == null
    ? null
    : assertDigest(
      receiptInput.previous_receipt_digest,
      `${label}.reservation_receipt.previous_receipt_digest`,
    );
  if (generation === 1 && previousReceiptDigest !== null) {
    throw new Error(`${label}.reservation_receipt generation 1 cannot have a previous receipt`);
  }
  if (generation > 1 && previousReceiptDigest === null) {
    throw new Error(`${label}.reservation_receipt generation >1 requires a previous receipt`);
  }
  const receipt = {
    version: PHYSICAL_SCOPE_REPLAY_RESERVATION_VERSION,
    reservation_ref: normalizeOpaqueRef(
      receiptInput.reservation_ref,
      `${label}.reservation_receipt.reservation_ref`,
      { prefix: "scope-replay-reservation" },
    ),
    replay_claim: replayClaim,
    replay_claim_digest: replayClaimDigest,
    generation,
    previous_receipt_digest: previousReceiptDigest,
    reserved_at: reservedAt,
    fsynced_at: fsyncedAt,
  };
  const receiptDigest = hashCanonicalJson(receipt);
  assertDerivedDigest(receiptInput, "receipt_digest", receiptDigest, `${label}.reservation_receipt`);
  return deepFreeze({
    version: PHYSICAL_SCOPE_REPLAY_RESERVATION_VERSION,
    disposition,
    reservation_receipt: deepFreeze({ ...receipt, receipt_digest: receiptDigest }),
  });
}

function buildScopeReplayClaim(imported) {
  return normalizeScopeReplayClaim({
    version: PHYSICAL_SCOPE_REPLAY_RESERVATION_VERSION,
    import_id: imported.import_id,
    signed_import_digest: imported.signed_import_digest,
    import_payload_digest: imported.import_payload_digest,
    operator_principal_id: imported.operator_principal_id,
    policy_digest: imported.policy.policy_digest,
    authority_epoch: imported.policy.authority_epoch,
    revocation_generation: imported.policy.revocation_generation,
    authorization_record_digest: imported.authorization_record_digest,
    nonce: imported.nonce,
    sequence: imported.sequence,
    expires_at: imported.expires_at,
  });
}

function reserveScopeImportReplay(verifierState, replayClaim) {
  try {
    return normalizeScopeReplayReservation(verifierState.reserve_replay(replayClaim), replayClaim);
  } catch (cause) {
    const error = new Error("physical scope import replay reservation failed closed");
    Object.defineProperty(error, "cause", { value: cause });
    throw error;
  }
}

function projectVerifiedPhysicalScopeImport(input, registry, verifierInput) {
  const verifier = assertPhysicalScopeImportVerifier(verifierInput);
  const verifierState = PHYSICAL_SCOPE_IMPORT_VERIFIER_STATE.get(verifier);
  const imported = normalizePhysicalScopeImportEnvelope(input, registry);
  const live = resolveAndAssertCurrentScopeImport(imported, verifierState);
  const signatureVerified = verifierState.verify_detached_signature(deepFreeze({
    version: PHYSICAL_SCOPE_AUTHENTICATION_VERSION,
    domain: PHYSICAL_SCOPE_IMPORT_DOMAIN,
    kind: PHYSICAL_SCOPE_IMPORT_KIND,
    method: "ed25519",
    key_usage: PHYSICAL_SCOPE_IMPORT_KEY_USAGE,
    signature_input_digest: imported.signature_input_digest,
    proof_ref: imported.authentication.proof_ref,
    proof_digest: imported.authentication.proof_digest,
    trust_root_id: live.current.trust_root_id,
    trust_root_epoch: live.current.trust_root_epoch,
    trust_registry_digest: live.current.trust_registry_digest,
    signer_principal_id: live.current.signer_principal_id,
    signer_key_id: live.current.signer_key_id,
    signer_epoch: live.current.signer_epoch,
    signer_public_key_digest: live.current.signer_public_key_digest,
  }));
  if (signatureVerified !== true) {
    throw new Error("physical scope import Ed25519 detached signature verification failed");
  }
  if (verifierState.projected_import_ids.has(imported.import_id)
      || verifierState.projected_payload_digests.has(imported.import_payload_digest)) {
    throw new Error("physical scope import replay was rejected");
  }
  const replayClaim = buildScopeReplayClaim(imported);
  const replayClaimDigest = hashCanonicalJson(replayClaim);
  const replayReservation = reserveScopeImportReplay(verifierState, replayClaim);
  if (replayReservation.disposition !== "created") {
    throw new Error(
      "physical scope import existing replay reservation requires unavailable durable session rehydration",
    );
  }
  const receipt = replayReservation.reservation_receipt;
  const reservationObserved = trustedScopeImportNow(verifierState);
  if (Date.parse(receipt.reserved_at) < Date.parse(imported.not_before)
      || Date.parse(receipt.reserved_at) < Date.parse(imported.authentication.signed_at)
      || Date.parse(receipt.fsynced_at) >= Date.parse(imported.expires_at)
      || Date.parse(receipt.fsynced_at) > reservationObserved.nowMs) {
    throw new Error("physical scope import replay reservation is outside its trusted validity window");
  }
  verifierState.projected_import_ids.add(imported.import_id);
  verifierState.projected_payload_digests.add(imported.import_payload_digest);

  const signatureVerificationDigest = hashCanonicalJson({
    domain: PHYSICAL_SCOPE_IMPORT_DOMAIN,
    kind: PHYSICAL_SCOPE_IMPORT_KIND,
    key_usage: PHYSICAL_SCOPE_IMPORT_KEY_USAGE,
    signature_input_digest: imported.signature_input_digest,
    proof_digest: imported.authentication.proof_digest,
    verifier_id: verifier.verifier_id,
    trust_root_id: live.current.trust_root_id,
    trust_root_epoch: live.current.trust_root_epoch,
    trust_registry_digest: live.current.trust_registry_digest,
    signer_principal_id: live.current.signer_principal_id,
    signer_key_id: live.current.signer_key_id,
    signer_epoch: live.current.signer_epoch,
    signer_public_key_digest: live.current.signer_public_key_digest,
  });
  // Deliberately excludes authorization_record_ref/digest, proof_ref/digest,
  // and signature material. Stable digests retain the audit join.
  const provenance = deepFreeze({
    import_id: imported.import_id,
    operator_principal_id: imported.operator_principal_id,
    authored_at: imported.authored_at,
    authoring_system_ref: imported.authoring_system_ref,
    import_payload_digest: imported.import_payload_digest,
    authentication_method: imported.authentication.method,
    trust_root_id: live.current.trust_root_id,
    trust_root_epoch: live.current.trust_root_epoch,
    trust_registry_digest: live.current.trust_registry_digest,
    signer_principal_id: live.current.signer_principal_id,
    signer_key_id: live.current.signer_key_id,
    signer_epoch: live.current.signer_epoch,
    signer_public_key_digest: live.current.signer_public_key_digest,
    key_usage: PHYSICAL_SCOPE_IMPORT_KEY_USAGE,
    signed_at: imported.authentication.signed_at,
    verified_at: reservationObserved.now,
    authorization_verifier_id: verifier.verifier_id,
    authorization_verdict_digest: live.current.authorization_resolution_digest,
    signed_import_digest: imported.signed_import_digest,
    signature_input_digest: imported.signature_input_digest,
    signature_verification_digest: signatureVerificationDigest,
    replay_claim_digest: replayClaimDigest,
    replay_reservation_ref: receipt.reservation_ref,
    replay_reservation_generation: receipt.generation,
    replay_reservation_receipt_digest: receipt.receipt_digest,
  });
  const provenanceDigest = hashCanonicalJson(provenance);
  const compatibility = PHYSICAL_SCOPE_COMPATIBILITY_RULE;
  const projection = {
    version: PHYSICAL_SCOPE_PROJECTION_VERSION,
    physical_enabled: true,
    policy: imported.policy,
    policy_digest: imported.policy.policy_digest,
    provenance,
    provenance_digest: provenanceDigest,
    compatibility,
    compatibility_digest: hashCanonicalJson(compatibility),
  };
  const verifiedProjection = deepFreeze({
    ...projection,
    projection_digest: hashCanonicalJson(projection),
  });
  VERIFIED_SCOPE_IMPORT_PROJECTIONS.add(verifiedProjection);
  VERIFIED_SCOPE_IMPORT_PROJECTION_STATE.set(verifiedProjection, Object.freeze({
    verifier,
    imported,
    current_authority: live.current,
  }));
  return verifiedProjection;
}

function assertVerifiedPhysicalScopeImport(input, verifierInput) {
  const verifier = assertPhysicalScopeImportVerifier(verifierInput);
  const state = input == null ? null : VERIFIED_SCOPE_IMPORT_PROJECTION_STATE.get(input);
  if (!input || !VERIFIED_SCOPE_IMPORT_PROJECTIONS.has(input)
      || !state || state.verifier !== verifier) {
    throw new Error("physical scope import projection was not issued by the configured verifier");
  }
  const live = resolveAndAssertCurrentScopeImport(
    state.imported,
    PHYSICAL_SCOPE_IMPORT_VERIFIER_STATE.get(verifier),
  );
  if (live.current.authorization_resolution_digest
      !== state.current_authority.authorization_resolution_digest) {
    throw new Error(
      "physical_scope_import.current_authority.authorization_resolution_digest does not match current authority",
    );
  }
  return input;
}

// Only an authenticated import projection can mint the compact nucleus axis.
// The full policy and safe provenance remain operator-domain records; the
// session nucleus binds them by canonical digest plus live epoch/generation.
function projectPhysicalScopeNucleusAxis(projectionInput, verifierInput) {
  if (arguments.length !== 2) {
    throw new Error("physical scope nucleus binding accepts only a verified projection and its configured verifier");
  }
  const projection = assertVerifiedPhysicalScopeImport(projectionInput, verifierInput);
  return normalizePhysicalScopeNucleusAxis({
    version: PHYSICAL_SCOPE_NUCLEUS_AXIS_VERSION,
    physical_enabled: true,
    policy_version: projection.policy.version,
    policy_id: projection.policy.policy_id,
    policy_digest: projection.policy_digest,
    projection_version: projection.version,
    projection_digest: projection.projection_digest,
    provenance_digest: projection.provenance_digest,
    compatibility_digest: projection.compatibility_digest,
    transition_receipt_registry_digest: projection.policy.transition_receipt_registry_digest,
    authority_epoch: projection.policy.authority_epoch,
    revocation_generation: projection.policy.revocation_generation,
  });
}

function resolvePhysicalScopeCompatibility(input, registry) {
  if (input == null) {
    const result = {
      version: PHYSICAL_SCOPE_COMPATIBILITY_VERSION,
      mode: "legacy_absent",
      physical_enabled: false,
      policy: null,
      compatibility: PHYSICAL_SCOPE_COMPATIBILITY_RULE,
    };
    return deepFreeze({ ...result, compatibility_resolution_digest: hashCanonicalJson(result) });
  }
  const policy = normalizePhysicalScopePolicy(input, registry);
  const result = {
    version: PHYSICAL_SCOPE_COMPATIBILITY_VERSION,
    mode: "native_v1",
    physical_enabled: true,
    policy,
    compatibility: PHYSICAL_SCOPE_COMPATIBILITY_RULE,
  };
  return deepFreeze({ ...result, compatibility_resolution_digest: hashCanonicalJson(result) });
}

function migratePhysicalScopePolicy(input, registry, options = {}) {
  assertClosedObject(options, "physical scope migration options", [], ["targetVersion"]);
  const targetVersion = options.targetVersion == null
    ? PHYSICAL_SCOPE_POLICY_VERSION
    : options.targetVersion;
  if (!isPlainObject(input) || input.version !== PHYSICAL_SCOPE_POLICY_VERSION) {
    throw new Error("physical scope migration accepts only an explicit version 1 source policy");
  }
  if (targetVersion !== PHYSICAL_SCOPE_POLICY_VERSION) {
    throw new Error("physical scope migration has no registered target other than version 1");
  }
  const policy = normalizePhysicalScopePolicy(input, registry);
  return deepFreeze({
    version: PHYSICAL_SCOPE_COMPATIBILITY_VERSION,
    migration_kind: "identity",
    from_version: PHYSICAL_SCOPE_POLICY_VERSION,
    to_version: PHYSICAL_SCOPE_POLICY_VERSION,
    source_policy_digest: policy.policy_digest,
    migrated_policy: policy,
    migrated_policy_digest: policy.policy_digest,
    rollback_behavior: "new_session_nucleus_required",
  });
}

function buildPhysicalOnlySessionBootstrapPayload(projectionInput, verifierInput, input) {
  if (arguments.length !== 3) {
    throw new Error("physical-only bootstrap requires a verified projection, its verifier, and bootstrap input");
  }
  const projection = assertVerifiedPhysicalScopeImport(projectionInput, verifierInput);
  assertClosedObject(input, "physical_only_bootstrap", ["version", "session_id", "session_namespace"]);
  if (input.version !== PHYSICAL_ONLY_BOOTSTRAP_VERSION) {
    throw new Error(`physical_only_bootstrap.version must be ${PHYSICAL_ONLY_BOOTSTRAP_VERSION}`);
  }
  const payload = {
    version: PHYSICAL_ONLY_BOOTSTRAP_VERSION,
    bootstrap_kind: "physical_only",
    session_id: assertToken(input.session_id, "physical_only_bootstrap.session_id"),
    session_namespace: normalizeOpaqueRef(
      input.session_namespace,
      "physical_only_bootstrap.session_namespace",
      { prefix: "session-namespace" },
    ),
    scope_axes: Object.freeze(["physical"]),
    physical_scope: projection,
    physical_scope_projection_digest: projection.projection_digest,
    physical_scope_policy_digest: projection.policy_digest,
    physical_scope_provenance_digest: projection.provenance_digest,
    authority_epoch: projection.policy.authority_epoch,
    revocation_generation: projection.policy.revocation_generation,
    transition_receipt_registry_digest: projection.policy.transition_receipt_registry_digest,
  };
  return deepFreeze({ ...payload, bootstrap_payload_digest: hashCanonicalJson(payload) });
}

function physicalScopePolicyDigest(input, registry) {
  return normalizePhysicalScopePolicy(input, registry).policy_digest;
}

module.exports = {
  ASSET_ROLES,
  AUTHENTICATION_METHODS,
  CONSTRAINT_KINDS,
  CONSTRAINT_SUBJECT_KINDS,
  EXCLUSION_KINDS,
  PHYSICAL_ONLY_BOOTSTRAP_VERSION,
  PHYSICAL_SCOPE_AUTHENTICATION_VERSION,
  PHYSICAL_SCOPE_COMPATIBILITY_RULE,
  PHYSICAL_SCOPE_COMPATIBILITY_VERSION,
  PHYSICAL_SCOPE_IMPORT_DOMAIN,
  PHYSICAL_SCOPE_IMPORT_KEY_USAGE,
  PHYSICAL_SCOPE_IMPORT_KIND,
  PHYSICAL_SCOPE_IMPORT_VERSION,
  PHYSICAL_SCOPE_POLICY_VERSION,
  PHYSICAL_SCOPE_PROJECTION_VERSION,
  PHYSICAL_SCOPE_REPLAY_RESERVATION_VERSION,
  assertVerifiedPhysicalScopeImport,
  buildPhysicalOnlySessionBootstrapPayload,
  createPhysicalScopeImportVerifier,
  migratePhysicalScopePolicy,
  normalizePhysicalScopeImportEnvelope,
  normalizePhysicalScopePolicy,
  physicalScopePolicyDigest,
  physicalScopeImportSignatureInputDigest,
  projectPhysicalScopeNucleusAxis,
  projectVerifiedPhysicalScopeImport,
  resolvePhysicalScopeCompatibility,
};
