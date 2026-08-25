"use strict";

// PH-I5 / PH-C9 — provider-neutral physical composition adapter.
//
// The SurfaceGraph service is the authority boundary: it rereads the current
// canonical physical session nucleus, checks the pinned receipt registry, and
// reconstructs the complete N-ary transition from signed receipts on every
// query.  This module never treats resolver callbacks or graph adjacency as an
// attestation.  It accepts only a privately branded SurfaceGraph service and a
// privately branded live physical finding, selects the exact verdict-bound
// receipt, derives directed reachability, and emits non-authorizing leaves for
// downstream generic composition.

const { types: utilTypes } = require("node:util");

let assertPhysicalFinding;
let PHYSICAL_CAPABILITY_CONSUMERS;
let PHYSICAL_SURFACE_NODE_TYPES;
const {
  assertSafeDomain,
} = require("../io/paths.js");
const {
  assertPhysicalSurfaceGraphServerService,
  describePhysicalSurfaceGraphServerService,
  MAX_QUERY_LIMIT,
} = require("../frontier/surface-graph.js");
const {
  hashCanonicalJson,
} = require("../verification/verification-contracts.js");
let assertProductionPhysicalExperimentLedger;
let assertVerifiedPhysicalClaimProjection;
let describeProductionPhysicalExperimentLedger;

let compositionPortsConfigured = false;
function configureCapabilityPackCompositionPorts(ports) {
  if (compositionPortsConfigured) {
    throw new Error("capability-pack composition ports are already configured");
  }
  ({
    assertPhysicalFinding,
    physicalCapabilityConsumers: PHYSICAL_CAPABILITY_CONSUMERS,
    physicalSurfaceNodeTypes: PHYSICAL_SURFACE_NODE_TYPES,
    assertProductionPhysicalExperimentLedger,
    assertVerifiedPhysicalClaimProjection,
    describeProductionPhysicalExperimentLedger,
  } = ports || {});
  if (typeof assertPhysicalFinding !== "function"
      || !PHYSICAL_CAPABILITY_CONSUMERS
      || !Array.isArray(PHYSICAL_SURFACE_NODE_TYPES)
      || typeof assertProductionPhysicalExperimentLedger !== "function"
      || typeof assertVerifiedPhysicalClaimProjection !== "function"
      || typeof describeProductionPhysicalExperimentLedger !== "function") {
    throw new Error("capability-pack composition ports are incomplete");
  }
  const ontologyTypes = [...PHYSICAL_SURFACE_NODE_TYPES].sort();
  const policyTypes = Object.keys(PHYSICAL_BLAST_RADIUS_NODE_POLICY).sort();
  if (JSON.stringify(ontologyTypes) !== JSON.stringify(policyTypes)) {
    throw new Error("physical blast-radius policy must cover the exact SurfaceGraph ontology");
  }
  compositionPortsConfigured = true;
}

function ensureCompositionPorts() {
  if (!compositionPortsConfigured) {
    throw new Error("capability-pack composition ports are not configured");
  }
}

const PHYSICAL_COMPOSITION_ADAPTER_VERSION = 1;
const PHYSICAL_COMPOSITION_ADAPTER_ID = "physical_surface_transition_v1";
const PHYSICAL_COMPOSITION_PORT_ASSURANCE =
  "bob_owned_surface_graph_with_canonical_nucleus_and_signed_receipt_revalidation";
const PHYSICAL_LIVE_COMPOSITION_BLOCKER =
  "restart_durable_signed_trusted_time_not_installed";
const DIGEST_RE = /^[a-f0-9]{64}$/u;
const SEVERITY_RANK = Object.freeze({
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
});

// Every physical ontology node has an explicit blast-radius interpretation.
// The registry is intentionally conservative: helper/observation nodes never
// lift a finding above MEDIUM, while only demonstrated control, boundary,
// zone, safety, or network reachability can support HIGH.  CRITICAL requires
// a verifier-signed compound category pair below; node count alone can never
// manufacture it.
const PHYSICAL_BLAST_RADIUS_NODE_POLICY = Object.freeze({
  actuator: Object.freeze({ category: "actuation", severity_ceiling: "medium" }),
  alarm: Object.freeze({ category: "safety_control", severity_ceiling: "high" }),
  asset: Object.freeze({ category: "asset", severity_ceiling: "low" }),
  control_point: Object.freeze({ category: "control", severity_ceiling: "high" }),
  enclosure: Object.freeze({ category: "boundary", severity_ceiling: "high" }),
  instrument: Object.freeze({ category: "instrument", severity_ceiling: "medium" }),
  interface: Object.freeze({ category: "interface", severity_ceiling: "medium" }),
  medium: Object.freeze({ category: "medium", severity_ceiling: "low" }),
  network_attachment: Object.freeze({ category: "network", severity_ceiling: "high" }),
  physical_barrier: Object.freeze({ category: "boundary", severity_ceiling: "high" }),
  physical_zone: Object.freeze({ category: "zone", severity_ceiling: "high" }),
  representation: Object.freeze({ category: "representation", severity_ceiling: "low" }),
  sensor: Object.freeze({ category: "observation", severity_ceiling: "medium" }),
  signal_source: Object.freeze({ category: "signal", severity_ceiling: "low" }),
  verifier: Object.freeze({ category: "verification", severity_ceiling: "low" }),
  workspace: Object.freeze({ category: "workspace", severity_ceiling: "medium" }),
  zone: Object.freeze({ category: "zone", severity_ceiling: "high" }),
});

const CRITICAL_CATEGORY_PAIRS = Object.freeze([
  Object.freeze(["control", "network"]),
  Object.freeze(["network", "zone"]),
  Object.freeze(["control", "safety_control"]),
  Object.freeze(["safety_control", "zone"]),
]);

const PRODUCTION_PORTS = new WeakSet();
const PRODUCTION_PORT_STATE = new WeakMap();
const INSTALLED_PORTS = new Map();
const PHYSICAL_COMPOSITION_PROJECTIONS = new WeakSet();
const PHYSICAL_COMPOSITION_PROJECTION_STATE = new WeakMap();
const PHYSICAL_BLAST_RADIUS_GRADE_BINDINGS = new WeakSet();
const PHYSICAL_BLAST_RADIUS_GRADE_BINDING_STATE = new WeakMap();

function deepFreeze(value) {
  if (value == null || typeof value !== "object" || Object.isFrozen(value)) return value;
  for (const child of Object.values(value)) deepFreeze(child);
  return Object.freeze(value);
}

function readExactDataFields(input, label, fields) {
  if (input == null || typeof input !== "object" || Array.isArray(input)
      || utilTypes.isProxy(input) || Object.getPrototypeOf(input) !== Object.prototype) {
    throw new Error(`${label} must be an exact plain data object`);
  }
  const keys = Reflect.ownKeys(input);
  if (keys.some((key) => typeof key !== "string")) {
    throw new Error(`${label} cannot contain symbol fields`);
  }
  const expected = fields.slice().sort();
  const actual = keys.slice().sort();
  if (actual.length !== expected.length
      || actual.some((field, index) => field !== expected[index])) {
    throw new Error(`${label} must carry exactly ${fields.join(", ")}`);
  }
  const descriptors = Object.getOwnPropertyDescriptors(input);
  const values = {};
  for (const field of fields) {
    const descriptor = descriptors[field];
    if (!descriptor || !Object.prototype.hasOwnProperty.call(descriptor, "value")
        || descriptor.enumerable !== true) {
      throw new Error(`${label}.${field} must be an enumerable data property`);
    }
    values[field] = descriptor.value;
  }
  return values;
}

function assertDigest(value, label) {
  if (typeof value !== "string" || !DIGEST_RE.test(value)) {
    throw new Error(`${label} must be a lowercase SHA-256 digest`);
  }
  return value;
}

function nodeKey(node) {
  return `${node.type}\u0000${node.id}`;
}

function compareNodes(left, right) {
  return left.type.localeCompare(right.type) || left.id.localeCompare(right.id);
}

function compareEdges(left, right) {
  return left.edge_hash.localeCompare(right.edge_hash);
}

function maxSeverity(left, right) {
  return SEVERITY_RANK[right] > SEVERITY_RANK[left] ? right : left;
}

function assertManifestRegistration() {
  const composition = PHYSICAL_CAPABILITY_CONSUMERS.composition;
  if (!composition
      || composition.adapter !== PHYSICAL_COMPOSITION_ADAPTER_ID
      || composition.requires_verified_projection !== true
      || composition.live_capability_requires_current_revalidation !== true) {
    throw new Error("physical capability-pack composition adapter is not registered coherently");
  }
  return composition;
}

function createProductionPhysicalCompositionPort(input) {
  ensureCompositionPorts();
  const fields = readExactDataFields(
    input,
    "production physical composition port",
    ["version", "surface_graph_service", "production_experiment_ledgers"],
  );
  if (fields.version !== PHYSICAL_COMPOSITION_ADAPTER_VERSION) {
    throw new Error(
      `production physical composition port.version must be ${PHYSICAL_COMPOSITION_ADAPTER_VERSION}`,
    );
  }
  assertManifestRegistration();
  const service = assertPhysicalSurfaceGraphServerService(fields.surface_graph_service);
  const identity = describePhysicalSurfaceGraphServerService(service);
  const ledgerInput = fields.production_experiment_ledgers;
  if (!Array.isArray(ledgerInput) || utilTypes.isProxy(ledgerInput)
      || ledgerInput.length < 1 || ledgerInput.length > 1024) {
    throw new Error(
      "production physical composition port.production_experiment_ledgers must contain 1..1024 live ledgers",
    );
  }
  const descriptors = Object.getOwnPropertyDescriptors(ledgerInput);
  const ledgers = [];
  const ledgerIdentities = new Set();
  for (let index = 0; index < ledgerInput.length; index += 1) {
    const descriptor = descriptors[String(index)];
    if (!descriptor || !Object.prototype.hasOwnProperty.call(descriptor, "value")
        || descriptor.enumerable !== true) {
      throw new Error(
        `production physical composition port.production_experiment_ledgers[${index}] must be an enumerable data property`,
      );
    }
    const ledger = assertProductionPhysicalExperimentLedger(descriptor.value);
    const ledgerIdentity = describeProductionPhysicalExperimentLedger(ledger);
    if (ledgerIdentity.target_domain !== identity.target_domain) {
      throw new Error("production physical composition ledger target_domain drift");
    }
    const key = `${ledgerIdentity.session_nucleus_hash}:${ledgerIdentity.plan_hash}`;
    if (ledgerIdentities.has(key)) {
      throw new Error("production physical composition port contains a duplicate ledger");
    }
    ledgerIdentities.add(key);
    ledgers.push(ledger);
  }
  for (const key of Reflect.ownKeys(ledgerInput)) {
    if (key === "length") continue;
    if (typeof key !== "string" || !/^(0|[1-9][0-9]*)$/u.test(key)) {
      throw new Error(
        "production physical composition port.production_experiment_ledgers contains a non-index field",
      );
    }
  }
  const port = deepFreeze({
    version: PHYSICAL_COMPOSITION_ADAPTER_VERSION,
    adapter: PHYSICAL_COMPOSITION_ADAPTER_ID,
    target_domain: identity.target_domain,
    service_kind: identity.service_kind,
    production_experiment_ledger_count: ledgers.length,
    port_assurance: PHYSICAL_COMPOSITION_PORT_ASSURANCE,
    historical_projection_ready: true,
    live_capability_ready: false,
    live_capability_reason: PHYSICAL_LIVE_COMPOSITION_BLOCKER,
    production_ready: true,
  });
  PRODUCTION_PORTS.add(port);
  PRODUCTION_PORT_STATE.set(port, Object.freeze({
    service,
    targetDomain: identity.target_domain,
    ledgers: Object.freeze([...ledgers]),
  }));
  return port;
}

function installPhysicalCompositionPort(port) {
  ensureCompositionPorts();
  if (!port || !PRODUCTION_PORTS.has(port) || !PRODUCTION_PORT_STATE.has(port)
      || port.production_ready !== true) {
    throw new Error("physical composition runtime requires a production-qualified port");
  }
  const state = PRODUCTION_PORT_STATE.get(port);
  assertPhysicalSurfaceGraphServerService(state.service, state.targetDomain);
  if (INSTALLED_PORTS.has(state.targetDomain)) {
    throw new Error(`physical composition runtime is already installed for ${state.targetDomain}`);
  }
  INSTALLED_PORTS.set(state.targetDomain, Object.freeze({ port, ...state }));
  let active = true;
  return function uninstallPhysicalCompositionPort() {
    const current = INSTALLED_PORTS.get(state.targetDomain);
    if (active && current && current.port === port) {
      INSTALLED_PORTS.delete(state.targetDomain);
      active = false;
    }
  };
}

function physicalCompositionRuntimeReadiness(targetDomain = null) {
  ensureCompositionPorts();
  if (targetDomain == null) {
    const domains = [...INSTALLED_PORTS.keys()].sort();
    return deepFreeze({
      version: PHYSICAL_COMPOSITION_ADAPTER_VERSION,
      adapter: PHYSICAL_COMPOSITION_ADAPTER_ID,
      production_ready: domains.length > 0,
      historical_projection_ready: domains.length > 0,
      live_capability_ready: false,
      live_capability_reason: PHYSICAL_LIVE_COMPOSITION_BLOCKER,
      installed_target_domains: domains,
    });
  }
  const domain = assertSafeDomain(targetDomain);
  const installed = INSTALLED_PORTS.get(domain);
  return deepFreeze({
    version: PHYSICAL_COMPOSITION_ADAPTER_VERSION,
    adapter: PHYSICAL_COMPOSITION_ADAPTER_ID,
    target_domain: domain,
    production_ready: !!installed,
    historical_projection_ready: !!installed,
    live_capability_ready: false,
    live_capability_reason: PHYSICAL_LIVE_COMPOSITION_BLOCKER,
    reason: installed ? null : "production_physical_composition_port_not_installed",
  });
}

function normalizeObserverAssurance(binding) {
  const fields = [
    "external_observer_independence_domain_count",
    "external_observer_independence_domain_digest",
    "high_impact_corroboration_satisfied",
  ];
  const present = fields.filter((field) => Object.prototype.hasOwnProperty.call(binding, field));
  if (present.length === 0) {
    return Object.freeze({
      external_observer_independence_domain_count: 0,
      external_observer_independence_domain_digest: null,
      high_impact_corroboration_satisfied: false,
      observer_assurance_legacy_missing: true,
    });
  }
  if (present.length !== fields.length) {
    throw new Error("physical transition observer-assurance fields are incomplete");
  }
  const count = binding.external_observer_independence_domain_count;
  if (!Number.isSafeInteger(count) || count < 0 || count > 256) {
    throw new Error("physical transition external observer-domain count is invalid");
  }
  const satisfied = binding.high_impact_corroboration_satisfied;
  if (typeof satisfied !== "boolean" || satisfied !== (count >= 2)) {
    throw new Error("physical transition high-impact corroboration does not match observer-domain count");
  }
  return Object.freeze({
    external_observer_independence_domain_count: count,
    external_observer_independence_domain_digest: assertDigest(
      binding.external_observer_independence_domain_digest,
      "physical transition external observer-domain digest",
    ),
    high_impact_corroboration_satisfied: satisfied,
    observer_assurance_legacy_missing: false,
  });
}

function transitionGroupKey(edge) {
  const binding = edge && edge.demonstrated_transition_binding;
  if (!binding || typeof binding !== "object") {
    throw new Error("physical composition query returned an unbound transition edge");
  }
  return assertDigest(binding.transition_receipt_digest, "physical transition receipt digest");
}

function groupTransitionEdges(edges) {
  const groups = new Map();
  for (const edge of edges) {
    const key = transitionGroupKey(edge);
    const group = groups.get(key) || [];
    group.push(edge);
    groups.set(key, group);
  }
  for (const group of groups.values()) group.sort(compareEdges);
  return groups;
}

function exactFindingGroup(group, finding) {
  let matchedVerdict = false;
  for (const edge of group) {
    const binding = edge.demonstrated_transition_binding;
    if (binding.verdict_ref !== finding.verified_verdict_ref) continue;
    matchedVerdict = true;
    if (binding.session_nucleus_hash !== finding.session_nucleus_hash) {
      throw new Error("physical composition transition belongs to a different session nucleus");
    }
    if (binding.verified_claim_projection_digest !== finding.verification_projection_digest) {
      throw new Error("physical composition transition verification projection drift");
    }
  }
  return matchedVerdict;
}

function assertUniformGroup(group, finding) {
  if (!Array.isArray(group) || group.length < 1) {
    throw new Error("physical composition transition group is empty");
  }
  const first = group[0].demonstrated_transition_binding;
  const observer = normalizeObserverAssurance(first);
  const invariant = {
    session_nucleus_hash: finding.session_nucleus_hash,
    plan_hash: first.plan_hash,
    execution_request_digest: first.execution_request_digest,
    verdict_ref: finding.verified_verdict_ref,
    verified_claim_projection_digest: finding.verification_projection_digest,
    verdict_hash: first.verdict_hash,
    claim_predicate_digest: first.claim_predicate_digest,
    verdict_signer_principal_ref: first.verdict_signer_principal_ref,
    verifier_template_id: first.verifier_template_id,
    verifier_template_version: first.verifier_template_version,
    verifier_template_digest: first.verifier_template_digest,
    decision_rule_digest: first.decision_rule_digest,
    verifier_execution_receipt_ref: first.verifier_execution_receipt_ref,
    verifier_execution_receipt_digest: first.verifier_execution_receipt_digest,
    executed_evidence_registry_digest: first.executed_evidence_registry_digest,
    verdict_signer_key_id: first.verdict_signer_key_id,
    trust_root_epoch: first.trust_root_epoch,
    verdict_trust_domain_ref: first.verdict_trust_domain_ref,
    verdict_independence_domain_ref: first.verdict_independence_domain_ref,
    verdict_trust_registry_digest: first.verdict_trust_registry_digest,
    verdict_signer_enrollment_digest: first.verdict_signer_enrollment_digest,
    verdict_authorization_context_digest: first.verdict_authorization_context_digest,
    transition_signer_key_id: first.transition_signer_key_id,
    transition_trust_root_epoch: first.transition_trust_root_epoch,
    transition_receipt_digest: first.transition_receipt_digest,
    transition_instance_ref: first.transition_instance_ref,
    participants_digest: first.participants_digest,
    transition_state_epoch: first.transition_state_epoch,
    transition_state_digest: first.transition_state_digest,
    validity_kind: first.validity_kind,
    valid_from: first.valid_from,
    expires_at: first.expires_at == null ? null : first.expires_at,
    capability_instance_ref: first.capability_instance_ref == null
      ? null : first.capability_instance_ref,
    custody_state_digest: first.custody_state_digest == null
      ? null : first.custody_state_digest,
    upstream_context_digest: first.upstream_context_digest,
    upstream_execution_identities: first.upstream_execution_identities,
    observer,
  };
  for (const edge of group) {
    const binding = edge.demonstrated_transition_binding;
    const candidate = {
      session_nucleus_hash: binding.session_nucleus_hash,
      plan_hash: binding.plan_hash,
      execution_request_digest: binding.execution_request_digest,
      verdict_ref: binding.verdict_ref,
      verified_claim_projection_digest: binding.verified_claim_projection_digest,
      verdict_hash: binding.verdict_hash,
      claim_predicate_digest: binding.claim_predicate_digest,
      verdict_signer_principal_ref: binding.verdict_signer_principal_ref,
      verifier_template_id: binding.verifier_template_id,
      verifier_template_version: binding.verifier_template_version,
      verifier_template_digest: binding.verifier_template_digest,
      decision_rule_digest: binding.decision_rule_digest,
      verifier_execution_receipt_ref: binding.verifier_execution_receipt_ref,
      verifier_execution_receipt_digest: binding.verifier_execution_receipt_digest,
      executed_evidence_registry_digest: binding.executed_evidence_registry_digest,
      verdict_signer_key_id: binding.verdict_signer_key_id,
      trust_root_epoch: binding.trust_root_epoch,
      verdict_trust_domain_ref: binding.verdict_trust_domain_ref,
      verdict_independence_domain_ref: binding.verdict_independence_domain_ref,
      verdict_trust_registry_digest: binding.verdict_trust_registry_digest,
      verdict_signer_enrollment_digest: binding.verdict_signer_enrollment_digest,
      verdict_authorization_context_digest: binding.verdict_authorization_context_digest,
      transition_signer_key_id: binding.transition_signer_key_id,
      transition_trust_root_epoch: binding.transition_trust_root_epoch,
      transition_receipt_digest: binding.transition_receipt_digest,
      transition_instance_ref: binding.transition_instance_ref,
      participants_digest: binding.participants_digest,
      transition_state_epoch: binding.transition_state_epoch,
      transition_state_digest: binding.transition_state_digest,
      validity_kind: binding.validity_kind,
      valid_from: binding.valid_from,
      expires_at: binding.expires_at == null ? null : binding.expires_at,
      capability_instance_ref: binding.capability_instance_ref == null
        ? null : binding.capability_instance_ref,
      custody_state_digest: binding.custody_state_digest == null
        ? null : binding.custody_state_digest,
      upstream_context_digest: binding.upstream_context_digest,
      upstream_execution_identities: binding.upstream_execution_identities,
      observer: normalizeObserverAssurance(binding),
    };
    if (hashCanonicalJson(candidate) !== hashCanonicalJson(invariant)) {
      throw new Error("physical composition transition arc binding drift");
    }
    if (edge.source_artifact !== invariant.transition_instance_ref) {
      throw new Error("physical composition transition source receipt drift");
    }
  }
  return deepFreeze(invariant);
}

function directedReachability(group, assetLocator) {
  const nodes = new Map();
  const outgoing = new Map();
  for (const edge of group) {
    for (const node of [edge.source, edge.target]) {
      if (!node || typeof node.type !== "string" || typeof node.id !== "string"
          || !PHYSICAL_BLAST_RADIUS_NODE_POLICY[node.type]) {
        throw new Error("physical composition edge contains an unknown physical node");
      }
      nodes.set(nodeKey(node), Object.freeze({ type: node.type, id: node.id }));
    }
    const sourceKey = nodeKey(edge.source);
    const list = outgoing.get(sourceKey) || [];
    list.push(edge);
    outgoing.set(sourceKey, list);
  }
  const assetMatches = [...nodes.values()].filter((node) => (
    node.type === "asset" && node.id === assetLocator
  ));
  if (assetMatches.length !== 1) {
    throw new Error("physical composition transition does not bind the finding asset exactly once");
  }
  const start = nodeKey(assetMatches[0]);
  const distance = new Map([[start, 0]]);
  const queue = [start];
  const reachableEdges = new Map();
  while (queue.length > 0) {
    const current = queue.shift();
    const currentDistance = distance.get(current);
    for (const edge of outgoing.get(current) || []) {
      reachableEdges.set(edge.edge_hash, edge);
      const target = nodeKey(edge.target);
      if (!distance.has(target)) {
        distance.set(target, currentDistance + 1);
        queue.push(target);
      }
    }
  }
  const reachableNodes = [...distance.entries()]
    .filter(([key]) => key !== start)
    .map(([key, minimumHops]) => ({
      node: nodes.get(key),
      minimum_hops: minimumHops,
    }))
    .sort((left, right) => compareNodes(left.node, right.node));
  return deepFreeze({
    reachableNodes,
    reachableEdges: [...reachableEdges.values()].sort(compareEdges),
  });
}

function blastRadiusPolicy(reachableNodes, observer) {
  let structuralCeiling = "low";
  const nodeTypeCounts = {};
  const categories = new Set();
  for (const entry of reachableNodes) {
    const policy = PHYSICAL_BLAST_RADIUS_NODE_POLICY[entry.node.type];
    structuralCeiling = maxSeverity(structuralCeiling, policy.severity_ceiling);
    categories.add(policy.category);
    nodeTypeCounts[entry.node.type] = (nodeTypeCounts[entry.node.type] || 0) + 1;
  }
  const sortedCategories = [...categories].sort();
  const criticalPair = CRITICAL_CATEGORY_PAIRS.find(([left, right]) => (
    categories.has(left) && categories.has(right)
  ));
  if (criticalPair) structuralCeiling = "critical";
  const corroborated = observer.high_impact_corroboration_satisfied === true;
  const verifiedCeiling = SEVERITY_RANK[structuralCeiling] >= SEVERITY_RANK.high
    && !corroborated
    ? "medium"
    : structuralCeiling;
  const orderedCounts = Object.fromEntries(
    Object.entries(nodeTypeCounts).sort(([left], [right]) => left.localeCompare(right)),
  );
  const radiusClass = criticalPair
    ? "compound_control_plane"
    : (categories.has("network")
      ? "network_attachment"
      : (categories.has("zone")
        ? "bounded_zone"
        : (SEVERITY_RANK[structuralCeiling] >= SEVERITY_RANK.high
          ? "bounded_control"
          : "asset_local")));
  return deepFreeze({
    reachable_node_type_counts: orderedCounts,
    blast_radius_categories: sortedCategories,
    blast_radius_class: radiusClass,
    attack_vector: categories.has("network") ? "network" : "local",
    structural_severity_ceiling: structuralCeiling,
    verified_severity_ceiling: verifiedCeiling,
    critical_category_pair: criticalPair ? [...criticalPair] : null,
  });
}

function transitionLeaf(edge, invariant) {
  const binding = edge.demonstrated_transition_binding;
  const body = {
    version: PHYSICAL_COMPOSITION_ADAPTER_VERSION,
    leaf_kind: "physical_verified_surface_transition",
    edge_hash: edge.edge_hash,
    source: edge.source,
    target: edge.target,
    source_participant_role: binding.source_participant_role,
    target_participant_role: binding.target_participant_role,
    session_nucleus_hash: invariant.session_nucleus_hash,
    plan_hash: invariant.plan_hash,
    execution_request_digest: invariant.execution_request_digest,
    verified_verdict_ref: invariant.verdict_ref,
    verified_verdict_hash: invariant.verdict_hash,
    verification_projection_digest: invariant.verified_claim_projection_digest,
    claim_predicate_digest: invariant.claim_predicate_digest,
    verdict_signer_principal_ref: invariant.verdict_signer_principal_ref,
    verifier_template_id: invariant.verifier_template_id,
    verifier_template_version: invariant.verifier_template_version,
    verifier_template_digest: invariant.verifier_template_digest,
    decision_rule_digest: invariant.decision_rule_digest,
    verifier_execution_receipt_ref: invariant.verifier_execution_receipt_ref,
    verifier_execution_receipt_digest: invariant.verifier_execution_receipt_digest,
    executed_evidence_registry_digest: invariant.executed_evidence_registry_digest,
    verdict_signer_key_id: invariant.verdict_signer_key_id,
    verdict_trust_root_epoch: invariant.trust_root_epoch,
    verdict_trust_domain_ref: invariant.verdict_trust_domain_ref,
    verdict_independence_domain_ref: invariant.verdict_independence_domain_ref,
    verdict_trust_registry_digest: invariant.verdict_trust_registry_digest,
    verdict_signer_enrollment_digest: invariant.verdict_signer_enrollment_digest,
    verdict_authorization_context_digest: invariant.verdict_authorization_context_digest,
    transition_signer_key_id: invariant.transition_signer_key_id,
    transition_trust_root_epoch: invariant.transition_trust_root_epoch,
    transition_receipt_ref: invariant.transition_instance_ref,
    transition_receipt_digest: invariant.transition_receipt_digest,
    transition_state_epoch: invariant.transition_state_epoch,
    transition_state_digest: invariant.transition_state_digest,
    validity_kind: invariant.validity_kind,
    upstream_execution_identities: invariant.upstream_execution_identities,
    upstream_context_digest: invariant.upstream_context_digest,
    prerequisite_eligible: edge.prerequisite_eligible === true,
    eligibility_reason: edge.eligibility_reason,
    authority_inherited: false,
    downstream_authority_required: true,
    downstream_consumption_verified: false,
    ...(invariant.expires_at == null ? {} : {
      expires_at: invariant.expires_at,
      capability_instance_ref: invariant.capability_instance_ref,
      custody_state_digest: invariant.custody_state_digest,
    }),
    ...(edge.live_revalidation == null ? {} : {
      live_revalidation_receipt_ref: edge.live_revalidation.receipt_ref,
      live_revalidation_receipt_digest: edge.live_revalidation.receipt_digest,
      live_revalidation_signer_key_id: edge.live_revalidation.signer_key_id,
      live_revalidation_trust_root_epoch: edge.live_revalidation.trust_root_epoch,
      revalidated_at: edge.live_revalidation.revalidated_at,
      revalidation_expires_at: edge.live_revalidation.revalidation_expires_at,
    }),
  };
  const leafDigest = hashCanonicalJson({
    domain: "hacker-bob/physical-composition-leaf/v1",
    ...body,
  });
  return deepFreeze({
    ...body,
    leaf_ref: `physical-composition-leaf:v1:${leafDigest}`,
    leaf_digest: leafDigest,
  });
}

function buildPhysicalCompositionProjection(targetDomain, findingInput) {
  ensureCompositionPorts();
  const domain = assertSafeDomain(targetDomain);
  assertManifestRegistration();
  const finding = assertPhysicalFinding(findingInput);
  const installed = INSTALLED_PORTS.get(domain);
  if (!installed || !PRODUCTION_PORTS.has(installed.port)
      || PRODUCTION_PORT_STATE.get(installed.port)?.service !== installed.service) {
    throw new Error("production physical composition runtime is not installed for this target");
  }
  const service = assertPhysicalSurfaceGraphServerService(installed.service, domain);
  const matchingClaimProjections = [];
  for (const ledger of installed.ledgers) {
    const identity = describeProductionPhysicalExperimentLedger(
      assertProductionPhysicalExperimentLedger(ledger),
    );
    if (identity.target_domain !== domain
        || identity.session_nucleus_hash !== finding.session_nucleus_hash) continue;
    const claim = assertVerifiedPhysicalClaimProjection(ledger.projectVerifiedClaim());
    if (claim.claim_verdict_ref !== finding.verified_verdict_ref) continue;
    if (claim.projection_digest !== finding.verification_projection_digest
        || claim.target_asset_ref !== finding.asset_locator) {
      throw new Error("physical composition live experiment projection drift");
    }
    matchingClaimProjections.push(claim);
  }
  if (matchingClaimProjections.length !== 1) {
    throw new Error(
      matchingClaimProjections.length === 0
        ? "physical composition finding has no exact live production experiment projection"
        : "physical composition finding is ambiguous across live production experiment projections",
    );
  }
  const liveClaimProjection = matchingClaimProjections[0];
  const query = service.queryVerifiedTransitionEdges({
    verdict_ref: finding.verified_verdict_ref,
    verified_claim_projection_digest: finding.verification_projection_digest,
    limit: MAX_QUERY_LIMIT,
  });
  if (!query || !Array.isArray(query.edges)
      || !Number.isSafeInteger(query.total_matched)
      || query.total_matched !== query.edges.length) {
    throw new Error("physical composition refuses a truncated SurfaceGraph transition projection");
  }
  if (query.quarantined_count !== 0) {
    throw new Error("physical composition refuses SurfaceGraph state with quarantined records");
  }
  const groups = groupTransitionEdges(query.edges);
  const matching = [...groups.values()].filter((group) => exactFindingGroup(group, finding));
  if (matching.length !== 1) {
    throw new Error(
      matching.length === 0
        ? "physical finding has no exact verified SurfaceGraph transition receipt"
        : "physical finding has ambiguous verified SurfaceGraph transition receipts",
    );
  }
  const group = matching[0];
  const invariant = assertUniformGroup(group, finding);
  const transitionClaimBinding = {
    session_nucleus_hash: invariant.session_nucleus_hash,
    plan_hash: invariant.plan_hash,
    execution_request_digest: invariant.execution_request_digest,
    claim_predicate_digest: invariant.claim_predicate_digest,
    claim_verdict_ref: invariant.verdict_ref,
    claim_verdict_hash: invariant.verdict_hash,
    claim_verdict_signer_key_id: invariant.verdict_signer_key_id,
    claim_verdict_signer_principal_ref: invariant.verdict_signer_principal_ref,
    claim_verdict_trust_root_epoch: invariant.trust_root_epoch,
    claim_verdict_trust_domain_ref: invariant.verdict_trust_domain_ref,
    claim_verdict_independence_domain_ref: invariant.verdict_independence_domain_ref,
    claim_verdict_trust_registry_digest: invariant.verdict_trust_registry_digest,
    claim_verdict_signer_enrollment_digest: invariant.verdict_signer_enrollment_digest,
    claim_verdict_authorization_context_digest:
      invariant.verdict_authorization_context_digest,
    verifier_template_id: invariant.verifier_template_id,
    verifier_template_version: invariant.verifier_template_version,
    verifier_template_digest: invariant.verifier_template_digest,
    decision_rule_digest: invariant.decision_rule_digest,
    verifier_execution_receipt_ref: invariant.verifier_execution_receipt_ref,
    verifier_execution_receipt_digest: invariant.verifier_execution_receipt_digest,
    executed_evidence_registry_digest: invariant.executed_evidence_registry_digest,
    upstream_execution_identities: invariant.upstream_execution_identities,
    upstream_context_digest: invariant.upstream_context_digest,
    transition_state_epoch: invariant.transition_state_epoch,
    transition_state_digest: invariant.transition_state_digest,
    validity_kind: invariant.validity_kind,
    valid_from: invariant.valid_from,
    expires_at: invariant.expires_at,
    capability_instance_ref: invariant.capability_instance_ref,
    custody_state_digest: invariant.custody_state_digest,
    external_observer_independence_domain_count:
      invariant.observer.external_observer_independence_domain_count,
    external_observer_independence_domain_digest:
      invariant.observer.external_observer_independence_domain_digest,
    high_impact_corroboration_satisfied:
      invariant.observer.high_impact_corroboration_satisfied,
  };
  const liveClaimBinding = Object.fromEntries(
    Object.keys(transitionClaimBinding).map((field) => [
      field,
      liveClaimProjection[field] == null ? null : liveClaimProjection[field],
    ]),
  );
  if (hashCanonicalJson(transitionClaimBinding) !== hashCanonicalJson(liveClaimBinding)) {
    throw new Error("physical composition transition drifted from the exact live claim projection");
  }
  const reachability = directedReachability(group, finding.asset_locator);
  if (reachability.reachableEdges.length < 1 || reachability.reachableNodes.length < 1) {
    throw new Error("physical transition proves no directed reachability from the bound asset");
  }
  if (invariant.validity_kind === "live_capability") {
    const ineligible = group.filter((edge) => (
      edge.prerequisite_eligible !== true || edge.live_revalidation == null
    ));
    if (ineligible.length > 0) {
      throw new Error(
        "physical live-capability transition is expired, revoked, stale, or lacks current custody revalidation",
      );
    }
    // SurfaceGraph's current implementation validates the signed live-state
    // receipt against process-local wall time plus an in-memory rollback floor.
    // That is sufficient to withhold stale prerequisites during one process,
    // but it is not restart-durable trusted time.  Refuse production promotion
    // until a signed monotonic mapping with a durable high-water mark is bound
    // into the service/receipt verification path.
    throw new Error(
      `physical live-capability composition lacks restart-durable signed trusted-time validation (${PHYSICAL_LIVE_COMPOSITION_BLOCKER})`,
    );
  }
  const policy = blastRadiusPolicy(reachability.reachableNodes, invariant.observer);
  // The signed receipt may describe more than one disconnected component.  It
  // is still validated and bound as one exact N-ary transition above, but only
  // directed edges causally reachable from the finding's exact asset may enter
  // downstream composition.  A separately verified yet disconnected arc is
  // not evidence that this finding exposed its target.
  const leaves = reachability.reachableEdges.map((edge) => transitionLeaf(edge, invariant));
  const liveLeaves = leaves.filter((leaf) => leaf.prerequisite_eligible === true);
  const reachableNodeSet = reachability.reachableNodes.map((entry) => ({
    type: entry.node.type,
    id: entry.node.id,
    minimum_hops: entry.minimum_hops,
  }));
  const reachableEdgeSet = reachability.reachableEdges.map((edge) => ({
    edge_hash: edge.edge_hash,
    source: edge.source,
    target: edge.target,
  }));
  const body = {
    version: PHYSICAL_COMPOSITION_ADAPTER_VERSION,
    adapter: PHYSICAL_COMPOSITION_ADAPTER_ID,
    target_domain: domain,
    capability_pack: "physical",
    finding_dedupe_key: finding.finding_dedupe_key,
    asset_locator: finding.asset_locator,
    session_nucleus_hash: finding.session_nucleus_hash,
    plan_hash: invariant.plan_hash,
    execution_request_digest: invariant.execution_request_digest,
    verified_verdict_ref: finding.verified_verdict_ref,
    verified_verdict_hash: invariant.verdict_hash,
    verification_projection_digest: finding.verification_projection_digest,
    verdict_signer_principal_ref: invariant.verdict_signer_principal_ref,
    verdict_signer_key_id: invariant.verdict_signer_key_id,
    verdict_trust_root_epoch: invariant.trust_root_epoch,
    verdict_trust_domain_ref: invariant.verdict_trust_domain_ref,
    verdict_independence_domain_ref: invariant.verdict_independence_domain_ref,
    verdict_trust_registry_digest: invariant.verdict_trust_registry_digest,
    verdict_signer_enrollment_digest: invariant.verdict_signer_enrollment_digest,
    verdict_authorization_context_digest: invariant.verdict_authorization_context_digest,
    verifier_template_id: invariant.verifier_template_id,
    verifier_template_version: invariant.verifier_template_version,
    verifier_template_digest: invariant.verifier_template_digest,
    decision_rule_digest: invariant.decision_rule_digest,
    verifier_execution_receipt_ref: invariant.verifier_execution_receipt_ref,
    verifier_execution_receipt_digest: invariant.verifier_execution_receipt_digest,
    executed_evidence_registry_digest: invariant.executed_evidence_registry_digest,
    transition_receipt_ref: invariant.transition_instance_ref,
    transition_receipt_digest: invariant.transition_receipt_digest,
    transition_signer_key_id: invariant.transition_signer_key_id,
    transition_trust_root_epoch: invariant.transition_trust_root_epoch,
    claim_predicate_digest: invariant.claim_predicate_digest,
    participants_digest: invariant.participants_digest,
    transition_state_epoch: invariant.transition_state_epoch,
    transition_state_digest: invariant.transition_state_digest,
    validity_kind: invariant.validity_kind,
    valid_from: invariant.valid_from,
    ...(invariant.expires_at == null ? {} : {
      expires_at: invariant.expires_at,
      capability_instance_ref: invariant.capability_instance_ref,
      custody_state_digest: invariant.custody_state_digest,
    }),
    upstream_execution_identities: invariant.upstream_execution_identities,
    upstream_context_digest: invariant.upstream_context_digest,
    external_observer_independence_domain_count:
      invariant.observer.external_observer_independence_domain_count,
    external_observer_independence_domain_digest:
      invariant.observer.external_observer_independence_domain_digest,
    high_impact_corroboration_satisfied:
      invariant.observer.high_impact_corroboration_satisfied,
    observer_assurance_legacy_missing: invariant.observer.observer_assurance_legacy_missing,
    transition_edge_count: group.length,
    transition_edge_set_digest: hashCanonicalJson({
      domain: "hacker-bob/physical-transition-edge-set/v1",
      edges: group.map((edge) => edge.edge_hash).sort(),
    }),
    reachable_node_count: reachableNodeSet.length,
    reachable_node_set_digest: hashCanonicalJson({
      domain: "hacker-bob/physical-reachable-node-set/v1",
      nodes: reachableNodeSet,
    }),
    reachable_edge_count: reachableEdgeSet.length,
    reachable_edge_set_digest: hashCanonicalJson({
      domain: "hacker-bob/physical-reachable-edge-set/v1",
      edges: reachableEdgeSet,
    }),
    reachable_node_type_counts: policy.reachable_node_type_counts,
    blast_radius_categories: policy.blast_radius_categories,
    blast_radius_category_digest: hashCanonicalJson({
      domain: "hacker-bob/physical-blast-radius-categories/v1",
      categories: policy.blast_radius_categories,
    }),
    blast_radius_class: policy.blast_radius_class,
    attack_vector: policy.attack_vector,
    structural_severity_ceiling: policy.structural_severity_ceiling,
    verified_severity_ceiling: policy.verified_severity_ceiling,
    critical_category_pair: policy.critical_category_pair,
    historical_fact_only: invariant.validity_kind === "historical_event",
    live_capability_current: invariant.validity_kind === "live_capability",
    transition_leaves: leaves,
    live_capability_leaf_count: liveLeaves.length,
    live_capability_leaf_set_digest: hashCanonicalJson({
      domain: "hacker-bob/physical-live-capability-leaf-set/v1",
      leaf_digests: liveLeaves.map((leaf) => leaf.leaf_digest).sort(),
    }),
    authority_inherited: false,
    downstream_authority_required: true,
    downstream_consumption_verified: false,
    production_ready: true,
  };
  const projection = deepFreeze({
    ...body,
    composition_projection_digest: hashCanonicalJson({
      domain: "hacker-bob/physical-composition-projection/v1",
      ...body,
    }),
  });
  PHYSICAL_COMPOSITION_PROJECTIONS.add(projection);
  PHYSICAL_COMPOSITION_PROJECTION_STATE.set(projection, Object.freeze({
    targetDomain: domain,
    port: installed.port,
    finding,
  }));
  return projection;
}

function assertPhysicalCompositionProjection(value) {
  ensureCompositionPorts();
  const state = value && PHYSICAL_COMPOSITION_PROJECTION_STATE.get(value);
  if (!value || !PHYSICAL_COMPOSITION_PROJECTIONS.has(value) || !state
      || value.production_ready !== true) {
    throw new Error("physical composition projection must come from the production pack adapter");
  }
  const installed = INSTALLED_PORTS.get(state.targetDomain);
  if (!installed || installed.port !== state.port) {
    throw new Error("physical composition projection's production port is no longer installed");
  }
  // A projection is a snapshot, never lasting authority.  Rebuild it now so
  // expiry, revocation, custody, session, graph, and receipt changes invalidate
  // every downstream grade/report consumer.  A fresh live challenge naturally
  // changes the live-revalidation receipt and whole projection digest; compare
  // the stable causal/blast-radius binding, then return the refreshed object.
  const rebuilt = buildPhysicalCompositionProjection(
    state.targetDomain,
    // `finding` is a privately branded server projection, not persisted caller
    // data.  Higher lifecycle consumers resolve the claim ledger again before
    // calling this assertion; this repeat additionally rechecks the graph,
    // transition issuer, current nucleus, expiry, state epoch, and custody.
    state.finding,
  );
  const stableFields = [
    "target_domain",
    "finding_dedupe_key",
    "asset_locator",
    "session_nucleus_hash",
    "plan_hash",
    "execution_request_digest",
    "verified_verdict_ref",
    "verified_verdict_hash",
    "verification_projection_digest",
    "verdict_signer_principal_ref",
    "verdict_signer_key_id",
    "verdict_trust_root_epoch",
    "verdict_trust_domain_ref",
    "verdict_independence_domain_ref",
    "verdict_trust_registry_digest",
    "verdict_signer_enrollment_digest",
    "verdict_authorization_context_digest",
    "verifier_template_id",
    "verifier_template_version",
    "verifier_template_digest",
    "decision_rule_digest",
    "verifier_execution_receipt_ref",
    "verifier_execution_receipt_digest",
    "executed_evidence_registry_digest",
    "transition_receipt_ref",
    "transition_receipt_digest",
    "transition_signer_key_id",
    "transition_trust_root_epoch",
    "claim_predicate_digest",
    "participants_digest",
    "transition_state_epoch",
    "transition_state_digest",
    "validity_kind",
    "valid_from",
    "expires_at",
    "capability_instance_ref",
    "custody_state_digest",
    "upstream_context_digest",
    "upstream_execution_identities",
    "external_observer_independence_domain_count",
    "external_observer_independence_domain_digest",
    "high_impact_corroboration_satisfied",
    "observer_assurance_legacy_missing",
    "transition_edge_count",
    "transition_edge_set_digest",
    "reachable_node_count",
    "reachable_node_set_digest",
    "reachable_edge_count",
    "reachable_edge_set_digest",
    "reachable_node_type_counts",
    "blast_radius_categories",
    "blast_radius_category_digest",
    "blast_radius_class",
    "attack_vector",
    "structural_severity_ceiling",
    "verified_severity_ceiling",
    "critical_category_pair",
    "historical_fact_only",
    "live_capability_current",
    "authority_inherited",
    "downstream_authority_required",
    "downstream_consumption_verified",
  ];
  if (stableFields.some((field) => (
    hashCanonicalJson(rebuilt[field] ?? null) !== hashCanonicalJson(value[field] ?? null)
  ))) {
    throw new Error("physical composition projection drifted from current verified reachability");
  }
  return rebuilt;
}

function bindPhysicalSeverityToVerifiedBlastRadius(compositionInput, verifiedSeverity) {
  ensureCompositionPorts();
  if (!Object.prototype.hasOwnProperty.call(SEVERITY_RANK, verifiedSeverity)) {
    throw new Error("physical blast-radius grade severity is invalid");
  }
  const composition = assertPhysicalCompositionProjection(compositionInput);
  if ((verifiedSeverity === "high" || verifiedSeverity === "critical")
      && composition.high_impact_corroboration_satisfied !== true) {
    throw new Error(
      `physical ${verifiedSeverity} severity requires at least two independently enrolled external observer domains`,
    );
  }
  if (SEVERITY_RANK[verifiedSeverity]
      > SEVERITY_RANK[composition.verified_severity_ceiling]) {
    throw new Error(
      `physical ${verifiedSeverity} severity exceeds verified blast-radius ceiling ${composition.verified_severity_ceiling}`,
    );
  }
  const body = {
    version: PHYSICAL_COMPOSITION_ADAPTER_VERSION,
    binding_kind: "physical_verified_blast_radius_grade",
    adapter: PHYSICAL_COMPOSITION_ADAPTER_ID,
    target_domain: composition.target_domain,
    finding_dedupe_key: composition.finding_dedupe_key,
    asset_locator: composition.asset_locator,
    session_nucleus_hash: composition.session_nucleus_hash,
    verified_verdict_ref: composition.verified_verdict_ref,
    verification_projection_digest: composition.verification_projection_digest,
    composition_projection_digest: composition.composition_projection_digest,
    transition_receipt_ref: composition.transition_receipt_ref,
    transition_receipt_digest: composition.transition_receipt_digest,
    claim_predicate_digest: composition.claim_predicate_digest,
    transition_state_epoch: composition.transition_state_epoch,
    transition_state_digest: composition.transition_state_digest,
    validity_kind: composition.validity_kind,
    verified_severity: verifiedSeverity,
    verified_severity_ceiling: composition.verified_severity_ceiling,
    structural_severity_ceiling: composition.structural_severity_ceiling,
    blast_radius_class: composition.blast_radius_class,
    attack_vector: composition.attack_vector,
    transition_edge_count: composition.transition_edge_count,
    transition_edge_set_digest: composition.transition_edge_set_digest,
    reachable_node_count: composition.reachable_node_count,
    reachable_node_set_digest: composition.reachable_node_set_digest,
    reachable_edge_count: composition.reachable_edge_count,
    reachable_edge_set_digest: composition.reachable_edge_set_digest,
    reachable_node_type_counts: composition.reachable_node_type_counts,
    blast_radius_categories: composition.blast_radius_categories,
    blast_radius_category_digest: composition.blast_radius_category_digest,
    critical_category_pair: composition.critical_category_pair,
    external_observer_independence_domain_count:
      composition.external_observer_independence_domain_count,
    external_observer_independence_domain_digest:
      composition.external_observer_independence_domain_digest,
    high_impact_corroboration_satisfied:
      composition.high_impact_corroboration_satisfied,
    observer_assurance_legacy_missing:
      composition.observer_assurance_legacy_missing,
    historical_fact_only: composition.historical_fact_only,
    live_capability_current: composition.live_capability_current,
    authority_inherited: false,
    downstream_authority_required: true,
    downstream_consumption_verified: false,
    production_ready: true,
  };
  const binding = deepFreeze({
    ...body,
    blast_radius_grade_binding_digest: hashCanonicalJson({
      domain: "hacker-bob/physical-verified-blast-radius-grade/v1",
      ...body,
    }),
  });
  PHYSICAL_BLAST_RADIUS_GRADE_BINDINGS.add(binding);
  PHYSICAL_BLAST_RADIUS_GRADE_BINDING_STATE.set(binding, Object.freeze({
    composition,
    verifiedSeverity,
  }));
  return binding;
}

function assertPhysicalBlastRadiusGradeBinding(value) {
  ensureCompositionPorts();
  const state = value && PHYSICAL_BLAST_RADIUS_GRADE_BINDING_STATE.get(value);
  if (!value || !state || !PHYSICAL_BLAST_RADIUS_GRADE_BINDINGS.has(value)
      || value.production_ready !== true) {
    throw new Error("physical blast-radius grade binding must come from the composition adapter");
  }
  // A grade binding is a snapshot of a verified transition, not lasting
  // authority.  Reasserting it must requery the branded SurfaceGraph service
  // and current experiment ledger through the source composition projection.
  // This makes a later receipt revocation, state-epoch drift, or port removal
  // invalidate direct consumers as well as the top-level artifact adapters.
  const rebuilt = bindPhysicalSeverityToVerifiedBlastRadius(
    state.composition,
    state.verifiedSeverity,
  );
  if (rebuilt.blast_radius_grade_binding_digest
      !== value.blast_radius_grade_binding_digest) {
    throw new Error("physical blast-radius grade binding drifted from current verified reachability");
  }
  return rebuilt;
}

module.exports = Object.freeze({
  CRITICAL_CATEGORY_PAIRS,
  PHYSICAL_BLAST_RADIUS_NODE_POLICY,
  PHYSICAL_COMPOSITION_ADAPTER_ID,
  PHYSICAL_COMPOSITION_ADAPTER_VERSION,
  PHYSICAL_LIVE_COMPOSITION_BLOCKER,
  assertPhysicalBlastRadiusGradeBinding,
  assertPhysicalCompositionProjection,
  bindPhysicalSeverityToVerifiedBlastRadius,
  buildPhysicalCompositionProjection,
  createProductionPhysicalCompositionPort,
  configureCapabilityPackCompositionPorts,
  installPhysicalCompositionPort,
  physicalCompositionRuntimeReadiness,
});
