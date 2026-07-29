"use strict";

// PH-X8 signed release-readiness binds one private conformance snapshot to an
// exact release candidate and a gate-owned, nonsemantic atomic evidence receipt.
// A snapshot is never release-action authority: consumers must assert currentness
// immediately before use, and production readiness remains deliberately false.
//
// This module also owns the shared structural graph diagnostics
// (evaluatePlanePhysicalReleaseReadiness / evaluatePackagedPlanePhysicalReleaseReadiness)
// that the CI release-check consumes and that the signed evaluator reuses before
// applying its stricter independently-signed evidence contract.

const crypto = require("node:crypto");
const { types: utilTypes } = require("node:util");
const {
  assertConformancePlanePhysicalGateEvidenceBatch,
  assertVerifiedPlanePhysicalGateEvidenceBatch,
  planePhysicalReleaseCandidateDigest,
  resolveAndVerifyPlanePhysicalGateEvidenceBatch,
} = require("./plane-physical-gate-evidence.js");
const {
  PLANE_PHYSICAL_GRAPH_ID,
  PLANE_PHYSICAL_PRODUCTION_NONWAIVABLE_HIL_NODE_IDS,
  PLANE_PHYSICAL_RELEASE_NODE_ID,
  PLANE_PHYSICAL_REVIEWED_HYPEREDGE_REGISTRY_SHA256,
  PLANE_PHYSICAL_REVIEWED_NODE_CONTRACT_REGISTRY_SHA256,
  planePhysicalHyperedgeRegistryDigest,
  planePhysicalNodeContractDigest,
  planePhysicalNodeContractRegistryDigest,
} = require("./plane-physical-release-contracts.js");
const {
  PLANE_PHYSICAL_PACKAGED_RELEASE_SNAPSHOT,
  assertPackagedPlanePhysicalReleaseSnapshot,
} = require("./plane-physical-release-snapshot.js");

const VERSION = 1;
const DOMAIN = "hacker-bob/plane-physical-release-readiness";
const ASSURANCE = "exact_release_candidate_independently_signed_gate_evidence";
const EVIDENCE_RE = /^bob-evidence:sha256:[a-f0-9]{64}$/u;
const DIGEST_RE = /^[a-f0-9]{64}$/u;
const GATE_KINDS = Object.freeze(["engineering", "review", "hil"]);
const EVIDENCE_CLASSES = Object.freeze(["engineering", "review", "hil", "qualification"]);
const REVIEW_REQUIREMENT =
  "Independent review approves the exact immutable node contract and bound release candidate.";
const RELEASE_VERDICTS = new WeakSet();
const RELEASE_VERDICT_STATE = new WeakMap();
const RELEASE_READINESS_PLANS = new WeakSet();
const RELEASE_READINESS_PLAN_STATE = new WeakMap();
const RELEASE_EVALUATIONS_IN_FLIGHT = new WeakSet();
const RUNTIME_RECEIPT_COMMIT_METHOD = "commit_release_snapshot_receipt";
const RUNTIME_RECEIPT_CURRENT_METHOD = "assert_current_release_snapshot_receipt";

// ==== shared structural graph diagnostics (folded from the former standalone
// readiness module) ====  This is a self-contained conformance engine that can
// prove a candidate is blocked and why, but never mints a production-ready
// verdict.  It is scoped so its non-canonical/boolean helper set never collides
// with the signed evaluator's canonical/throwing helpers below.
const {
  PLANE_PHYSICAL_RELEASE_QUALIFICATION_CHECK_REGISTRY,
  PLANE_PHYSICAL_RELEASE_QUALIFICATION_CHECK_REGISTRY_SHA256,
  PLANE_PHYSICAL_RELEASE_READINESS_ASSURANCE,
  PLANE_PHYSICAL_RELEASE_READINESS_DOMAIN,
  PLANE_PHYSICAL_RELEASE_READINESS_VERSION,
  evaluatePlanePhysicalReleaseReadiness,
  evaluatePackagedPlanePhysicalReleaseReadiness,
} = (() => {
  const STRUCTURAL_VERSION = 1;
  const STRUCTURAL_DOMAIN = "hacker-bob/plane-physical-release-readiness/conformance";
  const STRUCTURAL_ASSURANCE = "caller_asserted_conformance";
  const EVIDENCE_REF_PATTERN = /^bob-evidence:sha256:[a-f0-9]{64}$/;
  const WAIVER_REF_PATTERN = /^bob-waiver:v1:sha256:[a-f0-9]{64}$/;
  const DIGEST_PATTERN = /^[a-f0-9]{64}$/;
  const PRODUCTION_ONLY_BLOCKERS = new Set([
    "gate_evidence_not_production_qualified",
    "release_validator_not_production_qualified",
  ]);

  const QUALIFICATION_CHECK_BASES = Object.freeze([
    Object.freeze({
      check_id: "governance_taskgraph_contract_migrations",
      category: "migration",
      assertion: "governance, TaskGraph/cell, and contract-artifact schemas migrate by version",
    }),
    Object.freeze({
      check_id: "surface_pack_composition_finding_migrations",
      category: "migration",
      assertion: "SurfaceGraph, pack, composition, finding, and gate-evidence schemas migrate by version",
    }),
    Object.freeze({
      check_id: "v1_read_resume_compatibility",
      category: "compatibility",
      assertion: "v1 sessions remain readable and resumable under their original immutable contracts",
    }),
    Object.freeze({
      check_id: "v2_explicit_physical_opt_in",
      category: "compatibility",
      assertion: "physical authority requires explicit opt-in and never mutates a v1 nucleus",
    }),
    Object.freeze({
      check_id: "unknown_version_and_surface_fail_closed",
      category: "compatibility",
      assertion: "unknown schema, pack, and surface versions never fall back to web semantics",
    }),
    Object.freeze({
      check_id: "successor_nucleus_grant_rotation",
      category: "migration",
      assertion: "migration signs a successor nucleus and reissues or revokes every affected grant",
    }),
    Object.freeze({
      check_id: "rollback_idempotence_old_session_fixture",
      category: "rollback",
      assertion: "rollback is idempotent and old-session fixtures retain their original authority",
    }),
    Object.freeze({
      check_id: "clean_install_update_uninstall_doctor",
      category: "packaging",
      assertion: "clean install, update, uninstall, reinstall, and doctor preserve the runtime manifest",
    }),
    Object.freeze({
      check_id: "canonical_package_sanitization",
      category: "sanitization",
      assertion: "packed artifacts contain no live evidence, vault, credential, session, device, or secret data",
    }),
    Object.freeze({
      check_id: "package_release_audit_no_hardware_io",
      category: "sanitization",
      assertion: "package and release auditing performs no instrument or hardware operation",
    }),
  ]);

  const isProxy = utilTypes.isProxy.bind(utilTypes);
  const jsonParse = JSON.parse;
  const jsonStringify = JSON.stringify;
  const objectFreeze = Object.freeze;
  const objectGetOwnPropertyDescriptor = Object.getOwnPropertyDescriptor;
  const objectGetOwnPropertyNames = Object.getOwnPropertyNames;
  const objectGetOwnPropertySymbols = Object.getOwnPropertySymbols;
  const objectGetPrototypeOf = Object.getPrototypeOf;
  const objectHasOwn = Function.call.bind(Object.prototype.hasOwnProperty);
  const objectPrototype = Object.prototype;

  function digestJson(value) {
    return crypto.createHash("sha256").update(jsonStringify(value)).digest("hex");
  }

  const QUALIFICATION_CHECK_REGISTRY = objectFreeze(QUALIFICATION_CHECK_BASES.map((basis) => (
    objectFreeze({ ...basis, test_manifest_digest: digestJson({ version: STRUCTURAL_VERSION, ...basis }) })
  )));
  const QUALIFICATION_CHECK_REGISTRY_SHA256 = digestJson(QUALIFICATION_CHECK_REGISTRY);

  function assertDataTree(value, label, seen = new WeakSet()) {
    if (value === null || typeof value === "string" || typeof value === "boolean") return value;
    if (typeof value === "number" && Number.isFinite(value)) return value;
    if (!value || typeof value !== "object" || isProxy(value)) {
      throw new Error(`${label} must contain only non-Proxy JSON data`);
    }
    if (seen.has(value)) throw new Error(`${label} cannot contain cycles`);
    seen.add(value);
    if (objectGetOwnPropertySymbols(value).length !== 0) {
      throw new Error(`${label} cannot contain symbol fields`);
    }
    if (Array.isArray(value)) {
      const names = objectGetOwnPropertyNames(value);
      if (names.length !== value.length + 1 || names[names.length - 1] !== "length") {
        throw new Error(`${label} must be a dense data-only array`);
      }
      for (let index = 0; index < value.length; index += 1) {
        const descriptor = objectGetOwnPropertyDescriptor(value, `${index}`);
        if (!descriptor || descriptor.get || descriptor.set || !descriptor.enumerable
            || !objectHasOwn(descriptor, "value")) {
          throw new Error(`${label}[${index}] must be an enumerable data property`);
        }
        assertDataTree(descriptor.value, `${label}[${index}]`, seen);
      }
      return value;
    }
    const prototype = objectGetPrototypeOf(value);
    if (prototype !== objectPrototype && prototype !== null) {
      throw new Error(`${label} must contain only plain data objects`);
    }
    for (const field of objectGetOwnPropertyNames(value)) {
      const descriptor = objectGetOwnPropertyDescriptor(value, field);
      if (!descriptor || descriptor.get || descriptor.set || !descriptor.enumerable
          || !objectHasOwn(descriptor, "value")) {
        throw new Error(`${label}.${field} must be an enumerable data property`);
      }
      assertDataTree(descriptor.value, `${label}.${field}`, seen);
    }
    return value;
  }

  function snapshot(value, label) {
    assertDataTree(value, label);
    return jsonParse(jsonStringify(value));
  }

  function deepFreeze(value) {
    if (!value || typeof value !== "object" || Object.isFrozen(value)) return value;
    for (const field of objectGetOwnPropertyNames(value)) deepFreeze(value[field]);
    return objectFreeze(value);
  }

  function assertClosedInput(input) {
    if (!input || typeof input !== "object" || Array.isArray(input) || isProxy(input)) {
      throw new Error("plane_physical_release_readiness input must be a non-Proxy object");
    }
    if (objectGetPrototypeOf(input) !== objectPrototype
        && objectGetPrototypeOf(input) !== null) {
      throw new Error("plane_physical_release_readiness input must be a plain data object");
    }
    if (objectGetOwnPropertySymbols(input).length !== 0) {
      throw new Error("plane_physical_release_readiness input cannot contain symbol fields");
    }
    const allowed = new Set([
      "nodes_document",
      "hyperedges_document",
      "release_context",
      "evidence_bindings",
      "qualification_evidence",
    ]);
    for (const field of objectGetOwnPropertyNames(input)) {
      const descriptor = objectGetOwnPropertyDescriptor(input, field);
      if (!descriptor || descriptor.get || descriptor.set || !descriptor.enumerable
          || !objectHasOwn(descriptor, "value")) {
        throw new Error(`plane_physical_release_readiness.${field} must be an enumerable data property`);
      }
      if (!allowed.has(field)) throw new Error(`plane_physical_release_readiness unknown field: ${field}`);
    }
    for (const field of ["nodes_document", "hyperedges_document"]) {
      if (!objectHasOwn(input, field)) throw new Error(`plane_physical_release_readiness missing ${field}`);
    }
    return input;
  }

  function addBlocker(blockers, code, dimensions = {}) {
    blockers.push({ code, ...dimensions });
  }

  function sortedStrings(values) {
    // A malformed non-string ref is already recorded as evidence_ref_invalid;
    // ordering it for the deterministic projection must never throw. String() is
    // not total (an object with null toString/valueOf throws), so non-strings
    // sort as a fixed empty key rather than being coerced.
    const key = (value) => (typeof value === "string" ? value : "");
    return [...values].sort((left, right) => key(left).localeCompare(key(right)));
  }

  function sameStrings(left, right) {
    if (left.length !== right.length) return false;
    for (let index = 0; index < left.length; index += 1) {
      if (left[index] !== right[index]) return false;
    }
    return true;
  }

  function validEvidenceRef(value) {
    return typeof value === "string" && EVIDENCE_REF_PATTERN.test(value);
  }

  function validDigest(value) {
    return typeof value === "string" && DIGEST_PATTERN.test(value);
  }

  function buildNodeMap(nodes, blockers) {
    const result = new Map();
    for (let index = 0; index < nodes.length; index += 1) {
      const node = nodes[index];
      if (!node || typeof node.id !== "string" || result.has(node.id)) {
        addBlocker(blockers, "node_registry_invalid", { node_index: index });
        continue;
      }
      result.set(node.id, node);
    }
    return result;
  }

  function buildBlockingProjection(hyperedges, nodeById, blockers) {
    const projection = new Map([...nodeById.keys()].map((nodeId) => [nodeId, new Set()]));
    const incomingCounts = new Map([...nodeById.keys()].map((nodeId) => [nodeId, 0]));
    for (const edge of hyperedges) {
      if (!edge || edge.kind !== "blocking" || !Array.isArray(edge.predecessors)
          || !Array.isArray(edge.unlocks)) continue;
      for (const unlocked of edge.unlocks) {
        if (!projection.has(unlocked)) {
          addBlocker(blockers, "hyperedge_unknown_unlock", { hyperedge_id: edge.id });
          continue;
        }
        incomingCounts.set(unlocked, incomingCounts.get(unlocked) + 1);
        for (const predecessor of edge.predecessors) {
          if (!nodeById.has(predecessor)) {
            addBlocker(blockers, "hyperedge_unknown_predecessor", { hyperedge_id: edge.id });
          } else {
            projection.get(unlocked).add(predecessor);
          }
        }
      }
    }
    for (const [nodeId, node] of nodeById) {
      const declared = sortedStrings(Array.isArray(node.predecessors) ? node.predecessors : []);
      const projected = sortedStrings(projection.get(nodeId) || []);
      if (!sameStrings(declared, projected)) {
        addBlocker(blockers, "predecessor_projection_mismatch", { node_id: nodeId });
      }
      const expectedClauses = declared.length === 0 ? 0 : 1;
      if (incomingCounts.get(nodeId) !== expectedClauses) {
        addBlocker(blockers, "blocking_clause_count_mismatch", { node_id: nodeId });
      }
    }
    return projection;
  }

  function transitivePredecessors(releaseNodeId, projection) {
    const result = new Set();
    const visit = (nodeId) => {
      for (const predecessor of projection.get(nodeId) || []) {
        if (result.has(predecessor)) continue;
        result.add(predecessor);
        visit(predecessor);
      }
    };
    visit(releaseNodeId);
    return result;
  }

  function addEvidenceUse(refUses, blockers, evidenceRef, use) {
    if (!validEvidenceRef(evidenceRef)) {
      addBlocker(blockers, "evidence_ref_invalid", use);
      return;
    }
    if (!refUses.has(evidenceRef)) refUses.set(evidenceRef, []);
    refUses.get(evidenceRef).push(use);
  }

  function gateUses(nodes, releaseClosure, nonwaivable, blockers) {
    const refUses = new Map();
    const tracking = nodes.gate_tracking && typeof nodes.gate_tracking === "object"
      ? nodes.gate_tracking
      : {};
    const applicableIds = sortedStrings(new Set([...releaseClosure, PLANE_PHYSICAL_RELEASE_NODE_ID]));
    for (const nodeId of applicableIds) {
      const node = nodes.nodes.find((candidate) => candidate.id === nodeId);
      const gate = tracking[nodeId];
      if (!node || !gate || typeof gate !== "object") {
        addBlocker(blockers, "gate_tracking_missing", { node_id: nodeId });
        continue;
      }
      const engineeringRefs = Array.isArray(gate.engineering_evidence_refs)
        ? gate.engineering_evidence_refs : [];
      if (gate.engineering_state !== "passed") {
        addBlocker(blockers, "engineering_gate_not_passed", { node_id: nodeId });
      }
      if (engineeringRefs.length === 0) {
        addBlocker(blockers, "engineering_evidence_missing", { node_id: nodeId });
      }
      for (const ref of engineeringRefs) {
        addEvidenceUse(refUses, blockers, ref, { node_id: nodeId, gate_kind: "engineering" });
      }

      const reviewRefs = Array.isArray(node.review_evidence) ? node.review_evidence : [];
      if (reviewRefs.length === 0) addBlocker(blockers, "review_evidence_missing", { node_id: nodeId });
      for (const ref of reviewRefs) {
        addEvidenceUse(refUses, blockers, ref, { node_id: nodeId, gate_kind: "review" });
      }

      const hilRefs = Array.isArray(gate.hil_evidence_refs) ? gate.hil_evidence_refs : [];
      if (node.hil_gate === null) {
        if (gate.hil_state !== "not_required" || hilRefs.length !== 0 || gate.hil_waiver_ref !== null) {
          addBlocker(blockers, "unexpected_hil_evidence", { node_id: nodeId });
        }
        continue;
      }
      if (nonwaivable.has(nodeId)) {
        if (gate.hil_state === "waived" || gate.hil_waiver_ref !== null) {
          addBlocker(blockers, "production_nonwaivable_hil_waived", { node_id: nodeId });
        }
        if (gate.hil_state !== "passed") {
          addBlocker(blockers, "hil_gate_not_passed", { node_id: nodeId });
        }
        if (hilRefs.length === 0) {
          addBlocker(blockers, "hil_evidence_missing", { node_id: nodeId });
        }
      } else if (gate.hil_state !== "passed" && gate.hil_state !== "waived") {
        addBlocker(blockers, "hil_gate_not_closed", { node_id: nodeId });
      }
      if (gate.hil_state === "waived"
          && (typeof gate.hil_waiver_ref !== "string"
            || !WAIVER_REF_PATTERN.test(gate.hil_waiver_ref))) {
        addBlocker(blockers, "hil_waiver_ref_invalid", { node_id: nodeId });
      }
      for (const ref of hilRefs) {
        addEvidenceUse(refUses, blockers, ref, { node_id: nodeId, gate_kind: "hil" });
      }
    }
    return refUses;
  }

  function normalizeEntryArray(value, label) {
    if (value == null) return [];
    const result = snapshot(value, label);
    if (!Array.isArray(result)) throw new Error(`${label} must be an array`);
    return result;
  }

  function bindingMap(entries, blockers) {
    const result = new Map();
    for (let index = 0; index < entries.length; index += 1) {
      const entry = entries[index];
      if (!entry || typeof entry !== "object"
          || !sameStrings(sortedStrings(Object.keys(entry)), ["evidence_ref", "expected_bindings"])
          || !validEvidenceRef(entry.evidence_ref)
          || !entry.expected_bindings || typeof entry.expected_bindings !== "object") {
        addBlocker(blockers, "evidence_binding_invalid", { binding_index: index });
        continue;
      }
      if (result.has(entry.evidence_ref)) {
        addBlocker(blockers, "evidence_binding_duplicate", { binding_index: index });
        continue;
      }
      result.set(entry.evidence_ref, entry.expected_bindings);
    }
    return result;
  }

  function qualificationMap(entries, blockers) {
    const known = new Set(QUALIFICATION_CHECK_REGISTRY.map((check) => check.check_id));
    const result = new Map();
    const refs = new Set();
    for (let index = 0; index < entries.length; index += 1) {
      const entry = entries[index];
      if (!entry || !sameStrings(sortedStrings(Object.keys(entry)), ["check_id", "evidence_ref"])
          || typeof entry.check_id !== "string" || !validEvidenceRef(entry.evidence_ref)) {
        addBlocker(blockers, "qualification_evidence_invalid", { qualification_index: index });
        continue;
      }
      if (!known.has(entry.check_id)) {
        addBlocker(blockers, "qualification_check_unknown", { check_id: entry.check_id });
        continue;
      }
      if (result.has(entry.check_id)) {
        addBlocker(blockers, "qualification_check_duplicate", { check_id: entry.check_id });
        continue;
      }
      if (refs.has(entry.evidence_ref)) {
        addBlocker(blockers, "qualification_evidence_reused", { check_id: entry.check_id });
      }
      refs.add(entry.evidence_ref);
      result.set(entry.check_id, entry.evidence_ref);
    }
    return result;
  }

  function evaluatePlanePhysicalReleaseReadiness(inputValue) {
    const input = assertClosedInput(inputValue);
    const nodes = snapshot(input.nodes_document, "plane_physical_release_readiness.nodes_document");
    const hyperedges = snapshot(
      input.hyperedges_document,
      "plane_physical_release_readiness.hyperedges_document",
    );
    const context = input.release_context == null
      ? { session_nucleus_hash: null, source_tree_digest: null }
      : snapshot(input.release_context, "plane_physical_release_readiness.release_context");
    const contextFields = sortedStrings(Object.keys(context));
    if (!sameStrings(contextFields, ["session_nucleus_hash", "source_tree_digest"])) {
      throw new Error(
        "plane_physical_release_readiness.release_context must contain exactly session_nucleus_hash and source_tree_digest",
      );
    }
    if (!objectHasOwn(context, "session_nucleus_hash")) context.session_nucleus_hash = null;
    if (!objectHasOwn(context, "source_tree_digest")) context.source_tree_digest = null;
    const qualificationEntries = normalizeEntryArray(
      input.qualification_evidence,
      "plane_physical_release_readiness.qualification_evidence",
    );
    const blockers = [];
    const bindingEntries = normalizeEntryArray(
      input.evidence_bindings,
      "plane_physical_release_readiness.evidence_bindings",
    );
    const expectedBindings = bindingMap(bindingEntries, blockers);
    const qualifications = qualificationMap(qualificationEntries, blockers);

    if (nodes.schema_version !== 1 || nodes.graph_id !== PLANE_PHYSICAL_GRAPH_ID
        || hyperedges.schema_version !== 1 || hyperedges.graph_id !== PLANE_PHYSICAL_GRAPH_ID
        || nodes.graph_id !== hyperedges.graph_id || nodes.version !== hyperedges.version) {
      addBlocker(blockers, "graph_identity_or_version_mismatch");
    }
    const nodeRegistryDigest = planePhysicalNodeContractRegistryDigest(nodes);
    const hyperedgeRegistryDigest = planePhysicalHyperedgeRegistryDigest(hyperedges);
    if (nodes.node_contract_registry_sha256 !== nodeRegistryDigest) {
      addBlocker(blockers, "node_contract_registry_digest_mismatch");
    }
    if (nodeRegistryDigest !== PLANE_PHYSICAL_REVIEWED_NODE_CONTRACT_REGISTRY_SHA256) {
      addBlocker(blockers, "reviewed_node_contract_registry_drift");
    }
    if (hyperedges.hyperedge_registry_sha256 !== hyperedgeRegistryDigest) {
      addBlocker(blockers, "hyperedge_registry_digest_mismatch");
    }
    if (hyperedgeRegistryDigest !== PLANE_PHYSICAL_REVIEWED_HYPEREDGE_REGISTRY_SHA256) {
      addBlocker(blockers, "reviewed_hyperedge_registry_drift");
    }

    const declaredNonwaivable = sortedStrings(nodes.production_nonwaivable_hil_node_ids || []);
    const reviewedNonwaivable = sortedStrings(PLANE_PHYSICAL_PRODUCTION_NONWAIVABLE_HIL_NODE_IDS);
    if (!sameStrings(declaredNonwaivable, reviewedNonwaivable)) {
      addBlocker(blockers, "production_nonwaivable_hil_registry_drift");
    }
    const nonwaivable = new Set(reviewedNonwaivable);
    const nodeById = buildNodeMap(Array.isArray(nodes.nodes) ? nodes.nodes : [], blockers);
    const projection = buildBlockingProjection(
      Array.isArray(hyperedges.hyperedges) ? hyperedges.hyperedges : [],
      nodeById,
      blockers,
    );
    const releaseNode = nodeById.get(PLANE_PHYSICAL_RELEASE_NODE_ID);
    if (!releaseNode) addBlocker(blockers, "release_node_missing");
    const closure = transitivePredecessors(PLANE_PHYSICAL_RELEASE_NODE_ID, projection);
    if (closure.size !== nodeById.size - 1) {
      addBlocker(blockers, "release_predecessor_closure_incomplete");
    }
    const directPredecessors = projection.get(PLANE_PHYSICAL_RELEASE_NODE_ID) || new Set();
    for (const nodeId of sortedStrings(closure)) {
      if (nodeById.get(nodeId)?.status !== "done") {
        addBlocker(blockers, directPredecessors.has(nodeId)
          ? "release_predecessor_not_done" : "transitive_predecessor_not_done", { node_id: nodeId });
      }
    }
    for (const nodeId of nonwaivable) {
      if (!nodeById.has(nodeId) || nodeById.get(nodeId).hil_gate === null) {
        addBlocker(blockers, "production_nonwaivable_hil_node_invalid", { node_id: nodeId });
      }
    }

    if (!validDigest(context.session_nucleus_hash)) {
      context.session_nucleus_hash = null;
      addBlocker(blockers, "release_session_nucleus_binding_missing");
    }
    if (!validDigest(context.source_tree_digest)) {
      context.source_tree_digest = null;
      addBlocker(blockers, "release_source_tree_binding_missing");
    }
    const normalizedContext = {
      session_nucleus_hash: context.session_nucleus_hash,
      source_tree_digest: context.source_tree_digest,
    };

    const refUses = gateUses(nodes, closure, nonwaivable, blockers);

    const releaseEngineeringRefs = new Set(
      nodes.gate_tracking?.[PLANE_PHYSICAL_RELEASE_NODE_ID]?.engineering_evidence_refs || [],
    );
    for (const check of QUALIFICATION_CHECK_REGISTRY) {
      const evidenceRef = qualifications.get(check.check_id);
      if (!evidenceRef) {
        addBlocker(blockers, "qualification_evidence_missing", { check_id: check.check_id });
        continue;
      }
      if (!releaseEngineeringRefs.has(evidenceRef)) {
        addBlocker(blockers, "qualification_evidence_not_release_gate_bound", {
          check_id: check.check_id,
        });
      }
      const binding = expectedBindings.get(evidenceRef);
      if (!binding || binding.test_manifest_digest !== check.test_manifest_digest) {
        addBlocker(blockers, "qualification_manifest_digest_mismatch", {
          check_id: check.check_id,
        });
      }
    }

    addBlocker(blockers, "release_validator_not_production_qualified");
    blockers.sort((left, right) => jsonStringify(left).localeCompare(jsonStringify(right)));
    const blockerCounts = {};
    for (const blocker of blockers) blockerCounts[blocker.code] = (blockerCounts[blocker.code] || 0) + 1;
    const orderedBlockerCounts = {};
    for (const code of sortedStrings(Object.keys(blockerCounts))) orderedBlockerCounts[code] = blockerCounts[code];
    const nonProductionBlockers = blockers.filter((blocker) => !PRODUCTION_ONLY_BLOCKERS.has(blocker.code));
    const evidenceRefSetDigest = digestJson(sortedStrings(refUses.keys()));
    const gateTrackingDigest = digestJson((nodes.nodes || []).map((node) => ({
      id: node.id,
      status: node.status,
      gate_tracking: nodes.gate_tracking?.[node.id] ? {
        engineering_state: nodes.gate_tracking[node.id].engineering_state,
        engineering_evidence_refs: sortedStrings(
          nodes.gate_tracking[node.id].engineering_evidence_refs || [],
        ),
        hil_state: nodes.gate_tracking[node.id].hil_state,
        hil_evidence_refs: sortedStrings(nodes.gate_tracking[node.id].hil_evidence_refs || []),
        hil_waiver_ref: nodes.gate_tracking[node.id].hil_waiver_ref,
      } : null,
      review_evidence: sortedStrings(node.review_evidence || []),
    })).sort((left, right) => left.id.localeCompare(right.id)));
    const qualificationEvidenceDigest = digestJson(QUALIFICATION_CHECK_REGISTRY.map((check) => ({
      check_id: check.check_id,
      evidence_ref_digest: qualifications.has(check.check_id)
        ? digestJson(qualifications.get(check.check_id)) : null,
    })));
    const body = {
      version: STRUCTURAL_VERSION,
      domain: STRUCTURAL_DOMAIN,
      assurance: STRUCTURAL_ASSURANCE,
      registry_source: "repository_documents",
      graph_id: nodes.graph_id,
      graph_version: nodes.version,
      release_node_id: PLANE_PHYSICAL_RELEASE_NODE_ID,
      node_contract_registry_sha256: nodeRegistryDigest,
      hyperedge_registry_sha256: hyperedgeRegistryDigest,
      release_node_contract_sha256: releaseNode
        ? planePhysicalNodeContractDigest(releaseNode) : null,
      qualification_check_registry_sha256: QUALIFICATION_CHECK_REGISTRY_SHA256,
      predecessor_closure_sha256: digestJson(sortedStrings(closure)),
      gate_tracking_sha256: gateTrackingDigest,
      evidence_ref_set_sha256: evidenceRefSetDigest,
      qualification_evidence_sha256: qualificationEvidenceDigest,
      release_context_sha256: context.session_nucleus_hash && context.source_tree_digest
        ? digestJson(normalizedContext) : null,
      node_count: nodeById.size,
      predecessor_count: closure.size,
      production_nonwaivable_hil_count: nonwaivable.size,
      qualification_check_count: QUALIFICATION_CHECK_REGISTRY.length,
      evidence_ref_count: refUses.size,
      blocker_count: blockers.length,
      blocker_counts: orderedBlockerCounts,
      blockers,
      conformance_ready: nonProductionBlockers.length === 0,
      physical_production_ready: false,
      verdict: "blocked",
    };
    return deepFreeze({ ...body, verdict_digest: digestJson(body) });
  }

  function evaluatePackagedPlanePhysicalReleaseReadiness() {
    const snapshotDocument = assertPackagedPlanePhysicalReleaseSnapshot(
      PLANE_PHYSICAL_PACKAGED_RELEASE_SNAPSHOT,
    );
    const blockers = [];
    const nodeById = new Map(snapshotDocument.nodes.map((node) => [node.node_id, node]));
    const releaseNode = nodeById.get(PLANE_PHYSICAL_RELEASE_NODE_ID);
    if (!releaseNode) addBlocker(blockers, "release_node_missing");
    const projection = new Map(snapshotDocument.nodes.map((node) => (
      [node.node_id, new Set(node.predecessors)]
    )));
    const closure = transitivePredecessors(PLANE_PHYSICAL_RELEASE_NODE_ID, projection);
    if (closure.size !== snapshotDocument.nodes.length - 1) {
      addBlocker(blockers, "release_predecessor_closure_incomplete");
    }
    const directPredecessors = projection.get(PLANE_PHYSICAL_RELEASE_NODE_ID) || new Set();
    for (const nodeId of sortedStrings(closure)) {
      if (nodeById.get(nodeId)?.status !== "done") {
        addBlocker(blockers, directPredecessors.has(nodeId)
          ? "release_predecessor_not_done" : "transitive_predecessor_not_done", { node_id: nodeId });
      }
    }
    const nonwaivable = new Set(PLANE_PHYSICAL_PRODUCTION_NONWAIVABLE_HIL_NODE_IDS);
    for (const node of snapshotDocument.nodes) {
      if (node.engineering_state !== "passed") {
        addBlocker(blockers, "engineering_gate_not_passed", { node_id: node.node_id });
      }
      if (node.engineering_evidence_count === 0) {
        addBlocker(blockers, "engineering_evidence_missing", { node_id: node.node_id });
      }
      if (node.review_evidence_count === 0) {
        addBlocker(blockers, "review_evidence_missing", { node_id: node.node_id });
      }
      if (nonwaivable.has(node.node_id)) {
        if (node.hil_waiver_present || node.hil_state === "waived") {
          addBlocker(blockers, "production_nonwaivable_hil_waived", { node_id: node.node_id });
        }
        if (node.hil_state !== "passed") {
          addBlocker(blockers, "hil_gate_not_passed", { node_id: node.node_id });
        }
        if (node.hil_evidence_count === 0) {
          addBlocker(blockers, "hil_evidence_missing", { node_id: node.node_id });
        }
      }
    }
    for (const check of QUALIFICATION_CHECK_REGISTRY) {
      addBlocker(blockers, "qualification_evidence_missing", { check_id: check.check_id });
    }
    addBlocker(blockers, "release_session_nucleus_binding_missing");
    addBlocker(blockers, "release_source_tree_binding_missing");
    addBlocker(blockers, "release_validator_not_production_qualified");
    blockers.sort((left, right) => jsonStringify(left).localeCompare(jsonStringify(right)));
    const counts = {};
    for (const blocker of blockers) counts[blocker.code] = (counts[blocker.code] || 0) + 1;
    const blockerCounts = {};
    for (const code of sortedStrings(Object.keys(counts))) blockerCounts[code] = counts[code];
    const emptyQualificationDigest = digestJson(QUALIFICATION_CHECK_REGISTRY.map((check) => ({
      check_id: check.check_id,
      evidence_ref_digest: null,
    })));
    const body = {
      version: STRUCTURAL_VERSION,
      domain: STRUCTURAL_DOMAIN,
      assurance: STRUCTURAL_ASSURANCE,
      registry_source: "packaged_reviewed_projection",
      graph_id: snapshotDocument.graph_id,
      graph_version: snapshotDocument.graph_version,
      release_node_id: PLANE_PHYSICAL_RELEASE_NODE_ID,
      node_contract_registry_sha256: snapshotDocument.node_contract_registry_sha256,
      hyperedge_registry_sha256: snapshotDocument.hyperedge_registry_sha256,
      release_node_contract_sha256: releaseNode?.node_contract_sha256 || null,
      compiled_release_snapshot_sha256: snapshotDocument.snapshot_sha256,
      qualification_check_registry_sha256: QUALIFICATION_CHECK_REGISTRY_SHA256,
      predecessor_closure_sha256: digestJson(sortedStrings(closure)),
      gate_tracking_sha256: snapshotDocument.snapshot_sha256,
      evidence_ref_set_sha256: digestJson([]),
      qualification_evidence_sha256: emptyQualificationDigest,
      release_context_sha256: null,
      node_count: snapshotDocument.nodes.length,
      predecessor_count: closure.size,
      production_nonwaivable_hil_count: nonwaivable.size,
      qualification_check_count: QUALIFICATION_CHECK_REGISTRY.length,
      evidence_ref_count: 0,
      blocker_count: blockers.length,
      blocker_counts: blockerCounts,
      blockers,
      conformance_ready: false,
      physical_production_ready: false,
      verdict: "blocked",
    };
    return deepFreeze({ ...body, verdict_digest: digestJson(body) });
  }

  return {
    PLANE_PHYSICAL_RELEASE_QUALIFICATION_CHECK_REGISTRY: QUALIFICATION_CHECK_REGISTRY,
    PLANE_PHYSICAL_RELEASE_QUALIFICATION_CHECK_REGISTRY_SHA256: QUALIFICATION_CHECK_REGISTRY_SHA256,
    PLANE_PHYSICAL_RELEASE_READINESS_ASSURANCE: STRUCTURAL_ASSURANCE,
    PLANE_PHYSICAL_RELEASE_READINESS_DOMAIN: STRUCTURAL_DOMAIN,
    PLANE_PHYSICAL_RELEASE_READINESS_VERSION: STRUCTURAL_VERSION,
    evaluatePlanePhysicalReleaseReadiness,
    evaluatePackagedPlanePhysicalReleaseReadiness,
  };
})();

const STRUCTURAL_FILTER_CODES = new Set([
  "evidence_ref_invalid",
  "evidence_binding_invalid",
  "evidence_binding_duplicate",
  "evidence_binding_missing",
  "evidence_binding_mismatch",
  "evidence_resolution_failed",
  "gate_evidence_ref_reused",
  "gate_evidence_not_production_qualified",
  "unreferenced_evidence_binding",
  "qualification_evidence_invalid",
  "qualification_check_unknown",
  "qualification_check_duplicate",
  "qualification_evidence_reused",
  "qualification_evidence_missing",
  "qualification_evidence_not_release_gate_bound",
  "qualification_manifest_digest_mismatch",
  "release_validator_not_production_qualified",
]);

const PRODUCTION_ONLY_CODES = new Set([
  "gate_evidence_not_production_qualified",
  "release_validator_not_production_qualified",
  "authenticated_boot_continuous_trusted_clock_unavailable",
  "independent_mechanism_a_monotonic_store_custody_unavailable",
  "independent_signer_custody_unavailable",
  "independent_release_action_custody_unavailable",
]);

function canonicalJson(value) {
  if (value === null || typeof value === "string" || typeof value === "boolean") {
    return JSON.stringify(value);
  }
  if (typeof value === "number" && Number.isFinite(value)) return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (!value || typeof value !== "object" || utilTypes.isProxy(value)
      || (Object.getPrototypeOf(value) !== Object.prototype
        && Object.getPrototypeOf(value) !== null)) {
    throw new Error("release readiness canonical input must be plain JSON data");
  }
  return `{${Object.keys(value).sort().map(
    (field) => `${JSON.stringify(field)}:${canonicalJson(value[field])}`,
  ).join(",")}}`;
}

function digestJson(value) {
  return crypto.createHash("sha256").update(canonicalJson(value)).digest("hex");
}

function deepFreeze(value) {
  if (!value || typeof value !== "object" || Object.isFrozen(value)) return value;
  for (const child of Object.values(value)) deepFreeze(child);
  return Object.freeze(value);
}

function exactObject(value, label, fields) {
  if (!value || typeof value !== "object" || Array.isArray(value) || utilTypes.isProxy(value)
      || (Object.getPrototypeOf(value) !== Object.prototype
        && Object.getPrototypeOf(value) !== null)) {
    throw new Error(`${label} must be an exact plain data object`);
  }
  const expected = [...fields].sort();
  const actual = Reflect.ownKeys(value);
  if (actual.some((field) => typeof field !== "string")
      || actual.length !== expected.length
      || actual.sort().some((field, index) => field !== expected[index])) {
    throw new Error(`${label} fields are not exact`);
  }
  const descriptors = Object.getOwnPropertyDescriptors(value);
  for (const field of fields) {
    const descriptor = descriptors[field];
    if (!descriptor || !descriptor.enumerable || !Object.hasOwn(descriptor, "value")) {
      throw new Error(`${label}.${field} must be an enumerable data property`);
    }
  }
  return value;
}

function dataSnapshot(value, label, seen = new WeakSet()) {
  if (value === null || typeof value === "string" || typeof value === "boolean") return value;
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (!value || typeof value !== "object" || utilTypes.isProxy(value) || seen.has(value)) {
    throw new Error(`${label} must contain only acyclic non-Proxy JSON data`);
  }
  seen.add(value);
  if (Object.getOwnPropertySymbols(value).length !== 0) {
    throw new Error(`${label} cannot contain symbol fields`);
  }
  if (Array.isArray(value)) {
    const names = Object.getOwnPropertyNames(value);
    if (names.length !== value.length + 1 || names.at(-1) !== "length") {
      throw new Error(`${label} must be a dense data-only array with no extra fields`);
    }
    const result = [];
    for (let index = 0; index < value.length; index += 1) {
      const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
      if (!descriptor || !descriptor.enumerable || !Object.hasOwn(descriptor, "value")) {
        throw new Error(`${label} must be a dense data-only array`);
      }
      result.push(dataSnapshot(descriptor.value, `${label}[${index}]`, seen));
    }
    return result;
  }
  if (Object.getPrototypeOf(value) !== Object.prototype
      && Object.getPrototypeOf(value) !== null) {
    throw new Error(`${label} must contain only plain objects`);
  }
  const result = {};
  for (const field of Object.getOwnPropertyNames(value)) {
    const descriptor = Object.getOwnPropertyDescriptor(value, field);
    if (!descriptor || !descriptor.enumerable || !Object.hasOwn(descriptor, "value")) {
      throw new Error(`${label}.${field} must be an enumerable data property`);
    }
    result[field] = dataSnapshot(descriptor.value, `${label}.${field}`, seen);
  }
  return result;
}

function validDigest(value, label) {
  if (typeof value !== "string" || !DIGEST_RE.test(value)) {
    throw new Error(`${label} must be a lowercase SHA-256 digest`);
  }
  return value;
}

const QUALIFICATION_CHECK_REGISTRY = deepFreeze(
  PLANE_PHYSICAL_RELEASE_QUALIFICATION_CHECK_REGISTRY.map((check) => {
    const basis = {
      check_id: check.check_id,
      category: check.category,
      assertion: check.assertion,
    };
    return {
      ...basis,
      test_manifest_digest: digestJson({
        domain: "hacker-bob/plane-physical-release-qualification",
        version: VERSION,
        ...basis,
      }),
    };
  }),
);
const QUALIFICATION_CHECK_REGISTRY_SHA256 = digestJson(QUALIFICATION_CHECK_REGISTRY);

function gateRequirement(node, gateKind) {
  if (gateKind === "engineering") return node.engineering_gate;
  if (gateKind === "hil") return node.hil_gate;
  return REVIEW_REQUIREMENT;
}

function planePhysicalGateContractDigest(nodeInput, gateKindInput) {
  const node = dataSnapshot(nodeInput, "plane physical gate node");
  const gateKind = GATE_KINDS.includes(gateKindInput) ? gateKindInput : null;
  if (!gateKind || typeof node.id !== "string") {
    throw new Error("plane physical gate contract requires a known node and gate kind");
  }
  const requirement = gateRequirement(node, gateKind);
  if (typeof requirement !== "string" || requirement.length === 0) {
    throw new Error(`plane physical ${gateKind} gate has no immutable requirement`);
  }
  return digestJson({
    domain: "hacker-bob/plane-physical-gate-contract",
    version: VERSION,
    graph_id: PLANE_PHYSICAL_GRAPH_ID,
    node_id: node.id,
    node_contract_digest: planePhysicalNodeContractDigest(node),
    gate_kind: gateKind,
    requirement,
  });
}

function planePhysicalGateAcceptanceDigest(input) {
  exactObject(input, "plane physical gate acceptance", [
    "graph_id",
    "node_id",
    "gate_kind",
    "evidence_class",
    "release_candidate_digest",
    "node_contract_digest",
    "gate_contract_digest",
    "qualification_check_id",
    "qualification_manifest_digest",
  ]);
  if (!GATE_KINDS.includes(input.gate_kind)
      || !EVIDENCE_CLASSES.includes(input.evidence_class)
      || (input.evidence_class === "qualification") !== (input.qualification_check_id != null)
      || (input.evidence_class === "qualification")
        !== (input.qualification_manifest_digest != null)) {
    throw new Error("plane physical gate acceptance class/qualification binding is invalid");
  }
  return digestJson({
    domain: "hacker-bob/plane-physical-gate-acceptance",
    version: VERSION,
    graph_id: input.graph_id,
    node_id: input.node_id,
    gate_kind: input.gate_kind,
    evidence_class: input.evidence_class,
    release_candidate_digest: validDigest(
      input.release_candidate_digest,
      "acceptance.release_candidate_digest",
    ),
    node_contract_digest: validDigest(input.node_contract_digest, "acceptance.node_contract_digest"),
    gate_contract_digest: validDigest(input.gate_contract_digest, "acceptance.gate_contract_digest"),
    qualification_check_id: input.qualification_check_id,
    qualification_manifest_digest: input.qualification_manifest_digest == null
      ? null
      : validDigest(
        input.qualification_manifest_digest,
        "acceptance.qualification_manifest_digest",
      ),
    required_verdict: "passed",
  });
}

function addBlocker(blockers, code, dimensions = {}) {
  blockers.push({ code, ...dimensions });
}

function releaseClosure(nodes, hyperedges) {
  const predecessors = new Map(nodes.map((node) => [node.id, new Set()]));
  for (const edge of hyperedges) {
    if (edge?.kind !== "blocking" || !Array.isArray(edge.predecessors)
        || !Array.isArray(edge.unlocks)) continue;
    for (const unlocked of edge.unlocks) {
      if (!predecessors.has(unlocked)) continue;
      for (const predecessor of edge.predecessors) predecessors.get(unlocked).add(predecessor);
    }
  }
  const result = new Set();
  const visit = (nodeId) => {
    for (const predecessor of predecessors.get(nodeId) || []) {
      if (result.has(predecessor)) continue;
      result.add(predecessor);
      visit(predecessor);
    }
  };
  visit(PLANE_PHYSICAL_RELEASE_NODE_ID);
  return result;
}

function normalizeBindings(entries, blockers) {
  const result = new Map();
  if (!Array.isArray(entries)) throw new Error("evidence_bindings must be an array");
  entries.forEach((entry, index) => {
    try {
      exactObject(entry, `evidence_bindings[${index}]`, ["evidence_ref", "expected_bindings"]);
      if (typeof entry.evidence_ref !== "string" || result.has(entry.evidence_ref)) {
        throw new Error("duplicate or invalid evidence reference");
      }
      result.set(entry.evidence_ref, dataSnapshot(
        entry.expected_bindings,
        `evidence_bindings[${index}].expected_bindings`,
      ));
    } catch {
      addBlocker(blockers, "evidence_binding_invalid", { binding_index: index });
    }
  });
  return result;
}

function normalizeQualifications(entries, blockers) {
  const known = new Map(QUALIFICATION_CHECK_REGISTRY.map((check) => [check.check_id, check]));
  const byCheck = new Map();
  const byRef = new Map();
  if (!Array.isArray(entries)) throw new Error("qualification_evidence must be an array");
  entries.forEach((entry, index) => {
    try {
      exactObject(entry, `qualification_evidence[${index}]`, ["check_id", "evidence_ref"]);
      if (!known.has(entry.check_id)) {
        addBlocker(blockers, "qualification_check_unknown", { check_id: entry.check_id });
      } else if (byCheck.has(entry.check_id)) {
        addBlocker(blockers, "qualification_check_duplicate", { check_id: entry.check_id });
      } else if (byRef.has(entry.evidence_ref)) {
        addBlocker(blockers, "qualification_evidence_reused", { check_id: entry.check_id });
      } else {
        byCheck.set(entry.check_id, entry.evidence_ref);
        byRef.set(entry.evidence_ref, known.get(entry.check_id));
      }
    } catch {
      addBlocker(blockers, "qualification_evidence_invalid", { qualification_index: index });
    }
  });
  return { byCheck, byRef };
}

function collectEvidenceUses(nodesDocument, closure, qualifications, blockers) {
  const nodes = new Map(nodesDocument.nodes.map((node) => [node.id, node]));
  const applicable = [...closure, PLANE_PHYSICAL_RELEASE_NODE_ID].sort();
  const uses = new Map();
  const add = (ref, use) => {
    if (typeof ref !== "string") {
      addBlocker(blockers, "evidence_ref_invalid", use);
      return;
    }
    if (!uses.has(ref)) uses.set(ref, []);
    uses.get(ref).push(use);
  };
  for (const nodeId of applicable) {
    const node = nodes.get(nodeId);
    const tracking = nodesDocument.gate_tracking?.[nodeId];
    if (!node || !tracking) continue;
    for (const ref of tracking.engineering_evidence_refs || []) {
      const check = qualifications.byRef.get(ref) || null;
      add(ref, {
        node_id: nodeId,
        gate_kind: "engineering",
        evidence_class: check ? "qualification" : "engineering",
        qualification_check_id: check?.check_id || null,
      });
    }
    for (const ref of node.review_evidence || []) add(ref, {
      node_id: nodeId,
      gate_kind: "review",
      evidence_class: "review",
      qualification_check_id: null,
    });
    for (const ref of tracking.hil_evidence_refs || []) add(ref, {
      node_id: nodeId,
      gate_kind: "hil",
      evidence_class: "hil",
      qualification_check_id: null,
    });
  }
  return uses;
}

function coreBindingMatches(binding, use, context, node, qualification) {
  const nodeDigest = planePhysicalNodeContractDigest(node);
  const gateDigest = planePhysicalGateContractDigest(node, use.gate_kind);
  const acceptanceDigest = planePhysicalGateAcceptanceDigest({
    graph_id: PLANE_PHYSICAL_GRAPH_ID,
    node_id: use.node_id,
    gate_kind: use.gate_kind,
    evidence_class: use.evidence_class,
    release_candidate_digest: context.release_candidate_digest,
    node_contract_digest: nodeDigest,
    gate_contract_digest: gateDigest,
    qualification_check_id: qualification?.check_id || null,
    qualification_manifest_digest: qualification?.test_manifest_digest || null,
  });
  return binding.graph_id === PLANE_PHYSICAL_GRAPH_ID
    && binding.node_id === use.node_id
    && binding.gate_kind === use.gate_kind
    && binding.evidence_class === use.evidence_class
    && binding.session_nucleus_hash === context.session_nucleus_hash
    && binding.source_tree_digest === context.source_tree_digest
    && binding.release_candidate_digest === context.release_candidate_digest
    && binding.package_digest === context.package_digest
    && binding.task_graph_digest === context.task_graph_digest
    && binding.release_snapshot_digest === context.release_snapshot_digest
    && binding.node_contract_digest === nodeDigest
    && binding.gate_contract_digest === gateDigest
    && binding.acceptance_digest === acceptanceDigest
    && validDigest(binding.result_digest, "evidence result_digest")
    && binding.verdict === "passed";
}

function dedupeBlockers(blockers) {
  const byDigest = new Map();
  for (const blocker of blockers) byDigest.set(digestJson(blocker), blocker);
  return [...byDigest.values()].sort(
    (left, right) => canonicalJson(left).localeCompare(canonicalJson(right)),
  );
}

function summarizeBlockers(blockers) {
  const finalBlockers = dedupeBlockers(blockers);
  const counts = {};
  for (const blocker of finalBlockers) {
    counts[blocker.code] = (counts[blocker.code] || 0) + 1;
  }
  const blockerCounts = Object.fromEntries(
    Object.entries(counts).sort(([left], [right]) => left.localeCompare(right)),
  );
  const conformanceBlockers = finalBlockers.filter(
    (blocker) => !PRODUCTION_ONLY_CODES.has(blocker.code),
  );
  return {
    blockers: finalBlockers,
    blockerCounts,
    conformanceReady: conformanceBlockers.length === 0,
  };
}

function conformanceSnapshotBasis(readiness) {
  return {
    version: VERSION,
    domain: `${DOMAIN}/conformance-snapshot-basis`,
    registry_source: readiness.registry_source,
    graph_id: readiness.graph_id,
    graph_version: readiness.graph_version,
    release_node_id: readiness.release_node_id,
    node_contract_registry_sha256: readiness.node_contract_registry_sha256,
    task_graph_digest: readiness.task_graph_digest,
    release_snapshot_digest: readiness.release_snapshot_digest,
    release_candidate_digest: readiness.release_candidate_digest,
    package_digest: readiness.package_digest,
    session_nucleus_hash: readiness.session_nucleus_hash,
    source_tree_digest: readiness.source_tree_digest,
    qualification_check_registry_sha256:
      readiness.qualification_check_registry_sha256,
    evidence_ref_set_sha256: readiness.evidence_ref_set_sha256,
    evidence_batch_request_set_sha256:
      readiness.evidence_batch_request_set_sha256,
    evidence_batch_verified_set_sha256:
      readiness.evidence_batch_verified_set_sha256,
    evidence_batch_entry_count: readiness.evidence_batch_entry_count,
    evidence_ref_count: readiness.evidence_ref_count,
    resolved_evidence_class_count: readiness.resolved_evidence_class_count,
    blocker_count: readiness.blocker_count,
    blocker_counts: readiness.blocker_counts,
    blockers: readiness.blockers,
    conformance_ready: readiness.conformance_ready,
    physical_production_ready: false,
    verdict: "blocked",
  };
}

function privateConformanceSnapshotRef(identity, snapshotBasisDigest, blockerSetDigest, receipt) {
  if (receipt == null) return null;
  return `gate-conformance-snapshot:${digestJson({
    release_candidate_digest: identity.release_candidate_digest,
    snapshot_basis_digest: snapshotBasisDigest,
    blocker_set_digest: blockerSetDigest,
    receipt_digest: receipt.receipt_digest,
  })}`;
}

function readinessVerdictBody(identity, outcome, snapshotBasisDigest, releaseReceipt = null) {
  const atomicBatch = releaseReceipt;
  const blockerSetDigest = digestJson(outcome.blockers);
  const committed = releaseReceipt != null;
  return {
    ...identity,
    evidence_batch_projection_sha256: atomicBatch?.batch_projection_digest || null,
    evidence_batch_request_set_sha256: atomicBatch?.request_entry_set_digest || null,
    evidence_batch_verified_set_sha256: atomicBatch?.verified_entry_set_digest || null,
    evidence_batch_collection_snapshot_sha256:
      atomicBatch?.collection_snapshot_digest || null,
    evidence_batch_revocation_set_sha256: atomicBatch?.revocation_set_digest || null,
    evidence_batch_owner_ledger_sha256: atomicBatch?.owner_ledger_digest || null,
    evidence_batch_common_verified_at: atomicBatch?.common_verified_at || null,
    evidence_batch_common_trusted_utc_earliest:
      atomicBatch?.common_trusted_utc_earliest || null,
    evidence_batch_common_trusted_utc_latest:
      atomicBatch?.common_trusted_utc_latest || null,
    evidence_batch_common_trusted_time_sha256:
      atomicBatch?.common_trusted_time_digest || null,
    evidence_batch_entry_count: atomicBatch?.entry_count || 0,
    conformance_snapshot_ref: privateConformanceSnapshotRef(
      identity,
      snapshotBasisDigest,
      blockerSetDigest,
      releaseReceipt,
    ),
    release_snapshot_receipt_ref: releaseReceipt?.receipt_ref || null,
    release_snapshot_receipt_sha256: releaseReceipt?.receipt_digest || null,
    release_snapshot_receipt_projection_sha256:
      releaseReceipt?.receipt_projection_digest || null,
    release_snapshot_receipt_sequence: releaseReceipt?.receipt_sequence || null,
    release_snapshot_receipt_previous_sha256:
      releaseReceipt?.previous_receipt_digest || null,
    conformance_snapshot_basis_sha256: snapshotBasisDigest,
    conformance_snapshot_blocker_set_sha256: blockerSetDigest,
    release_snapshot_receipt_issued_at: releaseReceipt?.issued_at || null,
    release_snapshot_receipt_not_before: releaseReceipt?.not_before || null,
    release_snapshot_receipt_expires_at: releaseReceipt?.expires_at || null,
    authorization_semantics: committed
      ? "committed_conformance_snapshot_requires_currentness_assertion"
      : "uncommitted_conformance_evaluation",
    currentness_assertion_required: committed,
    authoritative_release_action: false,
    blocker_count: outcome.blockers.length,
    blocker_counts: outcome.blockerCounts,
    blockers: outcome.blockers,
    conformance_ready: outcome.conformanceReady,
    physical_production_ready: false,
    verdict: "blocked",
  };
}

function createReleaseReadinessPlan(runtime, batch, identity, outcome, basisReadiness) {
  const snapshotBasisDigest = digestJson(conformanceSnapshotBasis(basisReadiness));
  const blockerSetDigest = digestJson(outcome.blockers);
  const planBody = {
    version: VERSION,
    kind: "plane_physical_release_readiness_private_plan",
    release_candidate_digest: identity.release_candidate_digest,
    request_entry_set_digest: batch.request_entry_set_digest,
    verified_entry_set_digest: batch.verified_entry_set_digest,
    snapshot_basis_digest: snapshotBasisDigest,
    blocker_set_digest: blockerSetDigest,
  };
  const plan = deepFreeze({ ...planBody, plan_digest: digestJson(planBody) });
  const frozenOutcome = deepFreeze({
    blockers: [...outcome.blockers],
    blockerCounts: { ...outcome.blockerCounts },
    conformanceReady: outcome.conformanceReady,
  });
  const frozenBasisReadiness = deepFreeze({
    ...basisReadiness,
    blockers: frozenOutcome.blockers,
    blocker_counts: frozenOutcome.blockerCounts,
    conformance_ready: frozenOutcome.conformanceReady,
  });
  RELEASE_READINESS_PLANS.add(plan);
  RELEASE_READINESS_PLAN_STATE.set(plan, {
    status: "fresh",
    runtime,
    initialBatch: batch,
    identity: deepFreeze({ ...identity }),
    outcome: frozenOutcome,
    basisReadiness: frozenBasisReadiness,
    snapshotBasisDigest,
    blockerSetDigest,
  });
  return plan;
}

function assertReleaseReadinessPlan(input, label) {
  const state = input == null ? null : RELEASE_READINESS_PLAN_STATE.get(input);
  if (!input || !Object.isFrozen(input) || !RELEASE_READINESS_PLANS.has(input) || !state) {
    throw new Error(`${label} requires a live privately branded readiness plan`);
  }
  const body = { ...input };
  delete body.plan_digest;
  if (input.plan_digest !== digestJson(body)
      || input.snapshot_basis_digest !== state.snapshotBasisDigest
      || input.blocker_set_digest !== state.blockerSetDigest) {
    throw new Error(`${label} private readiness plan integrity drift`);
  }
  return state;
}

function runtimeReceiptMethod(runtime, name, label) {
  if (!runtime || typeof runtime !== "object" || utilTypes.isProxy(runtime)
      || !Object.isFrozen(runtime)) {
    throw new Error(`${label} requires a frozen gate-evidence runtime`);
  }
  const descriptor = Object.getOwnPropertyDescriptor(runtime, name);
  if (!descriptor || descriptor.enumerable || descriptor.configurable
      || descriptor.writable || typeof descriptor.value !== "function") {
    throw new Error(`${label} requires an immutable runtime-owned receipt method`);
  }
  return descriptor.value;
}

const RELEASE_RECEIPT_PROJECTION_FIELDS = Object.freeze([
  "version",
  "domain",
  "receipt_ref",
  "receipt_digest",
  "receipt_sequence",
  "previous_receipt_digest",
  "session_nucleus_hash",
  "release_candidate_digest",
  "request_entry_set_digest",
  "verified_entry_set_digest",
  "batch_projection_digest",
  "entry_count",
  "authority_digest",
  "storage_root_identity_digest",
  "owner_ledger_digest",
  "revocation_set_digest",
  "revocation_head_digest",
  "collection_snapshot_digest",
  "common_verified_at",
  "common_trusted_utc_earliest",
  "common_trusted_utc_latest",
  "common_trusted_time_digest",
  "issued_at",
  "not_before",
  "expires_at",
  "assurance",
  "production_blockers",
  "receipt_projection_digest",
]);

function assertReleaseSnapshotReceipt(input) {
  exactObject(input, "release snapshot receipt projection", RELEASE_RECEIPT_PROJECTION_FIELDS);
  if (!Object.isFrozen(input)
      || input.version !== VERSION
      || input.domain
        !== "hacker-bob/plane-physical-release-snapshot-receipt-projection"
      || !Number.isSafeInteger(input.entry_count) || input.entry_count < 1
      || !/^[1-9][0-9]*$/u.test(input.receipt_sequence)
      || input.receipt_ref !== `gate-release-snapshot-receipt:${input.receipt_digest}`
      || !Array.isArray(input.production_blockers)
      || !Object.isFrozen(input.production_blockers)) {
    throw new Error("release snapshot receipt projection shape drift");
  }
  for (const [field, value] of Object.entries({
    receipt_digest: input.receipt_digest,
    release_candidate_digest: input.release_candidate_digest,
    request_entry_set_digest: input.request_entry_set_digest,
    verified_entry_set_digest: input.verified_entry_set_digest,
    batch_projection_digest: input.batch_projection_digest,
    authority_digest: input.authority_digest,
    storage_root_identity_digest: input.storage_root_identity_digest,
    revocation_set_digest: input.revocation_set_digest,
    collection_snapshot_digest: input.collection_snapshot_digest,
    common_trusted_time_digest: input.common_trusted_time_digest,
    receipt_projection_digest: input.receipt_projection_digest,
  })) validDigest(value, `release snapshot receipt.${field}`);
  for (const [field, value] of Object.entries({
    previous_receipt_digest: input.previous_receipt_digest,
    owner_ledger_digest: input.owner_ledger_digest,
    revocation_head_digest: input.revocation_head_digest,
  })) {
    if (value != null) validDigest(value, `release snapshot receipt.${field}`);
  }
  for (const field of [
    "common_verified_at",
    "common_trusted_utc_earliest",
    "common_trusted_utc_latest",
    "issued_at",
    "not_before",
    "expires_at",
  ]) {
    const parsed = Date.parse(input[field]);
    if (!Number.isFinite(parsed) || new Date(parsed).toISOString() !== input[field]) {
      throw new Error(`release snapshot receipt.${field} must be a canonical timestamp`);
    }
  }
  const body = { ...input };
  delete body.receipt_projection_digest;
  if (digestJson(body) !== input.receipt_projection_digest) {
    throw new Error("release snapshot receipt projection digest drift");
  }
  return input;
}

function finalizeSignedPlanePhysicalReleaseReadinessSnapshot(
  planInput,
  runtime,
  releaseReceiptInput,
) {
  const releaseReceipt = assertReleaseSnapshotReceipt(releaseReceiptInput);
  const state = assertReleaseReadinessPlan(planInput, "release snapshot finalization");
  if (state.status !== "fresh" || state.runtime !== runtime
      || state.initialBatch.release_candidate_digest
        !== releaseReceipt.release_candidate_digest
      || state.initialBatch.request_entry_set_digest
        !== releaseReceipt.request_entry_set_digest
      || state.initialBatch.verified_entry_set_digest
        !== releaseReceipt.verified_entry_set_digest
      || state.initialBatch.entry_count !== releaseReceipt.entry_count
      || state.identity.session_nucleus_hash !== releaseReceipt.session_nucleus_hash
      || digestJson(conformanceSnapshotBasis(state.basisReadiness))
        !== state.snapshotBasisDigest
      || digestJson(state.outcome.blockers) !== state.blockerSetDigest
      || state.basisReadiness.blockers !== state.outcome.blockers
      || state.basisReadiness.blocker_counts !== state.outcome.blockerCounts
      || state.basisReadiness.conformance_ready !== state.outcome.conformanceReady) {
    throw new Error(
      "release snapshot plan is replayed, cross-runtime, or semantically inconsistent",
    );
  }
  const body = readinessVerdictBody(
    state.identity,
    state.outcome,
    state.snapshotBasisDigest,
    releaseReceipt,
  );
  const verdict = deepFreeze({ ...body, verdict_digest: digestJson(body) });
  if (digestJson(conformanceSnapshotBasis(verdict)) !== state.snapshotBasisDigest) {
    throw new Error("private readiness basis changed during snapshot finalization");
  }
  const assertReceiptCurrent = runtimeReceiptMethod(
    runtime,
    RUNTIME_RECEIPT_CURRENT_METHOD,
    "release snapshot finalization",
  );
  RELEASE_VERDICTS.add(verdict);
  RELEASE_VERDICT_STATE.set(verdict, Object.freeze({
    runtime,
    releaseReceipt,
    assertReceiptCurrent,
    snapshotBasisDigest: state.snapshotBasisDigest,
    blockerSetDigest: state.blockerSetDigest,
    verdictDigest: verdict.verdict_digest,
  }));
  state.status = "consumed";
  return verdict;
}

function evaluateSignedPlanePhysicalReleaseReadinessInternal(inputValue) {
  exactObject(inputValue, "plane physical release readiness input", [
    "version",
    "nodes_document",
    "hyperedges_document",
    "release_context",
    "evidence_runtime",
    "evidence_bindings",
    "qualification_evidence",
  ]);
  if (inputValue.version !== VERSION) throw new Error(`release readiness version must be ${VERSION}`);
  const nodes = dataSnapshot(inputValue.nodes_document, "release readiness nodes");
  const hyperedges = dataSnapshot(inputValue.hyperedges_document, "release readiness hyperedges");
  const context = dataSnapshot(inputValue.release_context, "release readiness context");
  exactObject(context, "release readiness context", [
    "session_nucleus_hash",
    "source_tree_digest",
    "package_digest",
    "task_graph_digest",
    "release_snapshot_digest",
    "release_candidate_digest",
  ]);
  for (const field of Object.keys(context)) validDigest(context[field], `release_context.${field}`);
  const expectedCandidate = planePhysicalReleaseCandidateDigest({
    session_nucleus_hash: context.session_nucleus_hash,
    source_tree_digest: context.source_tree_digest,
    package_digest: context.package_digest,
    task_graph_digest: context.task_graph_digest,
    release_snapshot_digest: context.release_snapshot_digest,
  });
  const blockers = [];
  if (context.release_candidate_digest !== expectedCandidate) {
    addBlocker(blockers, "release_candidate_digest_mismatch");
  }
  const taskGraphDigest = planePhysicalHyperedgeRegistryDigest(hyperedges);
  if (context.task_graph_digest !== taskGraphDigest) {
    addBlocker(blockers, "release_task_graph_digest_mismatch");
  }
  const packagedSnapshot = assertPackagedPlanePhysicalReleaseSnapshot(
    PLANE_PHYSICAL_PACKAGED_RELEASE_SNAPSHOT,
  );
  if (context.release_snapshot_digest !== packagedSnapshot.snapshot_sha256) {
    addBlocker(blockers, "release_snapshot_digest_mismatch");
  }

  const structural = evaluatePlanePhysicalReleaseReadiness({
    nodes_document: nodes,
    hyperedges_document: hyperedges,
    release_context: {
      session_nucleus_hash: context.session_nucleus_hash,
      source_tree_digest: context.source_tree_digest,
    },
  });
  blockers.push(...structural.blockers.filter(
    (blocker) => !STRUCTURAL_FILTER_CODES.has(blocker.code),
  ));

  const bindingEntries = dataSnapshot(inputValue.evidence_bindings, "release evidence bindings");
  const qualificationEntries = dataSnapshot(
    inputValue.qualification_evidence,
    "release qualification evidence",
  );
  const bindings = normalizeBindings(bindingEntries, blockers);
  const qualifications = normalizeQualifications(qualificationEntries, blockers);
  for (const check of QUALIFICATION_CHECK_REGISTRY) {
    if (!qualifications.byCheck.has(check.check_id)) {
      addBlocker(blockers, "qualification_evidence_missing", { check_id: check.check_id });
    }
  }
  const closure = releaseClosure(nodes.nodes || [], hyperedges.hyperedges || []);
  const uses = collectEvidenceUses(nodes, closure, qualifications, blockers);
  const releaseEngineeringRefs = new Set(
    nodes.gate_tracking?.[PLANE_PHYSICAL_RELEASE_NODE_ID]?.engineering_evidence_refs || [],
  );
  for (const [checkId, ref] of qualifications.byCheck) {
    if (!releaseEngineeringRefs.has(ref)) {
      addBlocker(blockers, "qualification_evidence_not_release_gate_bound", { check_id: checkId });
    }
  }

  const nodesById = new Map((nodes.nodes || []).map((node) => [node.id, node]));
  const signerClasses = new Map();
  let everyResolvedEvidenceProduction = uses.size > 0;
  const batchRequests = [];
  const batchUses = new Map();
  for (const [ref, refUses] of uses) {
    const use = refUses[0];
    if (refUses.length !== 1) {
      addBlocker(blockers, "gate_evidence_ref_reused", use);
      everyResolvedEvidenceProduction = false;
    }
    if (!EVIDENCE_RE.test(ref)) {
      addBlocker(blockers, "evidence_ref_invalid", use);
      everyResolvedEvidenceProduction = false;
      continue;
    }
    const binding = bindings.get(ref);
    if (!binding) {
      addBlocker(blockers, "evidence_binding_missing", use);
      everyResolvedEvidenceProduction = false;
      continue;
    }
    const node = nodesById.get(use.node_id);
    const qualification = use.qualification_check_id == null
      ? null
      : QUALIFICATION_CHECK_REGISTRY.find(
        (check) => check.check_id === use.qualification_check_id,
      );
    let coreMatches = false;
    try { coreMatches = Boolean(node && coreBindingMatches(binding, use, context, node, qualification)); }
    catch { coreMatches = false; }
    if (!coreMatches) {
      addBlocker(blockers, "evidence_binding_mismatch", use);
      everyResolvedEvidenceProduction = false;
      continue;
    }
    batchRequests.push({ evidence_ref: ref, expected_bindings: binding });
    batchUses.set(ref, use);
  }

  let currentBatch = null;
  if (batchRequests.length === 0) {
    everyResolvedEvidenceProduction = false;
  } else {
    try {
      const resolvedBatch = resolveAndVerifyPlanePhysicalGateEvidenceBatch(
        batchRequests,
        inputValue.evidence_runtime,
      );
      currentBatch = assertConformancePlanePhysicalGateEvidenceBatch(
        resolvedBatch,
        inputValue.evidence_runtime,
        batchRequests,
      );
      for (const entry of currentBatch.entries) {
        const use = batchUses.get(entry.evidence_ref);
        if (!use) throw new Error("release evidence batch returned an unrequested entry");
        if (!signerClasses.has(entry.evidence_class)) {
          signerClasses.set(entry.evidence_class, {
            principals: new Set(),
            keys: new Set(),
          });
        }
        signerClasses.get(entry.evidence_class).principals.add(entry.signer_principal_id);
        signerClasses.get(entry.evidence_class).keys.add(entry.signer_key_id);
      }
      try {
        currentBatch = assertVerifiedPlanePhysicalGateEvidenceBatch(
          currentBatch,
          inputValue.evidence_runtime,
          batchRequests,
        );
      } catch {
        // A production-qualification exception can also mean that the atomic
        // set changed during assertVerified's currentness recheck.  Fence once
        // more before classifying it as a production-only custody failure;
        // staleness/revocation escapes to the outer resolution-failure path.
        currentBatch = assertConformancePlanePhysicalGateEvidenceBatch(
          currentBatch,
          inputValue.evidence_runtime,
          batchRequests,
        );
        everyResolvedEvidenceProduction = false;
        for (const request of batchRequests) {
          const use = batchUses.get(request.evidence_ref);
          addBlocker(blockers, "gate_evidence_not_production_qualified", use);
          for (const blocker of currentBatch.production_blockers) {
            addBlocker(blockers, blocker, use);
          }
        }
      }
    } catch {
      everyResolvedEvidenceProduction = false;
      currentBatch = null;
      for (const request of batchRequests) {
        addBlocker(blockers, "evidence_resolution_failed", batchUses.get(request.evidence_ref));
      }
    }
  }
  for (const ref of bindings.keys()) {
    if (!uses.has(ref)) addBlocker(blockers, "unreferenced_evidence_binding");
  }

  const principalClasses = new Map();
  const keyClasses = new Map();
  for (const [evidenceClass, identities] of signerClasses) {
    for (const principal of identities.principals) {
      if (!principalClasses.has(principal)) principalClasses.set(principal, new Set());
      principalClasses.get(principal).add(evidenceClass);
    }
    for (const key of identities.keys) {
      if (!keyClasses.has(key)) keyClasses.set(key, new Set());
      keyClasses.get(key).add(evidenceClass);
    }
  }
  if ([...principalClasses.values()].some((classes) => classes.size > 1)
      || [...keyClasses.values()].some((classes) => classes.size > 1)) {
    addBlocker(blockers, "evidence_class_issuer_separation_failed");
    everyResolvedEvidenceProduction = false;
  }
  if (!everyResolvedEvidenceProduction) {
    addBlocker(blockers, "release_validator_not_production_qualified");
  }

  let outcome = summarizeBlockers(blockers);
  const identity = {
    version: VERSION,
    domain: DOMAIN,
    assurance: ASSURANCE,
    registry_source: "repository_documents_and_packaged_release_snapshot",
    graph_id: nodes.graph_id,
    graph_version: nodes.version,
    release_node_id: PLANE_PHYSICAL_RELEASE_NODE_ID,
    node_contract_registry_sha256: planePhysicalNodeContractRegistryDigest(nodes),
    task_graph_digest: taskGraphDigest,
    release_snapshot_digest: packagedSnapshot.snapshot_sha256,
    release_candidate_digest: context.release_candidate_digest,
    package_digest: context.package_digest,
    session_nucleus_hash: context.session_nucleus_hash,
    source_tree_digest: context.source_tree_digest,
    qualification_check_registry_sha256: QUALIFICATION_CHECK_REGISTRY_SHA256,
    evidence_ref_set_sha256: digestJson([...uses.keys()].sort()),
    evidence_ref_count: uses.size,
    resolved_evidence_class_count: signerClasses.size,
  };

  const snapshotBasisReadiness = (batch, currentOutcome) => ({
    ...identity,
    evidence_batch_request_set_sha256: batch?.request_entry_set_digest || null,
    evidence_batch_verified_set_sha256: batch?.verified_entry_set_digest || null,
    evidence_batch_entry_count: batch?.entry_count || 0,
    resolved_evidence_class_count: signerClasses.size,
    blocker_count: currentOutcome.blockers.length,
    blocker_counts: currentOutcome.blockerCounts,
    blockers: currentOutcome.blockers,
    conformance_ready: currentOutcome.conformanceReady,
    physical_production_ready: false,
    verdict: "blocked",
  });

  let basisReadiness = snapshotBasisReadiness(currentBatch, outcome);
  let snapshotBasisDigest = digestJson(conformanceSnapshotBasis(basisReadiness));
  if (currentBatch != null && batchRequests.length > 0) {
    const readinessPlan = createReleaseReadinessPlan(
      inputValue.evidence_runtime,
      currentBatch,
      identity,
      outcome,
      basisReadiness,
    );
    try {
      const commitReceipt = runtimeReceiptMethod(
        inputValue.evidence_runtime,
        RUNTIME_RECEIPT_COMMIT_METHOD,
        "release readiness receipt commit",
      );
      const releaseReceipt = Reflect.apply(commitReceipt, undefined, [
        currentBatch,
        batchRequests,
      ]);
      const verdict = finalizeSignedPlanePhysicalReleaseReadinessSnapshot(
        readinessPlan,
        inputValue.evidence_runtime,
        releaseReceipt,
      );
      const verdictState = RELEASE_VERDICT_STATE.get(verdict);
      if (!Object.isFrozen(verdict) || !RELEASE_VERDICTS.has(verdict)
          || !verdictState || verdictState.runtime !== inputValue.evidence_runtime
          || verdictState.releaseReceipt !== releaseReceipt) {
        throw new Error("release readiness commit did not produce a private snapshot");
      }
      return verdict;
    } catch {
      // No public readiness object may retain a pre-commit batch if the final
      // in-lock re-resolution or signed receipt append failed.  Route the
      // entire requested set through the same fail-closed resolution outcome.
      currentBatch = null;
      signerClasses.clear();
      everyResolvedEvidenceProduction = false;
      for (const request of batchRequests) {
        addBlocker(
          blockers,
          "evidence_resolution_failed",
          batchUses.get(request.evidence_ref),
        );
      }
      addBlocker(blockers, "release_validator_not_production_qualified");
      outcome = summarizeBlockers(blockers);
      basisReadiness = snapshotBasisReadiness(null, outcome);
      snapshotBasisDigest = digestJson(conformanceSnapshotBasis(basisReadiness));
    }
  }

  const failureIdentity = {
    ...identity,
    resolved_evidence_class_count: signerClasses.size,
  };
  const body = readinessVerdictBody(
    failureIdentity,
    outcome,
    snapshotBasisDigest,
    null,
  );
  return deepFreeze({ ...body, verdict_digest: digestJson(body) });
}

function evaluateSignedPlanePhysicalReleaseReadiness(inputValue) {
  let runtime = null;
  if (inputValue && typeof inputValue === "object" && !utilTypes.isProxy(inputValue)
      && !Array.isArray(inputValue)) {
    const descriptor = Object.getOwnPropertyDescriptor(inputValue, "evidence_runtime");
    if (descriptor && Object.hasOwn(descriptor, "value")
        && descriptor.value && typeof descriptor.value === "object") {
      runtime = descriptor.value;
    }
  }
  if (runtime && RELEASE_EVALUATIONS_IN_FLIGHT.has(runtime)) {
    throw new Error("release readiness same-runtime evaluation reentrancy rejected");
  }
  if (runtime) RELEASE_EVALUATIONS_IN_FLIGHT.add(runtime);
  try {
    return evaluateSignedPlanePhysicalReleaseReadinessInternal(inputValue);
  } finally {
    if (runtime) RELEASE_EVALUATIONS_IN_FLIGHT.delete(runtime);
  }
}

function assertCurrentSignedPlanePhysicalReleaseReadiness(input, runtimeInput) {
  const state = input == null ? null : RELEASE_VERDICT_STATE.get(input);
  if (!input || !Object.isFrozen(input) || !RELEASE_VERDICTS.has(input) || !state
      || state.runtime !== runtimeInput) {
    throw new Error("release readiness must be a live privately branded committed verdict");
  }
  const body = { ...input };
  delete body.verdict_digest;
  if (input.verdict_digest !== state.verdictDigest
      || digestJson(body) !== state.verdictDigest
      || input.conformance_snapshot_basis_sha256 !== state.snapshotBasisDigest
      || digestJson(conformanceSnapshotBasis(input)) !== state.snapshotBasisDigest
      || input.conformance_snapshot_ref !== privateConformanceSnapshotRef(
        input,
        state.snapshotBasisDigest,
        state.blockerSetDigest,
        state.releaseReceipt,
      )
      || input.release_snapshot_receipt_ref
        !== state.releaseReceipt.receipt_ref
      || input.release_snapshot_receipt_sha256
        !== state.releaseReceipt.receipt_digest
      || input.release_snapshot_receipt_projection_sha256
        !== state.releaseReceipt.receipt_projection_digest
      || input.release_snapshot_receipt_sequence !== state.releaseReceipt.receipt_sequence
      || input.release_snapshot_receipt_previous_sha256
        !== state.releaseReceipt.previous_receipt_digest
      || input.release_snapshot_receipt_issued_at !== state.releaseReceipt.issued_at
      || input.release_snapshot_receipt_not_before !== state.releaseReceipt.not_before
      || input.release_snapshot_receipt_expires_at !== state.releaseReceipt.expires_at
      || input.conformance_snapshot_blocker_set_sha256
        !== state.blockerSetDigest
      || digestJson(input.blockers) !== state.blockerSetDigest
      || input.authorization_semantics
        !== "committed_conformance_snapshot_requires_currentness_assertion"
      || input.currentness_assertion_required !== true
      || input.authoritative_release_action !== false
      || input.physical_production_ready !== false
      || input.verdict !== "blocked") {
    throw new Error("release readiness committed verdict integrity drift");
  }
  const currentMethod = runtimeReceiptMethod(
    runtimeInput,
    RUNTIME_RECEIPT_CURRENT_METHOD,
    "release readiness currentness assertion",
  );
  if (currentMethod !== state.assertReceiptCurrent) {
    throw new Error("release readiness runtime receipt authority changed");
  }
  Reflect.apply(currentMethod, undefined, [
    state.releaseReceipt,
    { release_candidate_digest: input.release_candidate_digest },
  ]);
  return input;
}

module.exports = Object.freeze({
  PLANE_PHYSICAL_RELEASE_QUALIFICATION_CHECK_REGISTRY,
  PLANE_PHYSICAL_RELEASE_QUALIFICATION_CHECK_REGISTRY_SHA256,
  PLANE_PHYSICAL_RELEASE_READINESS_ASSURANCE,
  PLANE_PHYSICAL_RELEASE_READINESS_DOMAIN,
  PLANE_PHYSICAL_RELEASE_READINESS_VERSION,
  PLANE_PHYSICAL_SIGNED_RELEASE_QUALIFICATION_CHECK_REGISTRY: QUALIFICATION_CHECK_REGISTRY,
  PLANE_PHYSICAL_SIGNED_RELEASE_QUALIFICATION_CHECK_REGISTRY_SHA256:
    QUALIFICATION_CHECK_REGISTRY_SHA256,
  PLANE_PHYSICAL_SIGNED_RELEASE_READINESS_ASSURANCE: ASSURANCE,
  PLANE_PHYSICAL_SIGNED_RELEASE_READINESS_DOMAIN: DOMAIN,
  PLANE_PHYSICAL_SIGNED_RELEASE_READINESS_VERSION: VERSION,
  assertCurrentSignedPlanePhysicalReleaseReadiness,
  evaluatePackagedPlanePhysicalReleaseReadiness,
  evaluatePlanePhysicalReleaseReadiness,
  evaluateSignedPlanePhysicalReleaseReadiness,
  planePhysicalGateAcceptanceDigest,
  planePhysicalGateContractDigest,
});
