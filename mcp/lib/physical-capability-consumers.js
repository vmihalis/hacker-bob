"use strict";

// PH-S9 / PH-X1 — provider-neutral physical capability-pack consumers.
//
// These contracts deliberately stop before instrument execution.  They shape
// assignment, coverage, finding, verdict, grade, evidence, proof, report, and
// composition data
// without exposing a provider, transport, raw artifact, or effect grant.  A
// live verdict can enter through projectReportSafePhysicalVerdict only after a
// PhysicalExperimentLedger has issued and revalidated its private projection.

const { types: utilTypes } = require("node:util");

const {
  TERMINAL_STATE_VALUES,
} = require("./physical-campaign-closure.js");
const {
  PHYSICAL_SURFACE_NODE_TYPES,
} = require("./physical-surface-transition.js");
const {
  PHYSICAL_CAPABILITY_CONSUMERS,
  PHYSICAL_CAPABILITY_CONSUMER_VERSION,
  PHYSICAL_CAPABILITY_PACK_DISPATCH_BLOCK_REASON,
  PHYSICAL_COMPLETION_GATE,
  PHYSICAL_EFFECT_AUTHORITY,
  PHYSICAL_FINDING_KIND,
  PHYSICAL_LIFECYCLE_PRECONDITION,
  PHYSICAL_VERDICT_KIND,
  PHYSICAL_VERIFIED_TERMINAL_WITNESS_DOMAIN,
} = require("./physical-capability-manifest.js");
const {
  assertPhysicalFinding,
  assertPhysicalVerdictSessionDigest,
  assertReportSafePhysicalVerdict,
  buildPhysicalFinding,
  derivePhysicalFindingDedupeKey,
  projectReportSafePhysicalVerdict,
} = require("./physical-finding-contract.js");
const {
  validateNoPhysicalSensitiveMaterial,
} = require("./physical-sensitive-material.js");
const {
  hashCanonicalJson,
} = require("./verification-contracts.js");
const {
  assertSafeDomain,
} = require("./paths.js");

const DIGEST_RE = /^[a-f0-9]{64}$/u;
const OPAQUE_REF_RE = /^[a-z][a-z0-9._-]{0,63}:[A-Za-z0-9][A-Za-z0-9._:@-]{0,190}$/u;
const IDENTIFIER_RE = /^[a-z][a-z0-9._-]{0,127}$/u;
const SEVERITY_VALUES = Object.freeze(["critical", "high", "medium", "low", "info"]);
const PHYSICAL_SURFACE_TYPE_SET = new Set(["physical", ...PHYSICAL_SURFACE_NODE_TYPES]);
const TERMINAL_STATE_SET = new Set(TERMINAL_STATE_VALUES);
const PHYSICAL_COMPLETIONS = new WeakSet();
const DURABLE_PHYSICAL_COMPLETIONS = new WeakSet();
const DURABLE_PHYSICAL_COMPLETION_STATE = new WeakMap();
const PHYSICAL_GRADE_BINDINGS = new WeakSet();
const PHYSICAL_GRADE_BINDING_STATE = new WeakMap();
const PHYSICAL_REPORT_EVIDENCE = new WeakSet();

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

function derivePhysicalAssignmentContextDigest(body) {
  return hashCanonicalJson({
    domain: "hacker-bob/physical-assignment-context/v1",
    ...body,
  });
}

function normalizePhysicalAssignmentContext(input) {
  assertClosedObject(input, "physical assignment context", [
    "version",
    "capability_pack",
    "capability_pack_version",
    "evaluator_agent",
    "brief_profile",
    "surface_id",
    "surface_type",
    "surface_class",
    "session_nucleus_hash",
    "asset_locator",
    "campaign_ref",
    "assignment_context_digest",
    "physical_resource_bundle_ref",
    "lifecycle_precondition",
    "effect_authority",
  ]);
  assertVersion(input.version, "physical assignment context.version");
  if (input.capability_pack !== "physical" || input.capability_pack_version !== 1) {
    throw new Error("physical assignment context must bind capability_pack physical version 1");
  }
  if (input.evaluator_agent !== "evaluator-physical-agent" || input.brief_profile !== "physical") {
    throw new Error("physical assignment context must bind the dedicated physical evaluator and brief");
  }
  if (input.surface_class !== "physical" || !PHYSICAL_SURFACE_TYPE_SET.has(input.surface_type)) {
    throw new Error("physical assignment context must use the registered physical surface vocabulary");
  }
  if (input.lifecycle_precondition !== PHYSICAL_LIFECYCLE_PRECONDITION) {
    throw new Error(`physical assignment context lifecycle_precondition must be ${PHYSICAL_LIFECYCLE_PRECONDITION}`);
  }
  if (input.effect_authority !== PHYSICAL_EFFECT_AUTHORITY) {
    throw new Error(`physical assignment context effect_authority must be ${PHYSICAL_EFFECT_AUTHORITY}`);
  }
  const body = {
    version: input.version,
    capability_pack: input.capability_pack,
    capability_pack_version: input.capability_pack_version,
    evaluator_agent: input.evaluator_agent,
    brief_profile: input.brief_profile,
    surface_id: assertOpaqueRef(input.surface_id, "physical assignment context.surface_id", "surface"),
    surface_type: input.surface_type,
    surface_class: input.surface_class,
    session_nucleus_hash: assertDigest(
      input.session_nucleus_hash,
      "physical assignment context.session_nucleus_hash",
    ),
    asset_locator: assertOpaqueRef(input.asset_locator, "physical assignment context.asset_locator"),
    campaign_ref: assertOpaqueRef(input.campaign_ref, "physical assignment context.campaign_ref", "physical-campaign"),
    physical_resource_bundle_ref: assertOpaqueRef(
      input.physical_resource_bundle_ref,
      "physical assignment context.physical_resource_bundle_ref",
      "physical-resource-bundle",
    ),
    lifecycle_precondition: input.lifecycle_precondition,
    effect_authority: input.effect_authority,
  };
  const suppliedDigest = assertDigest(
    input.assignment_context_digest,
    "physical assignment context.assignment_context_digest",
  );
  const derivedDigest = derivePhysicalAssignmentContextDigest(body);
  if (suppliedDigest !== derivedDigest) {
    throw new Error("physical assignment context.assignment_context_digest does not bind its canonical fields");
  }
  return deepFreeze({ ...body, assignment_context_digest: derivedDigest });
}

function deriveVerifiedPhysicalCoverageTerminalWitnessDigest(input) {
  assertClosedObject(input, "verified physical terminal witness", [
    "assignment_context_digest",
    "session_nucleus_hash",
    "campaign_ref",
    "cell_ref",
    "asset_locator",
    "verified_verdict_ref",
    "verification_projection_digest",
  ]);
  return hashCanonicalJson({
    domain: PHYSICAL_VERIFIED_TERMINAL_WITNESS_DOMAIN,
    assignment_context_digest: assertDigest(
      input.assignment_context_digest,
      "verified physical terminal witness.assignment_context_digest",
    ),
    session_nucleus_hash: assertDigest(
      input.session_nucleus_hash,
      "verified physical terminal witness.session_nucleus_hash",
    ),
    campaign_ref: assertOpaqueRef(
      input.campaign_ref,
      "verified physical terminal witness.campaign_ref",
      "physical-campaign",
    ),
    cell_ref: assertOpaqueRef(
      input.cell_ref,
      "verified physical terminal witness.cell_ref",
      "physical-cell",
    ),
    asset_locator: assertOpaqueRef(
      input.asset_locator,
      "verified physical terminal witness.asset_locator",
    ),
    verified_verdict_ref: assertOpaqueRef(
      input.verified_verdict_ref,
      "verified physical terminal witness.verified_verdict_ref",
      "physical-claim-verdict",
    ),
    verification_projection_digest: assertDigest(
      input.verification_projection_digest,
      "verified physical terminal witness.verification_projection_digest",
    ),
  });
}

function normalizePhysicalCoverageCell(input) {
  assertClosedObject(input, "physical coverage cell", [
    "version",
    "cell_ref",
    "assignment_context_digest",
    "asset_locator",
    "technique_id",
    "context_ref",
    "control_ref",
    "terminal_state",
    "terminal_witness_digest",
  ], ["verified_verdict_ref", "verification_projection_digest"]);
  assertVersion(input.version, "physical coverage cell.version");
  if (!TERMINAL_STATE_SET.has(input.terminal_state)) {
    throw new Error(`physical coverage cell.terminal_state must be one of ${TERMINAL_STATE_VALUES.join(", ")}`);
  }
  const verifiedVerdictRef = input.verified_verdict_ref == null
    ? null
    : assertOpaqueRef(
      input.verified_verdict_ref,
      "physical coverage cell.verified_verdict_ref",
      "physical-claim-verdict",
    );
  const verificationProjectionDigest = input.verification_projection_digest == null
    ? null
    : assertDigest(
      input.verification_projection_digest,
      "physical coverage cell.verification_projection_digest",
    );
  if (input.terminal_state === "verified"
      && (verifiedVerdictRef == null || verificationProjectionDigest == null)) {
    throw new Error(
      "verified physical coverage requires verified_verdict_ref and verification_projection_digest",
    );
  }
  if (input.terminal_state !== "verified"
      && (verifiedVerdictRef != null || verificationProjectionDigest != null)) {
    throw new Error(
      "only a verified physical coverage cell may carry verdict projection fields",
    );
  }
  return deepFreeze({
    version: input.version,
    cell_ref: assertOpaqueRef(input.cell_ref, "physical coverage cell.cell_ref", "physical-cell"),
    assignment_context_digest: assertDigest(
      input.assignment_context_digest,
      "physical coverage cell.assignment_context_digest",
    ),
    asset_locator: assertOpaqueRef(input.asset_locator, "physical coverage cell.asset_locator"),
    technique_id: assertIdentifier(input.technique_id, "physical coverage cell.technique_id"),
    context_ref: assertOpaqueRef(input.context_ref, "physical coverage cell.context_ref"),
    control_ref: assertOpaqueRef(input.control_ref, "physical coverage cell.control_ref"),
    terminal_state: input.terminal_state,
    terminal_witness_digest: assertDigest(
      input.terminal_witness_digest,
      "physical coverage cell.terminal_witness_digest",
    ),
    ...(verifiedVerdictRef == null ? {} : {
      verified_verdict_ref: verifiedVerdictRef,
      verification_projection_digest: verificationProjectionDigest,
    }),
  });
}

function closePhysicalCoverage(input) {
  assertClosedObject(input, "physical completion input", [
    "version",
    "assignment",
    "applicable_cell_refs",
    "cells",
    "active_effect_count",
  ]);
  assertVersion(input.version, "physical completion input.version");
  const assignment = normalizePhysicalAssignmentContext(input.assignment);
  if (!Array.isArray(input.applicable_cell_refs) || input.applicable_cell_refs.length < 1) {
    throw new Error("physical completion input.applicable_cell_refs must be a non-empty array");
  }
  if (!Array.isArray(input.cells)) throw new Error("physical completion input.cells must be an array");
  if (input.active_effect_count !== 0) {
    throw new Error("physical completion requires active_effect_count=0 before handoff");
  }
  const applicable = input.applicable_cell_refs.map((ref, index) => (
    assertOpaqueRef(ref, `physical completion input.applicable_cell_refs[${index}]`, "physical-cell")
  ));
  if (new Set(applicable).size !== applicable.length) {
    throw new Error("physical completion input.applicable_cell_refs contains duplicates");
  }
  const cells = input.cells.map(normalizePhysicalCoverageCell);
  const byRef = new Map();
  for (const cell of cells) {
    if (byRef.has(cell.cell_ref)) throw new Error(`physical completion contains duplicate cell ${cell.cell_ref}`);
    if (cell.assignment_context_digest !== assignment.assignment_context_digest) {
      throw new Error(`physical completion cell ${cell.cell_ref} has assignment context drift`);
    }
    if (cell.asset_locator !== assignment.asset_locator) {
      throw new Error(`physical completion cell ${cell.cell_ref} has asset locator drift`);
    }
    if (cell.terminal_state === "verified") {
      const expectedWitnessDigest = deriveVerifiedPhysicalCoverageTerminalWitnessDigest({
        assignment_context_digest: assignment.assignment_context_digest,
        session_nucleus_hash: assignment.session_nucleus_hash,
        campaign_ref: assignment.campaign_ref,
        cell_ref: cell.cell_ref,
        asset_locator: cell.asset_locator,
        verified_verdict_ref: cell.verified_verdict_ref,
        verification_projection_digest: cell.verification_projection_digest,
      });
      if (cell.terminal_witness_digest !== expectedWitnessDigest) {
        throw new Error(
          `physical completion cell ${cell.cell_ref} verified terminal witness drift`,
        );
      }
    }
    byRef.set(cell.cell_ref, cell);
  }
  const missing = applicable.filter((ref) => !byRef.has(ref));
  const extra = Array.from(byRef.keys()).filter((ref) => !applicable.includes(ref));
  if (missing.length > 0 || extra.length > 0) {
    throw new Error(
      `physical completion cell set mismatch (missing: ${missing.join(", ") || "none"}; extra: ${extra.join(", ") || "none"})`,
    );
  }
  const terminalStateCounts = Object.fromEntries(TERMINAL_STATE_VALUES.map((state) => [state, 0]));
  for (const cell of cells) terminalStateCounts[cell.terminal_state] += 1;
  const body = {
    version: PHYSICAL_CAPABILITY_CONSUMER_VERSION,
    completion_gate: PHYSICAL_COMPLETION_GATE,
    assignment_context_digest: assignment.assignment_context_digest,
    asset_locator: assignment.asset_locator,
    applicable_cell_count: applicable.length,
    terminal_cell_count: cells.length,
    terminal_complete: true,
    active_effect_count: 0,
    active_effect_authority: "caller_projection_non_authorizing",
    production_ready: false,
    terminal_state_counts: terminalStateCounts,
    residue_cell_count: terminalStateCounts.inconclusive + terminalStateCounts.blocked,
    cell_refs: applicable.slice().sort(),
  };
  const completion = deepFreeze({ ...body, completion_digest: hashCanonicalJson(body) });
  PHYSICAL_COMPLETIONS.add(completion);
  return completion;
}

function projectDurablePhysicalCampaignCompletion(input) {
  assertClosedObject(input, "durable physical completion input", [
    "target_domain",
    "assignment",
    "finding",
  ]);
  const targetDomain = assertSafeDomain(input.target_domain);
  const assignment = normalizePhysicalAssignmentContext(input.assignment);
  const finding = assertPhysicalFinding(input.finding);
  if (finding.asset_locator !== assignment.asset_locator
      || finding.session_nucleus_hash !== assignment.session_nucleus_hash) {
    throw new Error(
      "durable physical completion assignment does not bind the finding session and asset",
    );
  }
  // Loaded lazily to keep the provider-neutral data contracts independent of
  // the filesystem-backed coordinator at module initialization time.
  const {
    readVerifiedPhysicalCampaignCompletionState,
  } = require("./physical-campaign-coordinator.js");
  const state = readVerifiedPhysicalCampaignCompletionState(targetDomain);
  if (state.campaign_identity_version !== 2
      || state.production_ready !== true
      || state.terminal_complete !== true
      || state.active_effect_count !== 0
      || state.residue_cell_count !== 0
      || state.coverage_credited_cell_count !== state.terminal_cell_count) {
    throw new Error(
      "durable physical completion requires a production-attested closed campaign with zero active effects and no residue",
    );
  }
  if (state.session_nucleus_hash !== assignment.session_nucleus_hash
      || state.campaign_id !== assignment.campaign_ref
      || state.authority_binding_digest !== assignment.assignment_context_digest) {
    throw new Error("durable physical completion campaign authority binding drift");
  }
  const matchedCellRefs = [];
  for (const terminal of state.terminal_cells) {
    if (terminal.terminal_state !== "verified") continue;
    const expected = deriveVerifiedPhysicalCoverageTerminalWitnessDigest({
      assignment_context_digest: assignment.assignment_context_digest,
      session_nucleus_hash: assignment.session_nucleus_hash,
      campaign_ref: assignment.campaign_ref,
      cell_ref: terminal.cell_id,
      asset_locator: assignment.asset_locator,
      verified_verdict_ref: finding.verified_verdict_ref,
      verification_projection_digest: finding.verification_projection_digest,
    });
    if (terminal.terminal_witness_digest === expected) {
      matchedCellRefs.push(terminal.cell_id);
    }
  }
  matchedCellRefs.sort();
  if (matchedCellRefs.length < 1) {
    throw new Error(
      "durable physical completion contains no verified terminal witness for the finding",
    );
  }
  const matchedVerifiedCellsDigest = hashCanonicalJson({
    domain: "hacker-bob/physical-finding-terminal-cell-set/v1",
    campaign_id: state.campaign_id,
    verified_verdict_ref: finding.verified_verdict_ref,
    verification_projection_digest: finding.verification_projection_digest,
    cell_refs: matchedCellRefs,
  });
  const body = {
    version: PHYSICAL_CAPABILITY_CONSUMER_VERSION,
    campaign_identity_version: 2,
    completion_gate: PHYSICAL_COMPLETION_GATE,
    target_domain: targetDomain,
    assignment_context_digest: assignment.assignment_context_digest,
    session_nucleus_hash: assignment.session_nucleus_hash,
    asset_locator: assignment.asset_locator,
    campaign_ref: state.campaign_id,
    verified_verdict_ref: finding.verified_verdict_ref,
    verification_projection_digest: finding.verification_projection_digest,
    aggregate_closure_root: state.aggregate_closure_root,
    terminal_cells_merkle_root: state.terminal_cells_merkle_root,
    terminal_cell_count: state.terminal_cell_count,
    coverage_credited_cell_count: state.coverage_credited_cell_count,
    residue_cell_count: 0,
    active_effect_count: 0,
    matched_verified_cell_count: matchedCellRefs.length,
    matched_verified_cells_digest: matchedVerifiedCellsDigest,
    campaign_completion_state_digest: state.completion_state_digest,
    anchor_attestation_digest: state.anchor_attestation_digest,
    campaign_obligation_digest: state.campaign_obligation_digest,
    physical_nucleus_authority_digest: state.physical_nucleus_authority_digest,
    closure_signer_enrollment_digest: state.closure_signer_enrollment_digest,
    terminal_witness_attestation_digest: state.terminal_witness_attestation_digest,
    no_active_effects_attestation_digest: state.no_active_effects_attestation_digest,
    terminal_complete: true,
    production_ready: true,
  };
  const completion = deepFreeze({
    ...body,
    completion_digest: hashCanonicalJson({
      domain: "hacker-bob/durable-physical-completion/v1",
      ...body,
    }),
  });
  DURABLE_PHYSICAL_COMPLETIONS.add(completion);
  DURABLE_PHYSICAL_COMPLETION_STATE.set(completion, Object.freeze({
    targetDomain,
    assignment,
    finding,
  }));
  return completion;
}

function assertDurablePhysicalCompletion(value) {
  const state = value && DURABLE_PHYSICAL_COMPLETION_STATE.get(value);
  if (value == null || typeof value !== "object"
      || !DURABLE_PHYSICAL_COMPLETIONS.has(value)
      || !state
      || value.production_ready !== true
      || value.active_effect_count !== 0
      || value.residue_cell_count !== 0) {
    throw new Error(
      "physical completion must be issued from a production-attested durable campaign",
    );
  }
  // Campaign closure is a point-in-time projection. Rebuild it against the
  // externally anchored checkpoint before every grade/report consumption so
  // anchor rollback, terminal-witness drift, or loss of the durable zero-effect
  // attestation invalidates an already branded completion.
  const rebuilt = projectDurablePhysicalCampaignCompletion({
    target_domain: state.targetDomain,
    assignment: state.assignment,
    finding: state.finding,
  });
  if (rebuilt.completion_digest !== value.completion_digest) {
    throw new Error("physical durable campaign completion drifted from current anchored state");
  }
  return rebuilt;
}

function buildPhysicalGradeBinding(input) {
  assertClosedObject(input, "physical grade input", [
    "finding",
    "completion",
    "verified_severity",
    "blast_radius_binding",
  ]);
  const finding = assertPhysicalFinding(input.finding);
  const completion = assertDurablePhysicalCompletion(input.completion);
  const {
    assertPhysicalBlastRadiusGradeBinding,
  } = require("./capability-pack-composition-adapters.js");
  const blastRadius = assertPhysicalBlastRadiusGradeBinding(input.blast_radius_binding);
  if (!SEVERITY_VALUES.includes(input.verified_severity)) {
    throw new Error("physical grade input.verified_severity is invalid");
  }
  if (finding.asset_locator !== completion.asset_locator) {
    throw new Error("physical grade input finding and completion asset locators do not match");
  }
  if (finding.session_nucleus_hash !== completion.session_nucleus_hash
      || finding.verified_verdict_ref !== completion.verified_verdict_ref
      || finding.verification_projection_digest !== completion.verification_projection_digest) {
    throw new Error("physical grade input finding and durable completion binding drift");
  }
  if (blastRadius.target_domain !== completion.target_domain
      || blastRadius.finding_dedupe_key !== finding.finding_dedupe_key
      || blastRadius.asset_locator !== finding.asset_locator
      || blastRadius.session_nucleus_hash !== finding.session_nucleus_hash
      || blastRadius.verified_verdict_ref !== finding.verified_verdict_ref
      || blastRadius.verification_projection_digest
        !== finding.verification_projection_digest
      || blastRadius.verified_severity !== input.verified_severity) {
    throw new Error("physical grade input verified blast-radius binding drift");
  }
  const body = {
    version: PHYSICAL_CAPABILITY_CONSUMER_VERSION,
    grade_binding_kind: "physical_verified_transition_grade_binding",
    capability_pack: "physical",
    target_domain: completion.target_domain,
    finding_dedupe_key: finding.finding_dedupe_key,
    finding_asserted_severity: finding.severity,
    severity: input.verified_severity,
    asset_locator: finding.asset_locator,
    verified_verdict_ref: finding.verified_verdict_ref,
    verification_projection_digest: finding.verification_projection_digest,
    session_nucleus_hash: finding.session_nucleus_hash,
    campaign_ref: completion.campaign_ref,
    campaign_completion_digest: completion.completion_digest,
    aggregate_closure_root: completion.aggregate_closure_root,
    terminal_cells_merkle_root: completion.terminal_cells_merkle_root,
    terminal_cell_count: completion.terminal_cell_count,
    matched_verified_cell_count: completion.matched_verified_cell_count,
    matched_verified_cells_digest: completion.matched_verified_cells_digest,
    active_effect_count: 0,
    residue_cell_count: 0,
    no_active_effects_attestation_digest: completion.no_active_effects_attestation_digest,
    composition_adapter: blastRadius.adapter,
    composition_projection_digest: blastRadius.composition_projection_digest,
    transition_receipt_ref: blastRadius.transition_receipt_ref,
    transition_receipt_digest: blastRadius.transition_receipt_digest,
    claim_predicate_digest: blastRadius.claim_predicate_digest,
    transition_state_epoch: blastRadius.transition_state_epoch,
    transition_state_digest: blastRadius.transition_state_digest,
    transition_validity_kind: blastRadius.validity_kind,
    verified_severity_ceiling: blastRadius.verified_severity_ceiling,
    structural_severity_ceiling: blastRadius.structural_severity_ceiling,
    blast_radius_class: blastRadius.blast_radius_class,
    attack_vector: blastRadius.attack_vector,
    transition_edge_count: blastRadius.transition_edge_count,
    transition_edge_set_digest: blastRadius.transition_edge_set_digest,
    reachable_node_count: blastRadius.reachable_node_count,
    reachable_node_set_digest: blastRadius.reachable_node_set_digest,
    reachable_edge_count: blastRadius.reachable_edge_count,
    reachable_edge_set_digest: blastRadius.reachable_edge_set_digest,
    reachable_node_type_counts: blastRadius.reachable_node_type_counts,
    blast_radius_categories: blastRadius.blast_radius_categories,
    blast_radius_category_digest: blastRadius.blast_radius_category_digest,
    critical_category_pair: blastRadius.critical_category_pair,
    external_observer_independence_domain_count:
      blastRadius.external_observer_independence_domain_count,
    external_observer_independence_domain_digest:
      blastRadius.external_observer_independence_domain_digest,
    high_impact_corroboration_satisfied:
      blastRadius.high_impact_corroboration_satisfied,
    observer_assurance_legacy_missing:
      blastRadius.observer_assurance_legacy_missing,
    historical_fact_only: blastRadius.historical_fact_only,
    live_capability_current: blastRadius.live_capability_current,
    authority_inherited: false,
    downstream_authority_required: true,
    downstream_consumption_verified: false,
    blast_radius_grade_binding_digest: blastRadius.blast_radius_grade_binding_digest,
    production_ready: true,
  };
  const binding = deepFreeze({
    ...body,
    grade_binding_digest: hashCanonicalJson({
      domain: "hacker-bob/physical-grade-binding/v1",
      ...body,
    }),
  });
  PHYSICAL_GRADE_BINDINGS.add(binding);
  PHYSICAL_GRADE_BINDING_STATE.set(binding, Object.freeze({
    finding,
    completion,
    blastRadius,
  }));
  return binding;
}

function renderPhysicalFindingEvidence(input) {
  assertClosedObject(input, "physical report input", ["finding", "grade_binding"]);
  const finding = assertPhysicalFinding(input.finding);
  const gradeBinding = input.grade_binding;
  const gradeState = gradeBinding && PHYSICAL_GRADE_BINDING_STATE.get(gradeBinding);
  if (gradeBinding == null || typeof gradeBinding !== "object"
      || !PHYSICAL_GRADE_BINDINGS.has(gradeBinding) || !gradeState) {
    throw new Error("physical report rendering requires a durable physical grade binding");
  }
  if (assertPhysicalFinding(gradeState.finding) !== finding) {
    throw new Error("physical report finding is not the grade binding's live source finding");
  }
  const {
    assertPhysicalBlastRadiusGradeBinding,
  } = require("./capability-pack-composition-adapters.js");
  const refreshedBlastRadius = assertPhysicalBlastRadiusGradeBinding(gradeState.blastRadius);
  if (refreshedBlastRadius.blast_radius_grade_binding_digest
      !== gradeBinding.blast_radius_grade_binding_digest) {
    throw new Error("physical report grade blast-radius binding drift");
  }
  const refreshedCompletion = assertDurablePhysicalCompletion(gradeState.completion);
  if (refreshedCompletion.completion_digest !== gradeBinding.campaign_completion_digest) {
    throw new Error("physical report grade campaign-completion binding drift");
  }
  if (gradeBinding.finding_dedupe_key !== finding.finding_dedupe_key
      || gradeBinding.finding_asserted_severity !== finding.severity
      || gradeBinding.asset_locator !== finding.asset_locator
      || gradeBinding.verified_verdict_ref !== finding.verified_verdict_ref
      || gradeBinding.verification_projection_digest
        !== finding.verification_projection_digest
      || gradeBinding.session_nucleus_hash !== finding.session_nucleus_hash) {
    throw new Error("physical report finding and grade binding drift");
  }
  const body = {
    version: PHYSICAL_CAPABILITY_CONSUMER_VERSION,
    renderer: "physical_report_safe_v1",
    capability_pack: "physical",
    finding_kind: finding.finding_kind,
    finding_dedupe_key: finding.finding_dedupe_key,
    // The claim's narrative is evaluator input.  Bind it by digest for audit,
    // but never render it as bob_verified prose.  Report text below is derived
    // solely from the verified transition, durable closure, and final verifier
    // severity so a persuasive candidate narrative cannot become evidence by
    // surviving persistence.
    title: `Verified physical control transition for ${finding.asset_locator}`,
    severity: gradeBinding.severity,
    cwe: null,
    description:
      `An independent positive/control differential verified the planned external physical transition for ${finding.asset_locator}.`,
    impact:
      `The verified transition is reportable at ${gradeBinding.severity} severity with a ${gradeBinding.blast_radius_class} blast radius bounded to ${gradeBinding.reachable_node_count} verifier-approved reachable node(s) and ${gradeBinding.reachable_edge_count} causal edge(s). Graph adjacency grants no authority, and downstream actions still require independent scope and effect admission.`,
    claim_narrative_digest: hashCanonicalJson({
      domain: "hacker-bob/physical-candidate-narrative/v1",
      title: finding.title,
      severity: finding.severity,
      cwe: finding.cwe,
      description: finding.description,
      impact: finding.impact,
    }),
    asset_locator: finding.asset_locator,
    verified_verdict_ref: finding.verified_verdict_ref,
    verification_projection_digest: finding.verification_projection_digest,
    campaign_ref: gradeBinding.campaign_ref,
    aggregate_closure_root: gradeBinding.aggregate_closure_root,
    terminal_cells_merkle_root: gradeBinding.terminal_cells_merkle_root,
    terminal_cell_count: gradeBinding.terminal_cell_count,
    matched_verified_cell_count: gradeBinding.matched_verified_cell_count,
    matched_verified_cells_digest: gradeBinding.matched_verified_cells_digest,
    composition_adapter: gradeBinding.composition_adapter,
    composition_projection_digest: gradeBinding.composition_projection_digest,
    transition_receipt_ref: gradeBinding.transition_receipt_ref,
    transition_receipt_digest: gradeBinding.transition_receipt_digest,
    claim_predicate_digest: gradeBinding.claim_predicate_digest,
    transition_state_epoch: gradeBinding.transition_state_epoch,
    transition_state_digest: gradeBinding.transition_state_digest,
    transition_validity_kind: gradeBinding.transition_validity_kind,
    verified_severity_ceiling: gradeBinding.verified_severity_ceiling,
    structural_severity_ceiling: gradeBinding.structural_severity_ceiling,
    blast_radius_class: gradeBinding.blast_radius_class,
    attack_vector: gradeBinding.attack_vector,
    transition_edge_count: gradeBinding.transition_edge_count,
    transition_edge_set_digest: gradeBinding.transition_edge_set_digest,
    reachable_node_count: gradeBinding.reachable_node_count,
    reachable_node_set_digest: gradeBinding.reachable_node_set_digest,
    reachable_edge_count: gradeBinding.reachable_edge_count,
    reachable_edge_set_digest: gradeBinding.reachable_edge_set_digest,
    reachable_node_type_counts: gradeBinding.reachable_node_type_counts,
    blast_radius_categories: gradeBinding.blast_radius_categories,
    blast_radius_category_digest: gradeBinding.blast_radius_category_digest,
    critical_category_pair: gradeBinding.critical_category_pair,
    external_observer_independence_domain_count:
      gradeBinding.external_observer_independence_domain_count,
    external_observer_independence_domain_digest:
      gradeBinding.external_observer_independence_domain_digest,
    high_impact_corroboration_satisfied:
      gradeBinding.high_impact_corroboration_satisfied,
    observer_assurance_legacy_missing:
      gradeBinding.observer_assurance_legacy_missing,
    historical_fact_only: gradeBinding.historical_fact_only,
    live_capability_current: gradeBinding.live_capability_current,
    authority_inherited: false,
    downstream_authority_required: true,
    downstream_consumption_verified: false,
    blast_radius_grade_binding_digest: gradeBinding.blast_radius_grade_binding_digest,
    grade_binding_digest: gradeBinding.grade_binding_digest,
    proof_summary: "Differential physical transition verified; full campaign closure and zero active effects were durably attested.",
    raw_evidence_allowed: false,
    production_ready: true,
  };
  const report = deepFreeze({
    ...body,
    report_evidence_digest: hashCanonicalJson({
      domain: "hacker-bob/physical-report-safe-evidence/v1",
      ...body,
    }),
  });
  PHYSICAL_REPORT_EVIDENCE.add(report);
  return report;
}

module.exports = Object.freeze({
  PHYSICAL_CAPABILITY_CONSUMERS,
  PHYSICAL_CAPABILITY_CONSUMER_VERSION,
  PHYSICAL_CAPABILITY_PACK_DISPATCH_BLOCK_REASON,
  PHYSICAL_COMPLETION_GATE,
  PHYSICAL_EFFECT_AUTHORITY,
  PHYSICAL_VERIFIED_TERMINAL_WITNESS_DOMAIN,
  PHYSICAL_FINDING_KIND,
  PHYSICAL_LIFECYCLE_PRECONDITION,
  PHYSICAL_VERDICT_KIND,
  assertPhysicalFinding,
  assertDurablePhysicalCompletion,
  assertPhysicalVerdictSessionDigest,
  assertReportSafePhysicalVerdict,
  buildPhysicalFinding,
  buildPhysicalGradeBinding,
  closePhysicalCoverage,
  derivePhysicalAssignmentContextDigest,
  derivePhysicalFindingDedupeKey,
  deriveVerifiedPhysicalCoverageTerminalWitnessDigest,
  normalizePhysicalAssignmentContext,
  normalizePhysicalCoverageCell,
  projectReportSafePhysicalVerdict,
  projectDurablePhysicalCampaignCompletion,
  renderPhysicalFindingEvidence,
});
