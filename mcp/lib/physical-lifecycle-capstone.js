"use strict";

// PH-C10 engineering capstone.
//
// This module does not mint physical authority and does not promote Plane-PH
// to production.  It gives the engineering suite one server-owned projection
// that joins the already-existing claim, freeze, verification, evidence,
// proof, grade, report, and campaign-closure contracts.  The projection is
// rebuilt from live artifacts; a caller-authored transcript, graph adjacency,
// or copied digest cannot satisfy it.

const fs = require("node:fs");
const path = require("node:path");
const { types: utilTypes } = require("node:util");

const {
  PHYSICAL_CAPABILITY_PACK,
} = require("./capability-packs.js");
const {
  buildCapabilityPackGradeBindings,
} = require("./capability-pack-grade-adapters.js");
const {
  buildCapabilityPackReportSections,
} = require("./capability-pack-report-adapters.js");
const {
  readCurrentClaimFreeze,
} = require("./claim-freeze.js");
const {
  readGradeVerdict,
} = require("./grade-verdict-store.js");
const {
  PHYSICAL_CAPABILITY_CONSUMERS,
} = require("./physical-capability-manifest.js");
const {
  normalizePhysicalAssignmentContext,
  projectDurablePhysicalCampaignCompletion,
} = require("./physical-capability-consumers.js");
const {
  normalizePhysicalCampaignClosurePreflight,
} = require("./physical-campaign-closure.js");
const {
  readVerifiedPhysicalCampaignCompletionState,
} = require("./physical-campaign-coordinator.js");
const {
  projectPhysicalCandidateVerification,
  resolvePhysicalCandidateClaim,
} = require("./physical-claim-lifecycle-adapter.js");
const {
  assertSafeDomain,
  evidencePackPaths,
  gradeArtifactPaths,
  physicalCampaignDir,
  proofBundlePaths,
  reportMarkdownPath,
} = require("./paths.js");
const {
  readReportSnapshots,
} = require("./report-snapshots.js");
const {
  resolveReportFinalizationHashes,
} = require("./report-finalize.js");
const {
  loadJsonDocumentStrict,
} = require("./storage.js");
const {
  parseFindingId,
} = require("./validation.js");
const {
  canonicalJson,
  hashCanonicalJson,
} = require("./verification-contracts.js");
const {
  readVerificationRound,
} = require("./verification-round-store.js");
const {
  readVerificationContext,
} = require("./verification.js");

const CAPSTONE_VERSION = 1;
const DIGEST_RE = /^[a-f0-9]{64}$/u;
const IDENTIFIER_RE = /^[A-Za-z][A-Za-z0-9._:-]{0,190}$/u;
const OPAQUE_REF_RE = /^[a-z][a-z0-9._-]{0,63}:[A-Za-z0-9][A-Za-z0-9._:@-]{0,190}$/u;
const CAPSTONE_COVERAGE_DECLARATIONS = new WeakSet();
const CAPSTONE_PROJECTIONS = new WeakSet();

const PHYSICAL_CAPSTONE_STAGE_ORDER = Object.freeze([
  "record",
  "claim_freeze",
  "verify_brutalist",
  "verify_balanced",
  "verify_final",
  "evidence",
  "proof",
  "grade",
  "report_render",
  "report_finalize",
]);

function deepFreeze(value) {
  if (value == null || typeof value !== "object" || Object.isFrozen(value)) return value;
  for (const child of Object.values(value)) deepFreeze(child);
  return Object.freeze(value);
}

function assertExactPlainObject(value, label, fields) {
  if (value == null || typeof value !== "object" || Array.isArray(value)
      || utilTypes.isProxy(value) || Object.getPrototypeOf(value) !== Object.prototype) {
    throw new Error(`${label} must be an exact plain data object`);
  }
  const keys = Reflect.ownKeys(value);
  const expected = fields.slice().sort();
  const actual = keys.filter((key) => typeof key === "string").sort();
  if (keys.some((key) => typeof key !== "string")
      || actual.length !== expected.length
      || actual.some((key, index) => key !== expected[index])) {
    throw new Error(`${label} must carry exactly ${fields.join(", ")}`);
  }
  const descriptors = Object.getOwnPropertyDescriptors(value);
  for (const field of fields) {
    const descriptor = descriptors[field];
    if (!descriptor || descriptor.enumerable !== true
        || !Object.prototype.hasOwnProperty.call(descriptor, "value")) {
      throw new Error(`${label}.${field} must be an enumerable data property`);
    }
  }
  return value;
}

function assertDigest(value, label) {
  if (typeof value !== "string" || !DIGEST_RE.test(value)) {
    throw new Error(`${label} must be a lowercase SHA-256 digest`);
  }
  return value;
}

function assertIdentifier(value, label) {
  if (typeof value !== "string" || !IDENTIFIER_RE.test(value)) {
    throw new Error(`${label} must be a bounded identifier`);
  }
  return value;
}

function assertOpaqueRef(value, label) {
  if (typeof value !== "string" || !OPAQUE_REF_RE.test(value) || value.includes("..")) {
    throw new Error(`${label} must be a namespaced opaque reference`);
  }
  return value;
}

function physicalPackCoverageDigest() {
  if (!PHYSICAL_CAPABILITY_PACK
      || PHYSICAL_CAPABILITY_PACK.id !== "physical"
      || PHYSICAL_CAPABILITY_PACK.capability_pack_version !== 1
      || PHYSICAL_CAPABILITY_PACK.coverage !== PHYSICAL_CAPABILITY_CONSUMERS.coverage) {
    throw new Error("physical capability-pack coverage declaration is not registered coherently");
  }
  return hashCanonicalJson({
    domain: "hacker-bob/physical-capability-pack-coverage-declaration/v1",
    capability_pack: PHYSICAL_CAPABILITY_PACK.id,
    capability_pack_version: PHYSICAL_CAPABILITY_PACK.capability_pack_version,
    completion_gate: PHYSICAL_CAPABILITY_PACK.completion_gate,
    assignment: PHYSICAL_CAPABILITY_PACK.assignment,
    coverage: PHYSICAL_CAPABILITY_PACK.coverage,
    finding: PHYSICAL_CAPABILITY_PACK.finding,
    verifier: PHYSICAL_CAPABILITY_PACK.verifier,
    evidence: PHYSICAL_CAPABILITY_PACK.evidence,
    proof: PHYSICAL_CAPABILITY_PACK.proof,
    grade: PHYSICAL_CAPABILITY_PACK.grade,
    report: PHYSICAL_CAPABILITY_PACK.report,
    composition: PHYSICAL_CAPABILITY_PACK.composition,
  });
}

function buildPhysicalCapstoneCoverageDeclaration(input) {
  assertExactPlainObject(input, "physical capstone coverage input", [
    "assignment",
    "context_ref",
    "control_ref",
    "technique_id",
  ]);
  const assignment = normalizePhysicalAssignmentContext(input.assignment);
  const valuesByDimension = {
    asset_locator: assignment.asset_locator,
    technique_id: assertIdentifier(input.technique_id, "technique_id"),
    context_ref: assertOpaqueRef(input.context_ref, "context_ref"),
    control_ref: assertOpaqueRef(input.control_ref, "control_ref"),
  };
  const declaredCellDimensions = PHYSICAL_CAPABILITY_CONSUMERS.coverage.cell_dimensions;
  if (!Array.isArray(declaredCellDimensions)
      || canonicalJson([...declaredCellDimensions].sort())
        !== canonicalJson(Object.keys(valuesByDimension).sort())) {
    throw new Error("physical capability-pack coverage dimensions drifted from PH-C10");
  }
  const declaredDimensions = Object.keys(valuesByDimension).sort().map((dimensionId) => ({
    dimension_id: dimensionId,
    values: [valuesByDimension[dimensionId]],
  }));
  const capabilityPackDigest = physicalPackCoverageDigest();
  const body = {
    version: CAPSTONE_VERSION,
    capability_pack: "physical",
    capability_pack_version: 1,
    coverage_adapter: PHYSICAL_CAPABILITY_CONSUMERS.coverage.adapter,
    assignment_context_digest: assignment.assignment_context_digest,
    session_nucleus_hash: assignment.session_nucleus_hash,
    campaign_ref: assignment.campaign_ref,
    capability_pack_digest: capabilityPackDigest,
    declared_cell_dimensions: [...declaredCellDimensions],
    declared_dimensions: declaredDimensions,
    applicable_cell_count: 1,
    full_provider_matrix: false,
    production_ready: false,
    hil_verified: false,
  };
  const declaration = deepFreeze({
    ...body,
    coverage_declaration_digest: hashCanonicalJson({
      domain: "hacker-bob/physical-lifecycle-capstone-coverage/v1",
      ...body,
    }),
  });
  CAPSTONE_COVERAGE_DECLARATIONS.add(declaration);
  return declaration;
}

function assertPhysicalCapstoneCoverageDeclaration(value) {
  if (value == null || typeof value !== "object"
      || !CAPSTONE_COVERAGE_DECLARATIONS.has(value)
      || value.production_ready !== false
      || value.hil_verified !== false) {
    throw new Error("physical capstone requires a live engineering coverage declaration");
  }
  return value;
}

function expectedVerificationResult(resolved) {
  const verification = projectPhysicalCandidateVerification(resolved);
  return deepFreeze({
    finding_id: resolved.finding_id,
    disposition: "confirmed",
    severity: verification.severity,
    reportable: true,
    reasoning:
      "Fresh server-owned projection replay revalidated the exact physical verdict, claim hash, session binding, and opaque asset without invoking hardware.",
    repro_steps: [
      `Invoke bob_verify_physical_candidate_claim for ${resolved.finding_id}; the server re-resolves ${verification.verified_verdict_ref}.`,
    ],
    evidence_refs: [verification.verified_verdict_ref],
    confidence: "high",
    confidence_reasons: ["fresh_replay_passed"],
    state_sensitive: verification.validity_kind === "live_capability",
    artifact_hashes: {
      candidate_claim: resolved.claim_hash,
      physical_verdict_projection: verification.verification_projection_digest,
    },
    inherited_confidence_reasons: [],
    resolved_confidence_reasons: [],
  });
}

function buildPhysicalCapstoneVerificationResult(targetDomain, findingIdInput) {
  const domain = assertSafeDomain(targetDomain);
  const findingId = parseFindingId(findingIdInput, "finding_id");
  const resolved = resolvePhysicalCandidateClaim(domain, findingId);
  return expectedVerificationResult(resolved);
}

function normalizedExpectedVerificationResult(expected) {
  return {
    finding_id: expected.finding_id,
    disposition: expected.disposition,
    severity: expected.severity,
    reportable: expected.reportable,
    reasoning: expected.reasoning,
    confidence: expected.confidence,
    confidence_reasons: expected.confidence_reasons.slice().sort(),
    state_sensitive: expected.state_sensitive,
    artifact_hashes: Object.fromEntries(
      Object.entries(expected.artifact_hashes).sort(([left], [right]) => left.localeCompare(right)),
    ),
    inherited_confidence_reasons: [],
    resolved_confidence_reasons: [],
  };
}

function readPhysicalCampaignPreflight(domain) {
  const filePath = path.join(physicalCampaignDir(domain), "preflight.json");
  const envelope = loadJsonDocumentStrict(filePath, "physical campaign preflight");
  assertExactPlainObject(envelope, "physical campaign preflight envelope", [
    "anchor_slot_digest",
    "envelope_digest",
    "preflight",
    "target_domain",
    "verifier",
    "version",
  ]);
  if (envelope.version !== 1 || envelope.target_domain !== domain) {
    throw new Error("physical campaign preflight envelope session binding drifted");
  }
  const expectedEnvelopeDigest = hashCanonicalJson({
    domain: "hacker-bob/physical-campaign-preflight-envelope/v1",
    version: envelope.version,
    target_domain: envelope.target_domain,
    anchor_slot_digest: assertDigest(
      envelope.anchor_slot_digest,
      "physical campaign preflight envelope.anchor_slot_digest",
    ),
    preflight: envelope.preflight,
    verifier: envelope.verifier,
  });
  if (envelope.envelope_digest !== expectedEnvelopeDigest) {
    throw new Error("physical campaign preflight envelope digest drifted");
  }
  return normalizePhysicalCampaignClosurePreflight(envelope.preflight);
}

function readJson(filePath, label) {
  return loadJsonDocumentStrict(filePath, label);
}

function singleFindingPack(document, findingId, label) {
  if (!document || !Array.isArray(document.packs)) {
    throw new Error(`${label} has no packs array`);
  }
  const matches = document.packs.filter((pack) => pack && pack.finding_id === findingId);
  if (matches.length !== 1) {
    throw new Error(`${label} must contain exactly one pack for ${findingId}`);
  }
  return matches[0];
}

function assertReportContainsSections(reportText, sections) {
  for (const section of sections) {
    if (!reportText.includes(section.heading) || !reportText.includes(section.prose)) {
      throw new Error(`rendered report is missing server-owned section ${section.section_id}`);
    }
  }
}

function auditPhysicalLifecycleEngineeringCapstone(input) {
  assertExactPlainObject(input, "physical lifecycle capstone audit input", [
    "coverage_declaration",
    "finding_id",
    "target_domain",
  ]);
  const domain = assertSafeDomain(input.target_domain);
  const findingId = parseFindingId(input.finding_id, "finding_id");
  const declaration = assertPhysicalCapstoneCoverageDeclaration(input.coverage_declaration);
  const resolved = resolvePhysicalCandidateClaim(domain, findingId);
  if (resolved.assignment.assignment_context_digest !== declaration.assignment_context_digest
      || resolved.assignment.session_nucleus_hash !== declaration.session_nucleus_hash
      || resolved.assignment.campaign_ref !== declaration.campaign_ref) {
    throw new Error("physical capstone coverage declaration drifted from the persisted claim");
  }

  const preflight = readPhysicalCampaignPreflight(domain);
  if (preflight.capability_pack_digest !== declaration.capability_pack_digest
      || canonicalJson(preflight.declared_dimensions)
        !== canonicalJson(declaration.declared_dimensions)
      || preflight.authority_binding_digest !== declaration.assignment_context_digest
      || preflight.campaign_id !== declaration.campaign_ref) {
    throw new Error("physical capstone campaign applicability drifted from the pack declaration");
  }
  const completionState = readVerifiedPhysicalCampaignCompletionState(domain);
  const completion = projectDurablePhysicalCampaignCompletion({
    target_domain: domain,
    assignment: resolved.assignment,
    finding: resolved.finding,
  });
  if (completionState.terminal_cell_count !== declaration.applicable_cell_count
      || completionState.coverage_credited_cell_count !== declaration.applicable_cell_count
      || completionState.active_effect_count !== 0
      || completionState.residue_cell_count !== 0
      || completion.active_effect_count !== 0
      || completion.residue_cell_count !== 0) {
    throw new Error("physical capstone campaign is incomplete or retains active effects/residue");
  }

  const freeze = readCurrentClaimFreeze(domain);
  if (!freeze || typeof freeze.freeze_hash !== "string" || !Array.isArray(freeze.claims)) {
    throw new Error("physical capstone claim freeze is unavailable");
  }
  const frozen = freeze.claims.filter((claim) => claim && claim.claim_id === resolved.claim_id);
  if (frozen.length !== 1 || frozen[0].claim_hash !== resolved.claim_hash) {
    throw new Error("physical capstone frozen claim does not bind the live claim hash");
  }

  const expectedVerification = normalizedExpectedVerificationResult(
    expectedVerificationResult(resolved),
  );
  const rounds = {};
  for (const round of ["brutalist", "balanced", "final"]) {
    const document = JSON.parse(readVerificationRound({
      target_domain: domain,
      round,
    }));
    if (document.version !== 2 || document.current !== true
        || !Array.isArray(document.results) || document.results.length !== 1
        || canonicalJson(document.results[0]) !== canonicalJson(expectedVerification)) {
      throw new Error(`physical capstone ${round} verification drifted from the server-owned replay projection`);
    }
    rounds[round] = document;
  }
  assertDigest(rounds.final.final_verification_hash, "final_verification_hash");
  const verificationContext = JSON.parse(readVerificationContext({ target_domain: domain }));
  if (verificationContext.snapshot_hash_current !== true
      || verificationContext.adjudication_status.current !== true
      || verificationContext.round_status.final.current !== true) {
    throw new Error("physical capstone verification attempt is stale or replayed");
  }

  // Snapshot uniqueness is the cheap replay boundary for this one-shot
  // engineering transcript. Check it before rebuilding the comparatively
  // expensive live pack projections so replay also fails resource-bounded.
  const snapshots = readReportSnapshots(domain);
  if (snapshots.length !== 1) {
    throw new Error("physical engineering capstone requires exactly one non-replayed report snapshot");
  }
  const snapshot = snapshots[0];

  const reportable = new Set([findingId]);
  const gradeProjection = buildCapabilityPackGradeBindings(domain, [findingId]);
  const reportProjection = buildCapabilityPackReportSections(domain, reportable);
  if (gradeProjection.handled_finding_ids.length !== 1
      || reportProjection.handled_finding_ids.length !== 1) {
    throw new Error("physical capstone bypassed a pack-declared lifecycle adapter");
  }

  const evidenceDocument = readJson(evidencePackPaths(domain).json, "evidence packs JSON");
  const proofDocument = readJson(proofBundlePaths(domain).json, "proof bundles JSON");
  const evidencePack = singleFindingPack(evidenceDocument, findingId, "evidence packs JSON");
  const proofPack = singleFindingPack(proofDocument, findingId, "proof bundles JSON");
  if (evidencePack.sample_type !== PHYSICAL_CAPABILITY_PACK.evidence.sample_type
      || !Array.isArray(evidencePack.representative_samples)
      || evidencePack.representative_samples.length !== 1
      || evidencePack.representative_samples[0].evidence_adapter
        !== PHYSICAL_CAPABILITY_PACK.evidence.adapter) {
    throw new Error("physical capstone evidence pack bypassed its declared adapter");
  }
  if (proofPack.bundle_kind !== PHYSICAL_CAPABILITY_PACK.proof.bundle_kind
      || !Array.isArray(proofPack.artifacts)
      || proofPack.artifacts.length !== 1
      || proofPack.artifacts[0].proof_adapter !== PHYSICAL_CAPABILITY_PACK.proof.adapter) {
    throw new Error("physical capstone proof bundle bypassed its declared adapter");
  }

  const grade = JSON.parse(readGradeVerdict({ target_domain: domain }));
  if (!Array.isArray(grade.capability_pack_bindings)
      || canonicalJson(grade.capability_pack_bindings)
        !== canonicalJson(gradeProjection.bindings)) {
    throw new Error("physical capstone grade bypassed the live pack adapter");
  }
  const gradePath = gradeArtifactPaths(domain).json;
  const gradeOnDisk = readJson(gradePath, "grade verdict JSON");
  const reportPath = reportMarkdownPath(domain);
  const reportText = fs.readFileSync(reportPath, "utf8");
  assertReportContainsSections(reportText, reportProjection.sections);

  // Finalization re-normalizes evidence and proof against their current
  // server-owned capability-pack projections before returning hashes. That is
  // the authoritative fabricated/stale-artifact rejection; avoid rebuilding
  // those same live projections independently a second time here.
  const finalization = resolveReportFinalizationHashes(domain);
  for (const field of [
    "claim_freeze_hash",
    "final_verification_hash",
    "evidence_hash",
    "proof_bundle_hash",
    "grade_verdict_hash",
    "report_content_hash",
  ]) {
    if (snapshot[field] !== finalization[field]) {
      throw new Error(`physical capstone report snapshot ${field} drifted from live artifacts`);
    }
  }

  const stageHashes = {
    record: resolved.claim_hash,
    claim_freeze: freeze.freeze_hash,
    verify_brutalist: rounds.brutalist.artifact_hash,
    verify_balanced: rounds.balanced.artifact_hash,
    verify_final: rounds.final.final_verification_hash,
    evidence: finalization.evidence_hash,
    proof: finalization.proof_bundle_hash,
    grade: hashCanonicalJson(gradeOnDisk),
    report_render: finalization.report_content_hash,
    report_finalize: snapshot.snapshot_hash,
  };
  for (const stage of PHYSICAL_CAPSTONE_STAGE_ORDER) {
    assertDigest(stageHashes[stage], `stage_hashes.${stage}`);
  }

  const body = {
    version: CAPSTONE_VERSION,
    capstone_kind: "physical_lifecycle_engineering_fixture",
    target_domain: domain,
    finding_id: findingId,
    claim_id: resolved.claim_id,
    capability_pack: "physical",
    capability_pack_version: 1,
    coverage_declaration_digest: declaration.coverage_declaration_digest,
    capability_pack_digest: declaration.capability_pack_digest,
    applicable_cell_count: declaration.applicable_cell_count,
    terminal_cell_count: completion.terminal_cell_count,
    coverage_credited_cell_count: completion.coverage_credited_cell_count,
    matched_verified_cell_count: completion.matched_verified_cell_count,
    active_effect_count: 0,
    residue_cell_count: 0,
    stage_order: PHYSICAL_CAPSTONE_STAGE_ORDER,
    stage_hashes: stageHashes,
    report_snapshot_id: snapshot.snapshot_id,
    adapter_bindings: {
      claim: PHYSICAL_CAPABILITY_PACK.finding.adapter,
      verifier: PHYSICAL_CAPABILITY_PACK.verifier.replay_tool,
      evidence: PHYSICAL_CAPABILITY_PACK.evidence.adapter,
      proof: PHYSICAL_CAPABILITY_PACK.proof.adapter,
      grade: PHYSICAL_CAPABILITY_PACK.grade.adapter,
      report: PHYSICAL_CAPABILITY_PACK.report.renderer,
    },
    provider_lineage_binding: "via_verified_ledger_projection_digest",
    provider_lineage_projection_digest: resolved.record.verification_projection_digest,
    capstone_path_verified: true,
    full_provider_matrix: false,
    lifecycle_transition_path_verified: false,
    production_ready: false,
    hil_verified: false,
    residuals: [
      "full_provider_applicability_matrix_not_exercised",
      "set_up_to_report_nucleus_transition_not_exercised",
      "physical_capability_pack_dispatch_remains_disabled",
      "owned_hardware_hil_not_exercised",
    ],
  };
  const projection = deepFreeze({
    ...body,
    capstone_digest: hashCanonicalJson({
      domain: "hacker-bob/physical-lifecycle-engineering-capstone/v1",
      ...body,
    }),
  });
  CAPSTONE_PROJECTIONS.add(projection);
  return projection;
}

function assertPhysicalLifecycleEngineeringCapstone(value) {
  if (value == null || typeof value !== "object"
      || !CAPSTONE_PROJECTIONS.has(value)
      || value.capstone_path_verified !== true
      || value.production_ready !== false
      || value.hil_verified !== false) {
    throw new Error("physical lifecycle capstone must be rebuilt by the server-owned engineering auditor");
  }
  return value;
}

module.exports = Object.freeze({
  CAPSTONE_VERSION,
  PHYSICAL_CAPSTONE_STAGE_ORDER,
  assertPhysicalCapstoneCoverageDeclaration,
  assertPhysicalLifecycleEngineeringCapstone,
  auditPhysicalLifecycleEngineeringCapstone,
  buildPhysicalCapstoneCoverageDeclaration,
  buildPhysicalCapstoneVerificationResult,
});
