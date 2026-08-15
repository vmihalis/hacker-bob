"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const {
  appendCandidateClaim,
} = require("../mcp/core/claims/claims.js");
const {
  buildClaimFreeze,
} = require("../mcp/core/claims/claim-freeze.js");
const {
  buildCapabilityPackGradeBindings,
  capabilityPackGradeAdapterId,
} = require("../mcp/core/capability/capability-pack-grade-adapters.js");
const {
  buildCapabilityPackReportSections,
} = require("../mcp/core/capability/capability-pack-report-adapters.js");
const {
  buildCapabilityPackEvidencePacks,
} = require("../mcp/core/capability/capability-pack-evidence-adapters.js");
const {
  buildCapabilityPackProofBundles,
} = require("../mcp/core/capability/capability-pack-proof-adapters.js");
const {
  PHYSICAL_CAPABILITY_PACK,
} = require("../mcp/core/capability/capability-packs.js");
const {
  normalizeProofBundlesDocument,
} = require("../mcp/core/proof-bundle.js");
const writeProofBundleTool = require("../mcp/tools/write-proof-bundle.js");
const {
  derivePhysicalAssignmentContextDigest,
  derivePhysicalFindingDedupeKey,
} = require("../mcp/domains/physical/physical-capability-consumers.js");
const {
  hashCanonicalJson,
} = require("../mcp/core/verification/verification-contracts.js");

const DOMAIN = "physical-lifecycle-adapter-test";

function physicalClaimFixture() {
  const assignment = {
    version: 1,
    capability_pack: "physical",
    capability_pack_version: 1,
    evaluator_agent: "evaluator-physical-agent",
    brief_profile: "physical",
    surface_id: "surface:door-reader",
    surface_type: "control_point",
    surface_class: "physical",
    session_nucleus_hash: "d".repeat(64),
    asset_locator: "physical-asset:door-reader",
    campaign_ref: "physical-campaign:campaign-1",
    physical_resource_bundle_ref: "physical-resource-bundle:bundle-1",
    lifecycle_precondition: "no_active_effects",
    effect_authority: "broker_admission_required",
  };
  assignment.assignment_context_digest = derivePhysicalAssignmentContextDigest(assignment);
  const finding = {
    id: "F-1",
    target_domain: DOMAIN,
    ...assignment,
    finding_kind: "physical_verified_transition",
    verified_verdict_ref: "physical-claim-verdict:verdict-1",
    verification_projection_digest: "b".repeat(64),
    title: "Credential representation crosses the restricted-zone control",
    severity: "high",
    cwe: "CWE-284",
    description: "An independent observer recorded the differential control transition.",
    impact: "An unauthorized bearer could reach the bounded restricted zone.",
    validity_kind: "historical_event",
    decided_at: "2026-07-20T00:01:00.000Z",
    validated: true,
  };
  finding.finding_dedupe_key = derivePhysicalFindingDedupeKey({
    asset_locator: finding.asset_locator,
    verified_verdict_ref: finding.verified_verdict_ref,
    verification_projection_digest: finding.verification_projection_digest,
    title: finding.title,
  });
  finding.dedupe_key = finding.finding_dedupe_key;
  const claim = {
    target_domain: DOMAIN,
    title: finding.title,
    summary: finding.description,
    severity: finding.severity,
    status: "candidate",
    created_at: "2026-07-20T00:02:00.000Z",
    surface_ids: [assignment.surface_id],
    impact: finding.impact,
    evidence_refs: [{
      kind: "finding",
      finding_id: finding.id,
      content_hash: hashCanonicalJson(finding),
    }],
    payload: {
      subject_id: assignment.asset_locator,
      surface_ref: assignment.surface_id,
      dedupe_key: finding.dedupe_key,
      physical_assignment: assignment,
      finding,
    },
  };
  return { assignment, finding, claim };
}

function withTemporaryHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-pack-physical-lifecycle-"));
  process.env.HOME = home;
  try {
    return fn();
  } finally {
    process.env.HOME = previousHome;
    fs.rmSync(home, { recursive: true, force: true });
  }
}

test("physical findings select the manifest-declared grade adapter", () => {
  const { finding } = physicalClaimFixture();
  assert.equal(
    capabilityPackGradeAdapterId(finding),
    "physical_verified_transition_grade_binding_v1",
  );
  assert.equal(
    PHYSICAL_CAPABILITY_PACK.evidence.adapter,
    "physical_report_safe_evidence_pack_v1",
  );
  assert.equal(
    PHYSICAL_CAPABILITY_PACK.proof.adapter,
    "physical_campaign_closure_proof_bundle_v1",
  );
  assert.equal(PHYSICAL_CAPABILITY_PACK.proof.bundle_kind, "capability_pack");
});

test("pack report dispatch remains inert for a legacy-only reportable set", () => {
  withTemporaryHome(() => {
    const projection = buildCapabilityPackReportSections(DOMAIN, new Set());
    assert.deepEqual(projection.handled_finding_ids, []);
    assert.deepEqual(projection.sections, []);
    assert.equal(projection.production_ready, true);
    const evidence = buildCapabilityPackEvidencePacks(DOMAIN, new Set());
    const proof = buildCapabilityPackProofBundles(DOMAIN, new Set());
    assert.deepEqual(evidence.handled_finding_ids, []);
    assert.deepEqual(evidence.packs, []);
    assert.deepEqual(proof.handled_finding_ids, []);
    assert.deepEqual(proof.packs, []);
  });
});

test("a declared physical grade adapter cannot fall through when production evidence is unavailable", () => {
  withTemporaryHome(() => {
    const { claim } = physicalClaimFixture();
    appendCandidateClaim(claim);
    assert.throws(
      () => buildCapabilityPackGradeBindings(DOMAIN, ["F-1"]),
      /production physical verdict resolver is not installed/,
    );
    assert.throws(
      () => buildCapabilityPackReportSections(DOMAIN, new Set(["F-1"])),
      /production physical verdict resolver is not installed/,
    );
    assert.throws(
      () => buildCapabilityPackEvidencePacks(DOMAIN, new Set(["F-1"])),
      /production physical verdict resolver is not installed/,
    );
    assert.throws(
      () => buildCapabilityPackProofBundles(DOMAIN, new Set(["F-1"])),
      /production physical verdict resolver is not installed/,
    );
  });
});

test("a frozen finding without embedded routing cannot be promoted from a later live physical claim", () => {
  withTemporaryHome(() => {
    const { claim } = physicalClaimFixture();
    const legacyFrozenClaim = {
      ...claim,
      created_at: "2026-07-20T00:01:30.000Z",
    };
    delete legacyFrozenClaim.payload;
    appendCandidateClaim(legacyFrozenClaim);
    buildClaimFreeze(DOMAIN, {
      write: true,
      now: new Date("2026-07-20T00:01:45.000Z"),
    });

    // This post-freeze row is deliberately valid live data, but it is not part
    // of the signed frozen payload.  It may reveal that the ID is pack-owned;
    // it must never supply grade-time routing authority for that frozen ID.
    appendCandidateClaim(claim);
    assert.throws(
      () => buildCapabilityPackGradeBindings(DOMAIN, ["F-1"]),
      /frozen pack-owned finding F-1 has no embedded routing payload/,
    );
  });
});

test("caller capability-pack proof cannot be attached to a legacy finding", () => {
  withTemporaryHome(() => {
    assert.throws(
      () => normalizeProofBundlesDocument({
        version: 1,
        target_domain: DOMAIN,
        packs: [{
          finding_id: "F-1",
          bundle_kind: "capability_pack",
          artifacts: [{ artifact_kind: "capability_pack", production_ready: true }],
        }],
      }, {
        expectedDomain: DOMAIN,
        findingIdSet: new Set(["F-1"]),
        finalReportableIdSet: new Set(["F-1"]),
      }),
      /has no registered live proof adapter/,
    );
  });
});

test("the public proof writer schema does not expose the server-owned bundle kind", () => {
  const kinds = writeProofBundleTool.inputSchema
    .properties.packs.items.properties.bundle_kind.enum;
  assert.deepEqual(kinds, ["replay_script", "invariant", "differential"]);
  assert.equal(kinds.includes("capability_pack"), false);
});
