"use strict";

// PH-C10 — physical-native CandidateClaim writer.
//
// This is intentionally a sibling of bob_record_candidate_claim rather than a
// mode branch inside it.  The physical capability pack supplies its own exact
// claim adapter: opaque asset + verified verdict, no endpoint, URL, raw PoC,
// provider command, or transport output.  The verdict is re-resolved through
// Bob's server-owned ledger while the session lock is held before any claim is
// persisted.

const {
  ERROR_CODES,
  ToolError,
} = require("../envelope.js");
const {
  claimsJsonlPath,
} = require("../paths.js");
const {
  withSessionLock,
} = require("../storage.js");
const {
  readVerifiedSessionNucleus,
} = require("../governance-store.js");
const {
  buildPhysicalFinding,
  normalizePhysicalAssignmentContext,
} = require("../physical-capability-consumers.js");
const {
  buildPersistedPhysicalFindingRecord,
} = require("../physical-finding-record-adapter.js");
const {
  physicalVerdictRuntimeReadiness,
  resolvePhysicalVerdict,
} = require("../physical-verdict-runtime.js");
const {
  appendCandidateClaim,
} = require("../claims.js");
const {
  appendFrontierEvent,
} = require("../frontier-events.js");
const {
  scheduleMaterialization,
} = require("../frontier-materialize-debounce.js");
const {
  safeAppendPipelineEventDirect,
} = require("../pipeline-events.js");
const {
  safeGovernanceContextForDomain,
} = require("../governance-context.js");
const {
  hashCanonicalJson,
} = require("../verification-contracts.js");
const {
  scanExistingFindingFootprint,
} = require("./record-candidate-claim.js");

function severityForClaim(severity) {
  return severity === "info" ? "informational" : severity;
}

function recordPhysicalCandidateClaim(args) {
  if (args == null || typeof args !== "object" || Array.isArray(args)) {
    throw new ToolError(
      ERROR_CODES.INVALID_ARGUMENTS,
      "bob_record_physical_candidate_claim args must be a plain object",
    );
  }
  if (args.force_record != null && typeof args.force_record !== "boolean") {
    throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, "force_record must be a boolean");
  }
  const assignment = normalizePhysicalAssignmentContext(args.assignment);
  const domain = args.target_domain;

  return withSessionLock(domain, () => {
    let nucleus;
    try {
      nucleus = readVerifiedSessionNucleus(domain);
    } catch {
      throw new ToolError(
        ERROR_CODES.STATE_CONFLICT,
        "verified physical session nucleus is unavailable",
      );
    }
    if (!nucleus.physical_scope || nucleus.nucleus_hash !== assignment.session_nucleus_hash) {
      throw new ToolError(
        ERROR_CODES.SCOPE_BLOCKED,
        "physical assignment does not bind the current authorized session nucleus",
      );
    }
    if (physicalVerdictRuntimeReadiness().production_ready !== true) {
      throw new ToolError(
        ERROR_CODES.STATE_CONFLICT,
        "production physical verdict resolver is not installed",
      );
    }

    const verdict = resolvePhysicalVerdict({
      target_domain: domain,
      asset_locator: assignment.asset_locator,
      verified_verdict_ref: args.verified_verdict_ref,
    });
    if (physicalVerdictRuntimeReadiness().production_ready !== true) {
      throw new ToolError(
        ERROR_CODES.STATE_CONFLICT,
        "production physical verdict resolver changed during claim recording",
      );
    }
    const liveFinding = buildPhysicalFinding({
      title: args.title,
      severity: args.severity,
      cwe: args.cwe,
      description: args.description,
      impact: args.impact,
      verdict,
    });

    const scan = scanExistingFindingFootprint(domain);
    const existing = scan.dedupeIndex.get(liveFinding.finding_dedupe_key) || null;
    if (existing && args.force_record !== true) {
      return JSON.stringify({
        recorded: false,
        duplicate: true,
        finding_id: existing.finding_id,
        existing_finding_id: existing.finding_id,
        dedupe_key: liveFinding.finding_dedupe_key,
        total: scan.total,
        written_jsonl: claimsJsonlPath(domain),
        claim_id: existing.claim ? existing.claim.claim_id : null,
        capability_pack: "physical",
      });
    }

    const findingSequence = scan.maxNumber + 1;
    const finding = buildPersistedPhysicalFindingRecord({
      finding: liveFinding,
      id: `F-${findingSequence}`,
      target_domain: domain,
      assignment,
      ...(args.force_record === true ? { force_record: true } : {}),
    });
    const findingContentHash = hashCanonicalJson(finding);
    const claimInput = {
      target_domain: domain,
      title: finding.title,
      summary: finding.description,
      severity: severityForClaim(finding.severity),
      status: "candidate",
      created_at: typeof args.created_at === "string" && args.created_at.trim()
        ? args.created_at
        : new Date().toISOString(),
      surface_ids: [assignment.surface_id],
      impact: finding.impact,
      tags: ["capability_pack:physical", "finding_kind:physical_verified_transition"],
      evidence_refs: [{
        kind: "finding",
        finding_id: finding.id,
        content_hash: findingContentHash,
      }],
      payload: {
        subject_id: assignment.asset_locator,
        attack_class: finding.cwe || finding.finding_kind,
        surface_ref: assignment.surface_id,
        dedupe_key: finding.dedupe_key,
        physical_assignment: assignment,
        finding,
      },
    };
    const claim = appendCandidateClaim(claimInput);

    appendFrontierEvent({
      target_domain: domain,
      kind: "claim.candidate.linked",
      payload: {
        claim_id: claim.claim_id,
        finding_id: finding.id,
        surface_id: assignment.surface_id,
        capability_pack: "physical",
        verified_verdict_ref: finding.verified_verdict_ref,
        verification_projection_digest: finding.verification_projection_digest,
      },
      surface_id: assignment.surface_id,
      claim_id: claim.claim_id,
      source: { artifact: "claims.jsonl", tool: "bob_record_physical_candidate_claim" },
    });
    scheduleMaterialization(domain);

    safeAppendPipelineEventDirect(domain, "finding_recorded", {
      wave: null,
      agent: null,
      surface_id: assignment.surface_id,
      status: finding.severity,
      source: "bob_record_physical_candidate_claim",
      capability_pack: "physical",
      counts: {
        findings: scan.total + 1,
        validated: 1,
      },
    }, safeGovernanceContextForDomain(domain));

    return JSON.stringify({
      recorded: true,
      finding_id: finding.id,
      claim_id: claim.claim_id,
      total: scan.total + 1,
      finding_sequence: findingSequence,
      dedupe_key: finding.dedupe_key,
      capability_pack: "physical",
      asset_locator: finding.asset_locator,
      verified_verdict_ref: finding.verified_verdict_ref,
      verification_projection_digest: finding.verification_projection_digest,
      written_jsonl: claimsJsonlPath(domain),
      ...(finding.force_record === true ? { force_record: true } : {}),
    });
  });
}

const DIGEST_PATTERN = "^[a-f0-9]{64}$";
const OPAQUE_REF_PATTERN = "^[a-z][a-z0-9._-]{0,63}:[A-Za-z0-9][A-Za-z0-9._:@-]{0,190}$";
const ASSIGNMENT_SCHEMA = Object.freeze({
  type: "object",
  additionalProperties: false,
  properties: {
    version: { type: "integer", enum: [1] },
    capability_pack: { type: "string", enum: ["physical"] },
    capability_pack_version: { type: "integer", enum: [1] },
    evaluator_agent: { type: "string", enum: ["evaluator-physical-agent"] },
    brief_profile: { type: "string", enum: ["physical"] },
    surface_id: { type: "string", pattern: "^surface:[A-Za-z0-9][A-Za-z0-9._:@-]{0,190}$" },
    surface_type: { type: "string", minLength: 1, maxLength: 128 },
    surface_class: { type: "string", enum: ["physical"] },
    session_nucleus_hash: { type: "string", pattern: DIGEST_PATTERN },
    asset_locator: { type: "string", pattern: OPAQUE_REF_PATTERN },
    campaign_ref: { type: "string", pattern: "^physical-campaign:[A-Za-z0-9][A-Za-z0-9._:@-]{0,190}$" },
    assignment_context_digest: { type: "string", pattern: DIGEST_PATTERN },
    physical_resource_bundle_ref: { type: "string", pattern: "^physical-resource-bundle:[A-Za-z0-9][A-Za-z0-9._:@-]{0,190}$" },
    lifecycle_precondition: { type: "string", enum: ["no_active_effects"] },
    effect_authority: { type: "string", enum: ["broker_admission_required"] },
  },
  required: [
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
  ],
});

module.exports = Object.freeze({
  name: "bob_record_physical_candidate_claim",
  description:
    "Record a physical-native CandidateClaim from a server-owned verified verdict projection. Accepts only an opaque asset assignment and verified_verdict_ref; never accepts endpoint, URL, raw PoC, provider commands, or transport output.",
  inputSchema: {
    type: "object",
    additionalProperties: false,
    properties: {
      target_domain: {
        type: "string",
        minLength: 1,
        maxLength: 255,
        description: "Initialized session authority key, not an asset locator or URL.",
      },
      assignment: ASSIGNMENT_SCHEMA,
      verified_verdict_ref: {
        type: "string",
        pattern: "^physical-claim-verdict:[A-Za-z0-9][A-Za-z0-9._:@-]{0,190}$",
        description: "Opaque claim-verdict reference already committed by the physical experiment ledger.",
      },
      title: { type: "string", minLength: 1, maxLength: 240 },
      severity: {
        type: "string",
        enum: ["critical", "high", "medium", "low", "info"],
      },
      cwe: {
        type: "string",
        pattern: "^CWE-[1-9][0-9]{0,5}$",
      },
      description: { type: "string", minLength: 1, maxLength: 4000 },
      impact: { type: "string", minLength: 1, maxLength: 2000 },
      force_record: { type: "boolean" },
      created_at: { type: "string", format: "date-time" },
    },
    required: [
      "target_domain",
      "assignment",
      "verified_verdict_ref",
      "title",
      "severity",
      "description",
      "impact",
    ],
  },
  handler: recordPhysicalCandidateClaim,
  role_bundles: ["evaluator-physical"],
  mutating: true,
  global_preapproval: true,
  network_access: false,
  browser_access: false,
  scope_required: false,
  sensitive_output: false,
  session_artifacts_written: ["claims.jsonl", "frontier-events.jsonl"],
  required_session_axes: ["physical"],
  effect_surface: [],
});
