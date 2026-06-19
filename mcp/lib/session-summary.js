"use strict";

const fs = require("fs");
const {
  assertNonEmptyString,
} = require("./validation.js");
const {
  reportMarkdownPath,
} = require("./paths.js");
const {
  readSessionStateStrict,
} = require("./session-state-store.js");
const {
  readSessionArtifactSummary,
} = require("./pipeline-analytics.js");
const {
  readSessionNucleus,
} = require("./governance-store.js");
const {
  deriveLegacyPhaseFromLifecycleState,
  deriveLifecycleStateFromLegacyPhase,
} = require("./session-state-contracts.js");
const {
  LIFECYCLE_STATE_VALUES,
} = require("./governance-contracts.js");

// LIFECYCLE_STATE_VALUES is ordered SETUP -> OPEN_FRONTIER -> CLAIM_FREEZE ->
// VERIFY -> GRADE -> REPORT, which is the canonical "progress" ordering.
// phaseAtLeast still accepts legacy phase strings so existing readers do not
// need a rewrite during the deprecation window; both inputs are projected to
// their lifecycle state before comparison.
function phaseAtLeast(phase, requiredPhase) {
  const currentState = deriveLifecycleStateFromLegacyPhase(phase) || phase;
  const requiredState = deriveLifecycleStateFromLegacyPhase(requiredPhase) || requiredPhase;
  const current = LIFECYCLE_STATE_VALUES.indexOf(currentState);
  const required = LIFECYCLE_STATE_VALUES.indexOf(requiredState);
  return current >= 0 && required >= 0 && current >= required;
}

function evidenceStatus(artifacts) {
  if (artifacts.evidence.valid && artifacts.evidence.skipped) return "skipped";
  if (artifacts.evidence.valid) return "valid";
  if (artifacts.verification.final_reportable_count > 0) return "missing_or_invalid";
  return artifacts.evidence.exists ? "invalid" : "not_required";
}

function deriveBlockers(state, artifacts) {
  const blockers = [];
  for (const error of artifacts.artifact_errors.slice(0, 6)) {
    blockers.push(`artifact_error: ${error}`);
  }

  if (state.pending_wave != null) {
    const pending = artifacts.waves.find((wave) => wave.wave_number === state.pending_wave);
    if (pending) {
      blockers.push(`wave_${state.pending_wave}_pending: ${pending.received_agents.length}/${pending.assignments_total} handoffs received`);
    } else {
      blockers.push(`wave_${state.pending_wave}_pending: readiness unavailable`);
    }
  }

  if (phaseAtLeast(state.phase, "GRADE") && !artifacts.verification.rounds.final.valid) {
    blockers.push("final_verification_missing_or_invalid");
  }

  if (
    phaseAtLeast(state.phase, "GRADE") &&
    artifacts.verification.final_reportable_count > 0 &&
    !artifacts.evidence.valid
  ) {
    const missing = artifacts.evidence.missing_finding_ids.length
      ? ` (${artifacts.evidence.missing_finding_ids.join(", ")})`
      : "";
    blockers.push(`evidence_missing_or_invalid${missing}`);
  }

  if (phaseAtLeast(state.phase, "REPORT") && !artifacts.grade.valid) {
    blockers.push("grade_missing_or_invalid");
  }

  if (state.phase === "REPORT" && !artifacts.report.present) {
    blockers.push("report_missing");
  }

  return blockers.slice(0, 10);
}

function nextAction(state, artifacts, blockers) {
  if (state.pending_wave != null) {
    return `Resume and settle pending wave ${state.pending_wave} with bob_apply_wave_merge.`;
  }
  if (blockers.includes("report_missing")) {
    return "Run the report writer, then call bob_read_session_summary again.";
  }
  if (artifacts.grade.verdict === "HOLD") {
    return "Return to OPEN_FRONTIER with grader feedback, then re-run CLAIM_FREEZE through REPORT.";
  }
  // Lifecycle-state-driven narration. The state field is the canonical
  // projection of nucleus.lifecycle_state into state.json; older sessions
  // without the field fall through the chain via the legacy phase mapping
  // emitted by session-state-contracts.
  const lifecycleState = state.lifecycle_state;
  if (lifecycleState === "SETUP") {
    return "Complete SETUP (seed discovery, auth capture as needed), then bob_advance_session to OPEN_FRONTIER.";
  }
  if (lifecycleState === "OPEN_FRONTIER") {
    return "Schedule or resume the next evaluator wave; freeze a claim batch with bob_advance_session to CLAIM_FREEZE.";
  }
  if (lifecycleState === "CLAIM_FREEZE") {
    return "Inspect the frozen claim batch, then bob_advance_session to VERIFY (or back to OPEN_FRONTIER).";
  }
  if (lifecycleState === "VERIFY") {
    return "Run verification rounds and evidence collection for final reportables.";
  }
  if (lifecycleState === "GRADE") {
    return "Run grader and read back the grade verdict.";
  }
  if (lifecycleState === "REPORT") {
    return artifacts.report.present
      ? "Present the compact summary and report path to the operator."
      : "Run report-writer and write report.md.";
  }
  return "Inspect session state through MCP readers.";
}

// Operator-actionability ordering: kinds the operator can resolve
// fastest first. auth/egress have registry-based unblock paths;
// funded_wallet/key_material/external_credential require operator
// procurement. Lower number = higher actionability.
const BLOCKED_PREREQ_KIND_ACTIONABILITY = Object.freeze({
  auth_missing: 0,
  egress_unreachable: 1,
  funded_wallet_missing: 2,
  key_material_missing: 3,
  external_credential_missing: 4,
});

function summarizeBlockedPrereqs(state) {
  // Folding "kind + identifier_hint" groups across blocked surfaces uses
  // state.blocked_prereq_history (the durable per-wave audit trail) as the
  // grouping source after D.3 removed state.terminally_blocked. The
  // frontier projection identifies the currently-blocked surface set;
  // groups are restricted to entries for those surfaces.
  const groups = new Map();
  let blockedSurfaceIds = [];
  if (state && typeof state.target === "string" && state.target) {
    try {
      const { currentBlockers } = require("./frontier-projections.js");
      blockedSurfaceIds = currentBlockers(state.target).map((entry) => entry.surface_id);
    } catch {
      blockedSurfaceIds = [];
    }
  }
  const blockedSet = new Set(blockedSurfaceIds);
  const history = Array.isArray(state.blocked_prereq_history) ? state.blocked_prereq_history : [];
  const surfaceWaveLookup = new Map();
  // Sort history by (surface, wave ASC) so the latest reason for a (kind,
  // identifier_hint) tuple wins.
  const sortedHistory = [...history].sort((a, b) => (a.wave || 0) - (b.wave || 0));
  for (const entry of sortedHistory) {
    if (!entry || typeof entry.surface_id !== "string" || !blockedSet.has(entry.surface_id)) continue;
    const hint = entry.identifier_hint || null;
    const key = `${entry.kind}\t${hint || ""}`;
    if (!groups.has(key)) {
      groups.set(key, {
        kind: entry.kind,
        identifier_hint: hint,
        surface_count: 0,
        surface_ids: [],
        latest_reason: null,
        latest_blocked_at_wave: 0,
      });
    }
    const group = groups.get(key);
    if (!group.surface_ids.includes(entry.surface_id)) {
      group.surface_ids.push(entry.surface_id);
      group.surface_count += 1;
    }
    if (entry.reason) {
      group.latest_reason = entry.reason;
    }
    const wave = Number.isInteger(entry.wave) ? entry.wave : 0;
    if (wave > group.latest_blocked_at_wave) {
      group.latest_blocked_at_wave = wave;
    }
    surfaceWaveLookup.set(entry.surface_id, Math.max(surfaceWaveLookup.get(entry.surface_id) || 0, wave));
  }
  return {
    total_blocked_surfaces: blockedSurfaceIds.length,
    by_kind: Array.from(groups.values()).sort((a, b) => {
      const aRank = BLOCKED_PREREQ_KIND_ACTIONABILITY[a.kind] ?? 99;
      const bRank = BLOCKED_PREREQ_KIND_ACTIONABILITY[b.kind] ?? 99;
      if (aRank !== bRank) return aRank - bRank;
      return (a.identifier_hint || "").localeCompare(b.identifier_hint || "");
    }),
  };
}

function readSessionSummary(args) {
  const domain = assertNonEmptyString(args.target_domain, "target_domain");
  const { state } = readSessionStateStrict(domain);
  const artifacts = readSessionArtifactSummary(domain);
  const blockers = deriveBlockers(state, artifacts);
  const reportPath = reportMarkdownPath(domain);
  let nucleusHash = null;
  let lifecycleState = null;
  try {
    const nucleus = readSessionNucleus(domain);
    nucleusHash = nucleus && typeof nucleus.nucleus_hash === "string" ? nucleus.nucleus_hash : null;
    lifecycleState = nucleus && typeof nucleus.lifecycle_state === "string" ? nucleus.lifecycle_state : null;
  } catch (_error) {
    nucleusHash = null;
    lifecycleState = null;
  }

  // Step 4: state.json is a pure projection of nucleus.lifecycle_state. Derive
  // the legacy `phase` from the nucleus (the single source of truth) so a
  // partially-written state.json can never make this summary disagree with the
  // lifecycle authority. Fall back to state.phase only when the nucleus carries
  // no lifecycle_state (legacy disk that predates the nucleus).
  const derivedPhase = deriveLegacyPhaseFromLifecycleState(lifecycleState);
  const phase = derivedPhase || state.phase;

  return JSON.stringify({
    version: 1,
    summary: {
      target: domain,
      phase,
      nucleus_hash: nucleusHash,
      lifecycle_state: lifecycleState,
      auth_status: state.auth_status,
      checkpoint_mode: state.checkpoint_mode,
      block_internal_hosts: state.block_internal_hosts,
      block_internal_hosts_source: state.block_internal_hosts_source,
      egress_profile: state.egress_profile,
      egress_region: state.egress_region,
      proxy_configured: state.proxy_configured,
      egress_profile_identity_hash: state.egress_profile_identity_hash,
      egress_profile_identity_version: state.egress_profile_identity_version,
      operator_note: state.operator_note,
      waves_run: state.evaluation_wave,
      pending_wave: state.pending_wave,
      finding_total: artifacts.findings.total,
      final_reportable_count: artifacts.verification.final_reportable_count,
      blocked_prereqs: summarizeBlockedPrereqs(state),
      evidence_status: {
        status: evidenceStatus(artifacts),
        exists: artifacts.evidence.exists,
        valid: artifacts.evidence.valid,
        skipped: artifacts.evidence.skipped,
        packs_count: artifacts.evidence.packs_count,
        reportable_findings_covered: artifacts.evidence.reportable_findings_covered,
        missing_finding_ids: artifacts.evidence.missing_finding_ids,
      },
      grade_verdict: artifacts.grade.verdict,
      grade: {
        exists: artifacts.grade.exists,
        valid: artifacts.grade.valid,
        verdict: artifacts.grade.verdict,
        total_score: artifacts.grade.total_score,
      },
      report: {
        present: fs.existsSync(reportPath),
        path: reportPath,
      },
      blockers,
      next_action: nextAction(state, artifacts, blockers),
    },
  });
}

module.exports = {
  readSessionSummary,
};
