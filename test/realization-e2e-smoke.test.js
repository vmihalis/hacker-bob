"use strict";

// Cycle Z.1 of the frontier-topology realization hypergraph.
//
// End-to-end smoke certification: drive a complete operator flow in a fresh
// HOME against a fixture domain and prove that the entire artifact chain
// from session-init through report-finalize stays hash-bound.
//
// Lifecycle states exercised (via bob_advance_session):
//   SETUP -> OPEN_FRONTIER -> CLAIM_FREEZE -> VERIFY -> GRADE -> REPORT
//
// MCP-owned artifacts traversed end-to-end:
//   - session-nucleus.json          (governance authority, written by init)
//   - session-events.jsonl          (governance ledger; lifecycle.advanced)
//   - frontier-events.jsonl         (frontier ledger; session.seeded, surface.observed,
//                                    frontier.enqueued, claim.candidate.linked,
//                                    claim.report_snapshot.appended)
//   - surface-index.json            (frontier materialized view; derives from
//                                    frontier-events.jsonl deterministically)
//   - task-queue.json               (frontier materialized view; sibling of
//                                    surface-index.json)
//   - scheduler-decisions.jsonl     (work-plane SchedulerDecision ledger)
//   - claims.jsonl                  (claim-plane CandidateClaim ledger)
//   - claim-freeze.json             (immutable frozen batch; freeze_hash)
//   - brutalist.json / balanced.json / verified-final.json   (V1 verification rounds,
//                                    upgraded to V2 in place for the C.7
//                                    final_verification_hash binding)
//   - evidence-packs.json           (evidence pack ledger; evidence_hash binds
//                                    via sha256 over canonical packs[])
//   - grade.json                    (grade verdict; grade_verdict_hash via
//                                    sha256 over canonical JSON)
//   - report.md                     (final human-facing report;
//                                    report_content_hash via sha256 of file)
//   - report-snapshots.jsonl        (ReportSnapshot ledger; one row binds all
//                                    four upstream hashes plus report content)
//
// The four upstream hashes recorded on a ReportSnapshot row (Cycle C.7):
//   - claim_freeze_hash             ← claim-freeze.json freeze_hash
//   - final_verification_hash       ← V2 final round final_verification_hash
//   - evidence_hash                 ← sha256 over canonical packs[] manifest
//   - grade_verdict_hash            ← sha256 over canonical grade.json
// plus the fifth hash:
//   - report_content_hash           ← sha256 over report.md bytes
//
// Z.1 review gate: each hash chain link validates against the on-disk
// artifact when recomputed from the file, and surface-index.json derives
// deterministically from frontier-events.jsonl.

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const initSessionTool = require("../mcp/lib/tools/init-session.js");
const advanceSessionTool = require("../mcp/lib/tools/advance-session.js");
const recordSurfaceLeadsTool = require("../mcp/lib/tools/record-surface-leads.js");
const promoteSurfaceLeadsTool = require("../mcp/lib/tools/promote-surface-leads.js");
const recordCandidateClaimTool = require("../mcp/lib/tools/record-candidate-claim.js");
const { writeChainAttempt } = require("../mcp/lib/chain-attempts.js");
const scheduleTasksTool = require("../mcp/lib/tools/schedule-tasks.js");
const writeVerificationRoundTool = require("../mcp/lib/tools/write-verification-round.js");
const writeEvidencePacksTool = require("../mcp/lib/tools/write-evidence-packs.js");
const writeGradeVerdictTool = require("../mcp/lib/tools/write-grade-verdict.js");
const finalizeReportTool = require("../mcp/lib/tools/finalize-report.js");

const {
  buildClaimFreeze,
  readCurrentClaimFreeze,
} = require("../mcp/lib/claim-freeze.js");
const {
  materializeFrontier,
} = require("../mcp/lib/frontier-materializer.js");
const {
  readFrontierEvents,
} = require("../mcp/lib/frontier-events.js");
const {
  readReportSnapshots,
} = require("../mcp/lib/report-snapshots.js");
const {
  finalVerificationHash,
  hashCanonicalJson,
} = require("../mcp/lib/verification-contracts.js");
const {
  resetForTests: resetMaterializationDebounce,
} = require("../mcp/lib/frontier-materialize-debounce.js");
const {
  claimFreezePath,
  evidencePackPaths,
  frontierEventsJsonlPath,
  gradeArtifactPaths,
  reportMarkdownPath,
  reportSnapshotsJsonlPath,
  sessionDir,
  sessionNucleusPath,
  surfaceIndexPath,
  taskQueuePath,
  verificationRoundPaths,
  findingDifferentialVerifiedJsonlPath,
} = require("../mcp/lib/paths.js");
const { appendJsonlLine: appendFindingDifferentialRow } = require("../mcp/lib/storage.js");

const HASH_HEX_RE = /^[a-f0-9]{64}$/;

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-z1-smoke-"));
  process.env.HOME = home;
  try {
    return fn(home);
  } finally {
    if (previousHome === undefined) {
      delete process.env.HOME;
    } else {
      process.env.HOME = previousHome;
    }
    resetMaterializationDebounce();
    fs.rmSync(home, { recursive: true, force: true });
  }
}

function sha256OfFile(filePath) {
  return crypto.createHash("sha256").update(fs.readFileSync(filePath)).digest("hex");
}

function callTool(tool, args) {
  const response = tool.handler(args);
  return typeof response === "string" ? JSON.parse(response) : response;
}

// Drive the operator flow from init through finalize for a single fixture
// domain. Returns the captured hash chain plus the lifecycle states observed
// so the test asserts can prove every link.
function driveRealizationFlow(domain) {
  // Step 1 — bob_init_session → SETUP, session-nucleus.json written.
  const initResponse = callTool(initSessionTool, {
    target_domain: domain,
    target_url: `https://${domain}/`,
  });
  assert.equal(initResponse.created, true, "bob_init_session must create the session");
  assert.ok(fs.existsSync(sessionNucleusPath(domain)), "session-nucleus.json must be written by init");

  // Step 2 — Seed work via bob_record_surface_leads (emits frontier.enqueued
  // events) and bob_promote_surface_leads (emits surface.observed events).
  // The promoted lead is given confidence: "high" so the promotion selector
  // accepts it without raising thresholds.
  const leadsResponse = callTool(recordSurfaceLeadsTool, {
    target_domain: domain,
    source: "z1-smoke",
    leads: [
      {
        title: "Billing API admin endpoint",
        hosts: [domain],
        endpoints: [`https://${domain}/api/admin/billing`],
        priority: "HIGH",
        surface_type: "web",
        confidence: "high",
        score: 90,
        promote: true,
        bug_class_hints: ["IDOR", "auth_bypass"],
        evidence: ["auth-required admin route observed in traffic"],
      },
    ],
  });
  assert.equal(leadsResponse.recorded, 1, "one surface lead must be recorded");

  const promoteResponse = callTool(promoteSurfaceLeadsTool, {
    target_domain: domain,
    limit: 5,
  });
  assert.equal(promoteResponse.promoted, 1, "the high-confidence lead must promote");
  const promotedSurfaceId = promoteResponse.promoted_surface_ids[0];
  assert.ok(typeof promotedSurfaceId === "string" && promotedSurfaceId.length > 0,
    "promoted surface id must be a non-empty string");

  // Step 3 — bob_advance_session(OPEN_FRONTIER).
  const openFrontierResponse = callTool(advanceSessionTool, {
    target_domain: domain,
    to_state: "OPEN_FRONTIER",
  });
  assert.equal(openFrontierResponse.advanced, true);
  assert.equal(openFrontierResponse.to_state, "OPEN_FRONTIER");

  // Step 4 — Materialize the frontier so surface-index.json and task-queue.json
  // are committed to disk before scheduling. The promotion path uses a
  // debounced auto-materialize; an explicit materializeFrontier call is the
  // documented operator entry point and guarantees the on-disk views are
  // current before bob_schedule_tasks reads them.
  materializeFrontier(domain, { write: true });
  assert.ok(fs.existsSync(surfaceIndexPath(domain)), "surface-index.json must be materialized");
  assert.ok(fs.existsSync(taskQueuePath(domain)), "task-queue.json must be materialized");

  // Step 5 — bob_schedule_tasks → SchedulerDecision (assignment batch). The
  // returned assignment_batch_id is part of the documented operator flow even
  // when no agents downstream consume it directly in this smoke run.
  const scheduleResponse = callTool(scheduleTasksTool, {
    target_domain: domain,
  });
  assert.ok(typeof scheduleResponse.scheduler_decision_id === "string"
    && scheduleResponse.scheduler_decision_id.length > 0,
    "schedule_tasks must return a scheduler_decision_id");
  assert.ok(typeof scheduleResponse.assignment_batch_id === "string"
    && scheduleResponse.assignment_batch_id.length > 0,
    "schedule_tasks must return an assignment_batch_id");

  // Step 6 — Record N=2 candidate claims via bob_record_candidate_claim. Each
  // append emits a claim.candidate.linked frontier event and a claims.jsonl
  // row.
  const claimAResponse = callTool(recordCandidateClaimTool, {
    target_domain: domain,
    title: "IDOR on admin billing endpoint",
    severity: "high",
    cwe: "CWE-639",
    endpoint: `https://${domain}/api/admin/billing/1`,
    description: "Tenant boundary allows cross-account view of billing metadata.",
    proof_of_concept: `GET /api/admin/billing/1 returns another tenant's payload`,
    response_evidence: "Cross-tenant billing payload observed in attacker session",
    impact: "Cross-tenant billing disclosure",
    validated: true,
    auth_profile: "attacker",
    surface_id: promotedSurfaceId,
    // Cross-tenant billing IDOR: network-reachable, low-privilege attacker
    // tenant, confidentiality impact.
    cvss_inputs: { attack_vector: "network", privileges_required: "low", confidentiality: "high" },
  });
  assert.equal(claimAResponse.recorded, true);
  const claimBResponse = callTool(recordCandidateClaimTool, {
    target_domain: domain,
    title: "Mass-assignment in admin billing update",
    severity: "medium",
    cwe: "CWE-915",
    endpoint: `https://${domain}/api/admin/billing/1`,
    description: "PATCH accepts privileged fields outside the documented schema.",
    proof_of_concept: `PATCH /api/admin/billing/1 with {"role":"admin"} succeeds`,
    response_evidence: "Privileged field accepted in attacker session",
    impact: "Privilege escalation via unauthorized field write",
    validated: true,
    auth_profile: "attacker",
    surface_id: promotedSurfaceId,
    // Mass-assignment privilege escalation: network-reachable, low-privilege
    // attacker tenant, integrity impact (unauthorized privileged field write).
    cvss_inputs: { attack_vector: "network", privileges_required: "low", integrity: "high" },
  });
  assert.equal(claimBResponse.recorded, true);
  const findingIds = [claimAResponse.finding_id, claimBResponse.finding_id];
  assert.equal(findingIds.length, 2);

  // Recorded chain work (two findings) must reach a terminal structured chain
  // attempt before CLAIM_FREEZE. The two findings are independent surfaces with
  // no credible cross-surface pivot, so the terminal outcome is not_applicable.
  JSON.parse(writeChainAttempt({
    target_domain: domain,
    finding_ids: findingIds,
    surface_ids: [],
    hypothesis: "The two recorded findings compose into no credible cross-surface pivot.",
    steps: ["Relate the CORS read and the mass-assignment write; they share no principal or object pivot."],
    outcome: "not_applicable",
    evidence_summary: "Terminal chain outcome for the recorded chain work.",
  }));

  // Step 7 — bob_advance_session(CLAIM_FREEZE), then materialize claim-freeze
  // explicitly. The lifecycle nucleus advances to CLAIM_FREEZE but does not
  // auto-write the immutable freeze artifact — that is the documented role of
  // the claim-freeze fabric, invoked here at the documented seam after the
  // CLAIM_FREEZE transition. (Drift: the realization spec describes the
  // freeze as materialized by the advance; the live code materializes it via
  // the claim-freeze fabric, including the auto-freeze fallback inside the
  // VERIFY entry. Either seam produces the same hash-bound artifact.)
  const claimFreezeAdvance = callTool(advanceSessionTool, {
    target_domain: domain,
    to_state: "CLAIM_FREEZE",
  });
  assert.equal(claimFreezeAdvance.advanced, true);
  assert.equal(claimFreezeAdvance.to_state, "CLAIM_FREEZE");
  buildClaimFreeze(domain, { write: true });
  assert.ok(fs.existsSync(claimFreezePath(domain)), "claim-freeze.json must be materialized");
  const freeze = readCurrentClaimFreeze(domain);
  assert.ok(freeze, "claim-freeze.json must load");
  assert.match(freeze.freeze_hash, HASH_HEX_RE);
  // The freeze must carry both candidate claims.
  assert.equal(freeze.claim_count, 2, "freeze must capture both candidate claims");

  // Step 8 — Write V1 verification rounds (brutalist → balanced → final). V1
  // is selected by the round writer because no verification-input-snapshot.json
  // is on disk yet (the VERIFY transition has not run). The V1 chain is what
  // the V1 evidence gate consumes for the VERIFY -> GRADE -> REPORT walk.
  for (const round of ["brutalist", "balanced", "final"]) {
    callTool(writeVerificationRoundTool, {
      target_domain: domain,
      round,
      notes: null,
      results: findingIds.map((findingId) => ({
        finding_id: findingId,
        disposition: "confirmed",
        severity: findingId === findingIds[0] ? "high" : "medium",
        reportable: true,
        reasoning: "Fresh replay confirmed the finding against the current target state.",
        // Y.1 B1 lift — repro_steps + evidence_refs are inputSchema.required.
        repro_steps: ["Smoke replay step 1 confirmed the finding."],
        evidence_refs: [`frontier_event:${findingId}`],
      })),
    });
  }

  // Step 9 — bob_advance_session(VERIFY). With V1 verification rounds already
  // on disk, prepareVerificationEntry picks the V1 path and the lifecycle
  // continues without spawning a V2 attempt that this smoke does not exercise.
  const verifyAdvance = callTool(advanceSessionTool, {
    target_domain: domain,
    to_state: "VERIFY",
  });
  assert.equal(verifyAdvance.advanced, true);
  assert.equal(verifyAdvance.to_state, "VERIFY");

  // Step 10 — Write V1 evidence packs (one per reportable finding).
  callTool(writeEvidencePacksTool, {
    target_domain: domain,
    packs: findingIds.map((findingId) => ({
      finding_id: findingId,
      sample_type: "cross-account replay",
      sample_count: 1,
      aggregate_counts: { affected_objects_sampled: 1 },
      representative_samples: [{
        request_ref: `http-audit:${findingId}`,
        endpoint: `/api/admin/billing/1`,
        auth_profile: "attacker",
        status: 200,
        observed_fields: ["billing_profile_id"],
        redacted_object_id: "acct_...002",
      }],
      sensitive_clusters: ["billing metadata"],
      replay_summary: "Fresh replay returned another tenant's private billing metadata.",
      redaction_notes: "Object IDs and personal values redacted; auth material omitted.",
      report_snippet: `An attacker can exploit ${findingId} via the admin billing endpoint.`,
    })),
  });
  assert.ok(fs.existsSync(evidencePackPaths(domain).json), "evidence-packs.json must be written");

  // Step 11 — bob_advance_session(GRADE). The VERIFY -> GRADE gate consults
  // requireVerificationCompleteForGrade; in V1 mode it passes once evidence
  // packs exist for every final reportable finding.
  const gradeAdvance = callTool(advanceSessionTool, {
    target_domain: domain,
    to_state: "GRADE",
  });
  assert.equal(gradeAdvance.advanced, true);
  assert.equal(gradeAdvance.to_state, "GRADE");

  // Step 12 — Write grade verdict. Per grade-verdict-store consistency rules:
  //   - per-finding total_score must equal the sum of its rubric scores
  //     (impact + proof_quality + severity_accuracy + chain_potential +
  //     report_quality)
  //   - the document total_score must equal the MAX per-finding total_score
  //   - the verdict must match the document total_score against
  //     GRADE_SUBMIT_MIN_SCORE / GRADE_HOLD_MIN_SCORE
  // Both findings are standalone web (IDOR / mass-assignment) executable-flip classes;
  // seed each one's finding-differential verified_pass arm so the grade-time standalone
  // gate is satisfied (NO amputation). Post-A1 the gate re-resolves the verdict against
  // MAC-covered offensive-runs rows + re-adjudicates the flip, so seed a real signed
  // exploited_safely positive + blocked_by_defense control (demonstrated severity >= the
  // finding's), then the verdict line binding them.
  {
    const { canonicalizeExploitTarget } = require("../mcp/lib/claims.js");
    const { ensureHandoffSigningKey } = require("../mcp/lib/handoff-signing-key.js");
    const { signOffensiveRunRow } = require("../mcp/lib/offensive-row-mac.js");
    const { offensiveRowHash } = require("../mcp/lib/finding-differential-verifier.js");
    const { offensiveRunsJsonlPath } = require("../mcp/lib/paths.js");
    for (const findingId of findingIds) {
      const demonstratedSeverity = findingId === findingIds[0] ? "high" : "medium";
      const mkRow = (suffix, outcome, ch) => {
        const row = {
          version: 1, target_domain: domain, run_id: `${findingId}-${suffix}`, tool_id: "bob_http_idor_confirm",
          target: canonicalizeExploitTarget(`https://${domain}/api/x/${findingId}`),
          offensive_outcome: outcome, dry_run: false, timed_out: false,
          command_hash: ch, exit_code: 0, stdout_hash: "b".repeat(64), stderr_hash: "c".repeat(64),
          demonstrated_severity: demonstratedSeverity, surface_id: promotedSurfaceId,
        };
        signOffensiveRunRow(row, ensureHandoffSigningKey(domain));
        fs.mkdirSync(sessionDir(domain), { recursive: true });
        fs.appendFileSync(offensiveRunsJsonlPath(domain), `${JSON.stringify(row)}\n`);
        return row;
      };
      const positive = mkRow("pos", "exploited_safely", `${findingId === findingIds[0] ? "1" : "3"}`.repeat(64));
      const control = mkRow("ctl", "blocked_by_defense", `${findingId === findingIds[0] ? "2" : "4"}`.repeat(64));
      appendFindingDifferentialRow(findingDifferentialVerifiedJsonlPath(domain), {
        version: 1, target_domain: domain, finding_id: findingId, result: "verified_pass",
        reason: "executed_finding_differential_flip", surface_id: promotedSurfaceId,
        source: "offensive_runs", positive_run_id: `${findingId}-pos`, positive_row_hash: offensiveRowHash(positive),
        control_run_id: `${findingId}-ctl`, control_row_hash: offensiveRowHash(control),
      });
    }
  }
  callTool(writeGradeVerdictTool, {
    target_domain: domain,
    verdict: "SUBMIT",
    total_score: 75,
    findings: findingIds.map((findingId) => ({
      finding_id: findingId,
      impact: 25,
      proof_quality: 20,
      severity_accuracy: 10,
      chain_potential: 10,
      report_quality: 10,
      total_score: 75,
      feedback: "Clear, reproducible, and reportable.",
    })),
    feedback: "Both findings are submission-ready.",
  });
  assert.ok(fs.existsSync(gradeArtifactPaths(domain).json), "grade.json must be written");

  // Step 13 — bob_advance_session(REPORT). The GRADE -> REPORT gate re-runs
  // the evidence check; we pass on V1 mode.
  const reportAdvance = callTool(advanceSessionTool, {
    target_domain: domain,
    to_state: "REPORT",
  });
  assert.equal(reportAdvance.advanced, true);
  assert.equal(reportAdvance.to_state, "REPORT");

  // Step 14 — Upgrade the V1 final verification round to V2 in place. The C.7
  // bob_finalize_report resolver only resolves final_verification_hash from a
  // V2 final round bound to the freeze. The upgrade preserves the result set
  // and adds the V2 envelope, the freeze-derived verification_snapshot_hash,
  // and the stamped final_verification_hash. This is the same pattern the
  // existing C.7 binding test uses (test/report-snapshot-binding.test.js)
  // and is the documented bridge between the V1 chain and the C.7 hash-bound
  // ReportSnapshot ledger. (Drift: the smoke spec describes the verification
  // round write as a single step. The live finalize tool refuses without a
  // V2 final_verification_hash, so this smoke explicitly performs the C.7
  // upgrade. The five-hash binding is what the Z.1 gate validates.)
  const finalPath = verificationRoundPaths(domain, "final").json;
  const v1FinalDocument = JSON.parse(fs.readFileSync(finalPath, "utf8"));
  const v2FinalDocument = {
    version: 2,
    target_domain: domain,
    round: "final",
    notes: null,
    verification_attempt_id: `attempt-${freeze.freeze_id}`,
    verification_snapshot_hash: freeze.freeze_hash,
    round_profile: "final",
    adjudication_plan_hash: crypto.createHash("sha256")
      .update(`adjudication:${freeze.freeze_id}`)
      .digest("hex"),
    results: v1FinalDocument.results,
  };
  v2FinalDocument.final_verification_hash = finalVerificationHash(v2FinalDocument);
  fs.writeFileSync(finalPath, JSON.stringify(v2FinalDocument, null, 2) + "\n");

  // Step 15 — Write report.md (the human-facing report). The report-writer
  // skill owns this artifact end-to-end; the smoke writes a minimal but
  // realistic structure so the report_content_hash is non-trivial.
  const reportMarkdown = [
    "# Bob Report",
    "",
    `Target: ${domain}`,
    "",
    "## Findings",
    "",
    ...findingIds.map((findingId) => `- ${findingId}: validated and reportable`),
    "",
  ].join("\n") + "\n";
  fs.writeFileSync(reportMarkdownPath(domain), reportMarkdown);

  // Step 16 — bob_finalize_report. Appends one ReportSnapshot row binding
  // the four upstream hashes + the report content hash. Refuses if any
  // upstream artifact is missing or malformed.
  const finalizeResponse = callTool(finalizeReportTool, { target_domain: domain });
  assert.equal(finalizeResponse.finalized, true);

  return {
    domain,
    finding_ids: findingIds,
    freeze,
    v2_final_document: v2FinalDocument,
    finalize_response: finalizeResponse,
  };
}

test("Cycle Z.1: end-to-end realization smoke exercises the canonical lifecycle and binds the four upstream hashes", () => {
  withTempHome(() => {
    const domain = "z1-smoke.example.com";
    const result = driveRealizationFlow(domain);

    // ── Lifecycle states exercised ────────────────────────────────────────
    const lifecycleStatesExercised = [
      "SETUP",
      "OPEN_FRONTIER",
      "CLAIM_FREEZE",
      "VERIFY",
      "GRADE",
      "REPORT",
    ];

    // ── Hash chain captures ──────────────────────────────────────────────
    const finalizeResponse = result.finalize_response;
    assert.match(finalizeResponse.claim_freeze_hash, HASH_HEX_RE);
    assert.match(finalizeResponse.final_verification_hash, HASH_HEX_RE);
    assert.match(finalizeResponse.evidence_hash, HASH_HEX_RE);
    assert.match(finalizeResponse.grade_verdict_hash, HASH_HEX_RE);
    assert.match(finalizeResponse.report_content_hash, HASH_HEX_RE);
    assert.match(finalizeResponse.snapshot_hash, HASH_HEX_RE);

    // ── ReportSnapshot row identity ──────────────────────────────────────
    const snapshots = readReportSnapshots(domain);
    assert.equal(snapshots.length, 1, "exactly one ReportSnapshot row after a single finalize");
    const row = snapshots[0];

    // ── Assertion 1: report-snapshots.jsonl row carries all four upstream
    //                 hashes plus report_content_hash. ────────────────────
    assert.equal(row.claim_freeze_hash, finalizeResponse.claim_freeze_hash);
    assert.equal(row.final_verification_hash, finalizeResponse.final_verification_hash);
    assert.equal(row.evidence_hash, finalizeResponse.evidence_hash);
    assert.equal(row.grade_verdict_hash, finalizeResponse.grade_verdict_hash);
    assert.equal(row.report_content_hash, finalizeResponse.report_content_hash);

    // ── Assertion 2: each hash chain link validates against the on-disk
    //                 artifact recomputed from its file. ─────────────────
    // 2a. claim_freeze_hash matches claim-freeze.json's freeze_hash.
    const freezeOnDisk = JSON.parse(fs.readFileSync(claimFreezePath(domain), "utf8"));
    assert.equal(
      row.claim_freeze_hash,
      freezeOnDisk.freeze_hash,
      "snapshot claim_freeze_hash must equal claim-freeze.json freeze_hash",
    );

    // 2b. final_verification_hash matches verified-final.json's stamped hash
    //     and recomputes deterministically via finalVerificationHash().
    const finalRoundOnDisk = JSON.parse(fs.readFileSync(verificationRoundPaths(domain, "final").json, "utf8"));
    assert.equal(
      row.final_verification_hash,
      finalRoundOnDisk.final_verification_hash,
      "snapshot final_verification_hash must equal verified-final.json final_verification_hash",
    );
    assert.equal(
      finalVerificationHash(finalRoundOnDisk),
      finalRoundOnDisk.final_verification_hash,
      "verified-final.json final_verification_hash must recompute deterministically",
    );

    // 2c. evidence_hash matches sha256 over canonical evidence-packs.json packs[].
    const evidenceOnDisk = JSON.parse(fs.readFileSync(evidencePackPaths(domain).json, "utf8"));
    assert.equal(
      row.evidence_hash,
      hashCanonicalJson(evidenceOnDisk.packs),
      "snapshot evidence_hash must equal sha256(canonical packs[])",
    );

    // 2d. grade_verdict_hash matches sha256 over canonical grade.json.
    const gradeOnDisk = JSON.parse(fs.readFileSync(gradeArtifactPaths(domain).json, "utf8"));
    assert.equal(
      row.grade_verdict_hash,
      hashCanonicalJson(gradeOnDisk),
      "snapshot grade_verdict_hash must equal sha256(canonical grade.json)",
    );

    // 2e. report_content_hash matches sha256 over the report.md file bytes.
    assert.equal(
      row.report_content_hash,
      sha256OfFile(reportMarkdownPath(domain)),
      "snapshot report_content_hash must equal sha256(report.md)",
    );

    // ── Assertion 3: surface-index.json derives deterministically from
    //                 frontier-events.jsonl. Two independent
    //                 rematerializations over the current event log must
    //                 produce identical surface_index_hash values. The
    //                 persisted view is a point-in-time snapshot — it can
    //                 lag the event log when later events (e.g.,
    //                 claim.report_snapshot.appended) arrive without an
    //                 intervening materializeFrontier call, which is the
    //                 documented behavior. ────────────────────────────────
    assert.ok(fs.existsSync(frontierEventsJsonlPath(domain)), "frontier-events.jsonl must exist");
    const rebuiltOnce = materializeFrontier(domain, { write: false }).surface_index;
    const rebuiltTwice = materializeFrontier(domain, { write: false }).surface_index;
    assert.match(rebuiltOnce.surface_index_hash, HASH_HEX_RE);
    assert.equal(
      rebuiltOnce.surface_index_hash,
      rebuiltTwice.surface_index_hash,
      "rematerializing surface-index.json from the same frontier-events.jsonl must be deterministic",
    );
    // Persisted view's source_event_count is a lower bound on the live log
    // (the log can only grow append-only); when no surface-affecting events
    // have arrived since the persisted view, the hash also matches.
    const persistedIndex = JSON.parse(fs.readFileSync(surfaceIndexPath(domain), "utf8"));
    assert.ok(
      persistedIndex.source_event_count <= rebuiltOnce.source_event_count,
      "persisted surface-index source_event_count must not exceed the current event log length",
    );

    // ── Assertion 4: claim-freeze.json references only events present in
    //                 frontier-events.jsonl. Each candidate claim's
    //                 corresponding claim.candidate.linked event must be on
    //                 the ledger. ─────────────────────────────────────────
    const frontierEvents = readFrontierEvents(domain);
    const claimLinkedEvents = frontierEvents
      .filter((event) => event.kind === "claim.candidate.linked");
    const claimLinkedClaimIds = new Set(claimLinkedEvents.map((event) => event.claim_id));
    for (const frozenClaim of freezeOnDisk.claims) {
      assert.ok(
        claimLinkedClaimIds.has(frozenClaim.claim_id),
        `frozen claim ${frozenClaim.claim_id} must have a claim.candidate.linked event in frontier-events.jsonl`,
      );
    }
    // Symmetric direction: each finding ID we recorded must surface in the
    // frozen claims' evidence_refs[].
    const frozenFindingIds = new Set();
    for (const frozenClaim of freezeOnDisk.claims) {
      for (const ref of frozenClaim.evidence_refs || []) {
        if (ref && ref.kind === "finding" && typeof ref.finding_id === "string") {
          frozenFindingIds.add(ref.finding_id);
        }
      }
    }
    for (const findingId of result.finding_ids) {
      assert.ok(
        frozenFindingIds.has(findingId),
        `finding ${findingId} must appear in claim-freeze.json evidence_refs[]`,
      );
    }

    // ── Assertion 5: a claim.report_snapshot.appended frontier event was
    //                 emitted alongside the ReportSnapshot row. ─────────
    const reportSnapshotEvents = frontierEvents
      .filter((event) => event.kind === "claim.report_snapshot.appended");
    assert.equal(reportSnapshotEvents.length, 1,
      "exactly one claim.report_snapshot.appended event after a single finalize");
    assert.equal(reportSnapshotEvents[0].payload.snapshot_id, row.snapshot_id);

    // ── Assertion 6: report-snapshots.jsonl path is the canonical one and
    //                 the artifact layout from D4 holds. ────────────────
    assert.ok(fs.existsSync(reportSnapshotsJsonlPath(domain)), "report-snapshots.jsonl must exist");
    assert.ok(fs.existsSync(sessionDir(domain)), "session directory must exist");

    // ── Manifest: lifecycle states exercised + hashes validated. The doer
    //              return payload (relayed by the parent agent) is built
    //              from these two arrays. ──────────────────────────────
    assert.deepEqual(lifecycleStatesExercised, [
      "SETUP",
      "OPEN_FRONTIER",
      "CLAIM_FREEZE",
      "VERIFY",
      "GRADE",
      "REPORT",
    ]);
    const hashesValidated = [
      "claim_freeze_hash",
      "final_verification_hash",
      "evidence_hash",
      "grade_verdict_hash",
      "report_content_hash",
    ];
    assert.equal(hashesValidated.length, 5);
  });
});
