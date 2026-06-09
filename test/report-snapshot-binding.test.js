"use strict";

// Cycle C.7 invariant: bob_finalize_report appends a ReportSnapshot row to
// report-snapshots.jsonl that binds five hashes:
//
//   - claim_freeze_hash       (claim-freeze.json freeze_hash)
//   - final_verification_hash (V2 final verification round)
//   - evidence_hash           (sha256 of canonical packs[] manifest)
//   - grade_verdict_hash      (sha256 of canonical grade.json)
//   - report_content_hash     (sha256 of report.md content)
//
// The five-hash binding is the realization of the C.7 ReportSnapshot ledger:
// a downstream consumer can read one snapshot row, hash the on-disk artifacts,
// and prove the report was finalized over an exact CLAIM_FREEZE → VERIFY →
// GRADE → REPORT chain. Re-running finalize after a report.md mutation
// produces a new row with a different report_content_hash; a missing
// upstream (no freeze / no final verification / no grade verdict / no
// evidence pack) refuses finalization.

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("crypto");
const fs = require("fs");
const os = require("os");
const path = require("path");

const finalizeReportTool = require("../mcp/lib/tools/finalize-report.js");
const reportWrittenTool = require("../mcp/lib/tools/report-written.js");
const recordFindingTool = require("../mcp/lib/tools/record-candidate-claim.js");
const {
  buildClaimFreeze,
  readCurrentClaimFreeze,
} = require("../mcp/lib/claim-freeze.js");
const {
  writeEvidencePacks,
} = require("../mcp/lib/evidence.js");
const {
  writeGradeVerdict,
} = require("../mcp/lib/grade-verdict-store.js");
const {
  normalizeProofBundlesDocument,
} = require("../mcp/lib/proof-bundle.js");
const {
  writeVerificationRound,
} = require("../mcp/lib/verification-round-store.js");
const {
  readReportSnapshots,
} = require("../mcp/lib/report-snapshots.js");
const {
  readFrontierEvents,
} = require("../mcp/lib/frontier-events.js");
const {
  evidencePackPaths,
  gradeArtifactPaths,
  proofBundlePaths,
  repoCommandRunsJsonlPath,
  repoRunsDir,
  reportMarkdownPath,
  sessionDir,
  statePath,
  verificationRoundPaths,
  claimFreezePath,
} = require("../mcp/lib/paths.js");
const {
  finalVerificationHash,
  hashCanonicalJson,
} = require("../mcp/lib/verification-contracts.js");
const {
  appendJsonlLine,
  writeFileAtomic,
} = require("../mcp/lib/storage.js");
const {
  resetForTests: resetMaterializationDebounce,
} = require("../mcp/lib/frontier-materialize-debounce.js");

const HASH_HEX_RE = /^[a-f0-9]{64}$/;

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-report-snapshot-binding-"));
  process.env.HOME = home;
  try {
    return fn(home);
  } finally {
    process.env.HOME = previousHome;
    resetMaterializationDebounce();
    fs.rmSync(home, { recursive: true, force: true });
  }
}

// Mirror of the seedSessionState helper used by mcp-server.test.js. The
// reportWritten path reads state.json for governance context, and the
// verification-write path requires a baseline state document so its
// schema-version probe selects V1 (no verification-input-snapshot.json on
// disk yet, no V2 marker in state).
function seedSessionState(domain, overrides = {}) {
  const dir = sessionDir(domain);
  fs.mkdirSync(dir, { recursive: true });
  const state = {
    target: domain,
    target_url: `https://${domain}`,
    deep_mode: false,
    checkpoint_mode: "normal",
    block_internal_hosts: false,
    block_internal_hosts_source: "legacy_default",
    phase: "REPORT",
    evaluation_wave: 1,
    pending_wave: null,
    total_findings: 1,
    explored: [],
    terminally_blocked: [],
    prereq_registry_snapshots: [],
    blocked_prereq_history: [],
    terminal_block_clear_history: [],
    dead_ends: [],
    waf_blocked_endpoints: [],
    lead_surface_ids: [],
    scope_exclusions: [],
    hold_count: 0,
    auth_status: "authenticated",
    egress_profile: "default",
    egress_region: null,
    proxy_configured: false,
    egress_profile_identity_hash: null,
    egress_profile_identity_version: null,
    egress_profile_identity_bound_at: null,
    egress_profile_identity_bind_source: null,
    operator_note: null,
    verification_schema_version: null,
    verification_attempt_id: null,
    verification_snapshot_hash: null,
    verification_entered_at: null,
    ...overrides,
  };
  writeFileAtomic(statePath(domain), `${JSON.stringify(state, null, 2)}\n`);
  return state;
}

function recordFinding(domain, overrides = {}) {
  return JSON.parse(recordFindingTool.handler({
    target_domain: domain,
    title: overrides.title || "IDOR on billing profile",
    severity: overrides.severity || "high",
    cwe: overrides.cwe || "CWE-639",
    endpoint: overrides.endpoint || "https://victim.example/api/billing/1",
    description: overrides.description || "Tenant boundary allows cross-account view",
    proof_of_concept: overrides.poc || "GET /api/billing/1 returns another tenant payload",
    response_evidence: overrides.response_evidence || "Cross-tenant billing payload",
    impact: overrides.impact || "Cross-tenant billing disclosure",
    validated: true,
    auth_profile: overrides.auth_profile || "attacker",
    surface_id: overrides.surface_id || "surface:billing-profile",
  }));
}

function evidencePackInput(findingId = "F-1", overrides = {}) {
  return {
    finding_id: findingId,
    sample_type: "cross-account replay",
    sample_count: 1,
    aggregate_counts: { affected_objects_sampled: 1 },
    representative_samples: [{
      request_ref: "http-audit:1",
      endpoint: "/api/billing/1",
      auth_profile: "attacker",
      status: 200,
      observed_fields: ["billing_profile_id"],
      redacted_object_id: "acct_...002",
    }],
    sensitive_clusters: ["billing metadata"],
    replay_summary: "Fresh replay returned another tenant's private billing metadata.",
    redaction_notes: "Object IDs and personal values redacted; auth material omitted.",
    report_snippet: "An attacker can retrieve another tenant's private billing metadata by changing the billing profile ID.",
    ...overrides,
  };
}

function gradeFindingInput(findingId = "F-1", overrides = {}) {
  return {
    finding_id: findingId,
    impact: 25,
    proof_quality: 20,
    severity_accuracy: 10,
    chain_potential: 10,
    report_quality: 10,
    total_score: 75,
    feedback: "Clear, reproducible, and reportable.",
    ...overrides,
  };
}

// Drive the entire pipeline up to (but not including) finalize. Writes a
// freeze, a V1 verification chain through final, evidence packs, a grade
// verdict, then upgrades the V1 final round document on disk to a V2 shape
// with a freeze-bound verification_snapshot_hash + final_verification_hash
// stamp so the C.7 bob_finalize_report resolver finds the four-hash chain.
// Finally writes report.md. Returns nothing; tests read the on-disk state
// via the public resolvers.
function drivePipelineToReportWritten(domain) {
  seedSessionState(domain);
  recordFinding(domain);
  buildClaimFreeze(domain, { write: true, now: new Date("2026-05-27T01:00:00.000Z") });

  // V1 verification chain (brutalist + balanced + final). The
  // selectVerificationWriteSchemaVersion probe selects V1 here because no
  // verification-input-snapshot.json is on disk and state has no V2 marker.
  for (const round of ["brutalist", "balanced", "final"]) {
    writeVerificationRound({
      target_domain: domain,
      round,
      notes: null,
      results: [{
        finding_id: "F-1",
        disposition: "confirmed",
        severity: "high",
        reportable: true,
        reasoning: "Fresh replay confirmed the finding against the current target state.",
      }],
    });
  }

  // V1 evidence-pack write is allowed because the final round is V1 at this
  // point. (The C.5 path is V1-aware when there is no V2 attempt.)
  writeEvidencePacks({
    target_domain: domain,
    packs: [evidencePackInput("F-1")],
  });
  writeGradeVerdict({
    target_domain: domain,
    verdict: "SUBMIT",
    total_score: 75,
    findings: [gradeFindingInput("F-1")],
  });

  // C.7 requires a V2-shape final round bound to the claim freeze (the
  // final_verification_hash field is only stamped on V2 final rounds). We
  // upgrade the V1 final round in-place on disk: same results, V2 envelope,
  // freeze-derived snapshot binding. The bob_finalize_report resolver only
  // reads final_verification_hash from the document; nothing else in the
  // post-write pipeline reads this artifact between now and finalize.
  const finalPath = verificationRoundPaths(domain, "final").json;
  const v1FinalDocument = JSON.parse(fs.readFileSync(finalPath, "utf8"));
  const freeze = readCurrentClaimFreeze(domain);
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

  fs.writeFileSync(reportMarkdownPath(domain), "# Bob Report\n\n## Findings\n\n- F-1: IDOR\n");
}

function sha256OfFile(filePath) {
  return crypto.createHash("sha256").update(fs.readFileSync(filePath)).digest("hex");
}

function appendRepoRunFixture(domain) {
  const runId = "run-proof";
  const replayCommand = ["sh", "-lc", "./repro.sh"];
  const stdout = "proof reproduced\n";
  const stderr = "";
  const replayCommandHash = crypto.createHash("sha256").update(JSON.stringify(replayCommand)).digest("hex");
  fs.mkdirSync(repoRunsDir(domain), { recursive: true });
  fs.writeFileSync(path.join(repoRunsDir(domain), `${runId}.stdout`), stdout);
  fs.writeFileSync(path.join(repoRunsDir(domain), `${runId}.stderr`), stderr);
  appendJsonlLine(repoCommandRunsJsonlPath(domain), {
    version: 1,
    target_domain: domain,
    run_id: runId,
    dry_run: false,
    command_hash: replayCommandHash,
    replay_command_hash: replayCommandHash,
    argv_hash: crypto.createHash("sha256").update(JSON.stringify(["run", "--network", "none"])).digest("hex"),
    network_mode: "none",
    mount_mode: "read_only",
    work_mount_mode: "read_write",
    replay_context: { finding_id: "F-1" },
    image_tag: `bob-oss-${domain}:stable`,
    timeout_ms: 300000,
    exit_code: 1,
    signal: null,
    timed_out: false,
    stdout_hash: crypto.createHash("sha256").update(stdout).digest("hex"),
    stderr_hash: crypto.createHash("sha256").update(stderr).digest("hex"),
    stdout_size_bytes: Buffer.byteLength(stdout),
    stderr_size_bytes: Buffer.byteLength(stderr),
    stdout_truncated: false,
    stderr_truncated: false,
  });
  return { runId, replayCommand };
}

function writeProofBundleDocument(domain) {
  const finalRound = JSON.parse(fs.readFileSync(verificationRoundPaths(domain, "final").json, "utf8"));
  const binding = {
    verification_attempt_id: finalRound.verification_attempt_id,
    verification_snapshot_hash: finalRound.verification_snapshot_hash,
    final_verification_hash: finalRound.final_verification_hash,
  };
  const { runId, replayCommand } = appendRepoRunFixture(domain);
  const document = normalizeProofBundlesDocument({
    version: 1,
    target_domain: domain,
    ...binding,
    packs: [{
      finding_id: "F-1",
      bundle_kind: "replay_script",
      artifacts: [{
        run_id: runId,
        replay_command: replayCommand,
        replay_summary: "Offline proof replay reproduces F-1.",
      }],
    }],
  }, {
    expectedDomain: domain,
    findingIdSet: new Set(["F-1"]),
    finalReportableIdSet: new Set(["F-1"]),
    verificationBinding: binding,
  });
  const paths = proofBundlePaths(domain);
  fs.writeFileSync(paths.json, `${JSON.stringify(document, null, 2)}\n`);
  return document;
}

test("bob_finalize_report appends a five-hash ReportSnapshot row after a full pipeline", () => {
  withTempHome(() => {
    const domain = "bind.example.com";
    drivePipelineToReportWritten(domain);

    const response = JSON.parse(finalizeReportTool.handler({ target_domain: domain }));
    assert.equal(response.finalized, true);
    assert.equal(response.target_domain, domain);
    assert.match(response.snapshot_hash, HASH_HEX_RE);
    assert.match(response.claim_freeze_hash, HASH_HEX_RE);
    assert.match(response.final_verification_hash, HASH_HEX_RE);
    assert.match(response.evidence_hash, HASH_HEX_RE);
    assert.match(response.grade_verdict_hash, HASH_HEX_RE);
    assert.match(response.report_content_hash, HASH_HEX_RE);

    const snapshots = readReportSnapshots(domain);
    assert.equal(snapshots.length, 1, "report-snapshots.jsonl must hold exactly one row after a single finalize");
    const row = snapshots[0];
    assert.match(row.claim_freeze_hash, HASH_HEX_RE);
    assert.match(row.final_verification_hash, HASH_HEX_RE);
    assert.match(row.evidence_hash, HASH_HEX_RE);
    assert.match(row.grade_verdict_hash, HASH_HEX_RE);
    assert.match(row.report_content_hash, HASH_HEX_RE);
    assert.equal(row.claim_freeze_hash, response.claim_freeze_hash);
    assert.equal(row.final_verification_hash, response.final_verification_hash);
    assert.equal(row.evidence_hash, response.evidence_hash);
    assert.equal(row.grade_verdict_hash, response.grade_verdict_hash);
    assert.equal(row.report_content_hash, response.report_content_hash);

    // The report content hash on the snapshot row must match a fresh sha256
    // of the report.md file on disk.
    assert.equal(
      row.report_content_hash,
      sha256OfFile(reportMarkdownPath(domain)),
      "snapshot report_content_hash must match sha256(report.md)",
    );

    // A claim.report_snapshot.appended frontier event must accompany the row.
    const events = readFrontierEvents(domain)
      .filter((event) => event.kind === "claim.report_snapshot.appended");
    assert.equal(events.length, 1, "exactly one claim.report_snapshot.appended event must be emitted per finalize");
    assert.equal(events[0].payload.snapshot_id, row.snapshot_id);
    assert.equal(events[0].payload.report_content_hash, row.report_content_hash);
  });
});

test("bob_finalize_report binds proof bundles when report cites proof_bundle refs", () => {
  withTempHome(() => {
    const domain = "bind-proof.example.com";
    drivePipelineToReportWritten(domain);
    const proofDocument = writeProofBundleDocument(domain);
    fs.writeFileSync(
      reportMarkdownPath(domain),
      "# Bob Report\n\n## Proof Bundle\n\nEvidence:\n- `proof_bundle:F-1`\n",
    );

    const response = JSON.parse(finalizeReportTool.handler({ target_domain: domain }));
    const expectedProofHash = hashCanonicalJson(proofDocument);
    assert.equal(response.proof_bundle_hash, expectedProofHash);

    const snapshots = readReportSnapshots(domain);
    assert.equal(snapshots.length, 1);
    const row = snapshots[0];
    assert.equal(row.proof_bundle_hash, expectedProofHash);
    assert.deepEqual(row.artifact_refs.find((ref) => ref.kind === "proof_bundle"), {
      kind: "proof_bundle",
      path: "proof-bundles.json",
      content_hash: expectedProofHash,
    });
  });
});

test("bob_finalize_report refuses proof bundle files with unnormalized fields", () => {
  withTempHome(() => {
    const domain = "proof-extra-field.example.com";
    drivePipelineToReportWritten(domain);
    const proofDocument = writeProofBundleDocument(domain);
    proofDocument.packs[0].artifacts[0].local_debug_path = "/Users/operator/harness/test/BobInvariant.t.sol";
    fs.writeFileSync(proofBundlePaths(domain).json, `${JSON.stringify(proofDocument, null, 2)}\n`);
    fs.writeFileSync(
      reportMarkdownPath(domain),
      "# Bob Report\n\n## Proof Bundle\n\nEvidence:\n- `proof_bundle:F-1`\n",
    );

    assert.throws(
      () => finalizeReportTool.handler({ target_domain: domain }),
      /do not match the normalized proof bundle artifact/,
    );
    assert.equal(readReportSnapshots(domain).length, 0, "finalization must not append a snapshot for mutated proof bundles");
  });
});

test("bob_finalize_report refuses proof_bundle refs without proof-bundles.json", () => {
  withTempHome(() => {
    const domain = "missing-proof.example.com";
    drivePipelineToReportWritten(domain);
    fs.writeFileSync(
      reportMarkdownPath(domain),
      "# Bob Report\n\n## Proof Bundle\n\nEvidence:\n- `proof_bundle:F-1`\n",
    );

    assert.throws(
      () => finalizeReportTool.handler({ target_domain: domain }),
      /proof bundles are not present/,
    );
  });
});

test("bob_finalize_report ignores prose proof_bundle mentions without F-N refs", () => {
  withTempHome(() => {
    const domain = "loose-proof-prose.example.com";
    drivePipelineToReportWritten(domain);
    fs.writeFileSync(
      reportMarkdownPath(domain),
      "# Bob Report\n\n## Notes\n\nThe proof_bundle: field is documented for future evidence refs.\n",
    );

    const response = JSON.parse(finalizeReportTool.handler({ target_domain: domain }));
    assert.equal(response.finalized, true);
    assert.equal(response.proof_bundle_hash, undefined);
    assert.equal(readReportSnapshots(domain).length, 1);
  });
});

test("bob_finalize_report refuses proof_bundle refs after proof bundle replacement", () => {
  withTempHome(() => {
    const domain = "replaced-proof.example.com";
    drivePipelineToReportWritten(domain);
    const finalRound = JSON.parse(fs.readFileSync(verificationRoundPaths(domain, "final").json, "utf8"));
    fs.writeFileSync(
      reportMarkdownPath(domain),
      "# Bob Report\n\n## Proof Bundle\n\nEvidence:\n- `proof_bundle:F-1`\n",
    );
    fs.writeFileSync(proofBundlePaths(domain).json, `${JSON.stringify({
      version: 1,
      target_domain: domain,
      verification_attempt_id: finalRound.verification_attempt_id,
      verification_snapshot_hash: finalRound.verification_snapshot_hash,
      final_verification_hash: finalRound.final_verification_hash,
      packs: [],
    }, null, 2)}\n`);

    assert.throws(
      () => finalizeReportTool.handler({ target_domain: domain }),
      /proof_bundle:F-1 does not resolve/,
    );
    assert.equal(readReportSnapshots(domain).length, 0, "finalization must not append a snapshot for stale proof refs");
  });
});

test("bob_finalize_report refuses proof bundles stale against current final verification", () => {
  withTempHome(() => {
    const domain = "stale-proof-finalize.example.com";
    drivePipelineToReportWritten(domain);
    fs.writeFileSync(
      reportMarkdownPath(domain),
      "# Bob Report\n\n## Proof Bundle\n\nEvidence:\n- `proof_bundle:F-1`\n",
    );
    fs.writeFileSync(proofBundlePaths(domain).json, `${JSON.stringify({
      version: 1,
      target_domain: domain,
      verification_attempt_id: "old-attempt",
      verification_snapshot_hash: "a".repeat(64),
      final_verification_hash: "b".repeat(64),
      packs: [],
    }, null, 2)}\n`);

    assert.throws(
      () => finalizeReportTool.handler({ target_domain: domain }),
      /do not validate against the current final verification/,
    );
    assert.equal(readReportSnapshots(domain).length, 0, "finalization must not append a snapshot for stale proof bindings");
  });
});

test("re-finalize after mutating report.md produces a new row with a different report_content_hash", () => {
  withTempHome(() => {
    const domain = "remutate.example.com";
    drivePipelineToReportWritten(domain);

    const firstResponse = JSON.parse(finalizeReportTool.handler({ target_domain: domain }));
    const firstRow = readReportSnapshots(domain)[0];
    assert.equal(firstRow.report_content_hash, firstResponse.report_content_hash);

    // Manually poke report.md (overwrite with new content).
    fs.writeFileSync(reportMarkdownPath(domain), "# Bob Report — revised\n\nSecond pass.\n");

    const secondResponse = JSON.parse(finalizeReportTool.handler({ target_domain: domain }));
    const rows = readReportSnapshots(domain);
    assert.equal(rows.length, 2, "re-finalize must append a second snapshot row");
    const secondRow = rows[1];

    assert.notEqual(
      secondRow.report_content_hash,
      firstRow.report_content_hash,
      "re-finalize after report.md mutation must change report_content_hash",
    );
    assert.equal(
      secondRow.report_content_hash,
      sha256OfFile(reportMarkdownPath(domain)),
      "the new row must bind to the new report.md content",
    );

    // The upstream four hashes are stable across the re-finalize because no
    // upstream artifact changed; only the report content moved.
    assert.equal(secondRow.claim_freeze_hash, firstRow.claim_freeze_hash);
    assert.equal(secondRow.final_verification_hash, firstRow.final_verification_hash);
    assert.equal(secondRow.evidence_hash, firstRow.evidence_hash);
    assert.equal(secondRow.grade_verdict_hash, firstRow.grade_verdict_hash);

    assert.equal(secondResponse.report_content_hash, secondRow.report_content_hash);
  });
});

test("bob_finalize_report refuses when claim-freeze.json is missing", () => {
  withTempHome(() => {
    const domain = "no-freeze.example.com";
    drivePipelineToReportWritten(domain);
    // Remove the claim freeze file but leave every other artifact intact.
    fs.rmSync(claimFreezePath(domain));
    assert.throws(
      () => finalizeReportTool.handler({ target_domain: domain }),
      /no claim-freeze.json/,
      "missing claim freeze must refuse finalization",
    );
    // Snapshot ledger must not be created.
    assert.equal(readReportSnapshots(domain).length, 0);
  });
});

test("bob_finalize_report refuses when the final verification round is missing", () => {
  withTempHome(() => {
    const domain = "no-final.example.com";
    drivePipelineToReportWritten(domain);
    // Remove the final verification round.
    fs.rmSync(verificationRoundPaths(domain, "final").json);
    assert.throws(
      () => finalizeReportTool.handler({ target_domain: domain }),
      /final verification round is not present/,
      "missing final verification round must refuse finalization",
    );
    assert.equal(readReportSnapshots(domain).length, 0);
  });
});

test("bob_finalize_report refuses when the grade verdict is missing", () => {
  withTempHome(() => {
    const domain = "no-grade.example.com";
    drivePipelineToReportWritten(domain);
    fs.rmSync(gradeArtifactPaths(domain).json);
    assert.throws(
      () => finalizeReportTool.handler({ target_domain: domain }),
      /grade verdict is not present/,
      "missing grade verdict must refuse finalization",
    );
    assert.equal(readReportSnapshots(domain).length, 0);
  });
});

test("bob_finalize_report refuses when evidence packs are missing", () => {
  withTempHome(() => {
    const domain = "no-evidence.example.com";
    drivePipelineToReportWritten(domain);
    fs.rmSync(evidencePackPaths(domain).json);
    assert.throws(
      () => finalizeReportTool.handler({ target_domain: domain }),
      /evidence packs are not present/,
      "missing evidence packs must refuse finalization",
    );
    assert.equal(readReportSnapshots(domain).length, 0);
  });
});

test("bob_finalize_report refuses when report.md is missing", () => {
  withTempHome(() => {
    const domain = "no-report.example.com";
    drivePipelineToReportWritten(domain);
    fs.rmSync(reportMarkdownPath(domain));
    assert.throws(
      () => finalizeReportTool.handler({ target_domain: domain }),
      /report\.md is not present/,
      "missing report.md must refuse finalization",
    );
    assert.equal(readReportSnapshots(domain).length, 0);
  });
});

test("legacy bounty_report_written dual-writes a ReportSnapshot row when all four upstream hashes resolve", () => {
  withTempHome(() => {
    const domain = "legacy-dualwrite.example.com";
    drivePipelineToReportWritten(domain);
    // Seed the legacy state so reportWritten's pipeline-event path resolves
    // governance context; without state.json the legacy tool still works but
    // skips the event emission. We need at minimum the report.md present —
    // already created by drivePipelineToReportWritten.
    // The dual-write should append a ReportSnapshot row regardless of state.
    const response = JSON.parse(reportWrittenTool.handler({ target_domain: domain }));
    assert.equal(response.report_written, true);

    const snapshots = readReportSnapshots(domain);
    assert.equal(snapshots.length, 1, "legacy report-written must dual-write a snapshot row");
    const row = snapshots[0];
    assert.match(row.claim_freeze_hash, HASH_HEX_RE);
    assert.match(row.final_verification_hash, HASH_HEX_RE);
    assert.match(row.evidence_hash, HASH_HEX_RE);
    assert.match(row.grade_verdict_hash, HASH_HEX_RE);
    assert.match(row.report_content_hash, HASH_HEX_RE);

    const events = readFrontierEvents(domain)
      .filter((event) => event.kind === "claim.report_snapshot.appended");
    assert.equal(events.length, 1, "legacy dual-write must emit the claim.report_snapshot.appended event");
    assert.equal(events[0].payload.via_legacy_tool, true);
  });
});

test("legacy bounty_report_written stays event-only when the four upstream hashes cannot be resolved", () => {
  withTempHome(() => {
    const domain = "legacy-eventonly.example.com";
    // Skip the freeze/verify/grade/evidence pipeline; only seed state and
    // create report.md. The legacy tool must succeed (its sole legacy
    // contract is "emit report_written when report.md exists") while the
    // dual-write path silently no-ops because no freeze / verification /
    // evidence / grade exist.
    seedSessionState(domain);
    fs.writeFileSync(reportMarkdownPath(domain), "# Bob Report\n");

    const response = JSON.parse(reportWrittenTool.handler({ target_domain: domain }));
    assert.equal(response.report_written, true);
    assert.equal(readReportSnapshots(domain).length, 0,
      "no snapshot row when upstream hashes are unresolved (legacy event-only path preserved)",
    );
  });
});

test("bob_finalize_report descriptor binds to the reporter role bundle", () => {
  assert.equal(finalizeReportTool.name, "bob_finalize_report");
  assert.deepEqual(
    finalizeReportTool.role_bundles,
    ["reporter"],
    "bob_finalize_report must be reporter-only per Cycle C.7",
  );
  assert.equal(finalizeReportTool.mutating, true);
  assert.ok(finalizeReportTool.session_artifacts_written.includes("report-snapshots.jsonl"));
});

test("legacy bounty_report_written tool descriptor is marked deprecated", () => {
  assert.equal(reportWrittenTool.name, "bounty_report_written");
  assert.equal(reportWrittenTool.deprecated, true,
    "Cycle C.7 marks bounty_report_written deprecated; bob_finalize_report is the canonical path",
  );
});
