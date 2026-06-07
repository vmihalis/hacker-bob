"use strict";

// Cycle O.10 of the Plane O hypergraph.
//
// End-to-end smoke for the Plane O OSS / repo-target axis. Drives the same
// v2.0.0 lifecycle (SETUP -> OPEN_FRONTIER -> CLAIM_FREEZE -> VERIFY ->
// GRADE -> REPORT) the Z.1 web smoke exercises, but bound to a locally
// synthesized repo target instead of a URL target. Asserts:
//   - the 5-hash ReportSnapshot chain (C.7) binds for an OSS-only session;
//   - surface-index.json materializes code-shaped surfaces (code_module,
//     manifest, dependency, ci_pipeline, entry_point, config) from the
//     repo-inventory walk;
//   - claim-freeze.json captures the repo_file evidence_ref alongside the
//     finding ref so the freeze hash covers both surface families;
//   - no `target_url` field exists in the persisted session-nucleus
//     scope_policy (the repo session is genuinely repo-only).
//
// A second test exercises mixed evidence_refs[] (repo_file + finding) on a
// single CandidateClaim per O-P6. The deeper cross-mode contract — a session
// carrying BOTH target_repo AND target_url at the scope-policy level — is
// not yet supported by the live tool surface (per the hypergraph the
// `bob_set_companion_target_url` helper is explicitly deferred to a future
// cycle; `normalizeScopePolicy` rejects scope policies that name both
// targets). The drift_note below captures this limitation. The test still
// proves the C.7 hash chain holds when a single claim's evidence_refs[] mix
// the repo and finding kinds, which is the load-bearing primitive O-P6
// promises end-to-end consumers.
//
// Fixture: synthesized at test time (per O.10 §1 and Reviewer B's parsimony
// recommendation); never committed under test/fixtures/.

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const advanceSessionTool = require("../mcp/lib/tools/advance-session.js");
const finalizeReportTool = require("../mcp/lib/tools/finalize-report.js");
const initRepoSessionTool = require("../mcp/lib/tools/init-repo-session.js");
const repoCheckTool = require("../mcp/lib/tools/repo-check.js");
const repoInventoryTool = require("../mcp/lib/tools/repo-inventory.js");
const repoPrepareEnvTool = require("../mcp/lib/tools/repo-prepare-env.js");
const scheduleTasksTool = require("../mcp/lib/tools/schedule-tasks.js");
const writeEvidencePacksTool = require("../mcp/lib/tools/write-evidence-packs.js");
const writeGradeVerdictTool = require("../mcp/lib/tools/write-grade-verdict.js");
const writeVerificationRoundTool = require("../mcp/lib/tools/write-verification-round.js");

const {
  appendCandidateClaim,
} = require("../mcp/lib/claims.js");
const {
  buildClaimFreeze,
  readCurrentClaimFreeze,
} = require("../mcp/lib/claim-freeze.js");
const {
  materializeFrontier,
} = require("../mcp/lib/frontier-materializer.js");
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
  appendFrontierEvent,
} = require("../mcp/lib/frontier-events.js");
const {
  claimFreezePath,
  evidencePackPaths,
  gradeArtifactPaths,
  repoInventoryPath,
  reportMarkdownPath,
  reportSnapshotsJsonlPath,
  sessionDir,
  sessionNucleusPath,
  surfaceIndexPath,
  taskQueuePath,
  verificationRoundPaths,
} = require("../mcp/lib/paths.js");

const HASH_HEX_RE = /^[a-f0-9]{64}$/;

async function withTempHome(fn) {
  // Unlike Z.1, the OSS smoke calls bob_repo_prepare_env which is async, so
  // the HOME-swap helper must `await fn(home)` before restoring HOME and
  // tearing down the temp directory. A purely synchronous return would
  // restore HOME mid-flight and route subsequent reads to the production
  // sessions root.
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-o10-oss-smoke-"));
  process.env.HOME = home;
  try {
    return await fn(home);
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

function sha256Hex(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function callTool(tool, args) {
  const response = tool.handler(args);
  return typeof response === "string" ? JSON.parse(response) : response;
}

async function callToolAsync(tool, args) {
  const response = await tool.handler(args);
  return typeof response === "string" ? JSON.parse(response) : response;
}

// Synthesize a temp repo fixture in the OS tempdir. Per Reviewer B's
// parsimony directive and O.10 §1, the fixture is materialized at test
// time and lives only for the run's lifetime. Carries a multi-language
// shape so the inventory walk produces code_module + manifest + dependency
// + ci_pipeline + entry_point + config surfaces.
function synthesizeOssRepoFixture(prefix = "bob-o10-oss-fixture-") {
  const raw = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  const root = fs.realpathSync.native ? fs.realpathSync.native(raw) : fs.realpathSync(raw);

  function write(rel, content) {
    const abs = path.join(root, rel);
    fs.mkdirSync(path.dirname(abs), { recursive: true });
    fs.writeFileSync(abs, content, "utf8");
  }

  write("package.json", JSON.stringify({
    name: "synthesized-oss-fixture",
    version: "0.0.0",
    description: "Plane O O.10 end-to-end smoke fixture (synthesized per-run).",
    scripts: { test: "node -e \"console.log('ok')\"" },
    dependencies: { "left-pad": "1.3.0" },
  }, null, 2));

  write("src/index.js", [
    "function greet(name) {",
    "  return `hello, ${name}`;",
    "}",
    "module.exports = { greet };",
    "",
  ].join("\n"));

  write("Cargo.toml", [
    "[package]",
    "name = \"synthesized-oss-fixture\"",
    "version = \"0.0.0\"",
    "edition = \"2021\"",
    "",
    "[dependencies]",
    "",
  ].join("\n"));

  // Native-code source carrying a deliberate distinctive pattern the smoke
  // probes for via bob_repo_check. The pattern is intentionally innocuous;
  // the smoke uses it to demonstrate the read-only repo evidence path
  // (Cycle O.5) without leaving residue beyond the temp dir.
  write("src/parser.c", [
    "#include <stdio.h>",
    "",
    "// O10_SMOKE_PARSER_MARKER: synthesized by realization-oss-e2e-smoke.",
    "int parse_packet(const unsigned char *buf, int len) {",
    "  if (len <= 0) return -1;",
    "  return buf[0];",
    "}",
    "",
  ].join("\n"));
  write("src/helper.c", [
    "#include <stdio.h>",
    "",
    "int helper_packet(const unsigned char *buf, int len) {",
    "  if (len <= 0) return -1;",
    "  return buf[len - 1];",
    "}",
    "",
  ].join("\n"));

  write(".github/workflows/ci.yml", [
    "name: ci",
    "on: [push, pull_request]",
    "jobs:",
    "  build:",
    "    runs-on: ubuntu-latest",
    "    steps:",
    "      - uses: actions/checkout@v4",
    "      - run: echo synthesized-fixture",
    "",
  ].join("\n"));

  // README so the surface walk sees non-empty content but it is not
  // mandatory for any of the assertions.
  write("README.md", "# Synthesized fixture\n");

  return root;
}

// Drive the OSS-only realization flow against a repo session. Returns the
// captured artifacts so the test assertions can validate the five-hash
// chain plus the OSS-specific projections (surface-index code shapes,
// claim-freeze code-bound evidence_ref).
async function driveOssRealizationFlow({
  repoRoot,
  extraEvidenceRefsForFirstClaim = [],
}) {
  // Step 1 — bob_init_repo_session → SETUP, session-nucleus.json with
  // target_repo (NOT target_url).
  const initResponse = callTool(initRepoSessionTool, {
    repo_path: repoRoot,
  });
  assert.equal(initResponse.created, true, "bob_init_repo_session must create the session");
  const domain = initResponse.target_domain;
  assert.ok(fs.existsSync(sessionNucleusPath(domain)), "session-nucleus.json must be written by init");
  const nucleus = JSON.parse(fs.readFileSync(sessionNucleusPath(domain), "utf8"));
  // The repo session must carry target_repo on its scope policy; target_url
  // must be absent (O-P1 + O-P5 sanity).
  assert.ok(nucleus.scope_policy && nucleus.scope_policy.target_repo,
    "scope_policy.target_repo must be present on a repo session");
  assert.equal(nucleus.scope_policy.target_url, undefined,
    "scope_policy.target_url must be absent on a repo-only session");

  // Step 2 — bob_repo_inventory → frontier surface.observed events for every
  // enumerated artefact, plus repo-inventory.json on disk.
  const inventoryResponse = callTool(repoInventoryTool, { target_domain: domain });
  assert.equal(inventoryResponse.created, true);
  assert.ok(fs.existsSync(repoInventoryPath(domain)),
    "repo-inventory.json must be materialized by bob_repo_inventory");
  const inventoryOnDisk = JSON.parse(fs.readFileSync(repoInventoryPath(domain), "utf8"));
  const surfaceCeilings = inventoryOnDisk.reachability && Array.isArray(inventoryOnDisk.reachability.surface_ceilings)
    ? inventoryOnDisk.reachability.surface_ceilings
    : [];
  const surfaceIdForFile = (filePath) => {
    const match = surfaceCeilings.find((surface) => surface && surface.file_path === filePath);
    assert.ok(match && typeof match.id === "string",
      `repo inventory must emit a reachability surface id for ${filePath}`);
    return match.id;
  };

  // Step 3 — bob_repo_prepare_env (dry_run is the default per O-P3). The
  // smoke does not invoke docker; this exercises the dockerfile-generation
  // path so the OSS lifecycle wiring stays end-to-end coherent.
  const prepareResponse = await callToolAsync(repoPrepareEnvTool, {
    target_domain: domain,
    dry_run: true,
  });
  assert.ok(prepareResponse, "bob_repo_prepare_env must return a non-empty envelope");

  // Step 4 — bob_advance_session(OPEN_FRONTIER).
  const openFrontierResponse = callTool(advanceSessionTool, {
    target_domain: domain,
    to_state: "OPEN_FRONTIER",
  });
  assert.equal(openFrontierResponse.advanced, true);
  assert.equal(openFrontierResponse.to_state, "OPEN_FRONTIER");

  // Step 5 — materialize the frontier so surface-index.json and
  // task-queue.json are on disk before scheduling. Mirrors the Z.1 web
  // smoke's explicit materialize step.
  materializeFrontier(domain, { write: true });
  assert.ok(fs.existsSync(surfaceIndexPath(domain)),
    "surface-index.json must be materialized after inventory");
  assert.ok(fs.existsSync(taskQueuePath(domain)),
    "task-queue.json must be materialized after inventory");

  // Step 6 — bob_schedule_tasks. The repo session's task queue is shaped by
  // the inventory-emitted surfaces. The call is exercised end-to-end so the
  // scheduler-decisions.jsonl ledger lands a row for the repo session even
  // when downstream lens dispatch is out of scope for the smoke.
  const scheduleResponse = callTool(scheduleTasksTool, { target_domain: domain });
  assert.ok(typeof scheduleResponse.scheduler_decision_id === "string"
    && scheduleResponse.scheduler_decision_id.length > 0,
    "schedule_tasks must return a scheduler_decision_id for a repo session");

  // Step 7 — bob_repo_check (read-only evidence probe under OPEN_FRONTIER).
  // The probe yields the file's sha256 which the CandidateClaim's repo_file
  // evidence_ref binds to. Per the pact constraint the claim severity stays
  // at medium so the O-P4 native-code gate does NOT require a
  // repo_command_run companion ref.
  const probe = callTool(repoCheckTool, {
    target_domain: domain,
    check_type: "regex_match",
    file_path: "src/parser.c",
    regex: "O10_SMOKE_PARSER_MARKER",
  });
  assert.equal(probe.matched, true,
    "repo_check must match the synthesized fixture's distinctive marker");
  assert.match(probe.file_hash, HASH_HEX_RE);

  // Step 8 — record candidate claims via appendCandidateClaim (direct
  // ledger append; the tool wrapper bob_record_candidate_claim only emits a
  // single `finding` evidence_ref and would not carry the repo_file ref).
  // Two claims are recorded so the freeze, verification, grade, and report
  // chain has more than one finding to walk (parity with the Z.1 web smoke
  // which also records N=2). Both claims stay at medium severity to keep
  // the O-P4 gate dormant.
  const firstSurfaceId = surfaceIdForFile("src/parser.c");
  const secondSurfaceId = surfaceIdForFile("src/helper.c");

  const firstClaim = appendCandidateClaim({
    target_domain: domain,
    title: "Repo-side parser claim",
    summary: "OSS smoke: parser claim with repo_file evidence + optional companion refs.",
    severity: "medium",
    surface_ids: [firstSurfaceId],
    evidence_refs: [
      {
        kind: "finding",
        finding_id: "F-1",
        content_hash: sha256Hex(`finding:${domain}:F-1`),
      },
      {
        kind: "repo_file",
        file_path: "src/parser.c",
        content_hash: probe.file_hash,
      },
      // Extra refs (e.g., a finding-shaped HTTP-side companion) flow in via
      // the caller; the smoke's first test passes [], the second test
      // passes a mixed finding ref to mirror the cross-mode evidence shape.
      ...extraEvidenceRefsForFirstClaim,
    ],
    impact: "Synthesized fixture probe; no real-world impact.",
  });

  const secondClaim = appendCandidateClaim({
    target_domain: domain,
    title: "Repo-side dependency claim",
    summary: "OSS smoke: top-level dependency hygiene observation.",
    severity: "medium",
    surface_ids: [secondSurfaceId],
    evidence_refs: [
      {
        kind: "finding",
        finding_id: "F-2",
        content_hash: sha256Hex(`finding:${domain}:F-2`),
      },
    ],
    impact: "Synthesized fixture observation; no real-world impact.",
  });

  // Emit claim.candidate.linked frontier events so the freeze projection /
  // surface index see both claims (the direct appendCandidateClaim path
  // does not emit these events; the bob_record_candidate_claim wrapper
  // does. Mirror that side-effect manually so the smoke's ledger
  // assertions stay symmetric with the Z.1 web smoke's expectations).
  for (const claim of [firstClaim, secondClaim]) {
    appendFrontierEvent({
      target_domain: domain,
      kind: "claim.candidate.linked",
      claim_id: claim.claim_id,
      surface_id: claim.surface_ids && claim.surface_ids[0] || null,
      payload: {
        claim_id: claim.claim_id,
        finding_id: claim.evidence_refs && claim.evidence_refs[0]
          ? claim.evidence_refs[0].finding_id
          : null,
      },
      source: { artifact: "claims.jsonl", tool: "test:oss_smoke_appendCandidateClaim" },
    });
  }

  const findingIds = ["F-1", "F-2"];

  // Step 9 — bob_advance_session(CLAIM_FREEZE), then build the freeze
  // explicitly. Mirrors the Z.1 seam where the lifecycle advance does not
  // auto-materialize the freeze; the claim-freeze fabric is the documented
  // producer.
  const claimFreezeAdvance = callTool(advanceSessionTool, {
    target_domain: domain,
    to_state: "CLAIM_FREEZE",
  });
  assert.equal(claimFreezeAdvance.advanced, true);
  assert.equal(claimFreezeAdvance.to_state, "CLAIM_FREEZE");
  buildClaimFreeze(domain, { write: true });
  assert.ok(fs.existsSync(claimFreezePath(domain)),
    "claim-freeze.json must be materialized");
  const freeze = readCurrentClaimFreeze(domain);
  assert.ok(freeze, "claim-freeze.json must load");
  assert.match(freeze.freeze_hash, HASH_HEX_RE);
  assert.equal(freeze.claim_count, 2, "freeze must capture both candidate claims");

  // Step 10 — V1 verification rounds (brutalist -> balanced -> final).
  for (const round of ["brutalist", "balanced", "final"]) {
    callTool(writeVerificationRoundTool, {
      target_domain: domain,
      round,
      notes: null,
      results: findingIds.map((findingId) => ({
        finding_id: findingId,
        disposition: "confirmed",
        severity: "medium",
        reportable: true,
        reasoning: "OSS smoke replay confirmed the finding against the synthesized fixture.",
        // Y.1 B1 lift — repro_steps + evidence_refs are inputSchema.required.
        repro_steps: ["OSS smoke replay step 1 confirmed the finding."],
        evidence_refs: [`frontier_event:${findingId}`],
      })),
    });
  }

  // Step 11 — bob_advance_session(VERIFY).
  const verifyAdvance = callTool(advanceSessionTool, {
    target_domain: domain,
    to_state: "VERIFY",
  });
  assert.equal(verifyAdvance.advanced, true);
  assert.equal(verifyAdvance.to_state, "VERIFY");

  // Step 12 — V1 evidence packs (one per reportable finding).
  callTool(writeEvidencePacksTool, {
    target_domain: domain,
    packs: findingIds.map((findingId) => ({
      finding_id: findingId,
      sample_type: "repo evidence replay",
      sample_count: 1,
      aggregate_counts: { affected_objects_sampled: 1 },
      representative_samples: [{
        request_ref: `repo-evidence:${findingId}`,
        endpoint: "/src/parser.c",
        auth_profile: "n/a",
        status: 0,
        observed_fields: ["repo_file"],
        redacted_object_id: "repo_obj_sample",
      }],
      sensitive_clusters: ["synthesized parser fixture"],
      replay_summary: "Synthesized OSS fixture probe confirmed via repo_check.",
      redaction_notes: "Fixture content is synthetic; no real secrets present.",
      report_snippet: `OSS smoke ${findingId}: evidence pack written for the synthesized fixture.`,
    })),
  });
  assert.ok(fs.existsSync(evidencePackPaths(domain).json),
    "evidence-packs.json must be written");

  // Step 13 — bob_advance_session(GRADE).
  const gradeAdvance = callTool(advanceSessionTool, {
    target_domain: domain,
    to_state: "GRADE",
  });
  assert.equal(gradeAdvance.advanced, true);
  assert.equal(gradeAdvance.to_state, "GRADE");

  // Step 14 — grade verdict. Per grade-verdict-store consistency rules the
  // per-finding total_score must equal the sum of its rubric scores and the
  // document total_score must equal the MAX per-finding total_score.
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
      feedback: "OSS smoke: synthesized fixture finding is reproducible.",
    })),
    feedback: "Both OSS smoke findings are submission-ready against the synthesized fixture.",
  });
  assert.ok(fs.existsSync(gradeArtifactPaths(domain).json), "grade.json must be written");

  // Step 15 — bob_advance_session(REPORT).
  const reportAdvance = callTool(advanceSessionTool, {
    target_domain: domain,
    to_state: "REPORT",
  });
  assert.equal(reportAdvance.advanced, true);
  assert.equal(reportAdvance.to_state, "REPORT");

  // Step 16 — upgrade V1 final round to V2 in place so bob_finalize_report
  // can resolve the final_verification_hash binding. Mirrors the Z.1
  // pattern verbatim — same seam, different target.
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

  // Step 17 — write report.md (human-facing report).
  const reportMarkdown = [
    "# Bob OSS Report",
    "",
    `Target: ${domain}`,
    `Repo: ${repoRoot}`,
    "",
    "## Findings",
    "",
    ...findingIds.map((findingId) => `- ${findingId}: validated against the synthesized OSS fixture.`),
    "",
  ].join("\n") + "\n";
  fs.writeFileSync(reportMarkdownPath(domain), reportMarkdown);

  // Step 18 — bob_finalize_report. Appends one ReportSnapshot row binding
  // the four upstream hashes + the report content hash.
  const finalizeResponse = callTool(finalizeReportTool, { target_domain: domain });
  assert.equal(finalizeResponse.finalized, true);

  return {
    domain,
    nucleus,
    finding_ids: findingIds,
    freeze,
    v2_final_document: v2FinalDocument,
    finalize_response: finalizeResponse,
    first_claim: firstClaim,
    second_claim: secondClaim,
    probe_file_hash: probe.file_hash,
  };
}

// Walk the standard 5-hash chain assertion set against the on-disk
// artifacts. Mirrors the Z.1 review gate so the OSS lifecycle is held to
// the same chain-of-custody bar as the URL lifecycle.
function assertFiveHashChain(result) {
  const { domain, finalize_response: finalizeResponse } = result;

  assert.match(finalizeResponse.claim_freeze_hash, HASH_HEX_RE);
  assert.match(finalizeResponse.final_verification_hash, HASH_HEX_RE);
  assert.match(finalizeResponse.evidence_hash, HASH_HEX_RE);
  assert.match(finalizeResponse.grade_verdict_hash, HASH_HEX_RE);
  assert.match(finalizeResponse.report_content_hash, HASH_HEX_RE);
  assert.match(finalizeResponse.snapshot_hash, HASH_HEX_RE);

  const snapshots = readReportSnapshots(domain);
  assert.equal(snapshots.length, 1, "exactly one ReportSnapshot row after a single finalize");
  const row = snapshots[0];

  assert.equal(row.claim_freeze_hash, finalizeResponse.claim_freeze_hash);
  assert.equal(row.final_verification_hash, finalizeResponse.final_verification_hash);
  assert.equal(row.evidence_hash, finalizeResponse.evidence_hash);
  assert.equal(row.grade_verdict_hash, finalizeResponse.grade_verdict_hash);
  assert.equal(row.report_content_hash, finalizeResponse.report_content_hash);

  // Each link recomputes from its on-disk artifact.
  const freezeOnDisk = JSON.parse(fs.readFileSync(claimFreezePath(domain), "utf8"));
  assert.equal(row.claim_freeze_hash, freezeOnDisk.freeze_hash);

  const finalRoundOnDisk = JSON.parse(fs.readFileSync(verificationRoundPaths(domain, "final").json, "utf8"));
  assert.equal(row.final_verification_hash, finalRoundOnDisk.final_verification_hash);
  assert.equal(finalVerificationHash(finalRoundOnDisk), finalRoundOnDisk.final_verification_hash);

  const evidenceOnDisk = JSON.parse(fs.readFileSync(evidencePackPaths(domain).json, "utf8"));
  assert.equal(row.evidence_hash, hashCanonicalJson(evidenceOnDisk.packs));

  const gradeOnDisk = JSON.parse(fs.readFileSync(gradeArtifactPaths(domain).json, "utf8"));
  assert.equal(row.grade_verdict_hash, hashCanonicalJson(gradeOnDisk));

  assert.equal(row.report_content_hash, sha256OfFile(reportMarkdownPath(domain)));

  assert.ok(fs.existsSync(reportSnapshotsJsonlPath(domain)), "report-snapshots.jsonl must exist");
  assert.ok(fs.existsSync(sessionDir(domain)), "session directory must exist");
}

// ── Test 1: OSS-only lifecycle ────────────────────────────────────────────────

test("Cycle O.10: OSS-only realization smoke walks the SETUP -> REPORT lifecycle and binds the 5-hash chain", async () => {
  await withTempHome(async () => {
    const repoRoot = synthesizeOssRepoFixture();
    try {
      const result = await driveOssRealizationFlow({ repoRoot });

      // Five-hash chain holds.
      assertFiveHashChain(result);

      // OSS-specific: surface-index.json materializes code-shaped surfaces.
      const persistedIndex = JSON.parse(fs.readFileSync(surfaceIndexPath(result.domain), "utf8"));
      assert.ok(Array.isArray(persistedIndex.surfaces),
        "surface-index.json must carry a surfaces[] array");
      const codeShapedKinds = new Set([
        "code_module",
        "manifest",
        "dependency",
        "ci_pipeline",
        "entry_point",
        "config",
      ]);
      const seenCodeKinds = new Set();
      for (const surface of persistedIndex.surfaces) {
        if (surface && typeof surface.kind === "string" && codeShapedKinds.has(surface.kind)) {
          seenCodeKinds.add(surface.kind);
        }
      }
      assert.ok(seenCodeKinds.size > 0,
        `surface-index.json must include at least one code-shaped surface (saw kinds: ${
          [...new Set(persistedIndex.surfaces.map((s) => s && s.kind).filter(Boolean))].join(", ")
        })`);

      // OSS-specific: claim-freeze.json carries the repo_file evidence_ref so
      // the freeze hash covers the repo surface family end-to-end.
      const freezeOnDisk = JSON.parse(fs.readFileSync(claimFreezePath(result.domain), "utf8"));
      const repoFileRefs = [];
      for (const frozenClaim of freezeOnDisk.claims) {
        for (const ref of frozenClaim.evidence_refs || []) {
          if (ref && ref.kind === "repo_file") {
            repoFileRefs.push(ref);
          }
        }
      }
      assert.ok(repoFileRefs.length >= 1,
        "claim-freeze.json must carry at least one repo_file evidence_ref");
      assert.equal(repoFileRefs[0].file_path, "src/parser.c");
      assert.equal(repoFileRefs[0].content_hash, result.probe_file_hash,
        "the frozen repo_file content_hash must equal the live bob_repo_check file_hash");

      // OSS-specific: the persisted nucleus is repo-only (no target_url).
      assert.ok(result.nucleus.scope_policy.target_repo,
        "nucleus scope_policy.target_repo must be present");
      assert.equal(result.nucleus.scope_policy.target_url, undefined,
        "nucleus scope_policy.target_url must be absent on a repo-only session");
    } finally {
      fs.rmSync(repoRoot, { recursive: true, force: true });
    }
  });
});

// ── Test 2: Cross-mode evidence-ref variant ──────────────────────────────────
//
// O-P6 promises cross-mode composition (a session may carry both target_repo
// AND target_url). The live `normalizeScopePolicy` rejects scope policies
// that name BOTH targets (a deliberate guardrail until a companion
// `bob_set_companion_target_url` tool ships, explicitly deferred per O.1 to
// "a future cycle — NOT in O.1 to keep scope tight"). `bob_import_http_traffic`
// further uses the session `target_domain` as the first-party host suffix
// when scope-checking imported records, so a repo session (whose
// target_domain is a `repo-<safeName>-<sha8>` slug, not a real DNS name)
// cannot accept any real HTTP record via the import path.
//
// Drift carried into this test:
//   - Cross-mode at the session/scope-policy level is structurally
//     unavailable in O.10. Adding it requires either the deferred
//     `bob_set_companion_target_url` tool OR a relaxation of
//     `normalizeScopePolicy`. Both are out-of-scope for O.10 per the
//     hypergraph.
//
// What this test PROVES (per the task spec's "defensible interpretation"):
//   - The mixed-evidence primitive that O-P6 is built on (a single
//     CandidateClaim carrying both repo and HTTP-side evidence refs) works
//     end-to-end against the repo-only session lifecycle. The 5-hash chain
//     holds when the first claim's evidence_refs[] mixes `repo_file` +
//     `finding` (the HTTP-side companion is represented as an extra
//     `finding`-kind ref, which is the same shape `bob_record_candidate_
//     claim` emits for any non-code-bound evidence).
//   - claim-freeze.json captures both ref kinds in the frozen evidence
//     payload so the freeze hash covers both surface families.
//   - The cross-mode session-state composition (target_repo + target_url
//     on the same scope_policy) is documented as drift below; the smoke
//     does NOT attempt to import an HTTP audit, because the import would
//     be rejected by the first-party scope check until the future
//     companion target tool ships.

test("Cycle O.10: cross-mode evidence-ref variant proves the 5-hash chain still binds when a claim mixes repo_file + finding refs (O-P6 primitive)", async () => {
  await withTempHome(async () => {
    const repoRoot = synthesizeOssRepoFixture();
    try {
      // Sentinel ref representing the HTTP-side companion finding. Per the
      // drift note this ref is a `finding`-kind ref instead of a true
      // `http_audit` ref because the live tool surface cannot import an
      // HTTP audit against a repo-only session (see comment block above).
      // The sentinel still proves the load-bearing O-P6 primitive: a single
      // CandidateClaim's evidence_refs[] mixes kinds and the freeze hash
      // covers all of them.
      const httpCompanionFindingId = "F-http-companion";
      const extraEvidenceRefsForFirstClaim = [
        {
          kind: "finding",
          finding_id: httpCompanionFindingId,
          content_hash: sha256Hex(`finding:cross_mode:http_companion`),
        },
      ];

      const result = await driveOssRealizationFlow({
        repoRoot,
        extraEvidenceRefsForFirstClaim,
      });

      // The 5-hash chain still binds for a cross-mode-shaped claim.
      assertFiveHashChain(result);

      // The frozen first claim carries BOTH ref kinds (repo_file and the
      // HTTP-side companion finding).
      const freezeOnDisk = JSON.parse(fs.readFileSync(claimFreezePath(result.domain), "utf8"));
      let foundRepoFile = false;
      let foundCompanion = false;
      for (const frozenClaim of freezeOnDisk.claims) {
        for (const ref of frozenClaim.evidence_refs || []) {
          if (!ref || typeof ref !== "object") continue;
          if (ref.kind === "repo_file" && ref.file_path === "src/parser.c") {
            foundRepoFile = true;
          }
          if (ref.kind === "finding" && ref.finding_id === httpCompanionFindingId) {
            foundCompanion = true;
          }
        }
      }
      assert.ok(foundRepoFile,
        "cross-mode claim must carry the repo_file evidence_ref in the frozen payload");
      assert.ok(foundCompanion,
        "cross-mode claim must carry the HTTP-side companion finding ref in the frozen payload");

      // The session is STILL repo-only at the scope-policy level. Per the
      // drift note the live tool surface cannot upgrade a repo session to
      // cross-mode at scope-policy granularity; the smoke records this
      // structural limit so a future cycle that adds the deferred
      // `bob_set_companion_target_url` tool can flip this assertion to a
      // positive `target_url` check without rewriting the rest of the
      // smoke.
      assert.equal(result.nucleus.scope_policy.target_url, undefined,
        "scope_policy.target_url stays undefined until a companion target tool ships");
      assert.ok(result.nucleus.scope_policy.target_repo,
        "scope_policy.target_repo remains the bound target on a cross-mode-claim repo session");
    } finally {
      fs.rmSync(repoRoot, { recursive: true, force: true });
    }
  });
});
