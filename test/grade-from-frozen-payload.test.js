"use strict";

// Cycle C.6 invariant: the GRADE phase sources its work-set from the frozen
// CandidateClaim batch (claim-freeze.json) rather than the live findings.jsonl
// ledger. Mutating findings.jsonl after the freeze must not change the grade
// verdict; the verdict records `claim_freeze_id` so a later consumer can prove
// which frozen claim batch was scored; and the C.5 evidence-completeness gate
// is preserved 1:1 on the new surface (an incomplete evidence pack still
// blocks the grade).

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");

const {
  buildClaimFreeze,
  readCurrentClaimFreeze,
} = require("../mcp/lib/claim-freeze.js");
const {
  appendJsonlLine,
  writeFileAtomic,
} = require("../mcp/lib/storage.js");
const {
  evidencePackPaths,
  gradeArtifactPaths,
  claimFreezePath,
  repoCommandRunsJsonlPath,
  repoInventoryPath,
  findingDifferentialVerifiedJsonlPath,
  sessionDir,
  verificationRoundPaths,
} = require("../mcp/lib/paths.js");
const {
  appendCandidateClaim,
} = require("../mcp/lib/claims.js");
const {
  buildRepoInventory,
  initRepoSession,
} = require("../mcp/lib/repo-target.js");
const {
  seedGenuineReproPair,
} = require("./helpers/repro-run-pair.js");
const {
  normalizeFindingRecord,
} = require("../mcp/lib/finding-contracts.js");
const {
  validateAgainstSchema,
} = require("../mcp/lib/tool-validation.js");
const recordFindingTool = require("../mcp/lib/tools/record-candidate-claim.js");
const {
  writeVerificationRound,
} = require("../mcp/lib/verification-round-store.js");
const {
  writeEvidencePacks,
} = require("../mcp/lib/evidence.js");
const {
  readGradeVerdict,
  writeGradeVerdict,
} = require("../mcp/lib/grade-verdict-store.js");
const {
  resetForTests: resetMaterializationDebounce,
} = require("../mcp/lib/frontier-materialize-debounce.js");
const {
  hashDocumentExcluding,
} = require("../mcp/lib/fabric-common.js");
const { withIsolatedSigner } = require("./helpers/sandbox-isolated-signer.js");

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-grade-from-frozen-"));
  process.env.HOME = home;
  try {
    // These tests grade verdict-ledger-backed reportable findings to exercise the
    // frozen-payload grade math, not the sandbox posture; run under an isolated
    // signer so the grade-door sandbox gate is inert (passes under enforce AND
    // degrade).
    return withIsolatedSigner(() => fn(home));
  } finally {
    process.env.HOME = previousHome;
    resetMaterializationDebounce();
    fs.rmSync(home, { recursive: true, force: true });
  }
}

function recordFindingViaTool(domain, overrides = {}) {
  const args = {
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
  };
  if (overrides.reachability_assertion) {
    args.reachability_assertion = overrides.reachability_assertion;
  }
  // Cross-tenant IDOR disclosure: network-reachable, low-privilege attacker
  // tenant, confidentiality impact. Callers asserting a reachability_assertion
  // (OSS) instead get attack_vector auto-derived, so leave cvss_inputs unset
  // there unless the override supplies it.
  if (overrides.cvss_inputs !== undefined) {
    if (overrides.cvss_inputs !== null) args.cvss_inputs = overrides.cvss_inputs;
  } else if (!overrides.reachability_assertion) {
    args.cvss_inputs = {
      attack_vector: "network",
      privileges_required: "low",
      confidentiality: "high",
    };
  }
  return JSON.parse(recordFindingTool.handler(args));
}

function appendClaimsJsonlDirect(domain, id, overrides = {}) {
  // Append a CandidateClaim directly so the live ledger drifts past the
  // freeze. The frozen grade work-set must remain anchored to the freeze.
  fs.mkdirSync(sessionDir(domain), { recursive: true });
  return appendCandidateClaim({
    target_domain: domain,
    title: overrides.title || `Post-freeze claim ${id}`,
    summary: overrides.description || "Mutated after the freeze",
    severity: overrides.severity || "critical",
    status: "candidate",
    surface_ids: [overrides.surface_id || "surface:post-freeze"],
    impact: overrides.impact || "Should not change grade verdict",
    evidence_refs: [{
      kind: "finding",
      finding_id: id,
      content_hash: "0".repeat(64),
    }],
  });
}

function verificationResult(findingId = "F-1", overrides = {}) {
  return {
    finding_id: findingId,
    disposition: "confirmed",
    severity: "high",
    reportable: true,
    reasoning: "Fresh replay confirmed the finding against the current target state.",
    ...overrides,
  };
}

function evidencePack(findingId = "F-1", overrides = {}) {
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
      observed_fields: ["billing_profile_id", "email"],
      redacted_object_id: "acct_...002",
    }],
    sensitive_clusters: ["billing metadata"],
    replay_summary: "Fresh replay returned another tenant's private billing metadata.",
    redaction_notes: "Object IDs and personal values redacted; auth material omitted.",
    report_snippet: "An attacker can retrieve another tenant's private billing metadata by changing the billing profile ID.",
    ...overrides,
  };
}

function gradeFinding(findingId = "F-1", overrides = {}) {
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

function writeRepoFile(root, relativePath, content) {
  const filePath = path.join(root, relativePath);
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, content, "utf8");
}

function seedLocalParserRepo(home, targetDomain) {
  const repo = path.join(home, targetDomain);
  fs.mkdirSync(repo, { recursive: true });
  writeRepoFile(repo, "CMakeLists.txt", "cmake_minimum_required(VERSION 3.22)\nproject(local_parser C)\n");
  writeRepoFile(repo, "src/parser.c", "int parse_packet(const char *buf, int len){ return len > 0 ? buf[0] : 0; }\n");
  writeRepoFile(repo, "server/httpd.c", [
    "#include <sys/socket.h>",
    "#include <netinet/in.h>",
    "int serve(void){",
    "  int fd = socket(AF_INET, SOCK_STREAM, 0);",
    "  listen(fd, 16);",
    "  return fd;",
    "}",
  ].join("\n"));
  const init = initRepoSession({ repo_path: repo, target_domain: targetDomain });
  buildRepoInventory({ target_domain: init.target_domain });
  return {
    target_domain: init.target_domain,
    surface_id: "repo:module:src-parser.c",
    network_surface_id: "repo:module:server-httpd.c",
  };
}

// The PoC recipe the reproduction verifier re-runs. Native high/critical findings
// declare it (on the claim's finding payload) and a matching verified_pass is
// seeded so the grade-time O-P4 gate can bind one to the other by command_hash.
const REPRO_COMMAND_ARGV = ["sh", "-lc", "./harness crash-input.bin"];

// Seed the MCP-write-only verified_pass ledger row the reproduction verifier would
// mint on a genuine differential flip (crashes vuln tree, quiet on fix tree),
// bound to REPRO_COMMAND_ARGV by command_hash.
// The O-P4 record gate requires a high/critical native-code claim to cite a
// backed repo_command_run row. Append the matching ledger row and return the
// evidence_ref so the frozen claim carries demonstrated (not inflated) impact.
const REPO_COMMAND_RUN_REF = Object.freeze({
  kind: "repo_command_run",
  run_id: "grade-repro-run-1",
  command_hash: "b".repeat(64),
  exit_code: 134,
  stdout_hash: "c".repeat(64),
  stderr_hash: "d".repeat(64),
});

function seedRepoCommandRun(domain) {
  appendJsonlLine(repoCommandRunsJsonlPath(domain), {
    run_id: REPO_COMMAND_RUN_REF.run_id,
    command_hash: REPO_COMMAND_RUN_REF.command_hash,
    exit_code: REPO_COMMAND_RUN_REF.exit_code,
    stdout_hash: REPO_COMMAND_RUN_REF.stdout_hash,
    stderr_hash: REPO_COMMAND_RUN_REF.stderr_hash,
    dry_run: false,
  });
}

// Seed a GENUINE flipping repro pair (two repo-command-runs rows + matching capture files)
// + the verified_pass verdict line citing it, so readReproVerifiedSummary's read-time
// re-adjudication ADMITS it at grade time. A bare verdict line citing nonexistent runs is
// no longer trusted.
function seedReproVerifiedPass(domain, findingId = "F-1") {
  seedGenuineReproPair(domain, {
    findingId,
    argv: REPRO_COMMAND_ARGV,
    // Distinct run ids per finding so multiple findings in one session never collide.
    vulnRunId: `repro-vuln-${findingId}`,
    controlRunId: `repro-control-${findingId}`,
  });
}

function seedFrozenRepoFinding(domain, surfaceIds, {
  findingId = "F-1",
  severity = "high",
  reachabilityAssertion = null,
} = {}) {
  const reproArgv = REPRO_COMMAND_ARGV;
  const isHighOrCritical = severity === "high" || severity === "critical";
  // A high/critical native claim must cite a backed repo_command_run row (O-P4);
  // seed the ledger row before recording so the frozen baseline is demonstrated.
  if (isHighOrCritical) seedRepoCommandRun(domain);
  const claim = {
    target_domain: domain,
    title: "Native parser over-read",
    summary: "Local file parser reads past the available buffer.",
    // Freeze at the demonstrated tier the verification rounds assert. The
    // repo/SC severity-rise guard clamps any verify-time rise above the frozen
    // baseline (no tiered SC allow-path), so a finding meant to be graded at
    // `severity` must be FROZEN at that tier, not raised at VERIFY.
    severity,
    status: "candidate",
    surface_ids: surfaceIds,
    evidence_refs: [
      {
        kind: "finding",
        finding_id: findingId,
        content_hash: "0".repeat(64),
      },
      ...(isHighOrCritical ? [REPO_COMMAND_RUN_REF] : []),
    ],
    impact: "Parser crash on crafted input.",
    payload: {
      finding: {
        id: findingId,
        capability_pack: "oss_native_code",
        repro_command_argv: reproArgv,
        ...(reachabilityAssertion ? { reachability_assertion: reachabilityAssertion } : {}),
      },
    },
  };
  appendCandidateClaim(claim);
  buildClaimFreeze(domain, {
    write: true,
    now: new Date("2026-05-27T01:00:00.000Z"),
  });
  for (const round of ["brutalist", "balanced", "final"]) {
    writeVerificationRound({
      target_domain: domain,
      round,
      notes: null,
      results: [verificationResult(findingId, { severity, reportable: true })],
    });
  }
  writeEvidencePacks({ target_domain: domain, packs: [evidencePack(findingId)] });
  // A native finding verified up to high/critical needs a differential
  // reproduction verified_pass to clear the grade-time O-P4 gate.
  if (severity === "high" || severity === "critical") {
    seedReproVerifiedPass(domain, findingId);
  }
}

// A standalone web (IDOR) finding is an executable-flip class; seed the
// finding-differential verified_pass arm the grade-time standalone gate requires so the
// web fixtures keep grading SUBMIT. Post-A1 the gate re-resolves the verdict against
// MAC-covered offensive-runs rows + re-adjudicates the flip, so seed a real MAC-signed
// exploited_safely positive + blocked_by_defense control (distinct command_hash, same
// surface, demonstrated severity >= the finding's), then the verdict line binding them.
function seedFindingDifferentialArm(domain, findingId = "F-1", surfaceId = "surface:billing-profile", demonstratedSeverity = "high") {
  const { canonicalizeExploitTarget } = require("../mcp/lib/claims.js");
  const { ensureHandoffSigningKey } = require("../mcp/lib/handoff-signing-key.js");
  const { signOffensiveRunRow } = require("../mcp/lib/offensive-row-mac.js");
  const { offensiveRowHash } = require("../mcp/lib/finding-differential-verifier.js");
  const { offensiveRunsJsonlPath } = require("../mcp/lib/paths.js");
  const mkRow = (suffix, outcome, ch) => {
    const row = {
      version: 1, target_domain: domain, run_id: `${findingId}-${suffix}`, tool_id: "bob_http_idor_confirm",
      target: canonicalizeExploitTarget(`https://${domain}/api/billing/1`),
      offensive_outcome: outcome, dry_run: false, timed_out: false,
      command_hash: ch, exit_code: 0, stdout_hash: "b".repeat(64), stderr_hash: "c".repeat(64),
      demonstrated_severity: demonstratedSeverity, surface_id: surfaceId,
    };
    signOffensiveRunRow(row, ensureHandoffSigningKey(domain));
    fs.mkdirSync(sessionDir(domain), { recursive: true });
    fs.appendFileSync(offensiveRunsJsonlPath(domain), `${JSON.stringify(row)}\n`);
    return row;
  };
  const positive = mkRow("pos", "exploited_safely", "1".repeat(64));
  const control = mkRow("ctl", "blocked_by_defense", "2".repeat(64));
  appendJsonlLine(findingDifferentialVerifiedJsonlPath(domain), {
    version: 1,
    target_domain: domain,
    finding_id: findingId,
    result: "verified_pass",
    reason: "executed_finding_differential_flip",
    surface_id: surfaceId,
    source: "offensive_runs",
    positive_run_id: `${findingId}-pos`,
    positive_row_hash: offensiveRowHash(positive),
    control_run_id: `${findingId}-ctl`,
    control_row_hash: offensiveRowHash(control),
  });
}

function seedFinalVerificationFromFrozen(domain, { findingId = "F-1" } = {}) {
  // Dual-write seeds a single CandidateClaim alongside the Finding.
  recordFindingViaTool(domain, { endpoint: "https://victim.example/api/billing/1" });
  // Freeze the claim batch so the verdict is bound to a stable claim_freeze_id.
  buildClaimFreeze(domain, {
    write: true,
    now: new Date("2026-05-27T01:00:00.000Z"),
  });
  // Write the V1 round chain. The C.6 path projects the work-set from the
  // frozen claim batch even though the verification artefacts are V1; the
  // round itself remains bound by content (reportable + severity) rather than
  // by snapshot hash.
  for (const round of ["brutalist", "balanced", "final"]) {
    writeVerificationRound({
      target_domain: domain,
      round,
      notes: null,
      results: [verificationResult(findingId)],
    });
  }
  writeEvidencePacks({ target_domain: domain, packs: [evidencePack(findingId)] });
  // The web IDOR fixture is a standalone executable-flip class; seed its arm row so the
  // grade-time standalone-finding gate is satisfied (it stays reportable, NO amputation).
  seedFindingDifferentialArm(domain, findingId);
}

test("grade verdict is bound to the frozen claim batch via claim_freeze_id", () => {
  withTempHome(() => {
    const domain = "grade-frozen-bound.example.com";
    seedFinalVerificationFromFrozen(domain);
    const freeze = readCurrentClaimFreeze(domain);
    assert.ok(freeze, "claim freeze must exist");
    assert.equal(freeze.claim_count, 1);

    const written = JSON.parse(writeGradeVerdict({
      target_domain: domain,
      verdict: "SUBMIT",
      total_score: 75,
      findings: [gradeFinding("F-1")],
    }));
    assert.equal(written.verdict, "SUBMIT");
    assert.equal(
      written.claim_freeze_id,
      freeze.freeze_id,
      "write response must echo the active claim_freeze_id",
    );

    const onDisk = JSON.parse(fs.readFileSync(gradeArtifactPaths(domain).json, "utf8"));
    assert.equal(
      onDisk.claim_freeze_id,
      freeze.freeze_id,
      "persisted grade verdict must carry claim_freeze_id pointing at the source freeze",
    );
    assert.equal(
      Object.prototype.hasOwnProperty.call(onDisk.findings[0], "reachability"),
      false,
      "ordinary non-repo findings must not receive unknown reachability metadata",
    );
    // Producer-fires proof: a no-reachability (web/SC) finding still gets its graded
    // severity (== recorded, uncapped) + defender word stamped, so the hosted witness
    // can light a severe live-target finding without a reachability stamp.
    assert.equal(onDisk.findings[0].graded_severity, "high");
    assert.equal(onDisk.findings[0].defender_disposition, "fix_now");

    const read = JSON.parse(readGradeVerdict({ target_domain: domain }));
    assert.equal(read.claim_freeze_id, freeze.freeze_id);
  });
});

test("reachability cap stamps graded severity without removing the reportable finding", () => {
  withTempHome((home) => {
    const repoSession = seedLocalParserRepo(home, "grade-reachability-cap");
    const domain = repoSession.target_domain;
    seedRepoCommandRun(domain);
    appendCandidateClaim({
      target_domain: domain,
      title: "Native parser over-read",
      summary: "Local file parser reads past the available buffer.",
      // Frozen at the demonstrated high tier (the repo/SC rise guard clamps any
      // verify-time rise above the baseline); the reachability cap then lowers
      // the GRADED severity to medium without clamping the recorded baseline.
      severity: "high",
      status: "candidate",
      surface_ids: [repoSession.surface_id],
      evidence_refs: [
        {
          kind: "finding",
          finding_id: "F-1",
          content_hash: "0".repeat(64),
        },
        REPO_COMMAND_RUN_REF,
      ],
      impact: "Parser crash on crafted local input.",
      payload: {
        finding: {
          id: "F-1",
          capability_pack: "oss_native_code",
          repro_command_argv: REPRO_COMMAND_ARGV,
        },
      },
    });
    seedReproVerifiedPass(domain, "F-1");
    buildClaimFreeze(domain, {
      write: true,
      now: new Date("2026-05-27T01:00:00.000Z"),
    });
    for (const round of ["brutalist", "balanced", "final"]) {
      writeVerificationRound({
        target_domain: domain,
        round,
        notes: null,
        results: [verificationResult("F-1", { severity: "high", reportable: true })],
      });
    }
    writeEvidencePacks({ target_domain: domain, packs: [evidencePack("F-1")] });
    // A native finding recorded at high needs a differential reproduction
    // verified_pass to clear the grade-time O-P4 gate.
    seedReproVerifiedPass(domain, "F-1");

    const written = JSON.parse(writeGradeVerdict({
      target_domain: domain,
      verdict: "SUBMIT",
      total_score: 75,
      findings: [gradeFinding("F-1")],
    }));
    assert.equal(written.verdict, "SUBMIT");
    assert.equal(written.findings_count, 1, "cap must not remove the finding from the reportable grade set");

    const onDisk = JSON.parse(fs.readFileSync(gradeArtifactPaths(domain).json, "utf8"));
    assert.equal(onDisk.findings.length, 1);
    assert.deepEqual(onDisk.findings[0].reachability, {
      recorded_severity: "high",
      severity_ceiling: "medium",
      attack_vector: "local",
      network_reachable: false,
      graded_severity: "medium",
      disposition: "capped",
      defensible: false,
      reachability_source: "heuristic",
    });

    const read = JSON.parse(readGradeVerdict({ target_domain: domain }));
    assert.equal(read.findings[0].reachability.graded_severity, "medium");
    assert.equal(read.findings[0].reachability.disposition, "capped");

    // Wiring proof (end-to-end): the grade verdict actually STAMPS the defender
    // relens per finding, and it reads the GRADED severity — capped-to-medium at a
    // submit score is worth_fixing, never fix_now, even though the RECORDED severity
    // was high. Reachability flows into the customer word exactly as into the grade.
    assert.equal(onDisk.findings[0].defender_disposition, "worth_fixing");
    assert.equal(read.findings[0].defender_disposition, "worth_fixing");

    appendCandidateClaim({
      target_domain: domain,
      title: "Post-freeze network duplicate",
      summary: "Live claim mutation must not change the frozen reachability surface.",
      severity: "medium",
      status: "candidate",
      surface_ids: [repoSession.network_surface_id],
      evidence_refs: [{
        kind: "finding",
        finding_id: "F-1",
        content_hash: "0".repeat(64),
      }],
      impact: "Should not affect the frozen grade verdict.",
    });
    writeGradeVerdict({
      target_domain: domain,
      verdict: "SUBMIT",
      total_score: 75,
      findings: [gradeFinding("F-1")],
    });
    const reread = JSON.parse(readGradeVerdict({ target_domain: domain }));
    assert.equal(
      reread.findings[0].reachability.disposition,
      "capped",
      "reachability must resolve from the frozen claim batch, not post-freeze live claims",
    );
  });
});

test("asserted local reachability overrides heuristic network and caps without dropping the finding", () => {
  withTempHome((home) => {
    const repoSession = seedLocalParserRepo(home, "grade-reachability-assert-local-over-network");
    const domain = repoSession.target_domain;
    seedFrozenRepoFinding(domain, [repoSession.network_surface_id], {
      reachabilityAssertion: {
        attack_vector: "local",
        network_reachable: false,
        call_path: "AgentX master unix socket -> handle_subagent_set_response -> parse_agentx_response",
        justification: "AgentX handling is local unix-socket IPC, not UDP-161 network input.",
      },
    });

    const written = JSON.parse(writeGradeVerdict({
      target_domain: domain,
      verdict: "SUBMIT",
      total_score: 75,
      findings: [gradeFinding("F-1")],
    }));
    assert.equal(written.findings_count, 1, "AV:L cap must not remove the finding from grade/reportability");

    const onDisk = JSON.parse(fs.readFileSync(gradeArtifactPaths(domain).json, "utf8"));
    assert.deepEqual(onDisk.findings[0].reachability, {
      recorded_severity: "high",
      severity_ceiling: "medium",
      attack_vector: "local",
      network_reachable: false,
      graded_severity: "medium",
      disposition: "capped",
      defensible: false,
      reachability_source: "asserted",
      call_path: "AgentX master unix socket -> handle_subagent_set_response -> parse_agentx_response",
      reachability_divergence: "asserted local/false overrides heuristic network/true; asserted local ceiling medium constrains producer ceiling critical",
    });
    const markdown = fs.readFileSync(gradeArtifactPaths(domain).markdown, "utf8");
    assert.match(markdown, /- Reachability Source: asserted/);
    assert.match(markdown, /- Reachability Call Path: AgentX master unix socket -> handle_subagent_set_response -> parse_agentx_response/);
    assert.match(markdown, /- Reachability Divergence: asserted local\/false overrides heuristic network\/true; asserted local ceiling medium constrains producer ceiling critical/);
  });
});

test("asserted network reachability overrides heuristic locality but preserves the producer ceiling", () => {
  withTempHome((home) => {
    const repoSession = seedLocalParserRepo(home, "grade-reachability-assert-network-over-local");
    const domain = repoSession.target_domain;
    seedFrozenRepoFinding(domain, [repoSession.surface_id], {
      reachabilityAssertion: {
        attack_vector: "network",
        network_reachable: true,
        call_path: "UDP-161 SNMP SET -> parse_pdu_value -> render_mib_value",
        justification: "The sink renders a reflected PDU value received over the SNMP listener.",
      },
    });

    writeGradeVerdict({
      target_domain: domain,
      verdict: "SUBMIT",
      total_score: 75,
      findings: [gradeFinding("F-1")],
    });

    const read = JSON.parse(readGradeVerdict({ target_domain: domain }));
    assert.deepEqual(read.findings[0].reachability, {
      recorded_severity: "high",
      severity_ceiling: "medium",
      attack_vector: "network",
      network_reachable: true,
      graded_severity: "medium",
      disposition: "capped",
      defensible: false,
      reachability_source: "asserted",
      call_path: "UDP-161 SNMP SET -> parse_pdu_value -> render_mib_value",
      reachability_divergence: "asserted network/true overrides heuristic local/false; producer ceiling medium constrains asserted network ceiling critical",
    });
  });
});

test("asserted reachability can grade without producer inventory and records an audit note", () => {
  withTempHome((home) => {
    const repoSession = seedLocalParserRepo(home, "grade-reachability-assertion-no-inventory");
    const domain = repoSession.target_domain;
    fs.rmSync(repoInventoryPath(domain), { force: true });
    seedFrozenRepoFinding(domain, [repoSession.surface_id], {
      reachabilityAssertion: {
        attack_vector: "network",
        network_reachable: true,
        call_path: "UDP listener -> parse_packet -> buffer read",
        justification: "The cited parser path is reached directly from UDP input.",
      },
    });

    writeGradeVerdict({
      target_domain: domain,
      verdict: "SUBMIT",
      total_score: 75,
      findings: [gradeFinding("F-1")],
    });

    const read = JSON.parse(readGradeVerdict({ target_domain: domain }));
    assert.deepEqual(read.findings[0].reachability, {
      recorded_severity: "high",
      severity_ceiling: "critical",
      attack_vector: "network",
      network_reachable: true,
      graded_severity: "high",
      disposition: "lifted",
      defensible: false,
      reachability_source: "asserted",
      call_path: "UDP listener -> parse_packet -> buffer read",
      reachability_divergence: "asserted reachability has no producer inventory or stamped-surface fallback",
    });
  });
});

test("asserted network reachability stays network when the heuristic agrees", () => {
  withTempHome((home) => {
    const repoSession = seedLocalParserRepo(home, "grade-reachability-assert-network-over-network");
    const domain = repoSession.target_domain;
    seedFrozenRepoFinding(domain, [repoSession.network_surface_id], {
      reachabilityAssertion: {
        attack_vector: "network",
        network_reachable: true,
        call_path: "UDP-161 SNMP SET -> write_vacmAccessStatus -> access_parse_oid",
        justification: "The call path starts at the UDP SNMP listener and reaches the sink.",
      },
    });

    writeGradeVerdict({
      target_domain: domain,
      verdict: "SUBMIT",
      total_score: 75,
      findings: [gradeFinding("F-1")],
    });

    const read = JSON.parse(readGradeVerdict({ target_domain: domain }));
    assert.deepEqual(read.findings[0].reachability, {
      recorded_severity: "high",
      severity_ceiling: "critical",
      attack_vector: "network",
      network_reachable: true,
      graded_severity: "high",
      disposition: "lifted",
      defensible: false,
      reachability_source: "asserted",
      call_path: "UDP-161 SNMP SET -> write_vacmAccessStatus -> access_parse_oid",
    });
  });
});

test("asserted network reachability does not exceed a stricter producer network ceiling", () => {
  withTempHome((home) => {
    const repoSession = seedLocalParserRepo(home, "grade-reachability-assert-network-bounded");
    const domain = repoSession.target_domain;
    const inventoryPath = repoInventoryPath(domain);
    const inventory = JSON.parse(fs.readFileSync(inventoryPath, "utf8"));
    const stamp = inventory.reachability.surface_ceilings.find((entry) => entry.id === repoSession.network_surface_id);
    stamp.severity_ceiling = "high";
    fs.writeFileSync(inventoryPath, JSON.stringify(inventory), "utf8");
    seedFrozenRepoFinding(domain, [repoSession.network_surface_id], {
      reachabilityAssertion: {
        attack_vector: "network",
        network_reachable: true,
        call_path: "TCP listener -> parse_packet -> bounded sink",
        justification: "The path is network-reachable, but the producer ceiling remains high.",
      },
    });

    writeGradeVerdict({
      target_domain: domain,
      verdict: "SUBMIT",
      total_score: 75,
      findings: [gradeFinding("F-1")],
    });

    const read = JSON.parse(readGradeVerdict({ target_domain: domain }));
    assert.deepEqual(read.findings[0].reachability, {
      recorded_severity: "high",
      severity_ceiling: "high",
      attack_vector: "network",
      network_reachable: true,
      graded_severity: "high",
      disposition: "lifted",
      defensible: false,
      reachability_source: "asserted",
      call_path: "TCP listener -> parse_packet -> bounded sink",
      reachability_divergence: "producer ceiling high constrains asserted network ceiling critical",
    });
  });
});

test("asserted local reachability records when it constrains a producer high ceiling", () => {
  withTempHome((home) => {
    const repoSession = seedLocalParserRepo(home, "grade-reachability-assert-local-bounds-high");
    const domain = repoSession.target_domain;
    const inventoryPath = repoInventoryPath(domain);
    const inventory = JSON.parse(fs.readFileSync(inventoryPath, "utf8"));
    const stamp = inventory.reachability.surface_ceilings.find((entry) => entry.id === repoSession.network_surface_id);
    stamp.severity_ceiling = "high";
    fs.writeFileSync(inventoryPath, JSON.stringify(inventory), "utf8");
    seedFrozenRepoFinding(domain, [repoSession.network_surface_id], {
      reachabilityAssertion: {
        attack_vector: "local",
        network_reachable: false,
        call_path: "local IPC message -> parse_packet -> bounded sink",
        justification: "The exploitable path is local-only even though the producer allows high.",
      },
    });

    writeGradeVerdict({
      target_domain: domain,
      verdict: "SUBMIT",
      total_score: 75,
      findings: [gradeFinding("F-1")],
    });

    const read = JSON.parse(readGradeVerdict({ target_domain: domain }));
    assert.deepEqual(read.findings[0].reachability, {
      recorded_severity: "high",
      severity_ceiling: "medium",
      attack_vector: "local",
      network_reachable: false,
      graded_severity: "medium",
      disposition: "capped",
      defensible: false,
      reachability_source: "asserted",
      call_path: "local IPC message -> parse_packet -> bounded sink",
      reachability_divergence: "asserted local/false overrides heuristic network/true; asserted local ceiling medium constrains producer ceiling high",
    });
  });
});

test("conflicting forced reachability assertions use the earliest assertion with an audit note", () => {
  withTempHome((home) => {
    const repoSession = seedLocalParserRepo(home, "grade-reachability-conflicting-forced");
    const domain = repoSession.target_domain;
    const baseClaim = {
      target_domain: domain,
      title: "Native parser over-read",
      summary: "Parser reads past the available buffer.",
      severity: "medium",
      status: "candidate",
      created_at: "2026-05-27T00:00:00.000Z",
      surface_ids: [repoSession.surface_id],
      evidence_refs: [{
        kind: "finding",
        finding_id: "F-1",
        content_hash: "0".repeat(64),
      }],
      impact: "Parser crash on crafted input.",
    };
    appendCandidateClaim({
      ...baseClaim,
      payload: {
        finding: {
          id: "F-1",
          repro_command_argv: REPRO_COMMAND_ARGV,
          capability_pack: "oss_native_code",
          reachability_assertion: {
            attack_vector: "network",
            network_reachable: true,
            call_path: "UDP listener -> parse_packet -> buffer read",
          },
        },
      },
    });
    appendCandidateClaim({
      ...baseClaim,
      title: "Native parser over-read duplicate",
      created_at: "2026-05-27T00:00:01.000Z",
      payload: {
        finding: {
          id: "F-1",
          repro_command_argv: REPRO_COMMAND_ARGV,
          capability_pack: "oss_native_code",
          reachability_assertion: {
            attack_vector: "local",
            network_reachable: false,
            call_path: "local file input -> parse_packet -> buffer read",
          },
        },
      },
    });
    buildClaimFreeze(domain, {
      write: true,
      now: new Date("2026-05-27T01:00:00.000Z"),
    });
    for (const round of ["brutalist", "balanced", "final"]) {
      writeVerificationRound({
        target_domain: domain,
        round,
        notes: null,
        results: [verificationResult("F-1", { severity: "high", reportable: true })],
      });
    }
    writeEvidencePacks({ target_domain: domain, packs: [evidencePack("F-1")] });
    seedReproVerifiedPass(domain);

    writeGradeVerdict({
      target_domain: domain,
      verdict: "SUBMIT",
      total_score: 75,
      findings: [gradeFinding("F-1")],
    });

    const read = JSON.parse(readGradeVerdict({ target_domain: domain }));
    assert.equal(read.findings[0].reachability.attack_vector, "network");
    assert.equal(read.findings[0].reachability.reachability_source, "asserted");
    assert.equal(
      read.findings[0].reachability.reachability_divergence,
      "conflicting reachability assertions present (2); using earliest; asserted network/true overrides heuristic local/false; producer ceiling medium constrains asserted network ceiling critical",
    );
  });
});

test("same-classification frozen reachability assertions with different call paths do not conflict", () => {
  withTempHome((home) => {
    const repoSession = seedLocalParserRepo(home, "grade-reachability-assertion-refined-path");
    const domain = repoSession.target_domain;
    const baseClaim = {
      target_domain: domain,
      title: "Native parser over-read",
      summary: "Parser reads past the available buffer.",
      severity: "medium",
      status: "candidate",
      created_at: "2026-05-27T00:00:00.000Z",
      surface_ids: [repoSession.surface_id],
      evidence_refs: [{
        kind: "finding",
        finding_id: "F-1",
        content_hash: "0".repeat(64),
      }],
      impact: "Parser crash on crafted input.",
    };
    appendCandidateClaim({
      ...baseClaim,
      payload: {
        finding: {
          id: "F-1",
          repro_command_argv: REPRO_COMMAND_ARGV,
          capability_pack: "oss_native_code",
          reachability_assertion: {
            attack_vector: "network",
            network_reachable: true,
            call_path: "UDP listener -> parse_packet -> buffer read",
          },
        },
      },
    });
    appendCandidateClaim({
      ...baseClaim,
      title: "Native parser over-read refined path",
      created_at: "2026-05-27T00:00:01.000Z",
      payload: {
        finding: {
          id: "F-1",
          repro_command_argv: REPRO_COMMAND_ARGV,
          capability_pack: "oss_native_code",
          reachability_assertion: {
            attack_vector: "network",
            network_reachable: true,
            call_path: "UDP listener -> parse_pdu_value -> decode_varbind -> buffer read",
          },
        },
      },
    });
    buildClaimFreeze(domain, {
      write: true,
      now: new Date("2026-05-27T01:00:00.000Z"),
    });
    for (const round of ["brutalist", "balanced", "final"]) {
      writeVerificationRound({
        target_domain: domain,
        round,
        notes: null,
        results: [verificationResult("F-1", { severity: "high", reportable: true })],
      });
    }
    writeEvidencePacks({ target_domain: domain, packs: [evidencePack("F-1")] });
    seedReproVerifiedPass(domain);

    writeGradeVerdict({
      target_domain: domain,
      verdict: "SUBMIT",
      total_score: 75,
      findings: [gradeFinding("F-1")],
    });

    const read = JSON.parse(readGradeVerdict({ target_domain: domain }));
    assert.equal(read.findings[0].reachability.reachability_source, "asserted");
    assert.equal(read.findings[0].reachability.call_path, "UDP listener -> parse_pdu_value -> decode_varbind -> buffer read");
    assert.doesNotMatch(
      read.findings[0].reachability.reachability_divergence || "",
      /conflicting reachability assertions/,
    );
  });
});

test("reachability assertion ordering sorts missing created_at after valid timestamps", () => {
  withTempHome((home) => {
    const repoSession = seedLocalParserRepo(home, "grade-reachability-assertion-missing-created-at");
    const domain = repoSession.target_domain;
    const baseClaim = {
      target_domain: domain,
      title: "Native parser over-read",
      summary: "Parser reads past the available buffer.",
      severity: "medium",
      status: "candidate",
      surface_ids: [repoSession.network_surface_id],
      evidence_refs: [{
        kind: "finding",
        finding_id: "F-1",
        content_hash: "0".repeat(64),
      }],
      impact: "Parser crash on crafted input.",
    };
    appendCandidateClaim({
      ...baseClaim,
      created_at: "2026-05-27T00:00:01.000Z",
      payload: {
        finding: {
          id: "F-1",
          repro_command_argv: REPRO_COMMAND_ARGV,
          capability_pack: "oss_native_code",
          reachability_assertion: {
            attack_vector: "network",
            network_reachable: true,
            call_path: "UDP listener -> parse_packet -> buffer read",
          },
        },
      },
    });
    appendCandidateClaim({
      ...baseClaim,
      title: "Native parser local correction",
      created_at: "2026-05-27T00:00:02.000Z",
      payload: {
        finding: {
          id: "F-1",
          repro_command_argv: REPRO_COMMAND_ARGV,
          capability_pack: "oss_native_code",
          reachability_assertion: {
            attack_vector: "local",
            network_reachable: false,
            call_path: "local IPC -> parse_packet -> buffer read",
          },
        },
      },
    });
    const freeze = buildClaimFreeze(domain, {
      write: true,
      now: new Date("2026-05-27T01:00:00.000Z"),
    });
    const undatedClaim = freeze.claims.find((claim) => (
      claim
      && claim.payload
      && claim.payload.finding
      && claim.payload.finding.reachability_assertion
      && claim.payload.finding.reachability_assertion.attack_vector === "network"
    ));
    assert.ok(undatedClaim, "fixture must include a network assertion to make timestamp fallback observable");
    delete undatedClaim.created_at;
    freeze.freeze_hash = hashDocumentExcluding(freeze, ["frozen_at", "freeze_hash"]);
    // This fixture hand-edits the frozen doc (drops a claim's created_at) and re-writes it
    // raw, so the Cycle B freeze_mac minted by buildClaimFreeze no longer covers the
    // content. Drop it so the re-written doc is a clean LEGACY (unsigned) freeze accepted-
    // with-warning by readCurrentClaimFreeze — not a present-but-invalid (tampered) mac,
    // which would correctly fail closed. The keying integrity is exercised in the dedicated
    // claim-freeze-mac-keying tests; this test exercises reachability-assertion ordering.
    delete freeze.freeze_mac;
    writeFileAtomic(claimFreezePath(domain), `${JSON.stringify(freeze, null, 2)}\n`);
    for (const round of ["brutalist", "balanced", "final"]) {
      writeVerificationRound({
        target_domain: domain,
        round,
        notes: null,
        results: [verificationResult("F-1", { severity: "high", reportable: true })],
      });
    }
    writeEvidencePacks({ target_domain: domain, packs: [evidencePack("F-1")] });
    seedReproVerifiedPass(domain);

    writeGradeVerdict({
      target_domain: domain,
      verdict: "SUBMIT",
      total_score: 75,
      findings: [gradeFinding("F-1")],
    });

    const read = JSON.parse(readGradeVerdict({ target_domain: domain }));
    assert.equal(read.findings[0].reachability.attack_vector, "local");
    assert.equal(read.findings[0].reachability.network_reachable, false);
    assert.equal(read.findings[0].reachability.call_path, "local IPC -> parse_packet -> buffer read");
    assert.equal(
      read.findings[0].reachability.reachability_divergence,
      "conflicting reachability assertions present (2); using earliest; asserted local/false overrides heuristic network/true; asserted local ceiling medium constrains producer ceiling critical",
    );
  });
});

test("grade-time reachability ignores malformed or idless frozen assertions", () => {
  withTempHome((home) => {
    const repoSession = seedLocalParserRepo(home, "grade-reachability-assertion-bad-frozen");
    const domain = repoSession.target_domain;
    seedRepoCommandRun(domain);
    const baseClaim = {
      target_domain: domain,
      title: "Native parser over-read",
      summary: "Parser reads past the available buffer.",
      // The F-1-bearing claims are frozen at the demonstrated high tier (backed
      // by repo_command_run) so the recorded baseline is high; the valid network
      // assertion then LIFTS the graded severity. The idless first claim stays
      // medium (it carries no finding id / repro recipe and is ignored).
      severity: "high",
      status: "candidate",
      surface_ids: [repoSession.network_surface_id],
      evidence_refs: [
        {
          kind: "finding",
          finding_id: "F-1",
          content_hash: "0".repeat(64),
        },
        REPO_COMMAND_RUN_REF,
      ],
      impact: "Parser crash on crafted input.",
    };
    appendCandidateClaim({
      ...baseClaim,
      severity: "medium",
      evidence_refs: [{
        kind: "finding",
        finding_id: "F-1",
        content_hash: "0".repeat(64),
      }],
      created_at: "2026-05-27T00:00:00.000Z",
      payload: {
        finding: {
          capability_pack: "oss_native_code",
          reachability_assertion: {
            attack_vector: "local",
            network_reachable: false,
            call_path: "local IPC -> parse_packet -> buffer read",
          },
        },
      },
    });
    appendCandidateClaim({
      ...baseClaim,
      title: "Malformed frozen assertion",
      created_at: "2026-05-27T00:00:01.000Z",
      payload: {
        finding: {
          id: "F-1",
          repro_command_argv: REPRO_COMMAND_ARGV,
          capability_pack: "oss_native_code",
          reachability_assertion: {
            attack_vector: "network",
            network_reachable: false,
            call_path: "UDP listener -> parse_packet -> buffer read",
          },
        },
      },
    });
    appendCandidateClaim({
      ...baseClaim,
      title: "Valid frozen assertion",
      created_at: "2026-05-27T00:00:02.000Z",
      payload: {
        finding: {
          id: "F-1",
          repro_command_argv: REPRO_COMMAND_ARGV,
          capability_pack: "oss_native_code",
          reachability_assertion: {
            attack_vector: "network",
            network_reachable: true,
            call_path: "UDP listener -> parse_packet -> buffer read",
          },
        },
      },
    });
    buildClaimFreeze(domain, {
      write: true,
      now: new Date("2026-05-27T01:00:00.000Z"),
    });
    for (const round of ["brutalist", "balanced", "final"]) {
      writeVerificationRound({
        target_domain: domain,
        round,
        notes: null,
        results: [verificationResult("F-1", { severity: "high", reportable: true })],
      });
    }
    writeEvidencePacks({ target_domain: domain, packs: [evidencePack("F-1")] });
    seedReproVerifiedPass(domain);

    writeGradeVerdict({
      target_domain: domain,
      verdict: "SUBMIT",
      total_score: 75,
      findings: [gradeFinding("F-1")],
    });

    const read = JSON.parse(readGradeVerdict({ target_domain: domain }));
    assert.equal(read.findings[0].reachability.attack_vector, "network");
    assert.equal(read.findings[0].reachability.reachability_source, "asserted");
    assert.equal(read.findings[0].reachability.call_path, "UDP listener -> parse_packet -> buffer read");
    assert.equal(read.findings[0].reachability.disposition, "lifted");
    assert.match(
      read.findings[0].reachability.reachability_divergence,
      /invalid reachability assertion in CL-[a-f0-9]+: reachability_assertion\.network_reachable must be true when attack_vector is network/,
    );
  });
});

test("corrupt frozen reachability assertion fallback is audited and not defensible", () => {
  withTempHome((home) => {
    const repoSession = seedLocalParserRepo(home, "grade-reachability-corrupt-fallback");
    const domain = repoSession.target_domain;
    seedRepoCommandRun(domain);
    appendCandidateClaim({
      target_domain: domain,
      title: "Native parser over-read",
      summary: "Parser reads past the available buffer.",
      // Frozen at high (demonstrated, repo_command_run-backed). The corrupt
      // assertion fallback then lifts the network ceiling above this recorded
      // baseline; the repo/SC rise guard does not touch a frozen baseline.
      severity: "high",
      status: "candidate",
      created_at: "2026-05-27T00:00:00.000Z",
      surface_ids: [repoSession.network_surface_id],
      evidence_refs: [
        {
          kind: "finding",
          finding_id: "F-1",
          content_hash: "0".repeat(64),
        },
        REPO_COMMAND_RUN_REF,
      ],
      impact: "Parser crash on crafted input.",
      payload: {
        finding: {
          id: "F-1",
          repro_command_argv: REPRO_COMMAND_ARGV,
          capability_pack: "oss_native_code",
          reachability_assertion: {
            attack_vector: "network",
            network_reachable: false,
            call_path: "UDP listener -> parse_packet -> buffer read",
          },
        },
      },
    });
    buildClaimFreeze(domain, {
      write: true,
      now: new Date("2026-05-27T01:00:00.000Z"),
    });
    for (const round of ["brutalist", "balanced", "final"]) {
      writeVerificationRound({
        target_domain: domain,
        round,
        notes: null,
        results: [verificationResult("F-1", { severity: "high", reportable: true })],
      });
    }
    writeEvidencePacks({ target_domain: domain, packs: [evidencePack("F-1")] });
    seedReproVerifiedPass(domain);

    writeGradeVerdict({
      target_domain: domain,
      verdict: "SUBMIT",
      total_score: 75,
      findings: [gradeFinding("F-1")],
    });

    const read = JSON.parse(readGradeVerdict({ target_domain: domain }));
    assert.equal(read.findings[0].reachability.reachability_source, "heuristic");
    assert.equal(read.findings[0].reachability.disposition, "lifted");
    assert.equal(read.findings[0].reachability.defensible, false);
    assert.match(
      read.findings[0].reachability.reachability_divergence,
      /invalid reachability assertion in CL-[a-f0-9]+: reachability_assertion\.network_reachable must be true when attack_vector is network/,
    );
  });
});

test("record-candidate-claim rejects reachability assertions without a call_path", () => {
  withTempHome(() => {
    assert.throws(
      () => recordFindingViaTool("reachability-assertion-missing-path.example.com", {
        reachability_assertion: {
          attack_vector: "network",
          network_reachable: true,
          justification: "Missing the cited entrypoint-to-sink path.",
        },
      }),
      /reachability_assertion\.call_path must be a non-empty string/,
    );
  });
});

test("record-candidate-claim rejects reachability assertions on web-routed findings", () => {
  withTempHome(() => {
    assert.throws(
      () => recordFindingViaTool("reachability-assertion-web-rejected.example.com", {
        reachability_assertion: {
          attack_vector: "network",
          network_reachable: true,
          call_path: "HTTP route -> controller -> sink",
          justification: "Web findings must not use repo reachability assertions.",
        },
      }),
      /reachability_assertion is only allowed for oss_native_code findings/,
    );
  });
});

test("reachability assertions require a structured entrypoint-to-sink call_path", () => {
  const schema = recordFindingTool.inputSchema
    .properties.reachability_assertion
    .properties.call_path;
  const schemaAccepts = (callPath) => {
    try {
      validateAgainstSchema(callPath, schema, ["reachability_assertion", "call_path"]);
      return true;
    } catch {
      return false;
    }
  };
  const normalizerAccepts = (callPath) => {
    try {
      normalizeFindingRecord({
        id: "F-1",
        target_domain: "reachability-assertion-path-contract.example.com",
        title: "Native parser over-read",
        severity: "high",
        endpoint: "src/parser.c",
        description: "Parser reads past the available buffer.",
        proof_of_concept: "Run the parser against the crafted input.",
        validated: true,
        capability_pack: "oss_native_code",
        evaluator_agent: "evaluator-agent",
        brief_profile: "oss",
        reachability_assertion: {
          attack_vector: "network",
          network_reachable: true,
          call_path: callPath,
        },
      });
      return true;
    } catch {
      return false;
    }
  };
  const assertRejectedBySchemaAndNormalizer = (callPath) => {
    assert.equal(schemaAccepts(callPath), false, `${callPath} must be rejected by the schema`);
    assert.equal(normalizerAccepts(callPath), false, `${callPath} must be rejected by the normalizer`);
  };
  const assertAcceptedBySchemaAndNormalizer = (callPath) => {
    assert.equal(schemaAccepts(callPath), true, `${callPath} must be accepted by the schema`);
    assert.equal(normalizerAccepts(callPath), true, `${callPath} must be accepted by the normalizer`);
  };

  assertRejectedBySchemaAndNormalizer("a->x->->");
  assertRejectedBySchemaAndNormalizer("X->Y->->");
  assertAcceptedBySchemaAndNormalizer("a->b->c");
  assertAcceptedBySchemaAndNormalizer("UDP-161 SNMP SET -> write_vacmAccessStatus -> access_parse_oid");

  const fuzzSegments = ["", " ", "a", " b ", "X", "-", "UDP-161 SNMP SET"];
  const fuzzInputs = new Set(["x", "a->b", "a->b->c\n"]);
  for (const first of fuzzSegments) {
    for (const second of fuzzSegments) {
      for (const third of fuzzSegments) {
        fuzzInputs.add(`${first}->${second}->${third}`);
        for (const fourth of fuzzSegments) {
          fuzzInputs.add(`${first}->${second}->${third}->${fourth}`);
        }
      }
    }
  }
  for (const callPath of fuzzInputs) {
    assert.ok(
      !(schemaAccepts(callPath) && !normalizerAccepts(callPath)),
      `schema accepted a call_path the normalizer rejected: ${JSON.stringify(callPath)}`,
    );
  }

  assert.throws(
    () => normalizeFindingRecord({
      id: "F-1",
      target_domain: "reachability-assertion-short-path.example.com",
      title: "Native parser over-read",
      severity: "high",
      endpoint: "src/parser.c",
      description: "Parser reads past the available buffer.",
      proof_of_concept: "Run the parser against the crafted input.",
      validated: true,
      capability_pack: "oss_native_code",
      evaluator_agent: "evaluator-agent",
      brief_profile: "oss",
      reachability_assertion: {
        attack_vector: "network",
        network_reachable: true,
        call_path: "x",
      },
    }),
    /reachability_assertion\.call_path must cite an entrypoint-to-sink path/,
  );
  assert.throws(
    () => normalizeFindingRecord({
      id: "F-1",
      target_domain: "reachability-assertion-one-hop-path.example.com",
      title: "Native parser over-read",
      severity: "high",
      endpoint: "src/parser.c",
      description: "Parser reads past the available buffer.",
      proof_of_concept: "Run the parser against the crafted input.",
      validated: true,
      capability_pack: "oss_native_code",
      evaluator_agent: "evaluator-agent",
      brief_profile: "oss",
      reachability_assertion: {
        attack_vector: "network",
        network_reachable: true,
        call_path: "entrypoint -> sink",
      },
    }),
    /reachability_assertion\.call_path must cite an entrypoint-to-sink path with at least two '->' hops/,
  );
  assert.throws(
    () => normalizeFindingRecord({
      id: "F-1",
      target_domain: "reachability-assertion-multiline-path.example.com",
      title: "Native parser over-read",
      severity: "high",
      endpoint: "src/parser.c",
      description: "Parser reads past the available buffer.",
      proof_of_concept: "Run the parser against the crafted input.",
      validated: true,
      capability_pack: "oss_native_code",
      evaluator_agent: "evaluator-agent",
      brief_profile: "oss",
      reachability_assertion: {
        attack_vector: "network",
        network_reachable: true,
        call_path: "listener -> parser\n## forged grade section -> sink",
      },
    }),
    /reachability_assertion\.call_path must not contain line breaks/,
  );
  const normalized = normalizeFindingRecord({
    id: "F-1",
    target_domain: "reachability-assertion-canonical-path.example.com",
    title: "Native parser over-read",
    severity: "high",
    endpoint: "src/parser.c",
    description: "Parser reads past the available buffer.",
    proof_of_concept: "Run the parser against the crafted input.",
    validated: true,
    capability_pack: "oss_native_code",
    evaluator_agent: "evaluator-agent",
    brief_profile: "oss",
    reachability_assertion: {
      attack_vector: "network",
      network_reachable: true,
      call_path: " listener  ->  parser -> sink ",
    },
  });
  assert.equal(normalized.reachability_assertion.call_path, "listener -> parser -> sink");
});

test("reachability assertion does not change finding dedupe identity", () => {
  withTempHome(() => {
    const base = {
      id: "F-1",
      target_domain: "reachability-assertion-dedupe.example.com",
      title: "Native parser over-read",
      severity: "high",
      endpoint: "src/parser.c",
      description: "Parser reads past the available buffer.",
      proof_of_concept: "Run the parser against the crafted input.",
      validated: true,
      capability_pack: "oss_native_code",
      evaluator_agent: "evaluator-agent",
      brief_profile: "oss",
    };
    const first = normalizeFindingRecord({
      ...base,
      reachability_assertion: {
        attack_vector: "network",
        network_reachable: true,
        call_path: "UDP listener -> parse_packet -> sink",
      },
    });
    const second = normalizeFindingRecord({
      ...base,
      reachability_assertion: {
        attack_vector: "local",
        network_reachable: false,
        call_path: "local file parser -> parse_packet -> sink",
      },
    });

    assert.equal(second.dedupe_key, first.dedupe_key);
  });
});

test("non-OSS frozen reachability assertions are ignored at grade time", () => {
  withTempHome(() => {
    const domain = "grade-reachability-web-assertion-ignored.example.com";
    appendCandidateClaim({
      target_domain: domain,
      title: "IDOR on billing profile",
      summary: "Tenant boundary allows cross-account view.",
      severity: "high",
      status: "candidate",
      surface_ids: ["surface:billing-profile"],
      evidence_refs: [{
        kind: "finding",
        finding_id: "F-1",
        content_hash: "0".repeat(64),
      }],
      impact: "Cross-tenant billing disclosure.",
      payload: {
        finding: {
          id: "F-1",
          capability_pack: "web",
          reachability_assertion: {
            attack_vector: "network",
            network_reachable: true,
            call_path: "HTTP route -> controller -> sink",
          },
        },
      },
    });
    buildClaimFreeze(domain, {
      write: true,
      now: new Date("2026-05-27T01:00:00.000Z"),
    });
    for (const round of ["brutalist", "balanced", "final"]) {
      writeVerificationRound({
        target_domain: domain,
        round,
        notes: null,
        results: [verificationResult("F-1", { severity: "high", reportable: true })],
      });
    }
    writeEvidencePacks({ target_domain: domain, packs: [evidencePack("F-1")] });
    // Standalone web (IDOR) executable-flip class: seed its arm row so the grade-time
    // standalone-finding gate is satisfied (isolates the reachability behavior under test).
    seedFindingDifferentialArm(domain, "F-1");

    writeGradeVerdict({
      target_domain: domain,
      verdict: "SUBMIT",
      total_score: 75,
      findings: [gradeFinding("F-1")],
    });

    const read = JSON.parse(readGradeVerdict({ target_domain: domain }));
    assert.equal(Object.prototype.hasOwnProperty.call(read.findings[0], "reachability"), false);
  });
});

test("grade verdict write rejects unresolved reachability for reportable repo module findings", () => {
  withTempHome((home) => {
    const repoSession = seedLocalParserRepo(home, "grade-reachability-missing");
    const domain = repoSession.target_domain;
    appendCandidateClaim({
      target_domain: domain,
      title: "Native parser over-read",
      summary: "Local file parser reads past the available buffer.",
      severity: "medium",
      status: "candidate",
      surface_ids: ["repo:module:missing-surface.c"],
      evidence_refs: [{
        kind: "finding",
        finding_id: "F-1",
        content_hash: "0".repeat(64),
      }],
      impact: "Parser crash on crafted local input.",
    });
    buildClaimFreeze(domain, {
      write: true,
      now: new Date("2026-05-27T01:00:00.000Z"),
    });
    for (const round of ["brutalist", "balanced", "final"]) {
      writeVerificationRound({
        target_domain: domain,
        round,
        notes: null,
        results: [verificationResult("F-1", { severity: "high", reportable: true })],
      });
    }
    writeEvidencePacks({ target_domain: domain, packs: [evidencePack("F-1")] });

    assert.throws(
      () => writeGradeVerdict({
        target_domain: domain,
        verdict: "SUBMIT",
        total_score: 75,
        findings: [gradeFinding("F-1")],
      }),
      /Reachability stamps are required.*F-1/,
      "direct grade writes must not bypass the repo-module reachability gate",
    );
  });
});

test("grade verdict write rejects absent reachability inventory for reportable repo module findings", () => {
  withTempHome((home) => {
    const repo = path.join(home, "grade-reachability-absent");
    fs.mkdirSync(repo, { recursive: true });
    writeRepoFile(repo, "CMakeLists.txt", "cmake_minimum_required(VERSION 3.22)\nproject(absent_inventory C)\n");
    writeRepoFile(repo, "src/parser.c", "int parse_packet(const char *buf, int len){ return len > 0 ? buf[0] : 0; }\n");
    const init = initRepoSession({ repo_path: repo, target_domain: "grade-reachability-absent" });
    const domain = init.target_domain;
    seedFrozenRepoFinding(domain, ["repo:module:src-parser.c"]);

    assert.throws(
      () => writeGradeVerdict({
        target_domain: domain,
        verdict: "SUBMIT",
        total_score: 75,
        findings: [gradeFinding("F-1")],
      }),
      /Reachability inventory is required.*F-1/,
      "direct grade writes must fail closed when repo-inventory.json has no reachability cycle",
    );
  });
});

test("reachability aggregation keeps mixed frozen repo module surfaces capped by the local surface", () => {
  withTempHome((home) => {
    const repoSession = seedLocalParserRepo(home, "grade-reachability-mixed-surfaces");
    const domain = repoSession.target_domain;
    seedFrozenRepoFinding(domain, [repoSession.surface_id, repoSession.network_surface_id]);

    writeGradeVerdict({
      target_domain: domain,
      verdict: "SUBMIT",
      total_score: 75,
      findings: [gradeFinding("F-1")],
    });

    const read = JSON.parse(readGradeVerdict({ target_domain: domain }));
    assert.deepEqual(read.findings[0].reachability, {
      recorded_severity: "high",
      severity_ceiling: "medium",
      attack_vector: "local",
      network_reachable: false,
      graded_severity: "medium",
      disposition: "capped",
      defensible: false,
      reachability_source: "heuristic",
    });
  });
});

test("reachability aggregation does not turn attack_vector network with network_reachable false into AV:N", () => {
  withTempHome((home) => {
    const repoSession = seedLocalParserRepo(home, "grade-reachability-network-false");
    const domain = repoSession.target_domain;
    const inventoryPath = repoInventoryPath(domain);
    const inventory = JSON.parse(fs.readFileSync(inventoryPath, "utf8"));
    const parserStamp = inventory.reachability.surface_ceilings.find((entry) => entry.id === repoSession.surface_id);
    assert.ok(parserStamp, "repo inventory must include the parser reachability stamp");
    parserStamp.attack_vector = "network";
    parserStamp.network_reachable = false;
    parserStamp.severity_ceiling = "critical";
    fs.writeFileSync(inventoryPath, JSON.stringify(inventory), "utf8");
    seedFrozenRepoFinding(domain, [repoSession.surface_id]);

    writeGradeVerdict({
      target_domain: domain,
      verdict: "SUBMIT",
      total_score: 75,
      findings: [gradeFinding("F-1")],
    });

    const read = JSON.parse(readGradeVerdict({ target_domain: domain }));
    assert.deepEqual(read.findings[0].reachability, {
      recorded_severity: "high",
      severity_ceiling: "critical",
      attack_vector: "local",
      network_reachable: false,
      graded_severity: "high",
      disposition: "unchanged",
      defensible: false,
      reachability_source: "heuristic",
    });
  });
});

test("mutating claims.jsonl after the freeze does NOT change the grade verdict (frozen set authoritative)", () => {
  withTempHome(() => {
    const domain = "grade-frozen-stability.example.com";
    seedFinalVerificationFromFrozen(domain);

    const baseline = JSON.parse(writeGradeVerdict({
      target_domain: domain,
      verdict: "SUBMIT",
      total_score: 75,
      findings: [gradeFinding("F-1")],
    }));
    const baselineDoc = JSON.parse(fs.readFileSync(gradeArtifactPaths(domain).json, "utf8"));
    const baselineFreezeId = baseline.claim_freeze_id;
    assert.ok(typeof baselineFreezeId === "string" && baselineFreezeId, "baseline must carry claim_freeze_id");

    // Mutate claims.jsonl AFTER the freeze + AFTER the verdict is written.
    // The grade work-set is enumerated from the frozen claims[], so a new
    // critical claim must not change the verdict.
    appendClaimsJsonlDirect(domain, "F-99", { severity: "critical" });

    // Rewrite the verdict (so we hit the C.6 write-path with the post-mutation
    // disk state). The verdict must still ignore F-99 because the freeze is
    // the source of the work-set, not claims.jsonl.
    const rewritten = JSON.parse(writeGradeVerdict({
      target_domain: domain,
      verdict: "SUBMIT",
      total_score: 75,
      findings: [gradeFinding("F-1")],
    }));
    const rewrittenDoc = JSON.parse(fs.readFileSync(gradeArtifactPaths(domain).json, "utf8"));

    assert.equal(rewritten.verdict, baseline.verdict);
    assert.equal(rewritten.findings_count, baseline.findings_count);
    assert.equal(
      rewritten.claim_freeze_id,
      baselineFreezeId,
      "claim_freeze_id must reference the same source freeze; mutations are ignored",
    );
    assert.equal(rewrittenDoc.claim_freeze_id, baselineDoc.claim_freeze_id);
    assert.equal(rewrittenDoc.findings.length, 1);
    assert.equal(rewrittenDoc.findings[0].finding_id, "F-1");

    // Attempting to grade the post-freeze critical finding (F-99) must be
    // rejected by the unknown-finding-id guard — F-99 is not in the frozen
    // claim batch, so it cannot be scored.
    assert.throws(
      () => writeGradeVerdict({
        target_domain: domain,
        verdict: "SUBMIT",
        total_score: 75,
        findings: [gradeFinding("F-99")],
      }),
      /Unknown finding_id: F-99/,
      "frozen work-set must reject grading findings added after the freeze",
    );
  });
});

test("strict gate: incomplete evidence (C.5 completeness contract) blocks the grade verdict", () => {
  withTempHome(() => {
    const domain = "grade-incomplete-evidence.example.com";
    // Dual-write so the freeze captures a CandidateClaim. Freeze, then write
    // the V1 final round. Skip the evidence-pack write so the C.5 evidence
    // completeness gate is unsatisfied at grade time.
    recordFindingViaTool(domain, { endpoint: "https://victim.example/api/billing/1" });
    buildClaimFreeze(domain, {
      write: true,
      now: new Date("2026-05-27T01:00:00.000Z"),
    });
    for (const round of ["brutalist", "balanced", "final"]) {
      writeVerificationRound({
        target_domain: domain,
        round,
        notes: null,
        results: [verificationResult("F-1")],
      });
    }
    // Confirm no evidence pack exists on disk.
    assert.equal(fs.existsSync(evidencePackPaths(domain).json), false);
    // Seed the standalone-finding arm row so the (earlier) finding-differential gate is
    // satisfied and the EVIDENCE gate under test is the one that blocks the grade.
    seedFindingDifferentialArm(domain, "F-1");

    assert.throws(
      () => writeGradeVerdict({
        target_domain: domain,
        verdict: "SUBMIT",
        total_score: 75,
        findings: [gradeFinding("F-1")],
      }),
      /Evidence packs are required/,
      "C.5 evidence-completeness gate must block the grade verdict on the C.6 surface",
    );
  });
});

test("strict gate: final verification must exist before grading (preserved 1:1)", () => {
  withTempHome(() => {
    const domain = "grade-missing-final.example.com";
    recordFindingViaTool(domain, { endpoint: "https://victim.example/api/billing/1" });
    buildClaimFreeze(domain, {
      write: true,
      now: new Date("2026-05-27T01:00:00.000Z"),
    });
    // No verification rounds at all.
    assert.equal(fs.existsSync(verificationRoundPaths(domain, "final").json), false);
    assert.throws(
      () => writeGradeVerdict({
        target_domain: domain,
        verdict: "SUBMIT",
        total_score: 75,
        findings: [gradeFinding("F-1")],
      }),
      /Final verification must exist and be valid before grading/,
      "final-verification gate must remain on the C.6 surface",
    );
  });
});

test("strict gate: grade total_score must equal max per-finding score (verdict consistency preserved)", () => {
  withTempHome(() => {
    const domain = "grade-score-consistency.example.com";
    seedFinalVerificationFromFrozen(domain);

    // Mismatch: total_score = 75 but per-finding total = 75 is fine; force
    // a mismatch by reporting a total_score that does not match the maximum
    // per-finding score.
    assert.throws(
      () => writeGradeVerdict({
        target_domain: domain,
        verdict: "SUBMIT",
        total_score: 100,
        findings: [gradeFinding("F-1", { total_score: 75 })],
      }),
      /grade total_score must equal the maximum per-finding score/,
      "C.6 must preserve the grade-score consistency gate",
    );

    // Mismatched verdict for the score must also be rejected.
    assert.throws(
      () => writeGradeVerdict({
        target_domain: domain,
        verdict: "SKIP",
        total_score: 75,
        findings: [gradeFinding("F-1", { total_score: 75 })],
      }),
      /grade verdict SKIP does not match total_score/,
      "C.6 must preserve the verdict-score consistency gate",
    );
  });
});

test("grade verdict is byte-identical with vs without a CVSS band on the input findings", () => {
  withTempHome(() => {
    const domain = "grade-cvss-nongating.example.com";
    seedFinalVerificationFromFrozen(domain);

    // The grader's read tool attaches a server-derived CVSS band to each
    // finding as an informational sanity signal. The grade store must never
    // read it: the verdict is computed purely from the five integer axes.
    // Writing the verdict with an extra cvss band on every grade-finding input
    // must yield the exact same persisted document and response as writing it
    // without one.
    const cvssBand = {
      version: "3.1",
      vector: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
      base_score: 6.5,
      severity_band: "medium",
    };

    const withoutBand = JSON.parse(writeGradeVerdict({
      target_domain: domain,
      verdict: "SUBMIT",
      total_score: 75,
      findings: [gradeFinding("F-1")],
    }));
    const docWithoutBand = fs.readFileSync(gradeArtifactPaths(domain).json, "utf8");

    const withBand = JSON.parse(writeGradeVerdict({
      target_domain: domain,
      verdict: "SUBMIT",
      total_score: 75,
      findings: [gradeFinding("F-1", { cvss: cvssBand, severity_band: "medium" })],
    }));
    const docWithBand = fs.readFileSync(gradeArtifactPaths(domain).json, "utf8");

    assert.equal(
      docWithBand,
      docWithoutBand,
      "persisted grade.json must be byte-identical whether or not a cvss band is attached to input findings",
    );
    assert.equal(withBand.verdict, withoutBand.verdict);
    assert.equal(withBand.findings_count, withoutBand.findings_count);
    assert.equal(withBand.claim_freeze_id, withoutBand.claim_freeze_id);
    assert.deepEqual(
      Object.prototype.hasOwnProperty.call(JSON.parse(docWithBand).findings[0], "cvss"),
      false,
      "the cvss band must never leak onto the persisted graded finding",
    );
  });
});

test("legacy adapter: callers passing finding_ids[] are routed through claimIdSetFromFindingIds", () => {
  withTempHome(() => {
    const domain = "grade-legacy-adapter.example.com";
    seedFinalVerificationFromFrozen(domain);
    const freeze = readCurrentClaimFreeze(domain);
    assert.ok(freeze);

    // Pass an explicit finding_ids array (legacy shape). The C.6 resolver
    // routes through verification-finding-id-adapter.claimIdSetFromFindingIds
    // to exercise the legacy contract; the resulting verdict must still
    // succeed and remain bound to the active freeze.
    const written = JSON.parse(writeGradeVerdict({
      target_domain: domain,
      verdict: "SUBMIT",
      total_score: 75,
      findings: [gradeFinding("F-1")],
      finding_ids: ["F-1"],
    }));
    assert.equal(written.verdict, "SUBMIT");
    assert.equal(written.claim_freeze_id, freeze.freeze_id);
  });
});
