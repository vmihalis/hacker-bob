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
  repoInventoryPath,
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

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-grade-from-frozen-"));
  process.env.HOME = home;
  try {
    return fn(home);
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

function seedFrozenRepoFinding(domain, surfaceIds, {
  findingId = "F-1",
  severity = "high",
  reachabilityAssertion = null,
} = {}) {
  const claim = {
    target_domain: domain,
    title: "Native parser over-read",
    summary: "Local file parser reads past the available buffer.",
    severity: "medium",
    status: "candidate",
    surface_ids: surfaceIds,
    evidence_refs: [{
      kind: "finding",
      finding_id: findingId,
      content_hash: "0".repeat(64),
    }],
    impact: "Parser crash on crafted input.",
  };
  if (reachabilityAssertion) {
    claim.payload = {
      finding: {
        id: findingId,
        capability_pack: "oss_native_code",
        reachability_assertion: reachabilityAssertion,
      },
    };
  }
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

    const read = JSON.parse(readGradeVerdict({ target_domain: domain }));
    assert.equal(read.claim_freeze_id, freeze.freeze_id);
  });
});

test("reachability cap stamps graded severity without removing the reportable finding", () => {
  withTempHome((home) => {
    const repoSession = seedLocalParserRepo(home, "grade-reachability-cap");
    const domain = repoSession.target_domain;
    appendCandidateClaim({
      target_domain: domain,
      title: "Native parser over-read",
      summary: "Local file parser reads past the available buffer.",
      severity: "medium",
      status: "candidate",
      surface_ids: [repoSession.surface_id],
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
    appendCandidateClaim({
      target_domain: domain,
      title: "Native parser over-read",
      summary: "Parser reads past the available buffer.",
      severity: "medium",
      status: "candidate",
      created_at: "2026-05-27T00:00:00.000Z",
      surface_ids: [repoSession.network_surface_id],
      evidence_refs: [{
        kind: "finding",
        finding_id: "F-1",
        content_hash: "0".repeat(64),
      }],
      impact: "Parser crash on crafted input.",
      payload: {
        finding: {
          id: "F-1",
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
