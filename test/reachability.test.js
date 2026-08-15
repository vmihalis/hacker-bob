"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const {
  classifyRepoReachability,
  detectNetworkReachability,
  safeReadText,
} = require("../mcp/core/frontier/reachability.js");
const {
  VERIFICATION_ROUND_VALUES,
} = require("../mcp/core/constants/shared-vocabulary.js");
const {
  capabilityBlockerCeilingViolations,
  computeReachabilityDisposition,
  normalizeReachabilityDispositionStamp,
} = require("../mcp/core/frontier/reachability-ceiling.js");
const {
  appendCandidateClaim,
} = require("../mcp/core/claims/claims.js");
const {
  buildClaimFreeze,
} = require("../mcp/core/claims/claim-freeze.js");
const {
  writeVerificationRound,
} = require("../mcp/core/verification/verification-round-store.js");
const {
  writeEvidencePacks,
} = require("../mcp/core/evidence.js");
const {
  evaluateLifecycleTransition,
} = require("../mcp/core/session/lifecycle-gates.js");
const {
  initSession,
} = require("../mcp/core/session/session-state.js");
const {
  sessionDir,
  techniqueAttemptsJsonlPath,
  waveAssignmentsPath,
} = require("../mcp/core/io/paths.js");
const {
  writeFileAtomic,
} = require("../mcp/core/io/storage.js");
const {
  ensureHandoffSigningKey,
  readHandoffSigningKey,
} = require("../mcp/core/ledger-integrity/handoff-signing-key.js");
const {
  loadWaveAssignments,
} = require("../mcp/core/session/assignments.js");
const {
  mergeWaveHandoffs,
} = require("../mcp/core/waves/wave-handoff-store.js");
const {
  sha256Hex,
  signHandoffProvenance,
} = require("../mcp/core/waves/wave-handoff-contracts.js");

function withRepo(files, fn) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "bob-reachability-"));
  try {
    for (const [rel, content] of Object.entries(files)) {
      const filePath = path.join(root, rel);
      fs.mkdirSync(path.dirname(filePath), { recursive: true });
      fs.writeFileSync(filePath, content, "utf8");
    }
    return fn(root, Object.keys(files).sort());
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
}

function projectionFor(files) {
  return {
    modules: files
      .filter((rel) => /\.(c|cc|cpp|cxx|h|hh|hpp)$/i.test(rel) || path.basename(rel) === "CMakeLists.txt")
      .map((rel) => ({
        rel,
        language: path.extname(rel).toLowerCase() === ".cpp" ? "cpp" : "c",
        nativeSource: /\.(c|cc|cpp|cxx|h|hh|hpp)$/i.test(rel),
        nativeBuild: path.basename(rel) === "CMakeLists.txt",
      })),
  };
}

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-capability-ceiling-"));
  process.env.HOME = home;
  try {
    return fn(home);
  } finally {
    if (previousHome === undefined) delete process.env.HOME;
    else process.env.HOME = previousHome;
    fs.rmSync(home, { recursive: true, force: true });
  }
}

const CAPABILITY_CEILING_SURFACE = "surface:signup-otp";

function capabilityCeilingEvidencePack(findingId = "F-1") {
  return {
    finding_id: findingId,
    sample_type: "authenticated replay",
    sample_count: 1,
    aggregate_counts: { affected_objects_sampled: 1 },
    representative_samples: [{
      request_ref: "http-audit:capability-ceiling",
      endpoint: "/signup/verify",
      auth_profile: "attacker",
      status: 200,
      observed_fields: ["signup_state"],
      redacted_object_id: "signup_...001",
    }],
    sensitive_clusters: ["signup state"],
    replay_summary: "Final replay confirmed the finding and preserved a reportable impact.",
    redaction_notes: "Personal and authentication values omitted.",
    report_snippet: "An attacker can preserve access to another user's signup flow state.",
  };
}

function writeCapabilityCeilingFinalVerification(domain, severity = "high") {
  for (const round of VERIFICATION_ROUND_VALUES) {
    writeVerificationRound({
      target_domain: domain,
      round,
      notes: null,
      results: [{
        finding_id: "F-1",
        disposition: "confirmed",
        severity,
        reportable: true,
        reasoning: "Fresh replay confirmed the reportable finding.",
      }],
    });
  }
  writeEvidencePacks({ target_domain: domain, packs: [capabilityCeilingEvidencePack("F-1")] });
}

function seedCapabilityCeilingFinding(domain, capabilityBlocker) {
  JSON.parse(initSession({ target_domain: domain, target_url: `https://${domain}/` }));
  const finding = {
    id: "F-1",
    title: "Signup step-up bypass remains reportable",
    severity: "high",
    cwe: "CWE-287",
    endpoint: `https://${domain}/signup/verify`,
    description: "The signup verification flow can be driven into a reportable inconsistent state.",
    proof_of_concept: "Replay the verifier request sequence and observe preserved signup state.",
    impact: "Attackers can preserve access to another user's signup flow state.",
    surface_id: CAPABILITY_CEILING_SURFACE,
  };
  if (capabilityBlocker !== undefined) {
    finding.capability_blocker_rationale = capabilityBlocker;
  }
  appendCandidateClaim({
    target_domain: domain,
    title: finding.title,
    summary: finding.description,
    severity: finding.severity,
    status: "candidate",
    surface_ids: [CAPABILITY_CEILING_SURFACE],
    evidence_refs: [{ kind: "finding", finding_id: "F-1", content_hash: "0".repeat(64) }],
    impact: finding.impact,
    payload: { finding },
  });
  buildClaimFreeze(domain, { write: true, now: new Date("2026-07-06T00:00:00.000Z") });
  writeCapabilityCeilingFinalVerification(domain);
}

function capabilityCeilingGateBlockers(domain) {
  return evaluateLifecycleTransition({
    target_domain: domain,
    from_state: "VERIFY",
    to_state: "GRADE",
  }).blockers.filter((blocker) => blocker.code === "self_capped_owned_capability");
}

function seedMergedBlockedHarnessRun(domain) {
  const waveNumber = 1;
  const agent = "a1";
  const token = `capability-ceiling-token:${domain}`;
  const assignment = {
    agent,
    surface_id: CAPABILITY_CEILING_SURFACE,
    handoff_token_required: true,
    handoff_token_sha256: sha256Hex(token),
  };
  fs.mkdirSync(sessionDir(domain), { recursive: true });
  writeFileAtomic(waveAssignmentsPath(domain, waveNumber), `${JSON.stringify({
    wave_number: waveNumber,
    handoff_tokens_required: true,
    assignments: [assignment],
  }, null, 2)}\n`);
  ensureHandoffSigningKey(domain);
  fs.appendFileSync(techniqueAttemptsJsonlPath(domain), `${JSON.stringify({
    version: 1,
    ts: "2026-07-06T00:00:01.000Z",
    target_domain: domain,
    surface_id: CAPABILITY_CEILING_SURFACE,
    pack_id: "generic-rest-api",
    status: "attempted",
    outcome: "blocked",
    evidence: "attempted signup step-up harness and recorded the concrete inadequacy",
  })}\n`);
  const persistedAssignment = loadWaveAssignments(domain, waveNumber).assignmentByAgent.get(agent);
  const handoff = signHandoffProvenance({
    target_domain: domain,
    wave: "w1",
    agent,
    surface_id: CAPABILITY_CEILING_SURFACE,
    surface_type: null,
    surface_status: "partial",
    summary: "Signup step-up harness was attempted and could not model the target's mailbox behavior.",
    chain_notes: [],
    blocked_harness_runs: [{
      kind: "external_api",
      harness: "temp-email mailbox polling for the signup verifier",
      reason:
        "The available temp email harness could not receive the provider-specific verifier message "
        + "after repeated live attempts against the routed signup surface.",
      needed_for: "Complete the signup email verification step for this finding surface.",
    }],
    blocked_prereqs: [],
    bypass_attempts: [],
    dead_ends: [],
    waf_blocked_endpoints: [],
    lead_surface_ids: [],
    provenance: "verified",
  }, readHandoffSigningKey(domain), { assignment: persistedAssignment });
  writeFileAtomic(
    path.join(sessionDir(domain), "handoff-w1-a1.json"),
    `${JSON.stringify(handoff, null, 2)}\n`,
  );
  JSON.parse(mergeWaveHandoffs({ target_domain: domain, wave_number: waveNumber }));
}

test("classifyRepoReachability keeps local native parsers at AV:L / medium", () => withRepo({
  "CMakeLists.txt": "cmake_minimum_required(VERSION 3.22)\nproject(local C)\n",
  "src/decode.c": "int decode(const unsigned char *buf, int len){ return len > 0 ? buf[0] : 0; }\n",
}, (root, files) => {
  const result = classifyRepoReachability({ repoRoot: root, files, projection: projectionFor(files) });
  const stamp = result.perSurface.get("src/decode.c");

  assert.equal(result.reachability.network_reachable, false);
  assert.equal(result.reachability.max_credible_severity_ceiling, "medium");
  assert.equal(stamp.attack_vector, "local");
  assert.equal(stamp.severity_ceiling, "medium");
}));

test("classifyRepoReachability detects network daemon anchors deterministically", () => withRepo({
  "CMakeLists.txt": "cmake_minimum_required(VERSION 3.22)\nproject(daemon C)\n",
  "daemon/server.c": [
    "#include <sys/socket.h>",
    "#include <netinet/in.h>",
    "int serve(void){",
    "  int fd = socket(AF_INET, SOCK_STREAM, 0);",
    "  listen(fd, 16);",
    "  return fd;",
    "}",
  ].join("\n"),
  "parsers/conf.c": "int parse_conf(const char *b, int n){ return n > 0 ? b[0] : 0; }\n",
}, (root, files) => {
  const first = classifyRepoReachability({ repoRoot: root, files, projection: projectionFor(files) });
  const second = classifyRepoReachability({ repoRoot: root, files, projection: projectionFor(files) });
  const daemon = first.perSurface.get("daemon/server.c");
  const parser = first.perSurface.get("parsers/conf.c");

  assert.deepEqual(first.reachability, second.reachability);
  assert.equal(first.reachability.network_reachable, true);
  assert.equal(first.reachability.max_credible_severity_ceiling, "critical");
  assert.equal(daemon.attack_vector, "network");
  assert.equal(daemon.severity_ceiling, "critical");
  assert.equal(parser.attack_vector, "local");
  assert.equal(parser.severity_ceiling, "medium");
  assert.deepEqual(parser.network_reachable_anchors, []);
  assert.deepEqual(parser.network_reachable_dirs, []);
}));

test("detectNetworkReachability handles digit XDR tokens and ignores non-shipping demos", () => withRepo({
  "src/proto_xdr.c": "int xdr_msg(XDR *xdrs, struct msg *m){ return xdr_uint32_t(xdrs, &m->id); }\n",
  "examples/echo_server.c": "int main(void){ int fd = socket(AF_INET, SOCK_STREAM, 0); listen(fd, 16); return fd; }\n",
}, (root, files) => {
  const reachable = detectNetworkReachability(root, files);
  assert.equal(reachable.network_reachable, true);
  assert.ok(reachable.signals.some((signal) => signal === "net_call:src/proto_xdr.c"));
  assert.ok(!reachable.signals.some((signal) => signal.includes("examples/echo_server.c")));
}));

test("safeReadText refuses symlink escapes outside the repo root", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "bob-reachability-root-"));
  const outside = fs.mkdtempSync(path.join(os.tmpdir(), "bob-reachability-outside-"));
  try {
    fs.mkdirSync(path.join(root, "src"), { recursive: true });
    const outsideFile = path.join(outside, "server.c");
    fs.writeFileSync(outsideFile, "int main(void){ int fd = socket(AF_INET, SOCK_STREAM, 0); listen(fd, 16); return fd; }\n");
    try {
      fs.symlinkSync(outsideFile, path.join(root, "src", "server.c"));
    } catch {
      return;
    }

    assert.equal(safeReadText(root, "src/server.c"), null);
    const reachable = detectNetworkReachability(root, ["src/server.c"]);
    assert.equal(reachable.network_reachable, false);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
    fs.rmSync(outside, { recursive: true, force: true });
  }
});

test("top-level src server anchors do not promote sibling parser files to AV:N", () => withRepo({
  "CMakeLists.txt": "cmake_minimum_required(VERSION 3.22)\nproject(src_server C)\n",
  "src/server.c": [
    "#include <sys/socket.h>",
    "#include <netinet/in.h>",
    "int serve(void){",
    "  int fd = socket(AF_INET, SOCK_STREAM, 0);",
    "  listen(fd, 16);",
    "  return fd;",
    "}",
  ].join("\n"),
  "src/parser.c": "int parse(const char *b, int n){ return n > 0 ? b[0] : 0; }\n",
}, (root, files) => {
  const result = classifyRepoReachability({ repoRoot: root, files, projection: projectionFor(files) });
  const server = result.perSurface.get("src/server.c");
  const parser = result.perSurface.get("src/parser.c");

  assert.equal(result.reachability.network_reachable, true);
  assert.equal(server.attack_vector, "network");
  assert.equal(parser.attack_vector, "local");
  assert.equal(parser.severity_ceiling, "medium");
  assert.ok(result.reachability.native_attack_vector_map.network_reachable_anchors.includes("src/server.c"));
  assert.ok(!result.reachability.native_attack_vector_map.network_reachable_dirs.includes("src"));
}));

test("semantic top-level server dirs can promote sibling native handlers", () => withRepo({
  "CMakeLists.txt": "cmake_minimum_required(VERSION 3.22)\nproject(server_dir C)\n",
  "server/httpd.c": [
    "#include <sys/socket.h>",
    "#include <netinet/in.h>",
    "int serve(void){",
    "  int fd = socket(AF_INET, SOCK_STREAM, 0);",
    "  listen(fd, 16);",
    "  return fd;",
    "}",
  ].join("\n"),
  "server/handler.c": "int handle(const char *b, int n){ return n > 0 ? b[0] : 0; }\n",
}, (root, files) => {
  const result = classifyRepoReachability({ repoRoot: root, files, projection: projectionFor(files) });
  const handler = result.perSurface.get("server/handler.c");

  assert.equal(handler.attack_vector, "network");
  assert.equal(handler.severity_ceiling, "critical");
  assert.ok(result.reachability.native_attack_vector_map.network_reachable_dirs.includes("server"));
}));

test("server path hints do not exhaust concrete net_call attribution", () => {
  const files = {};
  for (let i = 0; i < 18; i += 1) {
    files[`server/daemon-${String(i).padStart(2, "0")}.c`] = [
      "#include <sys/socket.h>",
      "#include <netinet/in.h>",
      `int serve_${i}(void){`,
      "  int fd = socket(AF_INET, SOCK_STREAM, 0);",
      "  listen(fd, 16);",
      "  return fd;",
      "}",
    ].join("\n");
  }
  withRepo(files, (root, rels) => {
    const reachable = detectNetworkReachability(root, rels);
    const netCalls = reachable.signals.filter((signal) => signal.startsWith("net_call:"));

    assert.equal(reachable.network_reachable, true);
    assert.ok(netCalls.length > 1, "content scans should produce multiple net_call anchors");
  });
});

test("token-only native headers do not create network reachability", () => withRepo({
  "server/socket_types.h": [
    "#include <netinet/in.h>",
    "struct socket_config {",
    "  struct sockaddr_in bind_addr;",
    "  int kind;",
    "};",
    "#define DEFAULT_KIND SOCK_STREAM",
  ].join("\n"),
  "src/parser.c": "int parse(const char *b, int n){ return n > 0 ? b[0] : 0; }\n",
}, (root, files) => {
  const reachable = detectNetworkReachability(root, files);
  const result = classifyRepoReachability({ repoRoot: root, files, projection: projectionFor(files) });
  const header = result.perSurface.get("server/socket_types.h");

  assert.equal(reachable.network_reachable, false);
  assert.equal(header.attack_vector, "local");
  assert.equal(header.severity_ceiling, "medium");
}));

test("computeReachabilityDisposition caps, certifies, and preserves unknowns", () => {
  assert.deepEqual(
    computeReachabilityDisposition("high", {
      severity_ceiling: "medium",
      attack_vector: "local",
      network_reachable: false,
    }),
    {
      recorded_severity: "high",
      severity_ceiling: "medium",
      attack_vector: "local",
      network_reachable: false,
      graded_severity: "medium",
      disposition: "capped",
      defensible: false,
      reachability_source: "heuristic",
    },
  );

  assert.deepEqual(
    computeReachabilityDisposition("high", {
      severity_ceiling: "critical",
      attack_vector: "network",
      network_reachable: true,
    }),
    {
      recorded_severity: "high",
      severity_ceiling: "critical",
      attack_vector: "network",
      network_reachable: true,
      graded_severity: "high",
      disposition: "lifted",
      defensible: true,
      reachability_source: "heuristic",
    },
  );

  assert.deepEqual(
    computeReachabilityDisposition("high", {
      severity_ceiling: "critical",
      attack_vector: "network",
      network_reachable: true,
      reachability_divergence: "invalid reachability assertion in C-ABC123: malformed",
    }),
    {
      recorded_severity: "high",
      severity_ceiling: "critical",
      attack_vector: "network",
      network_reachable: true,
      graded_severity: "high",
      disposition: "lifted",
      defensible: false,
      reachability_source: "heuristic",
      reachability_divergence: "invalid reachability assertion in C-ABC123: malformed",
    },
  );

  assert.deepEqual(
    computeReachabilityDisposition("high", {
      severity_ceiling: "critical",
      attack_vector: "network",
      network_reachable: true,
      reachability_source: "asserted",
      call_path: "listener -> parser -> sink",
    }),
    {
      recorded_severity: "high",
      severity_ceiling: "critical",
      attack_vector: "network",
      network_reachable: true,
      graded_severity: "high",
      disposition: "lifted",
      defensible: false,
      reachability_source: "asserted",
      call_path: "listener -> parser -> sink",
    },
  );

  assert.throws(
    () => computeReachabilityDisposition("high", {
      severity_ceiling: "critical",
      attack_vector: "network",
      network_reachable: true,
      reachability_source: "asserted-v2",
    }),
    /reachability\.reachability_source must be one of/,
  );
  assert.throws(
    () => computeReachabilityDisposition("high", {
      severity_ceiling: "critical",
      attack_vector: "network",
      network_reachable: true,
      reachability_source: "asserted",
    }),
    /reachability\.call_path is required when reachability_source is "asserted"/,
  );
  assert.throws(
    () => computeReachabilityDisposition("high", {
      severity_ceiling: "critical",
      attack_vector: "network",
      network_reachable: true,
      call_path: "listener -> parser -> sink",
    }),
    /reachability\.call_path is only allowed when reachability_source is "asserted"/,
  );

  assert.deepEqual(
    computeReachabilityDisposition("medium", null),
    {
      recorded_severity: "medium",
      severity_ceiling: "unknown",
      attack_vector: "unknown",
      network_reachable: null,
      graded_severity: "medium",
      disposition: "unknown",
      defensible: false,
      reachability_source: "none",
    },
  );
});

test("capability ceiling blocks WEB verify-to-grade when an owned self-cap has no escape", () => withTempHome(() => {
  const domain = "capability-ceiling-owned-no-escape.example.com";
  seedCapabilityCeilingFinding(domain, {
    capability_id: "S3_stepup_registration",
    rationale: "cannot read the OTP email for the signup verification step",
  });

  const blockers = capabilityCeilingGateBlockers(domain);

  assert.equal(blockers.length, 1);
  assert.equal(blockers[0].code, "self_capped_owned_capability");
  assert.equal(blockers[0].finding_id, "F-1");
  assert.equal(blockers[0].capability_id, "S3_stepup_registration");
  assert.ok(blockers[0].owning_tools.includes("bob_temp_email"));
}));

test("capability ceiling allows WEB verify-to-grade when a substantive blocked harness escape exists", () => withTempHome(() => {
  const domain = "capability-ceiling-owned-escaped.example.com";
  seedCapabilityCeilingFinding(domain, {
    capability_id: "S3_stepup_registration",
    rationale: "cannot read the OTP email for the signup verification step",
  });
  seedMergedBlockedHarnessRun(domain);

  const blockers = capabilityCeilingGateBlockers(domain);

  assert.deepEqual(blockers, []);
}));

test("capability ceiling is inert for an unowned capability id", () => withTempHome(() => {
  const domain = "capability-ceiling-unowned.example.com";
  seedCapabilityCeilingFinding(domain, {
    capability_id: "local_operator_only_mailbox_access",
    rationale: "cannot read the operator-only mailbox for this target",
  });

  const result = capabilityBlockerCeilingViolations(domain);

  assert.deepEqual(result.violations, []);
}));

test("capability ceiling is vacuous when the frozen finding has no capability-blocker rationale", () => withTempHome(() => {
  const domain = "capability-ceiling-clean.example.com";
  seedCapabilityCeilingFinding(domain, undefined);

  const result = capabilityBlockerCeilingViolations(domain);

  assert.deepEqual(result.violations, []);
}));

test("normalizeReachabilityDispositionStamp rejects impossible provenance combinations", () => {
  const base = {
    recorded_severity: "high",
    severity_ceiling: "critical",
    attack_vector: "network",
    network_reachable: true,
    graded_severity: "high",
    disposition: "lifted",
    defensible: true,
  };
  assert.throws(
    () => normalizeReachabilityDispositionStamp({
      ...base,
      reachability_source: "none",
    }),
    /reachability\.reachability_source must not be "none" unless disposition is "unknown"/,
  );
  assert.throws(
    () => normalizeReachabilityDispositionStamp({
      ...base,
      reachability_source: "asserted",
    }),
    /reachability\.call_path is required when reachability_source is "asserted"/,
  );
  assert.throws(
    () => normalizeReachabilityDispositionStamp({
      ...base,
      reachability_source: "heuristic",
      call_path: "listener -> parser -> sink",
    }),
    /reachability\.call_path is only allowed when reachability_source is "asserted"/,
  );
  assert.throws(
    () => normalizeReachabilityDispositionStamp({
      ...base,
      reachability_source: "asserted",
      call_path: "listener -> parser\n## forged grade section -> sink",
    }),
    /reachability\.call_path must not contain line breaks/,
  );
  assert.throws(
    () => normalizeReachabilityDispositionStamp({
      ...base,
      severity_ceiling: "unknown",
      attack_vector: "unknown",
      network_reachable: null,
      disposition: "unknown",
      reachability_source: "asserted",
    }),
    /reachability\.reachability_source must be "none" when disposition is "unknown"/,
  );
  assert.deepEqual(
    normalizeReachabilityDispositionStamp({
      ...base,
      reachability_source: "asserted",
      call_path: "listener -> parser -> sink",
    }),
    {
      ...base,
      reachability_source: "asserted",
      call_path: "listener -> parser -> sink",
    },
  );
});
