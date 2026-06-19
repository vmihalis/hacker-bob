"use strict";

// Plane Y Cycle Y.13 — Terminal smoke (rev 4.1).
//
// Seven-subtest terminal smoke + benchmark assertion. Mirrors Plane X Y.12's
// shape (per Part III cross-plane edges) but exercises Plane Y's rev-4 +
// rev-4.1 substrate end-to-end:
//
//   Subtest A — Capability friction (tool_absent) is appendable through the
//               Y.2 logger; the round-trip lands a frontier-event of kind
//               capability_friction_observed (Y.1 substrate) and the Y-P3
//               5-tuple idempotency holds.
//   Subtest B — Adversarial scanner (Y.7) catches silent Bash + the five W2
//               extensions + the rev-4.1 silent_lead_threshold_drop runtime
//               tripwire. Closed-set drift_signatures are surfaced for each
//               default scanner.
//   Subtest C — Protocol drift CI gates exit zero on the current tree
//               (check:skill-protocol-coherence, check:skill-runtime-
//               constraint-drift, check:skill-scheduler-coherence).
//   Subtest D — Y-P13 markdown-ownership: Y.3 NEW evidence_refs[] validator
//               on bob_write_chain_rollup rejects raw evidence/<path> >
//               LARGE_BODY_THRESHOLD_BYTES without an MCP-owned binding
//               handle. Remediation names ALL THREE accepted handles
//               literally and does NOT name bob_import_static_artifact (rev-
//               4.1 defect 2 surface correction). evidence_refs[] is a
//               SEPARATE validator from finding_refs[].
//   Subtest E — Skill / scheduler coherence + runtime gate. The Y.10
//               getLatestMergedWavePartialSurfaceIds helper exists on the
//               real path (no /waves/ subdirectory) and the
//               partial_surfaces_remaining gate prose is present in BOTH
//               prompts/roles/orchestrator.md (source) and the regenerated
//               SKILL.md (cited by TEXT not line number per defect 10).
//   Subtest F — Stigmergy CI (Y.9 / Y-P14c) passes on the real tree.
//   Subtest G — Stigmergy coherence end-to-end with rev 4.1 canonical-
//               vocabulary + terminal-table + chain-bundle audit
//               verification. Ten bullets per the spec.
//
// Step 0 + Step 8 — Benchmark assertion against Y.0-seeded
// test/fixtures/benchmark-baseline.json. The smoke measures subtest A-G
// wall-time and asserts it stays well inside the
// MAX(seeded baseline + 25%, 100s) budget. (Full `npm test` budget is the
// CI-side concern; the smoke's own internal budget is a soft sanity ceiling
// derived from the seeded baseline so the smoke itself does not blow the
// envelope.)

const test = require("node:test");
const assert = require("node:assert/strict");
const child_process = require("node:child_process");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const REPO_ROOT = path.resolve(__dirname, "..");

const {
  AUDIT_GRADED_PATHS,
  LARGE_BODY_THRESHOLD_BYTES,
  attackSurfacePath,
  sessionDir,
} = require("../mcp/lib/paths.js");
const {
  CAPABILITY_OBSERVATION_KIND_VALUES,
} = require("../mcp/lib/capability-observations.js");
const {
  FRICTION_PROMPT_FRAGMENTS,
  FRAGMENT_IDS,
} = require("../mcp/lib/friction-prompt-fragments.js");
const {
  ROLE_TRACE_EXPECTATIONS,
} = require("../mcp/lib/role-trace-expectations.js");
const {
  STIGMERGIC_PRODUCERS,
  PRODUCER_IDS,
} = require("../mcp/lib/stigmergic-producers.js");
const {
  STIGMERGIC_CONSUMERS,
  CONSUMER_IDS,
} = require("../mcp/lib/stigmergic-consumers.js");
const {
  composeTraceReadingExpectationsForRole,
} = require("../mcp/lib/trace-reading-composer.js");
const {
  DEFAULT_SCANNERS,
  SYNTHESIZERS,
  scanTranscript,
  listEvidenceFiles,
} = require("../mcp/lib/friction-scanners.js");
const {
  EVIDENCE_REF_HANDLE_PREFIXES,
} = require("../mcp/lib/tools/write-chain-rollup.js");
const writeChainRollupTool = require("../mcp/lib/tools/write-chain-rollup.js");
const writeChainAttemptTool = require("../mcp/lib/tools/write-chain-attempt.js");
const logFrictionTool = require("../mcp/lib/tools/log-capability-friction.js");
const {
  appendFrontierEvent,
  readFrontierEvents,
} = require("../mcp/lib/frontier-events.js");
const {
  getLatestMergedWavePartialSurfaceIds,
} = require("../mcp/lib/wave-handoff-store.js");
const {
  checkAssertionA,
  checkAssertionB,
  checkAssertionC,
} = require("../scripts/check-stigmergy-coherence.js");
const skillProtocolCoherence = require("../scripts/check-skill-protocol-coherence.js");
const skillRuntimeConstraintDrift = require("../scripts/check-skill-runtime-constraint-drift.js");
const skillSchedulerCoherence = require("../scripts/check-skill-scheduler-coherence.js");

const BENCHMARK_BASELINE_PATH = path.join(
  REPO_ROOT,
  "test",
  "fixtures",
  "benchmark-baseline.json",
);
const CANONICAL_TABLE_PATH = path.join(
  REPO_ROOT,
  "test",
  "fixtures",
  "plane-y-smoke",
  "canonical-table-snapshot.md",
);
const ORCHESTRATOR_PROMPT_PATH = path.join(
  REPO_ROOT,
  "prompts",
  "roles",
  "orchestrator.md",
);
const SKILL_MD_PATH = path.join(
  REPO_ROOT,
  ".claude",
  "skills",
  "bob-evaluate-runner",
  "SKILL.md",
);
const CHAIN_BUILDER_AGENT_PATH = path.join(
  REPO_ROOT,
  ".claude",
  "agents",
  "chain-builder.md",
);

// ─── Helpers ─────────────────────────────────────────────────────────

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-y13-smoke-"));
  process.env.HOME = home;
  try {
    return fn(home);
  } finally {
    if (previousHome === undefined) {
      delete process.env.HOME;
    } else {
      process.env.HOME = previousHome;
    }
    fs.rmSync(home, { recursive: true, force: true });
  }
}

function callTool(tool, args) {
  const response = tool.handler(args);
  return typeof response === "string" ? JSON.parse(response) : response;
}

function defaultsByName(name) {
  return DEFAULT_SCANNERS.filter((s) => s.name === name);
}

function ensureSessionDir(domain) {
  fs.mkdirSync(sessionDir(domain), { recursive: true });
}

function seedAttackSurface(domain, surfaces) {
  ensureSessionDir(domain);
  fs.writeFileSync(attackSurfacePath(domain), `${JSON.stringify({ surfaces }, null, 2)}\n`);
}

function writeEvidenceFile(domain, relPath, size) {
  const abs = path.join(sessionDir(domain), relPath);
  fs.mkdirSync(path.dirname(abs), { recursive: true });
  // Fill with deterministic bytes so size is exact.
  fs.writeFileSync(abs, Buffer.alloc(size, "y"));
}

function withTempTree(fn) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "bob-y13-negative-"));
  try {
    return fn(root);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
}

function writeTempMarkdown(root, relPath, body) {
  const abs = path.join(root, relPath);
  fs.mkdirSync(path.dirname(abs), { recursive: true });
  fs.writeFileSync(abs, body);
  return abs;
}

function parseRoleBundlesFromText(text) {
  const match = text.match(/role_bundles\s*:\s*\[([^\]]*)\]/);
  if (!match) return [];
  return match[1]
    .split(",")
    .map((s) => s.trim().replace(/^["']|["']$/g, ""))
    .filter(Boolean);
}

function readBenchmarkBaseline() {
  const raw = fs.readFileSync(BENCHMARK_BASELINE_PATH, "utf8");
  const baseline = JSON.parse(raw);
  return baseline;
}

function budgetSecondsFromBaseline(baseline) {
  const seconds = Number(baseline.npm_test_wall_time_seconds);
  if (!Number.isFinite(seconds) || seconds <= 0) {
    return 100;
  }
  return Math.max(seconds * 1.25, 100);
}

// Closed list of audit-graded basename matchers used for the Y-P13d
// negative-grep. Bound to the SAME source-of-truth registry the dispatch
// layer enforces.
function isAuditGradedFilePath(filePath) {
  if (typeof filePath !== "string" || !filePath) return false;
  const basename = path.basename(filePath);
  if (AUDIT_GRADED_PATHS.basenames.includes(basename)) return true;
  for (const pattern of AUDIT_GRADED_PATHS.filename_patterns) {
    if (pattern.test(basename)) return true;
  }
  // Detect basename inside any AUDIT_GRADED_RELATIVE_DIRS path component.
  const segments = filePath.split(path.sep);
  for (const dir of AUDIT_GRADED_PATHS.relative_dirs) {
    if (segments.includes(dir)) return true;
  }
  return false;
}

// ─── Step 0 — Benchmark seed read ────────────────────────────────────

const benchmarkBaseline = readBenchmarkBaseline();
const benchmarkBudgetSeconds = budgetSecondsFromBaseline(benchmarkBaseline);
const SMOKE_START_HRTIME = process.hrtime.bigint();

test("Y.13 Step 0 — benchmark baseline seeded and budget formula resolves", () => {
  assert.ok(
    Number.isFinite(benchmarkBaseline.npm_test_wall_time_seconds)
      && benchmarkBaseline.npm_test_wall_time_seconds > 0,
    "test/fixtures/benchmark-baseline.json MUST contain npm_test_wall_time_seconds (Y.0 hotfix seed)",
  );
  assert.equal(
    benchmarkBaseline.budget_formula,
    "MAX(npm_test_wall_time_seconds + 25%, 100)",
    "budget formula MUST match the rev-4 + rev-4.1 contract (MAX(seeded + 25%, 100s))",
  );
  assert.ok(
    benchmarkBudgetSeconds >= 100,
    "budget MUST be at least 100s per the MAX(... , 100s) clause",
  );
});

// ─── Subtest A — Capability friction (tool_absent) appendable ──────────

test("Y.13 Subtest A — tool_absent capability friction round-trips through Y.2 logger to Y.1 frontier-event kind", () => {
  withTempHome(() => {
    const domain = "y13-subtest-a.example.com";
    ensureSessionDir(domain);

    assert.ok(
      CAPABILITY_OBSERVATION_KIND_VALUES.includes("capability_friction_observed"),
      "Y.1 substrate MUST export capability_friction_observed in CAPABILITY_OBSERVATION_KIND_VALUES",
    );
    assert.ok(
      CAPABILITY_OBSERVATION_KIND_VALUES.includes("protocol_drift_observed"),
      "Y.1 substrate MUST export protocol_drift_observed in CAPABILITY_OBSERVATION_KIND_VALUES",
    );

    const args = {
      target_domain: domain,
      run_id: "run-y13-A",
      node_id: "TG-N-Y13A-1",
      wanted_tool: "bob_browser_session_start",
      friction_kind: "tool_absent",
      detected_by: "agent_self_report",
      purpose: "http_probe",
      rationale: "Subtest A: tool_absent voluntary friction; pack derivation should widen on the next dispatch.",
      fallback_used: "bash_curl",
    };
    const response = callTool(logFrictionTool, args);
    assert.equal(response.appended, true);
    assert.equal(response.observation_kind, "capability_friction_observed");

    const events = readFrontierEvents(domain);
    const frictionEvents = events.filter(
      (e) => e.payload && e.payload.observation_kind === "capability_friction_observed",
    );
    assert.equal(frictionEvents.length, 1, "exactly one capability_friction_observed event after one log call");
    assert.equal(frictionEvents[0].payload.wanted_tool, "bob_browser_session_start");
    assert.equal(frictionEvents[0].payload.friction_kind, "tool_absent");

    // Y-P3 5-tuple idempotency: re-emit with the SAME (run_id, node_id,
    // wanted_tool, purpose, detected_by) — must be deduped to a single
    // event on the ledger.
    const dupResponse = callTool(logFrictionTool, args);
    assert.equal(dupResponse.appended, false,
      "second emission with the same 5-tuple MUST be reported as not appended (Y-P3 idempotency)");
    assert.equal(dupResponse.idempotent, true);
    const eventsAfter = readFrontierEvents(domain).filter(
      (e) => e.payload && e.payload.observation_kind === "capability_friction_observed",
    );
    assert.equal(
      eventsAfter.length, 1,
      "Y-P3 5-tuple idempotency MUST silently de-dup a second emission with the same tuple",
    );
  });
});

// ─── Subtest B — Adversarial scanner (W2 + rev 4.1) ─────────────────────

test("Y.13 Subtest B — adversarial scanner catches silent Bash + W2 extensions + rev-4.1 silent_lead_threshold_drop", () => {
  withTempHome(() => {
    const domain = "y13-subtest-b.example.com";
    ensureSessionDir(domain);

    // (B.W2 1) curl_on_target_domain
    {
      const records = scanTranscript(defaultsByName("curl_on_target_domain"), {
        target_domain: domain,
        run_id: "run-y13-B-curl-target",
        node_id: "N-1",
        transcript_text:
          "Some preamble\n$ curl -sS https://y13-subtest-b.example.com/admin\nresponse here",
        tool_invocations: [],
        voluntary_frictions: [],
        evidence_files: [],
        handoff_summary: null,
        recorded_leads: [],
        queue_policy: null,
      });
      assert.ok(records.length >= 1, "curl_on_target_domain MUST fire on a Bash curl against the target");
    }

    // (B.W2 2) curl_on_osint_endpoint
    {
      const records = scanTranscript(defaultsByName("curl_on_osint_endpoint"), {
        target_domain: domain,
        run_id: "run-y13-B-curl-osint",
        node_id: "N-2",
        transcript_text:
          "$ curl https://urlscan.io/api/v1/scan -H 'API-Key: x'",
        tool_invocations: [],
        voluntary_frictions: [],
        evidence_files: [],
        handoff_summary: null,
        recorded_leads: [],
        queue_policy: null,
      });
      assert.ok(records.length >= 1, "curl_on_osint_endpoint MUST fire on a Bash curl against an OSINT endpoint");
    }

    // (B.W2 3) python_inline_curl_parse
    {
      const records = scanTranscript(defaultsByName("python_inline_curl_parse"), {
        target_domain: domain,
        run_id: "run-y13-B-py-curl",
        node_id: "N-3",
        transcript_text:
          "$ python3 -c \"import subprocess; subprocess.run(['curl', '-s', 'https://y13-subtest-b.example.com/api'])\"",
        tool_invocations: [],
        voluntary_frictions: [],
        evidence_files: [],
        handoff_summary: null,
        recorded_leads: [],
        queue_policy: null,
      });
      assert.ok(records.length >= 1, "python_inline_curl_parse MUST fire on a Python subprocess curl");
    }

    // (B.W2 4) large_response_body_unimported — rev 4.1 corrected handle set
    {
      writeEvidenceFile(domain, "evidence/large-body.html", LARGE_BODY_THRESHOLD_BYTES + 1024);
      const files = listEvidenceFiles(domain);
      const records = scanTranscript(defaultsByName("large_response_body_unimported"), {
        target_domain: domain,
        run_id: "run-y13-B-large",
        node_id: "N-4",
        transcript_text: "",
        tool_invocations: [{ tool: "bob_http_scan", outcome: "success", event_id: "evt-1" }],
        voluntary_frictions: [],
        evidence_files: files,
        handoff_summary: null,
        recorded_leads: [],
        queue_policy: null,
      });
      assert.equal(records.length, 1);
      const [record] = records;
      assert.equal(record.payload.wanted_tool, "bob_import_http_traffic");
      // Rationale MUST name all 3 accepted binding tools literally AND
      // MUST NOT name bob_import_static_artifact (rev-4.1 defect 2
      // surface correction).
      assert.match(record.payload.rationale, /bob_import_http_traffic/);
      assert.match(record.payload.rationale, /bob_resolve_body/);
      assert.match(record.payload.rationale, /bob_static_scan/);
      assert.equal(
        record.payload.rationale.includes("bob_import_static_artifact"), false,
        "rationale MUST NOT name bob_import_static_artifact (content-only for token contracts)",
      );
    }

    // (B.W2 5) producer_trace_dropped — ranked_leads with no bob_record_surface_leads call
    {
      const records = scanTranscript(defaultsByName("producer_trace_dropped"), {
        target_domain: domain,
        run_id: "run-y13-B-pt",
        node_id: "N-5",
        transcript_text: "",
        tool_invocations: [],
        voluntary_frictions: [],
        evidence_files: [],
        handoff_summary: {
          ranked_leads: [
            { lead_id: "L1", score: 80 },
            { lead_id: "L2", score: 70 },
            { lead_id: "L3", score: 60 },
          ],
        },
        recorded_leads: [],
        queue_policy: null,
      });
      assert.equal(records.length, 1);
      assert.equal(records[0].payload.drift_signature, "producer_trace_dropped");
    }

    // (B.rev-4.1 silent_lead_threshold_drop) — summary says N, ledger has M < N
    {
      const records = scanTranscript(defaultsByName("silent_lead_threshold_drop"), {
        target_domain: domain,
        run_id: "run-y13-B-stld",
        node_id: "N-6",
        transcript_text: "",
        tool_invocations: [],
        voluntary_frictions: [],
        evidence_files: [],
        handoff_summary: {
          ranked_leads: [
            { lead_id: "L1", score: 80 },
            { lead_id: "L2", score: 70 },
            { lead_id: "L3", score: 60 },
          ],
        },
        recorded_leads: [{ id: "SL-1", source: "run-y13-B-stld", score: 80 }],
        queue_policy: {
          lead_rationale_required_when_below_threshold: true,
        },
      });
      assert.equal(records.length, 1);
      const [record] = records;
      assert.equal(record.payload.drift_signature, "silent_lead_threshold_drop");
      assert.equal(record.payload.details.summary_count, 3);
      assert.equal(record.payload.details.recorded_count, 1);
      assert.equal(record.payload.details.rationale_required_but_missing, true);
    }

    // Subtest B safety: every default scanner's drift_signature stays a
    // member of the closed manifest (Y-P14e bullet 6).
    const scannerNames = new Set(DEFAULT_SCANNERS.map((s) => s.name));
    for (const required of [
      "curl_on_target_domain",
      "curl_on_osint_endpoint",
      "python_inline_curl_parse",
      "large_response_body_unimported",
      "producer_trace_dropped",
      "silent_lead_threshold_drop",
    ]) {
      assert.ok(
        scannerNames.has(required),
        `DEFAULT_SCANNERS MUST contain ${required} (W2 rev 4 + rev-4.1 default scanner registry)`,
      );
    }
  });
});

// ─── Subtest C — Protocol drift CI gates ──────────────────────────────

test("Y.13 Subtest C — protocol-drift CI gates exit zero on current tree", () => {
  for (const script of [
    "scripts/check-skill-protocol-coherence.js",
    "scripts/check-skill-runtime-constraint-drift.js",
    "scripts/check-skill-scheduler-coherence.js",
  ]) {
    const abs = path.join(REPO_ROOT, script);
    assert.ok(fs.existsSync(abs), `Y.8 / Y.10 substrate ${script} MUST exist`);
    const result = child_process.spawnSync("node", [abs], {
      cwd: REPO_ROOT,
      env: process.env,
      encoding: "utf8",
    });
    assert.equal(
      result.status, 0,
      `${script} MUST exit zero on the current tree (stdout=${result.stdout}; stderr=${result.stderr})`,
    );
  }
});

// ─── Subtest D — Y-P13 markdown-ownership: evidence_refs[] validator ───

test("Y.13 Subtest D — Y-P14b evidence_refs[] validator rejects raw large bodies; remediation names ALL 3 accepted handles; static_artifact handle is rejected (rev 4.1 defect 2 surface correction)", () => {
  withTempHome(() => {
    const domain = "y13-subtest-d.example.com";
    ensureSessionDir(domain);

    // Sanity: the validator constant carries the rev-4.1 corrected handle
    // set — three accepted prefixes and NO bob_import_static_artifact.
    const prefixes = EVIDENCE_REF_HANDLE_PREFIXES.slice();
    assert.deepEqual(
      prefixes.sort(),
      [
        "bob_import_http_traffic:",
        "bob_resolve_body:",
        "bob_static_scan:",
      ].sort(),
      "EVIDENCE_REF_HANDLE_PREFIXES MUST contain ONLY the 3 rev-4.1 corrected body-binding handles",
    );

    // (D-6 a) Reject a raw evidence/<path> entry over LARGE_BODY_THRESHOLD_BYTES.
    // The wrapped handler throws ToolError directly when called outside
    // the MCP server boundary, so we catch and inspect the error envelope.
    writeEvidenceFile(domain, "evidence/large-body.html", LARGE_BODY_THRESHOLD_BYTES + 1024);
    let rejectError = null;
    try {
      writeChainRollupTool.handler({
        target_domain: domain,
        chain_id: "chain-y13-D",
        narrative: "Subtest D test rollup that should fail validation.",
        confidence: "medium",
        finding_refs: [],
        evidence_refs: ["evidence/large-body.html"],
      });
    } catch (err) {
      rejectError = err;
    }
    assert.ok(rejectError, "validator MUST reject large raw body without binding handle");
    assert.equal(rejectError.code, "INVALID_ARGUMENTS");
    // Remediation MUST name ALL three accepted body-binding handles literally.
    const remediation = rejectError.remediation || rejectError.message || "";
    assert.match(remediation, /bob_import_http_traffic/);
    assert.match(remediation, /bob_resolve_body/);
    assert.match(remediation, /bob_static_scan/);
    // rev-4.1 disk-reality correction: bob_import_static_artifact MUST
    // NOT appear in the remediation string (it is content-only).
    assert.equal(
      remediation.includes("bob_import_static_artifact"), false,
      "remediation MUST NOT name bob_import_static_artifact (rev 4.1 defect 2 surface correction)",
    );

    // (D-6 b) Reject an entry whose prefix is not in the closed set,
    // specifically static_artifact:xyz which is NOT accepted.
    let wrongPrefixError = null;
    try {
      writeChainRollupTool.handler({
        target_domain: domain,
        chain_id: "chain-y13-D2",
        narrative: "Subtest D wrong-prefix test rollup.",
        confidence: "medium",
        finding_refs: [],
        evidence_refs: ["static_artifact:xyz"],
      });
    } catch (err) {
      wrongPrefixError = err;
    }
    assert.ok(wrongPrefixError, "static_artifact: prefix MUST be rejected (not in EVIDENCE_REF_HANDLE_PREFIXES)");
    assert.equal(wrongPrefixError.code, "INVALID_ARGUMENTS");

    // (D-6 c) finding_refs[] validation is UNCHANGED. Asserts a non-prefix
    // finding_ref is rejected with the original FINDING_REF_PREFIXES check
    // (separate validator from evidence_refs[]).
    let findingRefsError = null;
    try {
      writeChainRollupTool.handler({
        target_domain: domain,
        chain_id: "chain-y13-D3",
        narrative: "Subtest D finding_refs unchanged.",
        confidence: "medium",
        finding_refs: ["arbitrary_string_not_a_prefix"],
        evidence_refs: [],
      });
    } catch (err) {
      findingRefsError = err;
    }
    assert.ok(findingRefsError);
    assert.match(
      findingRefsError.message || "",
      /finding_refs/,
      "finding_refs[] MUST be validated separately from evidence_refs[]",
    );

    // (Y-P13d negative-grep) — assert that AUDIT_GRADED_PATHS is the SoT
    // for the file-write guard. Build a synthetic transcript carrying a
    // Write invocation on report.md and confirm the file-path matcher
    // recognizes it as audit-graded.
    assert.equal(isAuditGradedFilePath("/sessions/foo/report.md"), true);
    assert.equal(isAuditGradedFilePath("/sessions/foo/chains.md"), true);
    assert.equal(isAuditGradedFilePath("/sessions/foo/evidence-packs.md"), true);
    assert.equal(isAuditGradedFilePath("/sessions/foo/grade.md"), true);
    assert.equal(isAuditGradedFilePath("/sessions/foo/wave-handoffs/handoff-w1-a1.json"), true);
    // Scratch paths NOT in AUDIT_GRADED_PATHS.
    assert.equal(isAuditGradedFilePath("/sessions/foo/agent-notes.md"), false);
    assert.equal(isAuditGradedFilePath("/sessions/foo/evidence/large-body.html"), false);
  });
});

// ─── Subtest E — Skill / scheduler coherence + runtime gate ────────────

test("Y.13 Subtest E — skill/scheduler coherence + Y.10 partial-surface helper + D5 EDIT-by-TEXT prose present", () => {
  // (E-5) rev-4.1 defect 6 — getLatestMergedWavePartialSurfaceIds exists on
  // the real path (no /waves/ subdirectory) and returns empty array when
  // there is no merge yet.
  const ids = getLatestMergedWavePartialSurfaceIds("y13-subtest-e.example.com");
  assert.ok(Array.isArray(ids), "getLatestMergedWavePartialSurfaceIds MUST return an array");
  assert.equal(ids.length, 0, "no merge means empty array (forward-compat)");
  // Path-correctness — module loads from mcp/lib/wave-handoff-store.js, NOT
  // mcp/lib/waves/wave-handoff-store.js. The require resolved at the top
  // of this test file is the proof of (no-/waves/-subdirectory).

  // (E-6) rev-4.1 defect 10 — assert the new partial_surfaces_remaining
  // prose is present in BOTH the SOURCE prompts/roles/orchestrator.md AND
  // the regenerated SKILL.md. The EDIT is cited by TEXT (the literal
  // remediation prose) NOT by line number, so the test is robust to
  // future line drift in the generated SKILL.md.
  const orchestratorSource = fs.readFileSync(ORCHESTRATOR_PROMPT_PATH, "utf8");
  const skillMd = fs.readFileSync(SKILL_MD_PATH, "utf8");
  const partialSurfacesProsePattern =
    /STATE_CONFLICT[\s\S]*?partial_surfaces_remaining[\s\S]*?bob_set_queue_policy[\s\S]*?bob_start_next_wave/;
  assert.match(
    orchestratorSource,
    partialSurfacesProsePattern,
    "prompts/roles/orchestrator.md SOURCE MUST contain the partial_surfaces_remaining hard-stop prose",
  );
  assert.match(
    skillMd,
    partialSurfacesProsePattern,
    "regenerated SKILL.md MUST inherit the partial_surfaces_remaining prose verbatim from the source",
  );

  // The D5 EDIT-by-TEXT discipline — the partial_surfaces_remaining text
  // is cited as TEXT in the spec (rev 4.1 defect 10) and should resolve
  // mechanically against the source file by grep on the literal prose.
  assert.ok(
    orchestratorSource.includes("Treat `STATE_CONFLICT` or `SCOPE_BLOCKED` errors as hard stops"),
    "orchestrator source MUST contain the original hard-stops prose D5 cites by TEXT",
  );
});

// ─── Subtest F — Stigmergy CI gate (Y.9 / Y-P14c) on real tree ────────

test("Y.13 Subtest F — check:stigmergy-coherence exits zero against the real tree", () => {
  const result = child_process.spawnSync(
    "node",
    [path.join(REPO_ROOT, "scripts", "check-stigmergy-coherence.js")],
    {
      cwd: REPO_ROOT,
      env: process.env,
      encoding: "utf8",
    },
  );
  assert.equal(
    result.status, 0,
    `check-stigmergy-coherence MUST exit zero on the real tree (stdout=${result.stdout}; stderr=${result.stderr})`,
  );
});

// ─── Subtest G — Stigmergy coherence end-to-end (10 bullets) ───────────

test("Y.13 Subtest G-1 (O1 coverage) — jwt-oauth pack present in OSS technique registry; brief scorer prefers it for JWT-signal surfaces (already pinned by Y.5 regression)", () => {
  const evaluatorTechniquesPath = path.join(
    REPO_ROOT,
    ".hacker-bob",
    "knowledge",
    "evaluator-techniques.json",
  );
  assert.ok(fs.existsSync(evaluatorTechniquesPath), "evaluator-techniques registry MUST exist");
  const registry = JSON.parse(fs.readFileSync(evaluatorTechniquesPath, "utf8"));
  const ids = registry.entries.map((e) => e.id);
  assert.ok(ids.includes("jwt-oauth"), "jwt-oauth pack MUST be present in the registry");

  // Y.5 already pins the wave-brief assertion in
  // test/wave-brief-respects-scorer.test.js — this bullet asserts the
  // canonical-vocabulary anchor (the registry id) so any future renumber
  // would surface here too.
});

test("Y.13 Subtest G-2 (A4 coverage) — surface-leads producer-side rationale enforcement is the dispatch site (rev 4.1 defect 1 REFRAMED)", () => {
  // The Y.12 regression test
  // test/surface-leads-auto-promotion.test.js pins the 3-lead -> 3-lead
  // ledger semantics. This bullet asserts the structural anchor: the
  // producer-side tool is bob_record_surface_leads, NOT a fabricated
  // bob_promote_surface_leads({promote:false}) path. The Y.7 silent_lead_
  // threshold_drop scanner is the runtime tripwire complement.
  const recordSurfaceLeads = path.join(
    REPO_ROOT,
    "mcp",
    "lib",
    "tools",
    "record-surface-leads.js",
  );
  const promoteSurfaceLeads = path.join(
    REPO_ROOT,
    "mcp",
    "lib",
    "tools",
    "promote-surface-leads.js",
  );
  assert.ok(fs.existsSync(recordSurfaceLeads));
  assert.ok(fs.existsSync(promoteSurfaceLeads));
  const promoteText = fs.readFileSync(promoteSurfaceLeads, "utf8");
  // bob_promote_surface_leads inputSchema MUST NOT carry a per-lead
  // `promote` parameter (rev 4.1 defect 1 — fabricated rev-4 surface
  // explicitly never introduced).
  assert.equal(
    /per_lead_promote|promote:\s*false/.test(promoteText), false,
    "bob_promote_surface_leads MUST NOT carry a per-lead promote axis (rev 4.1 defect 1 reframing)",
  );

  // The silent_lead_threshold_drop scanner MUST be a default registered
  // scanner (already asserted in Subtest B; mirrored here as the A4
  // structural anchor).
  const stld = DEFAULT_SCANNERS.find((s) => s.name === "silent_lead_threshold_drop");
  assert.ok(stld, "silent_lead_threshold_drop MUST be a default scanner (rev 4.1 runtime tripwire)");
});

test("Y.13 Subtest G-3 (A3 coverage) — chain-builder prompt-body discipline: bob_read_chain_attempts appears BEFORE bob_propose_hypothesis", () => {
  const text = fs.readFileSync(CHAIN_BUILDER_AGENT_PATH, "utf8");
  // Strip the frontmatter to make the assertion robust to tools list
  // ordering. The Y-P14a consumer's source_location.token_or_regex (from
  // STIGMERGIC_CONSUMERS) is the read_chain_attempts -> propose_hypothesis
  // adjacency in the prompt BODY.
  const bodyStart = text.indexOf("\n---\n");
  const body = bodyStart === -1 ? text : text.slice(bodyStart + 5);
  const readIndex = body.indexOf("bob_read_chain_attempts");
  const proposeIndex = body.indexOf("bob_propose_hypothesis");
  assert.ok(readIndex >= 0, "chain-builder body MUST cite bob_read_chain_attempts");
  assert.ok(proposeIndex >= 0, "chain-builder body MUST cite bob_propose_hypothesis");
  assert.ok(
    readIndex < proposeIndex,
    "chain-builder body MUST cite bob_read_chain_attempts BEFORE bob_propose_hypothesis (Y.6 producer / Y.9 consumer discipline)",
  );
});

test("Y.13 Subtest G-4 (Y-P14b validator coverage — rev 4.1 corrected handle set) — large-body reject then bind-and-retry succeeds", () => {
  withTempHome(() => {
    const domain = "y13-g4.example.com";
    ensureSessionDir(domain);
    // Seed a minimal attack_surface.json so writeChainAttempt's
    // surface-id check resolves (Subtest G-4 bind-and-retry path).
    seedAttackSurface(domain, [{
      id: "surface:y13-g4",
      surface_type: "api",
      hosts: [`https://${domain}`],
      title: "Y.13 G-4 stub surface",
    }]);

    // (a) Reject large raw body without binding handle. Remediation names
    // ALL THREE accepted handles literally.
    writeEvidenceFile(domain, "evidence/giant.html", LARGE_BODY_THRESHOLD_BYTES + 8192);
    let rejectedError = null;
    try {
      writeChainRollupTool.handler({
        target_domain: domain,
        chain_id: "chain-y13-g4",
        narrative: "G-4 reject path.",
        confidence: "medium",
        finding_refs: [],
        evidence_refs: ["evidence/giant.html"],
      });
    } catch (err) {
      rejectedError = err;
    }
    assert.ok(rejectedError, "validator MUST reject large raw body");
    assert.equal(rejectedError.code, "INVALID_ARGUMENTS");
    const remediation = rejectedError.remediation || rejectedError.message || "";
    for (const handle of ["bob_import_http_traffic", "bob_resolve_body", "bob_static_scan"]) {
      assert.ok(remediation.includes(handle), `remediation MUST name ${handle} literally`);
    }

    // (b) Now retry with a handle-prefix entry — must succeed (no throw).
    // The rollup validator requires the chain_id to exist in
    // chain-attempts.jsonl, so seed an attempt first via the canonical
    // producer.
    const attemptResult = writeChainAttemptTool.handler({
      target_domain: domain,
      finding_ids: [],
      surface_ids: ["surface:y13-g4"],
      hypothesis: "G-4 accept-path stub chain attempt for the rollup citation.",
      steps: ["Step 1: stub for the rollup binding test."],
      outcome: "not_applicable",
      evidence_summary: "Stub evidence summary for the G-4 binding test.",
    });
    const attemptParsed = typeof attemptResult === "string"
      ? JSON.parse(attemptResult)
      : attemptResult;
    const seededChainId = attemptParsed.attempt_id;
    assert.ok(seededChainId, "writeChainAttempt MUST return an attempt_id");

    let acceptedResult = null;
    let acceptedError = null;
    try {
      acceptedResult = writeChainRollupTool.handler({
        target_domain: domain,
        chain_id: seededChainId,
        narrative: "G-4 accept path.",
        confidence: "medium",
        finding_refs: [],
        evidence_refs: ["bob_import_http_traffic:abc123"],
      });
    } catch (err) {
      acceptedError = err;
    }
    assert.equal(
      acceptedError, null,
      `validator MUST accept bob_import_http_traffic:<id> as a binding handle (got error: ${acceptedError && acceptedError.message})`,
    );
    assert.ok(acceptedResult, "successful write MUST return a response");
  });
});

test("Y.13 Subtest G-5 (Y-P14c CI gate coverage) — check:stigmergy-coherence exits zero on real tree (mirrored from Subtest F for traceability)", () => {
  const result = child_process.spawnSync(
    "node",
    [path.join(REPO_ROOT, "scripts", "check-stigmergy-coherence.js")],
    { cwd: REPO_ROOT, env: process.env, encoding: "utf8" },
  );
  assert.equal(result.status, 0, `check-stigmergy-coherence MUST exit zero (stdout=${result.stdout}; stderr=${result.stderr})`);
});

test("Y.13 Subtest G-6 (Y-P14d brief-discipline coverage) — chain-builder composed fragment carries the canonical-vocabulary fragment_id telemetry attribution", () => {
  const composed = composeTraceReadingExpectationsForRole("chain-builder");
  assert.ok(composed, "composeTraceReadingExpectationsForRole MUST return a slice for chain-builder");
  assert.equal(composed.role, "chain-builder");
  assert.ok(Array.isArray(composed.fragments));
  // The canonical fragment_id from rev-4.1 Y-D19 vocabulary.
  const readBefore = composed.fragments.find(
    (e) => e.fragment_id === "read_chain_attempts_before_propose",
  );
  assert.ok(readBefore, "chain-builder MUST include the read_chain_attempts_before_propose fragment");
  assert.equal(readBefore.decision_boundary, "chain_attempt_proposal");
  assert.equal(readBefore.producer_id, "chain_attempts_ledger");
  // Fragment text is the LIVE FRICTION_PROMPT_FRAGMENTS body (no
  // duplicated literal).
  assert.equal(
    readBefore.fragment_text,
    FRICTION_PROMPT_FRAGMENTS.read_chain_attempts_before_propose,
  );
});

test("Y.13 Subtest G-7 (Y-P14e non-example coverage) — no agent carries Task; ROLE_TRACE_EXPECTATIONS decision_boundaries are CLOSED enum", () => {
  // (Y-P8 preserved) — single-spawner topology test already enforces no
  // agent gains Task. Mirror the assertion here against the agents/
  // directory to make the structural anchor visible in the smoke.
  const agentsDir = path.join(REPO_ROOT, ".claude", "agents");
  const agentFiles = fs.readdirSync(agentsDir).filter((f) => f.endsWith(".md"));
  for (const file of agentFiles) {
    const text = fs.readFileSync(path.join(agentsDir, file), "utf8");
    const frontMatterEnd = text.indexOf("\n---\n");
    const frontMatter = frontMatterEnd === -1 ? text : text.slice(0, frontMatterEnd);
    const toolsLine = (frontMatter.match(/^tools:\s*(.*)$/m) || [, ""])[1];
    assert.equal(
      /\bTask\b/.test(toolsLine), false,
      `${file} MUST NOT carry Task in its tools frontmatter (Y-P8 preserved unconditionally)`,
    );
  }

  // (Y-P14e bullet 2) — reads happen at DECLARED decision boundaries
  // only. The closed enum is enforced structurally by the
  // ROLE_TRACE_EXPECTATIONS shape test (already in
  // test/role-trace-expectations.test.js); mirror the closed-enum check
  // here to keep the structural anchor visible in the smoke.
  const allowedBoundaries = new Set([
    "brief_composition",
    "handoff_receipt",
    "chain_attempt_proposal",
    "claim_recording",
    "validator_invocation",
  ]);
  for (const [role, entries] of Object.entries(ROLE_TRACE_EXPECTATIONS)) {
    for (const entry of entries) {
      assert.ok(
        allowedBoundaries.has(entry.decision_boundary),
        `${role} entry boundary "${entry.decision_boundary}" MUST be a closed-enum value`,
      );
    }
  }
});

test("Y.13 Subtest G-8 (rev 4.1 canonical-vocabulary verification — defect 5) — ROLE_TRACE_EXPECTATIONS producer/fragment ids resolve, no orphans, no escape-hatch", () => {
  // ROLE_TRACE_EXPECTATIONS producer_ids ⊆ STIGMERGIC_PRODUCERS producer_ids.
  const knownProducers = new Set(PRODUCER_IDS);
  for (const [role, entries] of Object.entries(ROLE_TRACE_EXPECTATIONS)) {
    for (const entry of entries) {
      assert.ok(
        knownProducers.has(entry.producer_id),
        `${role} cites producer_id "${entry.producer_id}" not in STIGMERGIC_PRODUCERS (defect 5: no orphan, no escape-hatch)`,
      );
    }
  }

  // FRICTION_PROMPT_FRAGMENTS keys ⊇ union of ROLE_TRACE_EXPECTATIONS.*.fragment_id.
  const knownFragments = new Set(FRAGMENT_IDS);
  const referencedFragmentIds = new Set();
  for (const entries of Object.values(ROLE_TRACE_EXPECTATIONS)) {
    for (const entry of entries) {
      referencedFragmentIds.add(entry.fragment_id);
    }
  }
  for (const fragmentId of referencedFragmentIds) {
    assert.ok(
      knownFragments.has(fragmentId),
      `fragment_id "${fragmentId}" referenced by ROLE_TRACE_EXPECTATIONS not in FRICTION_PROMPT_FRAGMENTS`,
    );
  }

  // Cross-reference STIGMERGIC_CONSUMERS' producer_ids against the
  // producers manifest (no orphan consumer references — defect 5).
  for (const consumer of STIGMERGIC_CONSUMERS) {
    assert.ok(
      knownProducers.has(consumer.producer_id),
      `STIGMERGIC_CONSUMERS entry "${consumer.consumer_id}" cites producer_id "${consumer.producer_id}" not in STIGMERGIC_PRODUCERS`,
    );
  }
});

test("Y.13 Subtest G-9 (rev 4.1 canonical-table assertion — defect 7 terminal-smoke single source of truth)", () => {
  // The renumbering table snapshot in test/fixtures/plane-y-smoke/ is
  // the canonical-table single source of truth for terminal-cycle
  // identity. The mechanical check from the spec:
  //   * grep /Y\.12.*terminal|terminal.*Y\.12/ MUST return 0 matches
  //   * grep /Y\.13.*[Tt]erminal|[Tt]erminal.*Y\.13/ MUST return >= 1
  // Running these greps against THIS fixture (the canonical-table snapshot
  // committed by Y.13) is the load-bearing assertion. The spec text itself
  // discusses the defect using `Y.12` + `terminal` tokens; the spec is
  // operator-authored and not CI-enforced, but the canonical-table
  // SNAPSHOT in test/fixtures/plane-y-smoke/ IS the mechanical SoT.
  const snapshot = fs.readFileSync(CANONICAL_TABLE_PATH, "utf8");
  const y12Matches = snapshot.match(/Y\.12.*terminal|terminal.*Y\.12/gi) || [];
  assert.equal(
    y12Matches.length, 0,
    `canonical-table snapshot MUST NOT mention Y.12 as terminal (found ${y12Matches.length} matches): ${y12Matches.join(" | ")}`,
  );
  const y13Matches = snapshot.match(/Y\.13.*[Tt]erminal|[Tt]erminal.*Y\.13/g) || [];
  assert.ok(
    y13Matches.length >= 1,
    "canonical-table snapshot MUST mention Y.13 as TERMINAL at least once",
  );

  // The canonical-table row `Y.9 (terminal) | Y.13 (TERMINAL)` is the
  // single source of truth for terminal-cycle identity. The snapshot
  // file may cite the row in its descriptive header comment too; the
  // load-bearing assertion is that the row exists AND no other row
  // claims a different terminal mapping (e.g. `Y.x (terminal) | Y.<not 13>`).
  const tableRowPattern = /\|\s*Y\.9 \(terminal\)\s*\|\s*Y\.13[^|]*\|/g;
  const tableRowMatches = snapshot.match(tableRowPattern) || [];
  assert.equal(
    tableRowMatches.length, 1,
    "canonical-table row `| Y.9 (terminal) | Y.13 (...) |` MUST appear exactly once as a real markdown table row",
  );
  // Negative: no other row maps a `(terminal)` rev-3 id to a NON-Y.13
  // rev-4.1 id. The grep covers `(terminal) | Y.X` where X != 13.
  const driftPattern = /\(terminal\)\s*\|\s*Y\.(?!13\b)\d/g;
  const driftMatches = snapshot.match(driftPattern) || [];
  assert.equal(
    driftMatches.length, 0,
    `canonical-table MUST NOT carry a (terminal) row mapping to anything other than Y.13 (found: ${driftMatches.join(" | ")})`,
  );
});

test("Y.13 Subtest G-10 (rev 4.1 chain-bundle audit verification — defect 3)", () => {
  // Every tool whose role_bundles[] includes BOTH "chain" and
  // "evaluator-shared" MUST carry the `// chain+evaluator-shared
  // justified:` header comment. The Y.9 single-spawner-topology test
  // already enforces this — this bullet re-asserts the structural anchor
  // against the 5 graph tools the rev-4.1 Y.11 cycle extended.
  const graphTools = [
    "propose-hypothesis.js",
    "propose-transition.js",
    "attach-contract.js",
    "append-chain-node.js",
    "query-chain-tree.js",
  ];
  const toolsDir = path.join(REPO_ROOT, "mcp", "lib", "tools");
  for (const tool of graphTools) {
    const abs = path.join(toolsDir, tool);
    assert.ok(fs.existsSync(abs), `Y.11 graph tool ${tool} MUST exist`);
    const text = fs.readFileSync(abs, "utf8");
    // Header comment — citing the rev 4.1 defect 3 absorption — MUST be
    // present near the top of the file (within the first 1024 chars to
    // mirror the Y.9 audit window).
    const head = text.slice(0, 1024);
    assert.match(
      head,
      /chain\+evaluator-shared justified:/,
      `${tool} MUST carry the chain+evaluator-shared justification header comment (rev 4.1 defect 3 audit trail)`,
    );
  }
});

// ─── Y.13 deferred negative refinements (#128) ───────────────────────

test("Y.13 deferred negative #1 — stigmergy gate rejects producer registered_consumers with no manifested consumer", () => {
  const producer = Object.freeze({
    producer_id: "y13_negative_orphaned_producer",
    registered_consumers: Object.freeze(["consumer_not_in_manifest"]),
  });
  const violations = checkAssertionA([producer], STIGMERGIC_CONSUMERS);
  assert.equal(violations.length, 1);
  assert.equal(violations[0].kind, "producer_consumers_not_manifested");
});

test("Y.13 deferred negative #2 — stigmergy gate rejects unresolved consumer source token", () => {
  withTempTree((root) => {
    writeTempMarkdown(root, "agent.md", "this file intentionally lacks the required token\n");
    const consumer = Object.freeze({
      consumer_id: "y13_negative_unresolved_consumer_token",
      source_location: Object.freeze({
        file: "agent.md",
        token_or_regex: "bob_read_chain_attempts",
      }),
      producer_id: STIGMERGIC_PRODUCERS[0].producer_id,
      decision_boundary: "brief_composition",
      rationale: "negative fixture for unresolved token",
    });
    const violations = checkAssertionB([consumer], root);
    assert.equal(violations.length, 1);
    assert.equal(violations[0].kind, "consumer_token_unresolved");
  });
});

test("Y.13 deferred negative #3 — stigmergy gate rejects consumer producer_id outside closed manifest", () => {
  const consumer = Object.freeze({
    consumer_id: "y13_negative_unknown_producer",
    source_location: Object.freeze({
      file: "mcp/lib/stigmergic-consumers.js",
      token_or_regex: "STIGMERGIC_CONSUMERS",
    }),
    producer_id: "not_a_manifested_producer",
    decision_boundary: "brief_composition",
    rationale: "negative fixture for orphan producer reference",
  });
  const violations = checkAssertionC([consumer]);
  assert.equal(violations.length, 1);
  assert.equal(violations[0].kind, "consumer_references_unknown_producer");
});

test("Y.13 deferred negative #4 — protocol gate rejects write-tool token without same-block @schema_ref", () => {
  withTempTree((root) => {
    const fixture = writeTempMarkdown(root, "skill.md", [
      "---",
      "name: y13-negative-protocol",
      "---",
      "## STATE: OPEN_FRONTIER",
      "Call bob_write_chain_rollup after composing the chain narrative.",
      "",
    ].join("\n"));
    const result = skillProtocolCoherence.runCheck({ additionalFiles: [fixture] });
    assert.ok(
      result.violations.some((v) =>
        v.dimension === "D1_structural_containment" && v.token === "bob_write_chain_rollup"),
      `expected D1_structural_containment for bob_write_chain_rollup, got ${JSON.stringify(result.violations)}`,
    );
  });
});

test("Y.13 deferred negative #5 — runtime-constraint gate rejects raw Bash read of sensitive session state", () => {
  withTempTree((root) => {
    const fixture = writeTempMarkdown(root, "runtime.md", [
      "---",
      "name: y13-negative-runtime",
      "---",
      "## STATE: OPEN_FRONTIER",
      "Inspect state with Bash(\"cat ~/hacker-bob-sessions/example.com/state.json\").",
      "",
    ].join("\n"));
    const result = skillRuntimeConstraintDrift.runCheck({ additionalFiles: [fixture] });
    assert.ok(
      result.violations.some((v) =>
        v.constraint_id === "bob_owned_session_read_guard_sensitive_files"),
      `expected sensitive-read runtime drift, got ${JSON.stringify(result.violations)}`,
    );
  });
});

test("Y.13 deferred negative #6 — scheduler-coherence gate rejects unknown @precondition directive", () => {
  withTempTree((root) => {
    const fixture = writeTempMarkdown(root, "scheduler.md", [
      "---",
      "name: y13-negative-scheduler",
      "---",
      "## STATE: CLAIM_FREEZE",
      "<!-- @precondition: not_a_scheduler_precondition -->",
      "",
    ].join("\n"));
    const result = skillSchedulerCoherence.runCheck({ additionalFiles: [fixture] });
    assert.ok(
      result.violations.some((v) =>
        v.dimension === "S2_unknown_precondition" && v.token === "not_a_scheduler_precondition"),
      `expected S2_unknown_precondition, got ${JSON.stringify(result.violations)}`,
    );
  });
});

test("Y.13 deferred negative #7 — terminal-table predicates detect Y.12 terminal drift", () => {
  const drifted = [
    "| Rev 3 | Rev 4.1 |",
    "| --- | --- |",
    "| Y.9 (terminal) | Y.12 (terminal) |",
  ].join("\n");
  assert.ok(
    /Y\.12.*terminal|terminal.*Y\.12/i.test(drifted),
    "negative fixture MUST trip the Y.12 terminal grep",
  );
  assert.ok(
    /\(terminal\)\s*\|\s*Y\.(?!13\b)\d/.test(drifted),
    "negative fixture MUST trip the non-Y.13 terminal-row drift grep",
  );
});

test("Y.13 deferred negative #8 — chain-bundle audit detects missing justification header", () => {
  const synthetic = [
    "\"use strict\";",
    "module.exports = {",
    "  name: \"y13_negative_chain_bundle\",",
    "  role_bundles: [\"chain\", \"evaluator-shared\"],",
    "};",
  ].join("\n");
  const bundles = parseRoleBundlesFromText(synthetic);
  assert.ok(bundles.includes("chain"));
  assert.ok(bundles.includes("evaluator-shared"));
  assert.equal(
    /\/\/\s*chain\+evaluator-shared\s+justified:/i.test(synthetic),
    false,
    "negative fixture MUST be classified as an unjustified chain+evaluator-shared widening",
  );
});

// ─── Step 8 — Benchmark assertion (smoke A-G wall-time within budget) ──

test("Y.13 Step 8 — measured subtest A-G wall-time fits within MAX(seeded baseline + 25%, 100s) budget", () => {
  const nowHrtime = process.hrtime.bigint();
  const elapsedSeconds = Number(nowHrtime - SMOKE_START_HRTIME) / 1e9;
  // The smoke's own subtest A-G wall-time is bounded by construction
  // (no full npm-test run within the smoke). The budget anchor here is
  // the smoke's PER-SUITE budget: it MUST stay well below the seeded
  // npm_test_wall_time_seconds baseline, since the full suite runs
  // hundreds of tests while the smoke runs only its own A-G subtests.
  assert.ok(
    elapsedSeconds <= benchmarkBudgetSeconds,
    `smoke A-G wall-time ${elapsedSeconds.toFixed(2)}s MUST be within Y-D18 budget of ${benchmarkBudgetSeconds.toFixed(2)}s (seeded baseline ${benchmarkBaseline.npm_test_wall_time_seconds.toFixed(2)}s + 25%, floor 100s)`,
  );
});
