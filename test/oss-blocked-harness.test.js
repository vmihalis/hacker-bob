"use strict";

// Plane O Cycle O.7 — enforcement gates.
//
// Three server-side rules that close paper invariants from the post-v2.0.0
// reviewer pass:
//   1. Handoff `surface_status: "complete"` with non-empty `blocked_harness_runs[]`
//      is rejected with a structured `surface_complete_with_blocked_harness`
//      code (paired with `surface_status: "partial"` acceptance).
//   2. CandidateClaim with severity high/critical against a native-code module
//      (C/C++/Rust-unsafe/asm) and zero `repo_command_run` evidence_refs is
//      rejected with `O_P4_static_only_native_code_high_severity`. Mixed
//      `repo_file + repo_command_run` evidence is accepted when the run ref
//      is backed by a non-dry-run row.
//   3. `BLOCKED_HARNESS_KIND_VALUES` enum carries the four OSS additions
//      (docker_unavailable, sanitizer_unavailable, static_analyzer_unavailable,
//      cve_feed_stale).
//   4. `session-read-guard.sh` blocks reads of `repo-runs/*.stdout` (and the
//      other O.7 artifacts) so agents cannot exfiltrate raw build stdout/stderr.

const test = require("node:test");
const assert = require("node:assert/strict");
const child_process = require("node:child_process");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const {
  BLOCKED_HARNESS_KIND_VALUES,
  assertBlockedHarnessConsistency,
  normalizeBlockedHarnessRuns,
} = require("../mcp/lib/wave-handoff-contracts.js");
const {
  appendCandidateClaim,
} = require("../mcp/lib/claims.js");
const {
  appendFrontierEvent,
} = require("../mcp/lib/frontier-events.js");
const {
  repoCommandRunsJsonlPath,
} = require("../mcp/lib/paths.js");

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-oss-o7-"));
  process.env.HOME = home;
  try {
    return fn(home);
  } finally {
    if (previousHome === undefined) delete process.env.HOME;
    else process.env.HOME = previousHome;
    fs.rmSync(home, { recursive: true, force: true });
  }
}

// ── 1 & 2. blocked_harness gate (complete vs partial) ────────────────────────

test("handoff surface_status: complete with blocked_harness_runs is rejected with structured code", () => {
  const runs = normalizeBlockedHarnessRuns([
    { kind: "docker_unavailable", harness: "fuzzer harness", reason: "docker CLI absent on host" },
  ]);
  let caught;
  try {
    assertBlockedHarnessConsistency("complete", runs);
  } catch (error) {
    caught = error;
  }
  assert.ok(caught, "expected ToolError when complete + blocked_harness_runs");
  assert.equal(caught.code, "INVALID_ARGUMENTS");
  assert.ok(caught.details, "expected structured details");
  assert.equal(caught.details.code, "surface_complete_with_blocked_harness");
  assert.equal(caught.details.surface_status, "complete");
  assert.deepEqual(caught.details.blocked_harness_kinds, ["docker_unavailable"]);
});

test("handoff surface_status: partial with blocked_harness_runs is accepted", () => {
  const runs = normalizeBlockedHarnessRuns([
    { kind: "docker_unavailable", harness: "fuzzer harness", reason: "docker CLI absent on host" },
  ]);
  // Must not throw — partial is the documented carrier for blocked harnesses.
  assertBlockedHarnessConsistency("partial", runs);
});

// ── 3. O-P4 validator on appendCandidateClaim ────────────────────────────────

function seedNativeCodeSurface(domain, surfaceId, language) {
  appendFrontierEvent({
    target_domain: domain,
    kind: "surface.observed",
    surface_id: surfaceId,
    payload: {
      kind: "code_module",
      file_path: "src/parser.c",
      language,
      native_source: true,
      native_build: true,
    },
    source: { tool: "bob_repo_inventory", artifact: "repo-inventory.json" },
  });
}

function appendRepoCommandRunRow(domain, {
  run_id: runId = "rr-fuzz-001",
  command_hash: commandHash = "c".repeat(64),
  exit_code: exitCode = 0,
  stdout_hash: stdoutHash = "d".repeat(64),
  stderr_hash: stderrHash = "e".repeat(64),
} = {}) {
  fs.mkdirSync(path.dirname(repoCommandRunsJsonlPath(domain)), { recursive: true });
  fs.appendFileSync(repoCommandRunsJsonlPath(domain), `${JSON.stringify({
    version: 1,
    target_domain: domain,
    run_id: runId,
    dry_run: false,
    command_hash: commandHash,
    exit_code: exitCode,
    stdout_hash: stdoutHash,
    stderr_hash: stderrHash,
    timed_out: false,
  })}\n`);
  return { run_id: runId, command_hash: commandHash, exit_code: exitCode, stdout_hash: stdoutHash, stderr_hash: stderrHash };
}

const HIGH_SEVERITY_NATIVE_CLAIM_BASE = Object.freeze({
  title: "Bounded copy parses attacker-length field",
  summary: "Parser reads a length-prefixed field but the underlying buffer is shorter; reachable via packet input.",
  severity: "high",
});

test("high-severity native-code claim with only repo_file evidence is rejected (O-P4)", () => {
  withTempHome(() => {
    const domain = "repo-oss-o7-static.example";
    const surfaceId = "repo:module:src_parser_c-abcdef";
    seedNativeCodeSurface(domain, surfaceId, "c");

    let caught;
    try {
      appendCandidateClaim({
        target_domain: domain,
        ...HIGH_SEVERITY_NATIVE_CLAIM_BASE,
        surface_ids: [surfaceId],
        evidence_refs: [
          {
            kind: "repo_file",
            file_path: "src/parser.c",
            content_hash: "a".repeat(64),
          },
        ],
      });
    } catch (error) {
      caught = error;
    }
    assert.ok(caught, "expected O-P4 rejection");
    assert.equal(caught.code, "INVALID_ARGUMENTS");
    assert.ok(caught.details, "expected structured details");
    assert.equal(caught.details.code, "O_P4_static_only_native_code_high_severity");
    assert.equal(caught.details.severity, "high");
    assert.ok(Array.isArray(caught.details.native_surfaces));
    assert.equal(caught.details.native_surfaces.length, 1);
    assert.equal(caught.details.native_surfaces[0].surface_id, surfaceId);
    assert.equal(caught.details.native_surfaces[0].language, "c");
  });
});

test("high-severity native-code claim with repo_file + repo_command_run evidence is accepted", () => {
  withTempHome(() => {
    const domain = "repo-oss-o7-mixed.example";
    const surfaceId = "repo:module:src_parser_c-fedcba";
    seedNativeCodeSurface(domain, surfaceId, "c");
    const row = appendRepoCommandRunRow(domain);

    const claim = appendCandidateClaim({
      target_domain: domain,
      ...HIGH_SEVERITY_NATIVE_CLAIM_BASE,
      surface_ids: [surfaceId],
      evidence_refs: [
        {
          kind: "repo_file",
          file_path: "src/parser.c",
          content_hash: "a".repeat(64),
        },
        {
          // O.8 payload shape: run_id is the natural identity; the four
          // hashes carry command + capture-file identity. Raw stdout/stderr
          // never appear in the EvidenceReference itself (O-P7).
          kind: "repo_command_run",
          run_id: row.run_id,
          command_hash: row.command_hash,
          exit_code: row.exit_code,
          stdout_hash: row.stdout_hash,
          stderr_hash: row.stderr_hash,
        },
      ],
    });
    assert.ok(claim.claim_id, "claim must persist");
    assert.equal(claim.severity, "high");
  });
});

test("high-severity claim on non-native code_module surface is unaffected by O-P4", () => {
  withTempHome(() => {
    // Reviewer guardrail: the rule narrows to {c, cpp, rust-unsafe, asm}.
    // A Python or generic Rust code_module surface must NOT trip the gate;
    // otherwise we starve web/oss findings of severity.
    const domain = "repo-oss-o7-python.example";
    const surfaceId = "repo:module:src_util_py-aaa111";
    seedNativeCodeSurface(domain, surfaceId, "python");

    const claim = appendCandidateClaim({
      target_domain: domain,
      ...HIGH_SEVERITY_NATIVE_CLAIM_BASE,
      surface_ids: [surfaceId],
      evidence_refs: [
        { kind: "repo_file", file_path: "src/util.py", content_hash: "c".repeat(64) },
      ],
    });
    assert.equal(claim.severity, "high");
  });
});

test("medium-severity native-code claim with only repo_file evidence is accepted (severity narrowing)", () => {
  withTempHome(() => {
    const domain = "repo-oss-o7-medium.example";
    const surfaceId = "repo:module:src_parser_c-222222";
    seedNativeCodeSurface(domain, surfaceId, "cpp");

    const claim = appendCandidateClaim({
      target_domain: domain,
      title: "Possible OOB read in legacy decoder",
      summary: "Decoder for malformed packets diverges from spec; impact is bounded.",
      severity: "medium",
      surface_ids: [surfaceId],
      evidence_refs: [
        { kind: "repo_file", file_path: "src/dec.cpp", content_hash: "d".repeat(64) },
      ],
    });
    assert.equal(claim.severity, "medium");
  });
});

// ── 4. BLOCKED_HARNESS_KIND_VALUES enum expansion ────────────────────────────

test("BLOCKED_HARNESS_KIND_VALUES includes the 4 OSS additions and keeps existing entries", () => {
  for (const added of [
    "docker_unavailable",
    "sanitizer_unavailable",
    "static_analyzer_unavailable",
    "cve_feed_stale",
  ]) {
    assert.ok(BLOCKED_HARNESS_KIND_VALUES.includes(added), `missing ${added}`);
  }
  for (const existing of [
    "foundry_fork",
    "anchor_fork",
    "aptos_fork",
    "sui_fork",
    "substrate_fork",
    "cosmwasm_fork",
    "rpc_endpoint",
    "fuzzer",
    "symbolic_solver",
    "mock_dependency",
    "external_api",
    "other",
  ]) {
    assert.ok(BLOCKED_HARNESS_KIND_VALUES.includes(existing), `regression: ${existing} removed`);
  }
});

// ── 5. session-read-guard blocks repo-runs/ stdout reads ──────────────────────

const READ_GUARD = path.resolve(__dirname, "..", ".claude", "hooks", "session-read-guard.sh");

function invokeReadGuard(toolInput) {
  return child_process.spawnSync(
    "bash",
    [READ_GUARD],
    {
      input: JSON.stringify({ tool_input: toolInput }),
      encoding: "utf8",
    },
  );
}

test("session-read-guard blocks cat ~/hacker-bob-sessions/<domain>/repo-runs/*.stdout", () => {
  const home = os.homedir();
  const sessionPath = path.join(home, "hacker-bob-sessions", "example.com");
  const target = path.join(sessionPath, "repo-runs", "foo.stdout");
  const result = invokeReadGuard({ command: `cat ${target}` });
  assert.notEqual(result.status, 0, `expected non-zero exit; stderr: ${result.stderr}`);
  assert.equal(result.status, 2);
  assert.match(result.stderr, /BLOCKED/);
});

test("session-read-guard blocks direct Read of repo-checks.jsonl", () => {
  const home = os.homedir();
  const target = path.join(home, "hacker-bob-sessions", "example.com", "repo-checks.jsonl");
  const result = invokeReadGuard({ file_path: target });
  assert.equal(result.status, 2);
  assert.match(result.stderr, /BLOCKED/);
});

test("session-read-guard blocks direct Read of Dockerfile.bob in a session dir", () => {
  const home = os.homedir();
  const target = path.join(home, "hacker-bob-sessions", "example.com", "Dockerfile.bob");
  const result = invokeReadGuard({ file_path: target });
  assert.equal(result.status, 2);
  assert.match(result.stderr, /BLOCKED/);
});

test("session-read-guard blocks Bash tail of repo-command-runs.jsonl", () => {
  const home = os.homedir();
  const target = path.join(home, "hacker-bob-sessions", "example.com", "repo-command-runs.jsonl");
  const result = invokeReadGuard({ command: `tail -n 5 ${target}` });
  assert.equal(result.status, 2);
  assert.match(result.stderr, /BLOCKED/);
});

test("session-read-guard blocks Bash cat of repo-env.json", () => {
  const home = os.homedir();
  const target = path.join(home, "hacker-bob-sessions", "example.com", "repo-env.json");
  const result = invokeReadGuard({ command: `cat ${target}` });
  assert.equal(result.status, 2);
  assert.match(result.stderr, /BLOCKED/);
});

test("session-read-guard blocks Bash cat of repo-inventory.json", () => {
  const home = os.homedir();
  const target = path.join(home, "hacker-bob-sessions", "example.com", "repo-inventory.json");
  const result = invokeReadGuard({ command: `cat ${target}` });
  assert.equal(result.status, 2);
  assert.match(result.stderr, /BLOCKED/);
});

test("session-read-guard blocks Bash cat of repo-work/scratch artifact", () => {
  const home = os.homedir();
  const target = path.join(home, "hacker-bob-sessions", "example.com", "repo-work", "build", "out.log");
  const result = invokeReadGuard({ command: `cat ${target}` });
  assert.equal(result.status, 2);
  assert.match(result.stderr, /BLOCKED/);
});
