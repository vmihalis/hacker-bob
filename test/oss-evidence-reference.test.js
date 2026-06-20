"use strict";

// Plane O Cycle O.8 — code-bound EvidenceReference shapes (repo_file +
// repo_command_run) + verifier-side on-disk completeness gate.
//
// Coverage:
//   1. EVIDENCE_REFERENCE_KIND_VALUES carries both new kinds alongside the
//      existing ones (no regression).
//   2. evidenceReferenceLookupKey returns the deterministic keys per spec
//      (`repo_file:<file_path>:<content_hash>` and
//      `repo_command_run:<run_id>`).
//   3. normalizeEvidenceReferenceShape enforces the kind-specific payloads:
//      repo_file requires file_path + content_hash (and validates
//      line_range / snippet_hash when present); repo_command_run requires
//      run_id + command_hash + stdout_hash + stderr_hash and accepts integer
//      exit_code.
//   4. Mixed-kind CandidateClaim (finding + repo_file + repo_command_run)
//      round-trips through appendCandidateClaim + buildClaimFreeze +
//      assertCompletenessAgainstFreeze.
//   5. Completeness gate fires `missing` when the referenced file was
//      removed (deleted between freeze and verify time).
//   6. Completeness gate fires `mismatched` when the stdout capture file's
//      actual sha differs from the recorded stdout_hash.
//   7. Raw evidence content (excerpts, raw stdout/stderr) NEVER appears in
//      the serialized EvidenceReference payload. Negative grep: pick a
//      distinctive string from the fixture, scan the serialized refs and
//      the on-disk freeze, assert absent.
//   8. The O.7 O-P4 validator still rejects a static-only high-severity
//      native-code claim, and now correctly accepts the same claim once a
//      properly-shaped repo_command_run evidence_ref is added.

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const {
  EVIDENCE_REFERENCE_KIND_VALUES,
  appendCandidateClaim,
  evidenceReferenceLookupKey,
  normalizeEvidenceReferenceShape,
} = require("../mcp/lib/claims.js");
const {
  assertCompletenessAgainstFreeze,
  buildClaimFreeze,
  iterateFrozenEvidenceRefs,
  projectCodeBoundObservedRefs,
  readCurrentClaimFreeze,
} = require("../mcp/lib/claim-freeze.js");
const {
  normalizeEvidencePacksDocument,
} = require("../mcp/lib/evidence.js");
const {
  appendFrontierEvent,
} = require("../mcp/lib/frontier-events.js");
const {
  initRepoSession,
  repoCheck,
} = require("../mcp/lib/repo-target.js");
const {
  claimFreezePath,
  repoChecksJsonlPath,
  repoCommandRunsJsonlPath,
  repoRunsDir,
} = require("../mcp/lib/paths.js");
const {
  appendJsonlLine,
} = require("../mcp/lib/storage.js");
const {
  resetForTests: resetMaterializationDebounce,
} = require("../mcp/lib/frontier-materialize-debounce.js");

const FIXTURE_CHECKOUT_OBJECT = "1".repeat(40);

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-oss-evref-"));
  process.env.HOME = home;
  try {
    return fn(home);
  } finally {
    if (previousHome === undefined) delete process.env.HOME;
    else process.env.HOME = previousHome;
    resetMaterializationDebounce();
    fs.rmSync(home, { recursive: true, force: true });
  }
}

function makeTempRepoDir(prefix = "bob-oss-evref-fixture-") {
  const raw = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  return fs.realpathSync.native ? fs.realpathSync.native(raw) : fs.realpathSync(raw);
}

function writeRepoFile(repoRoot, rel, content) {
  const abs = path.join(repoRoot, rel);
  fs.mkdirSync(path.dirname(abs), { recursive: true });
  fs.writeFileSync(abs, content, "utf8");
}

function sha256Hex(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function writeStdoutFile(domain, runId, content) {
  const dir = repoRunsDir(domain);
  fs.mkdirSync(dir, { recursive: true });
  const stdoutPath = path.join(dir, `${runId}.stdout`);
  fs.writeFileSync(stdoutPath, content);
  const stderrPath = path.join(dir, `${runId}.stderr`);
  fs.writeFileSync(stderrPath, "");
  return { stdoutPath, stderrPath };
}

function appendRepoCommandRunRow(domain, {
  run_id: runId,
  command_hash: commandHash,
  replay_command_hash: replayCommandHash = commandHash,
  exit_code: exitCode,
  stdout_hash: stdoutHash,
  stderr_hash: stderrHash,
  network_mode: networkMode = "none",
  mount_mode: mountMode = "read_only",
  checkout_ref: checkoutRef = null,
  checkout_kind: checkoutKind = null,
  checkout_object: checkoutObject = checkoutRef ? FIXTURE_CHECKOUT_OBJECT : null,
  checkout_object_format: checkoutObjectFormat = checkoutObject ? "sha1" : null,
  checkout_patch_hash: checkoutPatchHash = checkoutKind === "self_patch" ? sha256Hex("fixture patch\n") : null,
}) {
  fs.mkdirSync(path.dirname(repoCommandRunsJsonlPath(domain)), { recursive: true });
  const row = {
    version: 1,
    target_domain: domain,
    run_id: runId,
    dry_run: false,
    command_hash: commandHash,
    replay_command_hash: replayCommandHash,
    exit_code: exitCode,
    network_mode: networkMode,
    mount_mode: mountMode,
    stdout_hash: stdoutHash,
    stderr_hash: stderrHash,
    timed_out: false,
  };
  if (checkoutRef) row.checkout_ref = checkoutRef;
  if (checkoutKind) row.checkout_kind = checkoutKind;
  if (checkoutObject) row.checkout_object = checkoutObject;
  if (checkoutObjectFormat) row.checkout_object_format = checkoutObjectFormat;
  if (checkoutPatchHash) row.checkout_patch_hash = checkoutPatchHash;
  fs.appendFileSync(repoCommandRunsJsonlPath(domain), `${JSON.stringify(row)}\n`);
}

function seedNativeCodeSurface(domain, surfaceId, language, filePath = "src/parser.c") {
  appendFrontierEvent({
    target_domain: domain,
    kind: "surface.observed",
    surface_id: surfaceId,
    payload: {
      kind: "code_module",
      file_path: filePath,
      language,
      native_source: true,
      native_build: true,
    },
    source: { tool: "bob_repo_inventory", artifact: "repo-inventory.json" },
  });
}

// ── 1. enum extension ───────────────────────────────────────────────────────

test("EVIDENCE_REFERENCE_KIND_VALUES carries the two O.8 additions alongside the existing kinds", () => {
  // O-D4: extend, not fork. Reviewers can `Array.from(EVIDENCE_REFERENCE_KIND_VALUES)`
  // and see both old and new kinds in one list.
  for (const added of ["repo_file", "repo_command_run"]) {
    assert.ok(EVIDENCE_REFERENCE_KIND_VALUES.includes(added), `missing ${added}`);
  }
  for (const existing of [
    "finding",
    "verification_round",
    "chain_attempt",
    "http_audit",
    "smart_contract_evidence",
    "agent_run",
  ]) {
    assert.ok(EVIDENCE_REFERENCE_KIND_VALUES.includes(existing), `regression: ${existing} removed`);
  }
  assert.equal(EVIDENCE_REFERENCE_KIND_VALUES.length, 9);
});

// ── 2. deterministic lookup keys ─────────────────────────────────────────────

test("evidenceReferenceLookupKey emits the spec-defined deterministic keys for the new kinds", () => {
  const repoFileKey = evidenceReferenceLookupKey({
    kind: "repo_file",
    file_path: "src/parser.c",
    content_hash: "a".repeat(64),
  });
  assert.equal(repoFileKey, `repo_file:src/parser.c:${"a".repeat(64)}`);

  const repoCmdKey = evidenceReferenceLookupKey({
    kind: "repo_command_run",
    run_id: "run-deadbeef-cafef00d",
    command_hash: "b".repeat(64),
    exit_code: 0,
    stdout_hash: "c".repeat(64),
    stderr_hash: "d".repeat(64),
  });
  assert.equal(repoCmdKey, "repo_command_run:run-deadbeef-cafef00d");
});

// ── 3. payload shape validation ─────────────────────────────────────────────

test("normalizeEvidenceReferenceShape requires file_path + content_hash for kind=repo_file", () => {
  assert.throws(
    () => normalizeEvidenceReferenceShape({ kind: "repo_file" }),
    /file_path must be a non-empty string for kind="repo_file"/,
  );
  assert.throws(
    () => normalizeEvidenceReferenceShape({ kind: "repo_file", file_path: "src/p.c" }),
    /content_hash must be a 64-hex content digest for kind="repo_file"/,
  );
  // Optional snippet_hash, when supplied, must be a 64-hex sha.
  assert.throws(
    () => normalizeEvidenceReferenceShape({
      kind: "repo_file",
      file_path: "src/p.c",
      content_hash: "a".repeat(64),
      snippet_hash: "not-a-hash",
    }),
    /snippet_hash must be a 64-hex content digest when present/,
  );
  // Optional line_range, when supplied, must be a valid {start_line, end_line}.
  assert.throws(
    () => normalizeEvidenceReferenceShape({
      kind: "repo_file",
      file_path: "src/p.c",
      content_hash: "a".repeat(64),
      line_range: { start_line: 0, end_line: 5 },
    }),
    /line_range.start_line must be a positive integer/,
  );
  assert.throws(
    () => normalizeEvidenceReferenceShape({
      kind: "repo_file",
      file_path: "src/p.c",
      content_hash: "a".repeat(64),
      line_range: { start_line: 10, end_line: 5 },
    }),
    /line_range.end_line must be an integer >= start_line/,
  );
  // Valid shape round-trips.
  const ok = normalizeEvidenceReferenceShape({
    kind: "repo_file",
    file_path: "src/p.c",
    content_hash: "a".repeat(64),
    line_range: { start_line: 10, end_line: 20 },
    snippet_hash: "b".repeat(64),
    source_run_id: "AR-3",
  });
  assert.equal(ok.file_path, "src/p.c");
  assert.equal(ok.line_range.start_line, 10);
});

test("normalizeEvidenceReferenceShape requires run_id + command_hash + stdout_hash + stderr_hash for kind=repo_command_run", () => {
  assert.throws(
    () => normalizeEvidenceReferenceShape({ kind: "repo_command_run" }),
    /run_id must be a non-empty string for kind="repo_command_run"/,
  );
  assert.throws(
    () => normalizeEvidenceReferenceShape({ kind: "repo_command_run", run_id: "run-1" }),
    /command_hash must be a 64-hex content digest for kind="repo_command_run"/,
  );
  assert.throws(
    () => normalizeEvidenceReferenceShape({
      kind: "repo_command_run",
      run_id: "run-1",
      command_hash: "a".repeat(64),
    }),
    /stdout_hash must be a 64-hex content digest for kind="repo_command_run"/,
  );
  assert.throws(
    () => normalizeEvidenceReferenceShape({
      kind: "repo_command_run",
      run_id: "run-1",
      command_hash: "a".repeat(64),
      stdout_hash: "b".repeat(64),
    }),
    /stderr_hash must be a 64-hex content digest for kind="repo_command_run"/,
  );
  assert.throws(
    () => normalizeEvidenceReferenceShape({
      kind: "repo_command_run",
      run_id: "run-1",
      command_hash: "a".repeat(64),
      stdout_hash: "b".repeat(64),
      stderr_hash: "c".repeat(64),
      exit_code: "not-an-int",
    }),
    /exit_code must be an integer or null for kind="repo_command_run"/,
  );
  // Valid shape round-trips, including null exit_code (pre-completion capture).
  const ok = normalizeEvidenceReferenceShape({
    kind: "repo_command_run",
    run_id: "run-1",
    command_hash: "a".repeat(64),
    stdout_hash: "b".repeat(64),
    stderr_hash: "c".repeat(64),
    exit_code: null,
  });
  assert.equal(ok.run_id, "run-1");
});

// ── 4. mixed-kind round-trip through freeze + completeness gate ──────────────

test("mixed-kind CandidateClaim (finding + repo_file + repo_command_run) round-trips through freeze + completeness gate", () => {
  withTempHome(() => {
    const repoRoot = makeTempRepoDir();
    const distinctiveFileContent = "// FIXTURE_DISTINCTIVE_PARSER_SECRET_42 — only inside the file\n";
    writeRepoFile(repoRoot, "src/parser.c", distinctiveFileContent);
    const init = initRepoSession({ repo_path: repoRoot });
    const domain = init.target_domain;

    // Probe the file so repo-checks.jsonl carries a row with its real
    // sha256 in `file_hash`. The verifier-side projection will reference
    // this row when computing the observed content_hash.
    const probe = repoCheck({
      target_domain: domain,
      check_type: "file_exists",
      file_path: "src/parser.c",
    });
    assert.equal(probe.matched, true);
    const realFileHash = probe.file_hash;
    assert.match(realFileHash, /^[0-9a-f]{64}$/);

    // Synthesize a docker-run capture so repo-runs/<run_id>.stdout exists.
    const runId = "run-fixture-cafe1234";
    const distinctiveStdout = "FIXTURE_DISTINCTIVE_STDOUT_BANNER_99 from the sanitizer harness\n";
    writeStdoutFile(domain, runId, distinctiveStdout);
    const realStdoutHash = sha256Hex(distinctiveStdout);

    // Build the claim with three evidence refs: a `finding` ref (legacy
    // kind, no on-disk projection needed for this test), a `repo_file` ref
    // bound to the real file hash, and a `repo_command_run` ref bound to
    // the real stdout hash.
    const claim = appendCandidateClaim({
      target_domain: domain,
      title: "Mixed-kind evidence round trip",
      summary: "Parser bounds check missed; reachable via packet input.",
      severity: "medium",
      evidence_refs: [
        {
          kind: "finding",
          finding_id: "F-mixed-1",
          content_hash: "9".repeat(64),
        },
        {
          kind: "repo_file",
          file_path: "src/parser.c",
          content_hash: realFileHash,
          line_range: { start_line: 1, end_line: 1 },
          snippet_hash: sha256Hex(distinctiveFileContent),
        },
        {
          kind: "repo_command_run",
          run_id: runId,
          command_hash: sha256Hex(JSON.stringify(["/bin/sh", "-c", "true"])),
          exit_code: 0,
          stdout_hash: realStdoutHash,
          stderr_hash: sha256Hex(""),
        },
      ],
    });
    assert.equal(claim.evidence_refs.length, 3);

    const freeze = buildClaimFreeze(domain, {
      write: true,
      now: new Date("2026-05-31T00:00:00.000Z"),
    });
    assert.equal(freeze.claim_count, 1);

    // Iterate frozen refs and confirm both code-bound kinds round-tripped.
    const refs = [...iterateFrozenEvidenceRefs(freeze)].map((entry) => entry.ref);
    const kinds = refs.map((ref) => ref.kind).sort();
    assert.deepEqual(kinds, ["finding", "repo_command_run", "repo_file"]);

    // Supply the frozen refs back as observed → completeness must pass.
    const verdict = assertCompletenessAgainstFreeze(freeze, refs);
    assert.equal(verdict.complete, true, JSON.stringify(verdict, null, 2));
    assert.equal(verdict.satisfied, 3);

    // Verifier-side projection from on-disk artifacts should also find the
    // code-bound refs.
    const projected = projectCodeBoundObservedRefs(domain, freeze);
    const projectedKinds = projected.map((ref) => ref.kind).sort();
    assert.deepEqual(projectedKinds, ["repo_command_run", "repo_file"]);
  });
});

// ── 5. completeness gate fires on a missing repo_file ────────────────────────

test("completeness gate fires `missing` when the repo_file was removed between claim and verify", () => {
  withTempHome(() => {
    const repoRoot = makeTempRepoDir();
    writeRepoFile(repoRoot, "src/parser.c", "// content\n");
    const init = initRepoSession({ repo_path: repoRoot });
    const domain = init.target_domain;

    const probe = repoCheck({
      target_domain: domain,
      check_type: "file_exists",
      file_path: "src/parser.c",
    });
    const fileHash = probe.file_hash;

    appendCandidateClaim({
      target_domain: domain,
      title: "missing-after-freeze",
      summary: "Repo file removed between freeze and verify.",
      severity: "low",
      evidence_refs: [
        {
          kind: "repo_file",
          file_path: "src/parser.c",
          content_hash: fileHash,
        },
      ],
    });
    const freeze = buildClaimFreeze(domain, {
      write: true,
      now: new Date("2026-05-31T00:00:00.000Z"),
    });
    assert.equal(freeze.claim_count, 1);

    // Simulate the file being removed AND the producer's probe being
    // wiped out (so the projection sees no matching row at all). Replace
    // repo-checks.jsonl with an empty file.
    fs.writeFileSync(repoChecksJsonlPath(domain), "");

    const projected = projectCodeBoundObservedRefs(domain, freeze);
    assert.equal(projected.length, 0, "projection must skip missing files entirely");

    const verdict = assertCompletenessAgainstFreeze(freeze, projected);
    assert.equal(verdict.complete, false);
    assert.equal(verdict.required, 1);
    assert.equal(verdict.satisfied, 0);
    assert.equal(verdict.missing.length, 1);
    assert.equal(verdict.missing[0].kind, "repo_file");
    assert.ok(verdict.missing[0].ref_key.startsWith("repo_file:src/parser.c:"));
  });
});

// ── 6. completeness gate fires on a tampered stdout ─────────────────────────

test("completeness gate fires `mismatched` when the repo_command_run stdout file sha differs from the recorded stdout_hash", () => {
  withTempHome(() => {
    const repoRoot = makeTempRepoDir();
    writeRepoFile(repoRoot, "README.md", "# fixture\n");
    const init = initRepoSession({ repo_path: repoRoot });
    const domain = init.target_domain;

    const runId = "run-tamper-1234abcd";
    const originalStdout = "expected stdout banner from the harness\n";
    const originalHash = sha256Hex(originalStdout);
    writeStdoutFile(domain, runId, originalStdout);

    appendCandidateClaim({
      target_domain: domain,
      title: "tampered-stdout",
      summary: "Capture file tampered between freeze and verify.",
      severity: "low",
      evidence_refs: [
        {
          kind: "repo_command_run",
          run_id: runId,
          command_hash: sha256Hex(JSON.stringify(["true"])),
          exit_code: 0,
          stdout_hash: originalHash,
          stderr_hash: sha256Hex(""),
        },
      ],
    });
    const freeze = buildClaimFreeze(domain, {
      write: true,
      now: new Date("2026-05-31T00:00:00.000Z"),
    });
    assert.equal(freeze.claim_count, 1);

    // Tamper with the stdout capture file post-freeze.
    const tamperedStdout = "TAMPERED content not signed by the harness\n";
    fs.writeFileSync(path.join(repoRunsDir(domain), `${runId}.stdout`), tamperedStdout);

    const projected = projectCodeBoundObservedRefs(domain, freeze);
    assert.equal(projected.length, 1, "tampered file still exists; projection runs");
    assert.equal(projected[0].stdout_hash, sha256Hex(tamperedStdout));

    const verdict = assertCompletenessAgainstFreeze(freeze, projected);
    assert.equal(verdict.complete, false);
    assert.equal(verdict.mismatched.length, 1);
    assert.equal(verdict.mismatched[0].kind, "repo_command_run");
    assert.equal(verdict.mismatched[0].ref_key, `repo_command_run:${runId}`);
    assert.equal(verdict.mismatched[0].expected_hash, originalHash);
    assert.equal(verdict.mismatched[0].observed_hash, sha256Hex(tamperedStdout));
  });
});

test("C10 differential rejects missing stdout capture files", () => {
  withTempHome(() => {
    const domain = "repo-oss-c10-missing-stdout.example";
    fs.mkdirSync(repoRunsDir(domain), { recursive: true });
    const vulnRunId = "run-c10-vuln-missing";
    const controlRunId = "run-c10-control-present";
    appendRepoCommandRunRow(domain, {
      run_id: vulnRunId,
      command_hash: "a".repeat(64),
      replay_command_hash: "e".repeat(64),
      exit_code: 0,
      stdout_hash: "b".repeat(64),
      stderr_hash: "c".repeat(64),
    });
    writeStdoutFile(domain, controlRunId, "control quiet\n");
    appendRepoCommandRunRow(domain, {
      run_id: controlRunId,
      command_hash: "d".repeat(64),
      replay_command_hash: "e".repeat(64),
      exit_code: 0,
      stdout_hash: sha256Hex("control quiet\n"),
      stderr_hash: sha256Hex(""),
      checkout_ref: "HEAD",
      checkout_kind: "self_patch",
    });

    assert.throws(
      () => normalizeEvidencePacksDocument({
        version: 1,
        target_domain: domain,
        packs: [{
          finding_id: "F-1",
          sample_type: "oss_dynamic_replay",
          sample_count: 1,
          aggregate_counts: { runs: 2 },
          representative_samples: [{ run_id: vulnRunId }],
          sensitive_clusters: [],
          replay_summary: "Replay rows exist but one stdout capture is missing.",
          redaction_notes: null,
          report_snippet: "Differential rejects missing stdout captures.",
          differential: {
            control_kind: "self_patch",
            vuln_run_id: vulnRunId,
            control_run_id: controlRunId,
            control_ref: "HEAD",
            vuln_fired: true,
            control_fired: false,
            verdict: "patch_fixes",
            control_summary: "Control run completed; vulnerable stdout capture was unavailable.",
          },
        }],
      }, {
        expectedDomain: domain,
        findingIdSet: new Set(["F-1"]),
        finalReportableIdSet: new Set(["F-1"]),
      }),
      /stdout file is missing/,
    );
  });
});

// ── 7. raw evidence content never lands in the EvidenceReference payload ────

test("raw evidence content (file body, stdout body) NEVER appears in the serialized EvidenceReference payload", () => {
  withTempHome(() => {
    const repoRoot = makeTempRepoDir();
    // Distinctive sentinels: one in the file body, one in the stdout body.
    // Neither should appear anywhere in the serialized EvidenceReference
    // or the on-disk freeze (which carries the frozen evidence_refs[]).
    const fileSentinel = "FIXTURE_SENTINEL_FILE_BODY_BLOB_XYZ123";
    const stdoutSentinel = "FIXTURE_SENTINEL_STDOUT_BANNER_QQQ987";
    writeRepoFile(repoRoot, "src/leak.c", `int main(void){return 0;} // ${fileSentinel}\n`);
    const init = initRepoSession({ repo_path: repoRoot });
    const domain = init.target_domain;

    const probe = repoCheck({
      target_domain: domain,
      check_type: "file_exists",
      file_path: "src/leak.c",
    });
    const fileHash = probe.file_hash;

    const runId = "run-leakguard-aaaa0001";
    writeStdoutFile(domain, runId, `${stdoutSentinel}\n`);

    const claim = appendCandidateClaim({
      target_domain: domain,
      title: "leak guard",
      summary: "Verify raw bodies stay out of the EvidenceReference payload.",
      severity: "low",
      evidence_refs: [
        {
          kind: "repo_file",
          file_path: "src/leak.c",
          content_hash: fileHash,
          snippet_hash: sha256Hex("/* excerpted region */"),
        },
        {
          kind: "repo_command_run",
          run_id: runId,
          command_hash: sha256Hex(JSON.stringify(["true"])),
          exit_code: 0,
          stdout_hash: sha256Hex(`${stdoutSentinel}\n`),
          stderr_hash: sha256Hex(""),
        },
      ],
    });

    // Serialized in-memory CandidateClaim: neither sentinel may appear.
    const serialized = JSON.stringify(claim);
    assert.ok(!serialized.includes(fileSentinel), "file body sentinel leaked into serialized CandidateClaim");
    assert.ok(!serialized.includes(stdoutSentinel), "stdout body sentinel leaked into serialized CandidateClaim");

    // Build + write the freeze, then re-read the on-disk JSON: same
    // assertion — sentinels never land in the persisted freeze, which
    // carries the frozen evidence_refs[].
    buildClaimFreeze(domain, { write: true, now: new Date("2026-05-31T00:00:00.000Z") });
    const freezeBytes = fs.readFileSync(claimFreezePath(domain), "utf8");
    assert.ok(!freezeBytes.includes(fileSentinel), "file body sentinel leaked into persisted claim-freeze.json");
    assert.ok(!freezeBytes.includes(stdoutSentinel), "stdout body sentinel leaked into persisted claim-freeze.json");

    // Iterate the on-disk freeze and verify the individual evidence_refs[]
    // entries also do not carry the raw bodies — a second-line defense
    // against future schema drift that might smuggle a `body` field in.
    const onDisk = readCurrentClaimFreeze(domain);
    for (const entry of iterateFrozenEvidenceRefs(onDisk)) {
      const refSerialized = JSON.stringify(entry.ref);
      assert.ok(!refSerialized.includes(fileSentinel));
      assert.ok(!refSerialized.includes(stdoutSentinel));
    }
  });
});

// ── 8. O-P4 validator: still rejects static-only, now accepts mixed ─────────

test("O-P4 validator rejects static-only high-severity native-code claim", () => {
  withTempHome(() => {
    const domain = "repo-oss-o8-static.example";
    const surfaceId = "repo:module:src_parser_c-aa0001";
    seedNativeCodeSurface(domain, surfaceId, "c");

    let caught;
    try {
      appendCandidateClaim({
        target_domain: domain,
        title: "Bounds check missed",
        summary: "Parser bounds-check missed on packet input.",
        severity: "high",
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
    assert.equal(caught.details.code, "O_P4_static_only_native_code_high_severity");
    assert.equal(caught.details.severity, "high");
  });
});

test("O-P4 validator accepts the same high-severity native-code claim once a properly-shaped repo_command_run evidence_ref is added", () => {
  withTempHome(() => {
    const domain = "repo-oss-o8-accepts.example";
    const surfaceId = "repo:module:src_parser_c-aa0002";
    seedNativeCodeSurface(domain, surfaceId, "c");
    appendRepoCommandRunRow(domain, {
      run_id: "run-fuzzer-001",
      command_hash: "b".repeat(64),
      exit_code: 134,
      stdout_hash: "c".repeat(64),
      stderr_hash: "d".repeat(64),
    });

    const claim = appendCandidateClaim({
      target_domain: domain,
      title: "Bounds check missed",
      summary: "Parser bounds-check missed on packet input.",
      severity: "high",
      surface_ids: [surfaceId],
      evidence_refs: [
        {
          kind: "repo_file",
          file_path: "src/parser.c",
          content_hash: "a".repeat(64),
        },
        {
          // O.8 formal shape: every kind-specific field present and validated.
          kind: "repo_command_run",
          run_id: "run-fuzzer-001",
          command_hash: "b".repeat(64),
          exit_code: 134, // SIGABRT — typical sanitizer-trip outcome
          stdout_hash: "c".repeat(64),
          stderr_hash: "d".repeat(64),
        },
      ],
    });
    assert.ok(claim.claim_id, "claim must persist");
    assert.equal(claim.severity, "high");
    assert.equal(claim.evidence_refs.length, 2);
  });
});
