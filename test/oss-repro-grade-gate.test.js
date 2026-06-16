"use strict";

// B1b grade-time gate — the differential-reproduction proof contract.
// reproVerifiedGapForNativeReportableFindings returns the final-reportable
// high/critical native-code findings that LACK a verified_pass bound (by
// command_hash) to their declared repro_command_argv. Empty == every such finding
// is execution-graded. This is what makes the native-code claim non-fabricatable
// at report time: the single repo_command_run the claim cited is forgeable; only
// the verifier's differential re-run (MCP-write-only ledger) mints the verified_pass.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");

const { appendCandidateClaim, reproVerifiedGapForNativeReportableFindings } = require("../mcp/lib/claims.js");
const { appendFrontierEvent } = require("../mcp/lib/frontier-events.js");
const { verifyReproReproduction } = require("../mcp/lib/repro-replay-verifier.js");
const { resetForTests: resetMaterializationDebounce } = require("../mcp/lib/frontier-materialize-debounce.js");
const { repoCommandRunsJsonlPath } = require("../mcp/lib/paths.js");
const { appendJsonlLine } = require("../mcp/lib/storage.js");

const ASAN_CRASH = `==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x511
    #0 0x4f1c2a in parse /src/parser.c:42:10
SUMMARY: AddressSanitizer: heap-buffer-overflow /src/parser.c:42:10`;
const CLEAN = "ok\n";
const ARGV = ["sh", "-lc", "./fuzzer crash-input.bin"];
const CONTROL_REF = "322716256d60e316c9a3b905a387be36d4e47368";

async function withTempHome(fn) {
  const prev = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-repro-grade-gate-"));
  process.env.HOME = home;
  try {
    return await fn(home);
  } finally {
    if (prev === undefined) delete process.env.HOME;
    else process.env.HOME = prev;
    resetMaterializationDebounce();
    fs.rmSync(home, { recursive: true, force: true });
  }
}

function seedNativeSurface(domain, surfaceId, language = "c") {
  appendFrontierEvent({
    target_domain: domain,
    kind: "surface.observed",
    surface_id: surfaceId,
    payload: { kind: "code_module", file_path: "src/parser.c", language, native_source: true, native_build: true },
    source: { tool: "bob_repo_inventory", artifact: "repo-inventory.json" },
  });
}

function seedClaim(domain, { findingId, surfaceId, severity = "high", argv = ARGV }) {
  // The O-P4 claim gate requires a backed repo_command_run row for high/critical
  // native findings; append the matching ledger row before recording the claim.
  if (severity === "high" || severity === "critical") {
    appendJsonlLine(repoCommandRunsJsonlPath(domain), {
      run_id: "r1",
      command_hash: "b".repeat(64),
      exit_code: 134,
      stdout_hash: "c".repeat(64),
      stderr_hash: "d".repeat(64),
      dry_run: false,
    });
  }
  return appendCandidateClaim({
    target_domain: domain,
    title: "heap overflow in parse",
    summary: "Attacker input overflows the parse buffer.",
    severity,
    surface_ids: [surfaceId],
    payload: { finding: { id: findingId, repro_command_argv: argv } },
    evidence_refs: [
      { kind: "repo_command_run", run_id: "r1", command_hash: "b".repeat(64), exit_code: 134, stdout_hash: "c".repeat(64), stderr_hash: "d".repeat(64) },
    ],
  });
}

// Mint a verified_pass (or other result) for findingId by running the differential
// verifier with a fake runner: a checkout (control/fix tree) returns `control`,
// no checkout (vuln tree) returns `vuln`.
function mintVerified(domain, findingId, { vuln, control, command = ARGV }) {
  const runner = async ({ checkout }) => {
    const text = checkout ? control : vuln;
    return { run_id: checkout ? "RC" : "RV", exit_code: text.includes("ERROR") ? 1 : 0, stdout_text: "", stderr_text: text };
  };
  return verifyReproReproduction(
    { target_domain: domain, finding_id: findingId, command, control_ref: CONTROL_REF },
    { repoDockerRunFn: runner },
  );
}

test("native high finding WITHOUT a verified_pass is flagged missing", async () => {
  await withTempHome(async () => {
    const domain = "repo-grade-gate-1";
    const surfaceId = "repo:module:src_parser_c-0001";
    seedNativeSurface(domain, surfaceId);
    const claim = seedClaim(domain, { findingId: "F-1", surfaceId });
    const gap = reproVerifiedGapForNativeReportableFindings(domain, {
      reportableFindingIds: new Set([claim.payload.finding.id]),
      finalSeverities: new Map([["F-1", "high"]]),
    });
    assert.equal(gap.missing.length, 1);
    assert.equal(gap.missing[0].finding_id, "F-1");
    assert.equal(gap.missing[0].reason, "no_verified_pass");
  });
});

test("native high finding WITH a bound verified_pass passes the gate", async () => {
  await withTempHome(async () => {
    const domain = "repo-grade-gate-2";
    const surfaceId = "repo:module:src_parser_c-0002";
    seedNativeSurface(domain, surfaceId);
    seedClaim(domain, { findingId: "F-1", surfaceId });
    const r = await mintVerified(domain, "F-1", { vuln: ASAN_CRASH, control: CLEAN });
    assert.equal(r.result, "verified_pass");
    const gap = reproVerifiedGapForNativeReportableFindings(domain, {
      reportableFindingIds: new Set(["F-1"]),
      finalSeverities: new Map([["F-1", "high"]]),
    });
    assert.deepEqual(gap.missing, []);
  });
});

test("a verified_pass minted for a DIFFERENT command does not satisfy the gate", async () => {
  await withTempHome(async () => {
    const domain = "repo-grade-gate-3";
    const surfaceId = "repo:module:src_parser_c-0003";
    seedNativeSurface(domain, surfaceId);
    seedClaim(domain, { findingId: "F-1", surfaceId, argv: ARGV });
    // Verifier ran a different argv than the finding declares -> command_hash mismatch.
    await mintVerified(domain, "F-1", { vuln: ASAN_CRASH, control: CLEAN, command: ["sh", "-lc", "./other"] });
    const gap = reproVerifiedGapForNativeReportableFindings(domain, {
      reportableFindingIds: new Set(["F-1"]),
      finalSeverities: new Map([["F-1", "high"]]),
    });
    assert.equal(gap.missing.length, 1);
    assert.equal(gap.missing[0].reason, "verified_pass_command_hash_mismatch");
  });
});

test("a medium-severity native finding is NOT subject to the gate", async () => {
  await withTempHome(async () => {
    const domain = "repo-grade-gate-4";
    const surfaceId = "repo:module:src_parser_c-0004";
    seedNativeSurface(domain, surfaceId);
    // severity medium is allowed at claim time (O-P4 only triggers high/critical).
    seedClaim(domain, { findingId: "F-1", surfaceId, severity: "medium" });
    const gap = reproVerifiedGapForNativeReportableFindings(domain, {
      reportableFindingIds: new Set(["F-1"]),
      finalSeverities: new Map([["F-1", "medium"]]),
    });
    assert.deepEqual(gap.missing, []);
  });
});

test("a refuted differential (forged banner: crashes both trees) leaves the finding unbacked", async () => {
  await withTempHome(async () => {
    const domain = "repo-grade-gate-5";
    const surfaceId = "repo:module:src_parser_c-0005";
    seedNativeSurface(domain, surfaceId);
    seedClaim(domain, { findingId: "F-1", surfaceId });
    // Same banner on both trees -> no flip -> refuted -> no verified_pass minted.
    const r = await mintVerified(domain, "F-1", { vuln: ASAN_CRASH, control: ASAN_CRASH });
    assert.equal(r.result, "refuted");
    const gap = reproVerifiedGapForNativeReportableFindings(domain, {
      reportableFindingIds: new Set(["F-1"]),
      finalSeverities: new Map([["F-1", "high"]]),
    });
    assert.equal(gap.missing.length, 1);
    assert.equal(gap.missing[0].reason, "no_verified_pass");
  });
});
