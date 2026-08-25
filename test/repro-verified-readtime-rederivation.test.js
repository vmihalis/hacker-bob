"use strict";

// READ-TIME RE-DERIVATION of the O-P4 repro-confirm signal. readReproVerifiedSummary no
// longer trusts a verdict line's stored command_hash/crash_class; it RE-RESOLVES
// vuln_run_id/control_run_id against the content-hashed repo-command-runs.jsonl, re-checks
// each cited capture file's bytes against the row's stdout_hash/stderr_hash, and RE-RUNS
// adjudicateDifferential. A bare forged verdict line, a verdict citing a non-flipping pair,
// a verdict whose command_hash does not match the vuln run, a content-tampered capture, a
// single-run verdict, and a rotated ledger all drop out of verified_by_finding. This brings
// the repro ledger to content-hash parity with the invariant + finding-differential ledgers
// (their reverifyInvariantVerifiedRecord / reverifyFindingDifferentialRecord precedents), so
// the Fix-3 native-skip + the O-P4 gate no longer trust a bare forged verified_pass line.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const {
  reverifyReproRecord,
  readReproVerifiedSummary,
} = require("../mcp/domains/repo/repro-replay-verifier.js");
const { reproVerifiedGapForNativeReportableFindings, appendCandidateClaim } = require("../mcp/core/claims/claims.js");
const { appendFrontierEvent } = require("../mcp/core/frontier/frontier-events.js");
const { hashCanonicalJson } = require("../mcp/core/verification/verification-contracts.js");
const {
  repoCommandRunsJsonlPath,
  repoRunsDir,
} = require("../mcp/core/io/paths.js");
const { appendJsonlLine } = require("../mcp/core/io/storage.js");
const {
  seedGenuineReproPair,
  seedBareForgedReproPass,
} = require("./helpers/repro-run-pair.js");

const ARGV = ["sh", "-lc", "./harness crash-input.bin"];

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-repro-rederive-"));
  process.env.HOME = home;
  try {
    return fn(home);
  } finally {
    if (previousHome === undefined) delete process.env.HOME;
    else process.env.HOME = previousHome;
    fs.rmSync(home, { recursive: true, force: true });
  }
}

// A high native finding bound to a native code_module surface, so the O-P4 gate applies.
function seedNativeClaim(domain, { findingId = "F-1", surfaceId = "repo:module:src-parser.c" } = {}) {
  appendFrontierEvent({
    target_domain: domain,
    kind: "surface.observed",
    surface_id: surfaceId,
    payload: { kind: "code_module", file_path: "src/parser.c", language: "c", native_source: true, native_build: true },
    source: { tool: "bob_repo_inventory", artifact: "repo-inventory.json" },
  });
  // A high native claim must cite a repo_command_run backed by a matching non-dry-run
  // repo-command-runs row at claim-record time (O-P4). This is the CLAIM's own evidence
  // row, separate from the differential vuln/control rows the verifier mints.
  appendJsonlLine(repoCommandRunsJsonlPath(domain), {
    run_id: "claim-r1", command_hash: "b".repeat(64), exit_code: 134,
    stdout_hash: "c".repeat(64), stderr_hash: "d".repeat(64), dry_run: false,
  });
  appendCandidateClaim({
    target_domain: domain,
    title: "heap overflow in parse",
    summary: "Attacker input overflows the parse buffer.",
    severity: "high",
    surface_ids: [surfaceId],
    payload: { finding: { id: findingId, repro_command_argv: ARGV } },
    evidence_refs: [
      { kind: "repo_command_run", run_id: "claim-r1", command_hash: "b".repeat(64), exit_code: 134, stdout_hash: "c".repeat(64), stderr_hash: "d".repeat(64) },
    ],
  });
}

function gapArgs(findingId = "F-1", severity = "high") {
  return {
    reportableFindingIds: new Set([findingId]),
    finalSeverities: new Map([[findingId, severity]]),
  };
}

test("(a) a BARE forged verified_pass whose run ids resolve to NOTHING is EXCLUDED; O-P4 surfaces no_verified_pass", () => withTempHome(() => {
  const domain = "repro-rederive-bare.example.com";
  seedNativeClaim(domain);
  // command_hash matches the claim argv, but vuln_run_id/control_run_id point at no rows.
  seedBareForgedReproPass(domain, { findingId: "F-1", argv: ARGV });
  const summary = readReproVerifiedSummary(domain);
  assert.equal(summary.verified_pass_count, 1, "the raw line is counted as a stored verified_pass");
  assert.equal(summary.verified_by_finding["F-1"], undefined, "but re-derivation excludes it from the trusted map");
  // The O-P4 native gate now sees no admitted verified_pass -> the legible no_verified_pass reason.
  const gap = reproVerifiedGapForNativeReportableFindings(domain, gapArgs());
  assert.equal(gap.missing.length, 1);
  assert.equal(gap.missing[0].reason, "no_verified_pass");
}));

test("(b) a forged run PAIR that does NOT flip (both crash) is EXCLUDED (re-adjudication -> refuted)", () => withTempHome(() => {
  const domain = "repro-rederive-noflip.example.com";
  seedNativeClaim(domain);
  seedGenuineReproPair(domain, { findingId: "F-1", argv: ARGV, noflip: true });
  const summary = readReproVerifiedSummary(domain);
  assert.equal(summary.verified_by_finding["F-1"], undefined, "a pair that crashes on both trees never flips");
  assert.equal(reproVerifiedGapForNativeReportableFindings(domain, gapArgs()).missing[0].reason, "no_verified_pass");
}));

test("(c) a GENUINE flipping repro pair is ADMITTED and passes the O-P4 gate", () => withTempHome(() => {
  const domain = "repro-rederive-genuine.example.com";
  seedNativeClaim(domain);
  const { argv } = seedGenuineReproPair(domain, { findingId: "F-1", argv: ARGV });
  const summary = readReproVerifiedSummary(domain);
  assert.equal(summary.verified_pass_count, 1);
  const entry = summary.verified_by_finding["F-1"];
  assert.ok(entry, "a genuine flipping pair stays in verified_by_finding");
  // command_hash + crash_class are RE-DERIVED from the re-resolved vuln row/bytes.
  assert.equal(entry.command_hash, hashCanonicalJson(argv));
  assert.equal(entry.crash_class, "heap-buffer-overflow");
  // The O-P4 gate is satisfied (command_hash matches the claim argv).
  assert.deepEqual(reproVerifiedGapForNativeReportableFindings(domain, gapArgs()).missing, []);
}));

test("(c2) command_hash FORGE: a genuine flipping pair but a verdict command_hash != the vuln row's is EXCLUDED", () => withTempHome(() => {
  const domain = "repro-rederive-cmdforge.example.com";
  seedNativeClaim(domain);
  // The verdict line claims a different command_hash than the vuln row actually records.
  seedGenuineReproPair(domain, {
    findingId: "F-1", argv: ARGV,
    verdictCommandHash: hashCanonicalJson(["sh", "-lc", "./other"]),
  });
  const summary = readReproVerifiedSummary(domain);
  assert.equal(summary.verified_by_finding["F-1"], undefined, "the vuln-row command_hash re-bind catches a forged command_hash");
  assert.equal(reproVerifiedGapForNativeReportableFindings(domain, gapArgs()).missing[0].reason, "no_verified_pass");
}));

test("(c3) CONTENT-HASH TAMPER: a genuine pair whose vuln capture bytes are mutated is EXCLUDED (fail-closed)", () => withTempHome(() => {
  const domain = "repro-rederive-tamper.example.com";
  seedNativeClaim(domain);
  const { vulnRunId } = seedGenuineReproPair(domain, { findingId: "F-1", argv: ARGV });
  // Mutate the captured bytes so sha256 no longer matches the row's stderr_hash.
  const stderrPath = path.join(repoRunsDir(domain), `${vulnRunId}.stderr`);
  fs.appendFileSync(stderrPath, "\nTAMPERED");
  const summary = readReproVerifiedSummary(domain);
  assert.equal(summary.verified_by_finding["F-1"], undefined, "a capture-hash mismatch fails closed");
}));

test("(d) a GHOST single-run verdict (vuln_run_id === control_run_id) is EXCLUDED", () => withTempHome(() => {
  const domain = "repro-rederive-single.example.com";
  const out = reverifyReproRecord(domain, {
    result: "verified_pass",
    finding_id: "F-1",
    command_hash: hashCanonicalJson(ARGV),
    vuln_run_id: "same",
    control_run_id: "same",
  });
  assert.equal(out.ok, false, "a single run never flips against itself");
}));

test("(e) ROTATED ledger: the cited rows are removed -> the previously-present finding fails closed", () => withTempHome(() => {
  const domain = "repro-rederive-rotated.example.com";
  seedNativeClaim(domain);
  seedGenuineReproPair(domain, { findingId: "F-1", argv: ARGV });
  assert.ok(readReproVerifiedSummary(domain).verified_by_finding["F-1"], "present while the runs exist");
  // Remove the source run rows; the verdict line remains but is no longer re-derivable.
  fs.rmSync(repoCommandRunsJsonlPath(domain));
  const summary = readReproVerifiedSummary(domain);
  assert.equal(summary.verified_by_finding["F-1"], undefined, "rotated runs => fail closed");
}));

test("reverifyReproRecord is exported and fails closed on a null record", () => withTempHome(() => {
  const out = reverifyReproRecord("repro-rederive-null.example.com", null);
  assert.equal(out.ok, false);
  assert.equal(out.command_hash, null);
  assert.equal(out.control_ref, null);
  assert.equal(out.crash_class, null);
}));

test("reverifyReproRecord fails closed on a verdict that is not a verified_pass", () => withTempHome(() => {
  const domain = "repro-rederive-refuted.example.com";
  const { vulnRunId, controlRunId } = seedGenuineReproPair(domain, { findingId: "F-1", argv: ARGV });
  const out = reverifyReproRecord(domain, {
    result: "refuted",
    finding_id: "F-1",
    command_hash: hashCanonicalJson(ARGV),
    vuln_run_id: vulnRunId,
    control_run_id: controlRunId,
  });
  assert.equal(out.ok, false, "only a verified_pass record is re-adjudicated to ok");
}));
