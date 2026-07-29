"use strict";

// NATIVE-MISLABEL MEDIUM DOUBLE-SKIP closure. A MEDIUM finding on a native code_module
// surface used to be skipped by BOTH the standalone finding-differential gate (native-skip)
// AND the O-P4 repro gate (which only requires an arm at high/critical) — so no executed arm
// was required at all. The standalone native-skip now only fires at O-P4 severities OR when
// the finding already carries an executed repro verified_pass, so an UNARMED medium native
// finding falls through to the standalone arm. High/critical native still routes to O-P4
// only (no double requirement).

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const {
  appendCandidateClaim,
  findingDifferentialGapForStandaloneReportableFindings,
  reproVerifiedGapForNativeReportableFindings,
} = require("../mcp/lib/claims.js");
const {
  appendFrontierEvent,
} = require("../mcp/lib/frontier-events.js");
const {
  appendJsonlLine,
} = require("../mcp/lib/storage.js");
const {
  repoCommandRunsJsonlPath,
} = require("../mcp/lib/paths.js");
const {
  seedGenuineReproPair,
  seedBareForgedReproPass,
} = require("./helpers/repro-run-pair.js");

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-native-medium-"));
  process.env.HOME = home;
  try {
    return fn(home);
  } finally {
    if (previousHome === undefined) delete process.env.HOME;
    else process.env.HOME = previousHome;
    fs.rmSync(home, { recursive: true, force: true });
  }
}

const SURFACE = "repo:module:src-parser.c";
const REPRO_COMMAND_ARGV = ["sh", "-lc", "./harness crash-input.bin"];

function observeNativeSurface(domain) {
  appendFrontierEvent({
    target_domain: domain,
    kind: "surface.observed",
    ts: "2026-05-27T00:00:00.000Z",
    surface_id: SURFACE,
    payload: { kind: "code_module", language: "c" },
  });
}

function seedRepoCommandRun(domain) {
  appendJsonlLine(repoCommandRunsJsonlPath(domain), {
    run_id: "native-repro-run-1", command_hash: "b".repeat(64), exit_code: 134,
    stdout_hash: "c".repeat(64), stderr_hash: "d".repeat(64), dry_run: false,
  });
}

// Seed a GENUINE flipping repro pair (two repo-command-runs rows + matching capture files)
// + the verified_pass verdict line citing it, so readReproVerifiedSummary's read-time
// re-adjudication ADMITS it. A bare verdict line citing nonexistent runs is no longer
// trusted (see the forged-line case below).
function seedReproVerifiedPass(domain, findingId = "F-1") {
  seedGenuineReproPair(domain, { findingId, argv: REPRO_COMMAND_ARGV });
}

function recordNativeClaim(domain, { severity, withRepoCommandRun = false } = {}) {
  const evidenceRefs = [{ kind: "finding", finding_id: "F-1", content_hash: "0".repeat(64) }];
  if (withRepoCommandRun) {
    seedRepoCommandRun(domain);
    evidenceRefs.push({
      kind: "repo_command_run", run_id: "native-repro-run-1", command_hash: "b".repeat(64),
      exit_code: 134, stdout_hash: "c".repeat(64), stderr_hash: "d".repeat(64),
    });
  }
  appendCandidateClaim({
    target_domain: domain,
    title: "Native parser over-read",
    summary: "Local file parser reads past the available buffer.",
    severity,
    status: "candidate",
    surface_ids: [SURFACE],
    evidence_refs: evidenceRefs,
    impact: "Parser crash on crafted input.",
    payload: { finding: { id: "F-1", capability_pack: "oss_native_code", repro_command_argv: REPRO_COMMAND_ARGV } },
  });
}

function argsFor(severity) {
  return {
    reportableFindingIds: new Set(["F-1"]),
    finalSeverities: new Map([["F-1", severity]]),
  };
}

test("a MEDIUM native finding with NO repro arm AND no finding-differential arm surfaces a gap (no double-skip)", () => withTempHome(() => {
  const domain = "native-medium-noarm.example.com";
  observeNativeSurface(domain);
  recordNativeClaim(domain, { severity: "medium" });
  const args = argsFor("medium");
  // The standalone gate no longer short-circuits a medium native surface; it requires an arm.
  const standalone = findingDifferentialGapForStandaloneReportableFindings(domain, args);
  assert.deepEqual(standalone.missing, [{ finding_id: "F-1", reason: "no_finding_differential_verified_pass" }]);
  // The O-P4 repro gate does NOT require an arm at medium (so without fix 3 this would be a
  // double-skip). It must report no gap, proving the obligation lives on the standalone gate.
  const repro = reproVerifiedGapForNativeReportableFindings(domain, args);
  assert.deepEqual(repro.missing, [], "O-P4 carries no obligation at medium");
}));

test("a HIGH native finding with a real repro arm routes to O-P4 only — no standalone double requirement", () => withTempHome(() => {
  const domain = "native-high-repro.example.com";
  observeNativeSurface(domain);
  recordNativeClaim(domain, { severity: "high", withRepoCommandRun: true });
  seedReproVerifiedPass(domain, "F-1");
  const args = argsFor("high");
  // O-P4 owns the high native path and is satisfied by the repro verified_pass.
  assert.deepEqual(reproVerifiedGapForNativeReportableFindings(domain, args).missing, []);
  // The standalone gate still skips the native surface at high (O-P4-owned) — no double req.
  assert.deepEqual(findingDifferentialGapForStandaloneReportableFindings(domain, args).missing, []);
}));

test("a MEDIUM native finding WITH a repro verified_pass passes (its repro arm is the executed binding)", () => withTempHome(() => {
  const domain = "native-medium-repro.example.com";
  observeNativeSurface(domain);
  recordNativeClaim(domain, { severity: "medium" });
  seedReproVerifiedPass(domain, "F-1");
  const args = argsFor("medium");
  // The repro verified_pass is an executed arm; the standalone gate skips it (no gap), and
  // O-P4 carries no medium obligation. The legit native-repro path is untouched at any tier.
  assert.deepEqual(findingDifferentialGapForStandaloneReportableFindings(domain, args).missing, []);
  assert.deepEqual(reproVerifiedGapForNativeReportableFindings(domain, args).missing, []);
}));

test("a MEDIUM native finding with a BARE FORGED repro line still requires an executed arm (Fix-3 dependency is safe)", () => withTempHome(() => {
  const domain = "native-medium-forged.example.com";
  observeNativeSurface(domain);
  recordNativeClaim(domain, { severity: "medium" });
  // A bare forged verified_pass line whose vuln_run_id/control_run_id resolve to NOTHING:
  // it no longer makes reproVerifiedByFinding[F-1] truthy, so the Fix-3 native-skip does
  // NOT short-circuit — the finding falls through to the standalone arm.
  seedBareForgedReproPass(domain, { findingId: "F-1", argv: REPRO_COMMAND_ARGV });
  const args = argsFor("medium");
  const standalone = findingDifferentialGapForStandaloneReportableFindings(domain, args);
  assert.deepEqual(standalone.missing, [{ finding_id: "F-1", reason: "no_finding_differential_verified_pass" }]);
  // O-P4 still carries no obligation at medium (the obligation is on the standalone gate).
  assert.deepEqual(reproVerifiedGapForNativeReportableFindings(domain, args).missing, []);
}));
