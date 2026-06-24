"use strict";

// READ-TIME SEVERITY RE-CLAMP at the compose + grade read paths. The frozen-baseline clamp
// was write-time only; a runtime-indirection rewrite of verification-final.json (bump
// high->critical, recompute the keyless content hash) inflated the public report and the
// grade severity past the demonstrated baseline. The clamp is now re-applied AT READ, within
// band only: it lowers an above-baseline unproven severity back to the frozen baseline, never
// raises, and a MAC-armed proven rise keeps its higher value.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const {
  appendCandidateClaim,
  canonicalizeExploitTarget,
} = require("../mcp/lib/claims.js");
const {
  buildClaimFreeze,
} = require("../mcp/lib/claim-freeze.js");
const {
  writeVerificationRound,
  reclampSeveritiesAgainstFreeze,
} = require("../mcp/lib/verification-round-store.js");
const {
  finalSeverityByFinding,
} = require("../mcp/lib/reachability-ceiling.js");
const {
  requireFinalReportableSeveritySet,
} = require("../mcp/lib/grade-verdict-store.js");
const composeReportTool = require("../mcp/lib/tools/compose-report.js");
const recordClaimTool = require("../mcp/lib/tools/record-candidate-claim.js");
const { offensiveRowHash } = require("../mcp/lib/finding-differential-verifier.js");
const {
  ensureHandoffSigningKey,
} = require("../mcp/lib/handoff-signing-key.js");
const {
  signOffensiveRunRow,
} = require("../mcp/lib/offensive-row-mac.js");
const {
  appendJsonlLine,
} = require("../mcp/lib/storage.js");
const { initSession } = require("../mcp/lib/session-state.js");
const {
  findingDifferentialVerifiedJsonlPath,
  offensiveRunsJsonlPath,
  reportMarkdownPath,
  sessionDir,
  verificationRoundPaths,
} = require("../mcp/lib/paths.js");

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-severity-reclamp-"));
  process.env.HOME = home;
  try {
    return fn(home);
  } finally {
    if (previousHome === undefined) delete process.env.HOME;
    else process.env.HOME = previousHome;
    fs.rmSync(home, { recursive: true, force: true });
  }
}

function hex(char) {
  return char.repeat(64);
}

const SURFACE = "surface:billing-profile";

function initWebSession(domain) {
  JSON.parse(initSession({ target_domain: domain, target_url: `https://${domain}/` }));
}

function freezeFindingAt(domain, severity, { surfaceIds = null, evidenceRefs = null, exploitOutcome = null } = {}) {
  const claim = {
    target_domain: domain,
    title: "Fixture finding",
    summary: "Frozen baseline for the read-time reclamp test.",
    severity,
    status: "candidate",
    evidence_refs: evidenceRefs || [{ kind: "finding", finding_id: "F-1", content_hash: hex("0") }],
    impact: "Bounded fixture impact.",
  };
  if (surfaceIds) claim.surface_ids = surfaceIds;
  if (exploitOutcome) claim.exploit_outcome = exploitOutcome;
  appendCandidateClaim(claim);
  buildClaimFreeze(domain, { write: true, now: new Date("2026-06-01T00:00:00.000Z") });
}

function writeAllRounds(domain, severity, extraResultFields = {}) {
  for (const round of ["brutalist", "balanced", "final"]) {
    writeVerificationRound({
      target_domain: domain,
      round,
      notes: null,
      results: [{
        finding_id: "F-1",
        disposition: "confirmed",
        severity,
        reportable: true,
        reasoning: "fixture",
        ...extraResultFields,
      }],
    });
  }
}

function writeFinalRound(domain, severity) {
  writeAllRounds(domain, severity);
}

// Hand-edit verification-final.json to bump the persisted severity (the keyless-hash rewrite
// a runtime-indirection actor would do). We rewrite the whole file with the bumped severity;
// the read-time reclamp re-derives the baseline regardless of any recomputed content hash.
function bumpPersistedSeverity(domain, severity) {
  const file = verificationRoundPaths(domain, "final").json;
  const doc = JSON.parse(fs.readFileSync(file, "utf8"));
  for (const result of doc.results) result.severity = severity;
  fs.writeFileSync(file, `${JSON.stringify(doc, null, 2)}\n`);
}

test("a hand-bumped high->critical re-reads as the frozen baseline at grade (finalSeverityByFinding + reportable set)", () => withTempHome(() => {
  const domain = "reclamp-bump.example.com";
  initWebSession(domain);
  freezeFindingAt(domain, "high");
  writeFinalRound(domain, "high");
  bumpPersistedSeverity(domain, "critical");

  // Grade: finalSeverityByFinding + requireFinalReportableSeveritySet both re-clamp.
  assert.equal(finalSeverityByFinding(domain).get("F-1"), "high", "grade finalSeverityByFinding re-clamps the bumped critical");
  const reportable = requireFinalReportableSeveritySet(domain, new Set(["F-1"]));
  assert.ok(reportable.has("F-1"), "still reportable at the clamped baseline");
}));

test("a finding at/below its baseline is untouched by the read-time reclamp", () => withTempHome(() => {
  const domain = "reclamp-baseline.example.com";
  initWebSession(domain);
  freezeFindingAt(domain, "high");
  writeFinalRound(domain, "medium"); // below baseline, written honestly

  assert.equal(finalSeverityByFinding(domain).get("F-1"), "medium", "grade leaves a below-baseline severity untouched");
}));

test("the compose-rendered CVSS block re-reads a hand-bumped severity as its frozen baseline", () => withTempHome(() => {
  const domain = "reclamp-compose.example.com";
  initWebSession(domain);
  const WEB_SURFACE = "surface:orders";
  // Record a real web claim at baseline HIGH with cvss_inputs so the CVSS block renders.
  JSON.parse(recordClaimTool.handler({
    target_domain: domain,
    title: "IDOR in /api/orders",
    severity: "high",
    cwe: "CWE-639",
    endpoint: `https://${domain}/api/orders/1`,
    description: "An attacker can read other users' orders.",
    proof_of_concept: `curl https://${domain}/api/orders/2`,
    validated: true,
    surface_id: WEB_SURFACE,
    cvss_inputs: { attack_vector: "network", privileges_required: "low", confidentiality: "high", integrity: "none", availability: "none" },
  }));
  buildClaimFreeze(domain, { write: true, now: new Date("2026-06-01T00:00:00.000Z") });
  writeFinalRound(domain, "high");
  // Seed a genuine executed-flip arm so the compose executed-flip report-door gate is satisfied.
  const mkRow = (over) => {
    const row = {
      version: 1, target_domain: domain, run_id: over.run_id, tool_id: "bob_http_idor_confirm",
      target: canonicalizeExploitTarget(`https://${domain}/api/orders/1`),
      offensive_outcome: over.offensive_outcome, dry_run: false, timed_out: false,
      command_hash: over.command_hash, exit_code: 0, stdout_hash: hex("b"), stderr_hash: hex("c"),
      demonstrated_severity: "high", surface_id: WEB_SURFACE,
    };
    signOffensiveRunRow(row, ensureHandoffSigningKey(domain));
    fs.mkdirSync(sessionDir(domain), { recursive: true });
    fs.appendFileSync(offensiveRunsJsonlPath(domain), `${JSON.stringify(row)}\n`);
    return row;
  };
  const positive = mkRow({ run_id: "fd-positive-1", offensive_outcome: "exploited_safely", command_hash: hex("1") });
  const control = mkRow({ run_id: "fd-control-1", offensive_outcome: "blocked_by_defense", command_hash: hex("2") });
  appendJsonlLine(findingDifferentialVerifiedJsonlPath(domain), {
    version: 1, target_domain: domain, finding_id: "F-1", result: "verified_pass",
    reason: "executed_finding_differential_flip", surface_id: WEB_SURFACE, source: "offensive_runs",
    positive_run_id: "fd-positive-1", positive_row_hash: offensiveRowHash(positive),
    control_run_id: "fd-control-1", control_row_hash: offensiveRowHash(control),
  });
  // Runtime-indirection bump of the persisted final round high -> critical.
  bumpPersistedSeverity(domain, "critical");

  const response = composeReportTool.handler({
    target_domain: domain,
    sections: [{ kind: "impact", heading: "Impact", prose: "An attacker can read other users' orders.", provenance: "operator_osint", evidence_refs: [] }],
  });
  JSON.parse(typeof response === "string" ? response : JSON.stringify(response));
  const rendered = fs.readFileSync(reportMarkdownPath(domain), "utf8");
  // The CVSS block labels the FINAL-round severity through readFinalVerificationByFinding,
  // which reclamps the bumped critical back to the frozen high baseline.
  assert.match(rendered, /Final verification round severity:\*\* high/);
  assert.doesNotMatch(rendered, /Final verification round severity:\*\* critical/);
}));

test("a legitimately MAC-armed proven rise KEEPS its higher severity at read", () => withTempHome(() => {
  const domain = "reclamp-proven-rise.example.com";
  initWebSession(domain);
  // A MAC-signed exploited_safely row demonstrating HIGH (within bob_http_xss_confirm's
  // ceiling), bound to the claim's single surface, with the matching exploit_run ref so the
  // proven-rise allow-path validates a rise from the medium baseline to high.
  const target = canonicalizeExploitTarget(`https://${domain}/proof`);
  const ref = {
    kind: "exploit_run", run_id: "run-exploit-1", tool_id: "bob_http_xss_confirm", target,
    offensive_outcome: "exploited_safely", command_hash: hex("a"), exit_code: 0,
    stdout_hash: hex("b"), stderr_hash: hex("c"),
  };
  const row = {
    version: 1, target_domain: domain, run_id: ref.run_id, tool_id: ref.tool_id, target,
    offensive_outcome: "exploited_safely", dry_run: false, timed_out: false,
    command_hash: ref.command_hash, exit_code: 0, stdout_hash: ref.stdout_hash, stderr_hash: ref.stderr_hash,
    demonstrated_severity: "high", surface_id: SURFACE,
  };
  signOffensiveRunRow(row, ensureHandoffSigningKey(domain));
  fs.mkdirSync(sessionDir(domain), { recursive: true });
  fs.appendFileSync(offensiveRunsJsonlPath(domain), `${JSON.stringify(row)}\n`);

  freezeFindingAt(domain, "medium", {
    surfaceIds: [SURFACE],
    exploitOutcome: { outcome: "exploited_safely", safe_oracle: { kind: "reflected_canary" } },
    evidenceRefs: [{ kind: "finding", finding_id: "F-1", content_hash: hex("0") }, ref],
  });

  // The read-time reclamp is what BOTH read sites apply to the on-disk results. A result
  // carrying the exploit-replay proof signal, above its medium baseline, re-validates the
  // demonstrated tier from the MAC-covered row and is KEPT at high (not lowered to medium) —
  // the within-band carve-out that protects a legitimately-armed rise at read.
  const decisions = reclampSeveritiesAgainstFreeze(domain, [{
    finding_id: "F-1", severity: "high", confidence_reasons: ["exploit_replay_confirmed"],
  }]);
  assert.deepEqual(decisions.get("F-1"), { severity: "high", provenRise: true }, "the read-time reclamp keeps a MAC-proven rise");

  // And an UNPROVEN above-baseline result on the same finding (no proof signal) is lowered to
  // the medium baseline by the same read-time helper.
  const unproven = reclampSeveritiesAgainstFreeze(domain, [{ finding_id: "F-1", severity: "high" }]);
  assert.equal(unproven.get("F-1").severity, "medium", "an unproven above-baseline rise is lowered at read");
}));
