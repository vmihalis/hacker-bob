"use strict";

// Web-standalone finding-differential verifier: the per-finding executed-binding gate
// for standalone non-oracle classes. A verdict mints verified_pass ONLY when a flipping
// negative control resolves an executed positive bound to the finding's surface; a
// single executed run, a hash-identical control, a non-discriminating control, or a
// cross-surface row is REFUSED. The verdict goes only to the MCP-write-only, audit-
// graded finding-differential-verified.jsonl, keyed by finding_id.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const {
  verifyFindingDifferential,
  readFindingDifferentialVerifiedSummary,
  offensiveRowHash,
} = require("../mcp/core/differential/index.js");
const {
  canonicalizeExploitTarget,
} = require("../mcp/core/claims/claims.js");
const {
  offensiveRunsJsonlPath,
  findingDifferentialVerifiedJsonlPath,
} = require("../mcp/core/io/paths.js");
const {
  ensureHandoffSigningKey,
} = require("../mcp/core/ledger-integrity/index.js");
const {
  signOffensiveRunRow,
} = require("../mcp/core/ledger-integrity/index.js");
const {
  buildAndSignOffensiveRow,
} = require("../mcp/domains/web/offensive-capture-writer.js");
const { initSession } = require("../mcp/core/session/session-state.js");
const { withSessionLock } = require("../mcp/core/io/storage.js");

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-finding-diff-"));
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

// Build + sign a single offensive-runs row. The runner hardcodes exploited_safely for a
// real positive; a blocked control row is constructed directly here (its safe-variant
// outcome is what the producer would stamp on a defended request) and signed with the
// SAME per-session key, so it verifies its MAC like any genuine row.
function buildSignedRow(domain, over = {}) {
  const runId = over.run_id || "fd-run-default";
  const target = canonicalizeExploitTarget(over.target || `https://${domain}/api/billing/1`);
  const row = {
    version: 1,
    target_domain: domain,
    run_id: runId,
    tool_id: over.tool_id || "bob_http_idor_confirm",
    target,
    offensive_outcome: over.offensive_outcome || "exploited_safely",
    dry_run: over.dry_run === undefined ? false : over.dry_run,
    timed_out: over.timed_out === undefined ? false : over.timed_out,
    command_hash: over.command_hash || hex("a"),
    exit_code: over.exit_code === undefined ? 0 : over.exit_code,
    stdout_hash: over.stdout_hash || hex("b"),
    stderr_hash: over.stderr_hash || hex("c"),
    demonstrated_severity: over.demonstrated_severity || "medium",
    surface_id: over.surface_id === undefined ? SURFACE : over.surface_id,
  };
  signOffensiveRunRow(row, ensureHandoffSigningKey(domain));
  return row;
}

function appendRow(domain, row) {
  fs.mkdirSync(path.dirname(offensiveRunsJsonlPath(domain)), { recursive: true });
  fs.appendFileSync(offensiveRunsJsonlPath(domain), `${JSON.stringify(row)}\n`);
  return row;
}

// A positive (exploited_safely) + a flipping control (blocked_by_defense) on the SAME
// surface, distinct run_ids and distinct command_hash (a true safe-variant differs in
// request shape, not just id).
function seedFlippingPair(domain) {
  appendRow(domain, buildSignedRow(domain, {
    run_id: "fd-positive-1", offensive_outcome: "exploited_safely", command_hash: hex("1"),
  }));
  appendRow(domain, buildSignedRow(domain, {
    run_id: "fd-control-1", offensive_outcome: "blocked_by_defense", command_hash: hex("2"),
  }));
}

const REF_POS = { ledger: "offensive_runs", row_id: "fd-positive-1" };
const REF_CTL = { ledger: "offensive_runs", row_id: "fd-control-1" };

test("a genuine flip (exploited positive + blocked control, same surface) mints verified_pass", () => withTempHome(() => {
  const domain = "fd-flip.example.com";
  seedFlippingPair(domain);
  const out = verifyFindingDifferential({
    target_domain: domain, finding_id: "F-2", surface_id: SURFACE,
    positive_run_ref: REF_POS, control_run_ref: REF_CTL,
  });
  assert.equal(out.result, "verified_pass");
  assert.equal(out.reason, "executed_finding_differential_flip");
  assert.equal(out.finding_id, "F-2");
  assert.notEqual(out.positive_row_hash, out.control_row_hash);

  const summary = readFindingDifferentialVerifiedSummary(domain);
  assert.equal(summary.verified_pass_count, 1);
  assert.ok(summary.verified_by_finding["F-2"], "verified_by_finding indexes the finding");
  assert.equal(summary.verified_by_finding["F-2"].surface_id, SURFACE);
}));

test("a blocked_by_infra control does NOT flip — only an affirmative blocked_by_defense is a safe-variant denial", () => withTempHome(() => {
  const domain = "fd-infra-control.example.com";
  // A signed positive + a signed blocked_by_INFRA control (transport/infra noise:
  // egress unsupported, browser unavailable, baseline-not-auth-challenge). The accept
  // set is narrowed to blocked_by_defense, so this infra-noise control is REFUSED — a
  // transport hiccup cannot mint a false control / a verified_pass.
  appendRow(domain, buildSignedRow(domain, {
    run_id: "fd-positive-1", offensive_outcome: "exploited_safely", command_hash: hex("1"),
  }));
  appendRow(domain, buildSignedRow(domain, {
    run_id: "fd-control-1", offensive_outcome: "blocked_by_infra", command_hash: hex("2"),
  }));
  const out = verifyFindingDifferential({
    target_domain: domain, finding_id: "F-2", surface_id: SURFACE,
    positive_run_ref: REF_POS, control_run_ref: REF_CTL,
  });
  assert.equal(out.result, "refuted");
  assert.match(out.reason, /not a blocked safe-variant/);
  assert.match(out.reason, /blocked_by_infra/);
  assert.equal(readFindingDifferentialVerifiedSummary(domain).verified_pass_count, 0);

  // Control proof: the SAME shape with an affirmative blocked_by_defense control DOES flip.
  const domain2 = "fd-defense-control.example.com";
  seedFlippingPair(domain2);
  const flipped = verifyFindingDifferential({
    target_domain: domain2, finding_id: "F-2", surface_id: SURFACE,
    positive_run_ref: REF_POS, control_run_ref: REF_CTL,
  });
  assert.equal(flipped.result, "verified_pass");
}));

test("a single executed run (positive cited as both legs) is REFUSED — no control", () => withTempHome(() => {
  const domain = "fd-single.example.com";
  appendRow(domain, buildSignedRow(domain, { run_id: "fd-positive-1", offensive_outcome: "exploited_safely" }));
  assert.throws(
    () => verifyFindingDifferential({
      target_domain: domain, finding_id: "F-2", surface_id: SURFACE,
      positive_run_ref: REF_POS, control_run_ref: REF_POS,
    }),
    /DIFFERENT executed rows/,
  );
  // No verdict minted.
  assert.equal(readFindingDifferentialVerifiedSummary(domain).total_runs, 0);
}));

test("a hash-identical control (same proof material under a fresh run_id) is REFUSED", () => withTempHome(() => {
  const domain = "fd-hashid.example.com";
  // Identical command_hash + outcome + surface; differs only in run_id.
  appendRow(domain, buildSignedRow(domain, {
    run_id: "fd-positive-1", offensive_outcome: "exploited_safely", command_hash: hex("9"),
  }));
  appendRow(domain, buildSignedRow(domain, {
    run_id: "fd-control-1", offensive_outcome: "exploited_safely", command_hash: hex("9"),
  }));
  const out = verifyFindingDifferential({
    target_domain: domain, finding_id: "F-2", surface_id: SURFACE,
    positive_run_ref: REF_POS, control_run_ref: REF_CTL,
  });
  assert.equal(out.result, "refuted");
  assert.match(out.reason, /hash-identical/);
  assert.equal(readFindingDifferentialVerifiedSummary(domain).verified_pass_count, 0);
}));

test("a non-discriminating control (same offensive_outcome, different request) is REFUSED -> refuted", () => withTempHome(() => {
  const domain = "fd-nondiscrim.example.com";
  appendRow(domain, buildSignedRow(domain, {
    run_id: "fd-positive-1", offensive_outcome: "exploited_safely", command_hash: hex("1"),
  }));
  appendRow(domain, buildSignedRow(domain, {
    run_id: "fd-control-1", offensive_outcome: "exploited_safely", command_hash: hex("2"),
  }));
  const out = verifyFindingDifferential({
    target_domain: domain, finding_id: "F-2", surface_id: SURFACE,
    positive_run_ref: REF_POS, control_run_ref: REF_CTL,
  });
  assert.equal(out.result, "refuted");
  assert.match(out.reason, /no differential flip/);
  assert.equal(readFindingDifferentialVerifiedSummary(domain).verified_pass_count, 0);
}));

test("a surface_id mismatch between the rows is REFUSED (cross-surface binding, #111 generalized)", () => withTempHome(() => {
  const domain = "fd-surfacemismatch.example.com";
  appendRow(domain, buildSignedRow(domain, {
    run_id: "fd-positive-1", offensive_outcome: "exploited_safely", command_hash: hex("1"), surface_id: SURFACE,
  }));
  appendRow(domain, buildSignedRow(domain, {
    run_id: "fd-control-1", offensive_outcome: "blocked_by_defense", command_hash: hex("2"), surface_id: "surface:OTHER",
  }));
  const out = verifyFindingDifferential({
    target_domain: domain, finding_id: "F-2", surface_id: SURFACE,
    positive_run_ref: REF_POS, control_run_ref: REF_CTL,
  });
  // The control row binds to a different surface than the finding -> inconclusive, NOT verified.
  assert.equal(out.result, "inconclusive");
  assert.match(out.reason, /control row surface_id/);
  assert.equal(readFindingDifferentialVerifiedSummary(domain).verified_pass_count, 0);
}));

test("run_id single-use: a row bound to one finding-differential verdict cannot bind another", () => withTempHome(() => {
  const domain = "fd-singleuse.example.com";
  seedFlippingPair(domain);
  // First binding consumes both rows.
  verifyFindingDifferential({
    target_domain: domain, finding_id: "F-2", surface_id: SURFACE,
    positive_run_ref: REF_POS, control_run_ref: REF_CTL,
  });
  // Re-binding the same positive to a different finding is refused.
  appendRow(domain, buildSignedRow(domain, {
    run_id: "fd-control-2", offensive_outcome: "blocked_by_defense", command_hash: hex("3"),
  }));
  assert.throws(
    () => verifyFindingDifferential({
      target_domain: domain, finding_id: "F-3", surface_id: SURFACE,
      positive_run_ref: REF_POS, control_run_ref: { ledger: "offensive_runs", row_id: "fd-control-2" },
    }),
    /already bound to a finding-differential verdict/,
  );
}));

test("a row that fails MAC verification (foreign/tampered) is REFUSED before any field check", () => withTempHome(() => {
  const domain = "fd-mac.example.com";
  // Sign the positive with the real key, then tamper its outcome AFTER signing so the
  // MAC no longer covers the row.
  const positive = buildSignedRow(domain, { run_id: "fd-positive-1", offensive_outcome: "exploited_safely", command_hash: hex("1") });
  positive.offensive_outcome = "exploited_safely"; // unchanged identity, but mutate a covered field below
  positive.demonstrated_severity = "critical"; // tamper a MAC-covered field
  appendRow(domain, positive);
  appendRow(domain, buildSignedRow(domain, { run_id: "fd-control-1", offensive_outcome: "blocked_by_defense", command_hash: hex("2") }));
  assert.throws(
    () => verifyFindingDifferential({
      target_domain: domain, finding_id: "F-2", surface_id: SURFACE,
      positive_run_ref: REF_POS, control_run_ref: REF_CTL,
    }),
    /not a validly MAC-signed/,
  );
}));

test("an unsupported ledger ref (auth_differential, deferred) is REFUSED", () => withTempHome(() => {
  const domain = "fd-ledger.example.com";
  seedFlippingPair(domain);
  assert.throws(
    () => verifyFindingDifferential({
      target_domain: domain, finding_id: "F-2", surface_id: SURFACE,
      positive_run_ref: { ledger: "auth_differential", row_id: "fd-positive-1" },
      control_run_ref: REF_CTL,
    }),
    /ledger must be one of/,
  );
}));

test("ledger record shape + results_hash determinism, and the reader summary", () => withTempHome(() => {
  const domain = "fd-shape.example.com";
  seedFlippingPair(domain);
  verifyFindingDifferential({
    target_domain: domain, finding_id: "F-2", surface_id: SURFACE,
    positive_run_ref: REF_POS, control_run_ref: REF_CTL,
  });
  const lines = fs.readFileSync(findingDifferentialVerifiedJsonlPath(domain), "utf8")
    .split("\n").filter((l) => l.trim());
  assert.equal(lines.length, 1);
  const rec = JSON.parse(lines[0]);
  for (const k of [
    "version", "target_domain", "ts", "finding_id", "result", "reason", "surface_id",
    "source", "positive_run_id", "positive_row_hash", "control_run_id", "control_row_hash", "results_hash",
  ]) {
    assert.ok(Object.prototype.hasOwnProperty.call(rec, k), `record carries ${k}`);
  }
  assert.equal(rec.source, "offensive_runs");
  // results_hash is over the body (excluding results_hash itself); recompute is stable.
  const { hashCanonicalJson } = require("../mcp/core/verification/verification-contracts.js");
  const body = { ...rec };
  delete body.results_hash;
  assert.equal(rec.results_hash, hashCanonicalJson(body));

  const summary = readFindingDifferentialVerifiedSummary(domain);
  assert.equal(summary.total_runs, 1);
  assert.equal(summary.verified_pass_count, 1);
  assert.equal(summary.refuted_count, 0);
  assert.equal(summary.inconclusive_count, 0);
}));

test("offensiveRowHash excludes run_id + row_mac so identical proof material collides", () => withTempHome(() => {
  const domain = "fd-rowhash.example.com";
  const a = buildSignedRow(domain, { run_id: "fd-a", offensive_outcome: "exploited_safely", command_hash: hex("7") });
  const b = buildSignedRow(domain, { run_id: "fd-b", offensive_outcome: "exploited_safely", command_hash: hex("7") });
  assert.equal(offensiveRowHash(a), offensiveRowHash(b), "rows differing only in run_id/mac collide");
  const c = buildSignedRow(domain, { run_id: "fd-c", offensive_outcome: "blocked_by_defense", command_hash: hex("7") });
  assert.notEqual(offensiveRowHash(a), offensiveRowHash(c), "different outcome -> different hash");
}));

// ── A1 READ-TIME RE-DERIVATION: the summary reader re-resolves + re-adjudicates each ──
//    verified_pass record against the MAC-covered offensive-runs rows; a forged verdict
//    line is excluded, and surface_id + demonstrated_severity come from the SIGNED
//    positive row, not the record's self-hashed fields.

// Write a verdict line directly to the audit-graded ledger (the direct-disk forge the
// threat model admits: a same-UID node -e can append a line with a valid self results_hash).
function appendVerdictLine(domain, over = {}) {
  const body = {
    version: 1,
    target_domain: domain,
    ts: "2026-05-27T00:00:00.000Z",
    finding_id: over.finding_id || "F-FORGE",
    result: over.result || "verified_pass",
    reason: over.reason || "executed_finding_differential_flip",
    surface_id: over.surface_id === undefined ? SURFACE : over.surface_id,
    source: "offensive_runs",
    positive_run_id: over.positive_run_id || "fd-positive-1",
    positive_row_hash: over.positive_row_hash || hex("1"),
    control_run_id: over.control_run_id || "fd-control-1",
    control_row_hash: over.control_row_hash || hex("2"),
  };
  const { hashCanonicalJson } = require("../mcp/core/verification/verification-contracts.js");
  const record = { ...body, results_hash: hashCanonicalJson(body) };
  fs.mkdirSync(path.dirname(findingDifferentialVerifiedJsonlPath(domain)), { recursive: true });
  fs.appendFileSync(findingDifferentialVerifiedJsonlPath(domain), `${JSON.stringify(record)}\n`);
  return record;
}

test("A1: a forged verdict line whose run_ids do NOT resolve to MAC-valid flipping rows is EXCLUDED", () => withTempHome(() => {
  const domain = "fd-forge-dangling.example.com";
  // A bare forged verdict with a VALID self results_hash but NO backing offensive-runs rows.
  appendVerdictLine(domain, { finding_id: "F-9", positive_run_id: "ghost-pos", control_run_id: "ghost-ctl" });
  const summary = readFindingDifferentialVerifiedSummary(domain);
  // The record counts as a verified_pass on disk, but re-derivation finds no MAC-valid
  // backing rows, so it is NOT in verified_by_finding.
  assert.equal(summary.verified_pass_count, 1, "the raw line is on disk");
  assert.equal(summary.verified_by_finding["F-9"], undefined, "but a dangling forge is excluded at read time");
}));

test("A1: a forged verdict whose run_ids point at NON-flipping rows (two exploited) is EXCLUDED", () => withTempHome(() => {
  const domain = "fd-forge-noflip.example.com";
  // Two real MAC-signed rows, but BOTH exploited_safely — no flip. A forger points a
  // verified_pass verdict at them hoping the stored result is trusted.
  appendRow(domain, buildSignedRow(domain, { run_id: "fd-positive-1", offensive_outcome: "exploited_safely", command_hash: hex("1") }));
  appendRow(domain, buildSignedRow(domain, { run_id: "fd-control-1", offensive_outcome: "exploited_safely", command_hash: hex("2") }));
  appendVerdictLine(domain, { finding_id: "F-9" });
  const summary = readFindingDifferentialVerifiedSummary(domain);
  assert.equal(summary.verified_by_finding["F-9"], undefined, "re-adjudication finds no flip -> excluded");
}));

test("A1: a GENUINE flip is INCLUDED, exposing surface_id + demonstrated_severity from the RE-RESOLVED positive row", () => withTempHome(() => {
  const domain = "fd-rederive-ok.example.com";
  // A real flip: exploited positive (demonstrated_severity high) + blocked control.
  appendRow(domain, buildSignedRow(domain, {
    run_id: "fd-positive-1", offensive_outcome: "exploited_safely", command_hash: hex("1"),
    surface_id: SURFACE, demonstrated_severity: "high",
  }));
  appendRow(domain, buildSignedRow(domain, {
    run_id: "fd-control-1", offensive_outcome: "blocked_by_defense", command_hash: hex("2"),
    surface_id: SURFACE, demonstrated_severity: "high",
  }));
  // The verdict record STORES a DIFFERENT surface + a result that the reader must not
  // trust verbatim — the re-resolved positive ROW's surface/severity must WIN.
  appendVerdictLine(domain, {
    finding_id: "F-9", surface_id: "surface:LIAR", positive_row_hash: hex("z"), control_row_hash: hex("z"),
  });
  const summary = readFindingDifferentialVerifiedSummary(domain);
  const entry = summary.verified_by_finding["F-9"];
  assert.ok(entry, "a re-derivable genuine flip is included");
  assert.equal(entry.surface_id, SURFACE, "surface comes from the MAC-covered positive row, not the verdict record");
  assert.equal(entry.demonstrated_severity, "high", "demonstrated_severity comes from the positive row");
}));

test("C2/honest: a producer-signed exploited_safely positive + a producer-SIGNED blocked_by_defense control mints verified_pass (control leg no longer needs test fabrication)", () => withTempHome(() => {
  const domain = "fd-honest.example.com";
  initSession({ target_domain: domain, target_url: `https://${domain}/` });
  // BOTH rows are produced through the SHARED writer (the production sign path), NOT a
  // hand-built object. The blocked_by_defense control is now constructible by honest
  // means via the offensiveOutcome param — so verifyFindingDifferential is satisfiable
  // by an honest run, and the gate is enforceable rather than decorative.
  const positive = withSessionLock(domain, () => buildAndSignOffensiveRow(domain, {
    runIdPrefix: "idor", toolId: "bob_http_idor_confirm", method: "GET",
    canonicalTarget: `https://${domain}/api/billing/1`, surfaceId: SURFACE,
    identityTag: "B-as-A", stdoutContent: "{\"ok\":1}", stderrContent: "{}",
    offensiveOutcome: "exploited_safely",
  }));
  const control = withSessionLock(domain, () => buildAndSignOffensiveRow(domain, {
    runIdPrefix: "idor", toolId: "bob_http_idor_confirm", method: "GET",
    canonicalTarget: `https://${domain}/api/billing/1`, surfaceId: SURFACE,
    identityTag: "control:object_not_access_controlled", stdoutContent: "{\"deny\":1}", stderrContent: "{}",
    offensiveOutcome: "blocked_by_defense",
  }));
  assert.equal(positive.offensive_outcome, "exploited_safely");
  assert.equal(control.offensive_outcome, "blocked_by_defense");
  const out = verifyFindingDifferential({
    target_domain: domain, finding_id: "F-2", surface_id: SURFACE,
    positive_run_ref: { ledger: "offensive_runs", row_id: positive.run_id },
    control_run_ref: { ledger: "offensive_runs", row_id: control.run_id },
  });
  assert.equal(out.result, "verified_pass");
  const summary = readFindingDifferentialVerifiedSummary(domain);
  assert.ok(summary.verified_by_finding["F-2"], "the honest flip is re-derivable + included");
  assert.equal(summary.verified_by_finding["F-2"].surface_id, SURFACE);
}));

test("A1: reverifyFindingDifferentialRecord fails closed when the backing rows were removed (rotated ledger)", () => withTempHome(() => {
  const domain = "fd-rotated.example.com";
  seedFlippingPair(domain);
  verifyFindingDifferential({
    target_domain: domain, finding_id: "F-2", surface_id: SURFACE,
    positive_run_ref: REF_POS, control_run_ref: REF_CTL,
  });
  // It is included while the rows exist...
  assert.ok(readFindingDifferentialVerifiedSummary(domain).verified_by_finding["F-2"]);
  // ...then the source evidence is removed (rotation/truncation). The verdict is no
  // longer provable -> excluded (fail-closed; the source rows are the asset).
  fs.rmSync(offensiveRunsJsonlPath(domain));
  assert.equal(readFindingDifferentialVerifiedSummary(domain).verified_by_finding["F-2"], undefined);
}));

test("HIGH-1: verified_by_finding carries container_isolated:false when the positive offensive row lacks the field (fail-closed, mirrors the invariant leg)", () => withTempHome(() => {
  const domain = "fd-container-isolated.example.com";
  // Offensive-runs rows do NOT carry container_isolated today, so the re-resolved value
  // must read false -- the CORRECT fail-closed posture: a finding-differential-backed SC
  // reportable has NO containerization proof and the verdict gate's SC consult treats it
  // as un-isolated. This mirrors readInvariantVerifiedSummary's container_isolated
  // re-resolution from the MAC-covered positive row.
  seedFlippingPair(domain);
  const out = verifyFindingDifferential({
    target_domain: domain, finding_id: "F-2", surface_id: SURFACE,
    positive_run_ref: REF_POS, control_run_ref: REF_CTL,
  });
  assert.equal(out.result, "verified_pass");
  const entry = readFindingDifferentialVerifiedSummary(domain).verified_by_finding["F-2"];
  assert.ok(entry, "the honest flip is included");
  assert.equal(entry.container_isolated, false,
    "an offensive positive row with no container_isolated field re-resolves to false (fail-closed un-isolated)");
}));
