"use strict";

// READ-TIME RE-DERIVATION of the invariant FV-confirm signal. readInvariantVerifiedSummary
// no longer trusts a verdict line's stored run hashes; it RE-ADJUDICATES each verified_pass
// from the invariant-runs.jsonl rows it cites. A bare forged verdict line, a verdict citing
// a non-flipping pair, a single-run verdict, a rotated ledger, or a content-tampered row all
// drop out of verified_by_finding. Mirrors the A1 finding-differential precedent.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const {
  computeInvariantRunHash,
  invariantFoundryResultHash,
  verifyInvariantDifferential,
  reverifyInvariantVerifiedRecord,
  readInvariantVerifiedSummary,
} = require("../mcp/lib/invariant-runner.js");
const {
  appendJsonlLine,
} = require("../mcp/lib/storage.js");
const {
  invariantRunsJsonlPath,
  invariantVerifiedJsonlPath,
} = require("../mcp/lib/paths.js");

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-invariant-rederive-"));
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

// Build a fully-bound invariant-runs.jsonl row exactly as runInvariantForFinding persists it
// (outcome derived from foundry_result, run_hash from computeInvariantRunHash), so the
// read-time re-validation accepts it.
function makeRow(domain, { findingId = "F-1", outcome, treeRef, checkoutKind = "tree" } = {}) {
  const foundryResult = outcome === "test_failed"
    ? { tests: [{ success: false }] }
    : { tests: [{ success: true }] };
  const row = {
    target_domain: domain,
    finding_id: findingId,
    finding_hash: null,
    template_id: "INV-FIXTURE-001",
    slot_values: { a: "1" },
    contract_name: "BobInvariantTest_fixture",
    function_name: "testBobInvariant_fixture",
    execution_context_hash: "ctx-hash-shared",
    tree_ref: treeRef,
    checkout_kind: checkoutKind,
    outcome,
    foundry_result_hash: invariantFoundryResultHash(foundryResult),
    foundry_result: foundryResult,
    dry_run: false,
  };
  row.run_hash = computeInvariantRunHash(row);
  appendJsonlLine(invariantRunsJsonlPath(domain), row);
  return row;
}

function seedGenuineFlip(domain, findingId = "F-1") {
  const positive = makeRow(domain, { findingId, outcome: "test_failed", treeRef: "target", checkoutKind: "tree" });
  const control = makeRow(domain, { findingId, outcome: "test_passed", treeRef: "fixed", checkoutKind: "upstream_fix" });
  verifyInvariantDifferential({
    target_domain: domain,
    finding_id: findingId,
    positive_run_hash: positive.run_hash,
    control_run_hash: control.run_hash,
  });
  return { positive, control };
}

// Append a hand-built verdict line directly to invariant-verified.jsonl (the forgery shape:
// a same-UID write that bypasses verifyInvariantDifferential).
function forgeVerdict(domain, over = {}) {
  const body = {
    version: 1,
    target_domain: domain,
    ts: "2026-06-01T00:00:00.000Z",
    finding_id: "F-1",
    result: "verified_pass",
    reason: "forged",
    template_id: "INV-FIXTURE-001",
    positive_run_hash: hex("1"),
    control_run_hash: hex("2"),
    positive_violation: true,
    control_violation: false,
    ...over,
  };
  const filePath = invariantVerifiedJsonlPath(domain);
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.appendFileSync(filePath, `${JSON.stringify(body)}\n`);
}

test("(a) a real two-sided flipping pair re-derives ok and stays in verified_by_finding", () => withTempHome(() => {
  const domain = "inv-rederive-genuine.example.com";
  const { positive, control } = seedGenuineFlip(domain, "F-1");
  const summary = readInvariantVerifiedSummary(domain);
  assert.equal(summary.verified_pass_count, 1);
  assert.ok(summary.verified_by_finding["F-1"], "genuine flip stays in verified_by_finding");
  // The carried run hashes are the RE-RESOLVED signed-source values, not the verdict's stored fields.
  assert.equal(summary.verified_by_finding["F-1"].positive_run_hash, positive.run_hash);
  assert.equal(summary.verified_by_finding["F-1"].control_run_hash, control.run_hash);
}));

test("(b) a bare forged verified_pass whose run hashes point at NO rows is EXCLUDED", () => withTempHome(() => {
  const domain = "inv-rederive-bare-forge.example.com";
  // No invariant-runs rows at all; the verdict's run hashes resolve to nothing.
  forgeVerdict(domain, { positive_run_hash: hex("1"), control_run_hash: hex("2") });
  const summary = readInvariantVerifiedSummary(domain);
  assert.equal(summary.verified_pass_count, 1, "the line is counted as a stored verified_pass");
  assert.equal(summary.verified_by_finding["F-1"], undefined, "but re-derivation excludes it from the trusted map");
}));

test("(c) a verdict citing a NON-flipping pair (control also test_failed) is EXCLUDED", () => withTempHome(() => {
  const domain = "inv-rederive-noflip.example.com";
  const positive = makeRow(domain, { outcome: "test_failed", treeRef: "target", checkoutKind: "tree" });
  // Control on a different tree, but it ALSO fails -> no flip (harness/template artifact).
  const control = makeRow(domain, { outcome: "test_failed", treeRef: "fixed", checkoutKind: "upstream_fix" });
  forgeVerdict(domain, { positive_run_hash: positive.run_hash, control_run_hash: control.run_hash });
  const summary = readInvariantVerifiedSummary(domain);
  assert.equal(summary.verified_by_finding["F-1"], undefined, "a non-flipping pair never confirms");
}));

test("(d) a verdict with control_run_hash null (single-run pass) is EXCLUDED", () => withTempHome(() => {
  const domain = "inv-rederive-single.example.com";
  const positive = makeRow(domain, { outcome: "test_failed", treeRef: "target", checkoutKind: "tree" });
  forgeVerdict(domain, { positive_run_hash: positive.run_hash, control_run_hash: null });
  const summary = readInvariantVerifiedSummary(domain);
  assert.equal(summary.verified_by_finding["F-1"], undefined, "a single-run pass cannot confirm");
}));

test("(e) rotated/removed invariant-runs rows drop the previously-present finding (fail-closed)", () => withTempHome(() => {
  const domain = "inv-rederive-rotated.example.com";
  seedGenuineFlip(domain, "F-1");
  assert.ok(readInvariantVerifiedSummary(domain).verified_by_finding["F-1"], "present while the runs exist");
  // Remove the run rows; the verdict line remains on disk but is no longer re-derivable.
  fs.rmSync(invariantRunsJsonlPath(domain));
  const summary = readInvariantVerifiedSummary(domain);
  assert.equal(summary.verified_by_finding["F-1"], undefined, "rotated runs => fail closed");
}));

test("(f) a row whose foundry_result is tampered so computeInvariantRunHash no longer matches is EXCLUDED", () => withTempHome(() => {
  const domain = "inv-rederive-tampered.example.com";
  const positive = makeRow(domain, { outcome: "test_failed", treeRef: "target", checkoutKind: "tree" });
  const control = makeRow(domain, { outcome: "test_passed", treeRef: "fixed", checkoutKind: "upstream_fix" });
  // Mint a genuine verdict first.
  verifyInvariantDifferential({
    target_domain: domain,
    finding_id: "F-1",
    positive_run_hash: positive.run_hash,
    control_run_hash: control.run_hash,
  });
  // Now tamper the control row's foundry_result on disk so its content hash no longer binds.
  const runsPath = invariantRunsJsonlPath(domain);
  const lines = fs.readFileSync(runsPath, "utf8").split("\n").filter((l) => l.trim());
  const rewritten = lines.map((line) => {
    const row = JSON.parse(line);
    if (row.run_hash === control.run_hash) {
      // Flip the result payload but keep run_hash/foundry_result_hash stale -> mismatch.
      row.foundry_result = { tests: [{ success: false }] };
    }
    return JSON.stringify(row);
  });
  fs.writeFileSync(runsPath, `${rewritten.join("\n")}\n`);
  const summary = readInvariantVerifiedSummary(domain);
  assert.equal(summary.verified_by_finding["F-1"], undefined, "a content-inconsistent row breaks the re-derivation");
}));

test("reverifyInvariantVerifiedRecord is exported and fails closed on a null record", () => withTempHome(() => {
  const domain = "inv-rederive-null.example.com";
  const out = reverifyInvariantVerifiedRecord(domain, null);
  assert.equal(out.ok, false);
  assert.equal(out.positive_run_hash, null);
  assert.equal(out.control_run_hash, null);
}));
