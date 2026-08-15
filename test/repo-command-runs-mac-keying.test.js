"use strict";

// Cycle B: repo-command-runs.jsonl LIVE rows are KEYED with a domain-separated ed25519
// signature (bob.repo-command-run.v1). Forging a repro source row now requires the
// signing key, not just a recomputable content hash (command_hash + stdout/stderr_hash).
// Real KEYING, NOT a read-time re-hash. Does NOT close F3 (key still 0600 at the agent
// uid; F2 collapses INTO F3).
//
// The read site is repro-replay-verifier.js resolveRepoRunRow (used by reverifyReproRecord
// + readReproVerifiedSummary): AFTER the dry_run/timed_out checks it verifies the keyed
// row_mac. Two-state: an OLD unsigned row is accepted-with-warning (still re-resolved +
// capture-re-checked); a SIGNED-then-TAMPERED row hard-fails (ok:false). The dry-run PLAN
// row is never signed and is still rejected on dry_run (never a trust root).

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const {
  reverifyReproRecord,
  readReproVerifiedSummary,
} = require("../mcp/domains/repo/repro-replay-verifier.js");
const { repoCommandRunsJsonlPath } = require("../mcp/core/io/paths.js");
const {
  signRowWithMac,
  OFFENSIVE_ROW_MAC_CONTEXT,
  INVARIANT_RUN_MAC_CONTEXT,
} = require("../mcp/core/ledger-integrity/index.js");
const {
  ensureHandoffKeypair,
  readHandoffSigningPrivateKey,
} = require("../mcp/core/ledger-integrity/index.js");
const { hashCanonicalJson } = require("../mcp/core/verification/verification-contracts.js");
const { appendJsonlLine } = require("../mcp/core/io/storage.js");
const {
  seedGenuineReproPair,
} = require("./helpers/repro-run-pair.js");

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-repo-mac-keying-"));
  process.env.HOME = home;
  try {
    return fn(home);
  } finally {
    if (previousHome === undefined) delete process.env.HOME;
    else process.env.HOME = previousHome;
    fs.rmSync(home, { recursive: true, force: true });
  }
}

function readRows(domain) {
  return fs.readFileSync(repoCommandRunsJsonlPath(domain), "utf8")
    .split("\n").filter((l) => l.trim()).map((l) => JSON.parse(l));
}

function rewriteRows(domain, rows) {
  fs.writeFileSync(repoCommandRunsJsonlPath(domain), `${rows.map((r) => JSON.stringify(r)).join("\n")}\n`);
}

test("(a) NEW signed live rows carry bob.repo-command-run.v1 and reverify/summary admit", () => withTempHome(() => {
  const domain = "repo-keying-genuine.example.com";
  const seeded = seedGenuineReproPair(domain, { sign: true });
  const rows = readRows(domain);
  const vulnRow = rows.find((r) => r.run_id === seeded.vulnRunId);
  assert.ok(vulnRow.row_mac, "signed live row carries row_mac");
  assert.equal(vulnRow.row_mac.scheme, "ed25519");

  const out = reverifyReproRecord(domain, seeded.verdict);
  assert.equal(out.ok, true, "signed flipping pair re-adjudicates ok");
  const summary = readReproVerifiedSummary(domain);
  assert.ok(summary.verified_by_finding[seeded.findingId], "summary admits the signed pair");
}));

test("(b) a TAMPERED signed row (covered field mutated, stale mac kept) is fail-closed excluded", () => withTempHome(() => {
  const domain = "repo-keying-tamper.example.com";
  const seeded = seedGenuineReproPair(domain, { sign: true });
  const rows = readRows(domain);
  const rewritten = rows.map((row) => {
    if (row.run_id !== seeded.vulnRunId) return row;
    // Flip exit_code (a covered field) but KEEP the stale row_mac.
    return { ...row, exit_code: 137 };
  });
  rewriteRows(domain, rewritten);
  const out = reverifyReproRecord(domain, seeded.verdict);
  assert.equal(out.ok, false, "tampered signed row fails the keyed verify -> ok:false");
}));

test("(c) a forged row with a recomputed content-hash but NO valid mac is excluded (keying defeats the F2 forge)", () => withTempHome(() => {
  const domain = "repo-keying-content-forge.example.com";
  // A genuine SIGNED pair, then re-sign the vuln row under the WRONG (offensive) context:
  // its content hashes (command_hash/stdout_hash/stderr_hash) stay perfectly valid (the
  // old F2 forge), but it carries no valid bob.repo-command-run.v1 mac.
  const seeded = seedGenuineReproPair(domain, { sign: false });
  const rows = readRows(domain);
  ensureHandoffKeypair(domain);
  const rewritten = rows.map((row) => {
    if (row.run_id !== seeded.vulnRunId) return row;
    const copy = { ...row };
    delete copy.row_mac;
    // A real ed25519 signature, but under the offensive context (domain separation).
    signRowWithMac(OFFENSIVE_ROW_MAC_CONTEXT, copy, readHandoffSigningPrivateKey(domain));
    return copy;
  });
  rewriteRows(domain, rewritten);
  const out = reverifyReproRecord(domain, seeded.verdict);
  assert.equal(out.ok, false, "content-valid but repo-mac-invalid row is excluded");
}));

test("(d) an OLD unsigned legacy row is accepted-with-warning and still flips", () => withTempHome(() => {
  const domain = "repo-keying-legacy.example.com";
  const seeded = seedGenuineReproPair(domain, { sign: false });
  const rows = readRows(domain);
  assert.equal(rows.find((r) => r.run_id === seeded.vulnRunId).row_mac, undefined, "legacy row has no mac");
  const out = reverifyReproRecord(domain, seeded.verdict);
  assert.equal(out.ok, true, "unsigned legacy pair still flips (accept-with-warning)");
}));

test("(d2) cross-ledger replay: an INVARIANT-context mac on a repo row fails", () => withTempHome(() => {
  const domain = "repo-keying-crossledger.example.com";
  const seeded = seedGenuineReproPair(domain, { sign: false });
  const rows = readRows(domain);
  ensureHandoffKeypair(domain);
  const rewritten = rows.map((row) => {
    if (row.run_id !== seeded.vulnRunId) return row;
    const copy = { ...row };
    delete copy.row_mac;
    // A real signature under the INVARIANT context, not the repo-command-run context.
    signRowWithMac(INVARIANT_RUN_MAC_CONTEXT, copy, readHandoffSigningPrivateKey(domain));
    return copy;
  });
  rewriteRows(domain, rewritten);
  const out = reverifyReproRecord(domain, seeded.verdict);
  assert.equal(out.ok, false, "an invariant-context mac on a repo row fails domain separation");
}));

test("(e) the dry-run PLAN row is unsigned and still rejected on dry_run", () => withTempHome(() => {
  const domain = "repo-keying-planrow.example.com";
  // A plan (dry_run:true) row is never a trust root: resolveRepoRunRow rejects dry_run.
  // It is never signed by the producer; a verdict citing it must fail closed regardless.
  const planRow = {
    version: 1,
    run_id: "plan-1",
    target_domain: domain,
    dry_run: true,
    command_hash: hashCanonicalJson(["sh", "-lc", "x"]),
    exit_code: null,
    timed_out: false,
  };
  appendJsonlLine(repoCommandRunsJsonlPath(domain), planRow);
  assert.equal(planRow.row_mac, undefined, "plan row is never signed");
  const out = reverifyReproRecord(domain, {
    result: "verified_pass",
    finding_id: "F-1",
    vuln_run_id: "plan-1",
    control_run_id: "plan-1",
    command_hash: planRow.command_hash,
  });
  assert.equal(out.ok, false, "a dry-run plan row is rejected (never a trust root)");
}));
