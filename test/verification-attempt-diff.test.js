"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const crypto = require("node:crypto");

const {
  diffVerificationAttempts,
  describeAttempt,
  diffFileMaps,
} = require("../mcp/lib/verification-attempt-diff.js");

function uniqueDomain() {
  return `bob-diff-attempts-${crypto.randomBytes(4).toString("hex")}.local`;
}

function attemptDir(domain, attemptId) {
  return path.join(os.homedir(), "hacker-bob-sessions", domain, "verification-attempts", `attempt-${attemptId}`);
}

function writeManifest(domain, attemptId, manifest, files) {
  const dir = attemptDir(domain, attemptId);
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, "manifest.json"), `${JSON.stringify(manifest, null, 2)}\n`);
  if (files) {
    for (const [name, content] of Object.entries(files)) {
      fs.writeFileSync(path.join(dir, name), content);
    }
  }
}

function cleanupDomain(domain) {
  const dir = path.join(os.homedir(), "hacker-bob-sessions", domain);
  if (fs.existsSync(dir)) fs.rmSync(dir, { recursive: true, force: true });
}

test("diffFileMaps reports identical files, only-in-A, only-in-B, and content drift", () => {
  const result = diffFileMaps(
    { common_match: "h1", common_drift: "h2", only_a: "h3" },
    { common_match: "h1", common_drift: "h_DIFF", only_b: "h4" },
  );
  assert.equal(result.in_both.length, 2);
  const drift = result.in_both.find((e) => e.name === "common_drift");
  assert.equal(drift.hashes_match, false);
  assert.deepEqual(result.only_in_a, ["only_a"]);
  assert.deepEqual(result.only_in_b, ["only_b"]);
});

test("diffFileMaps tolerates null and non-object inputs", () => {
  const result = diffFileMaps(null, undefined);
  assert.deepEqual(result, { in_both: [], only_in_a: [], only_in_b: [] });
});

test("describeAttempt rejects attempt ids with unsafe characters", () => {
  assert.throws(() => describeAttempt(uniqueDomain(), "../escape"), /invalid characters/);
  assert.throws(() => describeAttempt(uniqueDomain(), "with/slash"), /invalid characters/);
});

test("describeAttempt throws when archived attempt directory is missing", () => {
  const domain = uniqueDomain();
  assert.throws(() => describeAttempt(domain, "missing-id"), /No archived verification attempt/);
});

test("describeAttempt reads manifest fields when archive exists", () => {
  const domain = uniqueDomain();
  try {
    writeManifest(domain, "attempt-001", {
      attempt_id: "attempt-001",
      archived_at: "2026-05-09T12:00:00Z",
      snapshot_hash: "abc123",
      adjudication_plan_hash: "def456",
      final_verification_hash: "ghi789",
      files: { "verification-input-snapshot.json": "h1" },
      missing_files: [],
    });
    const desc = describeAttempt(domain, "attempt-001");
    assert.equal(desc.id, "attempt-001");
    assert.equal(desc.source, "archive");
    assert.equal(desc.snapshot_hash, "abc123");
    assert.equal(desc.adjudication_plan_hash, "def456");
    assert.equal(desc.final_verification_hash, "ghi789");
    assert.equal(desc.files_count, 1);
  } finally {
    cleanupDomain(domain);
  }
});

test("diffVerificationAttempts emits matching hashes for two identical archives", () => {
  const domain = uniqueDomain();
  try {
    const manifest = {
      archived_at: "2026-05-09T00:00:00Z",
      snapshot_hash: "snap-X",
      adjudication_plan_hash: "adj-X",
      final_verification_hash: "final-X",
      files: { "verification-input-snapshot.json": "f1" },
      missing_files: [],
    };
    writeManifest(domain, "a", { ...manifest, attempt_id: "a" });
    writeManifest(domain, "b", { ...manifest, attempt_id: "b" });
    const diff = diffVerificationAttempts(domain, "a", "b");
    assert.equal(diff.matches.snapshot_hash, true);
    assert.equal(diff.matches.adjudication_plan_hash, true);
    assert.equal(diff.matches.final_verification_hash, true);
    assert.equal(diff.files.identical_count, 1);
    assert.equal(diff.files.different_count, 0);
    assert.deepEqual(diff.files.only_in_a, []);
    assert.deepEqual(diff.files.only_in_b, []);
  } finally {
    cleanupDomain(domain);
  }
});

test("diffVerificationAttempts surfaces snapshot hash mismatch and per-file divergence", () => {
  const domain = uniqueDomain();
  try {
    writeManifest(domain, "older", {
      attempt_id: "older",
      archived_at: "2026-05-09T00:00:00Z",
      snapshot_hash: "snap-OLD",
      adjudication_plan_hash: "adj-OLD",
      final_verification_hash: "final-OLD",
      files: {
        "verification-input-snapshot.json": "snap-hash-A",
        "verification-adjudication.json": "adj-hash-A",
        "verified-final.json": "final-hash-A",
      },
      missing_files: [],
    });
    writeManifest(domain, "newer", {
      attempt_id: "newer",
      archived_at: "2026-05-09T01:00:00Z",
      snapshot_hash: "snap-NEW",
      adjudication_plan_hash: "adj-NEW",
      final_verification_hash: "final-NEW",
      files: {
        "verification-input-snapshot.json": "snap-hash-A",  // identical
        "verification-adjudication.json": "adj-hash-B",     // changed
        "verified-final.json": "final-hash-B",              // changed
        "verified-brutalist.json": "brutalist-hash-only-newer",
      },
      missing_files: [],
    });
    const diff = diffVerificationAttempts(domain, "older", "newer");
    assert.equal(diff.matches.snapshot_hash, false);
    assert.equal(diff.matches.adjudication_plan_hash, false);
    assert.equal(diff.matches.final_verification_hash, false);
    assert.equal(diff.files.in_both_count, 3);
    assert.equal(diff.files.identical_count, 1);
    assert.equal(diff.files.different_count, 2);
    assert.deepEqual(diff.files.only_in_b, ["verified-brutalist.json"]);
    const driftNames = diff.files.different.map((e) => e.name).sort();
    assert.deepEqual(driftNames, ["verification-adjudication.json", "verified-final.json"]);
  } finally {
    cleanupDomain(domain);
  }
});

test("diffVerificationAttempts strips files map from per-attempt summary", () => {
  const domain = uniqueDomain();
  try {
    writeManifest(domain, "a", {
      attempt_id: "a",
      archived_at: "2026-05-09T00:00:00Z",
      snapshot_hash: "snap",
      files: { "verification-input-snapshot.json": "h" },
      missing_files: [],
    });
    writeManifest(domain, "b", {
      attempt_id: "b",
      archived_at: "2026-05-09T01:00:00Z",
      snapshot_hash: "snap",
      files: { "verification-input-snapshot.json": "h" },
      missing_files: [],
    });
    const diff = diffVerificationAttempts(domain, "a", "b");
    assert.ok(!("files" in diff.attempt_a), "files map elided from attempt_a");
    assert.ok(!("files" in diff.attempt_b), "files map elided from attempt_b");
    assert.equal(diff.attempt_a.files_count, 1);
    assert.equal(diff.attempt_b.files_count, 1);
  } finally {
    cleanupDomain(domain);
  }
});

test("diffVerificationAttempts works with current as one side", () => {
  const domain = uniqueDomain();
  try {
    writeManifest(domain, "older", {
      attempt_id: "older",
      archived_at: "2026-05-09T00:00:00Z",
      snapshot_hash: "snap-OLD",
      files: { "verification-input-snapshot.json": "hashA" },
      missing_files: [],
    });
    const diff = diffVerificationAttempts(domain, "older", "current");
    assert.equal(diff.attempt_a.source, "archive");
    assert.equal(diff.attempt_b.source, "current");
  } finally {
    cleanupDomain(domain);
  }
});
