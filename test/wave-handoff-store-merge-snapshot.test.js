"use strict";

// Y.10 (Y-P12 / defect 6) — getLatestMergedWavePartialSurfaceIds + merge
// snapshot persistence tests. Verifies that mergeWaveHandoffs writes a
// wave-N-merge-snapshot.json under <sessionDir>/wave-handoffs/ and that
// the helper returns the partial_surface_ids from the highest-numbered
// snapshot.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const {
  getLatestMergedWavePartialSurfaceIds,
  mergeWaveHandoffs,
  waveMergeSnapshotPath,
  waveHandoffsSnapshotDir,
} = require("../mcp/lib/wave-handoff-store.js");
const {
  sessionDir,
  waveAssignmentsPath,
} = require("../mcp/lib/paths.js");
const {
  writeFileAtomic,
} = require("../mcp/lib/storage.js");
const {
  loadWaveAssignments,
} = require("../mcp/lib/assignments.js");
const {
  ensureHandoffSigningKey,
  readHandoffSigningKey,
} = require("../mcp/lib/handoff-signing-key.js");
const {
  sha256Hex,
  signHandoffProvenance,
} = require("../mcp/lib/wave-handoff-contracts.js");

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const tempHome = fs.mkdtempSync(path.join(os.tmpdir(), "bob-merge-snap-"));
  process.env.HOME = tempHome;
  try {
    return fn(tempHome);
  } finally {
    if (previousHome === undefined) {
      delete process.env.HOME;
    } else {
      process.env.HOME = previousHome;
    }
    fs.rmSync(tempHome, { recursive: true, force: true });
  }
}

function seededHandoffToken(domain, waveNumber, agent) {
  return `test-handoff-token:${domain}:w${waveNumber}:${agent}`;
}

function writeAssignments(domain, waveNumber, assignments) {
  fs.mkdirSync(sessionDir(domain), { recursive: true });
  const persistedAssignments = assignments.map((assignment) => ({
    ...assignment,
    handoff_token_required: true,
    handoff_token_sha256: assignment.handoff_token_sha256 || sha256Hex(
      seededHandoffToken(domain, waveNumber, assignment.agent),
    ),
  }));
  writeFileAtomic(waveAssignmentsPath(domain, waveNumber), `${JSON.stringify({
    wave_number: waveNumber,
    handoff_tokens_required: true,
    assignments: persistedAssignments,
  }, null, 2)}\n`);
  ensureHandoffSigningKey(domain);
}

function writeHandoff(domain, wave, agent, surfaceId, fields = {}) {
  fs.mkdirSync(sessionDir(domain), { recursive: true });
  const waveNumber = Number(String(wave).replace(/^w/i, ""));
  const assignment = loadWaveAssignments(domain, waveNumber).assignmentByAgent.get(agent);
  assert.ok(assignment, `missing seeded assignment for ${agent}`);
  const payload = {
    target_domain: domain,
    wave,
    agent,
    surface_id: surfaceId,
    surface_type: null,
    surface_status: "complete",
    summary: `${agent} completed ${surfaceId}.`,
    chain_notes: [],
    blocked_harness_runs: [],
    blocked_prereqs: [],
    bypass_attempts: [],
    dead_ends: [],
    waf_blocked_endpoints: [],
    lead_surface_ids: [],
    ...fields,
  };
  const signed = signHandoffProvenance(
    payload.provenance == null ? { ...payload, provenance: "verified" } : payload,
    readHandoffSigningKey(domain),
    { assignment },
  );
  writeFileAtomic(
    path.join(sessionDir(domain), `handoff-${wave}-${agent}.json`),
    `${JSON.stringify(signed, null, 2)}\n`,
  );
}

test("getLatestMergedWavePartialSurfaceIds returns [] when no merges have happened", () => {
  withTempHome(() => {
    const domain = "merge-snap-empty.com";
    const result = getLatestMergedWavePartialSurfaceIds(domain);
    assert.deepEqual(result, []);
  });
});

test("getLatestMergedWavePartialSurfaceIds returns [] for missing snapshot directory", () => {
  withTempHome(() => {
    const domain = "merge-snap-missing.com";
    fs.mkdirSync(sessionDir(domain), { recursive: true });
    // Session dir exists but wave-handoffs/ does not.
    assert.equal(fs.existsSync(waveHandoffsSnapshotDir(domain)), false);
    assert.deepEqual(getLatestMergedWavePartialSurfaceIds(domain), []);
  });
});

test("mergeWaveHandoffs persists a snapshot containing partial_surface_ids", () => {
  withTempHome(() => {
    const domain = "merge-snap-persist.com";
    writeAssignments(domain, 1, [
      { agent: "a1", surface_id: "surface-complete-1" },
      { agent: "a2", surface_id: "surface-partial-1" },
    ]);
    writeHandoff(domain, "w1", "a1", "surface-complete-1", { surface_status: "complete" });
    writeHandoff(domain, "w1", "a2", "surface-partial-1", {
      surface_status: "partial",
    });

    const result = JSON.parse(mergeWaveHandoffs({ target_domain: domain, wave_number: 1 }));
    assert.deepEqual(result.partial_surface_ids, ["surface-partial-1"]);

    const snapshotPath = waveMergeSnapshotPath(domain, 1);
    assert.equal(fs.existsSync(snapshotPath), true);
    const snapshot = JSON.parse(fs.readFileSync(snapshotPath, "utf8"));
    assert.equal(snapshot.wave_number, 1);
    assert.deepEqual(snapshot.partial_surface_ids, ["surface-partial-1"]);
    assert.deepEqual(snapshot.completed_surface_ids, ["surface-complete-1"]);
    assert.equal(typeof snapshot.merged_at_iso, "string");
    assert.match(snapshot.merged_at_iso, /^\d{4}-\d{2}-\d{2}T/);

    assert.deepEqual(getLatestMergedWavePartialSurfaceIds(domain), ["surface-partial-1"]);
  });
});

test("getLatestMergedWavePartialSurfaceIds returns highest-numbered snapshot", () => {
  withTempHome(() => {
    const domain = "merge-snap-highest.com";
    fs.mkdirSync(waveHandoffsSnapshotDir(domain), { recursive: true });
    // Hand-write three snapshots; helper must pick the highest N.
    fs.writeFileSync(waveMergeSnapshotPath(domain, 1), JSON.stringify({
      wave_number: 1,
      merged_at_iso: "2026-06-01T00:00:00.000Z",
      partial_surface_ids: ["wave-1-partial"],
    }));
    fs.writeFileSync(waveMergeSnapshotPath(domain, 3), JSON.stringify({
      wave_number: 3,
      merged_at_iso: "2026-06-01T02:00:00.000Z",
      partial_surface_ids: ["wave-3-a", "wave-3-b"],
    }));
    fs.writeFileSync(waveMergeSnapshotPath(domain, 2), JSON.stringify({
      wave_number: 2,
      merged_at_iso: "2026-06-01T01:00:00.000Z",
      partial_surface_ids: ["wave-2-partial"],
    }));
    assert.deepEqual(getLatestMergedWavePartialSurfaceIds(domain), ["wave-3-a", "wave-3-b"]);
  });
});

test("getLatestMergedWavePartialSurfaceIds tolerates malformed snapshot JSON", () => {
  withTempHome(() => {
    const domain = "merge-snap-malformed.com";
    fs.mkdirSync(waveHandoffsSnapshotDir(domain), { recursive: true });
    fs.writeFileSync(waveMergeSnapshotPath(domain, 1), "{ bad json");
    assert.deepEqual(getLatestMergedWavePartialSurfaceIds(domain), []);
  });
});

test("getLatestMergedWavePartialSurfaceIds filters non-string entries", () => {
  withTempHome(() => {
    const domain = "merge-snap-filtered.com";
    fs.mkdirSync(waveHandoffsSnapshotDir(domain), { recursive: true });
    fs.writeFileSync(waveMergeSnapshotPath(domain, 1), JSON.stringify({
      wave_number: 1,
      partial_surface_ids: ["keep", null, "", 42, "also-keep"],
    }));
    assert.deepEqual(getLatestMergedWavePartialSurfaceIds(domain), ["keep", "also-keep"]);
  });
});

test("getLatestMergedWavePartialSurfaceIds requires target_domain string", () => {
  assert.throws(() => getLatestMergedWavePartialSurfaceIds(""), /target_domain/);
  assert.throws(() => getLatestMergedWavePartialSurfaceIds(null), /target_domain/);
});
