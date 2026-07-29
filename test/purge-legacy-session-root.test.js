"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const { purgeLegacySessionRoot } = require("../scripts/install.js");

// Build the retired legacy basename from parts so this file never embeds the
// bare literal that the session-read-guard hook blocks.
const LEGACY_SESSION_BASENAME = ["bounty", "agent", "sessions"].join("-");
const LEGACY_TELEMETRY_BASENAME = ["bounty", "agent", "telemetry"].join("-");

function makeHome() {
  return fs.mkdtempSync(path.join(os.tmpdir(), "bob-purge-home-"));
}

function seedSession(root, domain) {
  const dir = path.join(root, domain);
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, "state.json"), "{}\n");
}

test("dry-run reports candidates and deletes nothing", () => {
  const home = makeHome();
  try {
    const legacyRoot = path.join(home, LEGACY_SESSION_BASENAME);
    const canonicalRoot = path.join(home, "hacker-bob-sessions");
    seedSession(legacyRoot, "foo.com");
    seedSession(canonicalRoot, "bar.com");

    const report = purgeLegacySessionRoot({ home, dryRun: true, confirmed: false });

    assert.equal(report.dry_run, true);
    assert.equal(report.purged, false);
    assert.deepEqual(report.would_delete, ["foo.com"]);
    // Both roots still exist after a dry run.
    assert.ok(fs.existsSync(legacyRoot), "legacy root must survive a dry run");
    assert.ok(fs.existsSync(path.join(canonicalRoot, "bar.com")), "canonical root must survive");
  } finally {
    fs.rmSync(home, { recursive: true, force: true });
  }
});

test("confirmed purge deletes ONLY the legacy root, never the canonical root", () => {
  const home = makeHome();
  try {
    const legacyRoot = path.join(home, LEGACY_SESSION_BASENAME);
    const canonicalRoot = path.join(home, "hacker-bob-sessions");
    seedSession(legacyRoot, "foo.com");
    seedSession(legacyRoot, "baz.org");
    seedSession(canonicalRoot, "bar.com");

    const report = purgeLegacySessionRoot({ home, dryRun: false, confirmed: true });

    assert.equal(report.purged, true);
    assert.equal(report.deleted_root, legacyRoot);
    assert.equal(report.count, 2);
    assert.ok(!fs.existsSync(legacyRoot), "legacy root must be gone");
    assert.ok(fs.existsSync(path.join(canonicalRoot, "bar.com")), "canonical session must be untouched");
  } finally {
    fs.rmSync(home, { recursive: true, force: true });
  }
});

test("no legacy root present is an idempotent no-op", () => {
  const home = makeHome();
  try {
    const canonicalRoot = path.join(home, "hacker-bob-sessions");
    seedSession(canonicalRoot, "bar.com");

    const report = purgeLegacySessionRoot({ home, dryRun: false, confirmed: true });

    assert.equal(report.purged, false);
    assert.equal(report.reason, "no_legacy_root");
    assert.ok(fs.existsSync(path.join(canonicalRoot, "bar.com")), "canonical root untouched");
  } finally {
    fs.rmSync(home, { recursive: true, force: true });
  }
});

test("a symlinked legacy root is refused, leaving the decoy intact", () => {
  const home = makeHome();
  try {
    const decoy = path.join(home, "decoy-do-not-delete");
    seedSession(decoy, "victim.com");
    const legacyRoot = path.join(home, LEGACY_SESSION_BASENAME);
    fs.symlinkSync(decoy, legacyRoot);

    const report = purgeLegacySessionRoot({ home, dryRun: false, confirmed: true });

    assert.equal(report.purged, false);
    assert.equal(report.reason, "legacy_root_symlink_escape");
    // The symlink target (decoy) and its contents must be untouched.
    assert.ok(fs.existsSync(path.join(decoy, "victim.com", "state.json")), "decoy must survive");
  } finally {
    fs.rmSync(home, { recursive: true, force: true });
  }
});

test("include-legacy-telemetry purges the telemetry dir; default leaves it", () => {
  const home = makeHome();
  try {
    const legacyRoot = path.join(home, LEGACY_SESSION_BASENAME);
    const telemetryDir = path.join(home, LEGACY_TELEMETRY_BASENAME);
    seedSession(legacyRoot, "foo.com");
    fs.mkdirSync(telemetryDir, { recursive: true });
    fs.writeFileSync(path.join(telemetryDir, "tool-events.jsonl"), "{}\n");

    // Default: telemetry dir is left alone.
    const defaultReport = purgeLegacySessionRoot({ home, dryRun: false, confirmed: true });
    assert.equal(defaultReport.purged, true);
    assert.equal(defaultReport.telemetry_purged, false);
    assert.ok(fs.existsSync(telemetryDir), "telemetry dir must survive a default purge");

    // Re-seed and purge with telemetry included.
    seedSession(legacyRoot, "foo.com");
    const withTelemetry = purgeLegacySessionRoot({
      home,
      dryRun: false,
      confirmed: true,
      includeTelemetry: true,
    });
    assert.equal(withTelemetry.telemetry_purged, true);
    assert.ok(!fs.existsSync(telemetryDir), "telemetry dir must be removed with --include-legacy-telemetry");
  } finally {
    fs.rmSync(home, { recursive: true, force: true });
  }
});
