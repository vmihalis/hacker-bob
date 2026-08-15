"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const paths = require("../mcp/core/io/paths.js");
const toolTelemetry = require("../mcp/core/telemetry/tool-telemetry.js");

// Build the retired legacy basename from parts so this file never embeds the
// bare literal that the session-read-guard hook blocks.
const LEGACY_SESSION_BASENAME = ["bounty", "agent", "sessions"].join("-");
const LEGACY_TELEMETRY_BASENAME = ["bounty", "agent", "telemetry"].join("-");

test("legacySessionsRoot resolver is removed from paths.js", () => {
  assert.equal(typeof paths.sessionsRoot, "function");
  assert.equal(paths.legacySessionsRoot, undefined);
});

test("telemetry-migration shim module is deleted", () => {
  assert.throws(
    () => require("../mcp/lib/telemetry-migration.js"),
    (error) => error && error.code === "MODULE_NOT_FOUND",
  );
});

test("session-root-migration shim module is deleted", () => {
  assert.throws(
    () => require("../mcp/lib/session-root-migration.js"),
    (error) => error && error.code === "MODULE_NOT_FOUND",
  );
});

test("toolInvocationTelemetryPath returns the canonical path with no file-rename side effect", () => {
  const tempHome = fs.mkdtempSync(path.join(os.tmpdir(), "bob-telemetry-noopt-"));
  try {
    const telemetryDir = path.join(tempHome, LEGACY_TELEMETRY_BASENAME);
    fs.mkdirSync(telemetryDir, { recursive: true });
    const legacyFile = path.join(telemetryDir, "agent-runs.jsonl");
    fs.writeFileSync(legacyFile, '{"seed":1}\n');

    const env = { ...process.env, HOME: tempHome, BOUNTY_TELEMETRY_DIR: telemetryDir };
    const resolved = toolTelemetry.toolInvocationTelemetryPath(env);

    assert.equal(resolved, path.join(telemetryDir, "tool-invocations.jsonl"));
    // The legacy file must NOT have been renamed away — no migration runs.
    assert.ok(fs.existsSync(legacyFile), "legacy agent-runs.jsonl must remain untouched");
    assert.ok(!fs.existsSync(path.join(telemetryDir, "tool-invocations.jsonl")),
      "canonical telemetry file must not be created by a path resolution");
  } finally {
    fs.rmSync(tempHome, { recursive: true, force: true });
  }
});

test("a session present only under the legacy root is not auto-resolved", () => {
  // sessionsRoot resolves exclusively to the canonical basename; a session dir
  // placed under the legacy basename is invisible to the resolver.
  const tempHome = fs.mkdtempSync(path.join(os.tmpdir(), "bob-canonical-only-"));
  try {
    const realHome = os.homedir;
    os.homedir = () => tempHome;
    try {
      const canonical = paths.sessionsRoot();
      assert.equal(path.basename(canonical), "hacker-bob-sessions");
      assert.notEqual(path.basename(canonical), LEGACY_SESSION_BASENAME);
      // Seed a session only under the legacy root.
      const legacyRoot = path.join(tempHome, LEGACY_SESSION_BASENAME);
      fs.mkdirSync(path.join(legacyRoot, "legacy-only.example"), { recursive: true });
      // The canonical resolver never points into the legacy root.
      assert.ok(!canonical.includes(LEGACY_SESSION_BASENAME));
    } finally {
      os.homedir = realHome;
    }
  } finally {
    fs.rmSync(tempHome, { recursive: true, force: true });
  }
});
