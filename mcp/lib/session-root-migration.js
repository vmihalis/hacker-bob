"use strict";

const fs = require("fs");
const os = require("os");
const path = require("path");

// Compute roots inline rather than importing from `paths.js` to keep the
// migration shim free of a require cycle. The canonical root must match the
// value returned by `paths.sessionsRoot()`; if those literals drift, the
// `session-root-migration roots stay aligned with paths.js` invariant in the
// session-state-store test suite will fail loudly.
function sessionsRoot() {
  return path.join(os.homedir(), "hacker-bob-sessions");
}

function legacySessionsRoot() {
  return path.join(os.homedir(), "bounty-agent-sessions");
}

// Cycle P.2 of the frontier-topology realization hypergraph migrates the
// canonical session root from `~/bounty-agent-sessions` to
// `~/hacker-bob-sessions`. Per Risk R6 (session-root migration data loss),
// this migration is **copy-then-preserve**, never a destructive move:
//
//   - The legacy directory `~/bounty-agent-sessions/` stays on disk after
//     the copy so an operator can roll back or compare runs.
//   - A domain directory is copied only when the canonical location does
//     NOT already contain a session for that domain — never overwrite a
//     live canonical session with a stale legacy one.
//   - The shim is idempotent: re-calling it after a successful pass is a
//     no-op, and the per-process cache short-circuits repeated calls.
//   - Removal of the legacy root is reserved for v2.1.0 behind an explicit
//     `--purge-legacy-session-root` flag and is intentionally NOT performed
//     here.

let cachedResult = null;

function copyDirectoryRecursive(sourceDir, destinationDir) {
  fs.mkdirSync(destinationDir, { recursive: true });
  const entries = fs.readdirSync(sourceDir, { withFileTypes: true });
  for (const entry of entries) {
    const sourceEntry = path.join(sourceDir, entry.name);
    const destinationEntry = path.join(destinationDir, entry.name);
    if (entry.isDirectory()) {
      copyDirectoryRecursive(sourceEntry, destinationEntry);
      continue;
    }
    if (entry.isSymbolicLink()) {
      const linkTarget = fs.readlinkSync(sourceEntry);
      try {
        fs.symlinkSync(linkTarget, destinationEntry);
      } catch (error) {
        if (error && error.code !== "EEXIST") throw error;
      }
      continue;
    }
    if (entry.isFile()) {
      fs.copyFileSync(sourceEntry, destinationEntry);
    }
  }
}

function isReadableDirectory(candidatePath) {
  try {
    return fs.statSync(candidatePath).isDirectory();
  } catch (error) {
    if (error && error.code === "ENOENT") return false;
    throw error;
  }
}

function migrateLegacySessionRoot({ force = false } = {}) {
  if (!force && cachedResult) {
    return cachedResult;
  }

  const legacyRoot = legacySessionsRoot();
  const canonicalRoot = sessionsRoot();

  const result = {
    legacy_root: legacyRoot,
    canonical_root: canonicalRoot,
    legacy_present: false,
    copied_domains: [],
    skipped_existing_domains: [],
    preserved_legacy: true,
  };

  if (!isReadableDirectory(legacyRoot)) {
    cachedResult = result;
    return result;
  }
  result.legacy_present = true;

  let legacyEntries;
  try {
    legacyEntries = fs.readdirSync(legacyRoot, { withFileTypes: true });
  } catch (error) {
    if (error && error.code === "ENOENT") {
      cachedResult = result;
      return result;
    }
    throw error;
  }

  for (const entry of legacyEntries) {
    if (!entry.isDirectory()) continue;
    if (entry.name.startsWith(".")) continue;

    const legacyDomainDir = path.join(legacyRoot, entry.name);
    const canonicalDomainDir = path.join(canonicalRoot, entry.name);

    if (fs.existsSync(canonicalDomainDir)) {
      // Canonical wins: never overwrite a live session with stale legacy data.
      result.skipped_existing_domains.push(entry.name);
      continue;
    }

    copyDirectoryRecursive(legacyDomainDir, canonicalDomainDir);
    result.copied_domains.push(entry.name);
  }

  // Legacy root is intentionally preserved. The destructive purge is gated
  // behind the v2.1.0 `--purge-legacy-session-root` flag.
  cachedResult = result;
  return result;
}

function resetMigrationCacheForTests() {
  cachedResult = null;
}

module.exports = {
  migrateLegacySessionRoot,
  resetMigrationCacheForTests,
};
