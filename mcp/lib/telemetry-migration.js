"use strict";

const fs = require("fs");
const path = require("path");
const {
  telemetryDir,
  telemetryToolInvocationsJsonlPath,
} = require("./paths.js");

const LEGACY_TELEMETRY_FILE_NAME = "agent-runs.jsonl";

let migrationAttempted = false;

function legacyTelemetryAgentRunsPath(env = process.env) {
  return path.join(telemetryDir(env), LEGACY_TELEMETRY_FILE_NAME);
}

function migrateLegacyTelemetryAgentRunsFile({ env = process.env, force = false } = {}) {
  if (migrationAttempted && !force) return { migrated: false, reason: "already_attempted" };
  migrationAttempted = true;

  const legacyPath = legacyTelemetryAgentRunsPath(env);
  const canonicalPath = telemetryToolInvocationsJsonlPath(env);

  if (!fs.existsSync(legacyPath)) {
    return { migrated: false, reason: "no_legacy_file", legacy_path: legacyPath, canonical_path: canonicalPath };
  }

  if (fs.existsSync(canonicalPath)) {
    return {
      migrated: false,
      reason: "canonical_already_exists",
      legacy_path: legacyPath,
      canonical_path: canonicalPath,
    };
  }

  try {
    fs.mkdirSync(path.dirname(canonicalPath), { recursive: true });
    fs.renameSync(legacyPath, canonicalPath);
    return { migrated: true, legacy_path: legacyPath, canonical_path: canonicalPath };
  } catch (error) {
    return {
      migrated: false,
      reason: "rename_failed",
      error: error && error.message ? error.message : String(error),
      legacy_path: legacyPath,
      canonical_path: canonicalPath,
    };
  }
}

function resetTelemetryMigrationStateForTests() {
  migrationAttempted = false;
}

module.exports = {
  LEGACY_TELEMETRY_FILE_NAME,
  legacyTelemetryAgentRunsPath,
  migrateLegacyTelemetryAgentRunsFile,
  resetTelemetryMigrationStateForTests,
};
