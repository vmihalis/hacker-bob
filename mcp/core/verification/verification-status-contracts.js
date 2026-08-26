"use strict";

const fs = require("fs");
const path = require("path");
const {
  verificationAttemptsDir,
} = require("../io/paths.js");
const {
  readJsonFile,
} = require("../io/storage.js");

function capString(value, max) {
  if (typeof value !== "string") return null;
  return value.length > max ? value.slice(0, max) : value;
}

function readArchiveManifest(filePath) {
  try {
    return readJsonFile(filePath, { label: path.basename(filePath) });
  } catch {
    return null;
  }
}

function listArchivedVerificationAttempts(targetDomain) {
  const dir = verificationAttemptsDir(targetDomain);
  if (!fs.existsSync(dir)) return [];
  return fs.readdirSync(dir, { withFileTypes: true })
    .filter((entry) => entry.isDirectory() && /^attempt-/.test(entry.name))
    .map((entry) => {
      const archiveDir = path.join(dir, entry.name);
      const manifestPath = path.join(archiveDir, "manifest.json");
      const manifest = readArchiveManifest(manifestPath);
      return {
        attempt_id: manifest && manifest.attempt_id ? capString(manifest.attempt_id, 120) : entry.name.replace(/^attempt-/, ""),
        archive_dir: archiveDir,
        manifest_path: fs.existsSync(manifestPath) ? manifestPath : null,
        archived_at: manifest && manifest.archived_at ? capString(manifest.archived_at, 80) : null,
        snapshot_hash: manifest && manifest.snapshot_hash ? capString(manifest.snapshot_hash, 128) : null,
        adjudication_plan_hash: manifest && manifest.adjudication_plan_hash ? capString(manifest.adjudication_plan_hash, 128) : null,
        final_verification_hash: manifest && manifest.final_verification_hash ? capString(manifest.final_verification_hash, 128) : null,
        files_count: manifest && manifest.files ? Object.keys(manifest.files).length : 0,
        missing_files_count: manifest && Array.isArray(manifest.missing_files) ? manifest.missing_files.length : 0,
      };
    })
    .sort((a, b) => String(b.archived_at || "").localeCompare(String(a.archived_at || "")) || a.attempt_id.localeCompare(b.attempt_id));
}

function summarizeVerificationRoundArtifact({
  targetDomain,
  round,
  exists = false,
  document = null,
  state = null,
  artifactHash = null,
  mtime = null,
  error = null,
} = {}) {
  const summary = {
    round,
    exists: exists === true,
    valid: false,
    current: false,
    stale: false,
    blocker_reason: null,
    results_count: 0,
    reportable_count: 0,
    confirmed_count: 0,
    schema_version: null,
    verification_attempt_id: null,
    verification_snapshot_hash: null,
    adjudication_plan_hash: null,
    final_verification_hash: null,
    final_reportable_ids: [],
    artifact_hash: artifactHash,
    mtime,
    error,
  };

  if (error) {
    summary.stale = true;
    summary.blocker_reason = error;
    return summary;
  }
  if (!summary.exists) return summary;

  if (document == null || typeof document !== "object" || Array.isArray(document)) {
    summary.stale = true;
    summary.error = "verification round JSON must be an object";
    summary.blocker_reason = summary.error;
    return summary;
  }

  summary.valid = document.target_domain === targetDomain && document.round === round && Array.isArray(document.results);
  summary.schema_version = Number.isInteger(document.version) ? document.version : null;
  summary.verification_attempt_id = capString(document.verification_attempt_id, 120);
  summary.verification_snapshot_hash = capString(document.verification_snapshot_hash, 128);
  summary.adjudication_plan_hash = capString(document.adjudication_plan_hash, 128);
  summary.final_verification_hash = capString(document.final_verification_hash, 128);

  if (Array.isArray(document.results)) {
    summary.results_count = document.results.length;
    summary.reportable_count = document.results.filter((result) => result && result.reportable === true).length;
    summary.confirmed_count = document.results.filter((result) => result && result.disposition === "confirmed").length;
    if (round === "final") {
      summary.final_reportable_ids = document.results
        .filter((result) => result && result.reportable === true && typeof result.finding_id === "string")
        .map((result) => result.finding_id);
    }
  }

  if (!summary.valid) {
    summary.stale = true;
    summary.error = `${round} verification artifact metadata mismatch`;
    summary.blocker_reason = summary.error;
    return summary;
  }

  if (summary.schema_version === 1) {
    if (state && state.verification_schema_version === 2) {
      summary.stale = true;
      summary.blocker_reason = "v1 artifact in v2 context";
    } else {
      summary.current = true;
    }
    return summary;
  }

  if (summary.schema_version === 2) {
    if (!state || state.verification_schema_version !== 2) {
      summary.stale = true;
      summary.blocker_reason = "no current v2 verification attempt is active";
    } else if (document.verification_attempt_id !== state.verification_attempt_id) {
      summary.stale = true;
      summary.blocker_reason = "attempt mismatch";
    } else if (document.verification_snapshot_hash !== state.verification_snapshot_hash) {
      summary.stale = true;
      summary.blocker_reason = "snapshot mismatch";
    } else {
      summary.current = true;
    }
  }

  return summary;
}

function summarizeVerificationRoundStatus({
  targetDomain,
  round,
  exists = false,
  document = null,
  state = null,
  artifactHash = null,
  mtime = null,
  error = null,
  schemaVersionForContext = null,
  decorateVerificationRoundRead = null,
} = {}) {
  const summary = summarizeVerificationRoundArtifact({
    targetDomain,
    round,
    exists,
    document,
    state,
    artifactHash,
    mtime,
    error,
  });
  if (!summary.exists || summary.error || !summary.valid) return summary;

  if (summary.schema_version !== 2) {
    const contextVersion = typeof schemaVersionForContext === "function"
      ? schemaVersionForContext(targetDomain)
      : (state && state.verification_schema_version === 2 ? 2 : 1);
    summary.current = contextVersion === 1;
    summary.stale = !summary.current;
    summary.blocker_reason = summary.stale ? "v1 artifact in v2 context" : null;
    return summary;
  }

  if (typeof decorateVerificationRoundRead !== "function") return summary;
  const decorated = decorateVerificationRoundRead(targetDomain, document);
  summary.current = decorated.current === true;
  summary.stale = decorated.stale === true;
  summary.blocker_reason = decorated.blocker_reason || null;
  return summary;
}

module.exports = {
  capString,
  listArchivedVerificationAttempts,
  summarizeVerificationRoundArtifact,
  summarizeVerificationRoundStatus,
};
