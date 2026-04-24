"use strict";

const os = require("os");
const path = require("path");
const {
  SESSION_LOCK_NAME,
  STATIC_ARTIFACT_ID_RE,
  VERIFICATION_ROUND_FILE_MAP,
  VERIFICATION_ROUND_VALUES,
} = require("./constants.js");
const {
  assertEnumValue,
  assertNonEmptyString,
} = require("./validation.js");

function assertSafeDomain(domain) {
  const trimmed = assertNonEmptyString(domain, "target_domain");
  if (/[\/\\]/.test(trimmed) || /(?:^|\.)\.\.(?:\.|$)/.test(trimmed)) {
    throw new Error(`target_domain contains invalid path characters: ${trimmed}`);
  }
  return trimmed;
}

function sessionDir(domain) {
  const safe = assertSafeDomain(domain);
  return path.join(os.homedir(), "bounty-agent-sessions", safe);
}

function statePath(domain) {
  return path.join(sessionDir(domain), "state.json");
}

function attackSurfacePath(domain) {
  return path.join(sessionDir(domain), "attack_surface.json");
}

function sessionLockPath(domain) {
  return path.join(sessionDir(domain), SESSION_LOCK_NAME);
}

function waveAssignmentsPath(domain, waveNumber) {
  return path.join(sessionDir(domain), `wave-${waveNumber}-assignments.json`);
}

function scopeWarningsPath(domain) {
  return path.join(sessionDir(domain), "scope-warnings.log");
}

function findingsJsonlPath(domain) {
  return path.join(sessionDir(domain), "findings.jsonl");
}

function findingsMarkdownPath(domain) {
  return path.join(sessionDir(domain), "findings.md");
}

function coverageJsonlPath(domain) {
  return path.join(sessionDir(domain), "coverage.jsonl");
}

function httpAuditJsonlPath(domain) {
  return path.join(sessionDir(domain), "http-audit.jsonl");
}

function trafficJsonlPath(domain) {
  return path.join(sessionDir(domain), "traffic.jsonl");
}

function publicIntelPath(domain) {
  return path.join(sessionDir(domain), "public-intel.json");
}

function assertStaticArtifactId(artifactId) {
  const normalized = assertNonEmptyString(artifactId, "artifact_id");
  if (!STATIC_ARTIFACT_ID_RE.test(normalized)) {
    throw new Error("artifact_id must match SA-N");
  }
  return normalized;
}

function staticArtifactImportDir(domain) {
  return path.join(sessionDir(domain), "static-imports");
}

function staticArtifactPath(domain, artifactId) {
  return path.join(staticArtifactImportDir(domain), `${assertStaticArtifactId(artifactId)}.txt`);
}

function staticArtifactsJsonlPath(domain) {
  return path.join(sessionDir(domain), "static-artifacts.jsonl");
}

function staticScanResultsJsonlPath(domain) {
  return path.join(sessionDir(domain), "static-scan-results.jsonl");
}

function verificationRoundPaths(domain, round) {
  const normalizedRound = assertEnumValue(round, VERIFICATION_ROUND_VALUES, "round");
  const fileNames = VERIFICATION_ROUND_FILE_MAP[normalizedRound];
  const dir = sessionDir(domain);
  return {
    round: normalizedRound,
    json: path.join(dir, fileNames.json),
    markdown: path.join(dir, fileNames.markdown),
  };
}

function gradeArtifactPaths(domain) {
  const dir = sessionDir(domain);
  return {
    json: path.join(dir, "grade.json"),
    markdown: path.join(dir, "grade.md"),
  };
}

module.exports = {
  assertSafeDomain,
  assertStaticArtifactId,
  attackSurfacePath,
  coverageJsonlPath,
  findingsJsonlPath,
  findingsMarkdownPath,
  gradeArtifactPaths,
  httpAuditJsonlPath,
  publicIntelPath,
  scopeWarningsPath,
  sessionDir,
  sessionLockPath,
  statePath,
  staticArtifactImportDir,
  staticArtifactPath,
  staticArtifactsJsonlPath,
  staticScanResultsJsonlPath,
  trafficJsonlPath,
  verificationRoundPaths,
  waveAssignmentsPath,
};
