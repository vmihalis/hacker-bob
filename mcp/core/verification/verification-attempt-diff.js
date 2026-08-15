"use strict";

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const {
  assertSafeDomain,
  verificationAdjudicationPath,
  verificationAttemptsDir,
  verificationRoundPaths,
  verificationSnapshotPath,
} = require("../io/paths.js");
const { readJsonFile } = require("../io/storage.js");
const { VERIFICATION_ROUND_VALUES } = require("../../lib/constants.js");

const ATTEMPT_ID_PATTERN = /^[A-Za-z0-9._-]+$/;

function safeReadJson(filePath) {
  try {
    if (!fs.existsSync(filePath)) return null;
    return readJsonFile(filePath, { label: path.basename(filePath) });
  } catch (_err) {
    return null;
  }
}

function hashFile(filePath) {
  if (!fs.existsSync(filePath)) return null;
  return crypto.createHash("sha256").update(fs.readFileSync(filePath)).digest("hex");
}

function liveFilePaths(domain) {
  const paths = [];
  paths.push(["verification-input-snapshot.json", verificationSnapshotPath(domain)]);
  paths.push(["verification-adjudication.json", verificationAdjudicationPath(domain)]);
  for (const round of VERIFICATION_ROUND_VALUES) {
    const rp = verificationRoundPaths(domain, round);
    paths.push([path.basename(rp.json), rp.json]);
  }
  return paths;
}

function describeCurrentAttempt(domain) {
  const snapshot = safeReadJson(verificationSnapshotPath(domain));
  const adjudication = safeReadJson(verificationAdjudicationPath(domain));
  const filesMap = {};
  let presentCount = 0;
  for (const [name, fullPath] of liveFilePaths(domain)) {
    if (fs.existsSync(fullPath)) {
      filesMap[name] = hashFile(fullPath);
      presentCount += 1;
    }
  }
  return {
    id: snapshot && typeof snapshot.verification_attempt_id === "string"
      ? snapshot.verification_attempt_id
      : "current",
    source: "current",
    archived_at: null,
    snapshot_hash: snapshot && typeof snapshot.snapshot_hash === "string"
      ? snapshot.snapshot_hash
      : null,
    adjudication_plan_hash: adjudication && typeof adjudication.adjudication_plan_hash === "string"
      ? adjudication.adjudication_plan_hash
      : null,
    final_verification_hash: null,
    files: filesMap,
    files_count: presentCount,
    missing_files: [],
  };
}

function archiveDirFor(domain, attemptId) {
  if (typeof attemptId !== "string" || !ATTEMPT_ID_PATTERN.test(attemptId)) {
    throw new Error(`attempt_id contains invalid characters: ${attemptId}`);
  }
  return path.join(verificationAttemptsDir(domain), `attempt-${attemptId}`);
}

function describeArchivedAttempt(domain, attemptId) {
  const archiveDir = archiveDirFor(domain, attemptId);
  if (!fs.existsSync(archiveDir)) {
    throw new Error(`No archived verification attempt found: ${attemptId}`);
  }
  const manifestPath = path.join(archiveDir, "manifest.json");
  const manifest = safeReadJson(manifestPath);
  if (!manifest) {
    throw new Error(`Archived attempt manifest unreadable: ${manifestPath}`);
  }
  const files = manifest.files && typeof manifest.files === "object" ? manifest.files : {};
  return {
    id: typeof manifest.attempt_id === "string" ? manifest.attempt_id : attemptId,
    source: "archive",
    archive_dir: archiveDir,
    archived_at: typeof manifest.archived_at === "string" ? manifest.archived_at : null,
    snapshot_hash: typeof manifest.snapshot_hash === "string" ? manifest.snapshot_hash : null,
    adjudication_plan_hash: typeof manifest.adjudication_plan_hash === "string"
      ? manifest.adjudication_plan_hash
      : null,
    final_verification_hash: typeof manifest.final_verification_hash === "string"
      ? manifest.final_verification_hash
      : null,
    files,
    files_count: Object.keys(files).length,
    missing_files: Array.isArray(manifest.missing_files) ? manifest.missing_files : [],
  };
}

function describeAttempt(domain, attemptId) {
  if (attemptId === "current") return describeCurrentAttempt(domain);
  return describeArchivedAttempt(domain, attemptId);
}

function diffFileMaps(filesA, filesB) {
  const safeA = filesA && typeof filesA === "object" ? filesA : {};
  const safeB = filesB && typeof filesB === "object" ? filesB : {};
  const namesA = Object.keys(safeA);
  const namesB = Object.keys(safeB);
  const allNames = Array.from(new Set([...namesA, ...namesB])).sort();
  const inBoth = [];
  const onlyInA = [];
  const onlyInB = [];
  for (const name of allNames) {
    const hashA = typeof safeA[name] === "string" ? safeA[name] : null;
    const hashB = typeof safeB[name] === "string" ? safeB[name] : null;
    if (hashA && hashB) {
      inBoth.push({ name, hash_a: hashA, hash_b: hashB, hashes_match: hashA === hashB });
      continue;
    }
    if (hashA && !hashB) onlyInA.push(name);
    else if (!hashA && hashB) onlyInB.push(name);
  }
  return { in_both: inBoth, only_in_a: onlyInA, only_in_b: onlyInB };
}

function stripFiles(attempt) {
  const out = { ...attempt };
  delete out.files;
  return out;
}

function diffVerificationAttempts(domain, attemptA, attemptB) {
  const safeDomain = assertSafeDomain(domain);
  const a = describeAttempt(safeDomain, attemptA);
  const b = describeAttempt(safeDomain, attemptB);
  const fileDiff = diffFileMaps(a.files, b.files);
  const identicalCount = fileDiff.in_both.filter((entry) => entry.hashes_match).length;
  const differentEntries = fileDiff.in_both.filter((entry) => !entry.hashes_match);
  return {
    schema_version: 1,
    target_domain: safeDomain,
    attempt_a: stripFiles(a),
    attempt_b: stripFiles(b),
    matches: {
      snapshot_hash: a.snapshot_hash != null && a.snapshot_hash === b.snapshot_hash,
      adjudication_plan_hash: a.adjudication_plan_hash != null
        && a.adjudication_plan_hash === b.adjudication_plan_hash,
      final_verification_hash: a.final_verification_hash != null
        && a.final_verification_hash === b.final_verification_hash,
    },
    files: {
      in_both_count: fileDiff.in_both.length,
      identical_count: identicalCount,
      different_count: differentEntries.length,
      only_in_a: fileDiff.only_in_a,
      only_in_b: fileDiff.only_in_b,
      different: differentEntries.map((entry) => ({
        name: entry.name,
        hash_a: entry.hash_a.slice(0, 16),
        hash_b: entry.hash_b.slice(0, 16),
      })),
    },
  };
}

module.exports = {
  diffVerificationAttempts,
  describeAttempt,
  diffFileMaps,
};
