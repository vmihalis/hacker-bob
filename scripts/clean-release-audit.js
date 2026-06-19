#!/usr/bin/env node
"use strict";

const { spawnSync } = require("node:child_process");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const {
  LOCAL_INSTALL_METADATA_FILES,
  isInternalRefactorDoc,
  isInternalRefactorScratch,
} = require("./lib/package-policy.js");

const ROOT = path.join(__dirname, "..");
const KEEP = process.argv.includes("--keep");
const EXCLUDED_RELEASE_CANDIDATE_PATHS = new Set([
  ...LOCAL_INSTALL_METADATA_FILES,
]);
function run(command, args, options = {}) {
  const result = spawnSync(command, args, {
    cwd: options.cwd || ROOT,
    env: {
      ...process.env,
      ...(options.env || {}),
    },
    encoding: "utf8",
    stdio: options.stdio || ["ignore", "pipe", "pipe"],
  });
  if (result.status !== 0) {
    const output = `${result.stdout || ""}${result.stderr || ""}`.trim();
    throw new Error(`${command} ${args.join(" ")} failed with exit ${result.status}${output ? `\n${output}` : ""}`);
  }
  return result;
}

function git(args, options = {}) {
  return run("git", args, options);
}

function npm(args, options = {}) {
  return run("npm", args, {
    ...options,
    env: {
      npm_config_cache: options.npmCache,
      ...(options.env || {}),
    },
  });
}

function splitNul(output) {
  return String(output || "").split("\0").filter(Boolean);
}

function sha256(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function shouldExcludeUntracked(file) {
  if (!file || path.isAbsolute(file)) return true;
  if (EXCLUDED_RELEASE_CANDIDATE_PATHS.has(file)) return true;
  if (isInternalRefactorDoc(file)) return true;
  if (isInternalRefactorScratch(file)) return true;
  return false;
}

function materializeReleaseCandidate({ workDir, indexFile }) {
  const env = { GIT_INDEX_FILE: indexFile };
  const candidateDir = path.join(workDir, "release-candidate");
  fs.mkdirSync(candidateDir, { recursive: true });

  const head = git(["rev-parse", "HEAD"]).stdout.trim();
  const trackedChanges = git(["diff", "--name-status", "HEAD"]).stdout.trim().split(/\n/).filter(Boolean);
  git(["read-tree", "HEAD"], { env });
  git(["add", "-u", "--", "."], { env });

  const untracked = splitNul(git(["ls-files", "--others", "--exclude-standard", "-z"], { env }).stdout);
  const excludedUntracked = untracked.filter(shouldExcludeUntracked).sort();
  const blockingUntracked = untracked.filter((file) => !shouldExcludeUntracked(file)).sort();
  if (blockingUntracked.length > 0) {
    throw new Error(`untracked files block release: every net-new source must be committed or added to EXCLUDED_RELEASE_CANDIDATE_PATHS / refactor scratch policy before release: ${blockingUntracked.join(", ")}`);
  }

  const candidateTree = git(["write-tree"], { env }).stdout.trim();
  const candidateIndexManifest = git(["ls-files", "-s", "-z"], { env }).stdout;
  const candidateDiffNameStatus = git(["diff", "--cached", "--name-status", "HEAD"], { env }).stdout.trim().split(/\n/).filter(Boolean);
  git(["checkout-index", "-a", "--prefix", `${candidateDir}${path.sep}`], { env });
  return {
    candidateDir,
    head,
    trackedChanges,
    candidateTree,
    candidateManifestSha256: sha256(candidateIndexManifest),
    candidateDiffNameStatus,
    excludedUntracked,
  };
}

function parsePack(output) {
  const packs = JSON.parse(String(output || "").trim());
  if (!Array.isArray(packs) || packs.length !== 1) {
    throw new Error("npm pack --dry-run --json returned an unexpected shape");
  }
  const pack = packs[0];
  return {
    size: pack.size,
    unpackedSize: pack.unpackedSize,
    entryCount: pack.entryCount,
    shasum: pack.shasum,
    files: pack.files.map((file) => file.path).sort(),
  };
}

function countReleaseWarnings(stdout) {
  return String(stdout || "").split(/\n/).filter((line) => line.startsWith("WARN ")).length;
}

function gitArchiveSha256(tree) {
  const result = spawnSync("git", ["archive", "--format=tar", tree], {
    cwd: ROOT,
    env: process.env,
    encoding: "buffer",
    maxBuffer: 64 * 1024 * 1024,
    stdio: ["ignore", "pipe", "pipe"],
  });
  if (result.status !== 0) {
    throw new Error(`git archive --format=tar ${tree} failed with exit ${result.status}\n${String(result.stderr || "").trim()}`);
  }
  return sha256(result.stdout);
}

function forbiddenPackedFiles(files) {
  return files.filter((file) =>
    EXCLUDED_RELEASE_CANDIDATE_PATHS.has(file) ||
    LOCAL_INSTALL_METADATA_FILES.has(file) ||
    isInternalRefactorScratch(file) ||
    isInternalRefactorDoc(file)
  );
}

function main() {
  const workDir = fs.mkdtempSync(path.join(os.tmpdir(), "bob-clean-release-"));
  const indexFile = path.join(workDir, "index");
  const npmCache = path.join(workDir, "npm-cache");
  try {
    const candidate = materializeReleaseCandidate({ workDir, indexFile });

    const packageResult = npm(["run", "test:package"], {
      cwd: candidate.candidateDir,
      npmCache,
      stdio: ["ignore", "pipe", "pipe"],
    });
    const releaseResult = npm(["run", "release:check"], {
      cwd: candidate.candidateDir,
      npmCache,
      stdio: ["ignore", "pipe", "pipe"],
    });
    const packResult = npm(["pack", "--dry-run", "--json"], {
      cwd: candidate.candidateDir,
      npmCache,
      stdio: ["ignore", "pipe", "pipe"],
    });
    const pack = parsePack(packResult.stdout);
    const forbiddenPacked = forbiddenPackedFiles(pack.files);
    if (forbiddenPacked.length > 0) {
      throw new Error(`release candidate packed internal files: ${forbiddenPacked.join(", ")}`);
    }

    const summary = {
      release_candidate: candidate.candidateDir,
      head: candidate.head,
      candidate_tree: candidate.candidateTree,
      candidate_manifest_sha256: candidate.candidateManifestSha256,
      candidate_archive_sha256: gitArchiveSha256(candidate.candidateTree),
      tracked_changes: candidate.trackedChanges,
      candidate_diff_name_status: candidate.candidateDiffNameStatus,
      excluded_untracked: candidate.excludedUntracked,
      gates: {
        "npm run test:package": packageResult.status,
        "npm run release:check": releaseResult.status,
        "npm pack --dry-run --json": packResult.status,
      },
      release_check_warnings: countReleaseWarnings(releaseResult.stdout),
      pack: {
        size: pack.size,
        unpackedSize: pack.unpackedSize,
        entryCount: pack.entryCount,
        shasum: pack.shasum,
      },
      forbidden_packed: forbiddenPacked,
    };
    console.log(JSON.stringify(summary, null, 2));
  } finally {
    if (!KEEP) {
      fs.rmSync(workDir, { recursive: true, force: true });
    }
  }
}

try {
  main();
} catch (error) {
  console.error(error.message || String(error));
  process.exit(1);
}
