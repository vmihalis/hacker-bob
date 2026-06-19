"use strict";

// Plane X Cycle X.7 — body resolver for the `repo_command_run` X-D12 prefix.
//
// Reads from `repo-runs/<run_id>.stdout` + `repo-runs/<run_id>.stderr`
// (O.4) and returns the concatenated capture. Returns null when no
// stdout file exists for the run_id (which means either the dry-run
// path did not generate captures, or the run_id is unknown).
//
// The body shape is a JSON envelope so the X.6 verifier + the X.8
// brief renderer can address stdout / stderr separately through a
// JSONPath selector like `$.stdout` or `$.stderr`. content_hash binds
// both streams together so a verifier comparing against the JSONL
// row's `stdout_hash` + `stderr_hash` can confirm both halves at once.

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const {
  repoRunsDir,
} = require("../paths.js");

function sha256Hex(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function readUtf8OrNull(filePath) {
  if (!fs.existsSync(filePath)) return null;
  try {
    return fs.readFileSync(filePath, "utf8");
  } catch {
    return null;
  }
}

function resolve(targetDomain, refId) {
  const dir = repoRunsDir(targetDomain);
  const stdoutPath = path.join(dir, `${refId}.stdout`);
  const stderrPath = path.join(dir, `${refId}.stderr`);
  const stdout = readUtf8OrNull(stdoutPath);
  const stderr = readUtf8OrNull(stderrPath);
  if (stdout == null && stderr == null) return null;
  const envelope = {
    run_id: refId,
    stdout: stdout == null ? "" : stdout,
    stderr: stderr == null ? "" : stderr,
  };
  const body = JSON.stringify(envelope, null, 2);
  return {
    body,
    content_hash: sha256Hex(body),
    body_size_bytes: Buffer.byteLength(body, "utf8"),
  };
}

module.exports = resolve;
