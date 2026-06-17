"use strict";

const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const {
  ERROR_CODES,
  ToolError,
} = require("./envelope.js");
const {
  readOffensiveRunRecords,
} = require("./claims.js");
const {
  signOffensiveRunRow,
} = require("./offensive-row-mac.js");
const {
  readHandoffSigningKey,
} = require("./handoff-signing-key.js");
const {
  offensiveRunsDir,
  offensiveRunsJsonlPath,
  sessionsRoot,
  assertSafeDomain,
} = require("./paths.js");
const {
  canonicalJson,
} = require("./verification-contracts.js");

// run_id is a single clean [A-Za-z0-9-] segment so sha256OffensiveCaptureSecure
// (claim-freeze.js) accepts it as a direct child leaf of offensive-runs/.
function newRunId(prefix) {
  return `${prefix}-${crypto.randomUUID()}`;
}

function commandHashOf(method, canonicalTarget, identityTag) {
  return crypto
    .createHash("sha256")
    .update(canonicalJson({ method, canonical_target: canonicalTarget, identity_tag: identityTag }))
    .digest("hex");
}

function sha256OfFileFd(realLeaf) {
  const noFollow = fs.constants.O_NOFOLLOW || 0;
  if (!noFollow) {
    const lst = fs.lstatSync(realLeaf);
    if (lst.isSymbolicLink()) {
      throw new ToolError(ERROR_CODES.STATE_CONFLICT, `offensive capture must not be a symlink: ${realLeaf}`);
    }
  }
  let fd = null;
  try {
    fd = fs.openSync(realLeaf, fs.constants.O_RDONLY | noFollow);
    const stats = fs.fstatSync(fd);
    if (!stats.isFile()) {
      throw new ToolError(ERROR_CODES.STATE_CONFLICT, `offensive capture must be a regular file: ${realLeaf}`);
    }
    if (stats.nlink !== 1) {
      throw new ToolError(ERROR_CODES.STATE_CONFLICT, `offensive capture must not be hard-linked: ${realLeaf}`);
    }
    return crypto.createHash("sha256").update(fs.readFileSync(fd)).digest("hex");
  } finally {
    if (fd != null) {
      try { fs.closeSync(fd); } catch {}
    }
  }
}

// Securely realpath-resolve the capture dir the way readOffensiveRunRecords /
// sha256OffensiveCaptureSecure do (anchored to the real sessions root + safe
// domain), so a symlinked offensive-runs/ or session dir is rejected, not
// followed. Returns the real capture dir; creates it under the nominal dir first.
function resolveCaptureDirSecure(domain) {
  const nominalDir = offensiveRunsDir(domain);
  const nominalParent = path.dirname(nominalDir);
  const realRoot = fs.realpathSync(sessionsRoot());
  const expectedParent = path.join(realRoot, assertSafeDomain(domain));
  // Create + verify the SESSION dir BEFORE creating offensive-runs/ under it: a
  // recursive mkdir would otherwise FOLLOW a symlinked session dir and plant the
  // capture dir at the link target. Checking the parent first means children are
  // never created under a symlinked parent (the post-mkdir realpath check below is
  // kept as a second line for a symlinked offensive-runs/ leaf itself).
  fs.mkdirSync(nominalParent, { recursive: true });
  if (fs.realpathSync(nominalParent) !== expectedParent) {
    throw new ToolError(
      ERROR_CODES.STATE_CONFLICT,
      `offensive-runs session dir must stay inside its session root without symlinks: ${nominalParent}`,
    );
  }
  fs.mkdirSync(nominalDir, { recursive: true });
  const expectedDir = path.join(expectedParent, "offensive-runs");
  const realDir = fs.realpathSync(nominalDir);
  if (realDir !== expectedDir) {
    throw new ToolError(
      ERROR_CODES.STATE_CONFLICT,
      `offensive-runs capture dir must stay inside its session root without symlinks: ${nominalDir}`,
    );
  }
  return realDir;
}

// Write a capture leaf exclusively (O_NOFOLLOW via wx on a fresh path), then
// realpath/O_NOFOLLOW/nlink-recompute its on-disk sha256 — the recomputed hash
// (NOT an in-memory string) is what binds into the row, byte-identical to what
// projectExploitRunObservedRef re-hashes at freeze.
function writeCaptureAndHash(captureDir, runId, suffix, contentBytes) {
  const leaf = path.join(captureDir, `${runId}.${suffix}`);
  // Exclusive create defeats a pre-planted symlink at the leaf path.
  const fd = fs.openSync(leaf, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL, 0o600);
  try {
    fs.writeFileSync(fd, contentBytes);
    fs.fsyncSync(fd);
  } finally {
    try { fs.closeSync(fd); } catch {}
  }
  return sha256OfFileFd(leaf);
}

// Append one complete JSON line atomically. Single O_APPEND write of `${line}\n`
// so readOffensiveRunRecords (fail-closed on a partial line) never sees a torn
// record. Realpath/O_NOFOLLOW/nlink discipline on the ledger leaf.
function appendSignedRowHardened(domain, row) {
  const nominalPath = offensiveRunsJsonlPath(domain);
  const nominalDir = path.dirname(nominalPath);
  fs.mkdirSync(nominalDir, { recursive: true });
  const realRoot = fs.realpathSync(sessionsRoot());
  const expectedDir = path.join(realRoot, assertSafeDomain(domain));
  const realDir = fs.realpathSync(nominalDir);
  if (realDir !== expectedDir) {
    throw new ToolError(
      ERROR_CODES.STATE_CONFLICT,
      `offensive-runs.jsonl directory must stay inside its session root without domain-directory symlinks: ${nominalDir}`,
    );
  }
  const realLeaf = path.join(realDir, "offensive-runs.jsonl");
  const noFollow = fs.constants.O_NOFOLLOW || 0;
  if (!noFollow && fs.existsSync(realLeaf)) {
    const lst = fs.lstatSync(realLeaf);
    if (lst.isSymbolicLink()) {
      throw new ToolError(ERROR_CODES.STATE_CONFLICT, `offensive-runs.jsonl must not be a symlink: ${realLeaf}`);
    }
  }
  const line = `${JSON.stringify(row)}\n`;
  let fd = null;
  try {
    fd = fs.openSync(realLeaf, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_APPEND | noFollow, 0o600);
    const stats = fs.fstatSync(fd);
    if (!stats.isFile()) {
      throw new ToolError(ERROR_CODES.STATE_CONFLICT, `offensive-runs.jsonl must be a regular file: ${realLeaf}`);
    }
    if (stats.nlink !== 1) {
      throw new ToolError(ERROR_CODES.STATE_CONFLICT, `offensive-runs.jsonl must not be hard-linked: ${realLeaf}`);
    }
    fs.writeSync(fd, line);
    fs.fsyncSync(fd);
  } finally {
    if (fd != null) {
      try { fs.closeSync(fd); } catch {}
    }
  }
}

// Build + sign + persist the offensive row. Captures FIRST, recompute the THREE
// hashes from on-disk bytes, build the 14-field row, sign LAST, atomic append.
// Returns the persisted row (signed). Caller wraps in withSessionLock.
function buildAndSignOffensiveRow(domain, {
  runIdPrefix,
  toolId,
  demonstratedSeverity,
  method,
  canonicalTarget,
  surfaceId,
  identityTag,
  stdoutContent,
  stderrContent,
  relationBooleans = {},
}) {
  const runId = newRunId(runIdPrefix);

  // run_id single-use guard (mint condition #25): refuse to re-emit a run_id
  // already present in offensive-runs.jsonl this session.
  const existing = readOffensiveRunRecords(domain);
  for (const r of existing) {
    if (r && r.run_id === runId) {
      throw new ToolError(ERROR_CODES.STATE_CONFLICT, `offensive run_id collision (refusing to re-emit): ${runId}`);
    }
  }

  const captureDir = resolveCaptureDirSecure(domain);
  // STEP 1 — write captures FIRST (audit-graded #115; MCP-owned, agents cannot Write here).
  const stdoutBytes = Buffer.from(stdoutContent, "utf8");
  const stderrBytes = Buffer.from(stderrContent, "utf8");
  // STEP 2 — recompute the THREE hashes FROM THE ON-DISK CAPTURE BYTES.
  const stdoutHash = writeCaptureAndHash(captureDir, runId, "stdout", stdoutBytes);
  const stderrHash = writeCaptureAndHash(captureDir, runId, "stderr", stderrBytes);
  const commandHash = commandHashOf(method, canonicalTarget, identityTag);

  // STEP 3 — build the 14-field row + optional MAC-covered relation booleans
  // (honest self-documentation, NOT a soundness control). demonstrated_severity
  // is HARDCODED from the producer ceiling, never agent-supplied/content-derived.
  const row = {
    version: 1,
    target_domain: domain,
    run_id: runId,
    tool_id: toolId,
    target: canonicalTarget,
    offensive_outcome: "exploited_safely",
    dry_run: false,
    timed_out: false,
    command_hash: commandHash,
    exit_code: 0,
    stdout_hash: stdoutHash,
    stderr_hash: stderrHash,
    demonstrated_severity: demonstratedSeverity,
    surface_id: surfaceId,
    ...relationBooleans,
  };

  // STEP 4 — sign LAST (whole-row MAC auto-binds the relation booleans).
  signOffensiveRunRow(row, readHandoffSigningKey(domain));

  // APPEND — MCP-owned hardened writer.
  appendSignedRowHardened(domain, row);

  return row;
}

module.exports = {
  newRunId,
  commandHashOf,
  resolveCaptureDirSecure,
  writeCaptureAndHash,
  appendSignedRowHardened,
  buildAndSignOffensiveRow,
};
