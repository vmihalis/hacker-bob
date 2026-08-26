"use strict";

const fs = require("fs");
const crypto = require("crypto");
const os = require("os");
const path = require("path");
const {
  SESSION_LOCK_NAME,
  SESSION_LOCK_STALE_MS,
} = require("../session/session-state-vocabulary.js");
const {
  sessionDir,
  sessionLockPath,
} = require("./paths.js");
const {
  ERROR_CODES,
  ToolError,
} = require("./envelope.js");

const DEFAULT_ARTIFACT_READ_MAX_BYTES = 16 * 1024 * 1024;
const activeSessionLocks = new Map();
const activeSessionLockDirectoryIdentities = new Map();
const sessionLockReleaseHooks = [];

function ensureParentDir(filePath) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
}

function readJsonlStrict(filePath, label, normalizeRecord) {
  if (!fs.existsSync(filePath)) return [];
  const raw = readFileUtf8(filePath, { label });
  const lines = raw.split(/\r?\n/).filter((line) => line.trim().length > 0);
  const records = [];
  for (let i = 0; i < lines.length; i++) {
    let parsed;
    try {
      parsed = JSON.parse(lines[i]);
    } catch (error) {
      throw new Error(`Malformed ${label} at line ${i + 1}: ${error.message || String(error)}`);
    }
    records.push(normalizeRecord ? normalizeRecord(parsed, i) : parsed);
  }
  return records;
}

function writeJsonDocument(filePath, document) {
  writeFileAtomic(filePath, `${JSON.stringify(document, null, 2)}\n`);
}

function registerSessionLockReleaseHook(callback) {
  if (typeof callback !== "function") {
    throw new Error("session-lock release hook must be a function");
  }
  if (!sessionLockReleaseHooks.includes(callback)) {
    sessionLockReleaseHooks.push(callback);
  }
  return () => {
    const index = sessionLockReleaseHooks.indexOf(callback);
    if (index >= 0) sessionLockReleaseHooks.splice(index, 1);
  };
}

function runSessionLockReleaseHooks(domain) {
  // Best-effort fan-out: a misbehaving hook must not regress the producer or
  // leave another hook unfired. Hooks run after the lock is released and
  // re-acquire it themselves if they need it.
  for (const hook of sessionLockReleaseHooks.slice()) {
    try {
      hook(domain);
    } catch {}
  }
}

function readFileUtf8(filePath, {
  label = path.basename(filePath),
  maxBytes = DEFAULT_ARTIFACT_READ_MAX_BYTES,
} = {}) {
  if (maxBytes != null && (!Number.isInteger(maxBytes) || maxBytes < 1)) {
    throw new Error("maxBytes must be a positive integer");
  }
  const stats = fs.statSync(filePath);
  if (maxBytes != null && stats.size > maxBytes) {
    throw new Error(`${label} exceeds read cap of ${maxBytes} bytes: ${filePath}`);
  }
  return fs.readFileSync(filePath, "utf8");
}

function readJsonFile(filePath, options = {}) {
  return JSON.parse(readFileUtf8(filePath, options));
}

function writeFileAtomic(filePath, content, { mode } = {}) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  const tempPath = siblingTempPath(filePath);
  try {
    fs.writeFileSync(tempPath, content, mode == null ? undefined : { mode });
    fs.renameSync(tempPath, filePath);
  } finally {
    try { fs.unlinkSync(tempPath); } catch {}
  }
}

function siblingTempPath(filePath) {
  return path.join(
    path.dirname(filePath),
    `.${path.basename(filePath)}.${process.pid}.${Date.now()}.${Math.random().toString(16).slice(2)}.tmp`,
  );
}

function fileIdentityCandidate(filePath, stats, { owned = false } = {}) {
  return {
    path: filePath,
    dev: stats.dev,
    ino: stats.ino,
    nlink: stats.nlink,
    size: stats.size,
    type: stats.isSymbolicLink()
      ? "symlink"
      : stats.isFile()
        ? "file"
        : stats.isDirectory()
          ? "directory"
          : "other",
    owned,
  };
}

function sameDevIno(candidate, stats) {
  return Boolean(candidate)
    && stats
    && candidate.dev === stats.dev
    && candidate.ino === stats.ino;
}

function lstatCandidateIfPresent(filePath, { owned = false } = {}) {
  const stats = lstatIfPresent(filePath);
  return stats ? fileIdentityCandidate(filePath, stats, { owned }) : null;
}

function exactRegularCandidate(filePath, expectedIdentity) {
  const stats = lstatIfPresent(filePath);
  if (
    !stats
    || !stats.isFile()
    || stats.isSymbolicLink()
    || !sameDevIno(expectedIdentity, stats)
  ) return null;
  return fileIdentityCandidate(filePath, stats, { owned: true });
}

function cleanupExactTemp(tempPath, tempCandidate) {
  const current = exactRegularCandidate(tempPath, tempCandidate);
  if (!current) return { removed: false, candidate: null };
  fs.unlinkSync(tempPath);
  return { removed: true, candidate: current };
}

function makeExclusiveReceipt({
  status,
  phase,
  path: finalPath,
  tempPath,
  error = null,
  tempCandidate = null,
  finalCandidate = null,
  unresolvedTemp = null,
  probeError = null,
  closeError = null,
  cleanupError = null,
}) {
  const receipt = {
    status,
    phase,
    path: finalPath,
    tempPath,
    tempCandidate,
    finalCandidate,
  };
  if (error) receipt.error = error;
  if (unresolvedTemp) receipt.unresolvedTemp = unresolvedTemp;
  if (probeError) receipt.probeError = probeError;
  if (closeError) receipt.closeError = closeError;
  if (cleanupError) receipt.cleanupError = cleanupError;
  return receipt;
}

function closeDescriptorOnce(descriptor) {
  fs.closeSync(descriptor);
}

function attachBestEffortErrorDiagnostic(error, key, value) {
  if (!error || typeof error !== "object") return error;
  try {
    Object.defineProperty(error, key, {
      value,
      enumerable: true,
      configurable: true,
      writable: true,
    });
  } catch {}
  return error;
}

function attachExclusiveReceiptDiagnostics(error, receipt) {
  if (!error || typeof error !== "object") return error;
  const diagnosticReceipt = {
    status: receipt.status,
    phase: receipt.phase,
    path: receipt.path,
    tempPath: receipt.tempPath,
    tempCandidate: receipt.tempCandidate,
    finalCandidate: receipt.finalCandidate,
    unresolvedTemp: receipt.unresolvedTemp,
  };
  if (receipt.probeError) {
    attachBestEffortErrorDiagnostic(error, "probeError", receipt.probeError);
    diagnosticReceipt.probeError = receipt.probeError;
  }
  if (receipt.closeError) {
    attachBestEffortErrorDiagnostic(error, "closeError", receipt.closeError);
    diagnosticReceipt.closeError = receipt.closeError;
  }
  if (receipt.cleanupError) {
    attachBestEffortErrorDiagnostic(error, "cleanupError", receipt.cleanupError);
    diagnosticReceipt.cleanupError = receipt.cleanupError;
  }
  attachBestEffortErrorDiagnostic(error, "exclusiveReceipt", diagnosticReceipt);
  return error;
}

function writeFileExclusiveAtomicReceipt(filePath, content, { mode } = {}) {
  try {
    fs.mkdirSync(path.dirname(filePath), { recursive: true });
  } catch (error) {
    return makeExclusiveReceipt({
      status: "failed",
      phase: "mkdir",
      path: filePath,
      tempPath: null,
      error,
    });
  }

  const tempPath = siblingTempPath(filePath);
  let descriptor = null;
  let tempCandidate = null;

  const failWithCleanup = (phase, error, finalCandidate = null, unresolvedTemp = null) => {
    let closeError = null;
    let cleanupError = null;
    if (descriptor != null) {
      const closeTarget = descriptor;
      descriptor = null;
      try {
        closeDescriptorOnce(closeTarget);
      } catch (closeFailure) {
        closeError = closeFailure;
      }
    }
    if (tempCandidate) {
      try {
        cleanupExactTemp(tempPath, tempCandidate);
      } catch (cleanupFailure) {
        cleanupError = cleanupFailure;
      }
    }
    return makeExclusiveReceipt({
      status: "failed",
      phase,
      path: filePath,
      tempPath,
      error,
      tempCandidate,
      finalCandidate,
      unresolvedTemp,
      closeError,
      cleanupError,
    });
  };

  try {
    const flags = fs.constants.O_CREAT
      | fs.constants.O_EXCL
      | fs.constants.O_WRONLY
      | (fs.constants.O_NOFOLLOW || 0);
    descriptor = fs.openSync(tempPath, flags, mode == null ? 0o666 : mode);
  } catch (error) {
    if (error && error.code === "EEXIST") {
      return makeExclusiveReceipt({
        status: "failed",
        phase: "temp_open",
        path: filePath,
        tempPath,
        error,
        unresolvedTemp: { path: tempPath, reason: "temp_exists" },
      });
    }
    return makeExclusiveReceipt({
      status: "failed",
      phase: "temp_open",
      path: filePath,
      tempPath,
      error,
      unresolvedTemp: { path: tempPath, reason: "temp_open_failed" },
    });
  }

  let openedStats = null;
  for (let attempt = 0; attempt < 2; attempt += 1) {
    try {
      openedStats = fs.fstatSync(descriptor);
      break;
    } catch (error) {
      if (attempt === 1) {
        return failWithCleanup(
          "temp_identity",
          error,
          null,
          { path: tempPath, reason: "identity_unresolved" },
        );
      }
    }
  }

  if (!openedStats.isFile()) {
    return failWithCleanup(
      "temp_identity",
      new Error("exclusive temp path must be a regular file"),
    );
  }
  tempCandidate = fileIdentityCandidate(tempPath, openedStats, { owned: true });

  try {
    fs.writeFileSync(descriptor, content);
  } catch (error) {
    return failWithCleanup("write", error);
  }

  const closeTarget = descriptor;
  descriptor = null;
  try {
    closeDescriptorOnce(closeTarget);
  } catch (error) {
    return failWithCleanup("close", error);
  }

  try {
    const currentTemp = exactRegularCandidate(tempPath, tempCandidate);
    if (!currentTemp) {
      return failWithCleanup(
        "prelink_identity",
        new Error("exclusive temp identity changed before link"),
      );
    }
    tempCandidate = currentTemp;
  } catch (error) {
    return failWithCleanup("prelink_identity", error);
  }

  try {
    fs.linkSync(tempPath, filePath);
  } catch (error) {
    let finalCandidate = null;
    let probeError = null;
    let cleanupError = null;
    const recordProbeError = (probeFailure) => {
      if (probeError === null) probeError = probeFailure;
    };

    if (error && error.code === "EEXIST") {
      try {
        finalCandidate = lstatCandidateIfPresent(filePath, { owned: false });
      } catch (probeFailure) {
        recordProbeError(probeFailure);
      }
    } else {
      try {
        finalCandidate = exactRegularCandidate(filePath, tempCandidate);
      } catch (probeFailure) {
        recordProbeError(probeFailure);
      }
    }

    try {
      cleanupExactTemp(tempPath, tempCandidate);
      if (finalCandidate && finalCandidate.owned === true) {
        try {
          const finalAfterCleanup = exactRegularCandidate(filePath, tempCandidate);
          if (finalAfterCleanup) finalCandidate = finalAfterCleanup;
        } catch (probeFailure) {
          recordProbeError(probeFailure);
        }
      }
    } catch (cleanupFailure) {
      cleanupError = cleanupFailure;
    }
    if (error && error.code === "EEXIST") {
      return makeExclusiveReceipt({
        status: "exists",
        phase: "link",
        path: filePath,
        tempPath,
        error,
        tempCandidate,
        finalCandidate,
        probeError,
        cleanupError,
      });
    }
    return makeExclusiveReceipt({
      status: "failed",
      phase: "link",
      path: filePath,
      tempPath,
      error,
      tempCandidate,
      finalCandidate,
      probeError,
      cleanupError,
    });
  }

  let finalCandidate = null;
  try {
    finalCandidate = exactRegularCandidate(filePath, tempCandidate);
  } catch (error) {
    return failWithCleanup("postlink_proof", error);
  }
  if (!finalCandidate) {
    return failWithCleanup(
      "postlink_proof",
      new Error("exclusive final identity does not match temp identity"),
    );
  }
  if (finalCandidate.nlink !== 2) {
    return failWithCleanup(
      "postlink_proof",
      new Error("exclusive final link count proof failed"),
      finalCandidate,
    );
  }

  let cleanupError = null;
  try {
    const cleanup = cleanupExactTemp(tempPath, tempCandidate);
    if (!cleanup.removed) {
      cleanupError = new Error("exclusive temp cleanup did not remove the staged file");
    }
  } catch (error) {
    cleanupError = error;
  }
  if (cleanupError) {
    return makeExclusiveReceipt({
      status: "failed",
      phase: "temp_cleanup",
      path: filePath,
      tempPath,
      error: cleanupError,
      tempCandidate,
      finalCandidate,
      cleanupError,
    });
  }

  try {
    const finalAfterCleanup = exactRegularCandidate(filePath, tempCandidate);
    if (!finalAfterCleanup || finalAfterCleanup.nlink !== 1) {
      return makeExclusiveReceipt({
        status: "failed",
        phase: "final_proof",
        path: filePath,
        tempPath,
        error: new Error("exclusive final cleanup proof failed"),
        tempCandidate,
        finalCandidate,
      });
    }
    finalCandidate = finalAfterCleanup;
  } catch (error) {
    return makeExclusiveReceipt({
      status: "failed",
      phase: "final_proof",
      path: filePath,
      tempPath,
      error,
      tempCandidate,
      finalCandidate,
    });
  }

  return makeExclusiveReceipt({
    status: "created",
    phase: "complete",
    path: filePath,
    tempPath,
    tempCandidate,
    finalCandidate,
  });
}

function writeFileExclusiveAtomic(filePath, content, { mode } = {}) {
  const receipt = writeFileExclusiveAtomicReceipt(filePath, content, { mode });
  if (receipt.status === "created") return true;
  if (receipt.status === "exists") return false;
  const error = receipt.error || new Error(`exclusive file publish failed during ${receipt.phase}`);
  throw attachExclusiveReceiptDiagnostics(error, receipt);
}

function makeCasReceipt({
  status,
  phase,
  path: finalPath,
  expected,
  stagePath = null,
  quarantinePath = null,
  error = null,
  stageReceipt = null,
  stagedCandidate = null,
  displacedCandidate = null,
  producedCandidate = null,
  producedEntryOwned = false,
  displaced = false,
  probeError = null,
  cleanupError = null,
}) {
  const receipt = {
    status,
    phase,
    path: finalPath,
    expected,
    stagePath,
    quarantinePath,
    stageReceipt,
    stagedCandidate,
    displacedCandidate,
    producedCandidate,
    producedEntryOwned,
    displaced,
  };
  if (error) receipt.error = error;
  if (probeError) receipt.probeError = probeError;
  if (cleanupError) receipt.cleanupError = cleanupError;
  return receipt;
}

function normalizeCasExpected(expected) {
  if (expected == null || typeof expected !== "object" || Array.isArray(expected)) {
    throw new Error("expected must describe an absent or existing file");
  }
  if (expected.exists === false) return { exists: false, bytes: null };
  if (expected.exists !== true
      || !Buffer.isBuffer(expected.bytes)
      || !Number.isInteger(expected.dev)
      || !Number.isInteger(expected.ino)) {
    throw new Error("existing expected file requires Buffer bytes and dev/ino identity");
  }
  return {
    exists: true,
    bytes: Buffer.from(expected.bytes),
    dev: expected.dev,
    ino: expected.ino,
  };
}

function inspectRegularCandidate(filePath, identity, { nlink = null, bytes = null } = {}) {
  let descriptor = null;
  let primaryError = null;
  let closeError = null;
  let candidate = null;
  let content = null;
  try {
    const pathStats = fs.lstatSync(filePath);
    if (pathStats.isSymbolicLink()
        || !pathStats.isFile()
        || !sameDevIno(identity, pathStats)
        || (nlink != null && pathStats.nlink !== nlink)) {
      throw new Error(`${path.basename(filePath)} identity proof failed`);
    }
    descriptor = fs.openSync(filePath, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0));
    const descriptorStats = fs.fstatSync(descriptor);
    if (!descriptorStats.isFile()
        || !sameDevIno(pathStats, descriptorStats)
        || descriptorStats.nlink !== pathStats.nlink
        || descriptorStats.size !== pathStats.size) {
      throw new Error(`${path.basename(filePath)} changed before identity read`);
    }
    content = Buffer.alloc(descriptorStats.size);
    let offset = 0;
    while (offset < content.length) {
      const count = fs.readSync(descriptor, content, offset, content.length - offset, offset);
      if (count === 0) throw new Error(`${path.basename(filePath)} changed during identity read`);
      offset += count;
    }
    const afterStats = fs.fstatSync(descriptor);
    if (!afterStats.isFile()
        || !sameDevIno(descriptorStats, afterStats)
        || afterStats.nlink !== descriptorStats.nlink
        || afterStats.size !== descriptorStats.size) {
      throw new Error(`${path.basename(filePath)} changed during identity read`);
    }
    const finalStats = fs.lstatSync(filePath);
    if (finalStats.isSymbolicLink()
        || !finalStats.isFile()
        || !sameDevIno(afterStats, finalStats)
        || finalStats.nlink !== afterStats.nlink) {
      throw new Error(`${path.basename(filePath)} changed after identity read`);
    }
    if (bytes !== null && Buffer.compare(content, bytes) !== 0) {
      throw new Error(`${path.basename(filePath)} bytes do not match the CAS preimage`);
    }
    candidate = fileIdentityCandidate(filePath, finalStats, { owned: true });
  } catch (error) {
    primaryError = error;
  }
  if (descriptor != null) {
    try {
      closeDescriptorOnce(descriptor);
    } catch (error) {
      closeError = error;
      if (primaryError === null) primaryError = error;
    }
  }
  return {
    ok: primaryError === null,
    error: primaryError,
    closeError,
    candidate,
    bytes: content,
  };
}

function cleanupOwnedEntry(candidate) {
  if (!candidate || candidate.owned !== true || !candidate.path) {
    return { removed: false, absent: false, error: null };
  }
  try {
    const stats = fs.lstatSync(candidate.path);
    if (!sameDevIno(candidate, stats)
        || fileIdentityCandidate(candidate.path, stats).type !== candidate.type) {
      return {
        removed: false,
        absent: false,
        error: new Error(`${path.basename(candidate.path)} ownership changed before cleanup`),
      };
    }
    if (stats.isDirectory()) {
      return {
        removed: false,
        absent: false,
        error: new Error(`${path.basename(candidate.path)} owned cleanup refuses a directory`),
      };
    }
    fs.unlinkSync(candidate.path);
    return { removed: true, absent: false, error: null };
  } catch (error) {
    if (error && error.code === "ENOENT") {
      return { removed: false, absent: true, error: null };
    }
    try {
      const current = fs.lstatSync(candidate.path);
      if (!sameDevIno(candidate, current)) {
        return {
          removed: false,
          absent: false,
          error: new Error(`${path.basename(candidate.path)} ownership changed during cleanup`),
        };
      }
    } catch (probeError) {
      if (probeError && probeError.code === "ENOENT") {
        return { removed: true, absent: true, error };
      }
    }
    return { removed: false, absent: false, error };
  }
}

function linkedDirectoryEntryCandidate(
  sourcePath,
  destinationPath,
  expectedSource,
  { nlink, bytes },
) {
  const sourceProof = inspectRegularCandidate(
    sourcePath,
    expectedSource,
    { nlink, bytes },
  );
  if (!sourceProof.ok) return { candidate: null, error: sourceProof.error };

  const destinationProof = inspectRegularCandidate(
    destinationPath,
    expectedSource,
    { nlink, bytes },
  );
  if (!destinationProof.ok) return { candidate: null, error: destinationProof.error };
  if (!sameDevIno(sourceProof.candidate, destinationProof.candidate)) {
    return {
      candidate: null,
      error: new Error(`${path.basename(destinationPath)} no longer aliases its proven link source`),
    };
  }
  return { candidate: destinationProof.candidate, error: null };
}

function cleanupStageReceipt(receipt) {
  if (!receipt) return null;
  let firstError = null;
  const candidates = [];
  if (receipt.finalCandidate && receipt.finalCandidate.owned === true) {
    candidates.push(receipt.finalCandidate);
  } else if (receipt.tempCandidate
      && receipt.tempCandidate.owned === true
      && receipt.path
      && receipt.status !== "exists"
      && ["link", "postlink_proof"].includes(receipt.phase)) {
    candidates.push({ ...receipt.tempCandidate, path: receipt.path, owned: true });
  }
  if (receipt.tempCandidate && receipt.tempCandidate.owned === true) {
    candidates.push({ ...receipt.tempCandidate, path: receipt.tempPath, owned: true });
  }
  for (const candidate of candidates) {
    const cleanup = cleanupOwnedEntry(candidate);
    if (cleanup.error && firstError === null) firstError = cleanup.error;
  }
  return firstError;
}

function restoreCasPreimage(receipt) {
  if (!receipt.expected.exists || receipt.displaced !== true) return null;
  let current = null;
  try {
    current = lstatIfPresent(receipt.path);
  } catch (error) {
    return error;
  }
  if (current) {
    const expectedProof = inspectRegularCandidate(
      receipt.path,
      receipt.expected,
      { nlink: 1, bytes: receipt.expected.bytes },
    );
    if (expectedProof.ok) return null;
    return new Error(`${path.basename(receipt.path)} replacement preserved during CAS rollback`);
  }

  if (receipt.displacedCandidate) {
    const proof = inspectRegularCandidate(
      receipt.quarantinePath,
      receipt.displacedCandidate,
      { nlink: 1, bytes: receipt.expected.bytes },
    );
    if (proof.ok) {
      try {
        fs.linkSync(receipt.quarantinePath, receipt.path);
        const restored = inspectRegularCandidate(
          receipt.path,
          receipt.displacedCandidate,
          { nlink: 2, bytes: receipt.expected.bytes },
        );
        if (!restored.ok) return restored.error;
        const cleanup = cleanupOwnedEntry(receipt.displacedCandidate);
        if (cleanup.error) return cleanup.error;
        const finalProof = inspectRegularCandidate(
          receipt.path,
          receipt.displacedCandidate,
          { nlink: 1, bytes: receipt.expected.bytes },
        );
        return finalProof.ok ? null : finalProof.error;
      } catch (error) {
        return error;
      }
    }
  }

  const restoreReceipt = writeFileExclusiveAtomicReceipt(receipt.path, receipt.expected.bytes);
  if (restoreReceipt.status === "created") return null;
  const cleanupError = cleanupStageReceipt(restoreReceipt);
  return cleanupError
    || restoreReceipt.error
    || new Error(`${path.basename(receipt.path)} could not be restored after CAS failure`);
}

function rollbackFileCasAtomicReceipt(receipt) {
  if (!receipt || typeof receipt !== "object") return new Error("CAS receipt is required");
  if (receipt.rollbackComplete === true) return null;
  let firstError = cleanupStageReceipt(receipt.stageReceipt);

  if (receipt.stagedCandidate) {
    const cleanup = cleanupOwnedEntry(receipt.stagedCandidate);
    if (cleanup.error && firstError === null) firstError = cleanup.error;
  }

  if (receipt.producedCandidate && receipt.producedCandidate.owned === true) {
    let current = null;
    try {
      current = fs.lstatSync(receipt.path);
    } catch (error) {
      if (!error || error.code !== "ENOENT") {
        if (firstError === null) firstError = error;
      }
    }
    if (current && sameDevIno(receipt.producedCandidate, current)) {
      if (current.isDirectory()
          || (!receipt.producedEntryOwned
            && (!current.isFile() || current.isSymbolicLink() || current.nlink !== 1))) {
        if (firstError === null) {
          firstError = new Error(`${path.basename(receipt.path)} produced inode is not single-link during rollback`);
        }
      } else {
        const cleanup = cleanupOwnedEntry({
          ...receipt.producedCandidate,
          path: receipt.path,
          nlink: current.nlink,
          type: receipt.producedEntryOwned ? receipt.producedCandidate.type : "file",
          owned: true,
        });
        if (cleanup.error && firstError === null) firstError = cleanup.error;
      }
    } else if (current && firstError === null) {
      const expectedProof = receipt.expected.exists
        ? inspectRegularCandidate(
          receipt.path,
          receipt.expected,
          { nlink: 1, bytes: receipt.expected.bytes },
        )
        : { ok: false };
      if (!expectedProof.ok) {
        firstError = new Error(`${path.basename(receipt.path)} replacement preserved during CAS rollback`);
      }
    }
  }

  const restoreError = restoreCasPreimage(receipt);
  if (restoreError && firstError === null) firstError = restoreError;

  if (receipt.displacedCandidate) {
    const cleanup = cleanupOwnedEntry(receipt.displacedCandidate);
    if (cleanup.error && firstError === null) firstError = cleanup.error;
  }
  if (firstError === null) receipt.rollbackComplete = true;
  return firstError;
}

function finishCasFailure(receipt) {
  const rollbackError = rollbackFileCasAtomicReceipt(receipt);
  if (rollbackError) receipt.cleanupError = rollbackError;
  return receipt;
}

function writeFileCasAtomicReceipt(filePath, content, expected, { mode } = {}) {
  let normalizedExpected;
  try {
    normalizedExpected = normalizeCasExpected(expected);
  } catch (error) {
    return makeCasReceipt({
      status: "failed",
      phase: "precondition",
      path: filePath,
      expected,
      error,
    });
  }
  let contentBytes;
  try {
    if (Buffer.isBuffer(content)) contentBytes = Buffer.from(content);
    else if (typeof content === "string") contentBytes = Buffer.from(content, "utf8");
    else if (ArrayBuffer.isView(content)) {
      contentBytes = Buffer.from(content.buffer, content.byteOffset, content.byteLength);
    } else {
      throw new Error("CAS content must be a string, Buffer, or typed-array view");
    }
  } catch (error) {
    return makeCasReceipt({
      status: "failed",
      phase: "precondition",
      path: filePath,
      expected: normalizedExpected,
      error,
    });
  }

  if (!normalizedExpected.exists) {
    const exclusiveReceipt = writeFileExclusiveAtomicReceipt(filePath, contentBytes, { mode });
    const receipt = makeCasReceipt({
      status: exclusiveReceipt.status === "created" ? "created" : exclusiveReceipt.status,
      phase: exclusiveReceipt.phase,
      path: filePath,
      expected: normalizedExpected,
      stagePath: exclusiveReceipt.tempPath,
      error: exclusiveReceipt.error || null,
      stageReceipt: exclusiveReceipt.status === "created" ? null : exclusiveReceipt,
      stagedCandidate: exclusiveReceipt.tempCandidate,
      producedCandidate: exclusiveReceipt.finalCandidate
        && exclusiveReceipt.finalCandidate.owned === true
        ? exclusiveReceipt.finalCandidate
        : null,
    });
    return exclusiveReceipt.status === "created" ? receipt : finishCasFailure(receipt);
  }

  try {
    fs.mkdirSync(path.dirname(filePath), { recursive: true });
  } catch (error) {
    return makeCasReceipt({
      status: "failed",
      phase: "mkdir",
      path: filePath,
      expected: normalizedExpected,
      error,
    });
  }

  const stagePath = siblingTempPath(filePath);
  const quarantinePath = siblingTempPath(filePath);
  const stageReceipt = writeFileExclusiveAtomicReceipt(stagePath, contentBytes, { mode });
  let receipt = makeCasReceipt({
    status: "failed",
    phase: "stage",
    path: filePath,
    expected: normalizedExpected,
    stagePath,
    quarantinePath,
    error: stageReceipt.error || null,
    stageReceipt,
    stagedCandidate: stageReceipt.finalCandidate,
  });
  if (stageReceipt.status !== "created") return finishCasFailure(receipt);
  receipt.stagedCandidate = stageReceipt.finalCandidate;

  let quarantineWasAbsent = false;
  try {
    quarantineWasAbsent = fs.lstatSync(quarantinePath) == null;
  } catch (error) {
    if (error && error.code === "ENOENT") quarantineWasAbsent = true;
    else {
      receipt.phase = "quarantine_preflight";
      receipt.error = error;
      return finishCasFailure(receipt);
    }
  }
  if (!quarantineWasAbsent) {
    receipt.phase = "quarantine_preflight";
    receipt.error = new Error("CAS quarantine path already exists");
    return finishCasFailure(receipt);
  }

  try {
    fs.linkSync(filePath, quarantinePath);
  } catch (error) {
    receipt.phase = "quarantine_link";
    receipt.error = error;
    if (!error || error.code !== "EEXIST") {
      let proof = null;
      let firstProbeError = null;
      for (let attempt = 0; attempt < 2; attempt += 1) {
        proof = inspectRegularCandidate(
          quarantinePath,
          normalizedExpected,
          { nlink: 2, bytes: normalizedExpected.bytes },
        );
        if (proof.ok) break;
        if (firstProbeError === null) firstProbeError = proof.error;
      }
      if (proof.ok) {
        receipt.displacedCandidate = proof.candidate;
        receipt.probeError = firstProbeError;
      }
      else {
        receipt.displacedCandidate = {
          path: quarantinePath,
          dev: normalizedExpected.dev,
          ino: normalizedExpected.ino,
          nlink: 2,
          size: normalizedExpected.bytes.length,
          type: "file",
          owned: true,
        };
        if (!proof.error || proof.error.code !== "ENOENT") receipt.probeError = proof.error;
      }
    }
    receipt.status = error && ["ENOENT", "EEXIST"].includes(error.code) ? "conflict" : "failed";
    return finishCasFailure(receipt);
  }

  receipt.displacedCandidate = {
    path: quarantinePath,
    dev: normalizedExpected.dev,
    ino: normalizedExpected.ino,
    nlink: 2,
    size: normalizedExpected.bytes.length,
    type: "file",
    owned: true,
  };
  let quarantineLinkProof = null;
  let quarantineLinkProbeError = null;
  for (let attempt = 0; attempt < 2; attempt += 1) {
    quarantineLinkProof = linkedDirectoryEntryCandidate(
      filePath,
      quarantinePath,
      normalizedExpected,
      { nlink: 2, bytes: normalizedExpected.bytes },
    );
    if (quarantineLinkProof.candidate) break;
    if (quarantineLinkProbeError === null) quarantineLinkProbeError = quarantineLinkProof.error;
  }
  if (quarantineLinkProof.candidate) {
    receipt.displacedCandidate = quarantineLinkProof.candidate;
  }
  if (quarantineLinkProbeError) receipt.probeError = quarantineLinkProbeError;
  const beforeProof = inspectRegularCandidate(
    filePath,
    normalizedExpected,
    { nlink: 2, bytes: normalizedExpected.bytes },
  );
  const quarantineProof = inspectRegularCandidate(
    quarantinePath,
    normalizedExpected,
    { nlink: 2, bytes: normalizedExpected.bytes },
  );
  if (!beforeProof.ok
      || !quarantineProof.ok
      || !sameDevIno(beforeProof.candidate, quarantineProof.candidate)
      || !sameDevIno(normalizedExpected, quarantineProof.candidate)) {
    receipt.status = "conflict";
    receipt.phase = "preimage_proof";
    receipt.error = beforeProof.error || quarantineProof.error || new Error("CAS preimage identity changed");
    return finishCasFailure(receipt);
  }
  receipt.displacedCandidate = quarantineProof.candidate;

  try {
    const finalBeforeUnlink = fs.lstatSync(filePath);
    if (!finalBeforeUnlink.isFile()
        || finalBeforeUnlink.isSymbolicLink()
        || finalBeforeUnlink.nlink !== 2
        || !sameDevIno(normalizedExpected, finalBeforeUnlink)) {
      throw new Error("CAS preimage changed before displacement");
    }
    fs.unlinkSync(filePath);
    receipt.displaced = true;
  } catch (error) {
    let current = null;
    let probeError = null;
    try { current = lstatIfPresent(filePath); } catch (failure) { probeError = failure; }
    if (!current) receipt.displaced = true;
    receipt.status = "failed";
    receipt.phase = "displace";
    receipt.error = error;
    receipt.probeError = probeError;
    return finishCasFailure(receipt);
  }

  const displacedProof = inspectRegularCandidate(
    quarantinePath,
    receipt.displacedCandidate,
    { nlink: 1, bytes: normalizedExpected.bytes },
  );
  if (!displacedProof.ok) {
    receipt.phase = "displaced_proof";
    receipt.error = displacedProof.error;
    return finishCasFailure(receipt);
  }
  receipt.displacedCandidate = displacedProof.candidate;

  try {
    fs.linkSync(stagePath, filePath);
  } catch (error) {
    receipt.status = error && error.code === "EEXIST" ? "conflict" : "failed";
    receipt.phase = "publish_link";
    receipt.error = error;
    if (!error || error.code !== "EEXIST") {
      let proof = null;
      let firstProbeError = null;
      for (let attempt = 0; attempt < 2; attempt += 1) {
        proof = inspectRegularCandidate(
          filePath,
          receipt.stagedCandidate,
          { nlink: 2, bytes: contentBytes },
        );
        if (proof.ok) break;
        if (firstProbeError === null) firstProbeError = proof.error;
      }
      if (proof.ok) {
        receipt.producedCandidate = proof.candidate;
        receipt.probeError = firstProbeError;
      }
      else {
        receipt.producedCandidate = {
          ...receipt.stagedCandidate,
          path: filePath,
          owned: true,
        };
        receipt.probeError = proof.error;
      }
    }
    return finishCasFailure(receipt);
  }

  receipt.producedCandidate = {
    ...receipt.stagedCandidate,
    path: filePath,
    owned: true,
  };
  receipt.producedEntryOwned = true;
  let publishedLinkProof = null;
  let publishedLinkProbeError = null;
  for (let attempt = 0; attempt < 2; attempt += 1) {
    publishedLinkProof = linkedDirectoryEntryCandidate(
      stagePath,
      filePath,
      receipt.stagedCandidate,
      { nlink: 2, bytes: contentBytes },
    );
    if (publishedLinkProof.candidate) break;
    if (publishedLinkProbeError === null) publishedLinkProbeError = publishedLinkProof.error;
  }
  if (publishedLinkProof.candidate) receipt.producedCandidate = publishedLinkProof.candidate;
  if (publishedLinkProbeError) receipt.probeError = publishedLinkProbeError;
  const producedProof = inspectRegularCandidate(
    filePath,
    receipt.stagedCandidate,
    { nlink: 2, bytes: contentBytes },
  );
  if (!producedProof.ok) {
    receipt.phase = "produced_proof";
    receipt.error = producedProof.error;
    return finishCasFailure(receipt);
  }
  receipt.producedCandidate = producedProof.candidate;
  receipt.producedEntryOwned = false;

  const stageCleanup = cleanupOwnedEntry(receipt.stagedCandidate);
  if (stageCleanup.error) {
    receipt.phase = "stage_cleanup";
    receipt.error = stageCleanup.error;
    receipt.cleanupError = stageCleanup.error;
    return finishCasFailure(receipt);
  }
  const finalProof = inspectRegularCandidate(
    filePath,
    receipt.producedCandidate,
    { nlink: 1, bytes: contentBytes },
  );
  if (!finalProof.ok) {
    receipt.phase = "final_proof";
    receipt.error = finalProof.error;
    return finishCasFailure(receipt);
  }
  receipt.producedCandidate = finalProof.candidate;

  const quarantineCleanup = cleanupOwnedEntry(receipt.displacedCandidate);
  if (quarantineCleanup.error) {
    receipt.phase = "quarantine_cleanup";
    receipt.error = quarantineCleanup.error;
    receipt.cleanupError = quarantineCleanup.error;
    return finishCasFailure(receipt);
  }

  receipt.status = "replaced";
  receipt.phase = "complete";
  receipt.stageReceipt = null;
  receipt.producedEntryOwned = false;
  return receipt;
}

function normalizeMaxJsonlRecords(maxRecords) {
  if (maxRecords == null) return null;
  if (!Number.isInteger(maxRecords) || maxRecords < 1) {
    throw new Error("maxRecords must be a positive integer");
  }
  return maxRecords;
}

function trimJsonlFile(filePath, maxRecords) {
  const normalizedMaxRecords = normalizeMaxJsonlRecords(maxRecords);
  if (normalizedMaxRecords == null || !fs.existsSync(filePath)) {
    return { trimmed: false, total: 0, retained: 0 };
  }

  // Retention is the recovery path for oversized JSONL artifacts, so it must
  // be able to read and trim files that already exceed the normal read cap.
  const content = readFileUtf8(filePath, { label: path.basename(filePath), maxBytes: null });
  const lines = content.split("\n").filter((line) => line.trim());
  if (lines.length <= normalizedMaxRecords) {
    return { trimmed: false, total: lines.length, retained: lines.length };
  }

  const retainedLines = lines.slice(-normalizedMaxRecords);
  writeFileAtomic(filePath, `${retainedLines.join("\n")}\n`);
  return { trimmed: true, total: lines.length, retained: retainedLines.length };
}

function appendJsonlLines(filePath, documents, { maxRecords = null } = {}) {
  const normalizedMaxRecords = normalizeMaxJsonlRecords(maxRecords);
  if (!Array.isArray(documents)) {
    throw new Error("documents must be an array");
  }
  if (documents.length === 0) {
    return;
  }

  // Contract: session-owned callers must hold withSessionLock. This helper is
  // intentionally low-level so tests and non-session artifacts can use it too.
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.appendFileSync(
    filePath,
    `${documents.map((document) => JSON.stringify(document)).join("\n")}\n`,
    "utf8",
  );
  if (normalizedMaxRecords != null) {
    trimJsonlFile(filePath, normalizedMaxRecords);
  }
}

function appendJsonlLine(filePath, document, { maxRecords = null } = {}) {
  appendJsonlLines(filePath, [document], { maxRecords });
}

function writeMarkdownMirror(markdownPath, content, response) {
  try {
    writeFileAtomic(markdownPath, content);
    response.written_md = markdownPath;
  } catch (error) {
    response.markdown_sync_error = error.message || String(error);
  }
}

function appendMarkdownMirror(markdownPath, content, response) {
  try {
    fs.mkdirSync(path.dirname(markdownPath), { recursive: true });
    fs.appendFileSync(markdownPath, content, "utf8");
    response.written_md = markdownPath;
  } catch (error) {
    response.markdown_sync_error = error.message || String(error);
  }
}

function loadJsonDocumentStrict(filePath, label) {
  if (!fs.existsSync(filePath)) {
    throw new Error(`Missing ${label}: ${filePath}`);
  }

  const raw = readFileUtf8(filePath, { label });
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch (error) {
    throw new Error(`Malformed ${label}: ${filePath} (${error.message || String(error)})`);
  }

  if (parsed == null || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error(`Malformed ${label}: ${filePath} (expected object)`);
  }

  return parsed;
}

function isSessionDirEffectivelyEmpty(dirPath) {
  if (!fs.existsSync(dirPath)) {
    return true;
  }

  const entries = fs.readdirSync(dirPath).filter((entry) => entry !== SESSION_LOCK_NAME);
  return entries.length === 0;
}

function lstatIfPresent(filePath) {
  try {
    return fs.lstatSync(filePath);
  } catch (error) {
    if (error && error.code === "ENOENT") return null;
    throw error;
  }
}

function realDirectoryIdentity(directoryPath, label, { create = false, recursive = false } = {}) {
  let stats = lstatIfPresent(directoryPath);
  if (stats == null && create) {
    try {
      fs.mkdirSync(directoryPath, { recursive, mode: 0o700 });
    } catch (error) {
      // Another process may have won the create race. The lstat below decides
      // whether the winner created the exact real directory we require.
      if (!error || error.code !== "EEXIST") throw error;
    }
    stats = lstatIfPresent(directoryPath);
  }
  if (!stats || !stats.isDirectory() || stats.isSymbolicLink()) {
    throw new Error(`${label} must be a real directory, not a symbolic link`);
  }
  return Object.freeze({
    path: directoryPath,
    dev: stats.dev,
    ino: stats.ino,
  });
}

function assertRealDirectoryIdentity(identity, label) {
  const stats = lstatIfPresent(identity.path);
  if (
    !stats
    || !stats.isDirectory()
    || stats.isSymbolicLink()
    || stats.dev !== identity.dev
    || stats.ino !== identity.ino
  ) throw new Error(`${label} changed during session lock operation`);
}

// Capture both path components that anchor .session.lock. Node's synchronous
// filesystem API does not expose openat(2), so callers also recheck these
// identities immediately around pathname-based lock and persistence syscalls.
// This rejects pre-existing symlinks and narrows rename/swap races to the
// unavoidable interval between the final identity check and one syscall.
function ensureSafeSessionDirectory(domain) {
  const dirPath = sessionDir(domain);
  const rootPath = path.dirname(dirPath);
  const root = realDirectoryIdentity(rootPath, "Hacker Bob sessions root", {
    create: true,
    recursive: true,
  });
  const directory = realDirectoryIdentity(dirPath, "Hacker Bob session directory", {
    create: true,
    recursive: false,
  });
  assertRealDirectoryIdentity(root, "Hacker Bob sessions root");
  return Object.freeze({ root, directory });
}

function assertSafeSessionDirectoryIdentity(identity) {
  if (!identity || !identity.root || !identity.directory) {
    throw new Error("session directory identity is required");
  }
  assertRealDirectoryIdentity(identity.root, "Hacker Bob sessions root");
  assertRealDirectoryIdentity(identity.directory, "Hacker Bob session directory");
  if (path.dirname(identity.directory.path) !== identity.root.path) {
    throw new Error("Hacker Bob session directory is not anchored under the sessions root");
  }
  return identity;
}

function safeSessionLockStats(lockPathValue) {
  const stats = lstatIfPresent(lockPathValue);
  if (stats == null) return null;
  if (stats.isSymbolicLink()) {
    throw new Error("Session lock path must not be a symbolic link");
  }
  if (!stats.isFile() && !stats.isDirectory()) {
    throw new Error("Session lock path must be a regular file or legacy lock directory");
  }
  if (stats.isFile() && stats.nlink !== 1) {
    throw new Error("Session lock path must be a single-link regular file");
  }
  return stats;
}

function readSessionLockFile(lockPathValue, expectedStats) {
  let descriptor;
  try {
    descriptor = fs.openSync(
      lockPathValue,
      fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0),
    );
    const stats = fs.fstatSync(descriptor);
    if (
      !stats.isFile()
      || stats.nlink !== 1
      || (expectedStats && (stats.dev !== expectedStats.dev || stats.ino !== expectedStats.ino))
    ) throw new Error("Session lock file identity changed during verified read");
    if (stats.size > 64 * 1024) throw new Error("Session lock file exceeds the verified read cap");
    return fs.readFileSync(descriptor, "utf8");
  } catch (error) {
    if (error && ["ELOOP", "EMLINK"].includes(error.code)) {
      throw new Error("Session lock path must not be a symbolic link");
    }
    throw error;
  } finally {
    if (descriptor != null) fs.closeSync(descriptor);
  }
}

function writeSessionLockExclusiveAtomic(lockPathValue, payload, directoryIdentity) {
  let descriptor;
  let createdIdentity = null;
  let completed = false;
  try {
    assertSafeSessionDirectoryIdentity(directoryIdentity);
    try {
      // Create the final lock inode directly. Publishing a completed sibling
      // through link(2) leaves a legitimate nlink=2 interval until the sibling
      // is removed; a concurrent contender must reject multi-link lock files,
      // so that interval is indistinguishable from a hard-link attack. O_EXCL
      // is already the atomic election primitive and O_NOFOLLOW closes the
      // final-component symlink path without introducing that ambiguity.
      descriptor = fs.openSync(
        lockPathValue,
        fs.constants.O_CREAT
          | fs.constants.O_EXCL
          | fs.constants.O_WRONLY
          | (fs.constants.O_NOFOLLOW || 0),
        0o600,
      );
    } catch (error) {
      if (error && error.code === "EEXIST") return false;
      throw error;
    }
    const openedStats = fs.fstatSync(descriptor);
    if (!openedStats.isFile() || openedStats.nlink !== 1) {
      throw new Error("Session lock creation did not produce a single-link regular file");
    }
    createdIdentity = { dev: openedStats.dev, ino: openedStats.ino };
    fs.writeFileSync(descriptor, payload, "utf8");
    fs.fsyncSync(descriptor);
    fs.closeSync(descriptor);
    descriptor = null;
    assertSafeSessionDirectoryIdentity(directoryIdentity);
    const finalStats = safeSessionLockStats(lockPathValue);
    if (!finalStats
        || finalStats.dev !== createdIdentity.dev
        || finalStats.ino !== createdIdentity.ino) {
      throw new Error("Session lock file identity changed during creation");
    }
    completed = true;
    return true;
  } finally {
    if (descriptor != null) fs.closeSync(descriptor);
    if (!completed && createdIdentity) {
      try {
        // Remove only the exact inode this call created. If the verified parent
        // or final component changed, leave it for operator recovery rather
        // than unlinking an attacker-selected path.
        assertSafeSessionDirectoryIdentity(directoryIdentity);
        const stats = safeSessionLockStats(lockPathValue);
        if (stats
            && stats.isFile()
            && stats.dev === createdIdentity.dev
            && stats.ino === createdIdentity.ino) {
          fs.unlinkSync(lockPathValue);
        }
      } catch {}
    }
  }
}

function tryAcquireSessionLock(lockPathValue, directoryIdentity) {
  if (
    !directoryIdentity
    || path.dirname(lockPathValue) !== directoryIdentity.directory.path
    || path.basename(lockPathValue) !== SESSION_LOCK_NAME
  ) throw new Error("Session lock path is not anchored in the verified session directory");
  assertSafeSessionDirectoryIdentity(directoryIdentity);
  // Refuse a hostile final component before creating even the sibling temp.
  safeSessionLockStats(lockPathValue);
  const token = `${process.pid}-${Date.now()}-${Math.random().toString(16).slice(2)}`;
  const payload = `${JSON.stringify({
    pid: process.pid,
    hostname: os.hostname(),
    timestamp: new Date().toISOString(),
    token,
  }, null, 2)}\n`;
  const created = writeSessionLockExclusiveAtomic(lockPathValue, payload, directoryIdentity);
  assertSafeSessionDirectoryIdentity(directoryIdentity);
  return created ? token : null;
}

function readLockIdentity(lockPathValue) {
  try {
    const stats = safeSessionLockStats(lockPathValue);
    if (!stats) return null;
    return {
      dev: stats.dev,
      ino: stats.ino,
      isDirectory: stats.isDirectory(),
    };
  } catch {
    return null;
  }
}

function sameLockIdentity(stats, identity) {
  if (!stats || !identity) return false;
  return (
    stats.dev === identity.dev &&
    stats.ino === identity.ino &&
    stats.isDirectory() === identity.isDirectory
  );
}

function releaseSessionLock(lockPathValue, token, identity) {
  let stats;
  try {
    stats = safeSessionLockStats(lockPathValue);
  } catch {
    return;
  }
  if (!stats) return;

  const sameOwnedFile = sameLockIdentity(stats, identity);
  if (identity && !sameOwnedFile) {
    return;
  }

  let tokenMatches = false;
  try {
    if (!stats.isFile()) return;
    const current = JSON.parse(readSessionLockFile(lockPathValue, stats));
    tokenMatches = current && typeof current === "object" && current.token === token;
  } catch {}

  if (tokenMatches || sameOwnedFile) {
    try {
      const current = safeSessionLockStats(lockPathValue);
      if (current && sameLockIdentity(current, identity) && current.isFile()) {
        fs.unlinkSync(lockPathValue);
      }
    } catch {}
  }
}

function readSessionLockSnapshot(lockPathValue) {
  let stats;
  try {
    stats = safeSessionLockStats(lockPathValue);
  } catch (error) {
    throw error;
  }
  if (!stats) {
    return null;
  }

  let timestampMs = Number.NaN;
  let contentHash = null;
  if (stats.isFile()) {
    try {
      const content = readSessionLockFile(lockPathValue, stats);
      contentHash = crypto.createHash("sha256").update(content).digest("hex");
      const parsed = JSON.parse(content);
      timestampMs = Date.parse(parsed.timestamp);
    } catch {}
  }

  const staleReferenceMs = Number.isFinite(timestampMs)
    ? Math.min(timestampMs, stats.mtimeMs)
    : stats.mtimeMs;
  return {
    dev: stats.dev,
    ino: stats.ino,
    size: stats.size,
    mtimeMs: stats.mtimeMs,
    isDirectory: stats.isDirectory(),
    contentHash,
    isStale: Date.now() - staleReferenceMs > SESSION_LOCK_STALE_MS,
  };
}

function removeStaleSessionLock(lockPathValue, snapshot) {
  if (!snapshot || !snapshot.isStale) {
    return false;
  }

  let currentStats;
  try {
    currentStats = safeSessionLockStats(lockPathValue);
  } catch {
    return false;
  }
  if (!currentStats) return false;
  if (currentStats.dev !== snapshot.dev || currentStats.ino !== snapshot.ino) {
    return false;
  }
  if (currentStats.isDirectory() !== snapshot.isDirectory) {
    return false;
  }
  if (currentStats.size !== snapshot.size || currentStats.mtimeMs !== snapshot.mtimeMs) {
    return false;
  }
  if (!snapshot.isDirectory) {
    let currentContentHash = null;
    try {
      currentContentHash = crypto
        .createHash("sha256")
        .update(readSessionLockFile(lockPathValue, currentStats))
        .digest("hex");
    } catch {
      return false;
    }
    if (currentContentHash !== snapshot.contentHash) {
      return false;
    }
  }

  if (snapshot.isDirectory) fs.rmdirSync(lockPathValue);
  else fs.unlinkSync(lockPathValue);
  return true;
}

function acquireSessionLock(domain) {
  const dir = sessionDir(domain);
  const directoryIdentity = ensureSafeSessionDirectory(domain);

  const lockPathValue = sessionLockPath(domain);
  for (let attempt = 0; attempt < 2; attempt += 1) {
    assertSafeSessionDirectoryIdentity(directoryIdentity);
    const token = tryAcquireSessionLock(lockPathValue, directoryIdentity);
    if (token) {
      const identity = readLockIdentity(lockPathValue);
      if (!identity || identity.isDirectory) {
        throw new Error("Session lock acquisition did not produce a regular lock file");
      }
      assertSafeSessionDirectoryIdentity(directoryIdentity);
      const release = () => releaseSessionLock(lockPathValue, token, identity);
      Object.defineProperty(release, "sessionDirectoryIdentity", {
        value: directoryIdentity,
        enumerable: false,
        writable: false,
        configurable: false,
      });
      return release;
    }

    const staleSnapshot = readSessionLockSnapshot(lockPathValue);
    if (attempt === 0 && staleSnapshot && staleSnapshot.isStale) {
      try {
        assertSafeSessionDirectoryIdentity(directoryIdentity);
        removeStaleSessionLock(lockPathValue, staleSnapshot);
        assertSafeSessionDirectoryIdentity(directoryIdentity);
      } catch {}
      continue;
    }

    throw new ToolError(ERROR_CODES.STATE_CONFLICT, `Session lock busy: ${dir}`);
  }

  throw new ToolError(ERROR_CODES.STATE_CONFLICT, `Session lock busy: ${dir}`);
}

function withSessionLock(domain, callback) {
  const lockKey = sessionLockPath(domain);
  const heldCount = activeSessionLocks.get(lockKey) || 0;
  if (heldCount > 0) {
    const directoryIdentity = activeSessionLockDirectoryIdentities.get(lockKey);
    assertSafeSessionDirectoryIdentity(directoryIdentity);
    activeSessionLocks.set(lockKey, heldCount + 1);
    try {
      const result = callback(directoryIdentity);
      if (result && typeof result.then === "function") {
        throw new Error("withSessionLock callback must be synchronous");
      }
      return result;
    } finally {
      const nextCount = (activeSessionLocks.get(lockKey) || 1) - 1;
      if (nextCount > 0) activeSessionLocks.set(lockKey, nextCount);
      else {
        activeSessionLocks.delete(lockKey);
        activeSessionLockDirectoryIdentities.delete(lockKey);
      }
    }
  }

  const release = acquireSessionLock(domain);
  const directoryIdentity = release.sessionDirectoryIdentity;
  assertSafeSessionDirectoryIdentity(directoryIdentity);
  activeSessionLocks.set(lockKey, 1);
  activeSessionLockDirectoryIdentities.set(lockKey, directoryIdentity);
  let result;
  let callbackFailed = false;
  try {
    result = callback(directoryIdentity);
    if (result && typeof result.then === "function") {
      throw new Error("withSessionLock callback must be synchronous");
    }
  } catch (error) {
    callbackFailed = true;
    activeSessionLocks.delete(lockKey);
    activeSessionLockDirectoryIdentities.delete(lockKey);
    release();
    throw error;
  }
  activeSessionLocks.delete(lockKey);
  activeSessionLockDirectoryIdentities.delete(lockKey);
  release();
  if (!callbackFailed) {
    // Outermost release: fire deferred hooks (e.g., frontier materialization
    // debounce). Hooks run after the lock is released so they cannot deadlock;
    // hooks that need the lock must re-acquire it themselves.
    runSessionLockReleaseHooks(domain);
  }
  return result;
}

module.exports = {
  DEFAULT_ARTIFACT_READ_MAX_BYTES,
  acquireSessionLock,
  appendJsonlLine,
  appendJsonlLines,
  appendMarkdownMirror,
  attachBestEffortErrorDiagnostic,
  ensureParentDir,
  isSessionDirEffectivelyEmpty,
  ensureSafeSessionDirectory,
  assertSafeSessionDirectoryIdentity,
  loadJsonDocumentStrict,
  readFileUtf8,
  readJsonFile,
  readJsonlStrict,
  registerSessionLockReleaseHook,
  trimJsonlFile,
  readSessionLockSnapshot,
  removeStaleSessionLock,
  tryAcquireSessionLock,
  withSessionLock,
  writeFileAtomic,
  rollbackFileCasAtomicReceipt,
  writeFileCasAtomicReceipt,
  writeFileExclusiveAtomic,
  writeFileExclusiveAtomicReceipt,
  writeJsonDocument,
  writeMarkdownMirror,
};
