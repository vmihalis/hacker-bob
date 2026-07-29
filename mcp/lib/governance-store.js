"use strict";

const fs = require("fs");
const {
  buildSessionNucleus,
  sessionNucleusFromState,
} = require("./governance-contracts.js");
const {
  sessionDir,
  sessionNucleusPath,
  sessionsRoot,
} = require("./paths.js");
const {
  readSessionStateStrict,
} = require("./session-state-store.js");
const {
  readFileUtf8,
} = require("./storage.js");

const VERIFIED_NUCLEUS_MAX_BYTES = 1024 * 1024;

function sameFileIdentity(left, right) {
  return left.dev === right.dev
    && left.ino === right.ino
    && left.nlink === right.nlink;
}

function directoryIdentity(directoryPath, label, { duringRead = false } = {}) {
  let stats;
  try {
    stats = fs.lstatSync(directoryPath);
  } catch {
    throw new Error(duringRead
      ? `${label} changed during verified nucleus read`
      : `${label} must be a real directory`);
  }
  if (!stats.isDirectory() || stats.isSymbolicLink()) {
    throw new Error(duringRead
      ? `${label} changed during verified nucleus read`
      : `${label} must be a real directory`);
  }
  return { dev: stats.dev, ino: stats.ino };
}

function readSessionNucleus(domain) {
  const filePath = sessionNucleusPath(domain);
  if (fs.existsSync(filePath)) {
    const raw = readFileUtf8(filePath, { label: "session-nucleus.json" });
    return JSON.parse(raw);
  }
  return sessionNucleusFromState(readSessionStateStrict(domain).state);
}

function readVerifiedSessionNucleus(domain) {
  const rootPath = sessionsRoot();
  const dirPath = sessionDir(domain);
  const filePath = sessionNucleusPath(domain);
  const rootIdentity = directoryIdentity(rootPath, "Hacker Bob sessions root");
  const dirIdentity = directoryIdentity(dirPath, "Hacker Bob session directory");
  let pathStats;
  try {
    pathStats = fs.lstatSync(filePath);
  } catch (error) {
    if (error && error.code === "ENOENT") {
      throw new Error("verified session nucleus requires session-nucleus.json");
    }
    throw new Error("session-nucleus.json could not be verified");
  }
  if (pathStats.isSymbolicLink()) {
    throw new Error("session-nucleus.json must not be a symbolic link");
  }
  if (!pathStats.isFile() || pathStats.nlink !== 1) {
    throw new Error("session-nucleus.json must be a single-link regular file");
  }
  if (pathStats.size > VERIFIED_NUCLEUS_MAX_BYTES) {
    throw new Error("session-nucleus.json exceeds the verified read cap");
  }
  let descriptor;
  let rawText;
  try {
    descriptor = fs.openSync(
      filePath,
      fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0),
    );
    const stats = fs.fstatSync(descriptor);
    if (!stats.isFile() || stats.nlink !== 1) {
      throw new Error("session-nucleus.json must be a single-link regular file");
    }
    if (stats.size > VERIFIED_NUCLEUS_MAX_BYTES) {
      throw new Error("session-nucleus.json exceeds the verified read cap");
    }
    if (!sameFileIdentity(pathStats, stats)) {
      throw new Error("session-nucleus.json changed before verified read");
    }

    const bytes = Buffer.alloc(stats.size);
    let offset = 0;
    while (offset < bytes.length) {
      const count = fs.readSync(descriptor, bytes, offset, bytes.length - offset, offset);
      if (count === 0) {
        throw new Error("session-nucleus.json changed while reading");
      }
      offset += count;
    }
    const descriptorAfter = fs.fstatSync(descriptor);
    if (!descriptorAfter.isFile()
        || !sameFileIdentity(stats, descriptorAfter)
        || descriptorAfter.nlink !== 1
        || descriptorAfter.size !== stats.size) {
      throw new Error("session-nucleus.json changed while reading");
    }

    let finalPathStats;
    try {
      finalPathStats = fs.lstatSync(filePath);
    } catch {
      throw new Error("session-nucleus.json changed during verified read");
    }
    if (!finalPathStats.isFile() || finalPathStats.isSymbolicLink()
        || finalPathStats.nlink !== 1
        || !sameFileIdentity(stats, finalPathStats)) {
      throw new Error("session-nucleus.json changed during verified read");
    }

    for (const [directoryPath, identity, label] of [
      [rootPath, rootIdentity, "Hacker Bob sessions root"],
      [dirPath, dirIdentity, "Hacker Bob session directory"],
    ]) {
      const current = directoryIdentity(directoryPath, label, { duringRead: true });
      if (current.dev !== identity.dev || current.ino !== identity.ino) {
        throw new Error(`${label} changed during verified nucleus read`);
      }
    }
    rawText = bytes.toString("utf8");
  } catch (error) {
    if (error && ["ELOOP", "EMLINK"].includes(error.code)) {
      throw new Error("session-nucleus.json must not be a symbolic link");
    }
    if (error && error.code === "ENOENT") {
      throw new Error("session-nucleus.json changed before verified read");
    }
    throw error;
  } finally {
    if (descriptor != null) fs.closeSync(descriptor);
  }
  const raw = JSON.parse(rawText);
  const normalized = buildSessionNucleus(raw);
  if (raw == null || raw.nucleus_hash !== normalized.nucleus_hash) {
    throw new Error("session-nucleus.json nucleus_hash does not match its canonical content");
  }
  if (normalized.target_domain !== domain) {
    throw new Error("session-nucleus.json target_domain drift");
  }
  return normalized;
}

module.exports = {
  readSessionNucleus,
  readVerifiedSessionNucleus,
};
