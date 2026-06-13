"use strict";

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const {
  beliefScratchDir,
  beliefSignalsJsonlPath,
  isAuditGradedPath,
  sessionDir,
} = require("../paths.js");

const BELIEF_SIGNAL_KIND_VALUES = Object.freeze([
  "mechanism_projection",
  "belief_signal",
]);

function assertBeliefSignalKind(kind) {
  if (!BELIEF_SIGNAL_KIND_VALUES.includes(kind)) {
    throw new Error(`invalid belief signal kind: ${kind}`);
  }
  return kind;
}

function normalizeTargetDomain(targetDomain) {
  if (typeof targetDomain !== "string" || !targetDomain.trim()) {
    throw new Error("target_domain is required");
  }
  return targetDomain.trim();
}

function assertPlainObject(value, fieldName) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${fieldName} must be a plain object`);
  }
}

function canonicalJson(value) {
  if (Array.isArray(value)) {
    return `[${value.map(canonicalJson).join(",")}]`;
  }
  if (value && typeof value === "object") {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

function sha256Hex(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function assertBeliefScratchWritePath({ target_domain, file_path }) {
  const targetDomain = normalizeTargetDomain(target_domain);
  if (typeof file_path !== "string" || !file_path.trim()) {
    throw new Error("file_path is required");
  }
  const root = path.resolve(sessionDir(targetDomain));
  const scratch = path.resolve(beliefScratchDir(targetDomain));
  const resolved = path.resolve(file_path);
  if (isAuditGradedPath(resolved, targetDomain)) {
    throw new Error("belief outputs are advisory scratch and cannot write audit-graded artifacts");
  }
  if (resolved !== scratch && !resolved.startsWith(`${scratch}${path.sep}`)) {
    throw new Error("belief outputs must be written under belief-scratch");
  }
  if (resolved === root) {
    throw new Error("belief outputs cannot target the session root");
  }
  return resolved;
}

function normalizeSignal({ kind, source, payload }) {
  assertBeliefSignalKind(kind);
  if (typeof source !== "string" || !source.trim()) {
    throw new Error("source is required");
  }
  assertPlainObject(payload, "payload");
  const body = {
    kind,
    source: source.trim(),
    payload,
  };
  return Object.freeze({
    ...body,
    advisory: true,
    derived: true,
    scratch: true,
    content_hash: sha256Hex(canonicalJson(body)),
  });
}

function appendJsonl(filePath, record) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.appendFileSync(filePath, `${JSON.stringify(record)}\n`);
}

function writeBeliefSignalScratch({ target_domain, kind, source, payload }) {
  const targetDomain = normalizeTargetDomain(target_domain);
  const filePath = assertBeliefScratchWritePath({
    target_domain: targetDomain,
    file_path: beliefSignalsJsonlPath(targetDomain),
  });
  const signal = normalizeSignal({ kind, source, payload });
  appendJsonl(filePath, signal);
  return {
    target_domain: targetDomain,
    artifact_path: filePath,
    signal_hash: signal.content_hash,
    advisory: true,
    derived: true,
    scratch: true,
  };
}

function readBeliefSignals({ target_domain, limit = 100 } = {}) {
  const targetDomain = normalizeTargetDomain(target_domain);
  const max = Number.isInteger(limit) && limit > 0 ? Math.min(limit, 1000) : 100;
  const filePath = beliefSignalsJsonlPath(targetDomain);
  if (!fs.existsSync(filePath)) {
    return {
      target_domain: targetDomain,
      artifact_path: filePath,
      signals: [],
    };
  }
  const lines = fs.readFileSync(filePath, "utf8").split(/\n/).filter(Boolean);
  return {
    target_domain: targetDomain,
    artifact_path: filePath,
    signals: lines.slice(-max).map((line) => JSON.parse(line)),
  };
}

function queryBeliefSignals({ target_domain, kind, source, limit } = {}) {
  const read = readBeliefSignals({ target_domain, limit });
  return {
    ...read,
    signals: read.signals.filter((signal) => {
      if (kind && signal.kind !== kind) return false;
      if (source && signal.source !== source) return false;
      return true;
    }),
  };
}

module.exports = {
  BELIEF_SIGNAL_KIND_VALUES,
  assertBeliefScratchWritePath,
  queryBeliefSignals,
  readBeliefSignals,
  writeBeliefSignalScratch,
  _internals: {
    canonicalJson,
    normalizeSignal,
  },
};
