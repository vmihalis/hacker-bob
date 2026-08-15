"use strict";

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const {
  redactTextSensitiveValues,
  validateNoSensitiveMaterial,
} = require("../redaction/sensitive-material.js");
const {
  beliefScratchDir,
  beliefSignalsJsonlPath,
  assertAgentWriteAllowed,
  sessionDir,
} = require("../io/paths.js");

const BELIEF_SIGNAL_KIND_VALUES = Object.freeze([
  "mechanism_projection",
  "belief_signal",
]);

const BELIEF_PROVENANCE_VALUES = Object.freeze([
  "observed_http",
  "observed_traffic",
  "declared_schema",
  "static_code",
  "surface_graph",
  "claim_ledger",
  "verification_result",
  "operator_asserted",
  "llm_inferred",
  "learned_prior",
  "verified_intervention",
  "residual_anomaly",
]);

const BELIEF_SIGNAL_ROLE_VALUES = Object.freeze([
  "evidence",
  "prior",
  "diagnostic",
]);

function assertBeliefSignalKind(kind) {
  if (!BELIEF_SIGNAL_KIND_VALUES.includes(kind)) {
    throw new Error(`invalid belief signal kind: ${kind}`);
  }
  return kind;
}

function assertBeliefProvenance(provenance) {
  if (!BELIEF_PROVENANCE_VALUES.includes(provenance)) {
    throw new Error(`invalid belief provenance: ${provenance}`);
  }
  return provenance;
}

function assertBeliefSignalRole(role) {
  if (!BELIEF_SIGNAL_ROLE_VALUES.includes(role)) {
    throw new Error(`invalid belief signal role: ${role}`);
  }
  return role;
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

function redactStringLeaves(value) {
  if (typeof value === "string") {
    return redactTextSensitiveValues(value);
  }
  if (Array.isArray(value)) {
    return value.map(redactStringLeaves);
  }
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value).map(([key, child]) => [key, redactStringLeaves(child)]),
    );
  }
  return value;
}

function assertBeliefScratchWritePath({ target_domain, file_path }) {
  const targetDomain = normalizeTargetDomain(target_domain);
  if (typeof file_path !== "string" || !file_path.trim()) {
    throw new Error("file_path is required");
  }
  const root = path.resolve(sessionDir(targetDomain));
  const scratch = path.resolve(beliefScratchDir(targetDomain));
  const resolved = path.resolve(file_path);
  // Y-P13 (T4): single in-process audit-graded decision. Belief has no composer
  // identity, so a null callerToolName fail-closes any audit-graded target.
  // Re-message to keep the belief-specific guidance.
  try {
    assertAgentWriteAllowed(resolved, targetDomain, null);
  } catch {
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

function normalizeSignal({ kind, source, provenance, artifact_ref, role = "evidence", payload }) {
  assertBeliefSignalKind(kind);
  assertBeliefProvenance(provenance);
  assertBeliefSignalRole(role);
  if (provenance === "residual_anomaly" && role !== "diagnostic") {
    throw new Error("residual_anomaly is diagnostic-only and cannot enter the belief window as evidence or prior");
  }
  // CB-B7: an agent-elicited belief is advisory. It may be a prior or a diagnostic,
  // never evidence -- the honesty rail that keeps llm_inferred from masquerading as a
  // verified_intervention-grade fact. The downstream demotion holds: when a
  // latent has both an elicited prior AND a verified_intervention, the belief-window
  // posterior follows the verified state (test/belief-evidence-dominates-prior.test.js).
  if (provenance === "llm_inferred" && role === "evidence") {
    throw new Error("llm_inferred is advisory and cannot enter the belief window as evidence; use role 'prior' or 'diagnostic'");
  }
  if (typeof source !== "string" || !source.trim()) {
    throw new Error("source is required");
  }
  if (typeof artifact_ref !== "string" || !artifact_ref.trim()) {
    throw new Error("artifact_ref is required");
  }
  assertPlainObject(payload, "payload");
  const redactedPayload = redactStringLeaves(payload);
  const redactedSource = redactTextSensitiveValues(source.trim());
  const redactedArtifactRef = redactTextSensitiveValues(artifact_ref.trim());
  const body = {
    kind,
    source: redactedSource,
    provenance,
    artifact_ref: redactedArtifactRef,
    role,
    payload: redactedPayload,
  };
  validateNoSensitiveMaterial(body, "belief_signal");
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

function writeBeliefSignalScratch({ target_domain, kind, source, provenance, artifact_ref, role, payload }) {
  const targetDomain = normalizeTargetDomain(target_domain);
  const filePath = assertBeliefScratchWritePath({
    target_domain: targetDomain,
    file_path: beliefSignalsJsonlPath(targetDomain),
  });
  const signal = normalizeSignal({ kind, source, provenance, artifact_ref, role, payload });
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

function queryBeliefSignals({ target_domain, kind, source, provenance, role, limit } = {}) {
  const read = readBeliefSignals({ target_domain, limit });
  return {
    ...read,
    signals: read.signals.filter((signal) => {
      if (kind && signal.kind !== kind) return false;
      if (source && signal.source !== source) return false;
      if (provenance && signal.provenance !== provenance) return false;
      if (role && signal.role !== role) return false;
      return true;
    }),
  };
}

module.exports = {
  BELIEF_PROVENANCE_VALUES,
  BELIEF_SIGNAL_KIND_VALUES,
  BELIEF_SIGNAL_ROLE_VALUES,
  assertBeliefScratchWritePath,
  assertBeliefProvenance,
  queryBeliefSignals,
  readBeliefSignals,
  writeBeliefSignalScratch,
  _internals: {
    canonicalJson,
    normalizeSignal,
  },
};
