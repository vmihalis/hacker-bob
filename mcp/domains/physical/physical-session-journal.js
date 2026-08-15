"use strict";

const fs = require("fs");
const path = require("path");
const {
  assertSafeDomain,
  physicalSessionBootstrapPath,
  sessionDir,
  sessionsRoot,
} = require("../../core/io/paths.js");
const {
  normalizeIsoTimestamp,
} = require("../../core/io/validation.js");
const {
  withDocumentHash,
} = require("../../core/verification/document-hash.js");
const {
  normalizePhysicalScopeNucleusAxis,
} = require("../../lib/physical-scope-axis.js");
const {
  isPhysicalSessionTargetDomain,
} = require("../../lib/physical-session-identity.js");
const {
  hashCanonicalJson,
} = require("../../core/verification/verification-contracts.js");
const {
  normalizeOpaqueRef,
} = require("./physical-quantities.js");

const PHYSICAL_SESSION_BOOTSTRAP_JOURNAL_VERSION = 1;
const JOURNAL_STATUS_VALUES = Object.freeze(["pending", "complete"]);
const HASH_PATTERN = /^[a-f0-9]{64}$/;

function assertDigest(value, fieldName) {
  if (typeof value !== "string" || !HASH_PATTERN.test(value)) {
    throw new Error(`${fieldName} must be a lowercase SHA-256 digest`);
  }
  return value;
}

function normalizePhysicalSessionBootstrapJournal(input, {
  expectedDomain = null,
  requireComplete = false,
} = {}) {
  if (input == null || typeof input !== "object" || Array.isArray(input)) {
    throw new Error("physical session bootstrap journal must be an object");
  }
  const required = [
    "version",
    "bootstrap_kind",
    "status",
    "target_domain",
    "session_id",
    "physical_scope_import_ref_digest",
    "session_namespace_digest",
    "bootstrap_binding_digest",
    "bootstrap_payload_digest",
    "signed_import_digest",
    "replay_reservation_ref",
    "replay_reservation_receipt_digest",
    "nucleus_hash",
    "scope_policy_hash",
    "state_hash",
    "physical_scope",
    "started_at",
  ];
  const allowed = new Set([...required, "completed_at", "journal_hash"]);
  const unknown = Object.keys(input).filter((field) => !allowed.has(field)).sort();
  if (unknown.length > 0) {
    throw new Error(`physical session bootstrap journal has unknown fields: ${unknown.join(", ")}`);
  }
  const missing = required.filter((field) => !Object.prototype.hasOwnProperty.call(input, field));
  if (missing.length > 0) {
    throw new Error(`physical session bootstrap journal is missing fields: ${missing.join(", ")}`);
  }
  if (input.version !== PHYSICAL_SESSION_BOOTSTRAP_JOURNAL_VERSION) {
    throw new Error(`physical session bootstrap journal version must be ${PHYSICAL_SESSION_BOOTSTRAP_JOURNAL_VERSION}`);
  }
  if (input.bootstrap_kind !== "physical_only") {
    throw new Error("physical session bootstrap journal kind must be physical_only");
  }
  if (!JOURNAL_STATUS_VALUES.includes(input.status)) {
    throw new Error(`physical session bootstrap journal status must be one of ${JOURNAL_STATUS_VALUES.join(", ")}`);
  }
  if (requireComplete && input.status !== "complete") {
    throw new Error("physical session bootstrap journal is pending recovery");
  }
  const targetDomain = assertSafeDomain(input.target_domain);
  if (!isPhysicalSessionTargetDomain(targetDomain)) {
    throw new Error("physical session bootstrap journal target_domain is not a derived physical session id");
  }
  if (expectedDomain != null && targetDomain !== expectedDomain) {
    throw new Error("physical session bootstrap journal target_domain drift");
  }
  if (input.session_id !== targetDomain) {
    throw new Error("physical session bootstrap journal session_id must equal target_domain");
  }
  const replayReservationRef = normalizeOpaqueRef(
    input.replay_reservation_ref,
    "replay_reservation_ref",
  );
  const physicalScopeImportRefDigest = assertDigest(
    input.physical_scope_import_ref_digest,
    "physical_scope_import_ref_digest",
  );
  const sessionNamespaceDigest = assertDigest(input.session_namespace_digest, "session_namespace_digest");
  const expectedBootstrapBindingDigest = hashCanonicalJson({
    domain: "hacker-bob/physical-session-bootstrap-binding/v1",
    version: PHYSICAL_SESSION_BOOTSTRAP_JOURNAL_VERSION,
    target_domain: targetDomain,
    session_id: targetDomain,
    physical_scope_import_ref_digest: physicalScopeImportRefDigest,
    session_namespace_digest: sessionNamespaceDigest,
  });
  if (assertDigest(input.bootstrap_binding_digest, "bootstrap_binding_digest")
      !== expectedBootstrapBindingDigest) {
    throw new Error("bootstrap_binding_digest does not match the canonical physical session binding");
  }
  const journal = {
    version: PHYSICAL_SESSION_BOOTSTRAP_JOURNAL_VERSION,
    bootstrap_kind: "physical_only",
    status: input.status,
    target_domain: targetDomain,
    session_id: targetDomain,
    physical_scope_import_ref_digest: physicalScopeImportRefDigest,
    session_namespace_digest: sessionNamespaceDigest,
    bootstrap_binding_digest: expectedBootstrapBindingDigest,
    bootstrap_payload_digest: assertDigest(input.bootstrap_payload_digest, "bootstrap_payload_digest"),
    signed_import_digest: assertDigest(input.signed_import_digest, "signed_import_digest"),
    replay_reservation_ref: replayReservationRef,
    replay_reservation_receipt_digest: assertDigest(
      input.replay_reservation_receipt_digest,
      "replay_reservation_receipt_digest",
    ),
    nucleus_hash: assertDigest(input.nucleus_hash, "nucleus_hash"),
    scope_policy_hash: assertDigest(input.scope_policy_hash, "scope_policy_hash"),
    state_hash: assertDigest(input.state_hash, "state_hash"),
    physical_scope: normalizePhysicalScopeNucleusAxis(input.physical_scope),
    started_at: normalizeIsoTimestamp(input.started_at, "started_at", null),
  };
  if (input.status === "complete") {
    journal.completed_at = normalizeIsoTimestamp(input.completed_at, "completed_at", null);
    if (Date.parse(journal.completed_at) < Date.parse(journal.started_at)) {
      throw new Error("physical session bootstrap journal completed_at precedes started_at");
    }
  } else if (input.completed_at != null) {
    throw new Error("pending physical session bootstrap journal must not carry completed_at");
  }
  const normalized = withDocumentHash(journal, "journal_hash");
  if (input.journal_hash != null
      && assertDigest(input.journal_hash, "journal_hash") !== normalized.journal_hash) {
    throw new Error("physical session bootstrap journal hash does not match canonical content");
  }
  return normalized;
}

function buildPendingPhysicalSessionBootstrapJournal(input, { now = new Date() } = {}) {
  return normalizePhysicalSessionBootstrapJournal({
    ...input,
    version: PHYSICAL_SESSION_BOOTSTRAP_JOURNAL_VERSION,
    bootstrap_kind: "physical_only",
    status: "pending",
    started_at: normalizeIsoTimestamp(now, "started_at"),
  });
}

function completePhysicalSessionBootstrapJournal(pendingInput, { now = new Date() } = {}) {
  const pending = normalizePhysicalSessionBootstrapJournal(pendingInput);
  if (pending.status !== "pending") {
    throw new Error("only a pending physical session bootstrap journal can be completed");
  }
  const { journal_hash: _pendingHash, ...fields } = pending;
  return normalizePhysicalSessionBootstrapJournal({
    ...fields,
    status: "complete",
    completed_at: normalizeIsoTimestamp(now, "completed_at"),
  }, { requireComplete: true });
}

function writePhysicalSessionBootstrapJournal(domain, journalInput) {
  const journal = normalizePhysicalSessionBootstrapJournal(journalInput, { expectedDomain: domain });
  const filePath = physicalSessionBootstrapPath(domain);
  const content = `${JSON.stringify(journal, null, 2)}\n`;
  fs.mkdirSync(path.dirname(filePath), { recursive: true, mode: 0o700 });
  const tempPath = path.join(
    path.dirname(filePath),
    `.${path.basename(filePath)}.${process.pid}.${Date.now()}.${Math.random().toString(16).slice(2)}.tmp`,
  );
  let fileDescriptor;
  let directoryDescriptor;
  try {
    fileDescriptor = fs.openSync(tempPath, "wx", 0o600);
    fs.writeFileSync(fileDescriptor, content, "utf8");
    fs.fsyncSync(fileDescriptor);
    fs.closeSync(fileDescriptor);
    fileDescriptor = null;
    fs.renameSync(tempPath, filePath);
    directoryDescriptor = fs.openSync(path.dirname(filePath), fs.constants.O_RDONLY);
    fs.fsyncSync(directoryDescriptor);
  } finally {
    if (fileDescriptor != null) {
      try { fs.closeSync(fileDescriptor); } catch {}
    }
    if (directoryDescriptor != null) {
      try { fs.closeSync(directoryDescriptor); } catch {}
    }
    try { fs.unlinkSync(tempPath); } catch {}
  }
  return journal;
}

function readVerifiedPhysicalSessionBootstrapJournal(domain, { requireComplete = false } = {}) {
  const targetDomain = assertSafeDomain(domain);
  const rootPath = sessionsRoot();
  const dirPath = sessionDir(targetDomain);
  const filePath = physicalSessionBootstrapPath(targetDomain);
  const directoryIdentity = (directoryPath, label) => {
    const stats = fs.lstatSync(directoryPath);
    if (!stats.isDirectory() || stats.isSymbolicLink()) {
      throw new Error(`${label} must be a real directory`);
    }
    return { dev: stats.dev, ino: stats.ino };
  };
  const rootIdentity = directoryIdentity(rootPath, "Hacker Bob sessions root");
  const dirIdentity = directoryIdentity(dirPath, "Hacker Bob session directory");
  const pathStats = fs.lstatSync(filePath);
  if (!pathStats.isFile() || pathStats.isSymbolicLink() || pathStats.nlink !== 1) {
    throw new Error("physical-session-bootstrap.json must be a single-link regular file");
  }
  let descriptor;
  try {
    descriptor = fs.openSync(filePath, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0));
    const stats = fs.fstatSync(descriptor);
    if (!stats.isFile() || stats.nlink !== 1 || stats.size > 256 * 1024) {
      throw new Error("physical-session-bootstrap.json failed verified-read constraints");
    }
    if (stats.dev !== pathStats.dev || stats.ino !== pathStats.ino) {
      throw new Error("physical-session-bootstrap.json changed before verified read");
    }
    const document = JSON.parse(fs.readFileSync(descriptor, "utf8"));
    const normalized = normalizePhysicalSessionBootstrapJournal(document, {
      expectedDomain: targetDomain,
      requireComplete,
    });
    const finalPathStats = fs.lstatSync(filePath);
    if (!finalPathStats.isFile() || finalPathStats.isSymbolicLink()
        || finalPathStats.nlink !== 1
        || finalPathStats.dev !== stats.dev || finalPathStats.ino !== stats.ino) {
      throw new Error("physical-session-bootstrap.json changed during verified read");
    }
    for (const [directoryPath, identity, label] of [
      [rootPath, rootIdentity, "Hacker Bob sessions root"],
      [dirPath, dirIdentity, "Hacker Bob session directory"],
    ]) {
      const current = directoryIdentity(directoryPath, label);
      if (current.dev !== identity.dev || current.ino !== identity.ino) {
        throw new Error(`${label} changed during verified journal read`);
      }
    }
    return normalized;
  } finally {
    if (descriptor != null) fs.closeSync(descriptor);
  }
}

module.exports = {
  JOURNAL_STATUS_VALUES,
  PHYSICAL_SESSION_BOOTSTRAP_JOURNAL_VERSION,
  buildPendingPhysicalSessionBootstrapJournal,
  completePhysicalSessionBootstrapJournal,
  normalizePhysicalSessionBootstrapJournal,
  readVerifiedPhysicalSessionBootstrapJournal,
  writePhysicalSessionBootstrapJournal,
};
