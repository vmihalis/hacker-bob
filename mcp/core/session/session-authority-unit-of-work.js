"use strict";

const fs = require("fs");
const path = require("path");
const {
  assertSafeDomain,
  sessionEventsJsonlPath,
  sessionNucleusPath,
  statePath,
} = require("../io/paths.js");
const {
  attachBestEffortErrorDiagnostic,
  rollbackFileCasAtomicReceipt,
  withSessionLock,
  writeFileCasAtomicReceipt,
  writeFileExclusiveAtomicReceipt,
} = require("../io/storage.js");
const {
  buildSessionNucleus,
  readVerifiedSessionNucleus,
  sessionNucleusFromState,
} = require("../governance/index.js");
const {
  normalizeSessionEvent,
  SESSION_EVENTS_MAX_RECORDS,
} = require("./session-events.js");
const {
  composeSessionStateDocument,
} = require("./session-state-contracts.js");

function snapshotFile(filePath) {
  let pathStats;
  try {
    pathStats = fs.lstatSync(filePath);
  } catch (error) {
    if (error && error.code === "ENOENT") {
      return {
        exists: false,
        bytes: null,
      };
    }
    throw new Error(`${filePath} could not be verified for rollback`);
  }

  const label = path.basename(filePath);
  if (pathStats.isSymbolicLink()) {
    throw new Error(`${label} must not be a symbolic link`);
  }
  if (!pathStats.isFile() || pathStats.nlink !== 1) {
    throw new Error(`${label} must be a single-link regular file`);
  }

  let descriptor;
  try {
    descriptor = fs.openSync(
      filePath,
      fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0),
    );
    const stats = fs.fstatSync(descriptor);
    if (!stats.isFile() || stats.nlink !== 1) {
      throw new Error(`${label} must be a single-link regular file`);
    }
    if (!sameFileIdentity(pathStats, stats)) {
      throw new Error(`${label} changed before rollback snapshot`);
    }

    const bytes = Buffer.alloc(stats.size);
    let offset = 0;
    while (offset < bytes.length) {
      const count = fs.readSync(descriptor, bytes, offset, bytes.length - offset, offset);
      if (count === 0) {
        throw new Error(`${label} changed while reading rollback snapshot`);
      }
      offset += count;
    }

    const descriptorAfter = fs.fstatSync(descriptor);
    if (!descriptorAfter.isFile()
        || !sameFileIdentity(stats, descriptorAfter)
        || descriptorAfter.nlink !== 1
        || descriptorAfter.size !== stats.size) {
      throw new Error(`${label} changed while reading rollback snapshot`);
    }

    let finalPathStats;
    try {
      finalPathStats = fs.lstatSync(filePath);
    } catch {
      throw new Error(`${label} changed during rollback snapshot`);
    }
    if (!finalPathStats.isFile()
        || finalPathStats.isSymbolicLink()
        || finalPathStats.nlink !== 1
        || !sameFileIdentity(stats, finalPathStats)) {
      throw new Error(`${label} changed during rollback snapshot`);
    }

    return {
      exists: true,
      bytes,
      dev: stats.dev,
      ino: stats.ino,
    };
  } catch (error) {
    if (error && ["ELOOP", "EMLINK"].includes(error.code)) {
      throw new Error(`${label} must not be a symbolic link`);
    }
    if (error && error.code === "ENOENT") {
      throw new Error(`${label} changed before rollback snapshot`);
    }
    throw error;
  } finally {
    if (descriptor != null) fs.closeSync(descriptor);
  }
}

function sameFileIdentity(left, right) {
  return left.dev === right.dev
    && left.ino === right.ino
    && left.nlink === right.nlink;
}

function attachExclusiveReceipt(error, receipt, label) {
  if (!error || typeof error !== "object") return error;
  attachBestEffortErrorDiagnostic(error, "exclusive_receipt", {
    label,
    status: receipt.status,
    phase: receipt.phase,
    path: receipt.path,
    tempPath: receipt.tempPath,
    tempCandidate: receipt.tempCandidate,
    finalCandidate: receipt.finalCandidate,
    unresolvedTemp: receipt.unresolvedTemp,
  });
  if (receipt.closeError) {
    attachBestEffortErrorDiagnostic(error, "close_error", receipt.closeError.message || String(receipt.closeError));
  }
  if (receipt.probeError) {
    attachBestEffortErrorDiagnostic(error, "probe_error", receipt.probeError.message || String(receipt.probeError));
  }
  if (receipt.cleanupError) {
    attachBestEffortErrorDiagnostic(error, "cleanup_error", receipt.cleanupError.message || String(receipt.cleanupError));
  }
  return error;
}

function attachCasReceipt(error, receipt, label) {
  if (!error || typeof error !== "object") return error;
  attachBestEffortErrorDiagnostic(error, "cas_receipt", {
    label,
    status: receipt.status,
    phase: receipt.phase,
    path: receipt.path,
    stagePath: receipt.stagePath,
    quarantinePath: receipt.quarantinePath,
    stagedCandidate: receipt.stagedCandidate,
    displacedCandidate: receipt.displacedCandidate,
    producedCandidate: receipt.producedCandidate,
    displaced: receipt.displaced,
  });
  if (receipt.probeError) {
    attachBestEffortErrorDiagnostic(error, "probe_error", receipt.probeError.message || String(receipt.probeError));
  }
  if (receipt.cleanupError) {
    attachBestEffortErrorDiagnostic(error, "cleanup_error", receipt.cleanupError.message || String(receipt.cleanupError));
  }
  return error;
}

function plannedFreshAuthorityPublications({
  canonicalNucleus,
  projection,
  sessionEvent,
  stateFile,
  nucleusFile,
  eventsFile,
}) {
  const publications = [];
  if (projection !== null) {
    const nextDocument = composeSessionStateDocument(projection.rawDocument, projection.nextState);
    publications.push({
      label: "state.json",
      path: stateFile,
      content: `${JSON.stringify(nextDocument, null, 2)}\n`,
    });
  }
  publications.push({
    label: "session-nucleus.json",
    path: nucleusFile,
    content: `${JSON.stringify(canonicalNucleus, null, 2)}\n`,
  });
  publications.push({
    label: "session-events.jsonl",
    path: eventsFile,
    content: `${JSON.stringify(sessionEvent)}\n`,
  });
  return publications;
}

function preflightFinalCandidate(filePath, stats) {
  return {
    path: filePath,
    dev: stats.dev,
    ino: stats.ino,
    owned: false,
  };
}

function preflightCollisionReceipt(publication, stats) {
  return {
    status: "exists",
    phase: "preflight",
    path: publication.path,
    tempPath: null,
    tempCandidate: null,
    finalCandidate: preflightFinalCandidate(publication.path, stats),
  };
}

// Publication order also defines the preflight scan order: expose the
// compatibility state projection before SessionNucleus when a projection is
// planned. Diagnostic priority is separate and reports SessionNucleus first
// because it is the canonical security authority.
function authorityDiagnosticPriority(publication) {
  if (publication.label === "session-nucleus.json") return 0;
  if (publication.label === "state.json") return 1;
  return 2;
}

function compareAuthorityDiagnosticPriority(left, right) {
  return authorityDiagnosticPriority(left.publication)
    - authorityDiagnosticPriority(right.publication);
}

function assertFreshAuthorityPreimagesAbsent(publications) {
  const findings = [];
  for (const publication of publications) {
    let stats;
    try {
      stats = fs.lstatSync(publication.path);
    } catch (error) {
      if (error && error.code === "ENOENT") continue;
      throw error;
    }

    if (stats.isSymbolicLink()) {
      findings.push({
        type: "unsafe",
        publication,
        error: new Error(`${publication.label} must not be a symbolic link`),
      });
    } else if (!stats.isFile() || stats.nlink !== 1) {
      findings.push({
        type: "unsafe",
        publication,
        error: new Error(`${publication.label} must be a single-link regular file`),
      });
    } else {
      findings.push({
        type: "file",
        publication,
        stats,
      });
    }
  }

  const unsafe = findings
    .filter((finding) => finding.type === "unsafe")
    .sort(compareAuthorityDiagnosticPriority)[0];
  if (unsafe) throw unsafe.error;

  const file = findings
    .filter((finding) => finding.type === "file")
    .sort(compareAuthorityDiagnosticPriority)[0];
  if (file) {
    throw attachExclusiveReceipt(
      new Error(`${file.publication.label} already exists`),
      preflightCollisionReceipt(file.publication, file.stats),
      file.publication.label,
    );
  }
}

function publishFreshAuthorityFile(publication, receipts) {
  const receipt = writeFileExclusiveAtomicReceipt(publication.path, publication.content);
  receipts.push({ label: publication.label, receipt });
  if (receipt.status === "created") return;
  if (receipt.status === "exists") {
    throw attachExclusiveReceipt(new Error(`${publication.label} already exists`), receipt, publication.label);
  }
  throw attachExclusiveReceipt(
    receipt.error || new Error(`${publication.label} exclusive publish failed during ${receipt.phase}`),
    receipt,
    publication.label,
  );
}

function unlinkOwnedExclusiveCandidate(candidate, candidatePath) {
  if (!candidate || candidate.owned !== true || !candidatePath) return null;
  try {
    const stats = fs.lstatSync(candidatePath);
    if (
      stats.isFile()
      && !stats.isSymbolicLink()
      && stats.dev === candidate.dev
      && stats.ino === candidate.ino
    ) {
      fs.unlinkSync(candidatePath);
    }
  } catch (error) {
    if (error && error.code === "ENOENT") return null;
    return error;
  }
  return null;
}

function rollbackFinalCandidateFromTemp(receipt) {
  if (!receipt
      || receipt.status !== "failed"
      || !["link", "postlink_proof"].includes(receipt.phase)
      || !receipt.path
      || (receipt.finalCandidate && receipt.finalCandidate.owned === true)
      || !receipt.tempCandidate
      || receipt.tempCandidate.owned !== true) {
    return null;
  }
  return {
    ...receipt.tempCandidate,
    path: receipt.path,
    owned: true,
  };
}

function rollbackOwnedExclusiveReceiptCandidates(receipts) {
  let rollbackError = null;
  for (const { receipt } of receipts.slice().reverse()) {
    if (!receipt) continue;
    const finalError = unlinkOwnedExclusiveCandidate(
      receipt.finalCandidate,
      receipt.finalCandidate && receipt.finalCandidate.path,
    );
    if (finalError !== null && rollbackError === null) rollbackError = finalError;

    const inferredFinalError = unlinkOwnedExclusiveCandidate(
      rollbackFinalCandidateFromTemp(receipt),
      receipt.path,
    );
    if (inferredFinalError !== null && rollbackError === null) rollbackError = inferredFinalError;

    const tempError = unlinkOwnedExclusiveCandidate(
      receipt.tempCandidate,
      receipt.tempPath,
    );
    if (tempError !== null && rollbackError === null) rollbackError = tempError;
  }
  return rollbackError;
}

function commitFreshSessionAuthority({
  domain,
  canonicalNucleus,
  projection,
  sessionEvent,
  stateFile,
  nucleusFile,
  eventsFile,
}) {
  const publications = plannedFreshAuthorityPublications({
    canonicalNucleus,
    projection,
    sessionEvent,
    stateFile,
    nucleusFile,
    eventsFile,
  });
  assertFreshAuthorityPreimagesAbsent(publications);

  const receipts = [];
  try {
    for (const publication of publications) {
      publishFreshAuthorityFile(publication, receipts);
    }
  } catch (error) {
    const rollbackError = rollbackOwnedExclusiveReceiptCandidates(receipts);
    if (rollbackError !== null && error && typeof error === "object") {
      attachBestEffortErrorDiagnostic(error, "rollback_error", rollbackError.message || String(rollbackError));
    }
    throw error;
  }

  return {
    target_domain: domain,
    nucleus_hash: canonicalNucleus.nucleus_hash,
    event_id: sessionEvent.event_id,
    state_written: projection !== null,
  };
}

function assertExpectedNucleusHash(expectedNucleusHash) {
  if (expectedNucleusHash === null || typeof expectedNucleusHash === "string") {
    return;
  }
  throw new Error("expectedNucleusHash must be null or a string");
}

function canonicalizeStateProjection(stateProjection, canonicalNucleus) {
  if (stateProjection === null) return null;
  if (stateProjection == null || typeof stateProjection !== "object" || Array.isArray(stateProjection)) {
    throw new Error("stateProjection must be null or an object");
  }
  if (!Object.prototype.hasOwnProperty.call(stateProjection, "rawDocument")
      || !Object.prototype.hasOwnProperty.call(stateProjection, "nextState")) {
    throw new Error("stateProjection must include rawDocument and nextState");
  }
  // canonicalNucleus may carry nucleus-only axes (physical_scope, repo_hash)
  // that state.json never represents; re-derive the state-side view with
  // those same axes supplied so parity is checked on equal terms rather than
  // spuriously failing whenever a state-backed rewrite preserves them.
  const stateNucleus = sessionNucleusFromState(stateProjection.nextState, {
    physical_scope: canonicalNucleus.physical_scope,
    repo_hash: canonicalNucleus.repo_hash,
  });
  if (stateNucleus.target_domain !== canonicalNucleus.target_domain) {
    throw new Error("stateProjection target_domain does not match nextNucleus");
  }
  if (stateNucleus.nucleus_hash !== canonicalNucleus.nucleus_hash) {
    throw new Error("stateProjection nucleus_hash does not match nextNucleus");
  }
  return stateProjection;
}

function bindSessionEvent(input, canonicalNucleus) {
  if (input == null || typeof input !== "object" || Array.isArray(input)) {
    throw new Error("event must be an object");
  }
  const targetDomain = canonicalNucleus.target_domain;
  const nucleusHash = canonicalNucleus.nucleus_hash;
  if (input.target_domain != null && assertSafeDomain(input.target_domain) !== targetDomain) {
    throw new Error("event target_domain does not match nextNucleus");
  }
  if (input.nucleus_hash != null && String(input.nucleus_hash) !== nucleusHash) {
    throw new Error("event nucleus_hash does not match nextNucleus");
  }

  const payload = input.payload == null ? {} : input.payload;
  if (payload == null || typeof payload !== "object" || Array.isArray(payload)) {
    throw new Error("event payload must be an object");
  }
  if (payload.nucleus_hash != null && String(payload.nucleus_hash) !== nucleusHash) {
    throw new Error("event payload nucleus_hash does not match nextNucleus");
  }

  return normalizeSessionEvent({
    ...input,
    target_domain: targetDomain,
    nucleus_hash: nucleusHash,
    payload: {
      ...payload,
      nucleus_hash: nucleusHash,
    },
  }, { targetDomain });
}

// Parses and self-verifies a nucleus-file snapshot (tamper-checks its own
// hash and target_domain) without asserting it binds any particular expected
// hash. Returns null when the snapshot is absent. Shared by
// assertSnapshotBindsExpectedNucleus (which additionally requires presence
// and a hash match) and the legacy-migration commit path (which treats
// absence as a valid starting point but still refuses to silently overwrite
// a present-but-malformed/tampered artifact).
function parseVerifiedNucleusSnapshot(snapshot, domain) {
  if (!snapshot.exists) return null;
  let raw;
  try {
    raw = JSON.parse(snapshot.bytes.toString("utf8"));
  } catch (error) {
    throw new Error(`Malformed session-nucleus.json: ${error.message || String(error)}`);
  }
  const normalized = buildSessionNucleus(raw);
  if (!raw || raw.nucleus_hash !== normalized.nucleus_hash) {
    throw new Error("session-nucleus.json nucleus_hash does not match its canonical content");
  }
  if (normalized.target_domain !== domain) {
    throw new Error("session-nucleus.json target_domain drift");
  }
  return normalized;
}

function assertSnapshotBindsExpectedNucleus(snapshot, domain, expectedNucleusHash) {
  const normalized = parseVerifiedNucleusSnapshot(snapshot, domain);
  if (normalized === null) {
    throw new Error("session nucleus changed before authority transaction");
  }
  if (normalized.nucleus_hash !== expectedNucleusHash) {
    throw new Error("session nucleus CAS mismatch");
  }
}

function appendEventBytes(snapshot, sessionEvent) {
  const eventLine = Buffer.from(`${JSON.stringify(sessionEvent)}\n`, "utf8");
  let combined;
  if (!snapshot.exists) {
    combined = eventLine;
  } else {
    // A valid-but-unterminated trailing line (no closing \n) is tolerated on
    // READ (split+filter below, and readJsonlStrict elsewhere), but a raw
    // concat here would fuse it with the next line's opening byte and
    // corrupt both records. Insert the missing separator so an append after
    // an unterminated tail always lands on its own line.
    const needsSeparator = snapshot.bytes.length > 0
      && snapshot.bytes[snapshot.bytes.length - 1] !== 0x0a;
    combined = needsSeparator
      ? Buffer.concat([snapshot.bytes, Buffer.from("\n", "utf8"), eventLine])
      : Buffer.concat([snapshot.bytes, eventLine]);
  }
  const lines = combined.toString("utf8").split("\n").filter((line) => line.trim());
  if (lines.length <= SESSION_EVENTS_MAX_RECORDS) return combined;
  return Buffer.from(`${lines.slice(-SESSION_EVENTS_MAX_RECORDS).join("\n")}\n`, "utf8");
}

function plannedUpdateAuthorityPublications({
  canonicalNucleus,
  projection,
  sessionEvent,
  stateFile,
  nucleusFile,
  eventsFile,
  snapshots,
}) {
  const publications = [];
  if (projection !== null) {
    const nextDocument = composeSessionStateDocument(projection.rawDocument, projection.nextState);
    publications.push({
      label: "state.json",
      path: stateFile,
      content: Buffer.from(`${JSON.stringify(nextDocument, null, 2)}\n`, "utf8"),
      expected: snapshots.get(stateFile),
    });
  }
  publications.push({
    label: "session-nucleus.json",
    path: nucleusFile,
    content: Buffer.from(`${JSON.stringify(canonicalNucleus, null, 2)}\n`, "utf8"),
    expected: snapshots.get(nucleusFile),
  });
  publications.push({
    label: "session-events.jsonl",
    path: eventsFile,
    content: appendEventBytes(snapshots.get(eventsFile), sessionEvent),
    expected: snapshots.get(eventsFile),
  });
  return publications;
}

function rollbackCasPublications(receipts) {
  let rollbackError = null;
  for (const { receipt } of receipts.slice().reverse()) {
    const error = rollbackFileCasAtomicReceipt(receipt);
    if (error !== null && rollbackError === null) rollbackError = error;
  }
  return rollbackError;
}

function commitUpdatedSessionAuthority({
  domain,
  canonicalNucleus,
  projection,
  sessionEvent,
  expectedNucleusHash,
  stateFile,
  nucleusFile,
  eventsFile,
}) {
  const snapshotPaths = projection === null
    ? [nucleusFile, eventsFile]
    : [stateFile, nucleusFile, eventsFile];
  const snapshots = new Map();
  for (const filePath of snapshotPaths) snapshots.set(filePath, snapshotFile(filePath));
  assertSnapshotBindsExpectedNucleus(
    snapshots.get(nucleusFile),
    domain,
    expectedNucleusHash,
  );

  const publications = plannedUpdateAuthorityPublications({
    canonicalNucleus,
    projection,
    sessionEvent,
    stateFile,
    nucleusFile,
    eventsFile,
    snapshots,
  });
  const receipts = [];
  try {
    for (const publication of publications) {
      const receipt = writeFileCasAtomicReceipt(
        publication.path,
        publication.content,
        publication.expected,
      );
      receipts.push({ label: publication.label, receipt });
      if (["created", "replaced"].includes(receipt.status)) continue;
      throw attachCasReceipt(
        receipt.error || new Error(`${publication.label} CAS publish failed during ${receipt.phase}`),
        receipt,
        publication.label,
      );
    }
  } catch (error) {
    const rollbackError = rollbackCasPublications(receipts);
    if (rollbackError !== null && error && typeof error === "object") {
      attachBestEffortErrorDiagnostic(error, "rollback_error", rollbackError.message || String(rollbackError));
    }
    throw error;
  }

  return {
    target_domain: domain,
    nucleus_hash: canonicalNucleus.nucleus_hash,
    event_id: sessionEvent.event_id,
    state_written: projection !== null,
  };
}

function commitSessionAuthority({
  targetDomain,
  nextNucleus,
  stateProjection = null,
  event,
  expectedNucleusHash,
}) {
  const domain = assertSafeDomain(targetDomain);
  assertExpectedNucleusHash(expectedNucleusHash);

  return withSessionLock(domain, () => {
    const canonicalNucleus = buildSessionNucleus(nextNucleus);
    if (canonicalNucleus.target_domain !== domain) {
      throw new Error("nextNucleus target_domain does not match targetDomain");
    }

    const nucleusFile = sessionNucleusPath(domain);
    if (expectedNucleusHash !== null) {
      const currentNucleus = readVerifiedSessionNucleus(domain);
      if (currentNucleus.nucleus_hash !== expectedNucleusHash) {
        throw new Error("session nucleus CAS mismatch");
      }
    }

    const projection = canonicalizeStateProjection(stateProjection, canonicalNucleus);
    const sessionEvent = bindSessionEvent(event, canonicalNucleus);

    const stateFile = statePath(domain);
    const eventsFile = sessionEventsJsonlPath(domain);

    if (expectedNucleusHash === null) {
      return commitFreshSessionAuthority({
        domain,
        canonicalNucleus,
        projection,
        sessionEvent,
        stateFile,
        nucleusFile,
        eventsFile,
      });
    }

    return commitUpdatedSessionAuthority({
      domain,
      canonicalNucleus,
      projection,
      sessionEvent,
      expectedNucleusHash,
      stateFile,
      nucleusFile,
      eventsFile,
    });
  });
}

// Commits a legacy-session-authority migration/repair: binds a nucleus
// DERIVED from prior history (never trusted raw off disk) to the domain,
// creating session-nucleus.json when absent, CAS-replacing it when present
// but hash-mismatched, and leaving it untouched when it already matches —
// then atomically appends the caller-built migration/repair event. Reuses
// the same snapshotFile/CAS/rollback primitives commitUpdatedSessionAuthority
// is built from rather than a second write path. The caller (session-
// authority-migration.js) owns the idempotency decision (whether to call
// this at all) by inspecting the validated prior event audit; this function
// only decides whether the nucleus FILE itself needs to move.
function commitLegacySessionAuthorityMigration({
  domain,
  derivedNucleus,
  migrationEvent,
  priorEvents,
  bindingEventKinds,
}) {
  const nucleusFile = sessionNucleusPath(domain);
  const eventsFile = sessionEventsJsonlPath(domain);

  return withSessionLock(domain, () => {
    const nucleusSnapshot = snapshotFile(nucleusFile);
    // A present-but-malformed/tampered nucleus artifact is never silently
    // overwritten — parseVerifiedNucleusSnapshot throws in that case, which
    // propagates out of this whole function with zero writes attempted.
    const currentNucleus = parseVerifiedNucleusSnapshot(nucleusSnapshot, domain);
    const currentNucleusHash = currentNucleus ? currentNucleus.nucleus_hash : null;
    const nucleusChanged = currentNucleusHash !== derivedNucleus.nucleus_hash;

    // True idempotent no-op: the nucleus FILE on disk already carries the
    // derived hash AND the validated audit already durably binds that same
    // hash. Both must hold together, checked under this same lock, so a
    // nucleus file that was deleted/replaced out from under a stale audit
    // can never be mistaken for "already migrated" — it falls through to a
    // repair below instead.
    const auditAlreadyBound = priorEvents.some((event) => (
      bindingEventKinds.includes(event.kind) && event.nucleus_hash === derivedNucleus.nucleus_hash
    ));
    if (!nucleusChanged && auditAlreadyBound) {
      return {
        target_domain: domain,
        nucleus_hash: derivedNucleus.nucleus_hash,
        migrated: false,
        repaired: false,
        event_id: null,
      };
    }

    const eventsSnapshot = snapshotFile(eventsFile);
    const eventsContent = appendEventBytes(eventsSnapshot, migrationEvent);

    const receipts = [];
    try {
      if (nucleusChanged) {
        const nucleusReceipt = writeFileCasAtomicReceipt(
          nucleusFile,
          `${JSON.stringify(derivedNucleus, null, 2)}\n`,
          nucleusSnapshot,
        );
        receipts.push({ label: "session-nucleus.json", receipt: nucleusReceipt });
        if (!["created", "replaced"].includes(nucleusReceipt.status)) {
          throw attachCasReceipt(
            nucleusReceipt.error
              || new Error(`session-nucleus.json CAS publish failed during ${nucleusReceipt.phase}`),
            nucleusReceipt,
            "session-nucleus.json",
          );
        }
      }
      const eventsReceipt = writeFileCasAtomicReceipt(eventsFile, eventsContent, eventsSnapshot);
      receipts.push({ label: "session-events.jsonl", receipt: eventsReceipt });
      if (!["created", "replaced"].includes(eventsReceipt.status)) {
        throw attachCasReceipt(
          eventsReceipt.error
            || new Error(`session-events.jsonl CAS publish failed during ${eventsReceipt.phase}`),
          eventsReceipt,
          "session-events.jsonl",
        );
      }
    } catch (error) {
      const rollbackError = rollbackCasPublications(receipts);
      if (rollbackError !== null && error && typeof error === "object") {
        attachBestEffortErrorDiagnostic(error, "rollback_error", rollbackError.message || String(rollbackError));
      }
      throw error;
    }

    return {
      target_domain: domain,
      nucleus_hash: derivedNucleus.nucleus_hash,
      migrated: currentNucleusHash == null,
      repaired: currentNucleusHash != null,
      event_id: migrationEvent.event_id,
    };
  });
}

module.exports = {
  commitLegacySessionAuthorityMigration,
  commitSessionAuthority,
};
