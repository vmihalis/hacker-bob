"use strict";

// Frontier materialization debounce.
//
// F.2 contract: each producer that appends a frontier event must trigger a
// materialization, but at most one materialization should run per session-lock
// hold. Producers wrap their writes in withSessionLock(domain, ...); inside
// that hold, appendFrontierEvent calls withSessionLock reentrantly. We mark
// the domain dirty here and flush on the outermost lock release.
//
// Materialization is best-effort: if it throws (corrupt event log, disk full,
// etc.), the producer write is already committed and we must not regress it.
//
// Plane X Cycle X.2 hooks the TaskGraph materializer onto the same trigger so
// task-graph.json folds with the surface-index in one debounced flush per
// session-lock hold. A ledger-pressure refusal (≥18k events) raises in the
// task-graph materializer; we swallow it here for the same best-effort
// reason as surface-index failures — producers must not regress on a
// downstream view fault.

const {
  registerSessionLockReleaseHook,
} = require("./storage.js");
const {
  materializeFrontier,
} = require("./frontier-materializer.js");
const {
  materializeTaskGraph,
} = require("./task-graph-materializer.js");

const dirtyDomains = new Set();
let hookRegistered = false;

function ensureHookRegistered() {
  if (hookRegistered) return;
  hookRegistered = true;
  registerSessionLockReleaseHook((domain) => {
    if (!dirtyDomains.has(domain)) return;
    dirtyDomains.delete(domain);
    try {
      materializeFrontier(domain, { write: true });
    } catch {
      // Best-effort: materialization failure must not regress the producer.
      // The dirty flag is already cleared; the next producer event will
      // reschedule a fresh materialization attempt.
    }
    try {
      materializeTaskGraph(domain, { write: true });
    } catch {
      // X.2 ledger-pressure refusal lands here; like surface-index failures,
      // a downstream view fault must not regress the producer write.
    }
  });
}

function scheduleMaterialization(targetDomain) {
  if (typeof targetDomain !== "string" || !targetDomain.trim()) return;
  ensureHookRegistered();
  dirtyDomains.add(targetDomain);
}

function pendingDomains() {
  return Array.from(dirtyDomains);
}

function resetForTests() {
  dirtyDomains.clear();
}

module.exports = {
  pendingDomains,
  resetForTests,
  scheduleMaterialization,
};
