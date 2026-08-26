"use strict";

// Locked entry point for making a session's legacy authority explicit: a
// session that predates (or somehow lost) session-nucleus.json has its
// nucleus DERIVED from prior validated history and bound exactly once,
// reusing session-authority-unit-of-work.js's CAS/exclusive commit
// machinery rather than a second write path. This is the only place a
// legacy session gains a durable, verifiable nucleus binding — every other
// consumer of session state either already has one or must call this first.

const {
  assertSafeDomain,
  sessionEventsJsonlPath,
} = require("../io/paths.js");
const {
  readJsonlStrict,
  withSessionLock,
} = require("../io/storage.js");
const {
  sessionNucleusFromState,
} = require("../governance/index.js");
const {
  readSessionStateStrict,
} = require("./session-state-store.js");
const {
  normalizeSessionEvent,
} = require("./session-events.js");
const {
  commitLegacySessionAuthorityMigration,
} = require("./session-authority-unit-of-work.js");

const MIGRATION_EVENT_KIND = "governance.session_authority.migrated";

// Either a fresh session-init event or a prior migration/repair event binds
// a nucleus hash durably enough to make a later migration call idempotent.
const BINDING_EVENT_KINDS = Object.freeze([
  "governance.session.initialized",
  MIGRATION_EVENT_KIND,
]);

// Validates every record in session-events.jsonl through the canonical event
// parser AND its own stored hash before the migration ever derives or
// writes anything. A single malformed/forged record aborts the whole
// migration with zero writes — readJsonlStrict already tolerates a valid
// unterminated trailing line, so that tolerance is preserved here too.
function readValidatedSessionEvents(domain) {
  return readJsonlStrict(
    sessionEventsJsonlPath(domain),
    "session-events.jsonl",
    (record, index) => {
      const normalized = normalizeSessionEvent(record, { targetDomain: domain, now: null });
      if (!record || record.event_hash !== normalized.event_hash) {
        throw new Error(`session-events.jsonl line ${index + 1} hash does not match its canonical content`);
      }
      return normalized;
    },
  );
}

function migrateLegacySessionAuthority(domain) {
  const normalizedDomain = assertSafeDomain(domain);
  return withSessionLock(normalizedDomain, () => {
    let priorEvents;
    try {
      priorEvents = readValidatedSessionEvents(normalizedDomain);
    } catch (error) {
      throw new Error(
        `session-authority migration aborted for ${normalizedDomain}: ${error.message || String(error)}`,
      );
    }

    let state;
    try {
      state = readSessionStateStrict(normalizedDomain).state;
    } catch (error) {
      throw new Error(
        `session-authority migration aborted for ${normalizedDomain}: session state is unavailable (${error.message || String(error)})`,
      );
    }
    const derivedNucleus = sessionNucleusFromState(state);

    const migrationEvent = normalizeSessionEvent({
      target_domain: normalizedDomain,
      kind: MIGRATION_EVENT_KIND,
      nucleus_hash: derivedNucleus.nucleus_hash,
      payload: { nucleus_hash: derivedNucleus.nucleus_hash },
    }, { targetDomain: normalizedDomain });

    // The idempotency decision (does the on-disk nucleus file AND the
    // validated audit already agree on this derived hash?) is made inside
    // commitLegacySessionAuthorityMigration, under the same session lock as
    // the nucleus-file read, so a file that changed out from under a stale
    // audit can never be mistaken for "already migrated".
    return commitLegacySessionAuthorityMigration({
      domain: normalizedDomain,
      derivedNucleus,
      migrationEvent,
      priorEvents,
      bindingEventKinds: BINDING_EVENT_KINDS,
    });
  });
}

module.exports = {
  MIGRATION_EVENT_KIND,
  migrateLegacySessionAuthority,
};
