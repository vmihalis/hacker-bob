"use strict";

const {
  assertEnumValue,
  normalizeOptionalText,
} = require("../io/validation.js");
const {
  assertSafeDomain,
  sessionEventsJsonlPath,
} = require("../io/paths.js");
const {
  appendJsonlLine,
  withSessionLock,
} = require("../io/storage.js");
const {
  hashCanonicalJson,
} = require("../verification/verification-contracts.js");
const {
  hashDocumentExcluding,
  withDocumentHash,
} = require("../verification/document-hash.js");
const {
  normalizeId,
  normalizeIsoTimestamp,
  normalizeOptionalId,
  normalizeOptionalObject,
  normalizePlainObject,
} = require("../io/validation.js");
const {
  readJsonlStrict,
} = require("../io/storage.js");

const SESSION_EVENT_VERSION = 1;
const SESSION_EVENTS_MAX_RECORDS = 20000;

const SESSION_EVENT_KINDS = Object.freeze([
  "governance.session.initialized",
  "governance.auth_context.replaced",
  "governance.lifecycle.advanced",
  "governance.lifecycle.override",
  "governance.operator_constraint.updated",
  "governance.egress_identity.bound",
  "governance.session_authority.migrated",
]);

function generatedSessionEventId(fields) {
  return `SE-${hashCanonicalJson(fields).slice(0, 24)}`;
}

function normalizeSessionEvent(input, { targetDomain = null, now = new Date() } = {}) {
  if (input == null || typeof input !== "object" || Array.isArray(input)) {
    throw new Error("session event must be an object");
  }
  const domain = assertSafeDomain(input.target_domain || targetDomain);
  const kind = assertEnumValue(input.kind, SESSION_EVENT_KINDS, "kind");
  const ts = normalizeIsoTimestamp(input.ts, "ts", now);
  const payload = normalizePlainObject(input.payload, "payload", { defaultValue: {} });
  const source = normalizeOptionalObject(input.source, "source");
  const actor = normalizeOptionalText(input.actor, "actor");
  const nucleusHash = normalizeOptionalText(input.nucleus_hash || payload.nucleus_hash, "nucleus_hash");

  const base = {
    version: SESSION_EVENT_VERSION,
    ts,
    target_domain: domain,
    plane: "governance",
    kind,
    payload,
  };
  if (source) base.source = source;
  if (actor) base.actor = actor;
  if (nucleusHash) base.nucleus_hash = nucleusHash;

  const eventId = normalizeOptionalId(input.event_id, "event_id")
    || generatedSessionEventId(base);
  const event = {
    event_id: eventId,
    ...base,
  };
  normalizeId(event.event_id, "event_id");

  // now === null is the read-path discriminator (readSessionEvents passes it
  // explicitly). A stored event must carry its own event_hash and that hash
  // must match its canonical content; minting/repairing a hash on read would
  // let an absent or tampered event_hash pass through silently. The author
  // path (appendSessionEvent) keeps minting the hash via withDocumentHash.
  if (now === null) {
    const storedHash = typeof input.event_hash === "string" ? input.event_hash : null;
    if (!storedHash) {
      throw new Error("session event is missing event_hash");
    }
    const expectedHash = hashDocumentExcluding(event, ["event_hash"]);
    if (storedHash !== expectedHash) {
      throw new Error("session event event_hash does not match its canonical content");
    }
    return { ...event, event_hash: storedHash };
  }
  return withDocumentHash(event, "event_hash");
}

function appendSessionEvent(input, options = {}) {
  const event = normalizeSessionEvent(input, options);
  return withSessionLock(event.target_domain, () => {
    appendJsonlLine(sessionEventsJsonlPath(event.target_domain), event, {
      maxRecords: options.maxRecords == null ? SESSION_EVENTS_MAX_RECORDS : options.maxRecords,
    });
    return event;
  });
}

function readSessionEvents(targetDomain) {
  const domain = assertSafeDomain(targetDomain);
  return readJsonlStrict(
    sessionEventsJsonlPath(domain),
    "session-events.jsonl",
    (record) => normalizeSessionEvent(record, { targetDomain: domain, now: null }),
  );
}

function sessionEventContentHash(event) {
  return hashDocumentExcluding(event, ["event_hash"]);
}

module.exports = {
  SESSION_EVENTS_MAX_RECORDS,
  SESSION_EVENT_KINDS,
  SESSION_EVENT_VERSION,
  appendSessionEvent,
  generatedSessionEventId,
  normalizeSessionEvent,
  readSessionEvents,
  sessionEventContentHash,
};
