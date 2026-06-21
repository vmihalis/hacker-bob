"use strict";

const {
  assertEnumValue,
  normalizeOptionalText,
} = require("./validation.js");
const {
  assertSafeDomain,
  frontierEventsJsonlPath,
} = require("./paths.js");
const {
  appendJsonlLine,
  withSessionLock,
} = require("./storage.js");
const {
  hashCanonicalJson,
} = require("./verification-contracts.js");
const {
  hashDocumentExcluding,
  normalizeId,
  normalizeIsoTimestamp,
  normalizeOptionalId,
  normalizeOptionalObject,
  normalizeOptionalTextArray,
  normalizePlainObject,
  readJsonlStrict,
  withDocumentHash,
} = require("./fabric-common.js");
const { CHAIN_FAMILY_VALUES } = require("./constants.js");
const { ToolError, ERROR_CODES } = require("./envelope.js");

const FRONTIER_EVENT_VERSION = 1;
const FRONTIER_EVENTS_MAX_RECORDS = 20000;

const FRONTIER_EVENT_KINDS = Object.freeze([
  "session.seeded",
  "surface.observed",
  "frontier.enqueued",
  "observation.recorded",
  "control_expectation.recorded",
  "blocker.asserted",
  "closure.recorded",
  "claim.candidate.linked",
  "claim.report_snapshot.appended",
  // Plane X Cycle X.1 — the ONE new top-level kind permitted by X-P8.
  // Every TaskGraph node state-machine transition lands as a single event of
  // this kind so the materializer (X.2) folds an authoritative state stream
  // without scanning typed observation.recorded payloads. Out-of-order
  // transitions are refused at append-time by appendNodeTransition (the
  // frozen state-transition table lives in task-graph-events.js).
  "node.transitioned",
]);

function generatedFrontierEventId(fields) {
  return `FE-${hashCanonicalJson(fields).slice(0, 24)}`;
}

// Mirrors capability-packs.normalizeSurfaceType (lowercase, collapse spaces and
// dashes to underscores) without importing that module, so frontier-events
// stays dependency-light and free of a require cycle. CHAIN_FAMILY_VALUES
// (constants.js) is the single known-chain-family authority — the same set
// SMART_CONTRACT_CHAIN_FAMILY_TO_PACK keys on at routing time, so the
// append-time gate and the router never disagree about what "known" means.
function normalizeChainToken(value) {
  if (value == null) return null;
  const normalized = String(value).trim().toLowerCase().replace(/[\s-]+/g, "_");
  return normalized || null;
}

// Y-D21 — Producer-boundary surface integrity. A surface.observed event whose
// surface_type is smart_contract MUST carry a known chain_family. Enforced
// fail-closed here, at the single append funnel every emitter flows through,
// instead of at far-downstream capability routing (classifySurfaceCapability),
// where a dropped field surfaced as a provenance-free INTERNAL_ERROR that
// poisoned the whole surface set and blocked every evaluator wave. Append-only:
// the read/replay path passes now:null and is intentionally lenient so ledgers
// written before this gate remain readable.
function assertSmartContractChainFamily(kind, payload, surfaceId) {
  if (kind !== "surface.observed") return;
  if (normalizeChainToken(payload.surface_type) !== "smart_contract") return;
  const chainFamily = normalizeChainToken(payload.chain_family);
  if (chainFamily && CHAIN_FAMILY_VALUES.includes(chainFamily)) return;
  throw new ToolError(
    ERROR_CODES.INVALID_ARGUMENTS,
    `surface.observed for smart_contract surface ${surfaceId || "(unknown)"} `
    + `must carry a known chain_family (one of ${CHAIN_FAMILY_VALUES.join(", ")}); `
    + `received ${payload.chain_family == null ? "none" : JSON.stringify(payload.chain_family)}`,
    { surface_id: surfaceId || null, chain_family: payload.chain_family == null ? null : payload.chain_family },
  );
}

function normalizeFrontierEvent(input, { targetDomain = null, now = new Date() } = {}) {
  if (input == null || typeof input !== "object" || Array.isArray(input)) {
    throw new Error("frontier event must be an object");
  }
  const domain = assertSafeDomain(input.target_domain || targetDomain);
  const kind = assertEnumValue(input.kind, FRONTIER_EVENT_KINDS, "kind");
  const ts = normalizeIsoTimestamp(input.ts, "ts", now);
  const payload = normalizePlainObject(input.payload, "payload", { defaultValue: {} });
  const source = normalizeOptionalObject(input.source, "source");
  const surfaceId = normalizeOptionalId(input.surface_id || payload.surface_id, "surface_id");
  const frontierItemId = normalizeOptionalId(input.frontier_item_id || payload.frontier_item_id, "frontier_item_id");
  const taskId = normalizeOptionalId(input.task_id || payload.task_id, "task_id");
  const claimId = normalizeOptionalId(input.claim_id || payload.claim_id, "claim_id");
  const actor = normalizeOptionalText(input.actor, "actor");
  const tags = normalizeOptionalTextArray(input.tags || payload.tags, "tags");

  // Append-path enforcement only (now !== null). readFrontierEvents replays
  // with now:null and must not retroactively reject pre-Y-D21 ledgers.
  if (now !== null) assertSmartContractChainFamily(kind, payload, surfaceId);

  const base = {
    version: FRONTIER_EVENT_VERSION,
    ts,
    target_domain: domain,
    plane: "frontier",
    kind,
    payload,
  };
  if (source) base.source = source;
  if (surfaceId) base.surface_id = surfaceId;
  if (frontierItemId) base.frontier_item_id = frontierItemId;
  if (taskId) base.task_id = taskId;
  if (claimId) base.claim_id = claimId;
  if (actor) base.actor = actor;
  if (tags.length > 0) base.tags = tags;

  const eventId = normalizeOptionalId(input.event_id, "event_id")
    || generatedFrontierEventId(base);
  const event = {
    event_id: eventId,
    ...base,
  };
  normalizeId(event.event_id, "event_id");
  return withDocumentHash(event, "event_hash");
}

function appendFrontierEvent(input, options = {}) {
  const event = normalizeFrontierEvent(input, options);
  return withSessionLock(event.target_domain, () => {
    appendJsonlLine(frontierEventsJsonlPath(event.target_domain), event, {
      maxRecords: options.maxRecords == null ? FRONTIER_EVENTS_MAX_RECORDS : options.maxRecords,
    });
    return event;
  });
}

function readFrontierEvents(targetDomain) {
  const domain = assertSafeDomain(targetDomain);
  return readJsonlStrict(
    frontierEventsJsonlPath(domain),
    "frontier-events.jsonl",
    (record) => normalizeFrontierEvent(record, { targetDomain: domain, now: null }),
  );
}

function frontierEventContentHash(event) {
  return hashDocumentExcluding(event, ["event_hash"]);
}

module.exports = {
  FRONTIER_EVENTS_MAX_RECORDS,
  FRONTIER_EVENT_KINDS,
  FRONTIER_EVENT_VERSION,
  appendFrontierEvent,
  frontierEventContentHash,
  generatedFrontierEventId,
  normalizeFrontierEvent,
  readFrontierEvents,
};
