"use strict";

const {
  assertEnumValue,
  normalizeOptionalText,
} = require("../io/validation.js");
const {
  assertSafeDomain,
  frontierEventsJsonlPath,
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
  normalizeOptionalTextArray,
  normalizePlainObject,
} = require("../io/validation.js");
const {
  readJsonlStrict,
} = require("../io/storage.js");
const { CHAIN_FAMILY_VALUES } = require("../constants/shared-vocabulary.js");
const { normalizeChainToken } = require("../constants/chain-token.js");
const { ToolError, ERROR_CODES } = require("../io/envelope.js");

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

// `node.transitioned` and `closure.recorded` are part of the durable frontier
// vocabulary, but they are not generic append capabilities. The TaskGraph state
// machine has a single writer (`appendNodeTransition`) that validates the live
// node head while the session lock is held, and surface closure has sanctioned
// materializer/merge writers. Keeping a separate public/direct set prevents the
// model-facing append tool from minting state or closure transitions with an
// arbitrary payload while preserving the full vocabulary for readers and
// predicates.
const DIRECT_FRONTIER_EVENT_KINDS = Object.freeze(
  FRONTIER_EVENT_KINDS.filter((kind) => !["node.transitioned", "closure.recorded"].includes(kind)),
);

// Producer observation subtypes. These are observation_kind VALUES that ride
// INSIDE observation.recorded payloads — they are NOT new top-level
// FRONTIER_EVENT_KINDS, so the frozen FRONTIER_EVENT_KINDS array above is
// byte-unchanged (// X-P8: no new top-level kind; the producer subtypes are
// observation.recorded payload discriminators only). They are SIBLINGS of the
// OSS kinds (repo-target.js OSS_OBSERVATION_KIND_VALUES) and the capability
// kinds (capability-observations.js CAPABILITY_OBSERVATION_KIND_VALUES), and
// follow the T.5 jwt_observed precedent — all of which register at the same
// observation.recorded dispatch point. Per OD6 there is intentionally NO
// materialized-seed-artifact subtype, and the coverage floor is NOT wired
// here; producer emission, projection/materializer folding, and floor logic
// live in their own modules (separate nodes). The discriminator field is
// payload.observation_kind — the field the projection reader prefers
// (frontier-projections.js:256 reads payload.observation_kind first) — so
// producers stamp these on observation_kind, but wiring those call-sites is a
// separate node.
const PRODUCER_OBSERVATION_SUBTYPES = Object.freeze([
  "producer_proposed",
  "producer_run",
]);

function isProducerObservationSubtype(value) {
  return typeof value === "string"
    && PRODUCER_OBSERVATION_SUBTYPES.includes(value);
}

function generatedFrontierEventId(fields) {
  return `FE-${hashCanonicalJson(fields).slice(0, 24)}`;
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

function appendNormalizedFrontierEvent(event, options = {}, beforeAppend = null) {
  return withSessionLock(event.target_domain, () => {
    if (beforeAppend != null) {
      if (typeof beforeAppend !== "function") {
        throw new Error("frontier append validator must be a function");
      }
      // Read under the same lock as the append.  This makes a transition's
      // current-state check and ledger write one compare-and-append operation;
      // two writers cannot both validate the same state head.
      beforeAppend({
        event,
        existing_events: readFrontierEvents(event.target_domain),
      });
    }
    appendJsonlLine(frontierEventsJsonlPath(event.target_domain), event, {
      maxRecords: options.maxRecords == null ? FRONTIER_EVENTS_MAX_RECORDS : options.maxRecords,
    });
    return event;
  });
}

function appendFrontierEvent(input, options = {}) {
  const event = normalizeFrontierEvent(input, options);
  if (event.kind === "node.transitioned") {
    throw new ToolError(
      ERROR_CODES.INVALID_ARGUMENTS,
      "node.transitioned is TaskGraph state authority and cannot be appended generically; use the sanctioned TaskGraph transition writer",
      { kind: event.kind },
    );
  }
  if (event.kind === "closure.recorded") {
    throw new ToolError(
      ERROR_CODES.INVALID_ARGUMENTS,
      "closure.recorded is surface closure authority and cannot be appended generically; use the sanctioned surface closure/merge writer",
      { kind: event.kind },
    );
  }
  return appendNormalizedFrontierEvent(event, options);
}

// Internal closure append funnel. Legitimate surface exhaustion and
// coverage-completion signals arrive through materializer/merge-owned code
// paths, not through bob_append_frontier_event.
function appendClosureRecordedEvent(input, options = {}) {
  const event = normalizeFrontierEvent(input, options);
  if (event.kind !== "closure.recorded") {
    throw new Error("appendClosureRecordedEvent accepts only closure.recorded");
  }
  return appendNormalizedFrontierEvent(event, options);
}

// Internal TaskGraph append funnel.  The event vocabulary remains owned by
// this module, while task-graph-events.js supplies the state-machine validator
// so this low-level ledger module does not acquire a materializer dependency.
// Callers cannot omit the validator, and the public MCP tool never calls this
// function.
function appendTaskGraphTransitionEvent(input, validateCurrentState, options = {}) {
  const event = normalizeFrontierEvent(input, options);
  if (event.kind !== "node.transitioned") {
    throw new Error("appendTaskGraphTransitionEvent accepts only node.transitioned");
  }
  if (typeof validateCurrentState !== "function") {
    throw new Error("appendTaskGraphTransitionEvent requires a live-state validator");
  }
  return appendNormalizedFrontierEvent(event, options, validateCurrentState);
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

function isPlainFrontierObject(value) {
  return value != null && typeof value === "object" && !Array.isArray(value);
}

// Single home for the capability_friction event predicate. A capability_friction
// observation rides inside an observation.recorded event as
// { kind: "observation.recorded", payload: { observation_kind:
// "capability_friction_observed", surface_id, friction_kind, ... } }. Pure and
// deterministic: it operates only on the in-memory `events` array (no fs, no IO),
// so filesystem reads stay caller-side. Returns the matching payload objects in
// array order. `surfaceId`, when a non-empty string, scopes to that surface;
// omitted means global (no surface filter). `frictionKinds`, when a non-empty
// array, gates payload.friction_kind to that set; omitted means no friction-kind
// filter — the analytics caller passes FRICTION_KIND_VALUES and stays the sole
// authority for its own gate, so no queue-policy dependency is required here.
function capabilityFrictionPayloads(events, { surfaceId = null, frictionKinds = null } = {}) {
  if (!Array.isArray(events)) return [];
  const scopeSurface = typeof surfaceId === "string" && surfaceId.length > 0;
  const gateFrictionKind = Array.isArray(frictionKinds) && frictionKinds.length > 0;
  const out = [];
  for (const event of events) {
    if (!isPlainFrontierObject(event)) continue;
    if (event.kind !== "observation.recorded") continue;
    const payload = isPlainFrontierObject(event.payload) ? event.payload : null;
    if (!payload) continue;
    if (payload.observation_kind !== "capability_friction_observed") continue;
    if (scopeSurface && payload.surface_id !== surfaceId) continue;
    if (gateFrictionKind && !frictionKinds.includes(payload.friction_kind)) continue;
    out.push(payload);
  }
  return out;
}

// Group capability_friction payloads by (capability_pack, wanted_tool) across
// all surfaces so systematic pack deficiencies surface ("pack X chronically
// lacks tool Y for surfaces {A,B,C}"). Friction payloads carry surface_id and
// wanted_tool but NOT capability_pack; the pack is resolved by joining
// surface_id -> pack through the caller-supplied `surfaceIdToPack` map (a plain
// object or a Map). Operates ONLY on the capabilityFrictionPayloads output —
// never re-walks events — and reuses isPlainFrontierObject for payload guards.
// Pure and deterministic: no fs/IO, no input mutation. Counts every payload as
// given (friction records are idempotent at append time), but dedupes
// surface_ids within a single (pack, wanted_tool) bucket in first-seen order.
// Exhaustive: every (pack, wanted_tool, surface) triple is counted and listed;
// downstream consumers rank, so nothing is truncated or capped here.
function aggregateFrictionByPack(frictionPayloads, surfaceIdToPack) {
  if (!Array.isArray(frictionPayloads)) return {};
  const isMap = surfaceIdToPack instanceof Map;
  if (!isMap && !isPlainFrontierObject(surfaceIdToPack)) return {};
  const lookup = isMap
    ? (id) => surfaceIdToPack.get(id)
    : (id) => surfaceIdToPack[id];

  const out = {};
  for (const payload of frictionPayloads) {
    if (!isPlainFrontierObject(payload)) continue;
    const surfaceId = typeof payload.surface_id === "string" ? payload.surface_id : null;
    const wantedTool = typeof payload.wanted_tool === "string" ? payload.wanted_tool : null;
    if (!surfaceId || !wantedTool) continue;
    const pack = lookup(surfaceId);
    if (typeof pack !== "string" || pack.length === 0) continue;

    const packBucket = out[pack] || (out[pack] = {});
    const toolBucket = packBucket[wantedTool] || (packBucket[wantedTool] = { count: 0, surface_ids: [] });
    toolBucket.count += 1;
    if (!toolBucket.surface_ids.includes(surfaceId)) {
      toolBucket.surface_ids.push(surfaceId);
    }
  }
  return out;
}

module.exports = {
  FRONTIER_EVENTS_MAX_RECORDS,
  FRONTIER_EVENT_KINDS,
  FRONTIER_EVENT_VERSION,
  DIRECT_FRONTIER_EVENT_KINDS,
  PRODUCER_OBSERVATION_SUBTYPES,
  aggregateFrictionByPack,
  appendClosureRecordedEvent,
  appendFrontierEvent,
  appendTaskGraphTransitionEvent,
  capabilityFrictionPayloads,
  frontierEventContentHash,
  generatedFrontierEventId,
  isProducerObservationSubtype,
  normalizeFrontierEvent,
  readFrontierEvents,
};
