"use strict";

// MCP-owned producer_run projection. A producer_run row is an
// observation.recorded SUBTYPE (discriminator payload.observation_kind ===
// "producer_run"), append-only, and is NEVER node/session state. It records the
// terminal/non-terminal disposition of a single producer dispatch so a later
// coverage floor can stop re-dispatching a producer that has either delivered
// (produced), been deliberately closed (blocked), or accumulated enough
// structural dispatch failures to be auto-closed.
//
// REUSE-ONLY: the row is written solely through frontier-events.js
// appendFrontierEvent and read solely through readFrontierEvents, exactly like
// task-graph-events.js appendCellProposal/readCellProposals. There is no new
// frontier-event top-level kind (producer_run is already a member of the frozen
// PRODUCER_OBSERVATION_SUBTYPES set), no new ledger file, and no direct
// storage.js / fabric-common.js call — the append+read path is reached
// transitively through frontier-events.js.
//
// Status vocabulary:
//   produced         — terminal; the producer emitted output.
//   blocked          — terminal; the producer is deliberately/structurally closed.
//   failed_retryable — NON-terminal; a single dispatch failed and may be retried.
//                      Only a STRUCTURAL failed_retryable (no source / EOA /
//                      unsupported family — a fault in the producer's standing
//                      ability to produce) counts toward the strike tally; a
//                      TRANSIENT failed_retryable (a flaky tool fault) is recorded
//                      for audit but never strikes and never auto-blocks.
//
// At STUCK_PRODUCER_DISPATCH_THRESHOLD structural strikes the producer_key is
// auto-written blocked exactly once (idempotent against an already-terminal
// producer_key), making it terminal so a later floor stops dispatching it.
//
// Standalone and UNWIRED: not registered as a bob_* tool, not in any registry,
// consumed by no generator, and not wired into the coverage floor — those land
// in later nodes.

const {
  appendFrontierEvent,
  readFrontierEvents,
  PRODUCER_OBSERVATION_SUBTYPES,
} = require("./frontier-events.js");
const {
  assertEnumValue,
  assertNonEmptyString,
  normalizeOptionalText,
} = require("./validation.js");
const { ToolError, ERROR_CODES } = require("./envelope.js");

// ─── Reused frozen vocabulary (fail loud on frontier-events.js drift) ────────

// The producer_run projection RIDES an already-registered observation subtype.
// If a future frontier-events.js edit drops this subtype from the frozen
// PRODUCER_OBSERVATION_SUBTYPES set, this module stops loading rather than
// silently writing an unregistered discriminator. Mirrors the reused-vocabulary
// module-load assertions in producer-contract.js.
const PRODUCER_RUN_OBSERVATION_KIND = "producer_run";
if (!PRODUCER_OBSERVATION_SUBTYPES.includes(PRODUCER_RUN_OBSERVATION_KIND)) {
  throw new Error(
    `producer-run-ledger: reused observation subtype "${PRODUCER_RUN_OBSERVATION_KIND}" is `
    + `absent from frontier-events.js PRODUCER_OBSERVATION_SUBTYPES (${PRODUCER_OBSERVATION_SUBTYPES.join(", ")}); `
    + "the producer_run projection must REUSE an already-registered subtype, never add one",
  );
}

// ─── Status / failure-class vocabulary ──────────────────────────────────────

const PRODUCER_RUN_STATUS_VALUES = Object.freeze([
  "produced",
  "blocked",
  "failed_retryable",
]);

// Terminal set R — a producer_key in R is done; a later floor stops dispatching
// it. failed_retryable is intentionally absent (non-terminal).
const TERMINAL_PRODUCER_RUN_STATUSES = Object.freeze([
  "produced",
  "blocked",
]);

// Only a STRUCTURAL failed_retryable strikes; a TRANSIENT one is audit-only.
const FAILURE_CLASS_VALUES = Object.freeze([
  "structural",
  "transient",
]);

const STUCK_PRODUCER_DISPATCH_THRESHOLD = 3;
const STUCK_PRODUCER_DISPATCH_BLOCK_REASON = "stuck_producer_dispatch_threshold";

// A producer that finalizes witness-empty has run and emitted nothing and can
// never re-execute, so it is closed DIRECTLY with a terminal blocked row at
// finalize — terminal-on-first, distinct from the strike-tally auto-block above.
const PRODUCER_WITNESS_EMPTY_BLOCK_REASON = "producer_output_empty";

// ─── Internal append + read helpers (reuse the frontier path only) ──────────

function appendProducerRunRow(domain, { producer_key, status, failure_class, reason, block_reason }) {
  // observation_kind is the discriminator the projection reader prefers
  // (frontier-projections.js normalizeObservationEvent reads
  // payload.observation_kind first), NOT payload.kind.
  const payload = {
    observation_kind: PRODUCER_RUN_OBSERVATION_KIND,
    producer_key,
    status,
  };
  if (failure_class) payload.failure_class = failure_class;
  if (reason) payload.reason = reason;
  if (block_reason) payload.block_reason = block_reason;
  return appendFrontierEvent({
    target_domain: domain,
    kind: "observation.recorded",
    payload,
  });
}

// Every producer_run row in append order. Mirrors readCellProposals: filter the
// frontier-event stream by the top-level observation.recorded kind and the
// payload discriminator, decoding no payload by hand. Graceful: tolerates
// pre-existing ledgers and never throws beyond readFrontierEvents' own
// domain/IO validation.
function readProducerRunRows(domain) {
  return readFrontierEvents(domain).filter((event) => (
    event.kind === "observation.recorded"
    && event.payload != null
    && typeof event.payload === "object"
    && !Array.isArray(event.payload)
    && event.payload.observation_kind === PRODUCER_RUN_OBSERVATION_KIND
  ));
}

// ─── Public API ─────────────────────────────────────────────────────────────

// Record one producer dispatch disposition. Writes exactly one
// observation.recorded producer_run row; a structural failed_retryable that
// pushes the strike tally to the threshold auto-writes a single terminal blocked
// row (idempotent against an already-terminal producer_key). Fail-loud on
// invalid input via the shared validation helpers — failure_class is REQUIRED
// (no silent default) for a failed_retryable so strikes are never inflated or
// hidden by a missing field.
function recordProducerRun(domain, options = {}) {
  if (options == null || typeof options !== "object" || Array.isArray(options)) {
    throw new ToolError(
      ERROR_CODES.INVALID_ARGUMENTS,
      "recordProducerRun options must be an object",
    );
  }
  const producerKey = assertNonEmptyString(options.producer_key, "producer_key");
  const status = assertEnumValue(options.status, PRODUCER_RUN_STATUS_VALUES, "status");
  let failureClass = null;
  if (status === "failed_retryable") {
    failureClass = assertEnumValue(options.failure_class, FAILURE_CLASS_VALUES, "failure_class");
  }
  const reason = normalizeOptionalText(options.reason, "reason");
  const blockReason = normalizeOptionalText(options.block_reason, "block_reason");

  const event = appendProducerRunRow(domain, {
    producer_key: producerKey,
    status,
    failure_class: failureClass,
    reason,
    block_reason: blockReason,
  });

  // Auto-block on stuck dispatch. Only a structural strike can trip the
  // threshold; recompute the tally against the post-append ledger (so the
  // just-written strike is counted) and append a single terminal blocked row
  // when the producer is at/over threshold and not already terminal.
  let autoBlocked = null;
  if (status === "failed_retryable" && failureClass === "structural") {
    const tally = producerStrikeTally(domain, producerKey);
    if (tally >= STUCK_PRODUCER_DISPATCH_THRESHOLD && !producerRunSet(domain).has(producerKey)) {
      autoBlocked = appendProducerRunRow(domain, {
        producer_key: producerKey,
        status: "blocked",
        block_reason: STUCK_PRODUCER_DISPATCH_BLOCK_REASON,
      });
    }
  }

  return { event, auto_blocked: autoBlocked };
}

// Record a DEFINITIVE terminal block for a producer whose finalize attested an
// empty run. A witness-empty finalize is terminal-on-first, NOT one of three
// structural strikes: the producer executed and emitted nothing, and a producer
// node can never re-execute, so there is no transient retry to wait out. Writes
// exactly one terminal blocked row keyed by the full producer_key and is
// idempotent against an already-terminal producer_key, so the key joins the
// terminal run set in a single finalize and a later floor stops dispatching it.
// The transient orphan-executed / stale-dispatch reconcilers MUST keep using
// recordProducerRun's structural-strike path (a strike ticks toward the
// threshold); only a witness-empty finalize is terminal-on-first.
function recordProducerTerminalBlock(domain, options = {}) {
  if (options == null || typeof options !== "object" || Array.isArray(options)) {
    throw new ToolError(
      ERROR_CODES.INVALID_ARGUMENTS,
      "recordProducerTerminalBlock options must be an object",
    );
  }
  const producerKey = assertNonEmptyString(options.producer_key, "producer_key");
  const blockReason = normalizeOptionalText(options.block_reason, "block_reason")
    || PRODUCER_WITNESS_EMPTY_BLOCK_REASON;
  // Idempotent: a producer_key already terminal (produced | blocked) is never
  // re-blocked, so the terminal set carries exactly one block row per producer.
  if (producerRunSet(domain).has(producerKey)) {
    return { event: null, blocked: false, already_terminal: true };
  }
  const event = appendProducerRunRow(domain, {
    producer_key: producerKey,
    status: "blocked",
    block_reason: blockReason,
  });
  return { event, blocked: true, already_terminal: false };
}

// The set of producer_keys with at least one TERMINAL (produced | blocked) row.
// A producer_key whose only rows are failed_retryable is excluded.
function producerRunSet(domain) {
  const keys = new Set();
  for (const event of readProducerRunRows(domain)) {
    const payload = event.payload;
    if (!TERMINAL_PRODUCER_RUN_STATUSES.includes(payload.status)) continue;
    if (typeof payload.producer_key === "string" && payload.producer_key) {
      keys.add(payload.producer_key);
    }
  }
  return keys;
}

// Count of STRUCTURAL dispatched-and-failed runs for a producer_key. Transient
// failed_retryable rows and produced/blocked rows are excluded — only structural
// dispatch failures strike.
function producerStrikeTally(domain, producerKey) {
  const key = assertNonEmptyString(producerKey, "producer_key");
  let count = 0;
  for (const event of readProducerRunRows(domain)) {
    const payload = event.payload;
    if (payload.producer_key !== key) continue;
    if (payload.status !== "failed_retryable") continue;
    if (payload.failure_class !== "structural") continue;
    // PRD-1 strike-counter monotonicity: only a STRUCTURAL failed_retryable
    // strikes (transient faults and produced/blocked rows never count); the
    // tally is recomputed over an append-only ledger, so it is monotone
    // non-decreasing. At STUCK_PRODUCER_DISPATCH_THRESHOLD recordProducerRun
    // auto-blocks the producer_key exactly once, idempotent against an
    // already-terminal key.
    count += 1;
  }
  return count;
}

module.exports = {
  PRODUCER_RUN_OBSERVATION_KIND,
  PRODUCER_RUN_STATUS_VALUES,
  TERMINAL_PRODUCER_RUN_STATUSES,
  FAILURE_CLASS_VALUES,
  STUCK_PRODUCER_DISPATCH_THRESHOLD,
  PRODUCER_WITNESS_EMPTY_BLOCK_REASON,
  recordProducerRun,
  recordProducerTerminalBlock,
  producerRunSet,
  producerStrikeTally,
};
