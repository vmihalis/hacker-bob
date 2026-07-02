"use strict";

// Pure SSOT for the per-producer OUTPUT contract — a structural sibling of
// producer-packs.js. Given a producer (resolved against the PRODUCER_PACKS
// authority) and a single run, it builds the witness obligation that proves the
// producer actually emitted output, and evaluates whether the run satisfies it.
//
// The witness REUSES the existing contracts.js "frontier_event_emitted" witness
// kind over a "surface.observed" frontier event — no new witness kind is ever
// introduced. The module-load assertions below fail loud if the reused
// contracts.js / frontier-events.js vocabulary ever drops those tokens.
//
// Satisfaction reads ONLY MCP-owned, run-attested signals and is NEVER a
// file_exists / agent-scratch existence check. A run satisfies the contract
// when ANY disjunct holds:
//   surface_observed     — >=1 run-scoped surface.observed event whose
//                          surface_type is one of the producer's
//                          emits_surface_types
//   producer_run_output  — the MCP-owned producer_run row reports an
//                          output_artifact.item_count that is a finite number >0
//   input_consumed       — the input_consumed attestation reports an
//                          input_item_count that is a finite number >0 (the
//                          honest-empty-intermediate path: a producer that emits
//                          no surface type but verifiably consumed input is
//                          still satisfied)
//
// PURE: no clock, random, env, fs, or network; no import-time side effects
// beyond the fail-loud frozen-vocabulary assertions. Returns are deep-frozen and
// deterministic per (producer, run), exactly like producer-packs.js.
//
// NOT wired into finalize — a later node owns that wiring. NOT registered in any
// registry and consumed by no generator. This module is the pure source of the
// contract only.

const { PRODUCER_PACKS } = require("./producer-packs.js");
const { WITNESS_KIND_VALUES } = require("./contracts.js");
const { FRONTIER_EVENT_KINDS } = require("./frontier-events.js");

// ─── Reused frozen vocabulary (fail loud on contracts.js / frontier drift) ──

// The witness is ALWAYS the existing contracts.js "frontier_event_emitted"
// obligation — reused, never minted. If a future contracts.js edit drops this
// kind from its closed WITNESS_KIND_VALUES set, this module stops loading rather
// than silently inventing a parallel vocabulary.
const PRODUCER_OUTPUT_WITNESS_KIND = "frontier_event_emitted";
if (!WITNESS_KIND_VALUES.includes(PRODUCER_OUTPUT_WITNESS_KIND)) {
  throw new Error(
    `producer-contract: reused witness kind "${PRODUCER_OUTPUT_WITNESS_KIND}" is `
    + `absent from contracts.js WITNESS_KIND_VALUES (${WITNESS_KIND_VALUES.join(", ")}); `
    + "the producer output contract must REUSE an existing witness kind, never add one",
  );
}

// The witness predicate fires on a "surface.observed" frontier event. Mirrors
// the membership check contracts.js's frontier_event_emitted predicate
// normalizer enforces, so a drift in the frontier vocabulary fails loud here too.
const PRODUCER_OUTPUT_FRONTIER_KIND = "surface.observed";
if (!FRONTIER_EVENT_KINDS.includes(PRODUCER_OUTPUT_FRONTIER_KIND)) {
  throw new Error(
    `producer-contract: reused frontier event kind "${PRODUCER_OUTPUT_FRONTIER_KIND}" is `
    + `absent from frontier-events.js FRONTIER_EVENT_KINDS (${FRONTIER_EVENT_KINDS.join(", ")})`,
  );
}

// The three disjuncts that can satisfy the contract, in priority order.
const SATISFIED_BY_SURFACE_OBSERVED = "surface_observed";
const SATISFIED_BY_PRODUCER_RUN_OUTPUT = "producer_run_output";
const SATISFIED_BY_INPUT_CONSUMED = "input_consumed";
const SATISFIED_BY = Object.freeze([
  SATISFIED_BY_SURFACE_OBSERVED,
  SATISFIED_BY_PRODUCER_RUN_OUTPUT,
  SATISFIED_BY_INPUT_CONSUMED,
]);

// ─── Internal pure helpers ──────────────────────────────────────────────────

function isPlainObject(value) {
  return value != null && typeof value === "object" && !Array.isArray(value);
}

// A count is only honoured when it is a real finite number strictly > 0. A
// missing / NaN / negative / zero / non-number count is honestly UNSATISFIED,
// never a throw.
function isPositiveFiniteCount(value) {
  return typeof value === "number" && Number.isFinite(value) && value > 0;
}

// Read the surface_type off a run-attested surface.observed event, tolerating
// either a flat row or a frontier-event-shaped { payload: { surface_type } }
// row. Returns null when no string surface_type is present.
function readSurfaceType(event) {
  if (typeof event === "string") return event;
  if (!isPlainObject(event)) return null;
  if (typeof event.surface_type === "string") return event.surface_type;
  if (isPlainObject(event.payload) && typeof event.payload.surface_type === "string") {
    return event.payload.surface_type;
  }
  return null;
}

// The run-scoped surface.observed events the run attests. Read defensively from
// an ordered set of candidate array fields because the run row shape is owned by
// sibling nodes; a missing list yields [] (no surface_observed satisfaction),
// never a throw.
function runSurfaceObservedEvents(run) {
  if (!isPlainObject(run)) return [];
  const candidates = [run.surfaces_observed, run.surface_observed, run.surface_observations];
  for (const candidate of candidates) {
    if (Array.isArray(candidate)) return candidate;
  }
  return [];
}

// ─── Producer authority resolution ──────────────────────────────────────────

// Resolve a producer pack from PRODUCER_PACKS — the SOLE producer authority.
// Accepts either a producer_id string or a pack-shaped object (reads its
// producer_id) and fails loud on an unknown / missing producer, mirroring the
// producerScratchNamespace fail-loud idiom in producer-packs.js.
function resolveProducer(producer) {
  let producerId = null;
  if (typeof producer === "string") {
    producerId = producer;
  } else if (isPlainObject(producer) && typeof producer.producer_id === "string") {
    producerId = producer.producer_id;
  }
  if (!producerId || !Object.prototype.hasOwnProperty.call(PRODUCER_PACKS, producerId)) {
    throw new Error(
      `resolveProducer: unknown producer ${JSON.stringify(producer)}; PRODUCER_PACKS is the `
      + `only producer authority (known: ${Object.keys(PRODUCER_PACKS).join(", ")})`,
    );
  }
  return PRODUCER_PACKS[producerId];
}

// ─── Witness construction (reuse contracts.js frontier_event_emitted shape) ──

// Build the frozen witness obligation. The shape matches the contracts.js
// frontier_event_emitted predicate normalizer:
//   { kind: "frontier_event_emitted",
//     predicate: { kind: "surface.observed", payload_kind?: <surface_type> } }
// payload_kind is bound ONLY when the producer emits exactly one surface type;
// for zero / multi it is omitted (still a valid frontier_event_emitted
// predicate). The witness is never a file_exists obligation.
function buildWitness(emitsSurfaceTypes) {
  const predicate = { kind: PRODUCER_OUTPUT_FRONTIER_KIND };
  if (Array.isArray(emitsSurfaceTypes) && emitsSurfaceTypes.length === 1) {
    predicate.payload_kind = emitsSurfaceTypes[0];
  }
  return Object.freeze({
    kind: PRODUCER_OUTPUT_WITNESS_KIND,
    predicate: Object.freeze(predicate),
  });
}

// ─── Disjunct evaluators (graceful, never throw, never file_exists) ─────────

// Disjunct 1: >=1 run-scoped surface.observed whose surface_type is one of the
// producer's emits_surface_types. An empty emits_surface_types yields false — an
// intermediate producer emits no surface type, so it can only be satisfied via
// the producer_run_output or input_consumed disjuncts.
function surfaceObservedSatisfied(run, emitsSurfaceTypes) {
  if (!Array.isArray(emitsSurfaceTypes) || emitsSurfaceTypes.length === 0) return false;
  if (!isPlainObject(run)) return false;
  const emitSet = new Set(emitsSurfaceTypes);
  for (const event of runSurfaceObservedEvents(run)) {
    const surfaceType = readSurfaceType(event);
    if (surfaceType != null && emitSet.has(surfaceType)) return true;
  }
  return false;
}

// Disjunct 2: the MCP-owned producer_run row reports an
// output_artifact.item_count that is a finite number > 0.
function producerRunOutputSatisfied(run) {
  if (!isPlainObject(run)) return false;
  const producerRun = run.producer_run;
  if (!isPlainObject(producerRun)) return false;
  const outputArtifact = producerRun.output_artifact;
  if (!isPlainObject(outputArtifact)) return false;
  return isPositiveFiniteCount(outputArtifact.item_count);
}

// Disjunct 3: the input_consumed attestation reports an input_item_count that is
// a finite number > 0 (the honest-empty-intermediate path).
function inputConsumedSatisfied(run) {
  if (!isPlainObject(run)) return false;
  const inputConsumed = run.input_consumed;
  if (!isPlainObject(inputConsumed)) return false;
  return isPositiveFiniteCount(inputConsumed.input_item_count);
}

// ─── Entry point ────────────────────────────────────────────────────────────

// Build the per-producer output contract for a run. PURE: no IO / clock / random
// / env; the returned object is deep-frozen and deterministic per (producer,
// run). The witness is always the reused frontier_event_emitted/surface.observed
// obligation; satisfaction reads only run-attested MCP-owned signals.
function buildProducerOutputContract(producer, run) {
  const pack = resolveProducer(producer);
  const emitsSurfaceTypes = Array.isArray(pack.emits_surface_types)
    ? pack.emits_surface_types.slice()
    : [];
  const witness = buildWitness(emitsSurfaceTypes);

  let satisfiedBy = null;
  if (surfaceObservedSatisfied(run, emitsSurfaceTypes)) {
    satisfiedBy = SATISFIED_BY_SURFACE_OBSERVED;
  } else if (producerRunOutputSatisfied(run)) {
    satisfiedBy = SATISFIED_BY_PRODUCER_RUN_OUTPUT;
  } else if (inputConsumedSatisfied(run)) {
    satisfiedBy = SATISFIED_BY_INPUT_CONSUMED;
  }

  return Object.freeze({
    producer_id: pack.producer_id,
    emits_surface_types: Object.freeze(emitsSurfaceTypes),
    witness,
    satisfied: satisfiedBy !== null,
    satisfied_by: satisfiedBy,
  });
}

module.exports = {
  PRODUCER_OUTPUT_WITNESS_KIND,
  PRODUCER_OUTPUT_FRONTIER_KIND,
  SATISFIED_BY,
  buildProducerOutputContract,
  buildWitness,
  inputConsumedSatisfied,
  producerRunOutputSatisfied,
  resolveProducer,
  surfaceObservedSatisfied,
};
